"""Stable TCP transport: 4-byte network-order length + UTF-8 JSON envelope."""
from __future__ import annotations
import socket
import struct
from typing import Any
from pydantic import ValidationError
from . import security
from .models import WireMessage

HEADER = struct.Struct("!I")
DEFAULT_MAX_FRAME = 65536
SOCKET_TIMEOUT = 5.0


class ProtocolError(Exception):
    pass


def recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < n:
        part = sock.recv(n - len(chunks))
        if not part:
            raise ConnectionError("peer closed connection before frame was complete")
        chunks.extend(part)
    return bytes(chunks)


def recv_message(sock: socket.socket, max_frame: int = DEFAULT_MAX_FRAME) -> WireMessage:
    header = recv_exact(sock, HEADER.size)
    (length,) = HEADER.unpack(header)
    if length <= 0 or length > max_frame:
        raise ProtocolError(f"invalid frame length: {length}")
    raw = recv_exact(sock, length)
    try:
        return WireMessage.model_validate_json(raw)
    except (ValidationError, ValueError) as exc:
        raise ProtocolError(f"invalid message envelope: {exc}") from exc


def send_message(sock: socket.socket, message: WireMessage, max_frame: int = DEFAULT_MAX_FRAME) -> None:
    raw = message.model_dump_json().encode("utf-8")
    if not raw or len(raw) > max_frame:
        raise ProtocolError(f"outbound frame exceeds limit ({len(raw)} bytes)")
    sock.sendall(HEADER.pack(len(raw)) + raw)


def request(host: str, port: int, message: WireMessage, timeout: float = SOCKET_TIMEOUT,
            max_frame: int = DEFAULT_MAX_FRAME, signing_key: str = "") -> dict[str, Any]:
    if signing_key:
        message = security.sign(message, signing_key)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        send_message(sock, message, max_frame=max_frame)
        response = recv_message(sock, max_frame=max_frame)
        if response.sender != message.recipient or response.recipient != message.sender:
            raise ProtocolError("response sender/recipient does not match the request")
        if response.correlation_id != message.message_id:
            raise ProtocolError("response correlation_id does not match request message_id")
        if signing_key:
            problem = security.verify(response, signing_key)
            if problem:
                raise ProtocolError(f"response authentication failed: {problem}")
        return response.model_dump(mode="json")
