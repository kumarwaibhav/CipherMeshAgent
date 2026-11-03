import socket
import threading
import pytest
from ciphermesh.models import MessageType, WireMessage
from ciphermesh.transport import recv_message, send_message, ProtocolError, HEADER


def test_socketpair_round_trip_json_frame():
    left, right = socket.socketpair()
    message = WireMessage(message_type=MessageType.PING, sender="Agent-A",
                          recipient="Agent-B", payload={"hello": "world"})
    errors = []
    def sender():
        try:
            send_message(left, message)
        except Exception as exc:
            errors.append(exc)
        finally:
            left.close()
    thread = threading.Thread(target=sender)
    thread.start()
    received = recv_message(right)
    thread.join(timeout=2)
    right.close()
    assert not errors
    assert received.message_id == message.message_id
    assert received.payload == {"hello": "world"}


def test_rejects_oversized_frame_header():
    left, right = socket.socketpair()
    left.sendall(HEADER.pack(1000))
    with pytest.raises(ProtocolError):
        recv_message(right, max_frame=100)
    left.close()
    right.close()


def test_recv_exact_handles_fragmented_header_and_body():
    left, right = socket.socketpair()
    message = WireMessage(message_type=MessageType.PING, sender="A", recipient="B")
    raw = message.model_dump_json().encode("utf-8")
    framed = HEADER.pack(len(raw)) + raw
    def fragmented_sender():
        for byte in framed:
            left.sendall(bytes([byte]))
        left.close()
    thread = threading.Thread(target=fragmented_sender)
    thread.start()
    received = recv_message(right)
    thread.join(timeout=2)
    right.close()
    assert received.message_id == message.message_id


def test_rejects_invalid_json_envelope():
    left, right = socket.socketpair()
    body = b'{"schema_version":"1","message_type":"NOT_A_TYPE"}'
    left.sendall(HEADER.pack(len(body)) + body)
    with pytest.raises(ProtocolError):
        recv_message(right)
    left.close()
    right.close()
