"""TCP network loop for the secure CipherMesh agent (reuses the Unit 2.2 frame format).

Assignment 5.1 - Agent Authentication and Host Integrity Verification.
Author: Kumar Waibhav Akshat (RA2212704010027).

Frame format is unchanged from :mod:`ciphermesh.transport`: a 4-byte
network-order length followed by that many bytes of UTF-8 JSON. The server
reads the length first and, if it is zero or above the limit, rejects the
request at checkpoint C1 *without* reading or allocating the body. The peer IP
address reported by the kernel (``accept()``) - never a value inside the
message - is the network origin used by checkpoint C7.

Slow-client defences: the whole frame must arrive before a monotonic deadline
(default 5 s, so dripping one byte at a time does not help), each peer address
may hold at most 4 connections, and both events are audited as L0 failures.
"""
from __future__ import annotations

import argparse
import logging
import socket
import sys
import threading
import time

from ..transport import HEADER
from .secure_agent import AgentConfig, SecureCipherMeshAgent, build_agent_from_dirs
from .verifier import Origin

LOG = logging.getLogger("ciphermesh.trust.server")
SOCKET_TIMEOUT_S = 5.0


class FrameDeadline(Exception):
    """The peer did not deliver a complete frame before the per-frame deadline."""


def _recv_by(conn: socket.socket, n: int, deadline: float) -> bytes:
    """Read exactly n bytes, but never past a monotonic deadline (defeats byte-by-byte dripping)."""
    chunks = bytearray()
    while len(chunks) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FrameDeadline(f"frame incomplete after deadline ({len(chunks)}/{n} bytes)")
        conn.settimeout(remaining)
        try:
            part = conn.recv(n - len(chunks))
        except socket.timeout:
            raise FrameDeadline(f"frame incomplete after deadline ({len(chunks)}/{n} bytes)") from None
        if not part:
            raise ConnectionError("peer closed connection before frame was complete")
        chunks.extend(part)
    return bytes(chunks)


def handle_connection(conn: socket.socket, address: tuple, agent: SecureCipherMeshAgent) -> None:
    peer_ip, peer_port = address[0], address[1]
    origin = Origin("tcp", peer_ip, str(peer_port))
    deadline = time.monotonic() + agent.config.frame_deadline_s
    with conn:
        try:
            (length,) = HEADER.unpack(_recv_by(conn, HEADER.size, deadline))
            if length == 0 or length > agent.config.max_frame:
                outcome = agent.handle_frame(b"", origin, declared_length=length)
            else:
                outcome = agent.handle_frame(_recv_by(conn, length, deadline), origin)
            conn.settimeout(SOCKET_TIMEOUT_S)
            conn.sendall(HEADER.pack(len(outcome.reply)) + outcome.reply)
        except FrameDeadline as exc:
            agent.record_transport_failure(origin, "FRAME_TIMEOUT", str(exc))
        except (OSError, ConnectionError) as exc:
            LOG.warning("[SERVER] connection from %s:%s ended early: %s", peer_ip, peer_port, type(exc).__name__)


class _PerIpSlots:
    """Counts open connections per peer address; a peer may hold at most ``limit`` at once."""

    def __init__(self, limit: int):
        self.limit, self._open, self._lock = limit, {}, threading.Lock()

    def acquire(self, ip: str) -> bool:
        with self._lock:
            if self._open.get(ip, 0) >= self.limit:
                return False
            self._open[ip] = self._open.get(ip, 0) + 1
            return True

    def release(self, ip: str) -> None:
        with self._lock:
            self._open[ip] -= 1
            if not self._open[ip]:
                del self._open[ip]


def serve(agent: SecureCipherMeshAgent, host: str = "127.0.0.1", port: int = 9061, max_workers: int = 32,
          ready_event: threading.Event | None = None, stop_event: threading.Event | None = None,
          bound: list | None = None) -> None:
    slots = threading.BoundedSemaphore(max_workers)
    per_ip = _PerIpSlots(agent.config.max_connections_per_ip)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(max_workers)
        server.settimeout(0.25)
        actual = server.getsockname()
        if bound is not None:
            bound.append(actual[1])
        LOG.info("[SERVER] %s listening on tcp://%s:%d (mode=%s, max_frame=%d bytes, frame deadline %.0f s, "
                 "%d connections per IP)", agent.agent_id, actual[0], actual[1],
                 "SAFE_MODE" if agent.safe_mode else "NORMAL", agent.config.max_frame,
                 agent.config.frame_deadline_s, agent.config.max_connections_per_ip)
        if ready_event:
            ready_event.set()
        while not (stop_event and stop_event.is_set()):
            try:
                conn, address = server.accept()
            except socket.timeout:
                continue
            ip = address[0]
            if not per_ip.acquire(ip):
                conn.close()
                agent.record_transport_failure(Origin("tcp", ip, str(address[1])), "CONNECTION_LIMIT",
                                               f"more than {agent.config.max_connections_per_ip} open "
                                               "connections from this address")
                continue
            if not slots.acquire(blocking=False):
                per_ip.release(ip)
                conn.close()
                LOG.warning("[SERVER] connection from %s refused: worker capacity reached", ip)
                continue

            def worker(c=conn, a=address):
                try:
                    handle_connection(c, a, agent)
                finally:
                    per_ip.release(a[0])
                    slots.release()

            threading.Thread(target=worker, daemon=True).start()


class BackgroundServer:
    """Runs :func:`serve` in a daemon thread (used by the simulation and the tests)."""

    def __init__(self, agent: SecureCipherMeshAgent, host: str = "127.0.0.1", port: int = 0):
        self.agent, self.host = agent, host
        self._ready, self._stop, self._bound = threading.Event(), threading.Event(), []
        self._thread = threading.Thread(target=serve, args=(agent, host, port),
                                        kwargs={"ready_event": self._ready, "stop_event": self._stop,
                                                "bound": self._bound}, daemon=True)

    def __enter__(self) -> "BackgroundServer":
        self._thread.start()
        if not self._ready.wait(5):
            raise RuntimeError("secure server did not start")
        return self

    @property
    def port(self) -> int:
        return self._bound[0]

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._thread.join(timeout=3)


def main(argv: list[str] | None = None) -> None:
    from pathlib import Path
    from .provision import DEFAULT_KEYS_DIR, DEFAULT_TRUST_DIR, ensure_provisioned, passphrase_from_env
    sys.dont_write_bytecode = True
    parser = argparse.ArgumentParser(description="CipherMesh secure agent TCP server (Assignment 5.1)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9061)
    parser.add_argument("--trust-dir", default=str(DEFAULT_TRUST_DIR))
    parser.add_argument("--keys-dir", default=str(DEFAULT_KEYS_DIR))
    parser.add_argument("--audit-log", default="logs/interactive_events.jsonl")
    parser.add_argument("--strict-integrity", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-7s | %(message)s")
    ensure_provisioned(Path(args.trust_dir), Path(args.keys_dir))
    agent = build_agent_from_dirs(args.trust_dir, args.keys_dir, passphrase_from_env(), args.audit_log,
                                  config=AgentConfig(strict_integrity=args.strict_integrity))
    try:
        serve(agent, args.host, args.port)
    except KeyboardInterrupt:
        LOG.info("[SERVER] shutting down")


if __name__ == "__main__":
    main()
