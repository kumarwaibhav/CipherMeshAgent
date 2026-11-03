"""TCP server for Agent-B, with bounded concurrency and loopback-first defaults."""
from __future__ import annotations
import argparse
import hmac
import os
import socket
import threading
from .agent import CipherMeshAgent
from .models import MessageType, WireMessage
from .transport import DEFAULT_MAX_FRAME, ProtocolError, recv_message, send_message

DEFAULT_HOST = os.getenv("CIPHERMESH_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.getenv("CIPHERMESH_PORT", "9052"))
DEFAULT_MAX_FRAME_BYTES = int(os.getenv("CIPHERMESH_MAX_BYTES", str(DEFAULT_MAX_FRAME)))
DEFAULT_SHARED_TOKEN = os.getenv("CIPHERMESH_SHARED_TOKEN", "")
DEFAULT_MAX_WORKERS = int(os.getenv("CIPHERMESH_MAX_WORKERS", "32"))


def serve(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, agent_id: str = "AGENT_B_NODE_01",
          audit_path: str = "agent_b_audit.db", shared_token: str = DEFAULT_SHARED_TOKEN,
          max_frame: int = DEFAULT_MAX_FRAME_BYTES, max_workers: int = DEFAULT_MAX_WORKERS,
          ready_event: threading.Event | None = None, stop_event: threading.Event | None = None):
    if not (1 <= max_frame <= 1_048_576):
        raise ValueError("max_frame must be between 1 byte and 1 MiB")
    if max_workers < 1:
        raise ValueError("max_workers must be positive")
    agent = CipherMeshAgent(agent_id, audit_path)
    slots = threading.BoundedSemaphore(max_workers)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(max_workers)
        server.settimeout(0.5)
        actual_host, actual_port = server.getsockname()[:2]
        print(f"[{agent_id}] listening on {actual_host}:{actual_port}; Ctrl+C to stop", flush=True)
        if not shared_token:
            print("[WARN] no shared token configured; loopback/local demo only", flush=True)
        if ready_event:
            ready_event.set()
        while not (stop_event and stop_event.is_set()):
            try:
                conn, address = server.accept()
            except socket.timeout:
                continue
            if not slots.acquire(blocking=False):
                conn.close()
                print("[WARN] client rejected: worker capacity reached", flush=True)
                continue
            thread = threading.Thread(target=_client,
                args=(conn, address, agent, shared_token, max_frame, slots), daemon=True)
            thread.start()
    return agent


def _client(conn: socket.socket, address, agent: CipherMeshAgent, shared_token: str,
            max_frame: int = DEFAULT_MAX_FRAME_BYTES, slots: threading.BoundedSemaphore | None = None):
    with conn:
        conn.settimeout(5.0)
        try:
            message = recv_message(conn, max_frame=max_frame)
            if shared_token and not hmac.compare_digest(message.auth_token or "", shared_token):
                reply = agent._reply(message, MessageType.ERROR, {"error": "authentication failed"})
                send_message(conn, WireMessage.model_validate(reply), max_frame=max_frame)
                return
            print(f"[{agent.state.agent_id}] received {message.message_type.value} from {message.sender} at {address}", flush=True)
            response = agent.handle(message)
            send_message(conn, WireMessage.model_validate(response), max_frame=max_frame)
            print(f"[{agent.state.agent_id}] replied {response['message_type']}", flush=True)
        except (OSError, ConnectionError, ProtocolError, ValueError) as exc:
            print(f"[{agent.state.agent_id}] connection error from {address}: {type(exc).__name__}: {exc}", flush=True)
        finally:
            if slots:
                slots.release()


def main():
    parser = argparse.ArgumentParser(description="CipherMesh Agent-B TCP listener")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--agent-id", default="AGENT_B_NODE_01")
    parser.add_argument("--audit-path", default="agent_b_audit.db")
    parser.add_argument("--max-frame", type=int, default=DEFAULT_MAX_FRAME_BYTES)
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS)
    parser.add_argument("--token", default=DEFAULT_SHARED_TOKEN)
    args = parser.parse_args()
    try:
        serve(args.host, args.port, args.agent_id, args.audit_path, args.token,
              args.max_frame, args.max_workers)
    except KeyboardInterrupt:
        print("\n[INFO] CipherMesh server shutting down")


if __name__ == "__main__":
    main()
