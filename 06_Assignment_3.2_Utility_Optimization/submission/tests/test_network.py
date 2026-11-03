"""Real TCP loopback exercise: client transfers policy, then asks receiver to inspect."""
import socket
import threading
from ciphermesh.agent import CipherMeshAgent
from ciphermesh.models import MessageType, WireMessage
from ciphermesh.server import _client
from ciphermesh.transport import request


def test_live_tcp_state_sync_then_remote_inspection(tmp_path):
    host = "127.0.0.1"
    token = "test-only-token"
    agent = CipherMeshAgent("AGENT_B_NODE_01", str(tmp_path / "audit.db"))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, 0))
    listener.listen(5)
    port = listener.getsockname()[1]
    server_errors = []

    def accept_three():
        try:
            for _ in range(3):
                conn, address = listener.accept()
                _client(conn, address, agent, token, 65536, None)
        except Exception as exc:
            server_errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=accept_three, daemon=True)
    thread.start()

    sync = WireMessage(message_type=MessageType.STATE_SYNC, sender="AGENT_A_NODE_01",
        recipient="AGENT_B_NODE_01", auth_token=token,
        payload={"state": {"policy_version": "1.1", "policy_revision": 2,
                            "provider_allowlist": ["local", "aws-bedrock"],
                            "max_prompt_bytes": 65536,
                            "require_review_for_internal_urls": True,
                            "redact_email_phone_ip": True, "block_critical_secrets": True,
                            "custom_redaction_patterns": []}})
    sync_response = request(host, port, sync)
    assert sync_response["payload"]["status"] == "state_applied"

    inspect = WireMessage(message_type=MessageType.INSPECT, sender="AGENT_A_NODE_01",
        recipient="AGENT_B_NODE_01", auth_token=token,
        payload={"text": "Contact alice@example.com"})
    inspect_response = request(host, port, inspect)
    assert inspect_response["payload"]["inspection"]["decision"] == "REDACT"
    assert "alice@example.com" not in str(inspect_response)

    telemetry = WireMessage(message_type=MessageType.COMMAND_INSTRUCTION, sender="AGENT_A_NODE_01",
        recipient="AGENT_B_NODE_01", auth_token=token,
        payload={"command": "REQUEST_TELEMETRY_DUMP"})
    telemetry_response = request(host, port, telemetry)
    assert telemetry_response["payload"]["status"] == "telemetry_ready"

    thread.join(timeout=3)
    assert not thread.is_alive()
    assert not server_errors
    assert agent.state.policy_revision == 2
