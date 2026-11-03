"""HMAC envelope signing, freshness, replay, and full pipeline over live TCP."""
import socket
import threading
from datetime import timedelta

import pytest

from ciphermesh import security
from ciphermesh.models import MessageType, WireMessage, utc_now
from ciphermesh.orchestrator import build_default_orchestrator
from ciphermesh.server import serve
from ciphermesh.transport import ProtocolError, recv_message, request, send_message

KEY = "unit-test-signing-key"


def _msg(**kw):
    base = dict(message_type=MessageType.PING, sender="AGENT_A_NODE_01", recipient="AGENT_B_NODE_01")
    base.update(kw)
    return WireMessage(**base)


def test_sign_verify_roundtrip_and_tamper_detection():
    signed = security.sign(_msg(payload={"x": 1}), KEY)
    assert security.verify(signed, KEY) is None
    tampered = signed.model_copy(update={"payload": {"x": 2}})
    assert security.verify(tampered, KEY) == "invalid signature"
    assert security.verify(signed, "other-key") == "invalid signature"
    assert security.verify(_msg(), KEY) == "missing signature"


def test_stale_and_future_messages_rejected():
    old = security.sign(_msg(timestamp=utc_now() - timedelta(minutes=10)), KEY)
    future = security.sign(_msg(timestamp=utc_now() + timedelta(minutes=10)), KEY)
    assert "stale" in security.verify(old, KEY)
    assert "stale" in security.verify(future, KEY)


def test_signature_excludes_legacy_token():
    m = _msg(auth_token="abc")
    assert security.compute_signature(m, KEY) == security.compute_signature(m.model_copy(update={"auth_token": None}), KEY)


@pytest.fixture
def live_gateway():
    orch = build_default_orchestrator(agent_id="AGENT_B_NODE_01", audit_path=":memory:")
    stop, ready, bound = threading.Event(), threading.Event(), []
    t = threading.Thread(target=serve, kwargs=dict(host="127.0.0.1", port=0, agent=orch.agent, signing_key=KEY,
                                                   ready_event=ready, stop_event=stop, bound=bound), daemon=True)
    t.start()
    assert ready.wait(5)
    yield orch, bound[0]
    stop.set()
    t.join(3)


def test_signed_pipeline_over_tcp(live_gateway):
    orch, port = live_gateway
    out = request("127.0.0.1", port, _msg(message_type=MessageType.PROCESS,
                                          payload={"text": "mail bob@example.com"}), signing_key=KEY, timeout=10)
    assert out["payload"]["outcome"]["status"] == "COMPLETED"
    assert "bob@example.com" not in str(out)
    pending = request("127.0.0.1", port, _msg(message_type=MessageType.PROCESS,
                                              payload={"text": "see https://git.corp.local/repo"}), signing_key=KEY)
    review_id = pending["payload"]["outcome"]["review_id"]
    listed = request("127.0.0.1", port, _msg(message_type=MessageType.COMMAND_INSTRUCTION,
                                             payload={"command": "LIST_PENDING_REVIEWS"}), signing_key=KEY)
    assert [r["review_id"] for r in listed["payload"]["reviews"]] == [review_id]
    decided = request("127.0.0.1", port, _msg(message_type=MessageType.APPROVAL, correlation_id=review_id,
                                              payload={"approved": True, "reviewer": "lead"}), signing_key=KEY)
    assert decided["payload"]["outcome"]["provider"] == "local"


def test_unsigned_and_forged_requests_rejected_server_side(live_gateway):
    _, port = live_gateway
    for message in (_msg(), security.sign(_msg(), "forged-key")):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            send_message(sock, message)
            reply = recv_message(sock)
        assert reply.message_type == MessageType.ERROR
        assert "authentication failed" in reply.payload["error"]
        assert security.verify(reply, KEY) is None


def test_replay_of_valid_signed_frame_rejected(live_gateway):
    _, port = live_gateway
    frame = security.sign(_msg(), KEY)
    kinds = []
    for _ in range(2):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            send_message(sock, frame)
            kinds.append(recv_message(sock).message_type)
    assert kinds == [MessageType.ACK, MessageType.ERROR]


def test_client_detects_unsigned_response(live_gateway):
    _, port = live_gateway
    with pytest.raises(ProtocolError):
        request("127.0.0.1", port, _msg(), signing_key="client-has-wrong-key")
