from ciphermesh.agent import CipherMeshAgent
from ciphermesh.models import AgentState, Decision, MessageType, WireMessage
from ciphermesh.policy import inspect_text


def test_aws_key_blocks_without_echoing_value():
    result = inspect_text("aws key AKIA1234567890ABCDEF", AgentState(agent_id="test"))
    assert result.decision == Decision.BLOCK
    assert "value" not in result.findings[0].model_dump()


def test_email_redacted():
    result = inspect_text("Contact alice@example.com", AgentState(agent_id="test"))
    assert result.decision == Decision.REDACT
    assert "alice@example.com" not in result.sanitized_text


def test_internal_url_review():
    result = inspect_text("See https://portal.corp.local/admin", AgentState(agent_id="test"))
    assert result.decision == Decision.REVIEW


def test_clean_text_allowed():
    result = inspect_text("Explain binary search simply.", AgentState(agent_id="test"))
    assert result.decision == Decision.ALLOW


def test_oversize_text_blocked():
    state = AgentState(agent_id="test", max_prompt_bytes=5)
    assert inspect_text("123456", state).decision == Decision.BLOCK


def test_lockdown_blocks_clean_text():
    state = AgentState(agent_id="test", force_block_all=True)
    result = inspect_text("ordinary harmless text", state)
    assert result.decision == Decision.BLOCK
    assert "lockdown" in result.reasons[0].lower()


def test_state_sync_applies_allowlisted_fields_and_keeps_identity(tmp_path):
    agent = CipherMeshAgent("B", str(tmp_path / "audit.db"))
    message = WireMessage(message_type=MessageType.STATE_SYNC, sender="A", recipient="B",
                          payload={"state": {"policy_version": "2.0", "policy_revision": 2,
                                             "agent_id": "evil", "sequence": 9000,
                                             "max_prompt_bytes": 2048}})
    response = agent.handle(message)
    assert response["message_type"] == "ACK"
    assert response["payload"]["status"] == "state_applied"
    assert agent.state.agent_id == "B"
    assert agent.state.policy_version == "2.0"
    assert agent.state.policy_revision == 2
    assert agent.state.max_prompt_bytes == 2048
    assert agent.state.sequence != 9000


def test_state_sync_rejects_stale_revision(tmp_path):
    agent = CipherMeshAgent("B", str(tmp_path / "audit.db"))
    agent.state.policy_revision = 4
    message = WireMessage(message_type=MessageType.STATE_SYNC, sender="A", recipient="B",
                          payload={"state": {"policy_version": "1.1", "policy_revision": 3,
                                             "max_prompt_bytes": 2048}})
    response = agent.handle(message)
    assert response["message_type"] == "ERROR"
    assert agent.state.max_prompt_bytes == 65536


def test_remote_lockdown_instruction(tmp_path):
    agent = CipherMeshAgent("B", str(tmp_path / "audit.db"))
    message = WireMessage(message_type=MessageType.COMMAND_INSTRUCTION, sender="A", recipient="B",
                          payload={"command": "TRIGGER_EMERGENCY_LOCKDOWN"})
    response = agent.handle(message)
    assert response["payload"]["status"] == "lockdown_enabled"
    assert agent.inspect("hello world").decision == Decision.BLOCK


def test_remote_redaction_pattern_update(tmp_path):
    agent = CipherMeshAgent("B", str(tmp_path / "audit.db"))
    message = WireMessage(message_type=MessageType.COMMAND_INSTRUCTION, sender="A", recipient="B",
                          payload={"command": "UPDATE_REDACTION_PATTERNS",
                                   "patterns": [r"PROJECT-CODE-[A-Z]{4}"]})
    response = agent.handle(message)
    assert response["message_type"] == "ACK"
    inspected = agent.inspect("Please review PROJECT-CODE-ABCD")
    assert inspected.decision == Decision.REDACT
    assert "PROJECT-CODE-ABCD" not in inspected.sanitized_text


def test_remote_pattern_guardrails_reject_nested_quantifier(tmp_path):
    agent = CipherMeshAgent("B", str(tmp_path / "audit.db"))
    message = WireMessage(message_type=MessageType.COMMAND_INSTRUCTION, sender="A", recipient="B",
                          payload={"command": "UPDATE_REDACTION_PATTERNS", "patterns": [r"(a+)+$"]})
    response = agent.handle(message)
    assert response["message_type"] == "ERROR"
    assert not agent.state.custom_redaction_patterns


def test_telemetry_excludes_prompt_text(tmp_path):
    agent = CipherMeshAgent("B", str(tmp_path / "audit.db"))
    agent.inspect("Contact alice@example.com")
    message = WireMessage(message_type=MessageType.COMMAND_INSTRUCTION, sender="A", recipient="B",
                          payload={"command": "REQUEST_TELEMETRY_DUMP"})
    response = agent.handle(message)
    encoded = str(response)
    assert response["payload"]["status"] == "telemetry_ready"
    assert "alice@example.com" not in encoded
    assert response["payload"]["telemetry"]["metrics"]["total_inspected_prompts"] == 1


def test_wrong_recipient_rejected(tmp_path):
    agent = CipherMeshAgent("B", str(tmp_path / "audit.db"))
    message = WireMessage(message_type=MessageType.PING, sender="A", recipient="C")
    assert agent.handle(message)["message_type"] == "ERROR"
