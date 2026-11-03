from ciphermesh.gateway import prepare_request
from ciphermesh.models import AgentState, Decision


def test_block_does_not_prepare_content_for_provider():
    state = AgentState(agent_id="test")
    result = prepare_request("AKIA1234567890ABCDEF", "local", state)
    assert result.inspection.decision == Decision.BLOCK
    assert result.forwardable is False
    assert result.content_for_provider is None


def test_redaction_prepares_only_sanitized_content():
    state = AgentState(agent_id="test")
    result = prepare_request("Email alice@example.com", "local", state)
    assert result.inspection.decision == Decision.REDACT
    assert result.forwardable is True
    assert "alice@example.com" not in result.content_for_provider


def test_unallowlisted_provider_is_blocked():
    state = AgentState(agent_id="test", provider_allowlist=["local"])
    result = prepare_request("hello", "unknown-provider", state)
    assert result.inspection.decision == Decision.BLOCK
    assert not result.forwardable


def test_lockdown_blocks_even_clean_provider_request():
    state = AgentState(agent_id="test", force_block_all=True)
    result = prepare_request("explain recursion", "local", state)
    assert result.inspection.decision == Decision.BLOCK
    assert result.content_for_provider is None
