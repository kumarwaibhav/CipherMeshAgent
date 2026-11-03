"""Provider-neutral decision boundary. Does not make external provider calls."""
from dataclasses import dataclass
from .models import AgentState, Decision, InspectionResult
from .policy import inspect_text


@dataclass(frozen=True)
class PreparedRequest:
    provider: str
    inspection: InspectionResult
    forwardable: bool
    content_for_provider: str | None
    note: str


def prepare_request(text: str, provider: str, state: AgentState) -> PreparedRequest:
    """Inspect content and prepare safe text, without transmitting it anywhere.

    Only ALLOW and REDACT are forwardable. REVIEW and BLOCK always return no
    provider content. A provider adapter must call this function and enforce
    the result immediately before performing its network request.
    """
    if provider not in state.provider_allowlist:
        result = InspectionResult(decision=Decision.BLOCK,
            reasons=["Provider is not in the configured allowlist"],
            policy_version=state.policy_version)
        return PreparedRequest(provider, result, False, None, "Provider denied by allowlist")

    result = inspect_text(text, state)
    if result.decision == Decision.ALLOW:
        return PreparedRequest(provider, result, True, text,
            "Inspection allowed the content unchanged")
    if result.decision == Decision.REDACT:
        return PreparedRequest(provider, result, True, result.sanitized_text,
            "Only the sanitized content may be sent by a provider adapter")
    return PreparedRequest(provider, result, False, None,
        "Content must not be transmitted; review or blocking is required")
