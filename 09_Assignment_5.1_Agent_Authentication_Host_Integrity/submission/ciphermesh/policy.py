"""Deterministic, ordered condition-action policy for inspected text.

Priority: lockdown > R5 size > R1 critical secret (BLOCK) > R3 internal URL
(REVIEW) > R2 PII / custom pattern (REDACT) > R4 default (ALLOW).
"""
from __future__ import annotations
from time import perf_counter
from .detector import CRITICAL, PII, detect, redact
from .models import AgentState, Decision, InspectionResult


def inspect_text(text: str, state: AgentState) -> InspectionResult:
    started = perf_counter()
    result = _inspect(text, state)
    result.latency_ms = round((perf_counter() - started) * 1000.0, 4)
    return result


def _inspect(text: str, state: AgentState) -> InspectionResult:
    size = len(text.encode("utf-8"))
    if state.force_block_all:
        return InspectionResult(decision=Decision.BLOCK, reasons=["Emergency lockdown active: all outbound content is blocked"],
                                policy_version=state.policy_version)
    if size > state.max_prompt_bytes:
        return InspectionResult(decision=Decision.BLOCK, reasons=["R5: payload exceeds configured byte limit"],
                                policy_version=state.policy_version)
    findings = detect(text, state.custom_redaction_patterns)
    categories = {item.category for item in findings}
    preview = redact(text, findings) if findings else None
    if state.block_critical_secrets and categories & CRITICAL:
        return InspectionResult(decision=Decision.BLOCK, findings=findings, safe_preview=preview,
                                reasons=["R1: critical credential/token pattern detected; do not transmit; revoke/rotate"],
                                policy_version=state.policy_version)
    if state.require_review_for_internal_urls and "internal_url" in categories:
        return InspectionResult(decision=Decision.REVIEW, findings=findings, safe_preview=preview,
                                reasons=["R3: internal/corporate URL requires human approval"],
                                policy_version=state.policy_version)
    if (state.redact_email_phone_ip and categories & PII) or "custom_redaction" in categories:
        return InspectionResult(decision=Decision.REDACT, findings=findings,
                                sanitized_text=preview, safe_preview=preview,
                                reasons=["R2: PII or custom redaction pattern detected; sanitize before transmission"],
                                policy_version=state.policy_version)
    return InspectionResult(decision=Decision.ALLOW, findings=findings, sanitized_text=text,
                            reasons=["R4: no policy-triggering sensitive findings"],
                            policy_version=state.policy_version)
