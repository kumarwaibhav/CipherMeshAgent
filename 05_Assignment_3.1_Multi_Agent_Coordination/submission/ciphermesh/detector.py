"""Local baseline detectors. Pattern matches are never returned as values."""
from __future__ import annotations
import re
from .models import Finding

PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), 0.99),
    ("gcp_private_key_header", re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"), 0.99),
    ("azure_sas_signature", re.compile(r"(?i)(?:^|[?&])sig=[A-Za-z0-9%+/=._~-]{16,}"), 0.98),
    ("generic_api_token", re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{12,}"), 0.90),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0.95),
    ("phone", re.compile(r"(?<!\w)(?:\+?\d[\d ()-]{8,}\d)(?!\w)"), 0.70),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), 0.90),
    ("internal_url", re.compile(r"(?i)\bhttps?://(?:[A-Za-z0-9-]+\.)*(?:internal|corp|intranet|local)(?:[./:\w?=&%-]*)"), 0.80),
]

CRITICAL = {"aws_access_key", "gcp_private_key_header", "azure_sas_signature", "generic_api_token"}
PII = {"email", "phone", "ipv4"}
MAX_FINDINGS = 256


def detect(text: str, custom_patterns: list[str] | None = None) -> list[Finding]:
    found: list[Finding] = []
    for category, pattern, confidence in PATTERNS:
        for match in pattern.finditer(text):
            found.append(Finding(category=category, start=match.start(), end=match.end(),
                                 confidence=confidence, source="regex"))
            if len(found) >= MAX_FINDINGS:
                return _resolve_overlaps(found)
    for pattern_text in custom_patterns or []:
        # Custom expressions are validated and capped before being accepted by the agent.
        try:
            pattern = re.compile(pattern_text)
        except re.error:
            continue
        for match in pattern.finditer(text):
            found.append(Finding(category="custom_redaction", start=match.start(), end=match.end(),
                                 confidence=0.85, source="remote_policy_regex"))
            if len(found) >= MAX_FINDINGS:
                return _resolve_overlaps(found)
    return _resolve_overlaps(found)


def _resolve_overlaps(found: list[Finding]) -> list[Finding]:
    priority = {name: i for i, name in enumerate([
        "gcp_private_key_header", "aws_access_key", "azure_sas_signature",
        "generic_api_token", "email", "ipv4", "phone", "internal_url", "custom_redaction"
    ])}
    found.sort(key=lambda f: (f.start, priority.get(f.category, 99), -(f.end - f.start)))
    selected: list[Finding] = []
    for finding in found:
        if selected and finding.start < selected[-1].end:
            if priority.get(finding.category, 99) < priority.get(selected[-1].category, 99):
                selected[-1] = finding
            continue
        selected.append(finding)
    return selected


def redact(text: str, findings: list[Finding]) -> str:
    result = text
    for finding in sorted(findings, key=lambda item: item.start, reverse=True):
        result = result[:finding.start] + f"[REDACTED:{finding.category.upper()}]" + result[finding.end:]
    return result


def validate_custom_pattern(pattern_text: str) -> str | None:
    """Return a reason if a user-supplied remote regex fails conservative guardrails."""
    if not isinstance(pattern_text, str) or not pattern_text or len(pattern_text) > 128:
        return "patterns must be non-empty strings of at most 128 characters"
    if "(?" in pattern_text or re.search(r"\\[1-9]", pattern_text):
        return "lookarounds, inline extensions, and backreferences are not accepted"
    if re.search(r"\([^)]*[+*][^)]*\)[+*{]", pattern_text):
        return "nested quantifiers are not accepted"
    if len(re.findall(r"(?<!\\)[+*?]|(?<!\\)\{", pattern_text)) > 6:
        return "pattern contains too many quantifiers"
    try:
        re.compile(pattern_text)
    except re.error:
        return "pattern is not valid regular-expression syntax"
    return None
