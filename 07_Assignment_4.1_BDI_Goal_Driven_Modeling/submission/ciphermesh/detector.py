"""Deterministic local detectors. Pattern matches are never returned as values.

Design notes
------------
* Every Assignment 1.2 rule (D1-D8) is preserved; token formats that 1.2 matched
  but the v0.4 package silently ALLOWed (``sk-``/``ghp_``/``xoxb-``) are restored.
* Identifier families with a checksum are validated after the regex match
  (Luhn for payment cards, Verhoeff for Aadhaar), which removes most digit-run
  false positives.
* Overlapping findings are merged into one span carrying the highest-risk
  category. The previous implementation replaced the earlier span with the later
  one, which could leave part of a longer match un-redacted.
"""
from __future__ import annotations

import base64
import binascii
import re
from functools import lru_cache
from typing import Callable

from .models import Finding


def luhn_valid(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6), (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4), (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2), (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_valid(digits: str) -> bool:
    check = 0
    for index, char in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[index % 8][int(char)]]
    return check == 0


def _digits(text: str) -> str:
    return re.sub(r"\D", "", text)


def _card(text: str) -> bool:
    d = _digits(text)
    return 13 <= len(d) <= 19 and luhn_valid(d)


def _aadhaar(text: str) -> bool:
    d = _digits(text)
    return len(d) == 12 and verhoeff_valid(d)


# (category, pattern, confidence, rule, severity, optional post-match validator)
DetectorSpec = tuple[str, "re.Pattern[str]", float, str, str, Callable[[str], bool] | None]

PATTERNS: list[DetectorSpec] = [
    ("private_key_header", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), 0.99, "D2", "CRITICAL", None),
    ("db_connection_string", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s@]+@[^\s]+"), 0.97, "D4", "CRITICAL", None),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b"), 0.99, "D1", "CRITICAL", None),
    ("aws_key_assignment", re.compile(r"(?i)\baws_access_key_id\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{16,}"), 0.96, "D1", "CRITICAL", None),
    ("aws_secret_key", re.compile(r"(?i)\baws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}"), 0.97, "D1", "CRITICAL", None),
    ("gcp_service_account_key", re.compile(r"\"private_key_id\"\s*:\s*\"[a-f0-9]{40}\""), 0.97, "D2", "CRITICAL", None),
    ("azure_sas_signature", re.compile(r"(?i)(?:^|[?&])sig=[A-Za-z0-9%+/=._~-]{16,}"), 0.98, "D3", "CRITICAL", None),
    ("azure_storage_key", re.compile(r"(?i)\bAccountKey=[A-Za-z0-9+/]{80,}={0,2}"), 0.98, "D3", "CRITICAL", None),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b"), 0.98, "D4", "CRITICAL", None),
    ("llm_api_key", re.compile(r"\bsk-(?:proj-|ant-[a-z0-9]{2,8}-)?[A-Za-z0-9_-]{20,}\b"), 0.95, "D4", "CRITICAL", None),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), 0.97, "D4", "CRITICAL", None),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0.97, "D4", "CRITICAL", None),
    ("stripe_secret_key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"), 0.98, "D4", "CRITICAL", None),
    ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), 0.93, "D4", "CRITICAL", None),
    ("generic_api_token", re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret|auth[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{12,}"), 0.90, "D4", "CRITICAL", None),
    ("password_assignment", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?(?![*xX•]{3,})[^\s'\",;]{6,}"), 0.88, "D4", "CRITICAL", None),
    ("payment_card", re.compile(r"(?<![\w.-])(?:\d[ -]?){12,18}\d(?![\w-])"), 0.95, "D9", "SENSITIVE", _card),
    ("aadhaar", re.compile(r"(?<![\w.-])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\w-])"), 0.92, "D10", "SENSITIVE", _aadhaar),
    ("pan", re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b"), 0.90, "D11", "SENSITIVE", None),
    ("us_ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), 0.85, "D12", "SENSITIVE", None),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0.95, "D5", "SENSITIVE", None),
    ("phone_in", re.compile(r"(?<![\w+])(?:\+91[ -]?)?[6-9]\d{4}[ -]?\d{5}(?![\w-])"), 0.85, "D6", "SENSITIVE", None),
    ("phone_intl", re.compile(r"(?<![\w+])\+(?!91)\d{1,3}[ -]?(?:\(\d{1,4}\)[ -]?)?\d{2,4}[ -]?\d{3,4}[ -]?\d{3,4}(?![\w-])"), 0.80, "D6", "SENSITIVE", None),
    ("ipv4", re.compile(r"(?<![\d.])(?<![vV])(?<!version )(?<!Version )(?<!VERSION )(?<!release )(?<!build )(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d]|\.\d)"), 0.90, "D7", "SENSITIVE", None),
    ("internal_url", re.compile(r"(?i)\bhttps?://(?:[A-Za-z0-9-]+\.)*(?:internal|corp|intranet|local|lan)(?::\d+)?(?:[/?#][^\s\"'<>)\]]*)?"), 0.80, "D8", "CONFIDENTIAL", None),
]

CRITICAL = {name for name, _, _, _, severity, _ in PATTERNS if severity == "CRITICAL"}
PII = {name for name, _, _, _, severity, _ in PATTERNS if severity == "SENSITIVE"}
REVIEW_CATEGORIES = {"internal_url"}
MAX_FINDINGS = 256

PRIORITY: dict[str, int] = {name: index for index, (name, *_rest) in enumerate(PATTERNS)}
PRIORITY["custom_redaction"] = len(PATTERNS)
POLICY_RULE = {**{c: "R1" for c in CRITICAL}, **{c: "R2" for c in PII},
               "internal_url": "R3", "custom_redaction": "R2"}


@lru_cache(maxsize=256)
def _compile_custom(pattern_text: str) -> "re.Pattern[str] | None":
    try:
        return re.compile(pattern_text)
    except re.error:
        return None


def detect(text: str, custom_patterns: list[str] | None = None) -> list[Finding]:
    found: list[Finding] = []
    for category, pattern, confidence, rule, severity, validator in PATTERNS:
        for match in pattern.finditer(text):
            if validator and not validator(match.group(0)):
                continue
            found.append(Finding(category=category, start=match.start(), end=match.end(),
                                 confidence=confidence, source="regex+checksum" if validator else "regex",
                                 rule=rule, severity=severity))
            if len(found) >= MAX_FINDINGS:
                return _resolve_overlaps(found)
    for pattern_text in custom_patterns or []:
        # Custom expressions are validated and capped before being accepted by the agent.
        pattern = _compile_custom(pattern_text)
        if pattern is None:
            continue
        for match in pattern.finditer(text):
            if match.end() <= match.start():
                continue
            found.append(Finding(category="custom_redaction", start=match.start(), end=match.end(),
                                 confidence=0.85, source="remote_policy_regex", rule="CUSTOM",
                                 severity="SENSITIVE"))
            if len(found) >= MAX_FINDINGS:
                return _resolve_overlaps(found)
    found.extend(_normalized_findings(text, {(f.start, f.end) for f in found}))
    return _resolve_overlaps(found)


_SPACED_RUN = re.compile(r"(?<![\w])(?:[A-Za-z0-9][ ._-]){8,}[A-Za-z0-9](?![\w])")
_BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_OBFUSCATED_EMAIL = re.compile(
    r"(?i)\b[\w.+-]+\s*[\[(]\s*at\s*[\])]\s*[\w-]+(?:\s*(?:[\[(]\s*dot\s*[\])]|\.)\s*[\w-]+)+")


def _normalized_findings(text: str, seen: set[tuple[int, int]]) -> list[Finding]:
    """Defense-in-depth: rescan de-obfuscated views; spans map to the original region."""
    out: list[Finding] = []

    def rescan(view: str, start: int, end: int, how: str) -> None:
        for category, pattern, confidence, rule, severity, validator in PATTERNS:
            match = pattern.search(view)
            if match and (validator is None or validator(match.group(0))):
                if (start, end) not in seen:
                    out.append(Finding(category=category, start=start, end=end,
                                       confidence=round(confidence * 0.9, 4),
                                       source=f"normalized:{how}", rule=rule, severity=severity))
                return

    for m in _SPACED_RUN.finditer(text):
        rescan(re.sub(r"[ ._-]", "", m.group(0)), m.start(), m.end(), "despaced")
    for m in _BASE64_TOKEN.finditer(text):
        token = m.group(0)
        try:
            decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode("ascii")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable() and len(decoded) >= 12:
            rescan(decoded, m.start(), m.end(), "base64")
    for m in _OBFUSCATED_EMAIL.finditer(text):
        view = re.sub(r"(?i)\s*[\[(]\s*at\s*[\])]\s*", "@", m.group(0))
        view = re.sub(r"(?i)\s*[\[(]\s*dot\s*[\])]\s*", ".", view)
        rescan(view, m.start(), m.end(), "deobfuscated_email")
    return out


def _resolve_overlaps(found: list[Finding]) -> list[Finding]:
    """Merge overlapping spans; the merged span takes the highest-risk category."""
    found.sort(key=lambda f: (f.start, -(f.end - f.start)))
    merged: list[Finding] = []
    for finding in found:
        if merged and finding.start < merged[-1].end:
            current = merged[-1]
            winner = finding if PRIORITY.get(finding.category, 99) < PRIORITY.get(current.category, 99) else current
            merged[-1] = winner.model_copy(update={
                "start": current.start,
                "end": max(current.end, finding.end),
                "confidence": max(current.confidence, finding.confidence),
            })
            continue
        merged.append(finding)
    return merged


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
    compiled = _compile_custom(pattern_text)
    if compiled is None:
        return "pattern is not valid regular-expression syntax"
    if compiled.match(""):
        return "pattern must not match the empty string"
    return None
