"""CipherMesh: a simple reflex privacy agent for multi-cloud LLM requests.

Student: Kumar Waibhav Akshat
Register No.: RA2212704010027
Programme: M.Tech Integrated - CSE Data Science | Section: AG1
Course: 21CSE525T Agent Technology | Assignment 1.2

The Unit-1 agent loop is deliberately explicit:
PERCEIVE JSON request -> PARSE -> MATCH condition-action rules -> ACT -> REPEAT.
No prompt is sent to a real provider in this assignment. Production adapters can
forward only ALLOW/REDACT results to AWS Bedrock, Azure AI, GCP Vertex AI, or a
local Ollama endpoint.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Pattern

SUPPORTED_PROVIDERS = {"aws-bedrock", "azure-ai", "gcp-vertex", "ollama-local"}


@dataclass(frozen=True)
class LLMRequest:
    timestamp: str
    request_id: str
    provider: str
    model: str
    prompt: str

    @classmethod
    def parse(cls, line: str) -> "LLMRequest":
        """Parse and validate a single mocked live request."""
        try:
            raw = json.loads(line)
            item = cls(
                timestamp=str(raw["timestamp"]),
                request_id=str(raw["request_id"]),
                provider=str(raw["provider"]).lower(),
                model=str(raw["model"]),
                prompt=str(raw["prompt"]),
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid request envelope: {exc}") from exc
        if item.provider not in SUPPORTED_PROVIDERS:
            raise ValueError(f"unsupported provider '{item.provider}'")
        if not item.request_id.strip() or not item.model.strip() or not item.prompt.strip():
            raise ValueError("request_id, model, and prompt must be non-empty")
        if len(item.prompt) > 20_000:
            raise ValueError("prompt exceeds the 20,000-character prototype limit")
        return item


@dataclass(frozen=True)
class Detector:
    detector_id: str
    label: str
    severity: str
    action: str
    pattern: Pattern[str]
    replacement: str


# Values in the mock stream are synthetic examples and are intentionally invalid.
DETECTORS: tuple[Detector, ...] = (
    Detector("D1", "AWS_ACCESS_KEY_ID", "CRITICAL", "BLOCK", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[AWS_ACCESS_KEY_REDACTED]"),
    Detector("D2", "GCP_PRIVATE_KEY", "CRITICAL", "BLOCK", re.compile(r"-----BEGIN PRIVATE KEY-----", re.I), "[PRIVATE_KEY_REDACTED]"),
    Detector("D3", "AZURE_SAS_SIGNATURE", "CRITICAL", "BLOCK", re.compile(r"[?&]sig=[A-Za-z0-9%+/=_-]{16,}", re.I), "&sig=[AZURE_SAS_REDACTED]"),
    Detector("D4", "GENERIC_API_TOKEN", "CRITICAL", "BLOCK", re.compile(r"\b(?:sk|ghp|xoxb)-[A-Za-z0-9_-]{16,}\b"), "[API_TOKEN_REDACTED]"),
    Detector("D5", "EMAIL_ADDRESS", "SENSITIVE", "REDACT", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "[EMAIL_REDACTED]"),
    Detector("D6", "INDIA_PHONE_NUMBER", "SENSITIVE", "REDACT", re.compile(r"(?<!\d)(?:\+91[- ]?)?[6-9]\d{9}(?!\d)"), "[PHONE_REDACTED]"),
    Detector("D7", "IP_ADDRESS", "SENSITIVE", "REDACT", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP_REDACTED]"),
    Detector("D8", "INTERNAL_URL", "CONFIDENTIAL", "REVIEW", re.compile(r"https?://(?:[\w-]+\.)*(?:internal|corp|local)(?::\d+)?(?:/\S*)?", re.I), "[INTERNAL_URL_REDACTED]"),
)


@dataclass(frozen=True)
class Finding:
    detector: Detector
    count: int


def inspect(prompt: str) -> tuple[list[Finding], str]:
    """Return detector findings and a privacy-safe redacted prompt."""
    findings: list[Finding] = []
    sanitized = prompt
    for detector in DETECTORS:
        matches = detector.pattern.findall(sanitized)
        if matches:
            findings.append(Finding(detector, len(matches)))
            sanitized = detector.pattern.sub(detector.replacement, sanitized)
    return findings, sanitized


def decide(findings: list[Finding]) -> tuple[str, str]:
    """Apply highest-risk-wins condition-action policy."""
    actions = {finding.detector.action for finding in findings}
    if "BLOCK" in actions:
        return "BLOCK", "Do not transmit; notify developer to revoke/rotate exposed credential"
    if "REVIEW" in actions:
        return "REVIEW", "Hold request for developer approval using the redacted preview"
    if "REDACT" in actions:
        return "REDACT", "Forward only the sanitized prompt"
    return "ALLOW", "Forward unchanged under the selected provider adapter"


def run(stream: Iterable[str]) -> None:
    """Consume the mock data stream and log auditable reactive decisions."""
    print("CipherMesh Multi-Cloud LLM Privacy Agent | STATUS=ONLINE | COST_MODE=LOCAL_FREE")
    print("PROVIDERS=aws-bedrock, azure-ai, gcp-vertex, ollama-local")
    print("-" * 108)
    accepted = 0
    for line_number, line in enumerate(stream, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            request = LLMRequest.parse(line)
        except ValueError as exc:
            print(f"[INPUT-{line_number:02d}] PARSE_ERROR | {exc} | ACTION=REJECT_ENVELOPE")
            continue
        accepted += 1
        fingerprint = hashlib.sha256(request.prompt.encode()).hexdigest()[:12]
        print(
            f"[{accepted:02d}] {request.timestamp} | PERCEIVE | id={request.request_id} "
            f"provider={request.provider} model={request.model} prompt_sha256={fingerprint}"
        )
        findings, sanitized = inspect(request.prompt)
        if findings:
            for finding in findings:
                d = finding.detector
                print(f"     REASON | {d.detector_id} matched | type={d.label} severity={d.severity} count={finding.count}")
        else:
            print("     REASON | DEFAULT_SAFE_RULE matched | findings=0")
        decision, explanation = decide(findings)
        print(f"     ACT    | {decision} | {explanation}")
        if decision in {"REDACT", "REVIEW", "BLOCK"}:
            print(f"     SAFE_PREVIEW | {sanitized}")
        print("-" * 108)
    print(f"STREAM_COMPLETE | accepted_requests={accepted} | STATUS=STANDBY")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the CipherMesh reflex privacy agent")
    parser.add_argument("stream", nargs="?", default=str(Path(__file__).with_name("mock_llm_requests.jsonl")))
    args = parser.parse_args()
    with Path(args.stream).open(encoding="utf-8") as source:
        run(source)


if __name__ == "__main__":
    main()
