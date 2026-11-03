"""Assignment 1.2 simple-reflex loop over a mocked live request stream, on the unified detector.

PERCEIVE JSON request -> PARSE envelope -> MATCH condition-action rules -> ACT -> REPEAT.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, TextIO
import sys

from .agent import CipherMeshAgent
from .providers import ALIASES, DEFAULT_PROFILES

SUPPORTED_PROVIDERS = {p.provider_id for p in DEFAULT_PROFILES} | set(ALIASES)
MAX_PROMPT_CHARS = 20_000
DEFAULT_STREAM = Path(__file__).resolve().parent / "data" / "mock_llm_requests.jsonl"


@dataclass(frozen=True)
class LLMRequest:
    timestamp: str
    request_id: str
    provider: str
    model: str
    prompt: str

    @classmethod
    def parse(cls, line: str) -> "LLMRequest":
        try:
            raw = json.loads(line)
            item = cls(timestamp=str(raw["timestamp"]), request_id=str(raw["request_id"]),
                       provider=str(raw["provider"]).lower(), model=str(raw["model"]),
                       prompt=str(raw["prompt"]))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid request envelope: {type(exc).__name__}") from exc
        if item.provider not in SUPPORTED_PROVIDERS:
            raise ValueError(f"unsupported provider '{item.provider[:40]}'")
        if not item.request_id.strip() or not item.model.strip() or not item.prompt.strip():
            raise ValueError("request_id, model, and prompt must be non-empty")
        if len(item.prompt) > MAX_PROMPT_CHARS:
            raise ValueError(f"prompt exceeds the {MAX_PROMPT_CHARS:,}-character limit")
        return item


ACTION_TEXT = {
    "BLOCK": "Do not transmit; notify developer to revoke/rotate exposed credential",
    "REVIEW": "Hold request for developer approval using the redacted preview",
    "REDACT": "Forward only the sanitized prompt",
    "ALLOW": "Forward unchanged under the selected provider adapter",
}


def run(stream: Iterable[str], agent: CipherMeshAgent | None = None, out: TextIO = sys.stdout) -> dict:
    agent = agent or CipherMeshAgent("REFLEX_AGENT", ":memory:")
    agent.state.provider_allowlist = sorted(SUPPORTED_PROVIDERS)
    write = lambda s="": print(s, file=out)  # noqa: E731
    write("CipherMesh Multi-Cloud LLM Privacy Agent | MODE=SIMPLE_REFLEX | STATUS=ONLINE | COST_MODE=LOCAL_FREE")
    write("PROVIDERS=" + ", ".join(sorted(p.provider_id for p in DEFAULT_PROFILES)))
    write("-" * 108)
    tally = {"accepted": 0, "rejected": 0, "ALLOW": 0, "REDACT": 0, "REVIEW": 0, "BLOCK": 0}
    for line_number, line in enumerate(stream, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            request = LLMRequest.parse(line)
        except ValueError as exc:
            tally["rejected"] += 1
            write(f"[INPUT-{line_number:02d}] PARSE_ERROR | {exc} | ACTION=REJECT_ENVELOPE")
            continue
        tally["accepted"] += 1
        fingerprint = hashlib.sha256(request.prompt.encode("utf-8")).hexdigest()[:12]
        write(f"[{tally['accepted']:02d}] {request.timestamp} | PERCEIVE | id={request.request_id} "
              f"provider={request.provider} model={request.model} prompt_sha256={fingerprint}")
        result = agent.inspect(request.prompt, open_review=False)
        if result.findings:
            for f in result.findings:
                write(f"     REASON | {f.rule} matched | type={f.category.upper()} severity={f.severity} "
                      f"confidence={f.confidence:.2f} source={f.source}")
        else:
            write("     REASON | DEFAULT_SAFE_RULE matched | findings=0")
        decision = result.decision.value
        tally[decision] += 1
        write(f"     ACT    | {decision} | {ACTION_TEXT[decision]} | {result.reasons[0]}")
        if decision != "ALLOW" and result.safe_preview:
            write(f"     SAFE_PREVIEW | {result.safe_preview}")
        write("-" * 108)
    write(f"STREAM_COMPLETE | accepted={tally['accepted']} rejected={tally['rejected']} "
          f"ALLOW={tally['ALLOW']} REDACT={tally['REDACT']} REVIEW={tally['REVIEW']} BLOCK={tally['BLOCK']} "
          "| STATUS=STANDBY")
    return tally


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Run the CipherMesh simple-reflex stream agent")
    parser.add_argument("stream", nargs="?", default=str(DEFAULT_STREAM))
    args = parser.parse_args(argv)
    with Path(args.stream).open(encoding="utf-8") as source:
        run(source)


if __name__ == "__main__":
    main()
