"""Agent-A CLI for state sync, inspection, end-to-end processing, and proactive instructions."""
from __future__ import annotations
import argparse
import json
import os
from .models import MessageType, WireMessage
from .transport import ProtocolError, request


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CipherMesh distributed agent client (Agent-A)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.getenv("CIPHERMESH_PORT", "9052")))
    parser.add_argument("--sender", default="AGENT_A_NODE_01")
    parser.add_argument("--recipient", default="AGENT_B_NODE_01")
    parser.add_argument("--token", default=os.getenv("CIPHERMESH_SHARED_TOKEN", ""))
    parser.add_argument("--signing-key", default=os.getenv("CIPHERMESH_SIGNING_KEY", ""))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("ping", help="check network endpoint and agent health")
    sync = sub.add_parser("sync-state", help="transfer active policy parameters to Agent-B")
    sync.add_argument("--revision", type=int, default=2)
    inspect_parser = sub.add_parser("inspect", help="ask Agent-B to inspect a text payload")
    inspect_parser.add_argument("--text", required=True)
    process = sub.add_parser("process", help="run the full inspect-route-negotiate-call pipeline on Agent-B")
    process.add_argument("--text", required=True)
    process.add_argument("--provider", default=None, help="optional provider hint")
    approve = sub.add_parser("approve", help="approve or deny a pending REVIEW ticket")
    approve.add_argument("review_id")
    approve.add_argument("--deny", action="store_true")
    approve.add_argument("--reviewer", default="security-reviewer")
    sub.add_parser("reviews", help="list pending REVIEW tickets")
    sub.add_parser("lockdown", help="send TRIGGER_EMERGENCY_LOCKDOWN")
    patterns = sub.add_parser("update-patterns", help="append custom redaction regex patterns")
    patterns.add_argument("patterns", nargs="+", help="one or more safe regex expressions")
    sub.add_parser("telemetry", help="request metadata-only telemetry snapshot")
    return parser


def build_message(args) -> WireMessage:
    payload: dict = {}
    kind = MessageType.PING
    correlation = None
    if args.command == "sync-state":
        kind = MessageType.STATE_SYNC
        payload = {"state": {
            "policy_version": f"1.{max(args.revision - 1, 0)}",
            "policy_revision": args.revision,
            "provider_allowlist": ["local", "aws-bedrock", "azure-ai", "gcp-vertex"],
            "max_prompt_bytes": 65536,
            "require_review_for_internal_urls": True,
            "redact_email_phone_ip": True,
            "block_critical_secrets": True,
            "custom_redaction_patterns": [],
            # Included as operational context; Agent-B never trusts incoming counters.
            "metrics": {"total_inspected_prompts": 0, "total_secrets_blocked": 0, "mean_latency_ms": 0.0},
        }}
    elif args.command == "inspect":
        kind, payload = MessageType.INSPECT, {"text": args.text}
    elif args.command == "process":
        kind, payload = MessageType.PROCESS, {"text": args.text, "provider": args.provider}
    elif args.command == "approve":
        kind, correlation = MessageType.APPROVAL, args.review_id
        payload = {"approved": not args.deny, "reviewer": args.reviewer}
    elif args.command == "reviews":
        kind, payload = MessageType.COMMAND_INSTRUCTION, {"command": "LIST_PENDING_REVIEWS"}
    elif args.command == "lockdown":
        kind, payload = MessageType.COMMAND_INSTRUCTION, {"command": "TRIGGER_EMERGENCY_LOCKDOWN"}
    elif args.command == "update-patterns":
        kind = MessageType.COMMAND_INSTRUCTION
        payload = {"command": "UPDATE_REDACTION_PATTERNS", "patterns": args.patterns}
    elif args.command == "telemetry":
        kind, payload = MessageType.COMMAND_INSTRUCTION, {"command": "REQUEST_TELEMETRY_DUMP"}
    return WireMessage(message_type=kind, sender=args.sender, recipient=args.recipient,
                       correlation_id=correlation, auth_token=args.token or None, payload=payload)


def main(argv=None):
    args = build_parser().parse_args(argv)
    message = build_message(args)
    try:
        response = request(args.host, args.port, message, signing_key=args.signing_key,
                           timeout=30.0 if args.command in {"process", "approve"} else 5.0)
        print(json.dumps(response, indent=2))
        if response.get("message_type") == "ERROR":
            raise SystemExit(2)
    except (OSError, TimeoutError, ConnectionError, ValueError, ProtocolError) as exc:
        raise SystemExit(f"CipherMesh request failed: {exc}")


if __name__ == "__main__":
    main()
