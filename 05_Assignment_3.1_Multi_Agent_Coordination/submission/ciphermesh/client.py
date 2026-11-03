"""Agent-A CLI for state sync, inspection, and proactive instructions."""
from __future__ import annotations
import argparse
import json
import os
from .models import MessageType, WireMessage
from .transport import ProtocolError, request


def main():
    parser = argparse.ArgumentParser(description="CipherMesh distributed agent client (Agent-A)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.getenv("CIPHERMESH_PORT", "9052")))
    parser.add_argument("--sender", default="AGENT_A_NODE_01")
    parser.add_argument("--recipient", default="AGENT_B_NODE_01")
    parser.add_argument("--token", default=os.getenv("CIPHERMESH_SHARED_TOKEN", ""))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("ping", help="check network endpoint and agent health")
    sub.add_parser("sync-state", help="transfer active policy parameters to Agent-B")
    inspect_parser = sub.add_parser("inspect", help="ask Agent-B to inspect a text payload")
    inspect_parser.add_argument("--text", required=True)
    sub.add_parser("lockdown", help="send TRIGGER_EMERGENCY_LOCKDOWN")
    patterns = sub.add_parser("update-patterns", help="append custom redaction regex patterns")
    patterns.add_argument("patterns", nargs="+", help="one or more safe regex expressions")
    sub.add_parser("telemetry", help="request metadata-only telemetry snapshot")
    args = parser.parse_args()

    payload: dict = {}
    kind = MessageType.PING
    if args.command == "sync-state":
        kind = MessageType.STATE_SYNC
        payload = {"state": {
            "policy_version": "1.1",
            "policy_revision": 2,
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
        kind = MessageType.INSPECT
        payload = {"text": args.text}
    elif args.command == "lockdown":
        kind = MessageType.COMMAND_INSTRUCTION
        payload = {"command": "TRIGGER_EMERGENCY_LOCKDOWN"}
    elif args.command == "update-patterns":
        kind = MessageType.COMMAND_INSTRUCTION
        payload = {"command": "UPDATE_REDACTION_PATTERNS", "patterns": args.patterns}
    elif args.command == "telemetry":
        kind = MessageType.COMMAND_INSTRUCTION
        payload = {"command": "REQUEST_TELEMETRY_DUMP"}

    message = WireMessage(message_type=kind, sender=args.sender, recipient=args.recipient,
                          auth_token=args.token or None, payload=payload)
    try:
        response = request(args.host, args.port, message)
        print(json.dumps(response, indent=2))
        if response.get("message_type") == "ERROR":
            raise SystemExit(2)
    except (OSError, TimeoutError, ConnectionError, ValueError, ProtocolError) as exc:
        raise SystemExit(f"CipherMesh request failed: {exc}")


if __name__ == "__main__":
    main()
