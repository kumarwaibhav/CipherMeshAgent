"""Command vocabulary and default role capabilities for signed CipherMesh commands.

Assignment 5.1 - Agent Authentication and Host Integrity Verification.
Author: Kumar Waibhav Akshat (RA2212704010027).

The command names reuse the Assignment 2.2 vocabulary (``STATE_SYNC`` and the
``COMMAND_INSTRUCTION`` sub-commands) so the signed channel drives the same
engine actions. ``RELEASE_LOCKDOWN`` is new: once lockdown can only be raised
by an authenticated administrator, it must also be possible to lower it the
same way. ``REPLY`` is used only by the agent for its signed answers.
"""
from __future__ import annotations

TRIGGER_EMERGENCY_LOCKDOWN = "TRIGGER_EMERGENCY_LOCKDOWN"
RELEASE_LOCKDOWN = "RELEASE_LOCKDOWN"
UPDATE_REDACTION_PATTERNS = "UPDATE_REDACTION_PATTERNS"
REQUEST_TELEMETRY_DUMP = "REQUEST_TELEMETRY_DUMP"
STATE_SYNC = "STATE_SYNC"
INSPECT = "INSPECT"
PING = "PING"
REPLY = "REPLY"

# Commands a remote host may send to the agent.
INBOUND_COMMANDS = frozenset({
    TRIGGER_EMERGENCY_LOCKDOWN, RELEASE_LOCKDOWN, UPDATE_REDACTION_PATTERNS,
    REQUEST_TELEMETRY_DUMP, STATE_SYNC, INSPECT, PING,
})
KNOWN_COMMANDS = INBOUND_COMMANDS | {REPLY}

# Commands that change engine state. Everything else is read-only.
MUTATING_COMMANDS = frozenset({TRIGGER_EMERGENCY_LOCKDOWN, RELEASE_LOCKDOWN, UPDATE_REDACTION_PATTERNS, STATE_SYNC})

# What an agent in SAFE MODE (failed self-attestation) will still execute.
SAFE_MODE_COMMANDS = frozenset({REQUEST_TELEMETRY_DUMP, PING})

# STATE_SYNC field-level authorization (checked at C13). A peer gateway may only move fields that
# cannot weaken detection; anything else (custom patterns, secret blocking, PII redaction, review of
# internal URLs, lockdown) needs the security-admin role.
STATE_SYNC_PEER_FIELDS = frozenset({"policy_revision", "policy_version", "provider_allowlist", "max_prompt_bytes"})
STATE_SYNC_PRIVILEGED_ROLE = "security-admin"

# Least-privilege role model (NIST SP 800-207: per-request, per-role authorization).
DEFAULT_ROLES: dict[str, list[str]] = {
    "security-admin": sorted([TRIGGER_EMERGENCY_LOCKDOWN, RELEASE_LOCKDOWN, UPDATE_REDACTION_PATTERNS,
                              STATE_SYNC, REQUEST_TELEMETRY_DUMP, PING]),
    "observer": sorted([REQUEST_TELEMETRY_DUMP, PING]),
    "peer-gateway": sorted([STATE_SYNC, INSPECT, PING]),
    "agent": [],
}
