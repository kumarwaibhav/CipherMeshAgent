"""Cryptographically enhanced CipherMesh agent node.

Assignment 5.1 - Agent Authentication and Host Integrity Verification.
Author: Kumar Waibhav Akshat (RA2212704010027).

:class:`SecureCipherMeshAgent` wraps the real Unit 1-3 engine
(:class:`ciphermesh.agent.CipherMeshAgent`, whose ``AgentState`` drives
``policy.inspect_text``). It accepts raw payloads from two channels:

* the TCP network loop (:mod:`ciphermesh.trust.secure_server`), and
* the local *system-command* channel - a spool directory or stdin - handled by
  :class:`SystemCommandChannel`.

Each raw payload goes through :class:`~ciphermesh.trust.verifier.CommandVerifier`
first. Only an accepted, fully authenticated and authorised command is turned
into an engine action. The agent signs every reply with its own Ed25519 key and
writes one JSONL audit event per decision. Audit events hold metadata only:
never payload values, prompt text, regex patterns, signatures or key material.

At start-up the agent attests its own code against the signed release
manifest. On mismatch it refuses to start (``strict_integrity=True``) or runs in
SAFE MODE, where the verifier allows only read-only telemetry. A trust store
that differs from the sealed copy always stops start-up.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import stat
import sys
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..agent import CipherMeshAgent
from ..models import AuditEvent, MessageType, WireMessage
from ..models import utc_now as engine_now
from . import commands as cmd
from .canonical import canonicalize
from .envelope import REPLY_CONTEXT, build_header, encode, sign, utc_now
from .integrity import IntegrityError, IntegrityReport, package_root, self_attest
from .keys import SigningIdentity, TrustStore
from .verifier import CHECKPOINT_NAMES, CommandVerifier, FailureLimiter, Origin, Verdict, lockout_key

LOG = logging.getLogger("ciphermesh.trust.agent")
UNAUTHENTICATED_PEER = "unauthenticated-peer"
GENERIC_REJECTION = "request rejected by the CipherMesh trust gate"


def _safe(text: Any, limit: int = 300) -> str:
    """Neutralise control characters so attacker-chosen strings cannot forge log lines."""
    value = str(text)
    value = "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in value)
    return value if len(value) <= limit else value[:limit] + "..."


def outcome_text(result: dict) -> str:
    """Short, value-free description of an execution result (for logs and audit)."""
    if result.get("status"):
        return str(result["status"])
    if isinstance(result.get("inspection"), dict):
        return f"inspection decision={result['inspection'].get('decision')}"
    if result.get("error"):
        return "error: " + str(result["error"])
    return "ok"


class SecurityAuditLog:
    """Append-only JSON Lines audit trail (one object per event, metadata only)."""

    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self.events: list[dict] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, **fields: Any) -> dict:
        record = {"ts": utc_now().isoformat(timespec="milliseconds").replace("+00:00", "Z"), "event": event}
        record.update({k: v for k, v in fields.items() if v is not None})
        with self._lock:
            self.events.append(record)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, sort_keys=False, ensure_ascii=True) + "\n")
        return record


@dataclass
class HandleResult:
    verdict: Verdict
    status: str
    result: dict
    incident: str | None
    reply: bytes
    state_before: dict
    state_after: dict

    @property
    def state_changed(self) -> bool:
        return self.state_before["fingerprint"] != self.state_after["fingerprint"]


@dataclass
class AgentConfig:
    max_frame: int = 65536
    max_skew_s: float = 60.0
    lockout_threshold: int = 5
    lockout_window_s: float = 60.0
    lockout_s: float = 300.0
    strict_integrity: bool = False
    frame_deadline_s: float = 5.0          # whole frame (prefix + body) must arrive within this time
    max_connections_per_ip: int = 4        # slow-client / connection-exhaustion cap per peer address
    local_uids: set[int] = field(default_factory=lambda: {os.getuid()})


class SecureCipherMeshAgent:
    def __init__(self, identity: SigningIdentity, trust_store: TrustStore, *, signed_manifest: dict,
                 release_public_key: Ed25519PublicKey, code_root: str | Path | None = None,
                 trust_store_path: str | Path | None = None, engine: CipherMeshAgent | None = None,
                 audit_log_path: str | Path | None = None, config: AgentConfig | None = None,
                 clock: Callable[[], datetime] = utc_now):
        self.config = config or AgentConfig()
        self.trust = trust_store
        self.agent_id = trust_store.agent_id
        if identity.host_id != self.agent_id:
            raise ValueError(f"signing identity {identity.host_id} is not the trust store agent {self.agent_id}")
        own = trust_store.key(identity.key_id)
        if own is None or own[0].host_id != self.agent_id:
            raise ValueError("the agent's own public key is not registered for it in the trust store")
        self.identity = identity
        self.audit = SecurityAuditLog(audit_log_path)
        self.alerts: list[dict] = []
        self.history: deque[HandleResult] = deque(maxlen=1000)
        self._incident_counter = 0
        self._lock = threading.Lock()

        # ---- self-attestation (host integrity of this node) -------------------------------
        root = Path(code_root) if code_root else package_root()
        self.integrity: IntegrityReport = self_attest(root, signed_manifest, release_public_key, trust_store_path)
        self.safe_mode = not self.integrity.ok
        self.attestation_digest = self.integrity.measured_digest
        self.audit.write("SELF_ATTESTATION", agent_id=self.agent_id, mode=self.integrity.mode,
                         ok=self.integrity.ok, files_checked=self.integrity.files_checked,
                         mismatched=[m["file"] for m in self.integrity.mismatched],
                         missing=self.integrity.missing, unexpected=self.integrity.unexpected,
                         bytecode=self.integrity.bytecode, reasons=self.integrity.reasons, measured_digest=self.integrity.measured_digest)
        if self.integrity.ok:
            LOG.info("[AGENT] self-attestation PASSED: %d source files match signed release %s (digest %s...)",
                     self.integrity.files_checked, self.integrity.release, self.attestation_digest[:16])
        else:
            LOG.error("[AGENT] self-attestation FAILED: %s", "; ".join(self.integrity.reasons))
            # A changed trust store could add a rogue admin key; SAFE MODE would still trust it for
            # telemetry, so this case always stops start-up, whatever strict_integrity says.
            if self.config.strict_integrity or self.integrity.trust_store_ok is False:
                self.audit.write("STARTUP_REFUSED", agent_id=self.agent_id, reasons=self.integrity.reasons)
                raise IntegrityError("agent refuses to start: " + "; ".join(self.integrity.reasons))
            LOG.warning("[AGENT] entering SAFE MODE: only %s will be executed", sorted(cmd.SAFE_MODE_COMMANDS))
            self.audit.write("SAFE_MODE_ENTERED", agent_id=self.agent_id, allowed=sorted(cmd.SAFE_MODE_COMMANDS))

        self.engine = engine or CipherMeshAgent(self.agent_id, audit_path=":memory:")
        limiter = FailureLimiter(self.config.lockout_threshold, self.config.lockout_window_s, self.config.lockout_s)
        self.verifier = CommandVerifier(trust_store, self.agent_id, max_frame=self.config.max_frame,
                                        max_skew_s=self.config.max_skew_s, limiter=limiter, clock=clock,
                                        safe_mode=self.safe_mode, local_uids=self.config.local_uids,
                                        alert_sink=self._on_alert)

    # ------------------------------------------------------------- state view
    def state_summary(self) -> dict:
        """Metadata-only fingerprint of the security-relevant engine state."""
        with self.engine._lock:
            state = self.engine.state
            material = {
                "force_block_all": state.force_block_all,
                "custom_redaction_patterns": list(state.custom_redaction_patterns),
                "policy_version": state.policy_version,
                "policy_revision": state.policy_revision,
                "provider_allowlist": list(state.provider_allowlist),
                "max_prompt_bytes": state.max_prompt_bytes,
                "require_review_for_internal_urls": state.require_review_for_internal_urls,
                "redact_email_phone_ip": state.redact_email_phone_ip,
                "block_critical_secrets": state.block_critical_secrets,
            }
        patterns_hash = hashlib.sha256(canonicalize(material["custom_redaction_patterns"])).hexdigest()
        return {
            "fingerprint": hashlib.sha256(canonicalize(material)).hexdigest()[:16],
            "lockdown": material["force_block_all"],
            "pattern_count": len(material["custom_redaction_patterns"]),
            "patterns_sha256": patterns_hash[:12],
            "policy_revision": material["policy_revision"],
        }

    # ------------------------------------------------------------ main entry
    def handle_frame(self, raw: bytes, origin: Origin, declared_length: int | None = None) -> HandleResult:
        before = self.state_summary()
        verdict = self.verifier.verify(raw, origin, declared_length)
        incident = None
        if verdict.accepted:
            status, result = self._execute(verdict)
        else:
            incident = self._next_incident()
            status, result = "REJECTED", {"error": GENERIC_REJECTION}
        after = self.state_summary()
        self._record(verdict, status, result, incident, before, after)
        reply = self._reply(verdict, status, result, incident)
        outcome = HandleResult(verdict, status, result, incident, reply, before, after)
        self.history.append(outcome)
        return outcome

    def record_transport_failure(self, origin: Origin, reason: str, detail: str) -> None:
        """A connection that never delivered a complete frame (timeout, per-IP cap): audit it as an L0
        failure and count it against (address, '-') so slow-client floods also lead to lockout."""
        key = lockout_key(origin.address, None)
        incident = self._next_incident()
        triggered = self.verifier.limiter.record_failure(key)
        self.audit.write("COMMAND_REJECTED", agent_id=self.agent_id, channel=origin.channel, origin=origin.label(),
                         checkpoint="L0", checkpoint_name="SOURCE_LOCKOUT", reason=reason, detail=_safe(detail),
                         incident=incident, status="REJECTED")
        LOG.warning("[AGENT] BLOCKED UNAUTHORIZED REQUEST %s: origin=%s checkpoint=L0 reason=%s (%s)", incident,
                    origin.label(), reason, _safe(detail))
        if triggered:
            self._on_alert({"alert": "SOURCE_LOCKOUT", "origin": origin.label(), "sender_host": None,
                            "checkpoint": "L0", "reason": reason,
                            "detail": f"{self.verifier.limiter.threshold} failed connections; {key} locked"})

    def _next_incident(self) -> str:
        with self._lock:
            self._incident_counter += 1
            return f"INC-{self._incident_counter:05d}"

    # -------------------------------------------------------------- execution
    def _execute(self, verdict: Verdict) -> tuple[str, dict]:
        message = verdict.message
        assert message is not None
        command, payload, header = message.header.command, message.payload, message.header
        if command == cmd.RELEASE_LOCKDOWN:
            with self.engine._lock:
                self.engine.state.force_block_all = False
                self.engine.state.updated_at = engine_now()
                self.engine.audit.write(AuditEvent(agent_id=self.agent_id, event_type="emergency_lockdown_released",
                                                   message_id=header.msg_id, details={"by": header.sender_host}))
            return "ACCEPTED", {"status": "lockdown_released", "current_policy_mode": "STRICT"}
        if command in (cmd.TRIGGER_EMERGENCY_LOCKDOWN, cmd.UPDATE_REDACTION_PATTERNS, cmd.REQUEST_TELEMETRY_DUMP):
            wire = WireMessage(message_type=MessageType.COMMAND_INSTRUCTION, sender=header.sender_host,
                               recipient=self.agent_id, message_id=header.msg_id,
                               payload={"command": command, **payload})
        elif command == cmd.STATE_SYNC:
            wire = WireMessage(message_type=MessageType.STATE_SYNC, sender=header.sender_host,
                               recipient=self.agent_id, message_id=header.msg_id, payload=payload)
        elif command == cmd.INSPECT:
            wire = WireMessage(message_type=MessageType.INSPECT, sender=header.sender_host,
                               recipient=self.agent_id, message_id=header.msg_id, payload=payload)
        elif command == cmd.PING:
            wire = WireMessage(message_type=MessageType.PING, sender=header.sender_host,
                               recipient=self.agent_id, message_id=header.msg_id)
        else:  # unreachable: C2 restricts commands to INBOUND_COMMANDS
            return "FAILED", {"error": "no executor for command"}
        reply = self.engine.handle(wire)
        if reply["message_type"] == MessageType.ERROR.value:
            return "FAILED", {"error": reply["payload"].get("error", "engine error")}
        return "ACCEPTED", reply["payload"]

    # --------------------------------------------------------------- outputs
    def _record(self, verdict: Verdict, status: str, result: dict, incident: str | None,
                before: dict, after: dict) -> None:
        common = dict(agent_id=self.agent_id, channel=verdict.origin.channel, origin=verdict.origin.label(),
                      msg_id=verdict.msg_id, sender_host=verdict.sender_host, key_id=verdict.key_id,
                      command=verdict.command, latency_us=round(verdict.latency_us, 1),
                      state_before=before["fingerprint"], state_after=after["fingerprint"],
                      state_changed=before["fingerprint"] != after["fingerprint"])
        if verdict.accepted:
            self.audit.write("COMMAND_ACCEPTED", checkpoint="PASS", checkpoint_name="ALL_CHECKPOINTS_PASSED",
                             reason="ACCEPTED", status=status,
                             outcome=_safe(outcome_text(result), 80), **common)
            LOG.info("[AGENT] ACCEPTED %s from %s via %s (13/13 checkpoints, %.0f us) -> %s; state %s -> %s",
                     verdict.command, verdict.sender_host, verdict.origin.label(), verdict.latency_us,
                     _safe(outcome_text(result), 60), before["fingerprint"],
                     after["fingerprint"])
        else:
            self.audit.write("COMMAND_REJECTED", checkpoint=verdict.checkpoint,
                             checkpoint_name=CHECKPOINT_NAMES.get(verdict.checkpoint), reason=verdict.reason,
                             detail=_safe(verdict.detail), incident=incident, status=status, **common)
            LOG.warning("[AGENT] BLOCKED UNAUTHORIZED REQUEST %s: command=%s claimed_host=%s origin=%s "
                        "checkpoint=%s %s reason=%s (%s)", incident, _safe(verdict.command or "?", 40),
                        _safe(verdict.sender_host or "?", 64), verdict.origin.label(), verdict.checkpoint,
                        CHECKPOINT_NAMES.get(verdict.checkpoint), verdict.reason, _safe(verdict.detail))

    def _on_alert(self, alert: dict) -> None:
        alert = {k: _safe(v) if isinstance(v, str) else v for k, v in alert.items()}
        self.alerts.append(alert)
        self.audit.write("SECURITY_ALERT", agent_id=self.agent_id, **alert)
        LOG.error("[AGENT] SECURITY ALERT %s: origin=%s claimed_host=%s - %s", alert["alert"], alert["origin"],
                  alert.get("sender_host") or "?", alert["detail"])

    def _reply(self, verdict: Verdict, status: str, result: dict, incident: str | None) -> bytes:
        recipient = verdict.sender_host if verdict.sender_host else UNAUTHENTICATED_PEER
        payload = {"in_reply_to": verdict.msg_id or "unknown", "status": status, "incident": incident,
                   "result": result}
        header = build_header(self.identity, recipient, cmd.REPLY, payload, self.attestation_digest)
        return encode(sign(self.identity, header, payload, REPLY_CONTEXT))


class SystemCommandChannel:
    """Local system-command channel: signed command files dropped into a spool directory.

    The spool directory must not be writable by group/others. Each file's owner
    and mode are passed to the verifier (checkpoint C7 for the local channel), so
    a command planted by another local account, or left world-writable where
    anyone could have swapped it, is rejected even if its signature is valid.
    """

    def __init__(self, agent: SecureCipherMeshAgent, spool_dir: str | Path):
        self.agent = agent
        self.spool = Path(spool_dir)
        if not self.spool.exists():
            self.spool.mkdir(parents=True, mode=0o700)
            os.chmod(self.spool, 0o700)
        for sub in ("incoming", "processed", "rejected", "replies"):
            (self.spool / sub).mkdir(exist_ok=True, mode=0o700)
        mode = stat.S_IMODE(self.spool.stat().st_mode)
        if mode & 0o022:
            raise PermissionError(f"spool directory {self.spool} is writable by group/others ({oct(mode)})")

    @property
    def incoming(self) -> Path:
        return self.spool / "incoming"

    def process_file(self, path: Path) -> HandleResult | None:
        try:
            return self._process_file(path)
        except FileNotFoundError:
            LOG.warning("[AGENT] spool file %s vanished before it could be processed; skipped", _safe(path.name))
            return None

    def _process_file(self, path: Path) -> HandleResult:
        # O_NOFOLLOW + fstat on the open descriptor: owner/mode belong to the bytes actually read
        # (no check-then-open race) and a symlink is never followed.
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            st = os.lstat(path)
            origin = Origin("system", "local", path.name, file_uid=st.st_uid, file_mode=stat.S_IMODE(st.st_mode),
                            regular_file=False)
            raw, declared = b"", 0
        else:
            with os.fdopen(fd, "rb") as handle:
                st = os.fstat(handle.fileno())
                regular = stat.S_ISREG(st.st_mode)
                origin = Origin("system", "local", path.name, file_uid=st.st_uid,
                                file_mode=stat.S_IMODE(st.st_mode), regular_file=regular)
                declared = st.st_size if regular else 0
                too_big = declared > self.agent.config.max_frame
                raw = handle.read(self.agent.config.max_frame + 1) if regular and not too_big else b""
        outcome = self.agent.handle_frame(raw, origin, declared_length=declared)
        target = self.spool / ("processed" if outcome.verdict.accepted else "rejected") / path.name
        os.replace(path, target)
        (self.spool / "replies" / (path.stem + ".reply.json")).write_bytes(outcome.reply)
        return outcome

    def process_spool(self) -> list[HandleResult]:
        outcomes = (self.process_file(p) for p in sorted(self.incoming.glob("*.json")))
        return [o for o in outcomes if o is not None]

    def process_stdin(self) -> HandleResult:
        st = os.fstat(sys.stdin.fileno())
        raw = sys.stdin.buffer.read(self.agent.config.max_frame + 1)
        origin = Origin("system", "local", "stdin", file_uid=st.st_uid, file_mode=stat.S_IMODE(st.st_mode))
        return self.agent.handle_frame(raw, origin)


def build_agent_from_dirs(trust_dir: str | Path, keys_dir: str | Path, passphrase: bytes | None,
                          audit_log_path: str | Path | None = None, code_root: str | Path | None = None,
                          config: AgentConfig | None = None) -> SecureCipherMeshAgent:
    """Load the trust store, the pinned release key, the signed manifest and the agent key from disk."""
    from .integrity import load_signed_manifest
    from .keys import load_public_key
    trust_dir, keys_dir = Path(trust_dir), Path(keys_dir)
    trust_path = trust_dir / "trusted_hosts.json"
    store = TrustStore.load(trust_path)
    identity = SigningIdentity.load(store.agent_id, keys_dir / f"{store.agent_id}.key.pem", passphrase)
    return SecureCipherMeshAgent(identity, store, signed_manifest=load_signed_manifest(trust_dir / "release_manifest.json"),
                                 release_public_key=load_public_key(trust_dir / "release_signer.pub"),
                                 code_root=code_root, trust_store_path=trust_path, audit_log_path=audit_log_path,
                                 config=config)


def main(argv: list[str] | None = None) -> int:
    from .provision import DEFAULT_KEYS_DIR, DEFAULT_TRUST_DIR, ensure_provisioned, passphrase_from_env
    sys.dont_write_bytecode = True
    parser = argparse.ArgumentParser(description="CipherMesh secure agent - local system-command channel")
    parser.add_argument("--trust-dir", default=str(DEFAULT_TRUST_DIR))
    parser.add_argument("--keys-dir", default=str(DEFAULT_KEYS_DIR))
    parser.add_argument("--audit-log", default="logs/interactive_events.jsonl")
    parser.add_argument("--strict-integrity", action="store_true", help="refuse to start on attestation failure")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--spool", help="process every signed command file in SPOOL/incoming once")
    group.add_argument("--stdin", action="store_true", help="read one signed command envelope from stdin")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-7s | %(message)s")
    ensure_provisioned(Path(args.trust_dir), Path(args.keys_dir))
    agent = build_agent_from_dirs(args.trust_dir, args.keys_dir, passphrase_from_env(), args.audit_log,
                                  config=AgentConfig(strict_integrity=args.strict_integrity))
    channel = SystemCommandChannel(agent, args.spool or Path(args.trust_dir) / "spool")
    outcomes = channel.process_spool() if args.spool else [channel.process_stdin()]
    for outcome in outcomes:
        print(json.dumps({"verdict": outcome.verdict.to_dict(), "status": outcome.status,
                          "incident": outcome.incident}, indent=2))
    return 0 if all(o.verdict.accepted for o in outcomes) else 2


if __name__ == "__main__":
    raise SystemExit(main())
