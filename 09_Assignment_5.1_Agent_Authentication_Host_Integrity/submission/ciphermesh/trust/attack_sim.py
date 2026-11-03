"""Untrusted-input breach simulation over real TCP loopback and the local system-command channel.

Assignment 5.1 - Agent Authentication and Host Integrity Verification.
Author: Kumar Waibhav Akshat (RA2212704010027).

The simulation starts a real :class:`SecureCipherMeshAgent` behind the TCP
server, then sends traffic from distinct loopback source addresses (the client
socket is bound before ``connect()``), so the agent sees genuine peer IPs:

    127.0.0.10        security console (allowed range 127.0.0.8/29)
    127.0.0.9, .11-.15  attacker footholds *inside* the admin range
    127.0.0.20        observer             127.0.0.30  peer gateway
    127.0.0.40        decommissioned console
    127.0.0.66-.72    untrusted network    127.0.0.99  brute-force source

Part A sends legitimate commands (they must be ACCEPTED and change state as
intended). Part B sends attacks; each must be REJECTED at the expected
checkpoint, and the engine state fingerprint (lockdown flag, pattern list,
policy fields) must be identical before and after. Part C checks that prompts
are still inspected correctly. Part D tampers with host code and shows the
self-attestation SAFE MODE and strict refusal paths.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import socket
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from pathlib import Path

from . import commands as cmd
from .client import ClientReply, verify_reply
from .envelope import build_header, encode, payload_digest, sign, utc_now
from .integrity import IntegrityError, load_signed_manifest, measure, package_root
from .keys import SigningIdentity, TrustStore, load_public_key
from .secure_agent import AgentConfig, SecureCipherMeshAgent, SystemCommandChannel, outcome_text
from .secure_server import BackgroundServer
from .verifier import CHECKPOINT_NAMES
from ..transport import HEADER, recv_exact

LOG = logging.getLogger("ciphermesh.trust.sim")
RULE = "-" * 100

ADMIN_IP, OBSERVER_IP, PEER_IP, LEGACY_IP = "127.0.0.10", "127.0.0.20", "127.0.0.30", "127.0.0.40"
BACKDOOR = ('    if "#cm-override" in text:  # injected backdoor\n'
            '        return InspectionResult(decision=Decision.ALLOW, reasons=["override"])\n')


@dataclass
class CaseRecord:
    sid: str
    title: str
    kind: str
    channel: str
    origin: str
    claimed_host: str | None
    command: str | None
    threat: str
    expected: str
    expected_reason: str | None
    accepted: bool
    checkpoint: str
    checkpoint_name: str
    reason: str
    detail: str
    latency_us: float
    incident: str | None
    state_before: str
    state_after: str
    state_unchanged: bool
    reply_verified: bool
    agent_integrity_trusted: bool
    outcome: str
    passed: bool
    notes: list[str] = field(default_factory=list)


def tamper_copy(src_root: Path, dest_parent: Path) -> Path:
    """Copy the package and inject a backdoor into policy.py (the original tree is untouched)."""
    dest = dest_parent / "ciphermesh"
    shutil.copytree(src_root, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.json", "*.pub"))
    policy = dest / "policy.py"
    text = policy.read_text(encoding="utf-8")
    anchor = "def _inspect(text: str, state: AgentState) -> InspectionResult:\n"
    policy.write_text(text.replace(anchor, anchor + BACKDOOR, 1), encoding="utf-8")
    return dest


class BreachSimulation:
    def __init__(self, trust_dir: Path, keys_dir: Path, log_dir: Path, passphrase: bytes):
        self.trust_dir, self.keys_dir, self.log_dir = Path(trust_dir), Path(keys_dir), Path(log_dir)
        self.passphrase = passphrase
        self.trust_path = self.trust_dir / "trusted_hosts.json"
        self.trust = TrustStore.load(self.trust_path)
        self.manifest = load_signed_manifest(self.trust_dir / "release_manifest.json")
        self.release_pub = load_public_key(self.trust_dir / "release_signer.pub")
        ids = {}
        for host in ("ciphermesh-node-01", "sec-console-01", "observer-01", "peer-gateway-01", "legacy-console-02"):
            ids[host] = SigningIdentity.load(host, self.keys_dir / f"{host}.key.pem", passphrase)
        ids["sec-console-01.old"] = SigningIdentity.load("sec-console-01", self.keys_dir / "sec-console-01.old.key.pem",
                                                         passphrase)
        self.ids = ids
        self.attacker = SigningIdentity.generate("rogue-console-99")
        self.digest = measure()
        self.records: list[CaseRecord] = []
        self.prompt_checks: list[dict] = []
        self.agent: SecureCipherMeshAgent | None = None
        self.port = 0
        self.tmp = Path(tempfile.mkdtemp(prefix="cm-sim-"))

    # ------------------------------------------------------------ helpers
    def env(self, identity: SigningIdentity, command: str, payload: dict | None = None, *, recipient: str | None = None,
            ttl_s: int = 30, issued_shift_s: float = 0.0, integrity: str | None = None,
            sender_host: str | None = None, key_id: str | None = None) -> dict:
        payload = payload or {}
        header = build_header(identity, recipient or self.trust.agent_id, command, payload,
                              integrity or self.digest, ttl_s=ttl_s, now=utc_now() + timedelta(seconds=issued_shift_s))
        if sender_host:
            header["sender_host"] = sender_host
        if key_id:
            header["key_id"] = key_id
        return sign(identity, header, payload)

    def send(self, ip: str, raw: bytes, declared_length: int | None = None) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.bind((ip, 0))
            sock.connect(("127.0.0.1", self.port))
            length = len(raw) if declared_length is None else declared_length
            sock.sendall(HEADER.pack(length) + (raw if declared_length is None else b""))
            (n,) = HEADER.unpack(recv_exact(sock, HEADER.size))
            return recv_exact(sock, n)

    def _describe(self, raw: bytes) -> tuple[str | None, str | None, str | None, str | None]:
        try:
            data = json.loads(raw)
            h = data.get("header", {})
            return h.get("sender_host"), h.get("command"), h.get("msg_id"), h.get("key_id")
        except Exception:
            return None, None, None, None

    def case(self, sid: str, title: str, threat: str, expect: str, raw: bytes, *, channel: str = "tcp",
             ip: str | None = None, expect_reason: str | None = None, declared_length: int | None = None,
             file_mode: int = 0o600, agent: SecureCipherMeshAgent | None = None, port: int | None = None,
             spool: SystemCommandChannel | None = None, notes: list[str] | None = None) -> CaseRecord:
        agent = agent or self.agent
        kind = "LEGITIMATE" if expect == "ACCEPT" else "ATTACK"
        claimed, command, msg_id, key_id = self._describe(raw)
        LOG.info(RULE)
        LOG.info("[%s] %s  (%s)", sid, title, kind)
        LOG.info("  threat    : %s", threat)
        where = f"tcp {ip} -> agent" if channel == "tcp" else f"system-command spool file (mode {oct(file_mode)})"
        size = declared_length if declared_length is not None else len(raw)
        LOG.info("  request   : %s | claimed_host=%s key_id=%s command=%s msg_id=%s frame=%d bytes", where,
                 claimed or "-", key_id or "-", command or "-", (msg_id or "-")[:8], size)
        LOG.info("  expected  : %s", "ACCEPT (all 13 checkpoints)" if expect == "ACCEPT"
                 else f"REJECT at {expect} {CHECKPOINT_NAMES.get(expect, '')} ({expect_reason or 'any reason'})")
        before = agent.state_summary()
        if channel == "tcp":
            saved_port, self.port = self.port, port or self.port
            reply_raw = self.send(ip, raw, declared_length)
            self.port = saved_port
            outcome = agent.history[-1]
        else:
            path = spool.incoming / f"{sid.lower()}.json"
            path.write_bytes(raw)
            os.chmod(path, file_mode)
            outcome = spool.process_file(path)
            reply_raw = outcome.reply
        after = agent.state_summary()
        verdict = outcome.verdict
        reply: ClientReply = verify_reply(reply_raw, self.trust, verdict.sender_host or "unauthenticated-peer",
                                          verdict.msg_id)
        unchanged = before["fingerprint"] == after["fingerprint"]
        if expect == "ACCEPT":
            ok = verdict.accepted and outcome.status == "ACCEPTED"
        else:
            ok = (not verdict.accepted and verdict.checkpoint == expect and unchanged
                  and (expect_reason is None or verdict.reason == expect_reason))
        # A genuine agent reply always has a valid signature; it is fully 'verified' only when the agent's
        # own code digest is trusted (not the case for the deliberately tampered SAFE MODE agent in Part D).
        ok = ok and reply.signature_valid and (reply.verified or agent.safe_mode)
        if verdict.accepted:
            LOG.info("  verdict   : ACCEPTED - all 13 checkpoints passed in %.0f us -> %s", verdict.latency_us,
                     outcome_text(outcome.result))
        else:
            LOG.info("  verdict   : REJECTED at %s %s reason=%s latency=%.0f us incident=%s", verdict.checkpoint,
                     CHECKPOINT_NAMES.get(verdict.checkpoint), verdict.reason, verdict.latency_us, outcome.incident)
            LOG.info("  detail    : %s", verdict.detail)
            LOG.warning("  >>> BLOCKED UNAUTHORIZED REQUEST: %s via %s stopped at %s (%s)", command or "unparsed frame",
                        ip or "local spool", verdict.checkpoint, verdict.reason)
        if unchanged:
            state_text = "STATE UNCHANGED"
        else:
            changes = [f"{label} {before[key]}->{after[key]}" for key, label in
                       (("lockdown", "lockdown"), ("pattern_count", "patterns"), ("policy_revision", "revision"))
                       if before[key] != after[key]]
            state_text = "STATE CHANGED as intended (" + ", ".join(changes) + ")"
        LOG.info("  state     : fingerprint %s -> %s | lockdown=%s patterns=%d (sha %s) -> %s", before["fingerprint"],
                 after["fingerprint"], after["lockdown"], after["pattern_count"], after["patterns_sha256"], state_text)
        LOG.info("  reply     : agent-signed %s reply, signature %s, agent integrity %s%s", reply.status,
                 "VERIFIED" if reply.signature_valid else f"NOT VERIFIED ({reply.problem})",
                 "TRUSTED" if reply.agent_integrity_trusted
                 else "UNTRUSTED (agent code differs from release; client treats reply as unverified)",
                 "" if verdict.accepted else "; body is a generic error (no checkpoint leaked to sender)")
        for note in notes or []:
            LOG.info("  note      : %s", note)
        LOG.info("  result    : %s", "PASS" if ok else "FAIL")
        record = CaseRecord(sid, title, kind, channel, verdict.origin.label(), claimed, command, threat, expect,
                            expect_reason, verdict.accepted, verdict.checkpoint, verdict.name, verdict.reason,
                            verdict.detail, round(verdict.latency_us, 1), outcome.incident, before["fingerprint"],
                            after["fingerprint"], unchanged, reply.verified, reply.agent_integrity_trusted,
                            outcome.status, ok, list(notes or []))
        self.records.append(record)
        return record

    def prompt_check(self, label: str, text_desc: str, text: str, expected: str) -> None:
        result = self.agent.engine.inspect(text, open_review=False)
        ok = result.decision.value == expected
        self.prompt_checks.append({"prompt": label, "content": text_desc, "expected": expected,
                                   "decision": result.decision.value, "rule": result.reasons[0][:60], "passed": ok})
        LOG.info("  prompt %-28s expected=%-6s got=%-6s %s", label, expected, result.decision.value,
                 "PASS" if ok else "FAIL")

    # ---------------------------------------------------------------- run
    def run(self) -> dict:
        # The simulation shortens the 5 s per-frame deadline to 2 s so the slow-client case runs quickly.
        config = AgentConfig(frame_deadline_s=2.0)
        agent_id = self.trust.agent_id
        LOG.info("=" * 100)
        LOG.info("CipherMesh Assignment 5.1 - Agent Authentication and Host Integrity Verification")
        LOG.info("Breach simulation (real TCP loopback + system-command spool). All times UTC.")
        LOG.info("=" * 100)
        LOG.info("trust store     : %s (schema cm-trust/1, %d hosts, %d revoked keys)", self.trust_path.name,
                 len(self.trust.document.hosts), len(self.trust.document.revocation_list))
        for host in self.trust.document.hosts:
            LOG.info("  host %-19s roles=%-15s sources=%-28s keys=%s%s", host.host_id, ",".join(host.roles),
                     ",".join(host.allowed_sources), ",".join(k.key_id + ("(revoked)" if k.revoked else "")
                                                             for k in host.keys),
                     "  [HOST REVOKED]" if host.revoked else "")
        LOG.info("release digest  : %s", self.digest)
        LOG.info("attacker key    : %s (not in trust store)", self.attacker.key_id)
        self.agent = SecureCipherMeshAgent(self.ids[agent_id], self.trust, signed_manifest=self.manifest,
                                           release_public_key=self.release_pub, trust_store_path=self.trust_path,
                                           audit_log_path=self.log_dir / "security_events.jsonl", config=config)
        if self.agent.safe_mode:
            raise SystemExit("baseline agent failed self-attestation (" + "; ".join(self.agent.integrity.reasons)
                             + "); remove ciphermesh/__pycache__, run with PYTHONDONTWRITEBYTECODE=1 and "
                             "re-run `python -B -m ciphermesh.trust.provision` if the sources changed")
        spool = SystemCommandChannel(self.agent, self.tmp / "spool")
        admin, observer, peer = self.ids["sec-console-01"], self.ids["observer-01"], self.ids["peer-gateway-01"]
        with BackgroundServer(self.agent) as server:
            self.port = server.port
            self._part_a(admin, observer, peer, spool)
            baseline = self.agent.state_summary()
            LOG.info(RULE)
            LOG.info("BASELINE before attacks: fingerprint=%s lockdown=%s patterns=%d revision=%d",
                     baseline["fingerprint"], baseline["lockdown"], baseline["pattern_count"],
                     baseline["policy_revision"])
            self._part_b(admin, observer, peer, spool)
            final = self.agent.state_summary()
            LOG.info(RULE)
            LOG.info("AFTER all attacks: fingerprint=%s lockdown=%s patterns=%d -> %s", final["fingerprint"],
                     final["lockdown"], final["pattern_count"],
                     "STATE UNCHANGED BY EVERY REJECTED COMMAND" if final == baseline else "STATE DRIFTED (FAIL)")
            self._part_c(peer)
        integrity = self._part_d(admin, observer)
        return self._summary(baseline, final, integrity)

    def _part_a(self, admin, observer, peer, spool) -> None:
        LOG.info("=" * 100)
        LOG.info("PART A - legitimate, correctly signed traffic (must be ACCEPTED)")
        lockdown = self.env(admin, cmd.TRIGGER_EMERGENCY_LOCKDOWN, {"reason": "SOC drill: suspected key leak"})
        self.captured_lockdown = lockdown
        self.case("S01", "Security console triggers emergency lockdown", "none - authorised SOC action",
                  "ACCEPT", encode(lockdown), ip=ADMIN_IP)
        decision = self.agent.engine.inspect("Summarise the Q3 roadmap", open_review=False).decision.value
        LOG.info("  check     : clean prompt under lockdown -> %s (expected BLOCK)", decision)
        self.lockdown_effect = decision
        self.case("S02", "Security console releases lockdown", "none - authorised SOC action", "ACCEPT",
                  encode(self.env(admin, cmd.RELEASE_LOCKDOWN, {"reason": "drill complete"})), ip=ADMIN_IP)
        self.case("S03", "Observer requests telemetry dump", "none - read-only monitoring", "ACCEPT",
                  encode(self.env(observer, cmd.REQUEST_TELEMETRY_DUMP)), ip=OBSERVER_IP)
        self.case("S04", "Security console adds a redaction pattern", "none - authorised policy change", "ACCEPT",
                  encode(self.env(admin, cmd.UPDATE_REDACTION_PATTERNS, {"patterns": ["PRJ-[0-9]{4}"]})), ip=ADMIN_IP)
        sync = {"state": {"policy_revision": 2, "policy_version": "1.1",
                          "provider_allowlist": ["local", "aws-bedrock", "azure-ai"]}}
        self.case("S05", "Peer gateway synchronises policy revision 2", "none - authorised peer sync", "ACCEPT",
                  encode(self.env(peer, cmd.STATE_SYNC, sync)), ip=PEER_IP)
        self.case("S06", "Peer gateway asks for a prompt inspection", "none - authorised inspection", "ACCEPT",
                  encode(self.env(peer, cmd.INSPECT, {"text": "Mail priya.sharma@example.com the draft"})), ip=PEER_IP)
        self.records[-1].notes = [f"engine decision for the inspected prompt: "
                                  f"{self.agent.history[-1].result['inspection']['decision']}"]
        LOG.info("  check     : inspected prompt decision -> %s", self.agent.history[-1].result["inspection"]["decision"])
        self.case("S07", "Admin pattern update via local system-command spool", "none - authorised local operator",
                  "ACCEPT", encode(self.env(admin, cmd.UPDATE_REDACTION_PATTERNS, {"patterns": ["EMP-[0-9]{6}"]})),
                  channel="system", spool=spool, file_mode=0o600)

    def _part_b(self, admin, observer, peer, spool) -> None:
        LOG.info("=" * 100)
        LOG.info("PART B - untrusted input breach attempts (must be REJECTED, state must not change)")
        lock = {"reason": "attacker wants a denial of service"}

        unsigned = self.env(admin, cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock)
        unsigned.pop("signature")
        self.case("A01", "Unsigned command", "attacker sends a command with no signature at all", "C2",
                  encode(unsigned), ip="127.0.0.66", expect_reason="SCHEMA_VIOLATION")
        self.case("A02", "Malformed JSON frame", "truncated / garbage JSON to crash the parser", "C2",
                  b'{"header": {"version": "cm-sig/1", "command": "TRIGGER_EMERGENCY_LOCKDOWN", "msg_id": ',
                  ip="127.0.0.70", expect_reason="JSON_MALFORMED")
        injected = self.env(observer, cmd.REQUEST_TELEMETRY_DUMP)
        injected["header"]["role_override"] = "security-admin"
        self.case("A03", "Unknown-field injection (role_override)", "extra header field to smuggle privileges",
                  "C2", encode(injected), ip="127.0.0.71", expect_reason="SCHEMA_VIOLATION")
        dup = encode(self.env(observer, cmd.REQUEST_TELEMETRY_DUMP)).replace(
            b'"command":"REQUEST_TELEMETRY_DUMP"',
            b'"command":"REQUEST_TELEMETRY_DUMP","command":"TRIGGER_EMERGENCY_LOCKDOWN"', 1)
        self.case("A04", "Duplicate-key smuggling", "parser differential: first vs last 'command' key", "C2",
                  dup, ip="127.0.0.71", expect_reason="JSON_DUPLICATE_KEY")
        self.case("A05", "Oversized frame (declares 1 MiB)", "memory exhaustion via huge length prefix", "C1",
                  b"", ip="127.0.0.69", declared_length=1_048_576, expect_reason="FRAME_TOO_LARGE")
        downgrade = self.env(admin, cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock)
        downgrade["header"]["version"] = "cm-sig/0"
        self.case("A06", "Protocol downgrade (cm-sig/0)", "force a weaker legacy envelope format", "C3",
                  encode(downgrade), ip="127.0.0.72", expect_reason="UNSUPPORTED_VERSION")
        self.case("A07", "Wrong recipient (message for node-02)", "re-target a valid command meant for another agent",
                  "C4", encode(self.env(admin, cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock, recipient="ciphermesh-node-02")),
                  ip="127.0.0.15", expect_reason="WRONG_RECIPIENT")
        self.case("A08", "Unknown host (rogue-console-99)", "attacker presents its own identity and key", "C5",
                  encode(self.env(self.attacker, cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock)), ip="127.0.0.67",
                  expect_reason="UNKNOWN_HOST")
        self.case("A09", "Decommissioned host (legacy-console-02)", "old console with a still-valid key is reused",
                  "C5", encode(self.env(self.ids["legacy-console-02"], cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock)),
                  ip=LEGACY_IP, expect_reason="HOST_REVOKED")
        self.case("A10", "Spoofed host_id with attacker key", "claims to be sec-console-01, signs with own key",
                  "C6", encode(self.env(self.attacker, cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock,
                                        sender_host="sec-console-01")),
                  ip="127.0.0.68", expect_reason="KEY_NOT_BOUND")
        self.case("A11", "Revoked (rotated-out) admin key", "leaked old key used after rotation", "C6",
                  encode(self.env(self.ids["sec-console-01.old"], cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock)),
                  ip="127.0.0.9", expect_reason="KEY_REVOKED")
        self.case("A12", "Stolen admin key used from untrusted network", "valid signature, wrong network origin",
                  "C7", encode(self.env(admin, cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock)), ip="127.0.0.66",
                  expect_reason="ORIGIN_NOT_ALLOWED")
        self.case("A13", "Forged signature (attacker key, admin key_id)",
                  "foothold inside admin subnet forges a lockdown", "C8",
                  encode(self.env(self.attacker, cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock, sender_host="sec-console-01",
                                  key_id=admin.key_id)),
                  ip="127.0.0.12", expect_reason="BAD_SIGNATURE")
        tampered = self.env(admin, cmd.UPDATE_REDACTION_PATTERNS, {"patterns": ["TKT-[0-9]{5}"]})
        tampered["payload"] = {"patterns": ["[A-Za-z]{1,}"]}
        self.case("A14", "Payload tampered after signing", "on-path attacker swaps the pattern list", "C8",
                  encode(tampered), ip="127.0.0.13", expect_reason="BAD_SIGNATURE")
        rehashed = self.env(admin, cmd.UPDATE_REDACTION_PATTERNS, {"patterns": ["TKT-[0-9]{5}"]})
        rehashed["payload"] = {"patterns": ["[A-Za-z]{1,}"]}
        rehashed["header"]["payload_sha256"] = payload_digest(rehashed["payload"])
        self.case("A15", "Payload tampered and digest recomputed", "attacker also fixes payload_sha256", "C8",
                  encode(rehashed), ip="127.0.0.14", expect_reason="BAD_SIGNATURE")
        faulty_payload = {"patterns": ["INV-[0-9]{6}"]}
        faulty_header = build_header(admin, self.trust.agent_id, cmd.UPDATE_REDACTION_PATTERNS, faulty_payload,
                                     self.digest)
        faulty_header["payload_sha256"] = payload_digest({"patterns": ["OTHER"]})
        self.case("A16", "Header digest does not match payload", "trusted but faulty client binds the wrong body",
                  "C9", encode(sign(admin, faulty_header, faulty_payload)), ip=ADMIN_IP,
                  expect_reason="PAYLOAD_HASH_MISMATCH")
        self.case("A17", "Stale command (issued 10 minutes ago)", "old captured command replayed much later", "C10",
                  encode(self.env(admin, cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock, issued_shift_s=-600)),
                  ip="127.0.0.11", expect_reason="STALE_MESSAGE")
        self.case("A18", "Expired command (ttl 5 s, sent after 20 s)", "delayed delivery past expires_at", "C10",
                  encode(self.env(admin, cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock, ttl_s=5, issued_shift_s=-20)),
                  ip="127.0.0.11", expect_reason="EXPIRED_MESSAGE")
        self.case("A19", "Future-dated command (+5 minutes)", "pre-signed command to beat the freshness window",
                  "C10", encode(self.env(admin, cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock, issued_shift_s=300)),
                  ip="127.0.0.14", expect_reason="FUTURE_MESSAGE")
        self.case("A20", "Replay of the captured S01 lockdown", "byte-identical copy of an accepted command", "C11",
                  encode(self.captured_lockdown), ip="127.0.0.11", expect_reason="REPLAY_MSG_ID",
                  notes=["the original S01 frame was accepted earlier; lockdown was then released in S02, "
                         "so an accepted replay would have re-locked the gateway"])
        tdir = self.tmp / "tampered-console"
        tdir.mkdir()
        bad_digest = measure(tamper_copy(package_root(), tdir))
        self.case("A21", "Compromised console (tampered host code)", "console runs a backdoored policy.py", "C12",
                  encode(self.env(admin, cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock, integrity=bad_digest)), ip=ADMIN_IP,
                  expect_reason="ATTESTATION_MISMATCH",
                  notes=[f"console attestation digest {bad_digest[:16]}... vs trusted release {self.digest[:16]}..."])
        self.case("A22", "Observer privilege escalation (lockdown)", "valid observer key asks for an admin action",
                  "C13", encode(self.env(observer, cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock)), ip=OBSERVER_IP,
                  expect_reason="COMMAND_NOT_PERMITTED")
        self.case("A23", "World-writable command file in spool", "another local user could have swapped the file",
                  "C7", encode(self.env(admin, cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock)), channel="system", spool=spool,
                  file_mode=0o666, expect_reason="LOCAL_SOURCE_UNTRUSTED")
        self.case("A24", "Forged command file in spool", "local attacker drops a forged admin command", "C8",
                  encode(self.env(self.attacker, cmd.UPDATE_REDACTION_PATTERNS, {"patterns": ["[a-z]{1,}"]},
                                  sender_host="sec-console-01", key_id=admin.key_id)),
                  channel="system", spool=spool, file_mode=0o600, expect_reason="BAD_SIGNATURE")
        LOG.info(RULE)
        LOG.info("[A25] Brute-force burst: 8 forged admin lockdowns from 127.0.0.99 (lockout after 5 failures)")
        for attempt in range(1, 9):
            expect = "C7" if attempt <= 5 else "L0"
            reason = "ORIGIN_NOT_ALLOWED" if attempt <= 5 else "SOURCE_LOCKED_OUT"
            self.case(f"A25.{attempt}", f"Brute-force attempt {attempt}/8", "rapid forged commands from one source",
                      expect, encode(self.env(self.attacker, cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock,
                                              sender_host="sec-console-01", key_id=admin.key_id)),
                      ip="127.0.0.99", expect_reason=reason)
        weaken = {"state": {"policy_revision": self.agent.engine.state.policy_revision + 1,
                            "custom_redaction_patterns": [], "block_critical_secrets": False,
                            "redact_email_phone_ip": False}}
        self.case("A26", "Peer gateway STATE_SYNC weakens policy", "valid peer key switches off secret blocking "
                  "and PII redaction", "C13", encode(self.env(peer, cmd.STATE_SYNC, weaken)), ip=PEER_IP,
                  expect_reason="STATE_FIELD_NOT_PERMITTED",
                  notes=["peer-gateway may only sync policy_revision, policy_version, provider_allowlist, "
                         "max_prompt_bytes; other fields need security-admin"])
        LOG.info(RULE)
        LOG.info("[A27] Lockout abuse: 5 forged commands claiming sec-console-01 from 127.0.0.8 (inside its range)")
        for attempt in range(1, 6):
            self.case(f"A27.{attempt}", f"Forged burst to lock out the console {attempt}/5",
                      "attacker tries to get the real console locked out", "C8",
                      encode(self.env(self.attacker, cmd.TRIGGER_EMERGENCY_LOCKDOWN, lock,
                                      sender_host="sec-console-01", key_id=admin.key_id)),
                      ip="127.0.0.8", expect_reason="BAD_SIGNATURE")
        record = self.case("S09", "Real console from the locked address 127.0.0.8", "none - authentic request "
                           "while (127.0.0.8, sec-console-01) is locked", "ACCEPT",
                           encode(self.env(admin, cmd.REQUEST_TELEMETRY_DUMP)), ip="127.0.0.8")
        cleared = "LOCKOUT_CLEARED" in self.agent.history[-1].verdict.alerts
        record.notes.append("authentic request passed C8 and cleared the lockout" if cleared else "lock NOT cleared")
        record.passed = record.passed and cleared
        LOG.info("  check     : lockout cleared by the authentic request -> %s", cleared)
        self._slow_client_case(admin)

    def _slow_client_case(self, admin) -> None:
        """A28: slow-drip connections hit the per-frame deadline and the per-IP connection cap."""
        LOG.info(RULE)
        ip, deadline = "127.0.0.72", self.agent.config.frame_deadline_s
        LOG.info("[A28] Slow-client exhaustion: 5 connections from %s each send 1 byte and stall", ip)
        LOG.info("  expected  : 4 connections REJECT at L0 (FRAME_TIMEOUT after %.0f s), the 5th at L0 "
                 "(CONNECTION_LIMIT, cap %d per IP); other clients still served", deadline,
                 self.agent.config.max_connections_per_ip)
        before = self.agent.state_summary()
        start = len(self.agent.audit.events)
        socks = []
        for _ in range(5):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((ip, 0))
            sock.connect(("127.0.0.1", self.port))
            sock.sendall(b"\x00")
            socks.append(sock)
        time.sleep(0.3)
        t0 = time.perf_counter()
        reply = verify_reply(self.send(ADMIN_IP, encode(env := self.env(admin, cmd.PING))), self.trust,
                             "sec-console-01", env["header"]["msg_id"])
        served_ms = (time.perf_counter() - t0) * 1000
        LOG.info("  check     : console PING from %s during the stall -> %s in %.1f ms", ADMIN_IP, reply.status,
                 served_ms)
        time.sleep(deadline + 0.6)
        for sock in socks:
            sock.close()
        events = [e for e in self.agent.audit.events[start:]
                  if e["event"] == "COMMAND_REJECTED" and e.get("checkpoint") == "L0"]
        after = self.agent.state_summary()
        unchanged = before["fingerprint"] == after["fingerprint"]
        for sid, title, reason, expected_n in (("A28.1", "Slow-drip connections hit frame deadline", "FRAME_TIMEOUT", 4),
                                               ("A28.2", "5th connection from same IP refused", "CONNECTION_LIMIT", 1)):
            n = sum(e["reason"] == reason for e in events)
            ok = n == expected_n and unchanged and reply.verified and reply.status == "ACCEPTED"
            LOG.warning("  >>> BLOCKED UNAUTHORIZED REQUEST: %d connection(s) from %s stopped at L0 (%s)", n, ip,
                        reason)
            self.records.append(CaseRecord(sid, title, "ATTACK", "tcp", f"tcp://{ip}", None, None,
                                           "slow-client / connection exhaustion", "L0", reason, False, "L0",
                                           "SOURCE_LOCKOUT", reason, f"{n} connection(s) ({expected_n} expected)",
                                           0.0, None, before["fingerprint"], after["fingerprint"], unchanged, True,
                                           True, "REJECTED", ok,
                                           [f"console request served in {served_ms:.1f} ms during the stall"]))
        LOG.info("  state     : fingerprint %s -> %s -> %s", before["fingerprint"], after["fingerprint"],
                 "STATE UNCHANGED" if unchanged else "STATE CHANGED (FAIL)")
        LOG.info("  result    : %s", "PASS" if all(r.passed for r in self.records[-2:]) else "FAIL")

    def _part_c(self, peer) -> None:
        LOG.info("=" * 100)
        LOG.info("PART C - prompts are still processed correctly after the attacks")
        self.prompt_check("clean business prompt", "plain text", "Summarise the Q3 hiring plan in five bullets", "ALLOW")
        self.prompt_check("email address", "PII (D5)", "Send the invoice to rahul.verma@example.in today", "REDACT")
        self.prompt_check("custom pattern PRJ-xxxx", "S04 pattern", "Status of PRJ-2041 for the steering group?",
                          "REDACT")
        self.prompt_check("custom pattern EMP-xxxxxx", "S07 pattern", "Payroll query for EMP-204118", "REDACT")
        self.prompt_check("AWS access key", "secret (D1)", "Use AKIAIOSFODNN7EXAMPLE to call S3", "BLOCK")
        self.prompt_check("internal URL", "R3 review", "See https://wiki.corp/finance/plan for details", "REVIEW")
        self.case("S08", "Peer gateway inspection after the attacks", "none - authorised inspection", "ACCEPT",
                  encode(self.env(peer, cmd.INSPECT, {"text": "Ping 9876543210 about PRJ-7781"})), ip=PEER_IP)
        decision = self.agent.history[-1].result["inspection"]["decision"]
        self.records[-1].notes = [f"engine decision for the inspected prompt: {decision}"]
        LOG.info("  check     : signed INSPECT over TCP after attacks -> %s (expected REDACT)", decision)

    def _part_d(self, admin, observer) -> dict:
        LOG.info("=" * 100)
        LOG.info("PART D - host integrity: agent started from tampered code (self-attestation)")
        tdir = self.tmp / "tampered-agent"
        tdir.mkdir()
        bad_root = tamper_copy(package_root(), tdir)
        LOG.info("  tampered copy : %s/policy.py now contains an ALLOW backdoor", bad_root.name)
        strict_refused = False
        try:
            SecureCipherMeshAgent(self.ids[self.trust.agent_id], self.trust, signed_manifest=self.manifest,
                                  release_public_key=self.release_pub, code_root=bad_root,
                                  trust_store_path=self.trust_path,
                                  audit_log_path=self.log_dir / "security_events.jsonl",
                                  config=AgentConfig(strict_integrity=True))
        except IntegrityError as exc:
            strict_refused = True
            LOG.warning("  [I01] strict mode: IntegrityError raised, agent REFUSED TO START (%s)", exc)
        safe_agent = SecureCipherMeshAgent(self.ids[self.trust.agent_id], self.trust, signed_manifest=self.manifest,
                                           release_public_key=self.release_pub, code_root=bad_root,
                                           trust_store_path=self.trust_path,
                                           audit_log_path=self.log_dir / "security_events.jsonl")
        report = safe_agent.integrity
        LOG.info("  [I02] non-strict mode: agent started in %s; mismatched files: %s", report.mode,
                 ", ".join(m["file"] for m in report.mismatched))
        with BackgroundServer(safe_agent) as server:
            self.case("I02a", "SAFE MODE agent receives a valid admin lockdown",
                      "tampered node must not execute state-changing commands", "C13",
                      encode(self.env(admin, cmd.TRIGGER_EMERGENCY_LOCKDOWN, {"reason": "valid SOC request"})),
                      ip=ADMIN_IP, agent=safe_agent, port=server.port, expect_reason="SAFE_MODE_RESTRICTED")
            record = self.case("I02b", "SAFE MODE agent still serves read-only telemetry",
                               "none - telemetry stays available for incident response", "ACCEPT",
                               encode(self.env(observer, cmd.REQUEST_TELEMETRY_DUMP)), ip=OBSERVER_IP,
                               agent=safe_agent, port=server.port)
            record.notes.append("client sees the agent's own integrity digest as UNTRUSTED (tamper visible to peers)")
        shutil.rmtree(tdir, ignore_errors=True)
        return {"strict_refused": strict_refused, "safe_mode_entered": safe_agent.safe_mode,
                "mismatched_files": [m["file"] for m in report.mismatched], "reasons": report.reasons}

    # ------------------------------------------------------------ summary
    def _summary(self, baseline: dict, final: dict, integrity: dict) -> dict:
        legit = [r for r in self.records if r.kind == "LEGITIMATE"]
        attacks = [r for r in self.records if r.kind == "ATTACK"]
        by_cp: dict[str, int] = {}
        for r in attacks:
            if not r.accepted:
                by_cp[r.checkpoint] = by_cp.get(r.checkpoint, 0) + 1
        totals = {
            "cases": len(self.records),
            "legitimate": len(legit),
            "legitimate_accepted": sum(r.accepted for r in legit),
            "attacks": len(attacks),
            "attacks_blocked": sum(not r.accepted for r in attacks),
            "attacks_blocked_at_expected_checkpoint": sum(r.passed for r in attacks),
            "state_unchanged_for_every_rejection": all(r.state_unchanged for r in self.records if not r.accepted),
            "baseline_equals_final_state": baseline == final,
            "replies_verified": sum(r.reply_verified for r in self.records),
            "prompt_checks_passed": sum(p["passed"] for p in self.prompt_checks),
            "prompt_checks": len(self.prompt_checks),
            "security_alerts": len(self.agent.alerts),
            "lockdown_blocked_clean_prompt": self.lockdown_effect == "BLOCK",
            "strict_start_refused": integrity["strict_refused"],
            "safe_mode_entered": integrity["safe_mode_entered"],
        }
        totals["all_passed"] = (all(r.passed for r in self.records) and totals["baseline_equals_final_state"]
                                and totals["prompt_checks_passed"] == totals["prompt_checks"]
                                and totals["lockdown_blocked_clean_prompt"] and integrity["strict_refused"])
        summary = {
            "assignment": "5.1 Agent Authentication and Host Integrity Verification",
            "author": "Kumar Waibhav Akshat (RA2212704010027)",
            "generated_at": utc_now().isoformat(timespec="seconds").replace("+00:00", "Z"),
            "agent_id": self.trust.agent_id, "release_digest": self.digest,
            "totals": totals, "blocked_by_checkpoint": dict(sorted(by_cp.items(), key=lambda kv: (kv[0][0], int(kv[0][1:])))),
            "baseline_state": baseline, "final_state": final, "integrity": integrity,
            "prompt_checks": self.prompt_checks, "alerts": self.agent.alerts,
            "cases": [asdict(r) for r in self.records],
        }
        self._write_table(summary)
        LOG.info("=" * 100)
        LOG.info("SUMMARY: %d cases | legitimate accepted %d/%d | attacks blocked %d/%d (all at expected checkpoint: %s)",
                 totals["cases"], totals["legitimate_accepted"], totals["legitimate"], totals["attacks_blocked"],
                 totals["attacks"], totals["attacks_blocked_at_expected_checkpoint"] == totals["attacks"])
        LOG.info("SUMMARY: state unchanged by every rejected command: %s | prompts correct %d/%d | alerts raised %d",
                 totals["state_unchanged_for_every_rejection"], totals["prompt_checks_passed"], totals["prompt_checks"],
                 totals["security_alerts"])
        LOG.info("SUMMARY: blocked by checkpoint: %s", ", ".join(f"{k}={v}" for k, v in summary["blocked_by_checkpoint"].items()))
        LOG.info("SUMMARY: OVERALL %s", "PASS" if totals["all_passed"] else "FAIL")
        shutil.rmtree(self.tmp, ignore_errors=True)
        return summary

    def _write_table(self, summary: dict) -> None:
        lines = [f"CipherMesh 5.1 breach simulation summary - generated {summary['generated_at']}", "",
                 f"{'ID':7} {'Scenario':52} {'Expected':9} {'Actual':7} {'Reason':26} {'State':10} {'Result':6}",
                 "-" * 123]
        for r in summary["cases"]:
            actual = "ACCEPT" if r["accepted"] else r["checkpoint"]
            state = "unchanged" if r["state_unchanged"] else "changed"
            lines.append(f"{r['sid']:7} {r['title'][:52]:52} {r['expected']:9} {actual:7} {r['reason'][:26]:26} "
                         f"{state:10} {'PASS' if r['passed'] else 'FAIL':6}")
        t = summary["totals"]
        lines += ["-" * 123, f"legitimate accepted {t['legitimate_accepted']}/{t['legitimate']}; attacks blocked "
                  f"{t['attacks_blocked']}/{t['attacks']}; state unchanged by every rejection: "
                  f"{t['state_unchanged_for_every_rejection']}; overall {'PASS' if t['all_passed'] else 'FAIL'}"]
        (self.log_dir / "breach_simulation_summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        for line in lines[2:]:
            LOG.info("%s", line)


def configure_logging(log_file: Path) -> logging.Handler:
    formatter = logging.Formatter("%(asctime)s.%(msecs)03dZ | %(levelname)-7s | %(message)s", "%Y-%m-%d %H:%M:%S")
    formatter.converter = time.gmtime
    handler = logging.FileHandler(log_file, mode="w", encoding="utf-8")
    handler.setFormatter(formatter)
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers[:] = [handler, console]
    root.setLevel(logging.INFO)
    return handler


def main(argv: list[str] | None = None) -> int:
    from .provision import DEFAULT_KEYS_DIR, DEFAULT_TRUST_DIR, ensure_provisioned, passphrase_from_env
    parser = argparse.ArgumentParser(description="Run the CipherMesh 5.1 breach simulation")
    parser.add_argument("--trust-dir", default=str(DEFAULT_TRUST_DIR))
    parser.add_argument("--keys-dir", default=str(DEFAULT_KEYS_DIR))
    parser.add_argument("--log-dir", default="logs")
    args = parser.parse_args(argv)
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "security_events.jsonl").unlink(missing_ok=True)
    configure_logging(log_dir / "security_runtime.log")
    ensure_provisioned(Path(args.trust_dir), Path(args.keys_dir))
    summary = BreachSimulation(Path(args.trust_dir), Path(args.keys_dir), log_dir, passphrase_from_env()).run()
    (log_dir / "breach_simulation_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 0 if summary["totals"]["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
