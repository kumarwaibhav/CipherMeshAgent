"""CommandVerifier: thirteen ordered, fail-closed cryptographic validation checkpoints.

Assignment 5.1 - Agent Authentication and Host Integrity Verification.
Author: Kumar Waibhav Akshat (RA2212704010027).

Every inbound payload - from the TCP loop or from the local system-command
channel - passes through :meth:`CommandVerifier.verify` *before* anything is
parsed into an action. The checkpoints run in a fixed order and the first
failure stops processing with a stable reason code ("fail closed"):

    L0  lockout per (address, claimed host); cleared by an authentic request
    C1  frame size limit              C8  Ed25519 signature over canonical bytes
    C2  strict JSON + schema          C9  payload hash matches header
    C3  protocol version              C10 freshness (+/-60 s skew, not expired)
    C4  recipient is this agent       C11 replay (msg_id / nonce cache with TTL)
    C5  sender host trusted           C12 host integrity attestation
    C6  key bound to that host        C13 authorization (roles, STATE_SYNC fields)
    C7  network origin allowed

Ordering rationale: cheap, content-free checks come first (C1-C4) so malformed
floods cost little; identity look-ups (C5-C7) come before the comparatively
expensive signature check (C8); replay state (C11) is only updated *after* the
signature has been proven, so an attacker cannot poison the cache with forged
IDs; authorization (C13) is decided last, on facts that are now authenticated.
Comparisons of identifiers and digests use :func:`hmac.compare_digest`.
"""
from __future__ import annotations

import hmac
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

from . import commands as cmd
from .envelope import (MAX_TTL_S, SUPPORTED_VERSIONS, EnvelopeError, SignedCommand, parse, payload_digest,
                       utc_now)
from .keys import LOCAL_SOURCE, TrustStore, verify_signature

CHECKPOINTS: list[tuple[str, str, str]] = [
    ("L0", "SOURCE_LOCKOUT", "(address, claimed host) not locked out, or lock cleared by an authentic request"),
    ("C1", "FRAME_SIZE", "Frame length is between 1 byte and the configured limit (local: regular file)"),
    ("C2", "STRICT_SCHEMA", "Strict UTF-8 JSON, no duplicate keys, exact schema, typed fields"),
    ("C3", "VERSION", "Envelope version is supported"),
    ("C4", "RECIPIENT", "Message is addressed to this agent"),
    ("C5", "HOST_TRUST", "Sender host is known, not revoked and inside its validity window"),
    ("C6", "KEY_BINDING", "key_id belongs to that host, is not revoked and is valid now"),
    ("C7", "NETWORK_ORIGIN", "Peer address (or local file owner) is allowed for that host"),
    ("C8", "SIGNATURE", "Ed25519 signature verifies over the canonical header and payload"),
    ("C9", "PAYLOAD_HASH", "payload_sha256 in the signed header matches the payload"),
    ("C10", "FRESHNESS", "issued_at within +/-60 s of local time and message not expired"),
    ("C11", "REPLAY", "msg_id and nonce have not been seen inside the replay window"),
    ("C12", "HOST_INTEGRITY", "Sender's code attestation digest matches its trusted release"),
    ("C13", "AUTHORIZATION", "Command and STATE_SYNC fields permitted for the host's roles; SAFE MODE"),
]
CHECKPOINT_NAMES = {cid: name for cid, name, _ in CHECKPOINTS}
CHECKPOINT_ORDER = [cid for cid, _, _ in CHECKPOINTS]

AlertSink = Callable[[dict], None]


def lockout_key(address: str, claimed_host: str | None) -> str:
    """Failure counters are kept per (peer address, claimed host); unparsable frames use host '-'."""
    return f"{address}/{claimed_host or '-'}"


@dataclass(frozen=True)
class Origin:
    """Where a payload came from. ``address`` is a peer IP or ``"local"``."""
    channel: str
    address: str
    detail: str = ""
    file_uid: int | None = None
    file_mode: int | None = None
    regular_file: bool = True

    def label(self) -> str:
        if self.channel == "tcp":
            return f"tcp://{self.address}{':' + self.detail if self.detail else ''}"
        return f"system://{self.detail or 'stdin'}"


@dataclass
class Verdict:
    accepted: bool
    checkpoint: str
    reason: str
    detail: str
    latency_us: float
    origin: Origin
    msg_id: str | None = None
    sender_host: str | None = None
    key_id: str | None = None
    command: str | None = None
    timings_ns: dict[str, int] = field(default_factory=dict)
    alerts: list[str] = field(default_factory=list)
    message: SignedCommand | None = field(default=None, repr=False)

    @property
    def name(self) -> str:
        return "ALL_CHECKPOINTS_PASSED" if self.accepted else CHECKPOINT_NAMES.get(self.checkpoint, "?")

    def to_dict(self) -> dict:
        return {
            "accepted": self.accepted, "checkpoint": self.checkpoint, "checkpoint_name": self.name,
            "reason": self.reason, "detail": self.detail, "latency_us": round(self.latency_us, 1),
            "channel": self.origin.channel, "origin": self.origin.label(), "msg_id": self.msg_id,
            "sender_host": self.sender_host, "key_id": self.key_id, "command": self.command,
            "alerts": list(self.alerts),
        }


class _Reject(Exception):
    def __init__(self, checkpoint: str, reason: str, detail: str):
        super().__init__(detail)
        self.checkpoint, self.reason, self.detail = checkpoint, reason, detail


class ReplayCache:
    """Remembers msg_id and nonce values until they could no longer pass C10.

    A message older than ``skew`` is rejected by C10 anyway, so an entry only has
    to live for ``max_ttl + 2*skew`` seconds. The cache is bounded; when full and
    nothing has expired it fails closed instead of forgetting live entries.
    """

    def __init__(self, ttl_s: float = MAX_TTL_S + 120, max_entries: int = 100_000):
        self.ttl_s = ttl_s
        self.max_entries = max_entries
        self._entries: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def _expire(self, now: float) -> None:
        while self._entries:
            key, expiry = next(iter(self._entries.items()))
            if expiry > now:
                break
            self._entries.popitem(last=False)

    def check_and_add(self, msg_id: str, nonce: str, now: float | None = None) -> str | None:
        now = time.monotonic() if now is None else now
        with self._lock:
            self._expire(now)
            if "m:" + msg_id in self._entries:
                return "REPLAY_MSG_ID"
            if "n:" + nonce in self._entries:
                return "REPLAY_NONCE"
            if len(self._entries) + 2 > self.max_entries:
                return "REPLAY_CACHE_FULL"
            expiry = now + self.ttl_s
            self._entries["m:" + msg_id] = expiry
            self._entries["n:" + nonce] = expiry
            return None

    def __len__(self) -> int:
        return len(self._entries)


class FailureLimiter:
    """Locks a source out after ``threshold`` failures inside ``window_s`` seconds."""

    def __init__(self, threshold: int = 5, window_s: float = 60.0, lockout_s: float = 300.0):
        self.threshold, self.window_s, self.lockout_s = threshold, window_s, lockout_s
        self._failures: dict[str, deque[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def locked_for(self, source: str, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        with self._lock:
            until = self._locked_until.get(source, 0.0)
            if until <= now:
                self._locked_until.pop(source, None)
                return 0.0
            return until - now

    def record_failure(self, source: str, now: float | None = None) -> bool:
        """Return True when this failure triggers a new lockout."""
        now = time.monotonic() if now is None else now
        with self._lock:
            window = self._failures.setdefault(source, deque())
            window.append(now)
            while window and window[0] <= now - self.window_s:
                window.popleft()
            if len(window) >= self.threshold and self._locked_until.get(source, 0.0) <= now:
                self._locked_until[source] = now + self.lockout_s
                window.clear()
                return True
            return False

    def clear(self, source: str) -> None:
        with self._lock:
            self._locked_until.pop(source, None)
            self._failures.pop(source, None)

    def failures(self, source: str) -> int:
        with self._lock:
            return len(self._failures.get(source, ()))


class CommandVerifier:
    """Runs the ordered checkpoints and returns a structured :class:`Verdict`."""

    def __init__(self, trust_store: TrustStore, agent_id: str | None = None, *, max_frame: int = 65536,
                 max_skew_s: float = 60.0, max_ttl_s: float = MAX_TTL_S,
                 replay_cache: ReplayCache | None = None, limiter: FailureLimiter | None = None,
                 clock: Callable[[], datetime] = utc_now, safe_mode: bool = False,
                 local_uids: set[int] | None = None, alert_sink: AlertSink | None = None):
        self.trust = trust_store
        self.agent_id = agent_id or trust_store.agent_id
        self.max_frame = max_frame
        self.max_skew = timedelta(seconds=max_skew_s)
        self.max_ttl = timedelta(seconds=max_ttl_s)
        self.replay = replay_cache or ReplayCache(ttl_s=max_ttl_s + 2 * max_skew_s)
        self.limiter = limiter or FailureLimiter()
        self.clock = clock
        self.safe_mode = safe_mode
        self.local_uids = set(local_uids) if local_uids is not None else set()
        self.alert_sink = alert_sink
        self.stats: dict[str, int] = {"accepted": 0, **{cid: 0 for cid in CHECKPOINT_ORDER}}
        self._stats_lock = threading.Lock()

    # ------------------------------------------------------------------ API
    def verify(self, raw: bytes, origin: Origin, declared_length: int | None = None) -> Verdict:
        started = time.perf_counter_ns()
        timings: dict[str, int] = {}
        verdict = Verdict(False, "", "", "", 0.0, origin)
        mark = started
        current = "L0"

        def passed(checkpoint: str) -> None:
            nonlocal mark, current
            now_ns = time.perf_counter_ns()
            timings[checkpoint] = now_ns - mark
            mark = now_ns
            index = CHECKPOINT_ORDER.index(checkpoint)
            current = CHECKPOINT_ORDER[index + 1] if index + 1 < len(CHECKPOINT_ORDER) else "DONE"

        try:
            # L0 - lockout state. Requests are keyed on (peer address, claimed host). Frames with no
            # parsable host use the key (address, "-"); a key locked by forged traffic is cleared by
            # the first request from that key that passes C8 (see _run).
            passed("L0")
            now = self.clock()
            message = self._run(raw, origin, declared_length, now, verdict, passed)
            verdict.accepted = True
            verdict.checkpoint = "PASS"
            verdict.reason = "ACCEPTED"
            verdict.detail = "all 13 checkpoints passed"
            verdict.message = message
        except Exception as unexpected:  # fail closed on any internal fault
            rejection = unexpected if isinstance(unexpected, _Reject) else _Reject(
                current, "INTERNAL_ERROR", f"verifier fault ({type(unexpected).__name__}); request refused")
            timings[current] = time.perf_counter_ns() - mark
            key = lockout_key(origin.address, verdict.sender_host)
            remaining = self.limiter.locked_for(key)
            if remaining > 0:
                # Locked key and the request did not prove itself at C8: refuse at L0, do not re-count.
                rejection = _Reject("L0", "SOURCE_LOCKED_OUT",
                                    f"{key} is locked out for another {remaining:.0f} s "
                                    f"(request would also fail {rejection.checkpoint} {rejection.reason})")
            verdict.checkpoint, verdict.reason, verdict.detail = rejection.checkpoint, rejection.reason, rejection.detail
            if rejection.checkpoint != "L0" and self.limiter.record_failure(key):
                verdict.alerts.append("SOURCE_LOCKOUT")
                self._alert("SOURCE_LOCKOUT", origin, verdict,
                            f"{self.limiter.threshold} failed requests within {self.limiter.window_s:.0f} s; "
                            f"{key} locked for {self.limiter.lockout_s:.0f} s")
            if rejection.reason == "ATTESTATION_MISMATCH":
                verdict.alerts.append("HOST_INTEGRITY_FAILURE")
                self._alert("HOST_INTEGRITY_FAILURE", origin, verdict, rejection.detail)
        verdict.timings_ns = timings
        verdict.latency_us = (time.perf_counter_ns() - started) / 1000.0
        with self._stats_lock:
            self.stats["accepted" if verdict.accepted else verdict.checkpoint] += 1
        return verdict

    # ----------------------------------------------------------- pipeline
    def _run(self, raw: bytes, origin: Origin, declared_length: int | None, now: datetime,
             verdict: Verdict, passed: Callable[[str], None]) -> SignedCommand:
        # C1 - frame size. A frame header claiming more than the limit is refused before reading the body.
        length = declared_length if declared_length is not None else len(raw)
        if origin.channel == "system" and not origin.regular_file:
            raise _Reject("C1", "NOT_REGULAR_FILE", "local command source is a symlink or special file; not read")
        if length <= 0:
            raise _Reject("C1", "FRAME_EMPTY", "empty frame")
        if length > self.max_frame:
            raise _Reject("C1", "FRAME_TOO_LARGE", f"frame of {length} bytes exceeds limit of {self.max_frame} bytes")
        passed("C1")

        # C2 - strict JSON parse and exact schema.
        try:
            message = parse(raw)
        except EnvelopeError as exc:
            raise _Reject("C2", exc.code, exc.detail) from None
        header = message.header
        verdict.msg_id, verdict.sender_host = header.msg_id, header.sender_host
        verdict.key_id, verdict.command = header.key_id, header.command
        if header.command not in cmd.INBOUND_COMMANDS:
            raise _Reject("C2", "SCHEMA_VIOLATION", f"{header.command} is not accepted on an inbound channel")
        passed("C2")

        # C3 - version.
        if header.version not in SUPPORTED_VERSIONS:
            raise _Reject("C3", "UNSUPPORTED_VERSION",
                          f"envelope version {header.version} not in {sorted(SUPPORTED_VERSIONS)}")
        passed("C3")

        # C4 - recipient.
        if not hmac.compare_digest(header.recipient.encode(), self.agent_id.encode()):
            raise _Reject("C4", "WRONG_RECIPIENT", f"addressed to {header.recipient}, this agent is {self.agent_id}")
        passed("C4")

        # C5 - sender host trust.
        host = self.trust.host(header.sender_host)
        if host is None:
            raise _Reject("C5", "UNKNOWN_HOST", f"host {header.sender_host} is not in the trust store")
        if host.revoked:
            raise _Reject("C5", "HOST_REVOKED", f"host {host.host_id} has been revoked (decommissioned)")
        if now < host.valid_from:
            raise _Reject("C5", "HOST_NOT_YET_VALID", f"host {host.host_id} is not valid before {host.valid_from}")
        if now > host.valid_until:
            raise _Reject("C5", "HOST_EXPIRED", f"host {host.host_id} trust expired at {host.valid_until}")
        passed("C5")

        # C6 - key binding, revocation and validity.
        bound = self.trust.key(header.key_id)
        if bound is None or not hmac.compare_digest(bound[0].host_id.encode(), host.host_id.encode()):
            raise _Reject("C6", "KEY_NOT_BOUND", f"key {header.key_id} is not bound to host {host.host_id}")
        record = bound[1]
        revocation = self.trust.revocation(header.key_id)
        if record.revoked or revocation is not None:
            why = revocation.reason if revocation else "key marked revoked"
            raise _Reject("C6", "KEY_REVOKED", f"key {header.key_id} is revoked ({why})")
        if now < record.valid_from:
            raise _Reject("C6", "KEY_NOT_YET_VALID", f"key {header.key_id} not valid before {record.valid_from}")
        if now > record.valid_until:
            raise _Reject("C6", "KEY_EXPIRED", f"key {header.key_id} expired at {record.valid_until}")
        passed("C6")

        # C7 - network origin / trusted host environment.
        if origin.channel == "system":
            if LOCAL_SOURCE not in host.allowed_sources:
                raise _Reject("C7", "ORIGIN_NOT_ALLOWED", f"host {host.host_id} may not use the local channel")
            if origin.file_uid is None or origin.file_uid not in self.local_uids:
                raise _Reject("C7", "LOCAL_SOURCE_UNTRUSTED",
                              f"command file owner uid {origin.file_uid} is not a trusted service account")
            if origin.file_mode is None or origin.file_mode & 0o022:
                raise _Reject("C7", "LOCAL_SOURCE_UNTRUSTED",
                              f"command file mode {oct(origin.file_mode or 0)} is writable by group/others")
        elif not self.trust.origin_allowed(host, origin.address):
            raise _Reject("C7", "ORIGIN_NOT_ALLOWED",
                          f"peer {origin.address} is outside {host.host_id} allowed sources {host.allowed_sources}")
        passed("C7")

        # C8 - Ed25519 signature over canonical header + payload.
        if not verify_signature(self.trust.public_key(header.key_id), message.signature, message.signing_input()):
            raise _Reject("C8", "BAD_SIGNATURE", "Ed25519 signature does not verify over the canonical bytes")
        key = lockout_key(origin.address, header.sender_host)
        if self.limiter.locked_for(key) > 0:
            # Authentic request from an allowed origin: forged traffic must not lock the real host out.
            self.limiter.clear(key)
            verdict.alerts.append("LOCKOUT_CLEARED")
        passed("C8")

        # C9 - payload digest bound into the signed header.
        if not hmac.compare_digest(payload_digest(message.payload), header.payload_sha256):
            raise _Reject("C9", "PAYLOAD_HASH_MISMATCH", "payload_sha256 in the signed header does not match the payload")
        passed("C9")

        # C10 - freshness.
        issued, expires = message.issued_at, message.expires_at
        if issued > now + self.max_skew:
            raise _Reject("C10", "FUTURE_MESSAGE", f"issued {(issued - now).total_seconds():.0f} s in the future")
        if issued < now - self.max_skew:
            raise _Reject("C10", "STALE_MESSAGE",
                          f"issued {(now - issued).total_seconds():.0f} s ago; window is "
                          f"+/-{self.max_skew.total_seconds():.0f} s")
        if expires <= issued or expires - issued > self.max_ttl:
            raise _Reject("C10", "INVALID_LIFETIME", f"lifetime must be 0 < ttl <= {self.max_ttl.total_seconds():.0f} s")
        if now >= expires:
            raise _Reject("C10", "EXPIRED_MESSAGE", f"expired {(now - expires).total_seconds():.1f} s ago")
        passed("C10")

        # C11 - replay protection (only reached by authentic messages).
        problem = self.replay.check_and_add(header.msg_id, header.nonce)
        if problem:
            raise _Reject("C11", problem, "message id or nonce already used inside the replay window")
        passed("C11")

        # C12 - host integrity attestation.
        trusted = host.trusted_release_digests
        if not any(hmac.compare_digest(header.integrity.encode(), d.encode()) for d in trusted):
            raise _Reject("C12", "ATTESTATION_MISMATCH",
                          f"sender code digest {header.integrity[:16]}... is not a trusted release for {host.host_id}")
        passed("C12")

        # C13 - authorization (least privilege), then SAFE MODE restriction.
        granted = self.trust.capabilities(host)
        if header.command not in granted:
            raise _Reject("C13", "COMMAND_NOT_PERMITTED",
                          f"{header.command} is not granted to roles {host.roles} of {host.host_id}")
        if header.command == cmd.STATE_SYNC and cmd.STATE_SYNC_PRIVILEGED_ROLE not in host.roles:
            fields = set(message.payload.get("state", {}))
            forbidden = sorted(fields - cmd.STATE_SYNC_PEER_FIELDS)
            if forbidden:
                raise _Reject("C13", "STATE_FIELD_NOT_PERMITTED",
                              f"STATE_SYNC fields {forbidden} may weaken policy; only "
                              f"{cmd.STATE_SYNC_PRIVILEGED_ROLE} may change them")
        if self.safe_mode and header.command not in cmd.SAFE_MODE_COMMANDS:
            raise _Reject("C13", "SAFE_MODE_RESTRICTED",
                          f"agent is in SAFE MODE (failed self-attestation); {header.command} refused")
        passed("C13")
        return message

    def _alert(self, kind: str, origin: Origin, verdict: Verdict, detail: str) -> None:
        if self.alert_sink:
            self.alert_sink({"alert": kind, "origin": origin.label(), "sender_host": verdict.sender_host,
                             "checkpoint": verdict.checkpoint, "reason": verdict.reason, "detail": detail})


__all__ = ["CHECKPOINTS", "CHECKPOINT_NAMES", "CHECKPOINT_ORDER", "CommandVerifier", "FailureLimiter", "Origin",
           "lockout_key",
           "ReplayCache", "Verdict"]
