"""CommandVerifier: positive and negative test for every checkpoint, ordering, replay, skew, lockout.

Author: Kumar Waibhav Akshat (RA2212704010027).
"""
import json
from datetime import timedelta

import pytest

from ciphermesh.trust import commands as cmd
from ciphermesh.trust.envelope import encode, payload_digest, sign, utc_now
from ciphermesh.trust.verifier import CHECKPOINT_ORDER, CommandVerifier, FailureLimiter, Origin, ReplayCache

from .helpers import OBSERVER_IP, PEER_IP, frame, tcp


def reject(verdict, checkpoint, reason):
    assert not verdict.accepted, verdict
    assert (verdict.checkpoint, verdict.reason) == (checkpoint, reason), verdict.detail


# ---------------------------------------------------------------- positive path

def test_valid_admin_command_passes_all_checkpoints(prov, ids, verifier):
    verdict = verifier.verify(frame(prov, ids["sec-console-01"]), tcp())
    assert verdict.accepted and verdict.checkpoint == "PASS" and verdict.reason == "ACCEPTED"
    assert list(verdict.timings_ns) == CHECKPOINT_ORDER
    assert verdict.message.header.command == cmd.TRIGGER_EMERGENCY_LOCKDOWN and verdict.latency_us > 0
    assert verifier.stats["accepted"] == 1


@pytest.mark.parametrize("host,ip,command", [
    ("observer-01", OBSERVER_IP, cmd.REQUEST_TELEMETRY_DUMP),
    ("peer-gateway-01", PEER_IP, cmd.STATE_SYNC),
    ("peer-gateway-01", PEER_IP, cmd.INSPECT),
    ("sec-console-01", "127.0.0.15", cmd.UPDATE_REDACTION_PATTERNS),
])
def test_each_role_is_accepted_for_its_own_commands(prov, ids, verifier, host, ip, command):
    payload = {cmd.STATE_SYNC: {"state": {"policy_revision": 2}}, cmd.INSPECT: {"text": "hello"},
               cmd.UPDATE_REDACTION_PATTERNS: {"patterns": ["PRJ-[0-9]{4}"]}}.get(command, {})
    assert verifier.verify(frame(prov, ids[host], command, payload), tcp(ip)).accepted


# ----------------------------------------------------------------------- C1

def test_c1_frame_size(prov, ids, store):
    small = CommandVerifier(store, max_frame=200, limiter=FailureLimiter(1000))
    reject(small.verify(frame(prov, ids["sec-console-01"]), tcp()), "C1", "FRAME_TOO_LARGE")
    reject(small.verify(b"", tcp(), declared_length=10**6), "C1", "FRAME_TOO_LARGE")
    reject(small.verify(b"", tcp()), "C1", "FRAME_EMPTY")


# ----------------------------------------------------------------------- C2

@pytest.mark.parametrize("mutator,reason", [
    (lambda raw: raw[:-20], "JSON_MALFORMED"),
    (lambda raw: raw.replace(b'"command":', b'"command":"PING","command":', 1), "JSON_DUPLICATE_KEY"),
    (lambda raw: json.dumps({k: v for k, v in json.loads(raw).items() if k != "signature"}).encode(),
     "SCHEMA_VIOLATION"),
    (lambda raw: json.dumps({**json.loads(raw), "extra": 1}).encode(), "SCHEMA_VIOLATION"),
    (lambda raw: raw.replace(b'"nonce":"', b'"admin":true,"nonce":"', 1), "SCHEMA_VIOLATION"),
    (lambda raw: raw.replace(b'"signature":"', b'"signature":"!!', 1), "SCHEMA_VIOLATION"),
    (lambda raw: b"[1,2,3]", "SCHEMA_VIOLATION"),
])
def test_c2_strict_schema(prov, ids, verifier, mutator, reason):
    reject(verifier.verify(mutator(frame(prov, ids["sec-console-01"])), tcp()), "C2", reason)


def test_c2_reply_is_not_an_inbound_command(prov, ids, verifier):
    raw = frame(prov, ids["sec-console-01"], cmd.REPLY,
                {"in_reply_to": "x", "status": "ACCEPTED", "incident": None, "result": {}})
    reject(verifier.verify(raw, tcp()), "C2", "SCHEMA_VIOLATION")


# ------------------------------------------------------------------ C3 / C4

def test_c3_version(prov, ids, verifier):
    raw = frame(prov, ids["sec-console-01"], mutate_header=lambda h: h.update(version="cm-sig/2"))
    reject(verifier.verify(raw, tcp()), "C3", "UNSUPPORTED_VERSION")


def test_c4_recipient(prov, ids, verifier):
    reject(verifier.verify(frame(prov, ids["sec-console-01"], recipient="ciphermesh-node-02"), tcp()),
           "C4", "WRONG_RECIPIENT")


# ----------------------------------------------------------------------- C5

def test_c5_unknown_and_revoked_host(prov, ids, attacker, verifier):
    reject(verifier.verify(frame(prov, attacker), tcp("127.0.0.67")), "C5", "UNKNOWN_HOST")
    reject(verifier.verify(frame(prov, ids["legacy-console-02"]), tcp("127.0.0.40")), "C5", "HOST_REVOKED")


def test_c5_host_validity_window(prov, ids, store):
    late = CommandVerifier(store, clock=lambda: utc_now() + timedelta(days=400), limiter=FailureLimiter(1000))
    early = CommandVerifier(store, clock=lambda: utc_now() - timedelta(days=3), limiter=FailureLimiter(1000))
    raw = frame(prov, ids["sec-console-01"])
    reject(late.verify(raw, tcp()), "C5", "HOST_EXPIRED")
    reject(early.verify(raw, tcp()), "C5", "HOST_NOT_YET_VALID")


# ----------------------------------------------------------------------- C6

def test_c6_key_must_belong_to_claimed_host(prov, ids, attacker, verifier):
    spoof = frame(prov, attacker, mutate_header=lambda h: h.update(sender_host="sec-console-01"))
    reject(verifier.verify(spoof, tcp()), "C6", "KEY_NOT_BOUND")
    borrowed = frame(prov, ids["observer-01"], mutate_header=lambda h: h.update(sender_host="sec-console-01"))
    reject(verifier.verify(borrowed, tcp()), "C6", "KEY_NOT_BOUND")


def test_c6_revoked_key(prov, verifier):
    reject(verifier.verify(frame(prov, prov.old_admin_identity), tcp("127.0.0.9")), "C6", "KEY_REVOKED")


def test_c6_key_validity_window(prov, ids, store):
    host = store.host("observer-01")
    key = host.keys[0].model_copy(update={"valid_until": utc_now() - timedelta(seconds=1),
                                          "valid_from": utc_now() - timedelta(days=2)})
    store._replace_host(host.model_copy(update={"keys": [key]}))
    verifier = CommandVerifier(store, limiter=FailureLimiter(1000))
    reject(verifier.verify(frame(prov, ids["observer-01"], cmd.PING), tcp(OBSERVER_IP)), "C6", "KEY_EXPIRED")


# ----------------------------------------------------------------------- C7

def test_c7_network_origin(prov, ids, verifier):
    raw = frame(prov, ids["sec-console-01"])
    reject(verifier.verify(raw, tcp("127.0.0.66")), "C7", "ORIGIN_NOT_ALLOWED")
    reject(verifier.verify(frame(prov, ids["sec-console-01"]), tcp("not-an-ip")), "C7", "ORIGIN_NOT_ALLOWED")
    assert verifier.verify(frame(prov, ids["sec-console-01"]), tcp("127.0.0.8")).accepted


def test_c7_local_channel_owner_mode_and_host_permission(prov, ids, store):
    verifier = CommandVerifier(store, local_uids={1000}, limiter=FailureLimiter(1000))
    ok = Origin("system", "local", "cmd.json", file_uid=1000, file_mode=0o600)
    assert verifier.verify(frame(prov, ids["sec-console-01"]), ok).accepted
    reject(verifier.verify(frame(prov, ids["sec-console-01"]),
                           Origin("system", "local", "cmd.json", file_uid=0, file_mode=0o600)),
           "C7", "LOCAL_SOURCE_UNTRUSTED")
    reject(verifier.verify(frame(prov, ids["sec-console-01"]),
                           Origin("system", "local", "cmd.json", file_uid=1000, file_mode=0o666)),
           "C7", "LOCAL_SOURCE_UNTRUSTED")
    reject(verifier.verify(frame(prov, ids["observer-01"], cmd.PING), ok), "C7", "ORIGIN_NOT_ALLOWED")


# ------------------------------------------------------------------- C8 / C9

def test_c8_forged_and_tampered_signatures(prov, ids, attacker, verifier):
    admin = ids["sec-console-01"]
    forged = frame(prov, attacker, mutate_header=lambda h: h.update(sender_host="sec-console-01", key_id=admin.key_id))
    reject(verifier.verify(forged, tcp()), "C8", "BAD_SIGNATURE")

    def swap(env):
        env["payload"] = {"patterns": ["[a-z]{1,}"]}
        env["header"]["payload_sha256"] = payload_digest(env["payload"])
    tampered = frame(prov, admin, cmd.UPDATE_REDACTION_PATTERNS, {"patterns": ["PRJ-1"]}, mutate_payload=swap)
    reject(verifier.verify(tampered, tcp()), "C8", "BAD_SIGNATURE")


def test_c9_header_digest_must_match_payload(prov, ids, verifier):
    raw = frame(prov, ids["sec-console-01"], mutate_header=lambda h: h.update(payload_sha256="0" * 64))
    reject(verifier.verify(raw, tcp()), "C9", "PAYLOAD_HASH_MISMATCH")


# ---------------------------------------------------------------------- C10

@pytest.mark.parametrize("shift,ttl,reason", [
    (-600, 30, "STALE_MESSAGE"), (-61, 120, "STALE_MESSAGE"), (61, 30, "FUTURE_MESSAGE"),
    (-20, 5, "EXPIRED_MESSAGE"), (0, 300, "INVALID_LIFETIME"),
])
def test_c10_freshness(prov, ids, verifier, shift, ttl, reason):
    reject(verifier.verify(frame(prov, ids["sec-console-01"], shift_s=shift, ttl_s=ttl), tcp()), "C10", reason)


@pytest.mark.parametrize("shift", [-55, 55])
def test_c10_clock_skew_inside_window_is_tolerated(prov, ids, verifier, shift):
    assert verifier.verify(frame(prov, ids["sec-console-01"], shift_s=shift, ttl_s=120), tcp()).accepted


def test_c10_receiver_clock_skew(prov, ids, store):
    raw = frame(prov, ids["sec-console-01"])
    fast = CommandVerifier(store, clock=lambda: utc_now() + timedelta(seconds=90), limiter=FailureLimiter(1000))
    reject(fast.verify(raw, tcp()), "C10", "STALE_MESSAGE")
    slightly = CommandVerifier(store, clock=lambda: utc_now() + timedelta(seconds=20), limiter=FailureLimiter(1000))
    assert slightly.verify(raw, tcp()).accepted


# ---------------------------------------------------------------------- C11

def test_c11_replay_of_msg_id_and_reuse_of_nonce(prov, ids, verifier):
    raw = frame(prov, ids["sec-console-01"])
    assert verifier.verify(raw, tcp()).accepted
    reject(verifier.verify(raw, tcp()), "C11", "REPLAY_MSG_ID")
    reused = frame(prov, ids["sec-console-01"], nonce="ab" * 16)
    assert verifier.verify(reused, tcp()).accepted
    reject(verifier.verify(frame(prov, ids["sec-console-01"], nonce="ab" * 16), tcp()), "C11", "REPLAY_NONCE")


def test_c11_forged_messages_do_not_poison_the_replay_cache(prov, ids, attacker, verifier):
    admin = ids["sec-console-01"]
    good = frame(prov, admin, raw_env=True)
    forged = sign(attacker, dict(good["header"]), good["payload"])   # same msg_id/nonce, attacker signature
    reject(verifier.verify(encode(forged), tcp()), "C8", "BAD_SIGNATURE")
    assert verifier.verify(encode(good), tcp()).accepted


def test_replay_cache_ttl_expiry_and_fail_closed_when_full():
    cache = ReplayCache(ttl_s=10, max_entries=4)
    assert cache.check_and_add("m1", "n1", now=0) is None
    assert cache.check_and_add("m1", "n9", now=5) == "REPLAY_MSG_ID"
    assert cache.check_and_add("m2", "n2", now=6) is None
    assert cache.check_and_add("m3", "n3", now=7) == "REPLAY_CACHE_FULL"
    assert cache.check_and_add("m1", "n1", now=11) is None      # m1 expired after its TTL


# ---------------------------------------------------------------------- C12

def test_c12_attestation_mismatch_raises_alert(prov, ids, store):
    alerts = []
    verifier = CommandVerifier(store, alert_sink=alerts.append, limiter=FailureLimiter(1000))
    verdict = verifier.verify(frame(prov, ids["sec-console-01"], integrity="b" * 64), tcp())
    reject(verdict, "C12", "ATTESTATION_MISMATCH")
    assert alerts and alerts[0]["alert"] == "HOST_INTEGRITY_FAILURE" and "HOST_INTEGRITY_FAILURE" in verdict.alerts


# ---------------------------------------------------------------------- C13

def test_c13_least_privilege(prov, ids, verifier):
    reject(verifier.verify(frame(prov, ids["observer-01"]), tcp(OBSERVER_IP)), "C13", "COMMAND_NOT_PERMITTED")
    reject(verifier.verify(frame(prov, ids["peer-gateway-01"], cmd.REQUEST_TELEMETRY_DUMP), tcp(PEER_IP)),
           "C13", "COMMAND_NOT_PERMITTED")
    reject(verifier.verify(frame(prov, ids["observer-01"], cmd.UPDATE_REDACTION_PATTERNS, {"patterns": ["A"]}),
                           tcp(OBSERVER_IP)), "C13", "COMMAND_NOT_PERMITTED")


def test_c13_safe_mode_allows_only_read_only_commands(prov, ids, store):
    verifier = CommandVerifier(store, safe_mode=True, limiter=FailureLimiter(1000))
    reject(verifier.verify(frame(prov, ids["sec-console-01"]), tcp()), "C13", "SAFE_MODE_RESTRICTED")
    assert verifier.verify(frame(prov, ids["sec-console-01"], cmd.REQUEST_TELEMETRY_DUMP), tcp()).accepted


# ------------------------------------------------------- ordering, lockout, faults

def test_first_failing_checkpoint_wins(prov, attacker, verifier):
    # wrong recipient + unknown host + forged signature + stale: C4 is reported.
    raw = frame(prov, attacker, recipient="ciphermesh-node-02", shift_s=-900)
    reject(verifier.verify(raw, tcp("127.0.0.66")), "C4", "WRONG_RECIPIENT")


def test_lockout_is_per_address_and_claimed_host_and_cleared_by_authentic_request(prov, ids, attacker, store):
    alerts = []
    verifier = CommandVerifier(store, limiter=FailureLimiter(threshold=5, window_s=60, lockout_s=300),
                               alert_sink=alerts.append)
    admin = ids["sec-console-01"]
    forged = lambda: frame(prov, attacker, mutate_header=lambda h: h.update(  # noqa: E731
        sender_host="sec-console-01", key_id=admin.key_id))
    verdicts = [verifier.verify(forged(), tcp()) for _ in range(5)]
    assert verdicts[-1].alerts == ["SOURCE_LOCKOUT"] and alerts[0]["alert"] == "SOURCE_LOCKOUT"
    reject(verifier.verify(forged(), tcp()), "L0", "SOURCE_LOCKED_OUT")
    reject(verifier.verify(frame(prov, admin, recipient="ciphermesh-node-02"), tcp()), "L0", "SOURCE_LOCKED_OUT")
    cleared = verifier.verify(frame(prov, admin), tcp())          # authentic: passes C8 and clears the lock
    assert cleared.accepted and "LOCKOUT_CLEARED" in cleared.alerts
    reject(verifier.verify(forged(), tcp()), "C8", "BAD_SIGNATURE")   # counted afresh, not locked


def test_junk_from_an_address_does_not_lock_out_a_host_using_it(prov, ids, store):
    verifier = CommandVerifier(store, limiter=FailureLimiter(threshold=5, window_s=60, lockout_s=300))
    for _ in range(5):
        verifier.verify(b"garbage", tcp())
    reject(verifier.verify(b"more garbage", tcp()), "L0", "SOURCE_LOCKED_OUT")
    assert verifier.verify(frame(prov, ids["sec-console-01"]), tcp()).accepted


def test_c13_peer_state_sync_cannot_weaken_policy(prov, ids, verifier):
    weaken = {"state": {"policy_revision": 9, "custom_redaction_patterns": [], "block_critical_secrets": False,
                        "redact_email_phone_ip": False}}
    reject(verifier.verify(frame(prov, ids["peer-gateway-01"], cmd.STATE_SYNC, weaken), tcp(PEER_IP)),
           "C13", "STATE_FIELD_NOT_PERMITTED")
    for field, value in [("require_review_for_internal_urls", False), ("force_block_all", False),
                         ("custom_redaction_patterns", ["X"])]:
        payload = {"state": {"policy_revision": 9, field: value}}
        reject(verifier.verify(frame(prov, ids["peer-gateway-01"], cmd.STATE_SYNC, payload), tcp(PEER_IP)),
               "C13", "STATE_FIELD_NOT_PERMITTED")
    safe = {"state": {"policy_revision": 9, "policy_version": "1.9", "provider_allowlist": ["local"],
                      "max_prompt_bytes": 32768}}
    assert verifier.verify(frame(prov, ids["peer-gateway-01"], cmd.STATE_SYNC, safe), tcp(PEER_IP)).accepted
    assert verifier.verify(frame(prov, ids["sec-console-01"], cmd.STATE_SYNC, weaken), tcp()).accepted


def test_failure_limiter_window_and_expiry():
    limiter = FailureLimiter(threshold=3, window_s=10, lockout_s=30)
    assert not limiter.record_failure("x", now=0)
    assert not limiter.record_failure("x", now=1)
    assert not limiter.record_failure("x", now=20)              # first two slid out of the window
    assert not limiter.record_failure("x", now=21)
    assert limiter.record_failure("x", now=22)
    assert limiter.locked_for("x", now=30) > 0 and limiter.locked_for("x", now=53) == 0


def test_internal_fault_fails_closed(prov, ids, store, monkeypatch):
    verifier = CommandVerifier(store, limiter=FailureLimiter(1000))
    monkeypatch.setattr(store, "capabilities", lambda host: (_ for _ in ()).throw(RuntimeError("boom")))
    verdict = verifier.verify(frame(prov, ids["sec-console-01"]), tcp())
    reject(verdict, "C13", "INTERNAL_ERROR")
    assert "boom" not in verdict.detail
