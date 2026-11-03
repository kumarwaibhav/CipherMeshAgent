"""SecureCipherMeshAgent: execution on real engine state, audit hygiene, SAFE MODE, system-command channel.

Author: Kumar Waibhav Akshat (RA2212704010027).
"""
import json
import os

import pytest

from ciphermesh.trust import commands as cmd
from ciphermesh.trust.attack_sim import tamper_copy
from ciphermesh.trust.client import verify_reply
from ciphermesh.trust.integrity import IntegrityError, package_root
from ciphermesh.trust.keys import SigningIdentity
from ciphermesh.trust.secure_agent import AgentConfig, SecureCipherMeshAgent, SystemCommandChannel

from .helpers import OBSERVER_IP, frame, tcp


def test_agent_refuses_foreign_identity(prov, make_agent, store):
    agent = make_agent()
    with pytest.raises(ValueError):
        SecureCipherMeshAgent(SigningIdentity.generate("ciphermesh-node-01"), store, signed_manifest={},
                              release_public_key=agent.identity.public_key)


def test_lockdown_and_release_drive_the_real_policy_engine(prov, ids, make_agent):
    agent = make_agent()
    assert agent.engine.inspect("hello world", open_review=False).decision.value == "ALLOW"
    result = agent.handle_frame(frame(prov, ids["sec-console-01"]), tcp())
    assert result.status == "ACCEPTED" and result.state_changed and agent.engine.state.force_block_all
    assert agent.engine.inspect("hello world", open_review=False).decision.value == "BLOCK"
    agent.handle_frame(frame(prov, ids["sec-console-01"], cmd.RELEASE_LOCKDOWN), tcp())
    assert agent.engine.inspect("hello world", open_review=False).decision.value == "ALLOW"


def test_pattern_update_changes_redaction_and_bad_regex_is_refused_by_engine(prov, ids, make_agent):
    agent = make_agent()
    agent.handle_frame(frame(prov, ids["sec-console-01"], cmd.UPDATE_REDACTION_PATTERNS,
                             {"patterns": ["PRJ-[0-9]{4}"]}), tcp())
    assert agent.engine.inspect("about PRJ-2041", open_review=False).decision.value == "REDACT"
    before = agent.state_summary()
    bad = agent.handle_frame(frame(prov, ids["sec-console-01"], cmd.UPDATE_REDACTION_PATTERNS,
                                   {"patterns": ["(a+)+$"]}), tcp())
    assert bad.verdict.accepted and bad.status == "FAILED" and agent.state_summary() == before


def test_rejected_command_leaves_state_and_replies_generically(prov, ids, attacker, make_agent):
    agent = make_agent()
    before = agent.state_summary()
    result = agent.handle_frame(frame(prov, attacker), tcp("127.0.0.66"))
    assert result.status == "REJECTED" and not result.state_changed and agent.state_summary() == before
    reply = verify_reply(result.reply, agent.trust, "rogue-console-99", result.verdict.msg_id)
    assert reply.verified and reply.status == "REJECTED" and reply.incident == "INC-00001"
    assert "C5" not in json.dumps(reply.result) and "UNKNOWN_HOST" not in json.dumps(reply.result)


def test_audit_log_has_every_decision_but_no_payload_values(prov, ids, make_agent, tmp_path):
    agent = make_agent()
    secret_text = "Mail priya.sharma@example.com the payroll"
    agent.handle_frame(frame(prov, ids["peer-gateway-01"], cmd.INSPECT, {"text": secret_text}), tcp("127.0.0.30"))
    agent.handle_frame(frame(prov, ids["sec-console-01"], cmd.UPDATE_REDACTION_PATTERNS,
                             {"patterns": ["SECRETPROJ-[0-9]{3}"]}), tcp())
    agent.handle_frame(frame(prov, ids["observer-01"]), tcp(OBSERVER_IP))
    text = (tmp_path / "events.jsonl").read_text()
    events = [json.loads(line) for line in text.splitlines()]
    assert [e["event"] for e in events] == ["SELF_ATTESTATION", "COMMAND_ACCEPTED", "COMMAND_ACCEPTED",
                                            "COMMAND_REJECTED"]
    assert events[-1]["checkpoint"] == "C13" and events[-1]["state_changed"] is False
    for forbidden in ("priya.sharma", "SECRETPROJ", "signature", "BEGIN", "payroll"):
        assert forbidden not in text


def test_reply_signature_and_addressing_are_checked_by_client(prov, ids, make_agent):
    agent = make_agent()
    result = agent.handle_frame(frame(prov, ids["observer-01"], cmd.REQUEST_TELEMETRY_DUMP), tcp(OBSERVER_IP))
    ok = verify_reply(result.reply, agent.trust, "observer-01", result.verdict.msg_id)
    assert ok.verified and ok.agent_integrity_trusted and ok.result["status"] == "telemetry_ready"
    assert verify_reply(result.reply, agent.trust, "sec-console-01", None).problem == "REPLY_NOT_ADDRESSED_TO_US"
    assert verify_reply(result.reply, agent.trust, "observer-01", "other").problem == "REPLY_CORRELATION_MISMATCH"
    tampered = result.reply.replace(b"telemetry_ready", b"telemetry_READY")
    assert verify_reply(tampered, agent.trust, "observer-01", None).problem == "BAD_SIGNATURE"


def test_tampered_code_gives_safe_mode_or_refusal(prov, ids, make_agent, tmp_path):
    bad_root = tamper_copy(package_root(), tmp_path)
    with pytest.raises(IntegrityError):
        make_agent(code_root=bad_root, config=AgentConfig(strict_integrity=True))
    agent = make_agent(code_root=bad_root)
    assert agent.safe_mode and agent.integrity.mismatched[0]["file"] == "policy.py"
    locked = agent.handle_frame(frame(prov, ids["sec-console-01"]), tcp())
    assert (locked.verdict.checkpoint, locked.verdict.reason) == ("C13", "SAFE_MODE_RESTRICTED")
    assert not agent.engine.state.force_block_all
    telemetry = agent.handle_frame(frame(prov, ids["observer-01"], cmd.REQUEST_TELEMETRY_DUMP), tcp(OBSERVER_IP))
    assert telemetry.status == "ACCEPTED"
    assert not verify_reply(telemetry.reply, agent.trust, "observer-01", None).agent_integrity_trusted


def test_system_command_spool_channel(prov, ids, attacker, make_agent, tmp_path):
    agent = make_agent()
    channel = SystemCommandChannel(agent, tmp_path / "spool")
    good = channel.incoming / "01-good.json"
    good.write_bytes(frame(prov, ids["sec-console-01"], cmd.UPDATE_REDACTION_PATTERNS, {"patterns": ["EMP-[0-9]{6}"]}))
    os.chmod(good, 0o600)
    loose = channel.incoming / "02-loose.json"
    loose.write_bytes(frame(prov, ids["sec-console-01"]))
    os.chmod(loose, 0o666)
    forged = channel.incoming / "03-forged.json"
    forged.write_bytes(frame(prov, attacker, mutate_header=lambda h: h.update(
        sender_host="sec-console-01", key_id=ids["sec-console-01"].key_id)))
    os.chmod(forged, 0o600)
    target = channel.incoming / "real.txt"
    target.write_bytes(frame(prov, ids["sec-console-01"]))
    os.symlink(target, channel.incoming / "04-link.json")
    results = channel.process_spool()
    assert [(r.verdict.checkpoint, r.verdict.reason) for r in results] == [
        ("PASS", "ACCEPTED"), ("C7", "LOCAL_SOURCE_UNTRUSTED"), ("C8", "BAD_SIGNATURE"),
        ("C1", "NOT_REGULAR_FILE")]
    assert agent.engine.state.custom_redaction_patterns == ["EMP-[0-9]{6}"] and not agent.engine.state.force_block_all
    assert (tmp_path / "spool" / "processed" / "01-good.json").exists()
    assert len(list((tmp_path / "spool" / "rejected").iterdir())) == 3
    assert len(list((tmp_path / "spool" / "replies").iterdir())) == 4


def test_world_writable_spool_directory_is_refused(make_agent, tmp_path):
    spool = tmp_path / "open"
    spool.mkdir()
    os.chmod(spool, 0o777)
    with pytest.raises(PermissionError):
        SystemCommandChannel(make_agent(), spool)


def test_log_strings_from_attackers_are_neutralised():
    from ciphermesh.trust.secure_agent import _safe
    assert "\n" not in _safe("evil\n2026-01-01 | INFO | [AGENT] ACCEPTED") and len(_safe("x" * 1000)) < 310


def test_peer_state_sync_cannot_switch_off_secret_blocking(prov, ids, make_agent):
    agent = make_agent()
    weaken = {"state": {"policy_revision": agent.engine.state.policy_revision + 1, "custom_redaction_patterns": [],
                        "block_critical_secrets": False, "redact_email_phone_ip": False}}
    before = agent.state_summary()
    result = agent.handle_frame(frame(prov, ids["peer-gateway-01"], cmd.STATE_SYNC, weaken), tcp("127.0.0.30"))
    assert (result.verdict.checkpoint, result.verdict.reason) == ("C13", "STATE_FIELD_NOT_PERMITTED")
    assert agent.state_summary() == before and agent.engine.state.block_critical_secrets
    assert agent.engine.inspect("Use AKIAIOSFODNN7EXAMPLE now", open_review=False).decision.value == "BLOCK"


def test_changed_trust_store_refuses_start_even_without_strict_mode(prov, make_agent, tmp_path):
    data = json.loads(prov.trust_path.read_bytes())
    data["hosts"][2]["roles"] = ["security-admin"]
    rogue = tmp_path / "trusted_hosts.json"
    rogue.write_text(json.dumps(data, indent=2))
    from ciphermesh.trust.integrity import load_signed_manifest
    from ciphermesh.trust.keys import TrustStore, load_public_key
    with pytest.raises(IntegrityError, match="trusted_hosts.json"):
        SecureCipherMeshAgent(prov.identities["ciphermesh-node-01"], TrustStore.load(rogue),
                              signed_manifest=load_signed_manifest(prov.manifest_path),
                              release_public_key=load_public_key(prov.release_pub_path), trust_store_path=rogue,
                              config=AgentConfig(strict_integrity=False))


def test_spool_survives_vanished_files_and_fifos(prov, ids, make_agent, tmp_path):
    agent = make_agent()
    channel = SystemCommandChannel(agent, tmp_path / "spool")
    assert channel.process_file(channel.incoming / "gone.json") is None
    os.mkfifo(channel.incoming / "fifo.json", 0o600)
    good = channel.incoming / "z-good.json"
    good.write_bytes(frame(prov, ids["sec-console-01"], cmd.PING))
    os.chmod(good, 0o600)
    results = channel.process_spool()
    assert [(r.verdict.checkpoint, r.verdict.reason) for r in results] == [("C1", "NOT_REGULAR_FILE"),
                                                                           ("PASS", "ACCEPTED")]
