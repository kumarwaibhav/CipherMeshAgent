"""Scenario tests: the full breach simulation, the integrity run and the benchmark all pass end to end.

Author: Kumar Waibhav Akshat (RA2212704010027).
"""
import json
import logging

from ciphermesh.trust import attack_sim, benchmark, integrity_check
from ciphermesh.trust.provision import provision

from .helpers import PASS


def test_breach_simulation_blocks_every_attack_and_keeps_state(tmp_path):
    prov = provision(tmp_path / "trust", tmp_path / "keys", passphrase=PASS)
    summary = attack_sim.BreachSimulation(prov.trust_dir, prov.keys_dir, tmp_path, PASS).run()
    totals = summary["totals"]
    assert totals["all_passed"], [c["sid"] for c in summary["cases"] if not c["passed"]]
    assert totals["attacks_blocked"] == totals["attacks"] == totals["attacks_blocked_at_expected_checkpoint"]
    assert totals["legitimate_accepted"] == totals["legitimate"]
    assert totals["state_unchanged_for_every_rejection"] and totals["baseline_equals_final_state"]
    blocked = set(summary["blocked_by_checkpoint"])
    assert {f"C{i}" for i in range(1, 14)} | {"L0"} <= blocked
    events = [json.loads(line) for line in (tmp_path / "security_events.jsonl").read_text().splitlines()]
    rejected = [e for e in events if e["event"] == "COMMAND_REJECTED"]
    transport = [e for e in rejected if e["reason"] in ("FRAME_TIMEOUT", "CONNECTION_LIMIT")]
    assert len(rejected) - len(transport) == totals["attacks"] - 2       # A28.1/A28.2 summarise 5 connections
    assert sorted(e["reason"] for e in transport) == ["CONNECTION_LIMIT"] + ["FRAME_TIMEOUT"] * 4
    assert any(c["sid"] == "A26" and c["reason"] == "STATE_FIELD_NOT_PERMITTED" for c in summary["cases"])
    assert any(e["event"] == "SECURITY_ALERT" and e["alert"] == "SOURCE_LOCKOUT" for e in events)
    assert (tmp_path / "breach_simulation_summary.txt").read_text().count("PASS") >= totals["cases"]


def test_integrity_check_run_detects_all_tampering(tmp_path):
    prov = provision(tmp_path / "trust", tmp_path / "keys", passphrase=PASS)
    logging.getLogger("ciphermesh.trust.agent").setLevel(logging.CRITICAL)
    result = integrity_check.run(prov.trust_dir, prov.keys_dir, PASS)
    logging.getLogger("ciphermesh.trust.agent").setLevel(logging.NOTSET)
    assert result["passed"] == result["total"] == 11


def test_benchmark_produces_complete_report():
    results = benchmark.run(n=40)
    text = benchmark.render(results)
    assert results["verify_accepted_total"]["n"] == 40 and len(results["per_checkpoint"]) == 14
    assert "Ed25519 verify" in text and "C13" in text
    logging.getLogger("ciphermesh.trust").setLevel(logging.NOTSET)
