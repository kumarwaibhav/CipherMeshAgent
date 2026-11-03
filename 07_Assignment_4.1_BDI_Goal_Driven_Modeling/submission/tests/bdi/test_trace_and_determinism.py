"""Trace completeness, privacy of logs, evidence integrity and run determinism.

Author: Kumar Waibhav Akshat (RA2212704010027)
"""
import json

from ciphermesh.bdi.scenarios import build_scenarios, run_scenario
from ciphermesh.bdi.services import EvidenceLedger
from ciphermesh.bdi.trace import EVENT_TYPES, Tracer


def _signature(agent):
    return [(e["event"], e.get("intention"), e.get("plan"), json.dumps(e.get("params"), sort_keys=True),
             e.get("step"), e.get("ok"), e.get("key"), json.dumps(e.get("new"), sort_keys=True, default=str))
            for e in agent.tracer.events]


def test_runs_are_deterministic():
    for idx in (1, 4, 6, 7):
        a1, r1, _ = run_scenario(build_scenarios()[idx])
        a2, r2, _ = run_scenario(build_scenarios()[idx])
        assert _signature(a1) == _signature(a2)
        assert [s.adopted["label"] for s in r1.shifts] == [s.adopted["label"] for s in r2.shifts]


def test_trace_covers_every_cycle_phase():
    seen = set()
    for scenario in build_scenarios():
        agent, _, _ = run_scenario(scenario)
        seen |= {e["event"] for e in agent.tracer.events}
    for required in ("PERCEIVE", "BELIEF", "DESIRE", "DELIBERATE", "INTEND", "STEP", "RECONSIDER", "DROP",
                     "REPLAN", "COMPLETE", "SUSPEND", "RESUME", "FINISH"):
        assert required in seen
    assert seen <= set(EVENT_TYPES)


def test_trace_never_contains_raw_secrets_or_identifiers(tmp_path):
    secrets = ["AKIAIOSFODNN7EXAMPLE", "2345 6789 0124", "ABCPE1234F", "priya.sharma@example.in",
               "jira.corp.internal"]
    for scenario in build_scenarios():
        agent, _, _ = run_scenario(scenario)
        path = tmp_path / f"{scenario.id}.jsonl"
        agent.tracer.write_jsonl(path)
        blob = path.read_text() + "\n".join(agent.tracer.lines) + json.dumps(agent.beliefs.snapshot(), default=str)
        for s in secrets:
            assert s not in blob, f"{s} leaked in {scenario.id}"


def test_every_trace_line_is_valid_json_with_timestamps(tmp_path):
    agent, _, _ = run_scenario(build_scenarios()[1])
    path = tmp_path / "t.jsonl"
    agent.tracer.write_jsonl(path)
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert rows and all({"ts", "t_ms", "cycle", "event", "msg"} <= set(r) for r in rows)
    assert [r["t_ms"] for r in rows] == sorted(r["t_ms"] for r in rows)


def test_unknown_trace_event_rejected():
    import pytest
    with pytest.raises(ValueError):
        Tracer().emit("GUESS", 0, "x")


def test_evidence_ledger_detects_tampering():
    ledger = EvidenceLedger(key="k")
    ledger.seal("a", {"x": 1})
    ledger.seal("b", {"x": 2})
    assert ledger.verify()
    ledger._records[0].record["x"] = 99
    assert not ledger.verify()


def test_intention_changes_are_written_to_engine_audit_log():
    agent, _, _ = run_scenario(build_scenarios()[1])
    kinds = [e["event_type"] for e in agent.services.agent.audit.recent(100)]
    assert "bdi_intention_dropped" in kinds and kinds.count("bdi_intention_adopted") == 2
