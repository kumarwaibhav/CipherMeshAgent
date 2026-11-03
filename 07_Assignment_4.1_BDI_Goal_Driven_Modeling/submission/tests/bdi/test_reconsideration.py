"""Scenario tests: every unexpected belief update produces the right intention shift.

Author: Kumar Waibhav Akshat (RA2212704010027)
"""
import pytest

from ciphermesh.bdi.engine import CommitmentStrategy
from ciphermesh.bdi.scenarios import (Disturbance, Environment, Trigger, ablation_scenarios, build_scenarios,
                                      run_scenario)
from ciphermesh.bdi.world import pkey

SCENARIOS = {s.id: s for s in build_scenarios()}


def _run(sid):
    scenario = {s.id: s for s in build_scenarios() + ablation_scenarios()}[sid]
    agent, result, env = run_scenario(scenario)
    return scenario, agent, result, env


def _final(result):
    return next(i for i in reversed(result.intentions) if i["status"] == "SUCCEEDED")


@pytest.mark.parametrize("sid", sorted(SCENARIOS))
def test_scenario_meets_expectation(sid):
    scenario, agent, result, env = _run(sid)
    assert env.unfired() == []
    assert result.intentions[0]["label"] == scenario.expect_initial
    assert result.final_status == scenario.expect_status
    assert _final(result)["label"] == scenario.expect_final_plan
    assert result.ledger_verified


def test_baseline_has_no_shift_and_no_reconsideration_drop():
    _, agent, result, _ = _run("S0")
    assert result.shifts == [] and result.reconsideration["dropped"] == 0
    assert len(result.intentions) == 1 and result.delivered


def test_outage_drops_before_dispatch_and_switches_provider():
    _, agent, result, _ = _run("S1")
    (shift,) = result.shifts
    assert shift.status == "DROPPED" and shift.before_step == "seal_dispatch_record"
    assert shift.trigger[0]["key"] == "provider.gcp-vertex.status" and shift.trigger[0]["new"] == "major_outage"
    assert "provider gcp-vertex is usable" in shift.reasons[0]
    assert shift.adopted["label"] == "allow_then_dispatch(provider=aws-bedrock)"
    assert [t["provider"] for t in result.transmissions] == ["aws-bedrock"]


def test_lockdown_preempts_and_nothing_is_transmitted():
    _, agent, result, _ = _run("S2")
    (shift,) = result.shifts
    assert any("pre-empted by D1" in r for r in shift.reasons)
    assert shift.adopted["desire"] == "D1" and shift.adopted["plan"] == "enforce_lockdown_block"
    assert result.transmissions == [] and agent.services.agent.state.force_block_all is True
    assert not any(e["event"] == "STEP" and e["step"] == "dispatch" for e in agent.tracer.events)


def test_reply_leak_is_withheld_and_alerted():
    _, agent, result, _ = _run("S3")
    (shift,) = result.shifts
    assert shift.before_step == "deliver" and shift.trigger[0]["key"] == "response.findings"
    assert result.delivered is False and agent.request.raw_response is None
    assert agent.request.delivered_text is None and agent.beliefs.get("threat.level") == "high"
    assert any(e["event_type"] == "bdi_security_alert" for e in agent.services.agent.audit.recent(50))


def test_price_spike_then_budget_cut_replans_twice():
    _, agent, result, _ = _run("S4")
    assert [s.adopted["label"] for s in result.shifts] == ["allow_then_dispatch(provider=aws-bedrock)",
                                                           "dispatch_local_only(provider=local)"]
    assert all("price within budget" in s.reasons[0] for s in result.shifts)
    (tx,) = result.transmissions
    assert tx["provider"] == "local" and agent.beliefs.get("dispatch.effective_cost") <= 1.0


@pytest.mark.parametrize("sid", ["S5", "S6"])
def test_residency_is_never_violated(sid):
    _, agent, result, _ = _run(sid)
    assert result.transmissions, "the request should still be answered"
    for tx in result.transmissions:
        assert tx["residency"] in {"IN", "LOCAL"} and tx["redacted"] is True
    assert agent.beliefs.get("dispatch.residency_violations") == 0


def test_prompt_correction_activates_d2_mid_execution():
    _, agent, result, _ = _run("S6")
    desire_events = [e for e in agent.tracer.events if e["event"] == "DESIRE" and e["desire"] == "D2"]
    assert desire_events and desire_events[0]["state"] == "constraining"
    drop = next(e for e in agent.tracer.events if e["event"] == "DROP")
    assert desire_events[0]["t_ms"] <= drop["t_ms"]


def test_transient_outage_suspends_then_resumes_without_replanning():
    _, agent, result, _ = _run("S7")
    kinds = [e["event"] for e in agent.tracer.events if e["event"] in {"SUSPEND", "RESUME", "DROP", "INTEND"}]
    assert kinds == ["INTEND", "SUSPEND", "RESUME"]
    assert result.reconsideration["suspended"] == 1 and result.reconsideration["resumed"] == 1


def test_suspension_times_out_into_a_drop():
    scenario = SCENARIOS["S7"]
    scenario = type(scenario)(**{**scenario.__dict__, "disturbances": [build_scenarios()[7].disturbances[0]]})
    agent, result, _ = run_scenario(scenario)
    (shift,) = result.shifts
    assert "suspension timeout" in shift.reasons[0]
    assert shift.adopted["label"] == "allow_then_dispatch(provider=aws-bedrock)"
    assert result.final_status == "COMPLETED"


def test_review_backlog_shift_crosses_desires():
    _, agent, result, _ = _run("S8")
    (shift,) = result.shifts
    assert shift.dropped["desire"] == "D3" and shift.adopted["desire"] == "D5"
    assert "D3" in result.impossible and result.transmissions == []


def test_blind_commitment_executes_a_doomed_step():
    _, _, open_r, _ = _run("S1")
    _, _, blind_r, _ = _run("S1-BLIND")
    assert open_r.reconsideration["failed"] == 0 and blind_r.reconsideration["failed"] == 1
    assert blind_r.steps_executed > open_r.steps_executed
    assert blind_r.shifts[0].status == "FAILED" and blind_r.reconsideration["evaluated"] == 0
    assert "interlock" in blind_r.shifts[0].reasons[0]
    assert [t["provider"] for t in blind_r.transmissions] == ["aws-bedrock"]


def test_blind_commitment_lockdown_stopped_only_by_interlock():
    _, agent, result, _ = _run("S2-BLIND")
    assert result.transmissions == []
    assert "interlock" in result.shifts[0].reasons[0]


def test_single_minded_drops_on_context_without_desire_reason():
    scenario = build_scenarios()[1]
    scenario.commitment = CommitmentStrategy.SINGLE_MINDED
    agent, result, _ = run_scenario(scenario)
    (shift,) = result.shifts
    assert shift.reasons[0].startswith("requires 'provider gcp-vertex is usable' but believed")
    assert result.final_status == "COMPLETED"


def test_irrelevant_belief_change_keeps_intention():
    scenario = build_scenarios()[0]
    scenario.disturbances = [Disturbance("noise", "unrelated azure price change", Trigger("before_step", step="dispatch"),
                                         [(pkey("azure-ai", "price_per_1k"), 2.10, "feed", 1.0)])]
    agent, result, _ = run_scenario(scenario)
    assert result.shifts == [] and result.final_status == "COMPLETED"
    assert result.reconsideration["ignored_changes"] >= 1


def test_change_after_dispatch_does_not_drop_finished_part():
    """Once the payload is sent, a provider outage no longer matters to the remaining steps."""
    scenario = build_scenarios()[0]
    scenario.disturbances = [Disturbance("late_outage", "outage after transmission", Trigger("before_step", step="deliver"),
                                         [(pkey("gcp-vertex", "status"), "major_outage", "feed", 1.0)])]
    agent, result, _ = run_scenario(scenario)
    assert result.shifts == [] and result.delivered


def test_secret_in_prompt_goes_straight_to_block(make_agent):
    from .conftest import SECRET
    agent = make_agent(SECRET)
    result = agent.run(Environment([]))
    assert result.final_status == "BLOCKED" and result.transmissions == []
    assert result.intentions[0]["plan"] == "block_and_advise_rotation" and result.advice
    assert "IAM" in result.advice[0]


def test_belief_changes_from_other_threads_are_processed_before_next_step(make_agent):
    import threading
    agent = make_agent()
    original = agent._execute_step
    calls = {"n": 0}

    def wrapped(intention):
        calls["n"] += 1
        res = original(intention)
        if calls["n"] == 2:   # after procure_contract, a monitor thread reports an outage
            t = threading.Thread(target=agent.beliefs.set,
                                 args=(pkey("gcp-vertex", "status"), "major_outage", "monitor-thread"))
            t.start()
            t.join()
        return res
    agent._execute_step = wrapped
    result = agent.run(None)
    assert result.shifts and result.shifts[0].before_step == "route_and_verify"
    assert [t["provider"] for t in result.transmissions] == ["aws-bedrock"]


def test_belief_written_during_deliberation_is_seen_before_the_step(make_agent):
    """A monitor write that lands between belief revision and acting must not let the step run."""
    agent = make_agent()
    original = agent.desires.deliberate
    state = {"done": False}

    def deliberate(beliefs):
        if agent.cycle == 4 and not state["done"]:
            state["done"] = True
            agent.beliefs.set(pkey("gcp-vertex", "status"), "major_outage", "monitor-thread")
        return original(beliefs)
    agent.desires.deliberate = deliberate
    result = agent.run(None)
    steps = [(e["intention"], e["step"]) for e in agent.tracer.events if e["event"] == "STEP"]
    assert ("I1", "seal_dispatch_record") not in steps
    assert result.shifts[0].before_step == "seal_dispatch_record"
    assert result.shifts[0].adopted["label"] == "allow_then_dispatch(provider=aws-bedrock)"
    assert [t["provider"] for t in result.transmissions] == ["aws-bedrock"]


def test_execution_time_guard_blocks_step_when_change_is_not_yet_processed(make_agent):
    """Even if a change is still queued, the step guard re-reads the belief base and refuses to run."""
    agent = make_agent()
    original = agent._revise_and_reconsider
    calls = {"n": 0}

    def revise(origin, executed=None):
        original(origin, executed)
        if agent.cycle == 4 and origin == "perception":
            calls["n"] += 1
            if calls["n"] == 2:     # the unconditional pre-step revision has just run
                agent.beliefs.set(pkey("gcp-vertex", "status"), "major_outage", "late-writer")
    agent._revise_and_reconsider = revise
    result = agent.run(None)
    guard = [e for e in agent.tracer.events if e["event"] == "RECONSIDER" and e.get("result") == "guard"]
    assert guard and guard[0]["step"] == "seal_dispatch_record"
    assert not any(e["event"] == "STEP" and e["intention"] == "I1" and e["step"] == "seal_dispatch_record"
                   for e in agent.tracer.events)
    assert result.final_status == "COMPLETED" and result.transmissions[0]["provider"] == "aws-bedrock"


def test_dispatch_interlock_refuses_provider_believed_down(make_agent):
    from ciphermesh.bdi.plans import StepContext, step_dispatch
    agent = make_agent()
    agent.request.payload = "hello"
    agent.beliefs.set("payload.prompt_sha256", agent.beliefs.get("prompt.sha256"), "test")
    agent.beliefs.set(pkey("gcp-vertex", "status"), "major_outage", "test")

    class _I:
        id = "Ix"
        next_step = None
    res = step_dispatch(StepContext(agent.services, agent.beliefs, agent.request, _I(), {"provider": "gcp-vertex"}))
    assert not res.ok and "believed major_outage" in res.detail and agent.services.transmissions == []
