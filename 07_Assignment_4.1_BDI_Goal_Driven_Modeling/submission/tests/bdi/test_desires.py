"""Desires: activation, satisfaction, priority ordering and conflict filtering.

Author: Kumar Waibhav Akshat (RA2212704010027)
"""
import pytest

from ciphermesh.bdi.beliefs import BeliefBase
from ciphermesh.bdi.desires import Desire, DesireSet, ciphermesh_desires


def _beliefs(**values):
    b = BeliefBase()
    defaults = {"request.status": "PENDING", "prompt.categories": [], "prompt.decision": "ALLOW",
                "policy.lockdown": False, "response.findings": [], "guard.secret_contained": False,
                "response.delivered": False, "budget.max_cost_per_1k": 6.0, "review.queue_depth": 0,
                "review.limit": 25, "dispatch.residency_violations": 0}
    defaults.update({k.replace("__", "."): v for k, v in values.items()})
    for k, v in defaults.items():
        b.set(k, v, "test")
    return b


def test_desires_ordered_by_priority():
    ds = ciphermesh_desires()
    assert [d.id for d in ds] == ["D1", "D2", "D3", "D4", "D5"]
    assert [d.priority for d in ds] == [100, 90, 60, 40, 30]


def test_clean_request_only_d3_is_an_option():
    ds = ciphermesh_desires()
    b = _beliefs()
    assert [d.id for d in ds.options(b)] == ["D3"]
    delib = ds.deliberate(b)
    assert delib.selected_ids() == ["D3"] and [d.id for d in delib.constraints] == ["D4"]


def test_d2_activates_on_indian_identifiers_and_constrains():
    ds = ciphermesh_desires()
    for cat in ("aadhaar", "pan", "phone_in"):
        b = _beliefs(prompt__categories=[cat])
        assert ds.get("D2").is_active(b)
        assert "D2" in [d.id for d in ds.deliberate(b).constraints]
        assert "D2" in [d.id for d in ds.constraining(ds.get("D3"), b)]
    assert not ds.get("D2").is_active(_beliefs(prompt__categories=["email"]))


@pytest.mark.parametrize("override", [{"policy__lockdown": True}, {"prompt__categories": ["aws_access_key"]},
                                      {"response__findings": [{"category": "github_token", "severity": "CRITICAL"}]}])
def test_d1_activates_and_preempts_d3(override):
    ds = ciphermesh_desires()
    b = _beliefs(**override)
    delib = ds.deliberate(b)
    assert delib.selected_ids() == ["D1"]
    assert delib.preempted == {"D3": "D1"}


def test_d1_satisfied_once_contained():
    ds = ciphermesh_desires()
    b = _beliefs(policy__lockdown=True, guard__secret_contained=True)
    assert ds.get("D1").is_active(b) and ds.get("D1").is_satisfied(b) and not ds.get("D1").is_option(b)


def test_d5_option_only_when_backlog_full_for_review_prompt():
    ds = ciphermesh_desires()
    assert not ds.get("D5").is_option(_beliefs(prompt__decision="REVIEW"))
    assert ds.get("D5").is_option(_beliefs(prompt__decision="REVIEW", review__queue_depth=25))
    assert not ds.get("D5").is_active(_beliefs(review__queue_depth=25))


def test_d3_inactive_after_final_status_and_satisfied_after_delivery():
    ds = ciphermesh_desires()
    assert not ds.get("D3").is_active(_beliefs(request__status="BLOCKED"))
    assert ds.get("D3").is_satisfied(_beliefs(response__delivered=True))


def test_d4_violated_when_cost_exceeds_budget():
    ds = ciphermesh_desires()
    b = _beliefs()
    b.set("dispatch.effective_cost", 7.0, "test")
    assert ds.get("D4").is_active(b) and not ds.get("D4").is_satisfied(b)


def test_desire_validation_and_duplicates():
    with pytest.raises(ValueError):
        Desire("X", "bad", 10, lambda b: True, lambda b: False, kind="perform")
    with pytest.raises(ValueError):
        Desire("X", "bad", 5000, lambda b: True, lambda b: False)
    d = Desire("X", "x", 1, lambda b: True, lambda b: False)
    with pytest.raises(ValueError):
        DesireSet([d, d])


def test_conflict_is_symmetric_and_priority_tie_break_by_id():
    a = Desire("A", "a", 10, lambda b: True, lambda b: False, conflicts_with=frozenset({"B"}))
    b_ = Desire("B", "b", 10, lambda b: True, lambda b: False)
    ds = DesireSet([b_, a])
    delib = ds.deliberate(BeliefBase())
    assert delib.selected_ids() == ["A"] and delib.preempted == {"B": "A"}
