"""Intention state machine and stack ordering.

Author: Kumar Waibhav Akshat (RA2212704010027)
"""
import pytest

from ciphermesh.bdi.intentions import Intention, IntentionError, IntentionStack, IntentionStatus, StepRecord
from ciphermesh.bdi.plans import ciphermesh_plans

PLANS = {p.id: p for p in ciphermesh_plans()}


def _intention(stack, desire="D3", plan="allow_then_dispatch", priority=60):
    return Intention(id=stack.next_id(), desire_id=desire, plan=PLANS[plan], params={"provider": "gcp-vertex"},
                     priority=priority)


def _rec(i, ok=True):
    return StepRecord(index=i, name="s", ok=ok, detail="", cycle=1, started_ms=0, duration_ms=0)


def test_lifecycle_and_cursor():
    stack = IntentionStack()
    it = _intention(stack)
    stack.push(it)
    assert it.next_step.name == "prepare_payload" and it.progress() == "0/7"
    it.advance(_rec(1))
    assert it.cursor == 1 and it.next_step.name == "procure_contract"
    it.transition(IntentionStatus.SUSPENDED, "wait", 2)
    assert it.suspended_cycle == 2
    with pytest.raises(IntentionError):
        it.advance(_rec(2))
    it.transition(IntentionStatus.ACTIVE, "resume", 3)
    it.transition(IntentionStatus.DROPPED, "outage", 4)
    assert [r.status for r in it.reasons] == ["SUSPENDED", "ACTIVE", "DROPPED"]
    with pytest.raises(IntentionError):
        it.transition(IntentionStatus.ACTIVE, "zombie", 5)


def test_failed_step_does_not_advance_cursor():
    stack = IntentionStack()
    it = _intention(stack)
    it.advance(_rec(1, ok=False))
    assert it.cursor == 0 and len(it.step_log) == 1


def test_watched_beliefs_shrink_as_steps_complete():
    stack = IntentionStack()
    it = _intention(stack)
    assert "provider.gcp-vertex.status" in it.watched_beliefs()
    it.cursor = 5   # only inspect_response and deliver remain
    assert "provider.gcp-vertex.status" not in it.watched_beliefs()
    assert "response.findings" in it.watched_beliefs()


def test_stack_orders_by_priority_and_one_live_intention_per_desire():
    stack = IntentionStack()
    low = _intention(stack)
    high = _intention(stack, desire="D1", plan="enforce_lockdown_block", priority=100)
    stack.push(low)
    stack.push(high)
    assert stack.top() is high and [i.id for i in stack.live()] == [high.id, low.id]
    with pytest.raises(IntentionError):
        stack.push(_intention(stack))
    high.transition(IntentionStatus.SUSPENDED, "wait", 1)
    assert stack.top() is low and stack.for_desire("D1") is high
    low.transition(IntentionStatus.DROPPED, "x", 2)
    stack.push(_intention(stack))     # allowed once the previous D3 intention is dead
    assert len(stack) == 3 and stack.get("I1") is low
