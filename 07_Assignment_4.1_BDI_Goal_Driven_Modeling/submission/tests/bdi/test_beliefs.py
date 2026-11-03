"""BeliefBase: change detection, history, subscriptions, retraction and thread safety.

Author: Kumar Waibhav Akshat (RA2212704010027)
"""
import threading

import pytest

from ciphermesh.bdi.beliefs import BeliefBase


def test_set_reports_change_and_revision():
    b = BeliefBase()
    assert b.set("provider.gcp-vertex.status", "operational", "feed") is True
    assert b.set("provider.gcp-vertex.status", "operational", "feed", 0.5) is False
    assert b.belief("provider.gcp-vertex.status").revision == 1
    assert b.belief("provider.gcp-vertex.status").confidence == 0.5
    assert b.set("provider.gcp-vertex.status", "major_outage", "feed") is True
    assert b.belief("provider.gcp-vertex.status").revision == 2
    assert b.get("provider.gcp-vertex.status") == "major_outage"
    assert b.has("provider.gcp-vertex.status") and not b.has("missing")
    assert b.get("missing", "dflt") == "dflt"


def test_history_is_append_only_copy():
    b = BeliefBase()
    b.set("budget.max_cost_per_1k", 6.0, "config")
    b.set("budget.max_cost_per_1k", 1.0, "finance")
    hist = b.history
    assert [(h.kind, h.old_value, h.new_value) for h in hist] == [("SET", None, 6.0), ("SET", 6.0, 1.0)]
    hist.clear()
    assert len(b.history) == 2 and b.revision == 2


def test_subscribers_receive_old_and_new_values_only_on_change():
    b = BeliefBase()
    seen = []
    b.subscribe(lambda k, o, n, s: seen.append((k, o, n, s)))
    b.set("policy.lockdown", False, "agent")
    b.set("policy.lockdown", False, "agent")
    b.set("policy.lockdown", True, "soc")
    assert seen == [("policy.lockdown", None, False, "agent"), ("policy.lockdown", False, True, "soc")]


def test_unsubscribe_and_faulty_callback_isolated():
    b = BeliefBase()
    seen = []

    def bad(*_):
        raise RuntimeError("observer bug")
    b.subscribe(bad)
    off = b.subscribe(lambda k, o, n, s: seen.append(k))
    b.set("threat.level", "normal", "monitor")
    off()
    b.set("threat.level", "high", "monitor")
    assert seen == ["threat.level"]
    assert len(b.callback_errors) == 2 and "observer bug" in b.callback_errors[0]


def test_retract_notifies_and_records():
    b = BeliefBase()
    seen = []
    b.set("review.ticket", "rev-1", "queue")
    b.subscribe(lambda k, o, n, s: seen.append((o, n)))
    assert b.retract("review.ticket", "queue") is True
    assert b.retract("review.ticket", "queue") is False
    assert seen == [("rev-1", None)] and b.history[-1].kind == "RETRACT"


def test_values_are_copied_in_and_out():
    b = BeliefBase()
    cats = ["pan"]
    b.set("prompt.categories", cats, "sensor")
    cats.append("aadhaar")
    out = b.get("prompt.categories")
    out.append("email")
    assert b.get("prompt.categories") == ["pan"]
    snap = b.snapshot()
    snap["prompt.categories"].append("x")
    assert b.snapshot() == {"prompt.categories": ["pan"]}


def test_matching_uses_patterns():
    b = BeliefBase()
    b.set("provider.a.status", "operational", "s")
    b.set("provider.b.status", "major_outage", "s")
    b.set("provider.a.price_per_1k", 1.0, "s")
    assert b.matching("provider.*.status") == {"provider.a.status": "operational", "provider.b.status": "major_outage"}


@pytest.mark.parametrize("key,source,conf", [("", "s", 1.0), ("a b", "s", 1.0), ("k", "", 1.0), ("k", "s", 1.5),
                                             ("k", "s", -0.1)])
def test_validation(key, source, conf):
    with pytest.raises(ValueError):
        BeliefBase().set(key, 1, source, conf)


def test_thread_safety_under_concurrent_writers_and_readers():
    b = BeliefBase()
    events = []
    lock = threading.Lock()

    def on_change(k, o, n, s):
        with lock:
            events.append(k)
    b.subscribe(on_change)

    def writer(t):
        for i in range(500):
            b.set(f"counter.t{t}", i, f"writer{t}")
            b.set("shared.last", (t, i), f"writer{t}")

    def reader():
        for _ in range(500):
            b.snapshot()
            b.get("shared.last")
    threads = [threading.Thread(target=writer, args=(t,)) for t in range(8)] + \
              [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for t in range(8):
        assert b.get(f"counter.t{t}") == 499
        assert b.belief(f"counter.t{t}").revision == 500
    seqs = [h.seq for h in b.history]
    assert seqs == list(range(1, len(seqs) + 1))
    assert len(events) == len(seqs) == b.revision
    assert sum(1 for h in b.history if h.key.startswith("counter.")) == 8 * 500
