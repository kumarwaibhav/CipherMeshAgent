"""PropertySink / AgentProperties behaviour and the adapter's derived-property rules.

Author: Kumar Waibhav Akshat (RA2212704010027)
"""
import hashlib
import threading

import pytest

from ciphermesh.knowledge import AgentProperties, KnowledgeAdapter, PropertySink
from ciphermesh.knowledge.feeds import Fact, FetchResult, ParseReport


def _fetch(feed="test", body=b"{}"):
    return FetchResult(feed=feed, url="https://example.test/feed", mode="live", status=200, body=body,
                       bytes=len(body), sha256=hashlib.sha256(body).hexdigest(), fetched_at="2026-10-30T10:00:00Z")


def test_agent_properties_satisfies_property_sink_protocol():
    assert isinstance(AgentProperties(), PropertySink)

    class BeliefBaseLike:                        # the shape of the Assignment 4.1 BeliefBase
        def __init__(self):
            self.d = {}

        def set(self, key, value, source, confidence=1.0):
            changed = self.d.get(key) != value
            self.d[key] = value
            return changed

        def get(self, key, default=None):
            return self.d.get(key, default)

    assert isinstance(BeliefBaseLike(), PropertySink)


def test_set_get_history_and_unchanged_values():
    p = AgentProperties()
    assert p.set("a", 1, "s1") is True
    assert p.set("a", 1, "s2") is False                    # same value: no change, provenance refreshed
    assert p.source_of("a")[0] == "s2"
    assert p.set("a", 2, "s3", 0.9) is True
    assert [(c.old, c.new, c.source) for c in p.history] == [(None, 1, "s1"), (1, 2, "s3")]
    assert p.get("missing", "dflt") == "dflt" and p.seq == 2


def test_confidence_gate_rejects_weak_evidence():
    p = AgentProperties(min_confidence=0.6)
    assert p.set("provider.x.status", "outage", "rumour", confidence=0.4) is False
    assert p.get("provider.x.status") is None and p.rejected[0]["reason"].startswith("confidence 0.40")
    with pytest.raises(ValueError):
        p.set("k", 1, "s", confidence=2.0)
    with pytest.raises(ValueError):
        p.set("", 1, "s")


def test_subscribers_fire_synchronously_with_prefix_filter_and_unsubscribe():
    p = AgentProperties()
    seen = []
    unsub = p.subscribe(lambda c: seen.append((c.key, c.new)), prefix="provider.")
    p.set("provider.a.status", "degraded", "feed")
    p.set("fx.usd_inr", 95.0, "feed")
    assert seen == [("provider.a.status", "degraded")]
    unsub()
    p.set("provider.a.status", "operational", "feed")
    assert len(seen) == 1


def test_lists_are_frozen_and_snapshot_thaws_them():
    p = AgentProperties()
    pats = ["a", "b"]
    p.set("policy.custom_redaction_patterns", pats, "x")
    pats.append("c")
    assert p.get("policy.custom_redaction_patterns") == ("a", "b")
    assert p.snapshot()["policy.custom_redaction_patterns"] == ["a", "b"]


def test_concurrent_writers_keep_consistent_history():
    p = AgentProperties()

    def worker(n):
        for i in range(200):
            p.set(f"k{n}", i, f"t{n}")
    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(p.history) == 800 and [c.seq for c in p.history] == list(range(1, 801))


def test_adapter_writes_triples_with_provenance_and_status_property(graph):
    props = AgentProperties()
    adapter = KnowledgeAdapter(graph, props)
    rep = ParseReport(feed="gcp_status", facts=[Fact("cm:provider/gcp-vertex", "cm:hasStatus", "cm:status/degraded",
                                                     True, "cm:feed/gcp-status", "2026-10-30T10:00:00Z", 0.9, "ev")],
                      signals={"provider_status": {"gcp-vertex": {"status": "degraded", "confidence": 0.9}},
                               "recent_incidents": {"gcp-vertex": 2}})
    ev = adapter.ingest(_fetch("gcp_status"), rep)
    assert graph.objects("cm:provider/gcp-vertex", "cm:hasStatus") == ["cm:status/degraded"]
    prov = graph.provenance("cm:provider/gcp-vertex", "cm:hasStatus", "cm:status/degraded")
    assert (prov.method, prov.source, prov.confidence) == ("live", "cm:feed/gcp-status", 0.9)
    assert ev.triples_added == 1 and ev.triples_replaced == 1
    assert props.get("provider.gcp-vertex.status") == "degraded"
    assert props.get("provider.gcp-vertex.recent_incidents") == 2
    assert {c["key"] for c in ev.property_changes} == {"provider.gcp-vertex.status",
                                                       "provider.gcp-vertex.recent_incidents"}


def test_budget_rule_converts_inr_budget_with_live_rate(graph):
    props = AgentProperties()
    adapter = KnowledgeAdapter(graph, props)
    adapter.ingest(_fetch("fx_usd_inr"), ParseReport(feed="fx_usd_inr", signals={"pair": "USD/INR", "rate": 94.95}))
    assert props.get("router.max_cost_per_1k_usd") == round(300 / 94.95, 4)
    assert props.source_of("router.max_cost_per_1k_usd")[0] == "derived:budget-rule"
    adapter.ingest(_fetch("fx_usd_inr"), ParseReport(feed="fx_usd_inr", signals={"pair": "USD/INR", "rate": 80.0}))
    assert props.get("router.max_cost_per_1k_usd") == 3.75


def _kev(ratio, relevant=0, ai=0, ransom=0):
    return ParseReport(feed="cisa_kev", signals={"ratio": ratio, "relevant_hits": relevant, "ai_ml_hits": ai,
                                                 "ransomware_hits": ransom})


def _aiid(privacy, per_day):
    return ParseReport(feed="aiid_rss", signals={"privacy_incidents": privacy, "privacy_per_day": per_day})


@pytest.mark.parametrize("report, posture, max_bytes, restrict, lockdown", [
    (_kev(0.9), "LOW", 65536, [], False),
    (_kev(1.5, relevant=10), "LOW", 65536, [], False),                 # below both calibrated thresholds
    (_kev(1.7), "ELEVATED", 32768, [], False),
    (_kev(0.5, relevant=11), "ELEVATED", 32768, [], False),
    (_kev(0.5, ai=3), "ELEVATED", 32768, [], False),
    (_kev(2.1), "ELEVATED", 32768, [], False),                          # one signal group only: not HIGH
    (_kev(1.0, ransom=4, relevant=12), "ELEVATED", 32768, [], False),   # same group twice is still one signal
    (_kev(1.9, relevant=12), "HIGH", 16384, ["IN", "LOCAL"], True),     # two independent groups at HIGH level
])
def test_posture_rule_thresholds_come_from_ontology(graph, report, posture, max_bytes, restrict, lockdown):
    props = AgentProperties()
    KnowledgeAdapter(graph, props).ingest(_fetch("cisa_kev"), report)
    assert props.get("threat.posture") == posture
    assert props.get("policy.max_prompt_bytes") == max_bytes
    assert list(props.get("router.restrict_all_traffic_to")) == restrict
    assert props.get("policy.lockdown_recommended") is lockdown
    assert graph.value("cm:agent/ciphermesh", "cm:hasPosture") == f"cm:posture/{posture}"


def test_ai_incident_rate_is_an_independent_signal(graph):
    props = AgentProperties()
    adapter = KnowledgeAdapter(graph, props)
    adapter.ingest(_fetch("cisa_kev"), _kev(0.8))
    assert props.get("threat.posture") == "LOW"
    adapter.ingest(_fetch("aiid_rss"), _aiid(9, 0.6))
    assert props.get("threat.posture") == "ELEVATED"
    assert "aiid.privacy_per_day=0.6 >= 0.5" in props.get("threat.posture_reason")
    assert adapter.posture_attribution() == {"all feeds": "ELEVATED", "without cisa_kev": "ELEVATED",
                                             "cisa_kev alone": "LOW", "without aiid_rss": "LOW",
                                             "aiid_rss alone": "ELEVATED"}
    adapter.ingest(_fetch("cisa_kev"), _kev(1.95, relevant=12))      # second independent signal at HIGH level
    adapter.ingest(_fetch("aiid_rss"), _aiid(30, 1.2))
    assert props.get("threat.posture") == "HIGH" and set(props.get("threat.posture_signals")) == {
        "ai_incidents", "kev_stack", "kev_volume"}


def test_hysteresis_keeps_posture_until_signal_clearly_drops(graph):
    props = AgentProperties()
    adapter = KnowledgeAdapter(graph, props)
    adapter.ingest(_fetch("cisa_kev"), _kev(1.70))
    assert props.get("threat.posture") == "ELEVATED"
    adapter.ingest(_fetch("cisa_kev"), _kev(1.55))                   # >= 1.69 x 0.9: stays
    assert props.get("threat.posture") == "ELEVATED"
    adapter.ingest(_fetch("cisa_kev"), _kev(1.50))                   # < 1.521: leaves
    assert props.get("threat.posture") == "LOW"
    adapter.ingest(_fetch("cisa_kev"), _kev(1.55))                   # re-entry needs the full threshold
    assert props.get("threat.posture") == "LOW"


def test_stale_snapshot_cannot_change_properties(graph):
    props = AgentProperties()
    adapter = KnowledgeAdapter(graph, props)
    rep = ParseReport(feed="fx_usd_inr", signals={"pair": "USD/INR", "rate": 80.0}, confidence_scale=0.4)
    adapter.ingest(_fetch("fx_usd_inr"), rep)
    assert props.get("fx.usd_inr") is None and props.rejected[0]["key"] == "fx.usd_inr"


def test_live_facts_from_an_older_fetch_are_expired(graph):
    props = AgentProperties()
    adapter = KnowledgeAdapter(graph, props)
    old = ParseReport(feed="gcp_status", source_iri="cm:feed/gcp-status", facts=[
        Fact("cm:incident/gcp-x", "rdf:type", "cm:Incident", True, "cm:feed/gcp-status", "2026-10-30T10:00:00Z")])
    adapter.ingest(_fetch("gcp_status"), old)
    assert ("cm:incident/gcp-x", "rdf:type", "cm:Incident") in graph
    new = ParseReport(feed="gcp_status", source_iri="cm:feed/gcp-status", facts=[
        Fact("cm:incident/gcp-y", "rdf:type", "cm:Incident", True, "cm:feed/gcp-status", "2026-10-30T11:00:00Z")])
    ev = adapter.ingest(_fetch("gcp_status"), new)
    assert ("cm:incident/gcp-x", "rdf:type", "cm:Incident") not in graph and ev.triples_expired == 1
    assert ("cm:incident/gcp-y", "rdf:type", "cm:Incident") in graph


def test_snapshot_mode_is_flagged_in_event(graph):
    props = AgentProperties()
    fetch = _fetch("fx_usd_inr")
    fetch.mode = "snapshot"
    ev = KnowledgeAdapter(graph, props).ingest(fetch, ParseReport(feed="fx_usd_inr",
                                                                  signals={"pair": "USD/INR", "rate": 90.0}))
    assert ev.mode == "snapshot" and any("snapshot" in w for w in ev.warnings)
