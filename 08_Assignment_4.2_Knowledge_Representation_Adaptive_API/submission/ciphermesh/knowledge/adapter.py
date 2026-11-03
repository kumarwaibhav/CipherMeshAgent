"""Adapter: parsed live facts -> knowledge-graph triples -> agent properties.

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

``KnowledgeAdapter.ingest(fetch, report)`` performs, in one call:

1. **Graph update** - every :class:`Fact` becomes a triple with provenance
   (source feed, fetched_at, confidence, evidence). Functional predicates such as
   ``cm:hasStatus`` replace the previous value instead of piling up.
2. **Observed properties** - feed signals are written to the :class:`PropertySink`
   (``provider.<id>.status``, ``fx.usd_inr``, ``threat.kev.ratio`` ...).
3. **Derived properties** - rules whose parameters live in the ontology turn the
   observations into control settings:

   * budget rule:  ``router.max_cost_per_1k_usd = budgetPer1k(INR) / fx.usd_inr``
   * posture rule: the highest ``cm:ThreatPosture`` whose any threshold is met
     (KEV ratio, relevant-vendor hits, AI/ML hits, ransomware hits, AI privacy
     incidents) -> ``threat.posture`` and its effects (``policy.max_prompt_bytes``,
     ``policy.custom_redaction_patterns``, ``router.restrict_all_traffic_to``,
     ``policy.lockdown_recommended``).

Because the sink notifies subscribers synchronously, an
:class:`~ciphermesh.knowledge.adaptive_agent.AdaptiveCipherMeshAgent` re-plans inside
the same ``set`` call. The returned :class:`AdaptationEvent` records the timing chain
fetch -> parse -> property change -> plan change in milliseconds.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from .feeds.base import FetchResult, ParseReport, iso, utc_now
from .graph import KnowledgeGraph, Literal, Provenance
from .posture import FEED_KEYS, PostureDecision, attribution, decide, specs_from_graph
from .properties import PropertyChange, PropertySink

AGENT = "cm:agent/ciphermesh"
EVIDENCE_KEYS = [k for keys in FEED_KEYS.values() for k in keys]


@dataclass
class AdaptationEvent:
    feed: str
    url: str
    mode: str
    http_status: int | None
    bytes: int
    sha256: str
    fetched_at: str
    facts: int
    triples_added: int
    triples_replaced: int
    property_changes: list[dict] = field(default_factory=list)
    plan_version_before: int | None = None
    plan_version_after: int | None = None
    timings_ms: dict[str, float] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    replay: bool = False
    as_of: str | None = None
    items_seen: int = 0
    items_relevant: int = 0
    signals: dict = field(default_factory=dict)
    triples_expired: int = 0
    original_sha256: str | None = None
    final_url: str | None = None
    stale: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class KnowledgeAdapter:
    def __init__(self, graph: KnowledgeGraph, sink: PropertySink,
                 plan_probe: Callable[[], tuple[int, int, float | None]] | None = None):
        """``plan_probe`` returns (plan_version, perf_counter_ns when the last re-plan finished,
        latency in ms from the triggering property change to that re-plan)."""
        self.graph = graph
        self.sink = sink
        self.plan_probe = plan_probe
        self.specs = specs_from_graph(graph)
        self.hysteresis = float(graph.value(AGENT, "cm:hysteresisFactor", 1.0))
        self.last_decision: PostureDecision | None = None

    # ------------------------------------------------------------------ graph
    def _apply_facts(self, report: ParseReport) -> tuple[int, int]:
        added = replaced = 0
        for f in report.facts:
            obj = f.obj if f.obj_is_iri else Literal(f.obj, _xsd(f.obj))
            prov = Provenance(source=f.source, fetched_at=f.fetched_at, confidence=f.confidence,
                              method="live", evidence=f.evidence)
            if f.predicate in self.graph.functional:
                existed = (f.subject, f.predicate, obj) in self.graph
                removed = self.graph.set_value(f.subject, f.predicate, obj, prov)
                replaced += len(removed)
                added += 0 if existed else 1
            else:
                added += self.graph.add(f.subject, f.predicate, obj, prov)
        return added, replaced

    def _expire(self, report: ParseReport) -> int:
        """Remove live triples from this feed that the newest fetch no longer reports."""
        sources = {f.source for f in report.facts} | ({report.source_iri} if report.source_iri else set())
        stamp = {f.fetched_at for f in report.facts}
        doomed = [t for t in list(self.graph.triples())
                  if (pv := self.graph.provenance(t.s, t.p, t.o)) and pv.method == "live"
                  and pv.source in sources and pv.fetched_at not in stamp]
        for t in doomed:
            self.graph.remove(t.s, t.p, t.o)
        return len(doomed)

    # ------------------------------------------------------------------ properties
    def _observe(self, report: ParseReport, source: str) -> None:
        s, k = report.signals, report.confidence_scale

        def put(key, value, src, conf):
            return self.sink.set(key, value, src, round(conf * k, 4))
        if "provider_status" in s:
            for pid, st in sorted(s["provider_status"].items()):
                put(f"provider.{pid}.status", st["status"], source, st["confidence"])
                put(f"provider.{pid}.recent_incidents", int(s.get("recent_incidents", {}).get(pid, 0)), source, 0.9)
        if report.feed == "cisa_kev":
            put("threat.kev.ratio", float(s["ratio"]), source, 1.0)
            put("threat.kev.relevant_hits", int(s["relevant_hits"]), source, 1.0)
            put("threat.kev.ai_ml_hits", int(s["ai_ml_hits"]), source, 1.0)
            put("threat.kev.ransomware_hits", int(s["ransomware_hits"]), source, 1.0)
        if report.feed == "aiid_rss":
            put("threat.aiid.privacy_incidents", int(s["privacy_incidents"]), source, 0.7)
            put("threat.aiid.privacy_per_day", float(s["privacy_per_day"]), source, 0.7)
        if "rate" in s and s.get("pair") == "USD/INR":
            put("fx.usd_inr", float(s["rate"]), source, 1.0)

    def derive(self) -> None:
        """Re-evaluate derived properties from the current observations and ontology parameters."""
        g, put, get = self.graph, self.sink.set, self.sink.get
        # Budget rule -------------------------------------------------------
        budget = g.value(AGENT, "cm:budgetPer1k")
        currency = g.value(g.value(AGENT, "cm:budgetCurrency"), "cm:isoCode")
        rate = get("fx.usd_inr")
        if budget is not None:
            if currency == "USD":
                put("router.max_cost_per_1k_usd", round(float(budget), 4), "derived:budget-rule", 1.0)
            elif currency == "INR" and rate:
                put("router.max_cost_per_1k_usd", round(float(budget) / float(rate), 4), "derived:budget-rule", 1.0)
                put("router.budget_inr_per_1k", float(budget), "ontology:cm:agent/ciphermesh", 1.0)
        # Posture rule (thresholds, min_signals and hysteresis from the ontology) --------
        evidence = {k: get(k) for k in EVIDENCE_KEYS}
        if all(v is None for v in evidence.values()):
            return
        current = next((sp.level for sp in self.specs if sp.label == get("threat.posture")), 0)
        decision = decide(evidence, self.specs, current_level=current, hysteresis=self.hysteresis)
        self.last_decision = decision
        chosen, why = decision.spec.node, decision.reason()
        put("threat.posture", decision.label, "derived:posture-rule", 1.0)
        put("threat.posture_reason", why, "derived:posture-rule", 1.0)
        put("threat.posture_signals", sorted(decision.met), "derived:posture-rule", 1.0)
        put("policy.max_prompt_bytes", int(g.value(chosen, "cm:maxPromptBytes", 65536)), f"derived:{chosen}", 1.0)
        put("policy.custom_redaction_patterns", sorted(str(x) for x in g.values(chosen, "cm:addsRedactionPattern")),
            f"derived:{chosen}", 1.0)
        put("router.restrict_all_traffic_to", sorted(str(x) for x in g.values(chosen, "cm:restrictsAllTrafficTo")),
            f"derived:{chosen}", 1.0)
        put("policy.lockdown_recommended", bool(g.value(chosen, "cm:recommendsLockdown", False)),
            f"derived:{chosen}", 1.0)
        g.set_value(AGENT, "cm:hasPosture", chosen,
                    Provenance(source="derived:posture-rule", fetched_at=iso(utc_now()), method="derived",
                               evidence=why))

    def posture_attribution(self) -> dict[str, str]:
        """Leave-one-feed-out view of the current evidence (which feed drives the posture)."""
        return attribution({k: self.sink.get(k) for k in EVIDENCE_KEYS}, self.specs)

    # ------------------------------------------------------------------ entry point
    def ingest(self, fetch: FetchResult, report: ParseReport, replay: bool = False,
               as_of: str | None = None) -> AdaptationEvent:
        version_before = self.plan_probe()[0] if self.plan_probe else None
        if replay is False and fetch.mode == "snapshot" and not any("fallback" in w for w in report.warnings):
            report.warnings.append("live fetch failed; facts come from the saved snapshot")
        seq_before = getattr(self.sink, "seq", None)
        t_apply = time.perf_counter_ns()
        added, replaced = self._apply_facts(report)
        expired = self._expire(report)
        source = f"{fetch.feed}:{fetch.mode}" + (":replay" if replay else "")
        self._observe(report, source)
        self.derive()
        t_props = time.perf_counter_ns()
        changes: list[PropertyChange] = (self.sink.changes_since(seq_before)  # type: ignore[attr-defined]
                                         if seq_before is not None else [])
        version_after, replan_ns, replan_ms = self.plan_probe() if self.plan_probe else (None, 0, None)
        first_change_ns = changes[0].mono_ns if changes else t_props
        timings = {
            "fetch_ms": round(fetch.latency_ms, 1),
            "parse_ms": report.parse_ms,
            "fetch_to_parsed_ms": _ms(fetch.t_start_ns, report.t_done_ns),
            "parsed_to_property_ms": _ms(report.t_done_ns, first_change_ns) if changes else None,
            "property_to_plan_ms": replan_ms if changes and version_after != version_before else None,
            "apply_total_ms": _ms(t_apply, t_props),
            "end_to_end_ms": _ms(fetch.t_start_ns, max(t_props, replan_ns or 0)),
        }
        return AdaptationEvent(feed=fetch.feed, url=fetch.url, mode=fetch.mode + ("+replay" if replay and "replay" not in fetch.mode else ""),
                               http_status=fetch.status, bytes=fetch.bytes, sha256=fetch.sha256,
                               fetched_at=fetch.fetched_at, facts=len(report.facts), triples_added=added,
                               triples_replaced=replaced,
                               property_changes=[_change_dict(c) for c in changes],
                               plan_version_before=version_before, plan_version_after=version_after,
                               timings_ms=timings, warnings=list(report.warnings), replay=replay, as_of=as_of,
                               items_seen=report.items_seen, items_relevant=report.items_relevant,
                               signals={k: v for k, v in report.signals.items() if k != "monthly_counts"},
                               triples_expired=expired, original_sha256=fetch.original_sha256,
                               final_url=fetch.final_url, stale=fetch.stale)


def _ms(a: int, b: int) -> float:
    return round((b - a) / 1e6, 3)


def _xsd(v: Any) -> str:
    if isinstance(v, bool):
        return "xsd:boolean"
    if isinstance(v, int):
        return "xsd:integer"
    if isinstance(v, float):
        return "xsd:decimal"
    return "xsd:string"


def _change_dict(c: PropertyChange) -> dict:
    d = c.to_dict()
    for k in ("old", "new"):
        if isinstance(d[k], tuple):
            d[k] = list(d[k])
    return d
