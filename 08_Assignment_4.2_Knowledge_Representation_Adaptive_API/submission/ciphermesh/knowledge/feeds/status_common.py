"""Helpers shared by the three provider-status connectors (GCP, Azure, AWS).

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from ..graph import KnowledgeGraph
from .base import Fact, FeedConnector, ParseReport
from .normalize import Normaliser, classify_impact

SEVERITY = {"operational": 0, "advisory": 1, "degraded": 2, "outage": 3}


class StatusConnector(FeedConnector):
    """A connector whose job is to report the status of the providers it monitors."""
    lookback_days = 30

    def __init__(self, graph: KnowledgeGraph, normaliser: Normaliser | None = None, **kw):
        super().__init__(**kw)
        self.graph = graph
        self.norm = normaliser or Normaliser(graph)
        node = self.source_iri
        self.lookback_days = int(graph.value(node, "cm:lookbackDays", self.lookback_days))
        self.configure_from(graph, keep_url=bool(kw.get("url")))
        self.monitored = {str(graph.value(p, "cm:providerId")): p
                          for p in graph.subjects("cm:monitoredBy", node)}

    @staticmethod
    def as_of(value: datetime | None) -> datetime:
        return (value or datetime.now(timezone.utc)).astimezone(timezone.utc)

    @staticmethod
    def incident_id(prefix: str, *parts: str) -> str:
        return f"cm:incident/{prefix}-" + hashlib.sha1("|".join(parts).encode()).hexdigest()[:10]

    def text_view(self, text: str) -> dict:
        """What the parser reads from free text; also what a derived (text-free) snapshot keeps."""
        return {"impact_class": classify_impact(text), "regions": sorted(self.norm.find_regions(text)),
                "providers": sorted(self.norm.find_providers(text))}

    def new_report(self) -> ParseReport:
        report = ParseReport(feed=self.name)
        report.signals = {"provider_status": {pid: {"status": "operational", "confidence": 0.8,
                                                    "incidents": [], "evidence": "no active incident in feed"}
                                              for pid in self.monitored},
                          "recent_incidents": {pid: 0 for pid in self.monitored},
                          "active_total": 0, "recent_total": 0, "regions_seen": []}
        return report

    def mark(self, report: ParseReport, pid: str, impact: str, confidence: float, incident: str,
             evidence: str) -> None:
        cur = report.signals["provider_status"][pid]
        if SEVERITY.get(impact, 0) > SEVERITY.get(cur["status"], 0) or (
                impact == cur["status"] and cur["incidents"] and confidence > cur["confidence"]):
            cur.update(status=impact, confidence=round(confidence, 3), evidence=evidence[:200])
        if cur["status"] == "operational" and impact == "operational":
            return
        if incident not in cur["incidents"]:
            cur["incidents"].append(incident)

    def incident_facts(self, report: ParseReport, iid: str, label: str, impact: str, regions: set[str],
                       providers: set[str], fetched_at: str, confidence: float, observed: str) -> None:
        """Structured incident facts. ``label`` is built from ids and codes, never copied feed prose."""
        f = report.facts
        f.append(self.fact(iid, "rdf:type", "cm:Incident", True, fetched_at, confidence, label))
        f.append(self.fact(iid, "rdfs:label", label[:160], False, fetched_at, confidence))
        f.append(self.fact(iid, "cm:reportedBy", self.source_iri, True, fetched_at, confidence))
        f.append(self.fact(iid, "cm:statusImpact", impact, False, fetched_at, confidence))
        f.append(self.fact(iid, "cm:observedAt", observed, False, fetched_at, confidence))
        for code in sorted(regions):
            node = self.norm.region_node.get(code.lower())
            if node:
                f.append(self.fact(iid, "cm:affectsRegion", node, True, fetched_at, confidence))
        for pid in sorted(providers):
            f.append(self.fact(iid, "cm:affectsProvider", self.monitored.get(pid, f"cm:provider/{pid}"), True,
                               fetched_at, confidence))

    def finish(self, report: ParseReport, fetched_at: str) -> ParseReport:
        for pid, st in report.signals["provider_status"].items():
            report.facts.append(Fact(subject=self.monitored[pid], predicate="cm:hasStatus",
                                     obj=f"cm:status/{st['status']}", obj_is_iri=True, source=self.source_iri,
                                     fetched_at=fetched_at, confidence=st["confidence"],
                                     evidence=st["evidence"]))
        report.signals["regions_seen"] = sorted(set(report.signals["regions_seen"]))
        return report
