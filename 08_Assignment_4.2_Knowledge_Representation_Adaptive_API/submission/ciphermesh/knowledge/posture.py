"""Threat-posture decision rule (shared by the live adapter and the offline backtest).

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

Evidence is grouped into three *independent* signals:

* ``kev_volume``   - CISA KEV additions in 30 days / 12-month median (ratio);
* ``kev_stack``    - KEV additions that hit the watched vendor stack, AI/ML products or are
                     ransomware-linked;
* ``ai_incidents`` - privacy-related AI incident reports per covered day (free-text feed).

A posture is entered when at least ``cm:minSignals`` groups meet one of the posture's
thresholds (ELEVATED needs 1, HIGH needs 2). Thresholds live in the ontology and were
calibrated on a one-year KEV backtest (see ``calibration.py``). Hysteresis: while the agent
is already at a level, the thresholds for that level and below are multiplied by the
agent's ``cm:hysteresisFactor`` (0.8), so the posture does not flap around a threshold.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .graph import KnowledgeGraph

SIGNAL_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {
    "kev_volume": (("minKevRatio", "threat.kev.ratio"),),
    "kev_stack": (("minRelevantHits", "threat.kev.relevant_hits"), ("minAiMlHits", "threat.kev.ai_ml_hits"),
                  ("minRansomwareHits", "threat.kev.ransomware_hits")),
    "ai_incidents": (("minAiPrivacyPerDay", "threat.aiid.privacy_per_day"),),
}
FEED_KEYS = {"cisa_kev": [k for _, k in SIGNAL_GROUPS["kev_volume"] + SIGNAL_GROUPS["kev_stack"]],
             "aiid_rss": [k for _, k in SIGNAL_GROUPS["ai_incidents"]]}


@dataclass
class PostureSpec:
    node: str
    label: str
    level: int
    min_signals: int
    thresholds: dict[str, float] = field(default_factory=dict)


@dataclass
class PostureDecision:
    spec: PostureSpec
    met: dict[str, list[str]]

    @property
    def label(self) -> str:
        return self.spec.label

    def reason(self) -> str:
        if not self.met:
            return "no signal group meets an ELEVATED threshold"
        return "; ".join(f"{g}: {', '.join(h)}" for g, h in sorted(self.met.items()))


def specs_from_graph(graph: KnowledgeGraph) -> list[PostureSpec]:
    specs = []
    for node in graph.instances_of("cm:ThreatPosture"):
        th = {}
        for pairs in SIGNAL_GROUPS.values():
            for attr, _key in pairs:
                v = graph.value(node, f"cm:{attr}")
                if v is not None:
                    th[attr] = float(v)
        specs.append(PostureSpec(node=node, label=str(graph.value(node, "rdfs:label")),
                                 level=int(graph.value(node, "cm:level", 0)),
                                 min_signals=int(graph.value(node, "cm:minSignals", 1)), thresholds=th))
    return sorted(specs, key=lambda s: -s.level)


def decide(evidence: dict[str, float | None], specs: list[PostureSpec], current_level: int = 0,
           hysteresis: float = 1.0) -> PostureDecision:
    """Highest posture whose number of satisfied signal groups reaches its ``min_signals``."""
    for spec in specs:
        if spec.level == 0:
            continue
        factor = hysteresis if spec.level <= current_level else 1.0
        met: dict[str, list[str]] = {}
        for group, pairs in SIGNAL_GROUPS.items():
            hits = []
            for attr, key in pairs:
                t, v = spec.thresholds.get(attr), evidence.get(key)
                if t is None or v is None:
                    continue
                if float(v) >= t * factor:
                    hits.append(f"{key.split('.', 1)[1]}={v} >= {round(t * factor, 3)}")
            if hits:
                met[group] = hits
        if len(met) >= spec.min_signals:
            return PostureDecision(spec, met)
    return PostureDecision(specs[-1], {})


def attribution(evidence: dict[str, float | None], specs: list[PostureSpec]) -> dict[str, str]:
    """Leave-one-feed-out and single-feed postures (no hysteresis), to show which feed drove the result."""
    out = {"all feeds": decide(evidence, specs).label}
    for feed, keys in FEED_KEYS.items():
        without = {k: v for k, v in evidence.items() if k not in keys}
        alone = {k: v for k, v in evidence.items() if k in keys}
        out[f"without {feed}"] = decide(without, specs).label
        out[f"{feed} alone"] = decide(alone, specs).label
    return out
