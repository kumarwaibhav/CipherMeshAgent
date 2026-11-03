"""Knowledge-driven CipherMesh agent that re-plans whenever its properties change.

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

The agent holds three things:

* the **knowledge graph** (ontology + live triples),
* the **agent properties** (observed + derived settings, see ``properties.py``),
* the **plan context** - effective provider profiles, routing constraints and policy
  state - which is recomputed synchronously on every property change.

``plan_for(prompt)`` then runs the real engine on that context:
``policy.inspect_text`` (R1-R5) for the decision, ``graph.derive_residency`` for the
residency constraint (derived from the ontology, not hard-coded), and
``routing.route`` for the constrained utility choice. The same prompt therefore gets a
different, explainable plan before and after a live update.
"""
from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from ..agent import CipherMeshAgent
from ..detector import validate_custom_pattern
from ..models import AgentState, Decision
from ..policy import inspect_text
from ..providers import ProviderProfile
from ..routing import RouteConstraints, RouteDecision, RouteWeights, route
from .adapter import AdaptationEvent, KnowledgeAdapter
from .feeds.base import FeedConnector, iso, utc_now
from .graph import KnowledgeGraph
from .ontology import load_graph
from .properties import AgentProperties, PropertyChange


@dataclass
class PlanContext:
    version: int
    created_at: str
    trigger: str
    state: AgentState
    constraints: RouteConstraints
    profiles: list[ProviderProfile]
    provider_status: dict[str, str]
    excluded: list[str]
    posture: str
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {"version": self.version, "trigger": self.trigger, "posture": self.posture,
                "max_cost_per_1k_usd": self.constraints.max_cost_per_1k_usd,
                "allowed_residency": list(self.constraints.allowed_residency),
                "max_prompt_bytes": self.state.max_prompt_bytes,
                "custom_redaction_patterns": len(self.state.custom_redaction_patterns),
                "provider_status": dict(self.provider_status), "excluded": list(self.excluded),
                "notes": list(self.notes)}


@dataclass
class Plan:
    label: str
    plan_version: int
    decision: str
    reasons: list[str]
    categories: list[str]
    action: str
    residency: list[str] | None
    residency_chain: list[str]
    route_status: str
    selected: str | None
    utility: float | None
    ranking: list[str]
    evaluations: dict[str, dict]
    constraints: dict[str, Any]
    posture: str
    notes: list[str]
    plan_ms: float

    def to_dict(self) -> dict:
        return asdict(self)

    def headline(self) -> str:
        route_txt = self.selected or self.route_status
        return f"{self.decision:<6} -> {route_txt}" + (f" (U={self.utility:.2f})" if self.utility is not None else "")


class AdaptiveCipherMeshAgent:
    def __init__(self, graph: KnowledgeGraph | None = None, properties: AgentProperties | None = None,
                 base_constraints: RouteConstraints | None = None, weights: RouteWeights | None = None,
                 agent_id: str = "CIPHERMESH_ADAPTIVE"):
        self.graph = graph or load_graph()
        self.properties = properties or AgentProperties()
        self.weights = weights or RouteWeights()
        self.base_constraints = base_constraints or RouteConstraints()
        self.agent_id = agent_id
        self._lock = threading.RLock()
        self.replans: list[dict] = []
        self.context: PlanContext | None = None
        self._last_done_ns = 0
        self._last_latency_ms: float | None = None
        self.adapter = KnowledgeAdapter(self.graph, self.properties, plan_probe=self.plan_probe)
        self.properties.subscribe(self._on_change)
        self._recompute("initial: ontology defaults", None)

    # ------------------------------------------------------------------ knowledge -> engine objects
    def base_profiles(self) -> list[ProviderProfile]:
        """Provider profiles read from the knowledge graph (must equal providers.DEFAULT_PROFILES)."""
        g = self.graph
        out = []
        for pid, node in sorted(g.providers().items()):
            region = g.value(node, "cm:hostedIn")
            out.append(ProviderProfile(
                provider_id=pid, display_name=g.label(node), kind=str(g.value(node, "cm:kind")),
                region=str(g.value(region, "cm:regionCode")),
                data_residency=g.provider_jurisdiction(node),
                cost_per_1k_requests_usd=float(g.value(node, "cm:costPer1kUsd")),
                p95_latency_ms=float(g.value(node, "cm:p95LatencyMs")),
                quality_score=float(g.value(node, "cm:qualityScore")),
                availability_pct=float(g.value(node, "cm:availabilityPct")),
                capacity_rps=1000, metrics_source="ontology.json (illustrative planning profile)"))
        return out

    def _effective_profiles(self) -> tuple[list[ProviderProfile], dict[str, str], list[str], list[str]]:
        g, props = self.graph, self.properties
        profiles, status, excluded, notes = [], {}, [], []
        for p in self.base_profiles():
            st = str(props.get(f"provider.{p.provider_id}.status", "operational"))
            node = f"cm:status/{st}"
            status[p.provider_id] = st
            update: dict[str, Any] = {}
            if bool(g.value(node, "cm:excludesProvider", False)):
                update["enabled"] = False
                excluded.append(p.provider_id)
                notes.append(f"{p.provider_id}: status '{st}' excludes the provider")
            penalty = float(g.value(node, "cm:availabilityPenalty", 0.0))
            factor = float(g.value(node, "cm:latencyFactor", 1.0))
            if penalty or factor != 1.0:
                update["availability_pct"] = round(max(0.0, p.availability_pct - penalty), 4)
                update["p95_latency_ms"] = round(p.p95_latency_ms * factor, 1)
                notes.append(f"{p.provider_id}: status '{st}' -> availability -{penalty} pts, p95 x{factor}")
            profiles.append(p.model_copy(update=update) if update else p)
        return profiles, status, excluded, notes

    def _effective_state(self, notes: list[str]) -> AgentState:
        props = self.properties
        patterns = []
        for pat in props.get("policy.custom_redaction_patterns", ()) or ():
            reason = validate_custom_pattern(pat)
            if reason:
                notes.append(f"custom pattern rejected by engine guardrail: {reason}")
            else:
                patterns.append(pat)
        return AgentState(agent_id=self.agent_id, provider_allowlist=[p for p in self.graph.providers()],
                          max_prompt_bytes=int(props.get("policy.max_prompt_bytes", 65536)),
                          custom_redaction_patterns=patterns)

    def _effective_constraints(self, notes: list[str]) -> RouteConstraints:
        props = self.properties
        update: dict[str, Any] = {"allowlist": sorted(self.graph.providers())}
        cap = props.get("router.max_cost_per_1k_usd")
        if cap:
            update["max_cost_per_1k_usd"] = float(cap)
            notes.append(f"budget: INR {props.get('router.budget_inr_per_1k')} per 1k / "
                         f"{props.get('fx.usd_inr')} INR per USD = USD {cap} per 1k")
        restrict = list(props.get("router.restrict_all_traffic_to", ()) or ())
        if restrict:
            update["allowed_residency"] = [r for r in self.base_constraints.allowed_residency if r in restrict]
            notes.append(f"threat posture restricts all traffic to {restrict}")
        return self.base_constraints.model_copy(update=update)

    # ------------------------------------------------------------------ reactive re-planning
    def _on_change(self, change: PropertyChange) -> None:
        self._recompute(f"{change.key}: {change.old!r} -> {change.new!r} ({change.source})", change)

    def _recompute(self, trigger: str, change: PropertyChange | None) -> PlanContext:
        with self._lock:
            notes: list[str] = []
            profiles, status, excluded, pnotes = self._effective_profiles()
            notes += pnotes
            state = self._effective_state(notes)
            constraints = self._effective_constraints(notes)
            if self.properties.get("policy.lockdown_recommended"):
                notes.append("lockdown RECOMMENDED to operator (not applied automatically)")
            version = (self.context.version + 1) if self.context else 1
            self.context = PlanContext(version=version, created_at=iso(utc_now()), trigger=trigger, state=state,
                                       constraints=constraints, profiles=profiles, provider_status=status,
                                       excluded=excluded, posture=str(self.properties.get("threat.posture",
                                                                                          self._graph_posture())),
                                       notes=notes)
            done = time.perf_counter_ns()
            latency = round((done - change.mono_ns) / 1e6, 4) if change else None
            self._last_done_ns, self._last_latency_ms = done, latency
            self.replans.append({"version": version, "at": self.context.created_at, "trigger": trigger,
                                 "property_to_plan_ms": latency})
            return self.context

    def _graph_posture(self) -> str:
        node = self.graph.value("cm:agent/ciphermesh", "cm:hasPosture")
        return str(self.graph.value(node, "rdfs:label", "LOW")) if node else "LOW"

    def plan_probe(self) -> tuple[int, int, float | None]:
        with self._lock:
            return (self.context.version if self.context else 0, self._last_done_ns, self._last_latency_ms)

    # ------------------------------------------------------------------ planning
    def plan_for(self, prompt: str, label: str = "prompt") -> Plan:
        t0 = time.perf_counter()
        with self._lock:
            ctx = self.context
        inspection = inspect_text(prompt, ctx.state)
        categories = sorted({f.category for f in inspection.findings})
        derivation = self.graph.derive_residency(categories)
        notes = list(ctx.notes)
        constraints = ctx.constraints
        if derivation.allowed_jurisdictions is not None:
            allowed = [r for r in constraints.allowed_residency if r in derivation.allowed_jurisdictions]
            constraints = constraints.model_copy(update={"allowed_residency": allowed})
            notes.append("residency derived from ontology: " + "; ".join(derivation.chain))
        decision: RouteDecision | None = None
        if inspection.decision == Decision.BLOCK:
            action, route_status = "do not transmit", "NOT_ROUTED"
        elif inspection.decision == Decision.REVIEW:
            action = "hold for human review; if approved, local trust tier only"
            constraints = constraints.model_copy(update={"require_local": True})
            decision = route(ctx.profiles, constraints, self.weights)
            route_status = "PREVIEW_AFTER_APPROVAL"
        else:
            action = "send sanitised text" if inspection.decision == Decision.REDACT else "send original text"
            decision = route(ctx.profiles, constraints, self.weights)
            route_status = decision.status
        evals = {}
        if decision is not None:
            evals = {e.provider_id: {"feasible": e.feasible, "utility": e.utility, "reasons": e.reasons}
                     for e in decision.evaluations}
        return Plan(label=label, plan_version=ctx.version, decision=inspection.decision.value,
                    reasons=list(inspection.reasons), categories=categories, action=action,
                    residency=derivation.allowed_jurisdictions, residency_chain=derivation.chain,
                    route_status=route_status, selected=decision.selected if decision else None,
                    utility=decision.utility if decision else None,
                    ranking=list(decision.ranking) if decision else [], evaluations=evals,
                    constraints={"max_cost_per_1k_usd": constraints.max_cost_per_1k_usd,
                                 "allowed_residency": list(constraints.allowed_residency),
                                 "require_local": constraints.require_local,
                                 "max_prompt_bytes": ctx.state.max_prompt_bytes,
                                 "custom_patterns": len(ctx.state.custom_redaction_patterns)},
                    posture=ctx.posture, notes=notes, plan_ms=round((time.perf_counter() - t0) * 1000, 3))

    # ------------------------------------------------------------------ live updates
    def update_from(self, connector: FeedConnector, offline: bool = False, as_of=None,
                    replay: bool = False) -> AdaptationEvent:
        fetch, report = connector.collect(offline=offline, as_of=as_of)
        return self.adapter.ingest(fetch, report, replay=replay, as_of=as_of.isoformat() if as_of else None)

    def replay_file(self, connector: FeedConnector, path, as_of=None, fetched_at: str | None = None) -> AdaptationEvent:
        """Deterministic what-if: parse a saved payload at instant ``as_of`` (clearly marked as replay)."""
        fetch, report = connector.collect_file(path, as_of=as_of, fetched_at=fetched_at)
        return self.adapter.ingest(fetch, report, replay=True, as_of=as_of.isoformat() if as_of else None)

    def sync_engine_agent(self, agent: CipherMeshAgent) -> dict[str, Any]:
        """Push the current policy settings into a running engine agent (Capstone hook)."""
        with self._lock:
            ctx = self.context
        with agent._lock:  # the engine agent guards its state with this lock
            agent.state.max_prompt_bytes = ctx.state.max_prompt_bytes
            agent.state.custom_redaction_patterns = list(ctx.state.custom_redaction_patterns)
            agent.state.policy_revision += 1
            agent.state.updated_at = utc_now()
        return {"max_prompt_bytes": ctx.state.max_prompt_bytes,
                "custom_redaction_patterns": list(ctx.state.custom_redaction_patterns),
                "policy_revision": agent.state.policy_revision}
