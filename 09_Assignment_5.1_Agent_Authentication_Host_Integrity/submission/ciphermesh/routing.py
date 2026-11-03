"""Policy-constrained, utility-maximizing provider routing.

This is the in-domain application of the Assignment 3.2 optimizer: the agent is
self-interested over *where a prompt is sent*. Hard constraints derived from the
privacy decision are applied first; only then is weighted utility maximized.

    U = 0.30*Q + 0.25*C + 0.20*L + 0.15*A + 0.10*P          (every term in 0..100)

    Q = 100 * quality_score / 5
    C = clamp(100 * (1 - effective_cost / max_cost))         effective_cost = negotiated
                                                             contract price, else list price
    L = clamp(100 * (1 - p95_latency_ms / max_latency_ms))
    A = clamp(10 * (availability_pct - 90))                  90% -> 0, 100% -> 100
    P = 100 local | 80 in-country cloud | 50 other residency

Ties: utility desc, effective cost asc, p95 latency asc, provider_id asc.
An exhaustive sort is computed independently and must agree with the single-pass winner.
"""
from __future__ import annotations

from math import isclose

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .models import AgentState, InspectionResult
from .providers import ProviderProfile

INDIA_PERSONAL_DATA = {"aadhaar", "pan", "phone_in"}


def _clamp(value: float) -> float:
    return max(0.0, min(100.0, value))


class RouteWeights(BaseModel):
    model_config = ConfigDict(extra="forbid")
    quality: float = 0.30
    cost: float = 0.25
    latency: float = 0.20
    availability: float = 0.15
    privacy: float = 0.10

    @model_validator(mode="after")
    def _sum_to_one(self):
        values = (self.quality, self.cost, self.latency, self.availability, self.privacy)
        if any(v < 0 for v in values) or not isclose(sum(values), 1.0, abs_tol=1e-9):
            raise ValueError("route weights must be non-negative and sum to 1.0")
        return self


class RouteConstraints(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_cost_per_1k_usd: float = Field(default=6.0, gt=0, allow_inf_nan=False)
    max_p95_latency_ms: float = Field(default=1500.0, gt=0, allow_inf_nan=False)
    min_quality: float = Field(default=3.0, ge=0, le=5)
    min_availability_pct: float = Field(default=99.0, ge=0, le=100)
    allowed_residency: list[str] = Field(default_factory=lambda: ["IN", "US", "EU", "LOCAL"])
    require_local: bool = False
    allowlist: list[str] = Field(default_factory=list)
    home_residency: str = "IN"


class RouteEvaluation(BaseModel):
    provider_id: str
    feasible: bool
    utility: float
    effective_cost: float
    priced_by: str
    scores: dict[str, float]
    reasons: list[str] = Field(default_factory=list)


class RouteDecision(BaseModel):
    status: str
    selected: str | None = None
    utility: float | None = None
    ranking: list[str] = Field(default_factory=list)
    evaluations: list[RouteEvaluation] = Field(default_factory=list)
    constraints: RouteConstraints
    verified: bool = False
    notes: list[str] = Field(default_factory=list)


def derive_constraints(inspection: InspectionResult, state: AgentState, base: RouteConstraints,
                       approved_review: bool = False) -> tuple[RouteConstraints, list[str]]:
    """Translate the privacy decision into hard routing constraints."""
    notes: list[str] = []
    update: dict = {"allowlist": list(state.provider_allowlist)}
    categories = {f.category for f in inspection.findings}
    if approved_review:
        update["require_local"] = True
        notes.append("approved REVIEW content is restricted to the local trust tier")
    if categories & INDIA_PERSONAL_DATA:
        residency = [r for r in base.allowed_residency if r in {"IN", "LOCAL"}]
        update["allowed_residency"] = residency
        notes.append("India personal-data identifiers detected: in-country or local processing only")
    return base.model_copy(update=update), notes


def score_provider(profile: ProviderProfile, effective_cost: float, c: RouteConstraints,
                   w: RouteWeights) -> tuple[float, dict[str, float]]:
    q = _clamp(100.0 * profile.quality_score / 5.0)
    cost = _clamp(100.0 * (1.0 - effective_cost / c.max_cost_per_1k_usd))
    lat = _clamp(100.0 * (1.0 - profile.p95_latency_ms / c.max_p95_latency_ms))
    avail = _clamp(10.0 * (profile.availability_pct - 90.0))
    if profile.data_residency == "LOCAL":
        privacy = 100.0
    elif profile.data_residency == c.home_residency:
        privacy = 80.0
    else:
        privacy = 50.0
    utility = w.quality * q + w.cost * cost + w.latency * lat + w.availability * avail + w.privacy * privacy
    scores = {"quality": round(q, 4), "cost": round(cost, 4), "latency": round(lat, 4),
              "availability": round(avail, 4), "privacy": round(privacy, 4)}
    return round(_clamp(utility), 4), scores


def _violations(p: ProviderProfile, cost: float, c: RouteConstraints, circuit_open: bool) -> list[str]:
    reasons: list[str] = []
    if not p.enabled:
        reasons.append("DISABLED")
    if c.allowlist and p.provider_id not in c.allowlist:
        reasons.append("NOT_ALLOWLISTED")
    if circuit_open:
        reasons.append("CIRCUIT_OPEN: recent consecutive failures")
    if c.require_local and p.kind != "local":
        reasons.append("LOCAL_ONLY_REQUIRED")
    if p.data_residency not in c.allowed_residency:
        reasons.append(f"RESIDENCY_NOT_ALLOWED: {p.data_residency}")
    if cost > c.max_cost_per_1k_usd + 1e-9:
        reasons.append(f"OVER_BUDGET: {cost:.2f} > {c.max_cost_per_1k_usd:.2f}")
    if p.p95_latency_ms > c.max_p95_latency_ms:
        reasons.append(f"TOO_SLOW: p95 {p.p95_latency_ms:.0f}ms > {c.max_p95_latency_ms:.0f}ms")
    if p.quality_score < c.min_quality:
        reasons.append(f"QUALITY_BELOW_MIN: {p.quality_score:.2f} < {c.min_quality:.2f}")
    if p.availability_pct < c.min_availability_pct:
        reasons.append(f"AVAILABILITY_BELOW_MIN: {p.availability_pct:.2f}% < {c.min_availability_pct:.2f}%")
    return reasons


def route(profiles: list[ProviderProfile], constraints: RouteConstraints,
          weights: RouteWeights | None = None, contract_prices: dict[str, float] | None = None,
          open_circuits: set[str] | None = None, provider_hint: str | None = None,
          exclude: set[str] | None = None) -> RouteDecision:
    w = weights or RouteWeights()
    prices = contract_prices or {}
    opened = open_circuits or set()
    excluded = exclude or set()
    evaluations: list[RouteEvaluation] = []
    winner: RouteEvaluation | None = None
    by_id = {p.provider_id: p for p in profiles}

    def key(e: RouteEvaluation):
        return (-e.utility, e.effective_cost, by_id[e.provider_id].p95_latency_ms, e.provider_id)

    for p in profiles:
        cost = prices.get(p.provider_id, p.cost_per_1k_requests_usd)
        utility, scores = score_provider(p, cost, constraints, w)
        reasons = _violations(p, cost, constraints, p.provider_id in opened)
        if p.provider_id in excluded:
            reasons.append("EXCLUDED: failed earlier in this request")
        ev = RouteEvaluation(provider_id=p.provider_id, feasible=not reasons, utility=utility,
                             effective_cost=round(cost, 4),
                             priced_by="negotiated_contract" if p.provider_id in prices else "list_price",
                             scores=scores, reasons=reasons)
        evaluations.append(ev)
        if ev.feasible and (winner is None or key(ev) < key(winner)):
            winner = ev

    feasible = sorted((e for e in evaluations if e.feasible), key=key)
    ranking = [e.provider_id for e in feasible]
    if winner is None:
        return RouteDecision(status="NO_FEASIBLE_ROUTE", evaluations=evaluations, constraints=constraints,
                             notes=["no provider satisfies every hard constraint; nothing is transmitted"])
    notes: list[str] = []
    selected = winner
    if provider_hint:
        hinted = next((e for e in feasible if e.provider_id == provider_hint), None)
        if hinted:
            selected = hinted
            notes.append(f"caller preference '{provider_hint}' honoured (feasible)")
        else:
            notes.append(f"caller preference '{provider_hint}' is infeasible under policy; utility winner used")
    return RouteDecision(status="SELECTED", selected=selected.provider_id, utility=selected.utility,
                         ranking=ranking, evaluations=evaluations, constraints=constraints,
                         verified=bool(feasible) and feasible[0].provider_id == winner.provider_id,
                         notes=notes)
