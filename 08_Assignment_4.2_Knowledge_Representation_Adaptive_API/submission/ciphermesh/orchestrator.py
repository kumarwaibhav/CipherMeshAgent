"""End-to-end CipherMesh agent pipeline.

PERCEIVE -> INSPECT (R1..R5) -> [REVIEW queue] -> PROCURE (Contract-Net) ->
ROUTE (constrained utility) -> ACT (provider adapter, fallback, circuit breaker) ->
INSPECT RESPONSE -> AUDIT.

Invariants enforced here, not by convention:
* Nothing but ALLOW text or REDACT-sanitized text ever reaches an adapter.
* Approved REVIEW content goes only to providers with ``kind == "local"``.
* A provider response is inspected before it is returned; a response containing
  a critical secret is withheld, sensitive data in a response is masked.
"""
from __future__ import annotations

import hashlib
import threading
import time
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field

from .agent import CipherMeshAgent
from .detector import redact
from .models import AuditEvent, Decision, InspectionResult
from .procurement import ContractBook
from .providers import ProviderRegistry, ProviderUnavailable, default_registry
from .review import ReviewQueue
from .routing import RouteConstraints, RouteDecision, RouteWeights, derive_constraints, route


class ProcessStatus(str, Enum):
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    PENDING_REVIEW = "PENDING_REVIEW"
    DENIED = "DENIED"
    NO_ROUTE = "NO_ROUTE"
    PROVIDER_FAILED = "PROVIDER_FAILED"
    RESPONSE_BLOCKED = "RESPONSE_BLOCKED"


class Attempt(BaseModel):
    provider_id: str
    ok: bool
    latency_ms: float
    error: str | None = None


class ProcessOutcome(BaseModel):
    request_id: str
    status: ProcessStatus
    decision: Decision
    reasons: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    prompt_sha256: str
    safe_preview: str | None = None
    review_id: str | None = None
    provider: str | None = None
    route: RouteDecision | None = None
    contract_price_per_1k_usd: float | None = None
    contract_digest: str | None = None
    attempts: list[Attempt] = Field(default_factory=list)
    response_text: str | None = None
    response_decision: Decision | None = None
    response_categories: list[str] = Field(default_factory=list)
    timings_ms: dict[str, float] = Field(default_factory=dict)


class CipherMeshOrchestrator:
    def __init__(self, agent: CipherMeshAgent, registry: ProviderRegistry | None = None,
                 constraints: RouteConstraints | None = None, weights: RouteWeights | None = None,
                 contracts: ContractBook | None = None, negotiate: bool = True,
                 max_attempts: int = 3, provider_timeout_s: float = 20.0):
        self.agent = agent
        self.registry = registry or default_registry()
        self.base_constraints = constraints or RouteConstraints()
        self.weights = weights or RouteWeights()
        self.contracts = contracts if contracts is not None else ContractBook(
            budget_per_1k_usd=self.base_constraints.max_cost_per_1k_usd,
            min_availability_pct=self.base_constraints.min_availability_pct,
            max_p95_latency_ms=self.base_constraints.max_p95_latency_ms)
        self.negotiate = negotiate
        self.max_attempts = max(1, max_attempts)
        self.provider_timeout_s = provider_timeout_s
        self._lock = threading.Lock()
        self.stats: dict[str, int] = {s.value: 0 for s in ProcessStatus}
        self.provider_usage: dict[str, int] = {}
        self.fallbacks = 0
        agent.process_handler = self._process_wire
        agent.approval_handler = self._approval_wire

    # ------------------------------------------------------------------ public API
    def process(self, text: str, provider_hint: str | None = None,
                request_id: str | None = None) -> ProcessOutcome:
        started = time.perf_counter()
        request_id = request_id or f"req-{uuid4().hex[:12]}"
        fingerprint = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        inspection = self.agent.inspect(text, provider=provider_hint)
        inspect_ms = (time.perf_counter() - started) * 1000
        base = dict(request_id=request_id, decision=inspection.decision, reasons=list(inspection.reasons),
                    categories=[f.category for f in inspection.findings], prompt_sha256=fingerprint,
                    safe_preview=inspection.safe_preview)
        if inspection.decision == Decision.BLOCK:
            return self._finish(ProcessOutcome(status=ProcessStatus.BLOCKED, **base), started,
                                {"inspect_ms": inspect_ms})
        if inspection.decision == Decision.REVIEW:
            return self._finish(ProcessOutcome(status=ProcessStatus.PENDING_REVIEW,
                                               review_id=inspection.review_id, **base),
                                started, {"inspect_ms": inspect_ms})
        payload = inspection.sanitized_text if inspection.decision == Decision.REDACT else text
        outcome = self._dispatch(payload or "", inspection, provider_hint, approved_review=False,
                                 base=base, started=started, inspect_ms=inspect_ms)
        return outcome

    def decide_review(self, review_id: str, approved: bool, reviewer: str) -> ProcessOutcome:
        started = time.perf_counter()
        ticket, held = self.agent.reviews.decide(review_id, approved, reviewer)
        self.agent.audit.write(AuditEvent(agent_id=self.agent.state.agent_id, event_type="review_decided",
                                          details={"review_id": review_id, "status": ticket.status.value,
                                                   "reviewer": ticket.decided_by}))
        base = dict(request_id=review_id, decision=Decision.REVIEW, reasons=list(ticket.reasons),
                    categories=list(ticket.categories), prompt_sha256=ticket.prompt_sha256,
                    safe_preview=ticket.safe_preview, review_id=review_id)
        if not approved or held is None:
            return self._finish(ProcessOutcome(status=ProcessStatus.DENIED, **base), started, {})
        # Re-inspect: policy may have changed (e.g. lockdown) while the ticket waited.
        inspection = self.agent.inspect(held, open_review=False)
        if inspection.decision == Decision.BLOCK:
            base["reasons"] = [*base["reasons"], *inspection.reasons]
            return self._finish(ProcessOutcome(status=ProcessStatus.BLOCKED, **base), started, {})
        return self._dispatch(held, inspection, ticket.requested_provider, approved_review=True,
                              base=base, started=started, inspect_ms=0.0)

    def dispatch(self, payload: str, inspection: InspectionResult, provider_hint: str | None = None,
                 request_id: str | None = None) -> ProcessOutcome:
        """Public entry for external orchestrators (e.g. LangGraph) that already inspected the prompt."""
        started = time.perf_counter()
        base = dict(request_id=request_id or f"req-{uuid4().hex[:12]}", decision=inspection.decision,
                    reasons=list(inspection.reasons), categories=[f.category for f in inspection.findings],
                    prompt_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16],
                    safe_preview=inspection.safe_preview)
        return self._dispatch(payload, inspection, provider_hint, approved_review=False, base=base,
                              started=started, inspect_ms=0.0)

    def preview_route(self, text: str, provider_hint: str | None = None) -> RouteDecision:
        inspection = self.agent.inspect(text, open_review=False)
        constraints, notes = derive_constraints(inspection, self.agent.state, self.base_constraints)
        decision = self._route(constraints, provider_hint, set())
        decision.notes = [*notes, *decision.notes]
        return decision

    def snapshot(self) -> dict:
        with self._lock:
            return {"status_counts": dict(self.stats), "provider_usage": dict(self.provider_usage),
                    "fallbacks": self.fallbacks,
                    "provider_health": self.registry.health.snapshot(),
                    "contracts": [r.model_dump(mode="json") for r in self.contracts.records()],
                    "pending_reviews": sum(t.status.value == "PENDING" for t in self.agent.reviews.list())}

    # ------------------------------------------------------------------ internals
    def _route(self, constraints: RouteConstraints, hint: str | None, exclude: set[str]) -> RouteDecision:
        profiles = self.registry.profiles()
        prices = self.contracts.ensure_all(profiles) if self.negotiate else {}
        opened = {p.provider_id for p in profiles if self.registry.health.is_open(p.provider_id)}
        return route(profiles, constraints, self.weights, prices, opened, hint, exclude)

    def _dispatch(self, payload: str, inspection: InspectionResult, hint: str | None,
                  approved_review: bool, base: dict, started: float, inspect_ms: float) -> ProcessOutcome:
        constraints, notes = derive_constraints(inspection, self.agent.state, self.base_constraints,
                                                approved_review=approved_review)
        attempts: list[Attempt] = []
        tried: set[str] = set()
        route_ms = provider_ms = 0.0
        decision: RouteDecision | None = None
        for _ in range(self.max_attempts):
            t0 = time.perf_counter()
            decision = self._route(constraints, hint if not tried else None, tried)
            decision.notes = [*notes, *decision.notes]
            route_ms += (time.perf_counter() - t0) * 1000
            if decision.status != "SELECTED" or decision.selected is None:
                break
            provider_id = decision.selected
            adapter = self.registry.get(provider_id)
            if adapter is None:
                tried.add(provider_id)
                continue
            if approved_review and adapter.profile.kind != "local":
                raise AssertionError("invariant violated: approved review routed off-host")
            t1 = time.perf_counter()
            try:
                response = adapter.complete(payload, timeout_s=self.provider_timeout_s)
            except (ProviderUnavailable, TimeoutError, OSError) as exc:
                elapsed = (time.perf_counter() - t1) * 1000
                provider_ms += elapsed
                self.registry.health.record_failure(provider_id)
                attempts.append(Attempt(provider_id=provider_id, ok=False, latency_ms=round(elapsed, 3),
                                        error=str(exc)[:200]))
                tried.add(provider_id)
                with self._lock:
                    self.fallbacks += 1
                continue
            elapsed = (time.perf_counter() - t1) * 1000
            provider_ms += elapsed
            self.registry.health.record_success(provider_id, response.latency_ms)
            attempts.append(Attempt(provider_id=provider_id, ok=True, latency_ms=round(elapsed, 3)))
            return self._complete(response.text, provider_id, decision, attempts, base, started,
                                  {"inspect_ms": inspect_ms, "route_ms": route_ms, "provider_ms": provider_ms})
        timings = {"inspect_ms": inspect_ms, "route_ms": route_ms, "provider_ms": provider_ms}
        if decision is not None and decision.status != "SELECTED" and not attempts:
            return self._finish(ProcessOutcome(status=ProcessStatus.NO_ROUTE, route=decision,
                                               **base), started, timings)
        return self._finish(ProcessOutcome(status=ProcessStatus.PROVIDER_FAILED, route=decision,
                                           attempts=attempts, **base), started, timings)

    def _complete(self, raw_response: str, provider_id: str, decision: RouteDecision,
                  attempts: list[Attempt], base: dict, started: float, timings: dict) -> ProcessOutcome:
        t0 = time.perf_counter()
        checked = self.agent.inspect_response(raw_response)
        timings["response_inspect_ms"] = (time.perf_counter() - t0) * 1000
        record = next((r for r in self.contracts.records() if r.provider_id == provider_id), None)
        contract = dict(contract_price_per_1k_usd=record.price_per_1k_usd if record else None,
                        contract_digest=record.contract_digest if record else None)
        categories = [f.category for f in checked.findings]
        if checked.decision == Decision.BLOCK and checked.findings:
            outcome = ProcessOutcome(status=ProcessStatus.RESPONSE_BLOCKED, provider=provider_id, route=decision,
                                     attempts=attempts, response_decision=Decision.BLOCK,
                                     response_categories=categories, **contract, **base)
        else:
            text = redact(raw_response, checked.findings) if checked.findings else raw_response
            outcome = ProcessOutcome(status=ProcessStatus.COMPLETED, provider=provider_id, route=decision,
                                     attempts=attempts, response_text=text,
                                     response_decision=checked.decision if checked.findings else Decision.ALLOW,
                                     response_categories=categories, **contract, **base)
        with self._lock:
            self.provider_usage[provider_id] = self.provider_usage.get(provider_id, 0) + 1
        return self._finish(outcome, started, timings)

    def _finish(self, outcome: ProcessOutcome, started: float, timings: dict) -> ProcessOutcome:
        timings = {k: round(v, 3) for k, v in timings.items()}
        timings["total_ms"] = round((time.perf_counter() - started) * 1000, 3)
        outcome.timings_ms = timings
        with self._lock:
            self.stats[outcome.status.value] += 1
        self.agent.audit.write(AuditEvent(
            agent_id=self.agent.state.agent_id, event_type="pipeline_outcome", decision=outcome.decision,
            categories=outcome.categories, message_id=outcome.request_id,
            details={"status": outcome.status.value, "provider": outcome.provider,
                     "attempts": len(outcome.attempts), "response_decision":
                         outcome.response_decision.value if outcome.response_decision else None,
                     "prompt_sha256": outcome.prompt_sha256, "total_ms": timings["total_ms"]}))
        return outcome

    def _process_wire(self, text: str, provider: str | None, request_id: str | None) -> dict:
        return self.process(text, provider, request_id).model_dump(mode="json")

    def _approval_wire(self, review_id: str, approved: bool, reviewer: str) -> dict:
        return self.decide_review(review_id, approved, reviewer).model_dump(mode="json")


def build_default_orchestrator(agent_id: str = "CIPHERMESH_GATEWAY", audit_path: str = "ciphermesh_audit.db",
                               latency_scale: float = 0.0, review_ttl_s: float = 900.0,
                               registry: ProviderRegistry | None = None,
                               constraints: RouteConstraints | None = None,
                               negotiate: bool = True) -> CipherMeshOrchestrator:
    agent = CipherMeshAgent(agent_id, audit_path, review_queue=ReviewQueue(ttl_seconds=review_ttl_s))
    registry = registry or default_registry(latency_scale=latency_scale)
    agent.state.provider_allowlist = registry.ids()
    return CipherMeshOrchestrator(agent, registry, constraints=constraints, negotiate=negotiate)
