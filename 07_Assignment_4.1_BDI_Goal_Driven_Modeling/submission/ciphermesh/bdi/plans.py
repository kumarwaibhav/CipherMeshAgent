"""Plans: the procedural know-how the agent can commit to (the plan library).

Author : Kumar Waibhav Akshat (RA2212704010027)
Course : 21CSE525T Agent Technology, Assignment 4.1 (BDI Goal-Driven Modeling)

A ``Plan`` is a template in the PRS / AgentSpeak style:

    plan  := achieves <desire> : <context conditions> <- step_1; step_2; ...; step_n

* The *context* is a conjunction of named ``Condition`` objects. Each condition
  returns a three-valued ``Verdict``: HOLDS, UNCERTAIN (wait and see, e.g. a
  provider in partial outage) or VIOLATED.
* A *binder* produces parameter bindings for a plan, each with an estimated
  utility and cost. The dispatch plans bind ``provider`` from the real
  constrained utility router (``routing.route``) run on a belief-derived world.
* Every ``PlanStep`` declares ``relevant_beliefs``: the belief keys whose change
  means the step's assumptions must be re-checked before it runs. Steps may
  also declare guard conditions that must hold at execution time.

Each step action calls the real CipherMesh engine through ``EngineServices``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable

from ..detector import redact
from ..models import AuditEvent
from ..providers import ProviderUnavailable
from . import world
from .services import EngineServices, RequestContext, TransmissionRecord, sha256_16


class Verdict(str, Enum):
    HOLDS = "HOLDS"
    UNCERTAIN = "UNCERTAIN"
    VIOLATED = "VIOLATED"

    @staticmethod
    def of(value: "Verdict | bool") -> "Verdict":
        if isinstance(value, Verdict):
            return value
        return Verdict.HOLDS if value else Verdict.VIOLATED


@dataclass(frozen=True)
class Condition:
    """A named precondition over beliefs (and plan parameters)."""
    description: str
    check: Callable[[Any, dict], "Verdict | bool"]
    reads: frozenset[str] = frozenset()

    def evaluate(self, beliefs: Any, params: dict) -> Verdict:
        return Verdict.of(self.check(beliefs, params))

    def describe(self, params: dict) -> str:
        return self.description.format(**params) if params else self.description

    def reads_for(self, params: dict) -> set[str]:
        return {r.format(**params) for r in self.reads} if params else set(self.reads)


@dataclass
class StepResult:
    ok: bool
    detail: str
    data: dict = field(default_factory=dict)


@dataclass
class StepContext:
    """What a step action may use. Raw prompt text lives only in ``request``."""
    services: EngineServices
    beliefs: Any
    request: RequestContext
    intention: Any
    params: dict

    @property
    def source(self) -> str:
        step = self.intention.next_step.name if self.intention.next_step else "-"
        return f"intention:{self.intention.id}/{step}"

    @property
    def provider(self) -> str:
        return self.params.get("provider", "")


StepAction = Callable[[StepContext], StepResult]


@dataclass(frozen=True)
class PlanStep:
    name: str
    action: StepAction
    relevant_beliefs: frozenset[str] = frozenset()
    guard: tuple[Condition, ...] = ()
    transmits: bool = False

    def relevant_for(self, params: dict) -> set[str]:
        return {r.format(**params) for r in self.relevant_beliefs} if params else set(self.relevant_beliefs)


@dataclass(frozen=True)
class Binding:
    params: dict
    utility: float
    cost: float


Binder = Callable[[Any, EngineServices], list[Binding]]


@dataclass(frozen=True)
class Plan:
    id: str
    achieves: str
    description: str
    conditions: tuple[Condition, ...]
    steps: tuple[PlanStep, ...]
    binder: Binder | None = None
    base_utility: float = 50.0
    base_cost: float = 0.0

    def label(self, params: dict | None = None) -> str:
        shown = {k: v for k, v in (params or {}).items() if k != "mode"}
        if not shown:
            return self.id
        return f"{self.id}({', '.join(f'{k}={v}' for k, v in sorted(shown.items()))})"

    def check(self, beliefs: Any, params: dict | None = None) -> list[tuple[Condition, Verdict]]:
        params = params or {}
        return [(c, c.evaluate(beliefs, params)) for c in self.conditions]

    def context(self, beliefs: Any, params: dict | None = None) -> bool:
        """True when every context condition HOLDS (UNCERTAIN does not count as holding)."""
        return all(v == Verdict.HOLDS for _, v in self.check(beliefs, params))

    def violations(self, beliefs: Any, params: dict | None = None) -> list[str]:
        params = params or {}
        return [f"{c.describe(params)}: {v.value}" for c, v in self.check(beliefs, params) if v != Verdict.HOLDS]

    def bindings(self, beliefs: Any, services: EngineServices) -> list[Binding]:
        if self.binder is None:
            return [Binding(params={}, utility=self.base_utility, cost=self.base_cost)]
        return self.binder(beliefs, services)


@dataclass(frozen=True)
class PlanOption:
    plan: Plan
    params: dict
    utility: float
    cost: float

    def label(self) -> str:
        return self.plan.label(self.params)

    def sort_key(self):
        return (-self.utility, self.cost, self.plan.id, json.dumps(self.params, sort_keys=True))


class PlanLibrary:
    """Holds plan templates and performs option generation for a desire."""

    def __init__(self, services: EngineServices, plans: Iterable[Plan] = ()) -> None:
        self.services = services
        self._plans: dict[str, Plan] = {}
        for plan in plans:
            self.add(plan)

    def add(self, plan: Plan) -> None:
        if plan.id in self._plans:
            raise ValueError(f"duplicate plan id {plan.id}")
        self._plans[plan.id] = plan

    def get(self, plan_id: str) -> Plan:
        return self._plans[plan_id]

    def plans(self) -> list[Plan]:
        return list(self._plans.values())

    def plans_for(self, desire_id: str) -> list[Plan]:
        return [p for p in self._plans.values() if p.achieves == desire_id]

    def options_for(self, desire: Any, beliefs: Any) -> list[PlanOption]:
        """Applicable (plan, binding) pairs for ``desire``, best first."""
        options: list[PlanOption] = []
        for plan in self.plans_for(desire.id):
            for binding in plan.bindings(beliefs, self.services):
                if plan.context(beliefs, binding.params):
                    options.append(PlanOption(plan, dict(binding.params), round(binding.utility, 4),
                                              round(binding.cost, 4)))
        return sorted(options, key=PlanOption.sort_key)

    def rejected_for(self, desire: Any, beliefs: Any) -> list[tuple[str, list[str]]]:
        """Plans for ``desire`` whose context fails right now, with reasons (for the trace)."""
        out: list[tuple[str, list[str]]] = []
        for plan in self.plans_for(desire.id):
            bindings = plan.bindings(beliefs, self.services) or [Binding(params={}, utility=0, cost=0)]
            for binding in bindings:
                if binding.params == {} and plan.binder is not None:
                    out.append((plan.id, ["no feasible binding from router"]))
                    continue
                reasons = plan.violations(beliefs, binding.params)
                if reasons:
                    out.append((plan.label(binding.params), reasons))
        return out


# ============================================================================ conditions
def _verdict_status(beliefs: Any, params: dict) -> Verdict:
    status = world.provider_status(beliefs, params["provider"])
    if status in world.STATUS_OK:
        return Verdict.HOLDS
    if status in world.STATUS_WAIT:
        return Verdict.UNCERTAIN
    return Verdict.VIOLATED


C_PENDING = Condition("request is pending", lambda b, p: world.request_pending(b), frozenset({"request.status"}))
C_NO_LOCKDOWN = Condition("policy lockdown is off", lambda b, p: not world.lockdown(b),
                          frozenset({"policy.lockdown"}))
C_ALLOW = Condition("prompt decision is ALLOW", lambda b, p: b.get("prompt.decision") == "ALLOW",
                    frozenset({"prompt.decision"}))
C_REDACT = Condition("prompt decision is REDACT", lambda b, p: b.get("prompt.decision") == "REDACT",
                     frozenset({"prompt.decision"}))
C_ALLOW_OR_REDACT = Condition("prompt decision is ALLOW or REDACT",
                              lambda b, p: b.get("prompt.decision") in {"ALLOW", "REDACT"},
                              frozenset({"prompt.decision"}))
C_REVIEW = Condition("prompt decision is REVIEW", lambda b, p: b.get("prompt.decision") == "REVIEW",
                     frozenset({"prompt.decision"}))
C_USABLE = Condition("provider {provider} is usable", _verdict_status, frozenset({"provider.{provider}.status"}))
C_RESIDENCY = Condition(
    "provider {provider} residency allowed for this prompt (D2)",
    lambda b, p: b.get(world.pkey(p["provider"], "residency")) in world.allowed_residency(b),
    frozenset({"provider.{provider}.residency", "prompt.categories"}))
C_BUDGET = Condition(
    "provider {provider} price within budget (D4)",
    lambda b, p: (world.provider_price(b, p["provider"]) or 0.0) <= world.budget(b) + 1e-9,
    frozenset({"provider.{provider}.price_per_1k", "budget.max_cost_per_1k"}))
C_REPLY_CLEAN = Condition("reply contains no critical secret (D1)", lambda b, p: not world.response_has_secret(b),
                          frozenset({"response.findings"}))
C_PROMPT_SECRET = Condition("prompt contains a critical secret", lambda b, p: world.prompt_has_secret(b),
                            frozenset({"prompt.categories"}))
C_LOCKDOWN_ON = Condition("policy lockdown is on", lambda b, p: world.lockdown(b), frozenset({"policy.lockdown"}))
C_REPLY_SECRET = Condition("reply contains a critical secret", lambda b, p: world.response_has_secret(b),
                           frozenset({"response.findings"}))
C_REVIEW_CAPACITY = Condition("review backlog has capacity (D5)", lambda b, p: world.review_capacity(b),
                              frozenset({"review.queue_depth", "review.limit"}))
C_REVIEW_FULL = Condition("review backlog is at its limit", lambda b, p: not world.review_capacity(b),
                          frozenset({"review.queue_depth", "review.limit"}))


# ============================================================================ step actions
def _fail(detail: str) -> StepResult:
    return StepResult(False, detail)


def step_prepare_payload(ctx: StepContext) -> StepResult:
    """Re-run the real detector/policy on the current prompt and build the outbound payload."""
    mode = ctx.params.get("mode", "auto")
    result = ctx.services.inspect(ctx.request.text)
    decision = result.decision.value
    if decision == "ALLOW" and mode in {"allow", "auto"}:
        payload, redacted = ctx.request.text, False
    elif decision == "REDACT" and mode in {"redact", "auto"} and result.sanitized_text:
        payload, redacted = result.sanitized_text, True
    else:
        return _fail(f"policy now says {decision}; plan mode '{mode}' cannot build a payload")
    ctx.request.payload = payload
    ctx.beliefs.set("payload.sha256", sha256_16(payload), ctx.source)
    ctx.beliefs.set("payload.redacted", redacted, ctx.source)
    ctx.beliefs.set("payload.prompt_sha256", ctx.beliefs.get("prompt.sha256"), ctx.source)
    kind = f"sanitized ({len(result.findings)} spans masked)" if redacted else "clean"
    return StepResult(True, f"policy {decision}; payload {kind}, sha256={sha256_16(payload)}",
                      {"decision": decision, "redacted": redacted})


def step_procure_contract(ctx: StepContext) -> StepResult:
    """Confirm a Contract-Net capacity contract for the bound provider (Unit 3.1)."""
    adapter = ctx.services.registry.get(ctx.provider)
    if adapter is None:
        return _fail(f"provider {ctx.provider} is not registered")
    record = ctx.services.contracts.ensure(adapter.profile)
    price = world.provider_price(ctx.beliefs, ctx.provider)
    if price is None or price > world.budget(ctx.beliefs) + 1e-9:
        return _fail(f"believed price {price} exceeds budget {world.budget(ctx.beliefs):.2f}")
    if record.contract_digest:
        ctx.beliefs.set(world.pkey(ctx.provider, "contract_digest"), record.contract_digest[:16], ctx.source)
    return StepResult(True, f"contract {record.status} with {ctx.provider}: effective ${price:.2f}/1k "
                            f"(list ${record.list_price_per_1k_usd:.2f}, {record.rounds} rounds)",
                      {"status": record.status, "price": price})


def step_route_and_verify(ctx: StepContext) -> StepResult:
    """Run the real constrained utility router on the belief-derived world."""
    local = ctx.intention.plan_id == "dispatch_local_only"
    decision = ctx.services.route_view(ctx.beliefs, require_local=local, hint=ctx.provider)
    ev = next((e for e in decision.evaluations if e.provider_id == ctx.provider), None)
    if ev is None or not ev.feasible:
        reasons = ", ".join(ev.reasons) if ev else "unknown provider"
        return _fail(f"router rejects {ctx.provider}: {reasons}")
    ctx.beliefs.set("route.selected", ctx.provider, ctx.source)
    ctx.beliefs.set("route.utility", ev.utility, ctx.source)
    ctx.beliefs.set("route.ranking", list(decision.ranking), ctx.source)
    rank = decision.ranking.index(ctx.provider) + 1
    return StepResult(True, f"router: {ctx.provider} feasible, U={ev.utility:.2f}, rank {rank}/"
                            f"{len(decision.ranking)} [{' > '.join(decision.ranking)}]",
                      {"utility": ev.utility, "ranking": list(decision.ranking)})


def step_seal_dispatch(ctx: StepContext) -> StepResult:
    sealed = ctx.services.ledger.seal("dispatch_intent", {
        "request_id": ctx.request.request_id, "intention": ctx.intention.id,
        "prompt_sha256": ctx.beliefs.get("prompt.sha256"), "payload_sha256": ctx.beliefs.get("payload.sha256"),
        "provider": ctx.provider, "residency": ctx.beliefs.get(world.pkey(ctx.provider, "residency")),
        "decision": ctx.beliefs.get("prompt.decision")})
    return StepResult(True, f"evidence record #{sealed.index} sealed (hmac {sealed.mac[:12]})",
                      {"index": sealed.index})


def step_dispatch(ctx: StepContext) -> StepResult:
    """Transmit the payload. Safety interlocks are re-checked here, independent of deliberation."""
    b, svc, pid = ctx.beliefs, ctx.services, ctx.provider
    residency = b.get(world.pkey(pid, "residency"))
    if svc.agent.state.force_block_all or world.lockdown(b):
        return _fail("interlock: emergency lockdown is active; nothing transmitted")
    if residency not in world.allowed_residency(b):
        return _fail(f"interlock: residency {residency} not allowed for this prompt; nothing transmitted")
    if world.provider_status(b, pid) in world.STATUS_DOWN:
        return _fail(f"interlock: {pid} is believed {world.provider_status(b, pid)}; nothing transmitted")
    if ctx.request.payload is None or b.get("payload.prompt_sha256") != b.get("prompt.sha256"):
        return _fail("interlock: payload was prepared from an older prompt; nothing transmitted")
    adapter = svc.registry.get(pid)
    if adapter is None:
        return _fail(f"provider {pid} is not registered")
    record = TransmissionRecord(request_id=ctx.request.request_id, provider=pid, residency=str(residency),
                                payload_sha256=sha256_16(ctx.request.payload),
                                redacted=bool(b.get("payload.redacted", False)), ok=False)
    try:
        response = adapter.complete(ctx.request.payload, timeout_s=20.0)
    except (ProviderUnavailable, TimeoutError, OSError) as exc:
        svc.registry.health.record_failure(pid)
        record.error = str(exc)[:160]
        svc.record_transmission(record)
        return _fail(f"provider error: {record.error}")
    record.ok = True
    svc.record_transmission(record)
    svc.registry.health.record_success(pid, response.latency_ms)
    ctx.request.raw_response = response.text
    b.set("dispatch.sent_to", pid, ctx.source)
    b.set("dispatch.residency", residency, ctx.source)
    b.set("dispatch.effective_cost", world.provider_price(b, pid) or 0.0, ctx.source)
    if residency not in world.allowed_residency(b):  # defensive accounting; the interlock prevents it
        b.set("dispatch.residency_violations", int(b.get("dispatch.residency_violations", 0)) + 1, ctx.source)
    b.set("response.received", True, ctx.source)
    return StepResult(True, f"transmitted to {pid} ({residency}); reply in {response.latency_ms:.1f} ms",
                      {"latency_ms": response.latency_ms})


def step_inspect_response(ctx: StepContext) -> StepResult:
    """Real response-side inspection with the same detectors."""
    if ctx.request.raw_response is None:
        return _fail("no provider reply in memory")
    result = ctx.services.agent.inspect_response(ctx.request.raw_response)
    findings = [{"category": f.category, "severity": f.severity, "rule": f.rule} for f in result.findings]
    ctx.beliefs.set("response.findings", findings, ctx.source)
    ctx.beliefs.set("response.decision", result.decision.value, ctx.source)
    cats = sorted({f["category"] for f in findings})
    return StepResult(True, f"reply inspected: {result.decision.value}" + (f" {cats}" if cats else " (clean)"),
                      {"decision": result.decision.value, "categories": cats})


def step_deliver(ctx: StepContext) -> StepResult:
    if world.response_has_secret(ctx.beliefs):
        return _fail("reply contains a critical secret; delivery refused")
    raw = ctx.request.raw_response or ""
    checked = ctx.services.agent.inspect_response(raw)
    ctx.request.delivered_text = redact(raw, checked.findings) if checked.findings else raw
    ctx.services.ledger.seal("delivered", {"request_id": ctx.request.request_id,
                                           "provider": ctx.beliefs.get("dispatch.sent_to"),
                                           "reply_sha256": sha256_16(ctx.request.delivered_text)})
    ctx.beliefs.set("response.delivered", True, ctx.source)
    ctx.beliefs.set("request.status", "COMPLETED", ctx.source)
    return StepResult(True, f"answer delivered to user ({len(ctx.request.delivered_text.split())} words)")


def step_seal_evidence(ctx: StepContext) -> StepResult:
    kind = ctx.params.get("evidence", ctx.intention.plan_id)
    sealed = ctx.services.ledger.seal(kind, {
        "request_id": ctx.request.request_id, "intention": ctx.intention.id,
        "prompt_sha256": ctx.beliefs.get("prompt.sha256"),
        "prompt_categories": sorted(world.prompt_categories(ctx.beliefs)),
        "response_categories": sorted({f["category"] for f in ctx.beliefs.get("response.findings", []) or []}),
        "lockdown": world.lockdown(ctx.beliefs)})
    return StepResult(True, f"evidence '{kind}' sealed as record #{sealed.index} (hmac {sealed.mac[:12]})")


ROTATION_ADVICE = {
    "aws": "deactivate the IAM access key in AWS IAM and issue a new one",
    "github_token": "revoke the token in GitHub developer settings",
    "llm_api_key": "revoke the API key in the provider console",
    "slack_token": "revoke the Slack token and reinstall the app",
    "google_api_key": "delete and recreate the key in Google Cloud credentials",
    "db_connection_string": "rotate the database password and update the secret store",
    "private_key_header": "treat the key pair as compromised and re-issue it",
    "password_assignment": "change the password and move it to the secret manager",
}


def step_advise_rotation(ctx: StepContext) -> StepResult:
    cats = sorted(world.prompt_categories(ctx.beliefs) & world.CRITICAL_CATEGORIES)
    advice = []
    for cat in cats:
        key = "aws" if cat.startswith("aws") else cat
        advice.append(f"{cat}: {ROTATION_ADVICE.get(key, 'revoke and rotate the credential')}")
    ctx.request.advice = advice
    ctx.beliefs.set("guard.rotation_advised", True, ctx.source)
    return StepResult(True, f"rotation advice prepared for {cats}")


def step_apply_lockdown(ctx: StepContext) -> StepResult:
    """Push the lockdown into the engine's policy state and re-inspect with the real policy."""
    ctx.services.agent.state.force_block_all = True
    result = ctx.services.inspect(ctx.request.text)
    ctx.beliefs.set("prompt.decision", result.decision.value, ctx.source)
    return StepResult(result.decision.value == "BLOCK",
                      f"engine force_block_all=True; policy re-inspection -> {result.decision.value}: "
                      f"{result.reasons[0] if result.reasons else ''}")


def step_discard_reply(ctx: StepContext) -> StepResult:
    had = ctx.request.raw_response is not None
    ctx.request.raw_response = None
    ctx.beliefs.set("response.discarded", True, ctx.source)
    return StepResult(True, "provider reply discarded from memory" if had else "no reply held")


def step_raise_alert(ctx: StepContext) -> StepResult:
    provider = ctx.beliefs.get("dispatch.sent_to", "unknown")
    cats = sorted({f["category"] for f in ctx.beliefs.get("response.findings", []) or []
                   if f.get("severity") == "CRITICAL"})
    alert = f"provider {provider} returned critical secret material {cats}"
    ctx.request.alerts.append(alert)
    ctx.beliefs.set("threat.level", "high", ctx.source)
    ctx.services.agent.audit.write(AuditEvent(agent_id=ctx.services.agent.state.agent_id,
                                              event_type="bdi_security_alert", categories=cats,
                                              details={"provider": provider,
                                                       "request_id": ctx.request.request_id}))
    return StepResult(True, f"security alert raised: {alert}; threat.level=high")


def step_open_review_ticket(ctx: StepContext) -> StepResult:
    if not world.review_capacity(ctx.beliefs):
        return _fail("review backlog at limit")
    insp = ctx.request.inspection
    ticket = ctx.services.agent.reviews.submit(ctx.request.text, [f.category for f in insp.findings],
                                               insp.reasons, insp.safe_preview, None)
    ctx.request.review_id = ticket.review_id
    ctx.beliefs.set("review.ticket", ticket.review_id, ctx.source)
    ctx.beliefs.set("review.queue_depth", ctx.services.review_depth(), ctx.source)
    return StepResult(True, f"review ticket {ticket.review_id} opened (TTL 900 s, local-only release)")


def _notify(status: str, contained: bool = False) -> StepAction:
    def action(ctx: StepContext) -> StepResult:
        if contained:
            ctx.beliefs.set("guard.secret_contained", True, ctx.source)
        ctx.beliefs.set("request.status", status, ctx.source)
        return StepResult(True, f"user notified; request.status={status}")
    action.__name__ = f"notify_{status.lower()}"
    return action


# ============================================================================ binders
def _cloud_binder(mode: str) -> Binder:
    def binder(beliefs: Any, services: EngineServices) -> list[Binding]:
        if beliefs.get("prompt.decision") != mode.upper():
            return []
        decision = services.route_view(beliefs)
        kinds = {p.provider_id: p.kind for p in services.registry.profiles()}
        return [Binding(params={"provider": e.provider_id, "mode": mode}, utility=e.utility,
                        cost=e.effective_cost)
                for e in decision.evaluations if e.feasible and kinds.get(e.provider_id) == "cloud"]
    return binder


def _local_binder(beliefs: Any, services: EngineServices) -> list[Binding]:
    if beliefs.get("prompt.decision") not in {"ALLOW", "REDACT"}:
        return []
    decision = services.route_view(beliefs, require_local=True)
    return [Binding(params={"provider": e.provider_id, "mode": "auto"}, utility=e.utility, cost=e.effective_cost)
            for e in decision.evaluations if e.feasible]


# ============================================================================ plan templates
_P = "provider.{provider}"
R_PROMPT = frozenset({"prompt.decision", "prompt.categories", "prompt.sha256"})
R_PRICE = frozenset({f"{_P}.price_per_1k", "budget.max_cost_per_1k"})
R_ROUTE = frozenset({f"{_P}.status", f"{_P}.residency", f"{_P}.price_per_1k", "budget.max_cost_per_1k",
                     "prompt.categories"})
R_DISPATCH = R_ROUTE | frozenset({"policy.lockdown", "prompt.decision", "prompt.sha256"})
R_DELIVER = frozenset({"response.findings", "response.decision", "policy.lockdown"})

G_DISPATCH = (C_NO_LOCKDOWN, C_USABLE, C_RESIDENCY, C_BUDGET)
G_DELIVER = (C_REPLY_CLEAN, C_NO_LOCKDOWN)


def _dispatch_steps() -> tuple[PlanStep, ...]:
    return (
        PlanStep("prepare_payload", step_prepare_payload, R_PROMPT),
        PlanStep("procure_contract", step_procure_contract, R_PRICE, guard=(C_BUDGET,)),
        PlanStep("route_and_verify", step_route_and_verify, R_ROUTE, guard=(C_USABLE, C_RESIDENCY, C_BUDGET)),
        PlanStep("seal_dispatch_record", step_seal_dispatch, R_DISPATCH, guard=G_DISPATCH),
        PlanStep("dispatch", step_dispatch, R_DISPATCH, guard=G_DISPATCH, transmits=True),
        PlanStep("inspect_response", step_inspect_response, frozenset({"response.received"})),
        PlanStep("deliver", step_deliver, R_DELIVER, guard=G_DELIVER),
    )


def ciphermesh_plans() -> list[Plan]:
    """The CipherMesh plan library (D1, D3 and D5 have achieve plans)."""
    return [
        # ------------------------------------------------------------ D3: deliver a useful answer
        Plan("allow_then_dispatch", "D3", "send the clean prompt to the best feasible cloud provider",
             (C_PENDING, C_NO_LOCKDOWN, C_ALLOW, C_USABLE, C_RESIDENCY, C_BUDGET, C_REPLY_CLEAN),
             _dispatch_steps(), binder=_cloud_binder("allow")),
        Plan("redact_then_dispatch", "D3", "mask PII spans, then send to the best feasible cloud provider",
             (C_PENDING, C_NO_LOCKDOWN, C_REDACT, C_USABLE, C_RESIDENCY, C_BUDGET, C_REPLY_CLEAN),
             _dispatch_steps(), binder=_cloud_binder("redact")),
        Plan("dispatch_local_only", "D3", "process on the local trust tier (Ollama); redact if required",
             (C_PENDING, C_NO_LOCKDOWN, C_ALLOW_OR_REDACT, C_USABLE, C_RESIDENCY, C_BUDGET, C_REPLY_CLEAN),
             _dispatch_steps(), binder=_local_binder),
        Plan("hold_for_review", "D3", "park the prompt in the human-review queue (R3)",
             (C_PENDING, C_NO_LOCKDOWN, C_REVIEW, C_REVIEW_CAPACITY),
             (PlanStep("open_review_ticket", step_open_review_ticket,
                       frozenset({"review.queue_depth", "review.limit"}), guard=(C_REVIEW_CAPACITY,)),
              PlanStep("notify_user", _notify("PENDING_REVIEW"), frozenset({"policy.lockdown"}))),
             base_utility=60.0),
        # ------------------------------------------------------------ D1: never transmit a secret
        Plan("block_and_advise_rotation", "D1", "block the prompt, seal evidence and advise key rotation (R1)",
             (C_PENDING, C_PROMPT_SECRET),
             (PlanStep("seal_evidence", step_seal_evidence, frozenset()),
              PlanStep("advise_rotation", step_advise_rotation, frozenset()),
              PlanStep("notify_user", _notify("BLOCKED", contained=True), frozenset())),
             base_utility=100.0),
        Plan("enforce_lockdown_block", "D1", "apply emergency lockdown in the engine and block outbound content",
             (C_PENDING, C_LOCKDOWN_ON),
             (PlanStep("apply_lockdown", step_apply_lockdown, frozenset()),
              PlanStep("seal_evidence", step_seal_evidence, frozenset()),
              PlanStep("notify_user", _notify("BLOCKED", contained=True), frozenset())),
             base_utility=100.0),
        Plan("withhold_reply_and_alert", "D1", "discard a leaking reply, seal evidence and raise an alert",
             (C_PENDING, C_REPLY_SECRET),
             (PlanStep("discard_reply", step_discard_reply, frozenset()),
              PlanStep("seal_evidence", step_seal_evidence, frozenset()),
              PlanStep("raise_alert", step_raise_alert, frozenset()),
              PlanStep("notify_user", _notify("RESPONSE_WITHHELD", contained=True), frozenset())),
             base_utility=100.0),
        # ------------------------------------------------------------ D5: review backlog under limit
        Plan("decline_review_overflow", "D5", "fail closed: do not add to a full review queue; ask to retry",
             (C_PENDING, C_REVIEW, C_REVIEW_FULL),
             (PlanStep("seal_evidence", step_seal_evidence, frozenset()),
              PlanStep("notify_user", _notify("DEFERRED"), frozenset())),
             base_utility=40.0),
    ]
