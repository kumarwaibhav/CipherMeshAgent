"""Scripted environments that change the world while the agent is mid-execution.

Author : Kumar Waibhav Akshat (RA2212704010027)
Course : 21CSE525T Agent Technology, Assignment 4.1 (BDI Goal-Driven Modeling)

A ``Disturbance`` is an unexpected event: it may change the simulated world
(e.g. make a provider adapter fail or leak a secret), amend the user's prompt,
and push belief updates the way a status feed or monitor would. A ``Trigger``
decides *when* it fires:

* ``before_step``  just before a named step of the running intention executes
                   (optionally only for a given plan or provider);
* ``idle``         on the n-th cycle in which no intention can run (all suspended);
* ``cycle``        at or after a given deliberation cycle.

Each disturbance fires once. ``SCENARIOS`` holds the verification-run catalogue.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .engine import BDIAgent, CommitmentStrategy, RunResult
from .services import EngineServices
from .trace import Tracer
from . import world

BeliefTuple = tuple[str, Any, str, float]


@dataclass(frozen=True)
class Trigger:
    kind: str                      # "before_step" | "idle" | "cycle"
    step: str | None = None
    plan: str | None = None
    provider: str | None = None
    n: int = 1

    def describe(self) -> str:
        if self.kind == "before_step":
            scope = "".join([f" of {self.plan}" if self.plan else "",
                             f" on {self.provider}" if self.provider else ""])
            return f"before step '{self.step}'{scope}"
        if self.kind == "idle":
            return f"on idle cycle {self.n}"
        return f"at cycle {self.n}"


@dataclass
class Disturbance:
    label: str
    description: str
    trigger: Trigger
    beliefs: list[BeliefTuple] | Callable[[EngineServices], list[BeliefTuple]] = field(default_factory=list)
    world: Callable[[EngineServices], None] | None = None
    amend_prompt: str | None = None
    fired: bool = False

    def belief_updates(self, services: EngineServices) -> list[BeliefTuple]:
        return list(self.beliefs(services)) if callable(self.beliefs) else list(self.beliefs)


class Environment:
    """Delivers each disturbance once, when its trigger matches."""

    def __init__(self, disturbances: list[Disturbance]) -> None:
        self.disturbances = disturbances
        self._idle_seen = 0
        self.log: list[tuple[int, str]] = []

    def poll(self, cycle: int, intention: Any, step: str | None, idle: bool) -> list[Disturbance]:
        if idle and step is None:
            self._idle_seen += 1
        fired: list[Disturbance] = []
        for d in self.disturbances:
            if d.fired:
                continue
            t = d.trigger
            hit = False
            if t.kind == "before_step" and step is not None and intention is not None:
                hit = (step == t.step and (t.plan is None or intention.plan_id == t.plan)
                       and (t.provider is None or intention.params.get("provider") == t.provider))
            elif t.kind == "idle" and idle and step is None:
                hit = self._idle_seen >= t.n
            elif t.kind == "cycle" and step is None:
                hit = cycle >= t.n
            if hit:
                d.fired = True
                fired.append(d)
                self.log.append((cycle, d.label))
        return fired

    def pending_timed(self) -> bool:
        return any(not d.fired and d.trigger.kind == "cycle" for d in self.disturbances)

    def unfired(self) -> list[str]:
        return [d.label for d in self.disturbances if not d.fired]


@dataclass
class Scenario:
    id: str
    title: str
    prompt: str
    disturbances: list[Disturbance] = field(default_factory=list)
    setup: dict[str, Any] = field(default_factory=dict)
    commitment: CommitmentStrategy = CommitmentStrategy.OPEN_MINDED
    expect_initial: str = ""
    expect_final_plan: str = ""
    expect_status: str = ""
    note: str = ""


# ---------------------------------------------------------------------------- world patches
LEAKED_KEY_SUFFIX = " Note: the deploy job still uses AKIAIOSFODNN7EXAMPLE for staging."


def _outage(provider: str) -> Callable[[EngineServices], None]:
    def patch(services: EngineServices) -> None:
        services.registry.get(provider).failure_rate = 1.0
    return patch


def _leak(provider: str) -> Callable[[EngineServices], None]:
    def patch(services: EngineServices) -> None:
        services.registry.get(provider).response_suffix = LEAKED_KEY_SUFFIX
    return patch


def _residency_change(provider: str, residency: str, region: str) -> Callable[[EngineServices], None]:
    def patch(services: EngineServices) -> None:
        adapter = services.registry.get(provider)
        adapter.profile = adapter.profile.model_copy(update={"data_residency": residency, "region": region})
    return patch


def _review_burst(count: int) -> Callable[[EngineServices], None]:
    def patch(services: EngineServices) -> None:
        for n in range(count):
            services.agent.reviews.submit(f"queued request {n} see https://wiki.corp.internal/page/{n}",
                                          ["internal_url"], ["R3: internal/corporate URL requires human approval"],
                                          None)
    return patch


def _review_depth(services: EngineServices) -> list[BeliefTuple]:
    return [("review.queue_depth", services.review_depth(), "engine:review_monitor", 1.0)]


# ---------------------------------------------------------------------------- catalogue
def build_scenarios() -> list[Scenario]:
    """Fresh scenario objects (disturbances carry a fired flag, so never reuse a list)."""
    gcp, aws = "gcp-vertex", "aws-bedrock"
    return [
        Scenario("S0", "Baseline: no disturbance",
                 "Summarise the main drivers of Q3 cloud spend for the leadership review in five bullet points.",
                 expect_initial="allow_then_dispatch(provider=gcp-vertex)",
                 expect_final_plan="allow_then_dispatch(provider=gcp-vertex)", expect_status="COMPLETED",
                 note="control run: the same pipeline completes unchanged when no belief changes"),
        Scenario("S1", "Provider outage mid-dispatch",
                 "Draft a customer FAQ that explains our new UPI refund timelines in plain language.",
                 [Disturbance("gcp_major_outage", "status feed reports GCP Vertex AI us-central1 major outage",
                              Trigger("before_step", step="seal_dispatch_record", provider=gcp),
                              [(world.pkey(gcp, "status"), "major_outage", "status-feed:gcp-vertex", 0.98)],
                              world=_outage(gcp))],
                 expect_initial="allow_then_dispatch(provider=gcp-vertex)",
                 expect_final_plan="allow_then_dispatch(provider=aws-bedrock)", expect_status="COMPLETED"),
        Scenario("S2", "Emergency lockdown mid-execution",
                 "Compare three approaches to rate-limiting a public REST API and list their trade-offs.",
                 [Disturbance("emergency_lockdown", "security operations declares an emergency lockdown",
                              Trigger("before_step", step="dispatch"),
                              [("policy.lockdown", True, "soc:command_instruction", 1.0)])],
                 expect_initial="allow_then_dispatch(provider=gcp-vertex)",
                 expect_final_plan="enforce_lockdown_block", expect_status="BLOCKED"),
        Scenario("S3", "Provider reply leaks a secret",
                 "Explain how to rotate cloud access keys safely inside a CI pipeline.",
                 [Disturbance("reply_leak", "GCP Vertex starts echoing a cached staging credential in replies",
                              Trigger("before_step", step="dispatch", provider=gcp), [], world=_leak(gcp))],
                 expect_initial="allow_then_dispatch(provider=gcp-vertex)",
                 expect_final_plan="withhold_reply_and_alert", expect_status="RESPONSE_WITHHELD"),
        Scenario("S4", "Price spike, then budget cut",
                 "Write a short product description for an ergonomic mesh office chair.",
                 [Disturbance("gcp_price_spike", "GCP re-prices capacity: contract lapses, on-demand $6.80/1k",
                              Trigger("before_step", step="seal_dispatch_record", provider=gcp),
                              [(world.pkey(gcp, "price_per_1k"), 6.80, "procurement:price-feed", 0.95),
                               (world.pkey(gcp, "price_source"), "on_demand_spike", "procurement:price-feed", 0.95)]),
                  Disturbance("budget_cut", "finance lowers the AI budget to $1.00 per 1k requests",
                              Trigger("before_step", step="dispatch", provider=aws),
                              [("budget.max_cost_per_1k", 1.00, "finance:budget-policy", 1.0)])],
                 expect_initial="allow_then_dispatch(provider=gcp-vertex)",
                 expect_final_plan="dispatch_local_only(provider=local)", expect_status="COMPLETED"),
        Scenario("S5", "Indian data residency: provider region changes",
                 "Update KYC for the customer with Aadhaar 2345 6789 0124 and email the confirmation "
                 "to priya.sharma@example.in.",
                 [Disturbance("bedrock_region_change",
                              "AWS enables a cross-region inference profile: Bedrock now serves from us-east-1",
                              Trigger("before_step", step="dispatch", provider=aws),
                              [(world.pkey(aws, "residency"), "US", "aws-health:inference-profile", 0.97),
                               (world.pkey(aws, "region"), "us-east-1", "aws-health:inference-profile", 0.97)],
                              world=_residency_change(aws, "US", "us-east-1"))],
                 expect_initial="redact_then_dispatch(provider=aws-bedrock)",
                 expect_final_plan="redact_then_dispatch(provider=azure-ai)", expect_status="COMPLETED"),
        Scenario("S6", "Indian data residency: prompt correction reveals PAN",
                 "Prepare a GST invoice summary for vendor Sharma Traders for October.",
                 [Disturbance("prompt_amended", "user edits the prompt and adds the vendor PAN",
                              Trigger("before_step", step="seal_dispatch_record", provider=gcp),
                              amend_prompt="Prepare a GST invoice summary for vendor Sharma Traders for "
                                           "October, PAN ABCPE1234F.")],
                 expect_initial="allow_then_dispatch(provider=gcp-vertex)",
                 expect_final_plan="redact_then_dispatch(provider=aws-bedrock)", expect_status="COMPLETED"),
        Scenario("S7", "Transient partial outage: suspend and resume",
                 "List five icebreaker questions for a new-joiner orientation session.",
                 [Disturbance("gcp_partial_outage", "status feed reports GCP Vertex partial outage",
                              Trigger("before_step", step="dispatch", provider=gcp),
                              [(world.pkey(gcp, "status"), "partial_outage", "status-feed:gcp-vertex", 0.90)]),
                  Disturbance("gcp_recovered", "status feed reports GCP Vertex operational again",
                              Trigger("idle", n=2),
                              [(world.pkey(gcp, "status"), "operational", "status-feed:gcp-vertex", 0.99)])],
                 expect_initial="allow_then_dispatch(provider=gcp-vertex)",
                 expect_final_plan="allow_then_dispatch(provider=gcp-vertex)", expect_status="COMPLETED",
                 note="a transient condition suspends the intention instead of dropping it"),
        Scenario("S8", "Review backlog fills up",
                 "Find out why https://jira.corp.internal/browse/PAY-2291 keeps failing in the nightly build.",
                 [Disturbance("review_burst", "a burst of 25 internal-URL prompts fills the review queue",
                              Trigger("before_step", step="open_review_ticket"), _review_depth,
                              world=_review_burst(25))],
                 expect_initial="hold_for_review", expect_final_plan="decline_review_overflow",
                 expect_status="DEFERRED"),
    ]


def ablation_scenarios() -> list[Scenario]:
    """S1 and S2 re-run with BLIND commitment (no reconsideration) for comparison."""
    out = []
    for base in build_scenarios():
        if base.id in {"S1", "S2"}:
            base.id = f"{base.id}-BLIND"
            base.title = f"{base.title} (blind commitment)"
            base.commitment = CommitmentStrategy.BLIND
            out.append(base)
    return out


def run_scenario(scenario: Scenario, latency_scale: float = 0.0, idle_wait_s: float = 0.0,
                 tracer: Tracer | None = None) -> tuple[BDIAgent, RunResult, Environment]:
    """Run one scenario end to end on a fresh engine and return the agent, result and environment."""
    services = EngineServices(latency_scale=latency_scale)
    agent = BDIAgent(services, tracer=tracer or Tracer(run_id=scenario.id), commitment=scenario.commitment,
                     idle_wait_s=idle_wait_s)
    agent.perceive_world()
    for key, value in scenario.setup.items():
        agent.beliefs.set(key, value, "scenario:setup")
    agent.submit(scenario.prompt, request_id=f"req-{scenario.id.lower()}")
    environment = Environment(scenario.disturbances)
    result = agent.run(environment)
    return agent, result, environment
