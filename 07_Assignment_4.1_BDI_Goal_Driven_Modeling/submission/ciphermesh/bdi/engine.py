"""BDIAgent: the deliberation cycle that turns beliefs and desires into intentions.

Author : Kumar Waibhav Akshat (RA2212704010027)
Course : 21CSE525T Agent Technology, Assignment 4.1 (BDI Goal-Driven Modeling)

The control loop follows the abstract BDI interpreter of Rao and Georgeff and
Bratman's account of intentions as commitments that filter later options:

    loop
      1  perceive            environment events (cycle / idle triggers)
      2  belief revision     apply changes; event-driven RECONSIDER
      3  option generation   desires that are active and not yet satisfied
      4  filtering           priority + conflicts -> selected desires, pre-emptions
      5  means-ends          best applicable (plan, binding) for each selected desire
      6  act                 pre-step perception, then execute ONE step of the top intention
      7  reconsider          after the step (and for every queued belief change)
    until no live intention and no achievable option remains

Commitment strategy (explicit, see ``CommitmentStrategy``)
----------------------------------------------------------
OPEN_MINDED (default) keeps an intention only while (a) its plan context and the
guards of its *remaining* steps still hold and (b) its desire is still an option
that no higher-priority desire pre-empts. Reconsideration is *event-driven*: an
intention is re-evaluated only when a changed belief is one its remaining steps
or the desires depend on, or right after it executed a step. A three-valued
check decides the outcome: VIOLATED -> DROP, UNCERTAIN -> SUSPEND (bounded wait),
HOLDS -> keep or RESUME. SINGLE_MINDED skips the desire check (b). BLIND never
reconsiders and abandons an intention only when a step fails; it exists for the
ablation that shows why reconsideration matters.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatchcase
from typing import Any, Iterable

from ..models import AuditEvent
from . import world
from .beliefs import BeliefBase
from .desires import Desire, DesireSet, ciphermesh_desires
from .intentions import Intention, IntentionStack, IntentionStatus, StepRecord
from .plans import (Condition, PlanLibrary, PlanOption, StepContext, StepResult, Verdict,
                    ciphermesh_plans)
from .services import EngineServices, RequestContext, sha256_16
from .trace import Tracer


class CommitmentStrategy(str, Enum):
    BLIND = "BLIND"
    SINGLE_MINDED = "SINGLE_MINDED"
    OPEN_MINDED = "OPEN_MINDED"


@dataclass
class IntentionShift:
    """One change of mind: an intention that ended early and what replaced it."""
    cycle: int
    at_ms: float
    dropped: dict
    status: str
    reasons: list[str]
    trigger: list[dict]
    before_step: str | None
    adopted: dict | None = None
    adopted_cycle: int | None = None
    adopted_at_ms: float | None = None

    def as_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class RunResult:
    request_id: str
    final_status: str
    commitment: str
    cycles: int
    steps_executed: int
    elapsed_ms: float
    intentions: list[dict]
    shifts: list[IntentionShift]
    transmissions: list[dict]
    reconsideration: dict
    impossible: list[str]
    ledger_records: int
    ledger_verified: bool
    delivered: bool
    advice: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)


def _matches(key: str, patterns: Iterable[str]) -> bool:
    return any(key == p or ("*" in p and fnmatchcase(key, p)) for p in patterns)


class BDIAgent:
    """Goal-driven CipherMesh agent with explicit beliefs, desires and intentions."""

    def __init__(self, services: EngineServices | None = None, desires: DesireSet | None = None,
                 library: PlanLibrary | None = None, beliefs: BeliefBase | None = None,
                 tracer: Tracer | None = None,
                 commitment: CommitmentStrategy = CommitmentStrategy.OPEN_MINDED,
                 max_suspend_cycles: int = 4, idle_wait_s: float = 0.0, max_cycles: int = 80) -> None:
        self.services = services or EngineServices()
        self.beliefs = beliefs or BeliefBase()
        self.desires = desires or ciphermesh_desires()
        self.library = library or PlanLibrary(self.services, ciphermesh_plans())
        self.tracer = tracer or Tracer()
        self.commitment = CommitmentStrategy(commitment)
        self.max_suspend_cycles = max_suspend_cycles
        self.idle_wait_s = idle_wait_s
        self.max_cycles = max_cycles
        self.intentions = IntentionStack()
        self.cycle = 0
        self.request: RequestContext | None = None
        self.shifts: list[IntentionShift] = []
        self.stats = {"steps": 0, "evaluated": 0, "kept": 0, "dropped": 0,
                      "suspended": 0, "resumed": 0, "failed": 0, "belief_changes": 0,
                      "ignored_changes": 0}
        self._pending: deque[dict] = deque()
        self._pending_lock = threading.Lock()
        self._open_shifts: list[IntentionShift] = []
        self._desire_state: dict[str, str] = {}
        self._last_deliberation: tuple | None = None
        self._impossible: dict[str, int] = {}
        self._impossible_ever: list[str] = []
        self._desire_reads: set[str] = set()
        for desire in self.desires:
            self._desire_reads |= set(desire.reads)
        self.beliefs.subscribe(self._on_belief_change)

    # ================================================================== perception
    def _on_belief_change(self, key: str, old: Any, new: Any, source: str) -> None:
        held = self.beliefs.belief(key)
        confidence = held.confidence if held is not None else 1.0
        with self._pending_lock:
            self._pending.append({"key": key, "old": old, "new": new, "source": source,
                                  "confidence": confidence})

    def _drain(self) -> list[dict]:
        with self._pending_lock:
            items = list(self._pending)
            self._pending.clear()
        return items

    def perceive_world(self) -> None:
        """Seed beliefs from the live engine (registry, procurement, policy state)."""
        self.services.perceive_world(self.beliefs)
        seeded = self._drain()
        providers = sorted({c["key"].split(".")[1] for c in seeded if c["key"].startswith("provider.")})
        prices = ", ".join(f"{p} ${world.provider_price(self.beliefs, p):.2f}" for p in providers)
        self.stats["belief_changes"] += len(seeded)
        self.tracer.emit("PERCEIVE", self.cycle, f"world model seeded with {len(seeded)} beliefs "
                         f"(contracts: {prices}; budget ${world.budget(self.beliefs):.2f}/1k)",
                         beliefs=len(seeded), providers=providers)

    def submit(self, text: str, request_id: str) -> RequestContext:
        """Perceive a new user request: run the real detector/policy and record derived beliefs."""
        inspection = self.services.inspect(text)
        self.request = RequestContext(request_id=request_id, text=text, inspection=inspection)
        src = "sensor:policy.inspect_text"
        for key, value in (("response.delivered", False), ("response.findings", []),
                           ("guard.secret_contained", False), ("dispatch.residency_violations", 0)):
            self.beliefs.set(key, value, "agent:init")
        self.beliefs.set("request.id", request_id, "gateway")
        self._set_prompt_beliefs(text, inspection, src)
        self.beliefs.set("request.status", "PENDING", "gateway")
        cats = sorted({f.category for f in inspection.findings})
        self.tracer.emit("PERCEIVE", self.cycle, f"request {request_id} received: "
                         f"{len(text.encode('utf-8'))} bytes, policy {inspection.decision.value}"
                         f"{' ' + str(cats) if cats else ''}", request_id=request_id,
                         decision=inspection.decision.value, categories=cats)
        return self.request

    def amend_prompt(self, text: str, source: str = "user:amendment") -> None:
        """The user corrected the prompt mid-execution: re-inspect and revise prompt beliefs."""
        if self.request is None:
            raise RuntimeError("no request to amend")
        inspection = self.services.inspect(text)
        self.request.text = text
        self.request.inspection = inspection
        self.request.payload = None
        self._set_prompt_beliefs(text, inspection, source)

    def _set_prompt_beliefs(self, text: str, inspection: Any, source: str) -> None:
        self.beliefs.set("prompt.sha256", sha256_16(text), source)
        self.beliefs.set("prompt.bytes", len(text.encode("utf-8")), source)
        self.beliefs.set("prompt.categories", sorted({f.category for f in inspection.findings}), source)
        self.beliefs.set("prompt.decision", inspection.decision.value, source)

    def _apply_disturbance(self, disturbance: Any) -> None:
        self.tracer.emit("PERCEIVE", self.cycle, f"environment: {disturbance.description}",
                         disturbance=disturbance.label)
        if disturbance.world is not None:
            disturbance.world(self.services)
        if disturbance.amend_prompt is not None:
            self.amend_prompt(disturbance.amend_prompt)
        for key, value, source, confidence in disturbance.belief_updates(self.services):
            self.beliefs.set(key, value, source, confidence)

    # ================================================================== main loop
    def run(self, environment: Any = None) -> RunResult:
        if self.request is None:
            raise RuntimeError("submit() a request before run()")
        started = time.perf_counter()
        while self.cycle < self.max_cycles:
            self.cycle += 1
            top = self.intentions.top()
            idle = top is None and bool(self.intentions.live())
            # 1 perceive (cycle / idle triggers)
            if environment is not None:
                for d in environment.poll(self.cycle, top, None, idle):
                    self._apply_disturbance(d)
            # 2 belief revision + event-driven reconsideration
            self._revise_and_reconsider(origin="perception")
            # 3-4 options and filtering
            delib = self.desires.deliberate(self.beliefs)
            self._trace_desires()
            self._preempt(delib)
            # 5 means-ends reasoning
            self._means_ends(delib)
            # 6 act: pre-step perception, then one step
            top = self.intentions.top()
            ran: Intention | None = None
            if top is not None:
                if environment is not None and top.next_step is not None:
                    fired = environment.poll(self.cycle, top, top.next_step.name, False)
                    for d in fired:
                        self._apply_disturbance(d)
                # last belief revision before acting: nothing written since phase 2 is left unprocessed
                self._revise_and_reconsider(origin="perception")
                if top.status == IntentionStatus.ACTIVE and self.intentions.top() is top:
                    if self._execute_step(top) is not None:
                        ran = top
            elif self.intentions.live() and self.idle_wait_s:
                time.sleep(self.idle_wait_s)
            # 7 reconsider after the step
            self._revise_and_reconsider(origin="step", executed=ran)
            if not self.intentions.live() and not self._has_achievable_option():
                if environment is None or not environment.pending_timed():
                    break
        self._finalise()
        return self._result(started)

    # ================================================================== deliberation helpers
    def _trace_desires(self) -> None:
        for desire in self.desires:
            if not desire.is_active(self.beliefs):
                state = "inactive"
            elif desire.kind == "maintain":
                state = "constraining" if desire.is_satisfied(self.beliefs) else "violated"
            else:
                state = "satisfied" if desire.is_satisfied(self.beliefs) else "option"
            previous = self._desire_state.get(desire.id)
            if previous != state:
                self._desire_state[desire.id] = state
                if previous is None and state == "inactive":
                    continue
                extra = f" -> {desire.constrains}" if state == "constraining" and desire.constrains else ""
                self.tracer.emit("DESIRE", self.cycle, f"{desire.id} '{desire.description}' "
                                 f"(p{desire.priority}, {desire.kind}): {previous or 'new'} -> {state}{extra}",
                                 desire=desire.id, state=state, previous=previous)

    def _preempt(self, delib: Any) -> None:
        signature = (tuple(d.id for d in delib.options), tuple(delib.selected_ids()),
                     tuple(sorted(delib.preempted.items())), tuple(d.id for d in delib.constraints))
        if signature != self._last_deliberation:
            self._last_deliberation = signature
            pre = ", ".join(f"{k} by {v}" for k, v in sorted(delib.preempted.items())) or "none"
            self.tracer.emit("DELIBERATE", self.cycle,
                             f"options {[d.id for d in delib.options]}; pursue {delib.selected_ids()}; "
                             f"pre-empted: {pre}; constraints {[d.id for d in delib.constraints]}",
                             options=[d.id for d in delib.options], selected=delib.selected_ids(),
                             preempted=delib.preempted, constraints=[d.id for d in delib.constraints])
        if self.commitment != CommitmentStrategy.OPEN_MINDED:
            return
        for desire_id, by in delib.preempted.items():
            intention = self.intentions.for_desire(desire_id)
            if intention is not None:
                blocker = self.desires.get(by)
                self._drop(intention, [f"pre-empted by {by} '{blocker.description}' (priority {blocker.priority})"],
                           trigger=[])

    def _means_ends(self, delib: Any) -> None:
        for desire in delib.selected:
            if self.intentions.for_desire(desire.id) is not None:
                continue
            if self._impossible.get(desire.id) == self.beliefs.revision:
                continue
            options = self.library.options_for(desire, self.beliefs)
            if not options:
                self._impossible[desire.id] = self.beliefs.revision
                if desire.id not in self._impossible_ever:
                    self._impossible_ever.append(desire.id)
                rejected = self.library.rejected_for(desire, self.beliefs)
                why = "; ".join(f"{label}: {reasons[0]}" for label, reasons in rejected[:3])
                self.tracer.emit("DESIRE", self.cycle, f"{desire.id} has no applicable plan now ({why})",
                                 desire=desire.id, state="no_applicable_plan",
                                 rejected=[{"plan": l, "reasons": r} for l, r in rejected])
                continue
            self._adopt(desire, options)

    def _adopt(self, desire: Desire, options: list[PlanOption]) -> Intention:
        best = options[0]
        listing = ", ".join(f"{o.label()} U={o.utility:.2f}" for o in options[:4])
        self.tracer.emit("DELIBERATE", self.cycle, f"means-ends for {desire.id}: {len(options)} applicable "
                         f"option(s): {listing}", desire=desire.id,
                         options=[{"label": o.label(), "utility": o.utility, "cost": o.cost} for o in options])
        replaces = self._open_shifts[-1].dropped["id"] if self._open_shifts else None
        intention = Intention(id=self.intentions.next_id(), desire_id=desire.id, plan=best.plan,
                              params=dict(best.params), priority=desire.priority, utility=best.utility,
                              created_cycle=self.cycle, replaces=replaces)
        self.intentions.push(intention)
        steps = " -> ".join(s.name for s in intention.steps)
        self.tracer.emit("INTEND", self.cycle, f"{intention.id} adopted for {desire.id}: {intention.label} "
                         f"U={best.utility:.2f} [{steps}]", intention=intention.id, desire=desire.id,
                         plan=intention.plan_id, params=intention.params, utility=best.utility,
                         steps=[s.name for s in intention.steps])
        self._audit("bdi_intention_adopted", intention)
        if self._open_shifts:
            for shift in self._open_shifts:
                shift.adopted = intention.summary()
                shift.adopted_cycle = self.cycle
                shift.adopted_at_ms = round(self.tracer.elapsed_ms(), 3)
                self.shifts.append(shift)
                self.tracer.emit("REPLAN", self.cycle, f"{shift.dropped['id']} {shift.dropped['label']} "
                                 f"[{shift.status}] -> {intention.id} {intention.label}",
                                 from_intention=shift.dropped["id"], to_intention=intention.id,
                                 from_label=shift.dropped["label"], to_label=intention.label)
            self._open_shifts = []
        return intention

    def _has_achievable_option(self) -> bool:
        delib = self.desires.deliberate(self.beliefs)
        return any(self.library.options_for(d, self.beliefs) for d in delib.selected
                   if self.intentions.for_desire(d.id) is None)

    # ================================================================== acting
    def _execute_step(self, intention: Intention) -> StepResult | None:
        step = intention.next_step
        assert step is not None and self.request is not None
        if self.commitment != CommitmentStrategy.BLIND:
            # execution-time guard check: a step never runs on a belief that already contradicts it
            failing = [c for c in step.guard if c.evaluate(self.beliefs, intention.params) != Verdict.HOLDS]
            if failing:
                self.tracer.emit("RECONSIDER", self.cycle, f"{intention.id} guard of '{step.name}' no longer "
                                 f"holds ({failing[0].describe(intention.params)}); step not executed",
                                 intention=intention.id, result="guard", step=step.name)
                self.stats["evaluated"] += 1
                self._reconsider(intention, [])
                return None
        index = intention.cursor + 1
        ctx = StepContext(self.services, self.beliefs, self.request, intention, intention.params)
        start = self.tracer.elapsed_ms()
        try:
            result = step.action(ctx)
        except Exception as exc:  # a step error becomes a failed step, never a crash of the loop
            result = StepResult(False, f"{type(exc).__name__}: {exc}")
        duration = self.tracer.elapsed_ms() - start
        intention.advance(StepRecord(index=index, name=step.name, ok=result.ok, detail=result.detail,
                                     cycle=self.cycle, started_ms=round(start, 3), duration_ms=round(duration, 3)))
        self.stats["steps"] += 1
        self.tracer.emit("STEP", self.cycle, f"{intention.id} {intention.label} [{index}/{len(intention.steps)}] "
                         f"{step.name} -> {'OK' if result.ok else 'FAILED'}: {result.detail}",
                         intention=intention.id, plan=intention.plan_id, params=intention.params,
                         step=step.name, index=index, total=len(intention.steps), ok=result.ok,
                         start_ms=round(start, 3), duration_ms=round(duration, 3), transmits=step.transmits)
        if not result.ok:
            self.stats["failed"] += 1
            intention.transition(IntentionStatus.FAILED, f"step {step.name} failed: {result.detail}", self.cycle)
            self.tracer.emit("FAIL", self.cycle, f"{intention.id} {intention.label} failed at {step.name}",
                             intention=intention.id, reason=result.detail)
            self._open_shift(intention, "FAILED", [f"step {step.name} failed: {result.detail}"],
                             [{"key": f"step:{step.name}", "old": None, "new": "FAILED", "source": "self"}],
                             step.name)
        elif intention.done:
            intention.transition(IntentionStatus.SUCCEEDED, "all steps completed", self.cycle)
            self.tracer.emit("COMPLETE", self.cycle, f"{intention.id} {intention.label} succeeded "
                             f"({len(intention.steps)} steps) for {intention.desire_id}",
                             intention=intention.id, desire=intention.desire_id)
        return result

    # ================================================================== reconsideration
    def _revise_and_reconsider(self, origin: str, executed: Intention | None = None) -> None:
        changes = self._drain()
        for ch in changes:
            self.stats["belief_changes"] += 1
            self.tracer.emit("BELIEF", self.cycle, f"{ch['key']}: {_short(ch['old'])} -> {_short(ch['new'])} "
                             f"(source {ch['source']})", key=ch["key"], old=ch["old"], new=ch["new"],
                             source=ch["source"])
        if changes:
            self._trace_desires()
        if self.commitment == CommitmentStrategy.BLIND:
            return
        live = self.intentions.live()
        if live:
            watch_all: set[str] = set()
            for intention in live:
                watch_all |= intention.watched_beliefs()
            if self.commitment == CommitmentStrategy.OPEN_MINDED:
                watch_all |= self._desire_reads
            self.stats["ignored_changes"] += sum(1 for c in changes if not _matches(c["key"], watch_all))
        for intention in live:
            watched = intention.watched_beliefs()
            if self.commitment == CommitmentStrategy.OPEN_MINDED:
                watched |= self._desire_reads
            relevant = [c for c in changes if _matches(c["key"], watched)]
            waiting = (intention.status == IntentionStatus.SUSPENDED and intention.suspended_cycle != self.cycle)
            due = bool(relevant) or (origin == "step" and (intention is executed or waiting))
            if not due:
                continue
            self.stats["evaluated"] += 1
            self._reconsider(intention, relevant)

    def _conditions(self, intention: Intention) -> list[Condition]:
        """Guards of the remaining steps plus plan-context conditions those steps still depend on."""
        relevant: set[str] = set()
        conds: dict[str, Condition] = {}
        for step in intention.remaining_steps:
            relevant |= step.relevant_for(intention.params)
            for cond in step.guard:
                conds.setdefault(cond.description, cond)
        for cond in intention.plan.conditions:
            if cond.reads_for(intention.params) & relevant:
                conds.setdefault(cond.description, cond)
        return list(conds.values())

    def _reconsider(self, intention: Intention, relevant: list[dict]) -> None:
        checked = [(c, c.evaluate(self.beliefs, intention.params)) for c in self._conditions(intention)]
        verdicts = [(c.describe(intention.params), v) for c, v in checked]
        violated = [c for c, v in checked if v == Verdict.VIOLATED]
        uncertain = [d for d, v in verdicts if v == Verdict.UNCERTAIN]
        reasons: list[str] = []
        if self.commitment == CommitmentStrategy.OPEN_MINDED:
            desire = self.desires.get(intention.desire_id)
            if not desire.is_active(self.beliefs):
                reasons.append(f"desire {desire.id} is no longer active")
            elif desire.is_satisfied(self.beliefs):
                reasons.append(f"desire {desire.id} is already satisfied")
            else:
                by = self.desires.deliberate(self.beliefs).preempted.get(desire.id)
                if by:
                    blocker = self.desires.get(by)
                    reasons.append(f"pre-empted by {by} '{blocker.description}' (priority {blocker.priority})")
        reasons += [self._requires(intention, c) for c in violated]
        keys = [c["key"] for c in relevant]
        if reasons:
            self._drop(intention, reasons, relevant)
        elif uncertain:
            if intention.status == IntentionStatus.ACTIVE:
                self.stats["suspended"] += 1
                reason = f"waiting: {uncertain[0]} is UNCERTAIN"
                intention.transition(IntentionStatus.SUSPENDED, reason, self.cycle)
                self.tracer.emit("SUSPEND", self.cycle, f"{intention.id} {intention.label} suspended at "
                                 f"{intention.next_step.name if intention.next_step else '-'}: {reason}",
                                 intention=intention.id, reason=reason, trigger=keys)
            else:
                waited = self.cycle - (intention.suspended_cycle or self.cycle)
                if waited >= self.max_suspend_cycles:
                    self._drop(intention, [f"suspension timeout after {waited} cycles ({uncertain[0]})"], relevant)
                else:
                    self.tracer.emit("RECONSIDER", self.cycle, f"{intention.id} still suspended "
                                     f"({uncertain[0]} UNCERTAIN; waited {waited}/{self.max_suspend_cycles} cycles)",
                                     intention=intention.id, result="wait", trigger=keys)
        elif intention.status == IntentionStatus.SUSPENDED:
            self.stats["resumed"] += 1
            intention.transition(IntentionStatus.ACTIVE, "all conditions hold again", self.cycle)
            self.tracer.emit("RESUME", self.cycle, f"{intention.id} {intention.label} resumed at "
                             f"{intention.next_step.name if intention.next_step else '-'} (all conditions hold)",
                             intention=intention.id, trigger=keys)
        else:
            self.stats["kept"] += 1
            if relevant:
                held = (f"{len(verdicts)} remaining condition(s) still hold" if verdicts
                        else "no remaining step depends on these beliefs")
                self.tracer.emit("RECONSIDER", self.cycle, f"{intention.id} kept after {keys}: {held}",
                                 intention=intention.id, result="kept",
                                 trigger=keys)

    def _requires(self, intention: Intention, cond: Condition) -> str:
        """Drop reason in the form: requires '<condition>' but believed <key>=<value>."""
        keys = sorted(k for k in cond.reads_for(intention.params) if self.beliefs.has(k))
        believed = ", ".join(f"{k}={_short(self.beliefs.get(k))}" for k in keys) or "nothing that satisfies it"
        return f"requires '{cond.describe(intention.params)}' but believed {believed}"

    def _drop(self, intention: Intention, reasons: list[str], trigger: list[dict]) -> None:
        self.stats["dropped"] += 1
        at = intention.next_step.name if intention.next_step else None
        intention.transition(IntentionStatus.DROPPED, "; ".join(reasons), self.cycle)
        self.tracer.emit("RECONSIDER", self.cycle, f"{intention.id} invalidated by "
                         f"{[c['key'] for c in trigger] or 'deliberation'}", intention=intention.id,
                         result="drop", trigger=[c["key"] for c in trigger])
        self.tracer.emit("DROP", self.cycle, f"{intention.id} {intention.label} dropped before "
                         f"'{at}' ({intention.progress()} done): {'; '.join(reasons)}",
                         intention=intention.id, plan=intention.plan_id, params=intention.params,
                         reasons=reasons, before_step=at)
        self._audit("bdi_intention_dropped", intention, reasons=reasons)
        self._open_shift(intention, "DROPPED", reasons, trigger, at)

    def _open_shift(self, intention: Intention, status: str, reasons: list[str], trigger: list[dict],
                    at: str | None) -> None:
        self._open_shifts.append(IntentionShift(cycle=self.cycle, at_ms=round(self.tracer.elapsed_ms(), 3),
                                                dropped=intention.summary(), status=status, reasons=reasons,
                                                trigger=[dict(c) for c in trigger], before_step=at))

    # ================================================================== bookkeeping
    def _audit(self, event_type: str, intention: Intention, **details: Any) -> None:
        self.services.agent.audit.write(AuditEvent(
            agent_id=self.services.agent.state.agent_id, event_type=event_type,
            message_id=self.request.request_id if self.request else None,
            details={"intention": intention.id, "desire": intention.desire_id, "plan": intention.plan_id,
                     "params": intention.params, **details}))

    def _finalise(self) -> None:
        if self.beliefs.get("request.status") not in world.FINAL_STATUSES:
            self.beliefs.set("request.status", "FAILED", "agent:deliberation")
            self._drain()
        for shift in self._open_shifts:
            self.shifts.append(shift)
        self._open_shifts = []
        status = self.beliefs.get("request.status")
        self.tracer.emit("FINISH", self.cycle, f"request {self.request.request_id} finished: {status} after "
                         f"{self.cycle} cycles, {self.stats['steps']} steps, {len(self.shifts)} intention shift(s), "
                         f"{len(self.services.transmissions_for(self.request.request_id))} transmission(s)",
                         status=status, stats=dict(self.stats))

    def _result(self, started: float) -> RunResult:
        assert self.request is not None
        tx = self.services.transmissions_for(self.request.request_id)
        return RunResult(
            request_id=self.request.request_id, final_status=str(self.beliefs.get("request.status")),
            commitment=self.commitment.value, cycles=self.cycle, steps_executed=self.stats["steps"],
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
            intentions=[i.summary() for i in self.intentions.all()], shifts=list(self.shifts),
            transmissions=[t.__dict__ for t in tx],
            reconsideration={k: self.stats[k] for k in ("evaluated", "kept", "dropped", "suspended",
                                                         "resumed", "failed", "belief_changes", "ignored_changes")},
            impossible=list(self._impossible_ever), ledger_records=len(self.services.ledger.records()),
            ledger_verified=self.services.ledger.verify(),
            delivered=bool(self.beliefs.get("response.delivered", False)),
            advice=list(self.request.advice), alerts=list(self.request.alerts))


def _short(value: Any) -> str:
    text = str(value)
    return text if len(text) <= 80 else text[:77] + "..."
