"""Intentions: committed, partially executed plans (the "I" of BDI).

Author : Kumar Waibhav Akshat (RA2212704010027)
Course : 21CSE525T Agent Technology, Assignment 4.1 (BDI Goal-Driven Modeling)

An intention binds one plan template (with concrete parameters such as the
provider) to one desire. It owns an ordered step pipeline and a cursor that
points at the next step to run. Its status follows a small state machine:

    ACTIVE ----> SUCCEEDED            (last step finished)
      |  \\----> FAILED               (a step returned an error)
      |   \\---> DROPPED              (reconsideration: invalid / pre-empted)
      v
    SUSPENDED --> ACTIVE (resume) | DROPPED | FAILED

Every transition is recorded with a reason, cycle number and timestamp, so the
trace can explain *why* the agent changed its mind.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .plans import Plan, PlanStep


class IntentionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    DROPPED = "DROPPED"


LIVE = frozenset({IntentionStatus.ACTIVE, IntentionStatus.SUSPENDED})
TERMINAL = frozenset({IntentionStatus.SUCCEEDED, IntentionStatus.FAILED, IntentionStatus.DROPPED})
ALLOWED = {
    IntentionStatus.ACTIVE: {IntentionStatus.SUSPENDED, IntentionStatus.SUCCEEDED,
                             IntentionStatus.FAILED, IntentionStatus.DROPPED},
    IntentionStatus.SUSPENDED: {IntentionStatus.ACTIVE, IntentionStatus.DROPPED, IntentionStatus.FAILED},
    IntentionStatus.SUCCEEDED: set(), IntentionStatus.FAILED: set(), IntentionStatus.DROPPED: set(),
}


class IntentionError(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ReasonEntry:
    cycle: int
    status: str
    reason: str
    at: str


@dataclass
class StepRecord:
    index: int
    name: str
    ok: bool
    detail: str
    cycle: int
    started_ms: float
    duration_ms: float


@dataclass
class Intention:
    id: str
    desire_id: str
    plan: Plan
    params: dict
    priority: int
    utility: float = 0.0
    created_cycle: int = 0
    cursor: int = 0
    status: IntentionStatus = IntentionStatus.ACTIVE
    created_at: datetime = field(default_factory=_now)
    reasons: list[ReasonEntry] = field(default_factory=list)
    step_log: list[StepRecord] = field(default_factory=list)
    suspended_cycle: int | None = None
    replaces: str | None = None

    # ------------------------------------------------------------------ views
    @property
    def plan_id(self) -> str:
        return self.plan.id

    @property
    def steps(self) -> tuple[PlanStep, ...]:
        return self.plan.steps

    @property
    def label(self) -> str:
        return self.plan.label(self.params)

    @property
    def next_step(self) -> PlanStep | None:
        return self.steps[self.cursor] if self.cursor < len(self.steps) else None

    @property
    def remaining_steps(self) -> tuple[PlanStep, ...]:
        return self.steps[self.cursor:]

    @property
    def done(self) -> bool:
        return self.cursor >= len(self.steps)

    @property
    def live(self) -> bool:
        return self.status in LIVE

    def progress(self) -> str:
        return f"{self.cursor}/{len(self.steps)}"

    def watched_beliefs(self) -> set[str]:
        """Belief keys whose change can invalidate the rest of this intention."""
        keys: set[str] = set()
        for step in self.remaining_steps:
            keys |= step.relevant_for(self.params)
            for cond in step.guard:
                keys |= cond.reads_for(self.params)
        return keys

    # ------------------------------------------------------------------ transitions
    def transition(self, new_status: IntentionStatus, reason: str, cycle: int) -> None:
        if new_status not in ALLOWED[self.status]:
            raise IntentionError(f"{self.id}: illegal transition {self.status.value} -> {new_status.value}")
        self.status = new_status
        self.suspended_cycle = cycle if new_status == IntentionStatus.SUSPENDED else None
        self.reasons.append(ReasonEntry(cycle=cycle, status=new_status.value, reason=reason,
                                        at=_now().isoformat(timespec="milliseconds")))

    def advance(self, record: StepRecord) -> None:
        if self.status != IntentionStatus.ACTIVE:
            raise IntentionError(f"{self.id}: cannot execute a step while {self.status.value}")
        self.step_log.append(record)
        if record.ok:
            self.cursor += 1

    def summary(self) -> dict[str, Any]:
        return {"id": self.id, "desire": self.desire_id, "plan": self.plan_id, "label": self.label,
                "params": {k: v for k, v in self.params.items()}, "utility": self.utility,
                "status": self.status.value, "progress": self.progress(),
                "steps_done": [s.name for s in self.step_log if s.ok],
                "reasons": [r.__dict__ for r in self.reasons], "replaces": self.replaces}


class IntentionStack:
    """All intentions of the agent; live ones ordered by desire priority, newest first on ties."""

    def __init__(self) -> None:
        self._items: list[Intention] = []
        self._lock = threading.RLock()
        self._counter = 0

    def next_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"I{self._counter}"

    def push(self, intention: Intention) -> None:
        with self._lock:
            if any(i.live and i.desire_id == intention.desire_id for i in self._items):
                raise IntentionError(f"desire {intention.desire_id} already has a live intention")
            self._items.append(intention)

    def live(self) -> list[Intention]:
        with self._lock:
            items = [i for i in self._items if i.live]
        order = {id(i): n for n, i in enumerate(items)}
        return sorted(items, key=lambda i: (-i.priority, -order[id(i)]))

    def active(self) -> list[Intention]:
        return [i for i in self.live() if i.status == IntentionStatus.ACTIVE]

    def for_desire(self, desire_id: str) -> Intention | None:
        return next((i for i in self.live() if i.desire_id == desire_id), None)

    def top(self) -> Intention | None:
        """The ACTIVE intention that runs next (highest desire priority)."""
        active = self.active()
        return active[0] if active else None

    def all(self) -> list[Intention]:
        with self._lock:
            return list(self._items)

    def get(self, intention_id: str) -> Intention | None:
        with self._lock:
            return next((i for i in self._items if i.id == intention_id), None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)
