"""Desires: CipherMesh's top-level strategic goals (the "D" of BDI).

Author : Kumar Waibhav Akshat (RA2212704010027)
Course : 21CSE525T Agent Technology, Assignment 4.1 (BDI Goal-Driven Modeling)

A desire is a state of the world the agent wants. It is *active* when the
situation makes it relevant and it is an *option* when it is active but not
yet satisfied. Only options can receive intentions.

Two kinds are used:

* ``achieve`` desires get intentions (a plan is executed to reach them).
* ``maintain`` desires never get an intention of their own; while active they
  constrain the plans chosen for lower-priority desires (for example D2 limits
  every dispatch to Indian or local providers).

Priority orders the desires (higher wins). ``conflicts_with`` lists desires
that cannot be pursued at the same time; when both are options, the
lower-priority one is pre-empted and any intention it holds is dropped.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from . import world

Predicate = Callable[[Any], bool]


@dataclass(frozen=True)
class Desire:
    id: str
    description: str
    priority: int
    active_when: Predicate
    satisfied_when: Predicate
    kind: str = "achieve"                       # "achieve" | "maintain"
    conflicts_with: frozenset[str] = frozenset()
    reads: frozenset[str] = frozenset()         # belief keys/patterns the predicates read
    constrains: str = ""                        # human description of the constraint (maintain)

    def __post_init__(self) -> None:
        if self.kind not in {"achieve", "maintain"}:
            raise ValueError("desire kind must be 'achieve' or 'maintain'")
        if not 0 <= self.priority <= 1000:
            raise ValueError("priority must be within [0, 1000]")

    def is_active(self, beliefs: Any) -> bool:
        return bool(self.active_when(beliefs))

    def is_satisfied(self, beliefs: Any) -> bool:
        return bool(self.satisfied_when(beliefs))

    def is_option(self, beliefs: Any) -> bool:
        return self.is_active(beliefs) and not self.is_satisfied(beliefs)

    def conflicts(self, other: "Desire") -> bool:
        return other.id in self.conflicts_with or self.id in other.conflicts_with


@dataclass
class Deliberation:
    """Result of filtering the options: which desires to pursue and which are pre-empted."""
    options: list[Desire] = field(default_factory=list)
    selected: list[Desire] = field(default_factory=list)
    preempted: dict[str, str] = field(default_factory=dict)     # desire id -> pre-empting desire id
    constraints: list[Desire] = field(default_factory=list)     # active maintain desires

    def selected_ids(self) -> list[str]:
        return [d.id for d in self.selected]


class DesireSet:
    """Ordered collection of desires with option generation and conflict filtering."""

    def __init__(self, desires: Iterable[Desire] = ()) -> None:
        self._desires: dict[str, Desire] = {}
        for desire in desires:
            self.add(desire)

    def add(self, desire: Desire) -> None:
        if desire.id in self._desires:
            raise ValueError(f"duplicate desire id {desire.id}")
        self._desires[desire.id] = desire

    def get(self, desire_id: str) -> Desire:
        return self._desires[desire_id]

    def __contains__(self, desire_id: str) -> bool:
        return desire_id in self._desires

    def __iter__(self):
        return iter(self.ordered())

    def __len__(self) -> int:
        return len(self._desires)

    def ordered(self) -> list[Desire]:
        """Highest priority first; ties broken by id for determinism."""
        return sorted(self._desires.values(), key=lambda d: (-d.priority, d.id))

    def active(self, beliefs: Any) -> list[Desire]:
        return [d for d in self.ordered() if d.is_active(beliefs)]

    def options(self, beliefs: Any) -> list[Desire]:
        return [d for d in self.ordered() if d.is_option(beliefs)]

    def deliberate(self, beliefs: Any) -> Deliberation:
        """Filter options by priority and conflicts (Bratman's filtering step)."""
        result = Deliberation(options=self.options(beliefs))
        result.constraints = [d for d in self.active(beliefs) if d.kind == "maintain"]
        for desire in result.options:
            blocker = next((s for s in result.selected if s.conflicts(desire)), None)
            if blocker is not None:
                result.preempted[desire.id] = blocker.id
                continue
            if desire.kind == "achieve":
                result.selected.append(desire)
        return result

    def constraining(self, desire: Desire, beliefs: Any) -> list[Desire]:
        """Active maintain desires with higher priority than ``desire``."""
        return [d for d in self.active(beliefs) if d.kind == "maintain" and d.priority > desire.priority]


# ---------------------------------------------------------------------------- CipherMesh desires
def _d1_active(b: Any) -> bool:
    return world.request_pending(b) and (world.prompt_has_secret(b) or world.lockdown(b)
                                         or world.response_has_secret(b))


def _d5_active(b: Any) -> bool:
    return world.request_pending(b) and b.get("prompt.decision") == "REVIEW"


def ciphermesh_desires() -> DesireSet:
    """The five CipherMesh desires D1..D5 (higher priority constrains lower)."""
    return DesireSet([
        Desire(
            id="D1", description="Never transmit a secret", priority=100, kind="achieve",
            active_when=_d1_active,
            satisfied_when=lambda b: bool(b.get("guard.secret_contained", False)),
            conflicts_with=frozenset({"D3", "D4"}),
            reads=frozenset({"request.status", "prompt.categories", "policy.lockdown",
                             "response.findings", "guard.secret_contained"}),
            constrains="no dispatch or delivery while a secret risk is believed"),
        Desire(
            id="D2", description="Keep Indian personal data in India", priority=90, kind="maintain",
            active_when=lambda b: world.india_personal_data(b),
            satisfied_when=lambda b: int(b.get("dispatch.residency_violations", 0)) == 0,
            reads=frozenset({"prompt.categories", "provider.*.residency",
                             "dispatch.residency_violations"}),
            constrains="dispatch only to providers with residency IN or LOCAL"),
        Desire(
            id="D3", description="Deliver a useful answer to the user", priority=60, kind="achieve",
            active_when=world.request_pending,
            satisfied_when=lambda b: bool(b.get("response.delivered", False)),
            reads=frozenset({"request.status", "response.delivered"})),
        Desire(
            id="D4", description="Lowest cost within quality bounds", priority=40, kind="maintain",
            active_when=lambda b: world.request_pending(b) and b.has("budget.max_cost_per_1k"),
            satisfied_when=lambda b: float(b.get("dispatch.effective_cost", 0.0)) <= world.budget(b) + 1e-9,
            reads=frozenset({"budget.max_cost_per_1k", "provider.*.price_per_1k"}),
            constrains="effective price per 1k requests must not exceed budget.max_cost_per_1k"),
        Desire(
            id="D5", description="Keep the human-review backlog under its limit", priority=30,
            kind="achieve", active_when=_d5_active,
            satisfied_when=lambda b: world.review_capacity(b) or b.get("request.status") == "DEFERRED",
            reads=frozenset({"prompt.decision", "review.queue_depth", "review.limit"}),
            constrains="hold_for_review is applicable only while the backlog has capacity"),
    ])
