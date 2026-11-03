"""Beliefs: the agent's thread-safe knowledge base (the "B" of BDI).

Author : Kumar Waibhav Akshat (RA2212704010027)
Course : 21CSE525T Agent Technology, Assignment 4.1 (BDI Goal-Driven Modeling)

A belief is one fact the agent currently holds about itself or its world,
stored under a dotted key such as ``provider.gcp-vertex.status`` or
``prompt.categories``. Each belief carries the source that reported it, a
confidence in [0, 1], a timestamp and a per-key revision number.

Design rules
------------
* ``set`` returns ``True`` only when the stored *value* changes. A repeated
  report of the same value refreshes the timestamp and confidence but does not
  notify subscribers, so the deliberation cycle reacts to real change only.
* Every change (set or retract) is appended to ``history``. The history is
  append-only: callers receive a copy and cannot rewrite the past.
* Subscribers are called *after* the internal lock is released, so a callback
  may read the belief base without deadlocking. Callbacks for one change are
  delivered in subscription order; a failing callback never blocks the others.
* Values must never contain raw prompt text or secret values. CipherMesh stores
  only derived facts (categories, decisions, hashes, prices, statuses).
"""
from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from typing import Any, Callable

BeliefCallback = Callable[[str, Any, Any, str], None]


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Belief:
    """One fact held by the agent."""
    key: str
    value: Any
    source: str
    confidence: float = 1.0
    updated_at: datetime = field(default_factory=_now)
    revision: int = 1

    def as_dict(self) -> dict:
        return {"key": self.key, "value": self.value, "source": self.source,
                "confidence": self.confidence, "updated_at": self.updated_at.isoformat(),
                "revision": self.revision}


@dataclass(frozen=True)
class BeliefChange:
    """One entry of the append-only belief history."""
    seq: int
    kind: str              # "SET" or "RETRACT"
    key: str
    old_value: Any
    new_value: Any
    source: str
    confidence: float
    at: datetime

    def as_dict(self) -> dict:
        return {"seq": self.seq, "kind": self.kind, "key": self.key, "old": self.old_value,
                "new": self.new_value, "source": self.source, "confidence": self.confidence,
                "at": self.at.isoformat()}


class BeliefBase:
    """Thread-safe belief repository with change subscriptions and history."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._beliefs: dict[str, Belief] = {}
        self._history: list[BeliefChange] = []
        self._subscribers: list[BeliefCallback] = []
        self._seq = 0
        self.callback_errors: list[str] = []

    # ------------------------------------------------------------------ writes
    def set(self, key: str, value: Any, source: str, confidence: float = 1.0) -> bool:
        """Store ``value`` under ``key``. Returns True if the stored value changed."""
        self._validate(key, source, confidence)
        value = copy.deepcopy(value)
        with self._lock:
            previous = self._beliefs.get(key)
            changed = previous is None or previous.value != value
            revision = 1 if previous is None else previous.revision + (1 if changed else 0)
            self._beliefs[key] = Belief(key=key, value=value, source=source, confidence=float(confidence),
                                        updated_at=_now(), revision=revision)
            if not changed:
                return False
            old_value = None if previous is None else previous.value
            self._seq += 1
            self._history.append(BeliefChange(seq=self._seq, kind="SET", key=key, old_value=old_value,
                                              new_value=value, source=source,
                                              confidence=float(confidence), at=_now()))
            callbacks = list(self._subscribers)
        self._notify(callbacks, key, old_value, value, source)
        return True

    def retract(self, key: str, source: str) -> bool:
        """Remove a belief. Returns True if it existed."""
        self._validate(key, source, 1.0)
        with self._lock:
            previous = self._beliefs.pop(key, None)
            if previous is None:
                return False
            self._seq += 1
            self._history.append(BeliefChange(seq=self._seq, kind="RETRACT", key=key,
                                              old_value=previous.value, new_value=None, source=source,
                                              confidence=1.0, at=_now()))
            callbacks = list(self._subscribers)
        self._notify(callbacks, key, previous.value, None, source)
        return True

    # ------------------------------------------------------------------ reads
    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            belief = self._beliefs.get(key)
            return default if belief is None else copy.deepcopy(belief.value)

    def has(self, key: str) -> bool:
        with self._lock:
            return key in self._beliefs

    def belief(self, key: str) -> Belief | None:
        with self._lock:
            return self._beliefs.get(key)

    def matching(self, pattern: str) -> dict[str, Any]:
        """Return ``{key: value}`` for keys that match a shell-style pattern."""
        with self._lock:
            return {k: copy.deepcopy(b.value) for k, b in sorted(self._beliefs.items())
                    if fnmatchcase(k, pattern)}

    def snapshot(self) -> dict[str, Any]:
        """A deep copy of every current value, keyed by belief key (sorted)."""
        with self._lock:
            return {k: copy.deepcopy(b.value) for k, b in sorted(self._beliefs.items())}

    @property
    def history(self) -> list[BeliefChange]:
        """Copy of the append-only change history (oldest first)."""
        with self._lock:
            return list(self._history)

    @property
    def revision(self) -> int:
        """Global revision: number of changes applied so far."""
        with self._lock:
            return self._seq

    def __len__(self) -> int:
        with self._lock:
            return len(self._beliefs)

    # ------------------------------------------------------------------ subscriptions
    def subscribe(self, callback: BeliefCallback) -> Callable[[], None]:
        """Register ``callback(key, old_value, new_value, source)``; returns an unsubscribe function."""
        if not callable(callback):
            raise TypeError("callback must be callable")
        with self._lock:
            self._subscribers.append(callback)

        def unsubscribe() -> None:
            with self._lock:
                if callback in self._subscribers:
                    self._subscribers.remove(callback)
        return unsubscribe

    def _notify(self, callbacks: list[BeliefCallback], key: str, old: Any, new: Any, source: str) -> None:
        for callback in callbacks:
            try:
                callback(key, copy.deepcopy(old), copy.deepcopy(new), source)
            except Exception as exc:  # a faulty observer must not break belief revision
                with self._lock:
                    self.callback_errors.append(f"{key}: {type(exc).__name__}: {exc}")

    @staticmethod
    def _validate(key: str, source: str, confidence: float) -> None:
        if not isinstance(key, str) or not key or key.strip() != key or " " in key:
            raise ValueError("belief keys must be non-empty dotted strings without spaces")
        if not isinstance(source, str) or not source:
            raise ValueError("every belief needs a non-empty source")
        if not 0.0 <= float(confidence) <= 1.0:
            raise ValueError("confidence must be within [0, 1]")
