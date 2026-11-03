"""Agent properties: the mutable, observable state that live knowledge writes into.

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

``PropertySink`` is the narrow interface the adapter depends on:

    set(key, value, source, confidence=1.0) -> bool     # True when the stored value changed
    get(key, default=None)

It is deliberately the same shape as the BDI ``BeliefBase`` of Assignment 4.1, so the
Capstone can pass a belief base where an ``AgentProperties`` is used here.

``AgentProperties`` is the built-in implementation: thread-safe, keeps a full change
history (old value, new value, source, confidence, wall-clock and monotonic time) and
notifies subscribers synchronously, so a plan can be recomputed in the same call that
changed the property ("changed instantly").
"""
from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Protocol, runtime_checkable


@runtime_checkable
class PropertySink(Protocol):
    def set(self, key: str, value: Any, source: str, confidence: float = 1.0) -> bool: ...
    def get(self, key: str, default: Any = None) -> Any: ...


@dataclass(frozen=True)
class PropertyChange:
    seq: int
    key: str
    old: Any
    new: Any
    source: str
    confidence: float
    at: str               # UTC ISO-8601 with milliseconds
    mono_ns: int          # time.perf_counter_ns() when the change was committed

    def to_dict(self) -> dict:
        return asdict(self)


Subscriber = Callable[[PropertyChange], None]


class AgentProperties:
    """Observable key/value store with provenance, change history and a confidence gate."""

    def __init__(self, initial: dict[str, Any] | None = None, min_confidence: float = 0.5,
                 source: str = "defaults"):
        if not 0.0 <= min_confidence <= 1.0:
            raise ValueError("min_confidence must be within [0, 1]")
        self.min_confidence = min_confidence
        self._lock = threading.RLock()
        self._values: dict[str, Any] = {}
        self._meta: dict[str, tuple[str, float, str]] = {}
        self._subs: list[tuple[str, Subscriber]] = []
        self.history: list[PropertyChange] = []
        self.rejected: list[dict] = []
        self._seq = 0
        for k, v in (initial or {}).items():
            self.set(k, v, source)

    # -- PropertySink -----------------------------------------------------------
    def set(self, key: str, value: Any, source: str, confidence: float = 1.0) -> bool:
        if not isinstance(key, str) or not key:
            raise ValueError("property key must be a non-empty string")
        if not 0.0 <= float(confidence) <= 1.0:
            raise ValueError("confidence must be within [0, 1]")
        value = _freeze(value)
        with self._lock:
            if confidence < self.min_confidence:
                self.rejected.append({"key": key, "value": value, "source": source, "confidence": confidence,
                                      "reason": f"confidence {confidence:.2f} < {self.min_confidence:.2f}"})
                return False
            old = self._values.get(key, _MISSING)
            if old is not _MISSING and old == value:
                self._meta[key] = (source, confidence, _now())     # refresh provenance only
                return False
            self._seq += 1
            change = PropertyChange(seq=self._seq, key=key, old=None if old is _MISSING else old, new=value,
                                    source=source, confidence=round(float(confidence), 4), at=_now(),
                                    mono_ns=time.perf_counter_ns())
            self._values[key] = value
            self._meta[key] = (source, confidence, change.at)
            self.history.append(change)
            subs = [fn for prefix, fn in self._subs if key.startswith(prefix)]
        for fn in subs:            # notify outside the lock; subscribers may read properties
            fn(change)
        return True

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._values.get(key, default)

    # -- extras -----------------------------------------------------------------
    def subscribe(self, fn: Subscriber, prefix: str = "") -> Callable[[], None]:
        entry = (prefix, fn)
        with self._lock:
            self._subs.append(entry)

        def unsubscribe() -> None:
            with self._lock:
                if entry in self._subs:
                    self._subs.remove(entry)
        return unsubscribe

    def source_of(self, key: str) -> tuple[str, float, str] | None:
        with self._lock:
            return self._meta.get(key)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {k: _thaw(v) for k, v in sorted(self._values.items())}

    def changes_since(self, seq: int) -> list[PropertyChange]:
        with self._lock:
            return [c for c in self.history if c.seq > seq]

    @property
    def seq(self) -> int:
        return self._seq


class _Missing:
    pass


_MISSING = _Missing()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _freeze(v: Any) -> Any:
    """Store lists as tuples so stored values cannot be mutated behind the history's back."""
    if isinstance(v, list):
        return tuple(_freeze(x) for x in v)
    if isinstance(v, dict):
        return tuple(sorted((k, _freeze(x)) for k, x in v.items()))
    return v


def _thaw(v: Any) -> Any:
    if isinstance(v, tuple):
        return [_thaw(x) for x in v]
    return v
