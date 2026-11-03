"""Structured trace for the BDI deliberation cycle.

Author : Kumar Waibhav Akshat (RA2212704010027)
Course : 21CSE525T Agent Technology, Assignment 4.1 (BDI Goal-Driven Modeling)

Every event is kept twice: as a JSON object (machine-readable, written to a
JSONL file) and as one aligned human-readable line. Event types:

PERCEIVE  BELIEF  DESIRE  DELIBERATE  INTEND  STEP  RECONSIDER
SUSPEND  RESUME  DROP  REPLAN  FAIL  COMPLETE  FINISH
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVENT_TYPES = ("PERCEIVE", "BELIEF", "DESIRE", "DELIBERATE", "INTEND", "STEP", "RECONSIDER",
               "SUSPEND", "RESUME", "DROP", "REPLAN", "FAIL", "COMPLETE", "FINISH")


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


class Tracer:
    def __init__(self, run_id: str = "run") -> None:
        self.run_id = run_id
        self.events: list[dict] = []
        self.lines: list[str] = []
        self._t0 = time.perf_counter()
        self._lock = threading.Lock()

    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self._t0) * 1000.0

    def emit(self, event: str, cycle: int, message: str, **fields: Any) -> dict:
        if event not in EVENT_TYPES:
            raise ValueError(f"unknown trace event {event}")
        record = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                  "t_ms": round(self.elapsed_ms(), 3), "run": self.run_id, "cycle": cycle,
                  "event": event, "msg": message, **_json_safe(fields)}
        with self._lock:
            self.events.append(record)
            self.lines.append(self.format(record))
        return record

    @staticmethod
    def format(record: dict) -> str:
        ts = record["ts"].replace("T", " ")[:23]
        return f"{ts}  +{record['t_ms']:8.2f} ms  c{record['cycle']:02d}  {record['event']:<10} {record['msg']}"

    def write_jsonl(self, path: str | Path, append: bool = False) -> None:
        with open(path, "a" if append else "w", encoding="utf-8") as fh:
            for record in self.events:
                fh.write(json.dumps(record, sort_keys=False) + "\n")
