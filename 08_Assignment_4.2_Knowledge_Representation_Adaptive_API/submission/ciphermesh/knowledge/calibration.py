"""One-year backtest of the CISA KEV posture signals and threshold calibration.

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

Method
------
1. Evaluate the KEV parser on the pinned catalog every ``step_days`` (3) from
   2025-11-01 to 2026-10-31 (122 evaluation dates), using its ``as_of`` time travel,
   so each date only sees entries that had been added by then.
2. For each signal choose the smallest threshold that is reached on at most 10 % of the
   dates (ELEVATED, about the 90th percentile) and at most 3 % (HIGH, about the 97th
   percentile). Ties of integer counts are counted honestly, so a count that is often
   equal to the percentile gets the next integer.
3. Simulate the posture rule over the same dates, in order, with hysteresis, and report
   how often each posture would have been active.

The AI Incident Database feed only exposes its newest items, so it cannot be backtested;
its threshold is a stated judgement value and it can only contribute one signal group.
"""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

from .feeds.cisa_kev import CisaKevConnector
from .posture import PostureSpec, decide

START = datetime(2025, 11, 1, 12, tzinfo=timezone.utc)
END = datetime(2026, 10, 31, 12, tzinfo=timezone.utc)
KEYS = {"ratio": "threat.kev.ratio", "relevant_hits": "threat.kev.relevant_hits",
        "ai_ml_hits": "threat.kev.ai_ml_hits", "ransomware_hits": "threat.kev.ransomware_hits"}
ATTR = {"ratio": "minKevRatio", "relevant_hits": "minRelevantHits", "ai_ml_hits": "minAiMlHits",
        "ransomware_hits": "minRansomwareHits"}


def kev_series(connector: CisaKevConnector, body: bytes, start: datetime = START, end: datetime = END,
               step_days: int = 3) -> list[dict]:
    rows, d = [], start
    while d <= end:
        s = connector.parse(body, "backtest", d).signals
        rows.append({"date": d.date().isoformat(), **{k: s[k] for k in KEYS}})
        d += timedelta(days=step_days)
    return rows


def percentile(values: list[float], q: float) -> float:
    v = sorted(values)
    k = (len(v) - 1) * q
    f = int(k)
    return v[f] + (v[min(f + 1, len(v) - 1)] - v[f]) * (k - f)


def exceedance_threshold(values: list[float], share: float, integer: bool) -> float:
    """Smallest threshold t with P(value >= t) <= share over the backtest (ties counted honestly)."""
    n = len(values)
    if integer:
        t = 1
        while sum(v >= t for v in values) / n > share:
            t += 1
        return float(t)
    t = round(percentile(values, 1 - share), 2)
    while sum(v >= t for v in values) / n > share:
        t = round(t + 0.01, 2)
    return t


def calibrate(series: list[dict], share_elevated: float = 0.10, share_high: float = 0.03) -> dict[str, dict]:
    """Per-signal thresholds that fire on at most 10 % (ELEVATED) and 3 % (HIGH) of backtest dates."""
    out: dict[str, dict] = {"ELEVATED": {}, "HIGH": {}, "percentiles": {}, "exceedance": {}}
    for k in KEYS:
        vals = [r[k] for r in series]
        integer = k != "ratio"
        e = exceedance_threshold(vals, share_elevated, integer)
        h = max(exceedance_threshold(vals, share_high, integer), e + (1 if integer else 0.01))
        out["ELEVATED"][ATTR[k]], out["HIGH"][ATTR[k]] = e, h
        out["percentiles"][k] = {"p50": round(percentile(vals, 0.5), 3), "p90": round(percentile(vals, 0.9), 3),
                                 "p97": round(percentile(vals, 0.97), 3), "max": max(vals)}
        out["exceedance"][k] = {"elevated": round(sum(v >= e for v in vals) / len(vals), 3),
                                "high": round(sum(v >= h for v in vals) / len(vals), 3)}
    return out


def simulate(series: list[dict], specs: list[PostureSpec], hysteresis: float) -> dict:
    """Posture over the series in date order (KEV evidence only), with hysteresis."""
    level, seq, counts = 0, [], {s.label: 0 for s in specs}
    for r in series:
        decision = decide({KEYS[k]: r[k] for k in KEYS}, specs, current_level=level, hysteresis=hysteresis)
        level = decision.spec.level
        counts[decision.label] += 1
        seq.append({"date": r["date"], "posture": decision.label})
    n = len(series)
    return {"n": n, "counts": counts, "share": {k: round(v / n, 3) for k, v in counts.items()},
            "changes": sum(1 for a, b in zip(seq, seq[1:]) if a["posture"] != b["posture"]), "sequence": seq}
