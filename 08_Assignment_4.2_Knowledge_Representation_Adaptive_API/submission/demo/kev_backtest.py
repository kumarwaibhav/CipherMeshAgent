"""One-year KEV backtest used to calibrate the threat-posture thresholds.

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

Reads the pinned KEV catalog (data/replay/cisa_kev.derived.json), evaluates the parser
every 3 days from 2025-11-01 to 2026-10-31, derives thresholds (calibration.calibrate),
compares them with the thresholds stored in ontology.json, and simulates the posture rule
with the previous (uncalibrated) and the current thresholds.

Usage: python demo/kev_backtest.py   -> logs/kev_backtest.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ciphermesh.knowledge import load_graph  # noqa: E402
from ciphermesh.knowledge.calibration import calibrate, kev_series, simulate  # noqa: E402
from ciphermesh.knowledge.feeds import CisaKevConnector  # noqa: E402
from ciphermesh.knowledge.posture import PostureSpec, specs_from_graph  # noqa: E402

# Thresholds used before calibration (first submission): any single threshold enters the posture.
UNCALIBRATED = [PostureSpec("cm:posture/HIGH", "HIGH", 2, 1, {"minKevRatio": 2.0, "minRelevantHits": 8,
                                                             "minAiMlHits": 2, "minRansomwareHits": 2}),
                PostureSpec("cm:posture/ELEVATED", "ELEVATED", 1, 1, {"minKevRatio": 1.25, "minRelevantHits": 3,
                                                                     "minAiMlHits": 1}),
                PostureSpec("cm:posture/LOW", "LOW", 0, 0, {})]


def main() -> int:
    graph = load_graph()
    body = (ROOT / "data" / "replay" / "cisa_kev.derived.json").read_bytes()
    series = kev_series(CisaKevConnector(graph), body)
    cal = calibrate(series)
    specs = specs_from_graph(graph)
    stored = {s.label: {k: v for k, v in s.thresholds.items() if k.startswith(("minKev", "minRel", "minAi", "minRan"))
                        and k != "minAiPrivacyPerDay"} for s in specs if s.level}
    hyst = float(graph.value("cm:agent/ciphermesh", "cm:hysteresisFactor", 1.0))
    before = simulate(series, UNCALIBRATED, 1.0)
    after = simulate(series, specs, hyst)
    out = {"dates": len(series), "from": series[0]["date"], "to": series[-1]["date"], "step_days": 3,
           "calibrated": {"ELEVATED": cal["ELEVATED"], "HIGH": cal["HIGH"]}, "ontology": stored,
           "match": stored == {"ELEVATED": cal["ELEVATED"], "HIGH": cal["HIGH"]},
           "percentiles": cal["percentiles"], "exceedance": cal["exceedance"], "hysteresis": hyst,
           "before": {k: v for k, v in before.items() if k != "sequence"},
           "after": {k: v for k, v in after.items() if k != "sequence"},
           "non_low_dates": [s for s in after["sequence"] if s["posture"] != "LOW"], "series": series}
    (ROOT / "logs" / "kev_backtest.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"{len(series)} dates {out['from']}..{out['to']}; thresholds match ontology: {out['match']}")
    print(f"uncalibrated: {before['share']} ({before['changes']} changes)")
    print(f"calibrated  : {after['share']} ({after['changes']} changes, hysteresis {hyst})")
    return 0 if out["match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
