"""Posture rule and threshold calibration on the pinned one-year KEV catalog.

Author: Kumar Waibhav Akshat (RA2212704010027)
"""
from pathlib import Path

import pytest

from ciphermesh.knowledge.calibration import calibrate, exceedance_threshold, kev_series, simulate
from ciphermesh.knowledge.feeds import CisaKevConnector
from ciphermesh.knowledge.posture import PostureSpec, attribution, decide, specs_from_graph

KEV = Path(__file__).resolve().parents[2] / "data" / "replay" / "cisa_kev.derived.json"


@pytest.fixture(scope="module")
def series():
    from ciphermesh.knowledge import load_graph
    return kev_series(CisaKevConnector(load_graph()), KEV.read_bytes())


def test_ontology_thresholds_equal_backtest_calibration(graph, series):
    cal = calibrate(series)
    stored = {s.label: s.thresholds for s in specs_from_graph(graph) if s.level}
    for label in ("ELEVATED", "HIGH"):
        for attr, value in cal[label].items():
            assert stored[label][attr] == value, (label, attr)
    for k, ex in cal["exceedance"].items():
        assert ex["elevated"] <= 0.10 and ex["high"] <= 0.03, k


def test_calibrated_posture_shares_are_bounded(graph, series):
    specs = specs_from_graph(graph)
    hyst = float(graph.value("cm:agent/ciphermesh", "cm:hysteresisFactor"))
    after = simulate(series, specs, hyst)
    assert len(series) == 122
    assert after["share"]["HIGH"] <= 0.03 and after["share"]["ELEVATED"] <= 0.35
    assert after["share"]["LOW"] >= 0.6


def test_exceedance_threshold_counts_ties():
    vals = [1, 1, 2, 2, 2, 2, 2, 2, 2, 3]
    assert exceedance_threshold(vals, 0.10, integer=True) == 3.0
    t = exceedance_threshold([1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9], 0.10, integer=False)
    assert t == 1.81 and sum(v >= t for v in [1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9]) == 1


def test_high_needs_two_independent_signal_groups():
    specs = [PostureSpec("h", "HIGH", 2, 2, {"minKevRatio": 2.0, "minRelevantHits": 10, "minAiPrivacyPerDay": 1.0}),
             PostureSpec("e", "ELEVATED", 1, 1, {"minKevRatio": 1.5, "minRelevantHits": 5, "minAiPrivacyPerDay": 0.5}),
             PostureSpec("l", "LOW", 0, 0, {})]
    assert decide({"threat.kev.ratio": 3.0}, specs).label == "ELEVATED"
    assert decide({"threat.kev.ratio": 3.0, "threat.kev.relevant_hits": 11}, specs).label == "HIGH"
    assert decide({"threat.kev.ratio": 3.0, "threat.aiid.privacy_per_day": 1.2}, specs).label == "HIGH"
    assert decide({}, specs).label == "LOW"
    assert decide({"threat.kev.ratio": 1.4}, specs, current_level=1, hysteresis=0.9).label == "ELEVATED"
    assert decide({"threat.kev.ratio": 1.4}, specs, current_level=0, hysteresis=0.9).label == "LOW"
    att = attribution({"threat.kev.ratio": 1.6, "threat.aiid.privacy_per_day": 0.6}, specs)
    assert att["without cisa_kev"] == "ELEVATED" and att["without aiid_rss"] == "ELEVATED"
