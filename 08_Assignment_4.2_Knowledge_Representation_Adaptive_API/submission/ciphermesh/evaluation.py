"""Labeled evaluation of the PEAS performance measures.

Splits are reported separately on purpose:
* ``known``        - formats the agent claims to detect; target is zero critical leaks.
* ``hard_negative``- benign text that looks sensitive; measures false blocks/redactions.
* ``adversarial``  - deliberately obfuscated secrets; documents the regex baseline's
                     limits instead of hiding them inside an aggregate score.

Synthetic credential strings are assembled here at runtime so the repository never
stores literals that secret scanners (or GitHub push protection) would flag.
"""
from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from pathlib import Path

from .models import AgentState, Decision, DECISION_PRIORITY
from .policy import inspect_text

DEFAULT_CORPUS = Path(__file__).resolve().parent / "data" / "eval_corpus.jsonl"
DECISIONS = [d.value for d in Decision]


def _synthetic_values() -> dict[str, str]:
    alnum = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    return {
        "AWS_KEY": "AKIA" + "IOSFODNN7EXAMPLE",
        "AWS_SECRET": "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
        "GITHUB": "gh" + "p_" + (alnum * 2)[:36],
        "OPENAI": "sk" + "-proj-" + alnum[:28],
        "SLACK": "xo" + "xb-" + "1234567890-" + alnum[:24],
        "GOOGLE": "AI" + "za" + (alnum * 2)[:35],
        "STRIPE": "sk" + "_live_" + alnum[:24],
        "JWT": "ey" + "JhbGciOiJIUzI1NiJ9." + "ey" + "JzdWIiOiJkZW1vIn0." + "c2lnbmF0dXJlLWRlbW8tb25seQ",
        "AZURE_KEY": "AccountKey=" + ("A1b2C3d4" * 11)[:86] + "==",
        "GCP_KEY_ID": "\"private_key_id\": \"" + ("0123456789abcdef" * 3)[:40] + "\"",
        "AADHAAR": "2345 6789 0124",
        "CARD": "4111 1111 1111 1111",
        "PEM": "-----BEGIN " + "RSA PRIVATE KEY-----",
    }


def load_corpus(path: Path | str = DEFAULT_CORPUS) -> list[dict]:
    values = _synthetic_values()
    cases: list[dict] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        case = json.loads(line)
        text = case["text"]
        for key, value in values.items():
            text = text.replace("{{" + key + "}}", value)
        case["text"] = text
        if case["expected"] not in DECISIONS:
            raise ValueError(f"case {case.get('id')} has invalid expected decision")
        cases.append(case)
    return cases


def _prf(confusion: dict[str, Counter], label: str) -> dict[str, float]:
    tp = confusion[label][label]
    fp = sum(confusion[other][label] for other in DECISIONS if other != label)
    fn = sum(confusion[label][other] for other in DECISIONS if other != label)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "support": tp + fn}


def evaluate(cases: list[dict], state: AgentState | None = None) -> dict:
    state = state or AgentState(agent_id="EVAL")
    by_split: dict[str, list[dict]] = {}
    rows: list[dict] = []
    for case in cases:
        result = inspect_text(case["text"], state)
        row = {"id": case["id"], "split": case.get("split", "known"), "expected": case["expected"],
               "predicted": result.decision.value, "categories": [f.category for f in result.findings],
               "latency_ms": result.latency_ms or 0.0, "tags": case.get("tags", [])}
        rows.append(row)
        by_split.setdefault(row["split"], []).append(row)

    def summarize(items: list[dict]) -> dict:
        confusion = {label: Counter() for label in DECISIONS}
        for r in items:
            confusion[r["expected"]][r["predicted"]] += 1
        exp_block = [r for r in items if r["expected"] == "BLOCK"]
        not_block = [r for r in items if r["expected"] != "BLOCK"]
        under = [r for r in items if DECISION_PRIORITY[Decision(r["predicted"])] < DECISION_PRIORITY[Decision(r["expected"])]]
        over = [r for r in items if DECISION_PRIORITY[Decision(r["predicted"])] > DECISION_PRIORITY[Decision(r["expected"])]]
        latencies = [r["latency_ms"] for r in items]
        return {
            "cases": len(items),
            "accuracy": round(sum(r["expected"] == r["predicted"] for r in items) / len(items), 4) if items else 0.0,
            "critical_leaks": [r["id"] for r in exp_block if r["predicted"] != "BLOCK"],
            "critical_recall": round(sum(r["predicted"] == "BLOCK" for r in exp_block) / len(exp_block), 4) if exp_block else 1.0,
            "false_block_rate": round(sum(r["predicted"] == "BLOCK" for r in not_block) / len(not_block), 4) if not_block else 0.0,
            "under_protected": [r["id"] for r in under],
            "over_protected": [r["id"] for r in over],
            "per_class": {label: _prf(confusion, label) for label in DECISIONS},
            "confusion": {label: dict(confusion[label]) for label in DECISIONS},
            "latency_ms": {"mean": round(statistics.fmean(latencies), 4) if latencies else 0.0,
                           "p50": round(statistics.median(latencies), 4) if latencies else 0.0,
                           "p95": round(sorted(latencies)[max(0, round(0.95 * (len(latencies) - 1)))], 4) if latencies else 0.0},
        }

    return {"overall": summarize(rows), "splits": {name: summarize(items) for name, items in sorted(by_split.items())},
            "rows": rows}


def render(report: dict) -> str:
    lines = ["CIPHERMESH DETECTOR EVALUATION (PEAS performance measures)", "=" * 92]
    header = f"{'split':<14}{'cases':>6}{'accuracy':>10}{'crit.recall':>13}{'false-block':>13}{'leaks':>7}{'p95 ms':>9}"
    lines.append(header)
    lines.append("-" * 92)
    for name, s in [("OVERALL", report["overall"]), *report["splits"].items()]:
        lines.append(f"{name:<14}{s['cases']:>6}{s['accuracy']:>10.2%}{s['critical_recall']:>13.2%}"
                     f"{s['false_block_rate']:>13.2%}{len(s['critical_leaks']):>7}{s['latency_ms']['p95']:>9.3f}")
    lines.append("-" * 92)
    lines.append("Per-decision (overall): " + " | ".join(
        f"{k}: P={v['precision']:.2f} R={v['recall']:.2f} F1={v['f1']:.2f} n={v['support']}"
        for k, v in report["overall"]["per_class"].items()))
    for name, s in report["splits"].items():
        if s["critical_leaks"]:
            lines.append(f"Critical leaks in '{name}': {', '.join(s['critical_leaks'])}")
        if s["under_protected"]:
            lines.append(f"Under-protected in '{name}': {', '.join(s['under_protected'])}")
        if s["over_protected"]:
            lines.append(f"Over-protected in '{name}': {', '.join(s['over_protected'])}")
    known = report["splits"].get("known")
    if known is not None:
        verdict = "PASS" if not known["critical_leaks"] else "FAIL"
        lines.append(f"PEAS target 'zero critical-secret forwarding in known cases': {verdict}")
    return "\n".join(lines)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Evaluate CipherMesh detectors on a labeled corpus")
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)
    report = evaluate(load_corpus(args.corpus))
    print(render(report))
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nJSON report written to {args.json_out}")


if __name__ == "__main__":
    main()
