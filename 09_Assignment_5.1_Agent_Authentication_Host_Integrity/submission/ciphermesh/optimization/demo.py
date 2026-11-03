"""Execute the ten-option e-commerce utility optimization demonstration."""
from __future__ import annotations
import argparse
import csv
from pathlib import Path

from .engine import optimize_offers, verify_optimality
from .models import OptimizationConstraints
from .scenarios import OFFERS, default_constraints


def fmt_money(value: float | None) -> str:
    return "--" if value is None else f"${value:,.2f}"


def _row_reasons(evaluation) -> str:
    return "; ".join(evaluation.reasons) if evaluation.reasons else "All hard constraints passed"


def render_terminal_table(result, constraints: OptimizationConstraints) -> str:
    lines = [
        "CIPHERMESH | SELF-INTERESTED E-COMMERCE UTILITY OPTIMIZATION",
        "=" * 112,
        "Scenario: choose a supplier for a 100-unit order; illustrative values, deterministic run.",
        f"Constraints: landed <= {fmt_money(constraints.max_landed_cost_per_unit)} | "
        f"quality >= {constraints.min_quality_rating:.1f}/5 | delivery <= {constraints.max_delivery_days}d | "
        f"reliability >= {constraints.min_reliability_pct:.1f}% | return rate <= {constraints.max_return_rate_pct:.1f}% | "
        f"quantity = {constraints.required_quantity}",
        "Weights: quality 0.30 | cost 0.25 | delivery 0.20 | reliability 0.15 | return-rate score 0.10",
        "-" * 112,
        f"{'OPTION':<9} {'SELLER':<18} {'LANDED':>10} {'UTILITY':>9} {'STATUS':<12} REASON / ELIGIBILITY",
        "-" * 112,
    ]
    for e in result.evaluations:
        reason = _row_reasons(e)
        if len(reason) > 67:
            reason = reason[:64] + "..."
        lines.append(
            f"{e.option_id:<9} {e.seller[:17]:<18} {fmt_money(e.landed_cost):>10} "
            f"{(f'{e.utility:.2f}' if e.utility is not None else '--'):>9} {e.status.value:<12} {reason}"
        )
    lines.extend([
        "-" * 112,
        f"EVALUATED={result.evaluated_count} | VALID={result.valid_count} | "
        f"FEASIBLE={result.feasible_count} | REJECTED={result.rejected_count}",
        f"FEASIBLE RANKING: {' > '.join(result.feasible_ranking) if result.feasible_ranking else '(none)'}",
    ])
    if result.selected_option_id:
        selected = result.evaluation_for(result.selected_option_id)
        lines.extend([
            "",
            "OPTIMIZER DECISION",
            f"  Selected seller  : {result.selected_seller} ({result.selected_option_id})",
            f"  Landed unit cost : {fmt_money(result.selected_landed_cost)}",
            f"  Utility score    : {result.selected_utility:.4f} / 100",
            f"  Component scores : quality={selected.breakdown.quality_score:.2f}; "
            f"cost={selected.breakdown.cost_score:.2f}; delivery={selected.breakdown.delivery_score:.2f}; "
            f"reliability={selected.breakdown.reliability_score:.2f}; returns={selected.breakdown.returns_score:.2f}",
            f"  Oracle comparison: {'PASS' if result.optimality_verified and verify_optimality(result, OFFERS, constraints) else 'FAIL'} "
            f"(single-pass winner={result.selected_option_id}; exhaustive reference={result.verification_winner_id})",
        ])
    else:
        lines.extend(["", "OPTIMIZER DECISION", "  No feasible option. The agent does not relax constraints silently."])
    lines.extend([
        "",
        f"Algorithm: {result.algorithm}",
        f"Complexity: {result.complexity}",
        "Safety property: infeasible options are never eligible to win, even if their utility is high.",
    ])
    return "\n".join(lines)


def save_csv(path: Path, result) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["option_id", "seller", "status", "landed_cost", "utility", "quality_score",
              "cost_score", "delivery_score", "reliability_score", "returns_score", "reasons"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for e in result.evaluations:
            b = e.breakdown
            writer.writerow({
                "option_id": e.option_id, "seller": e.seller, "status": e.status.value,
                "landed_cost": e.landed_cost, "utility": e.utility,
                "quality_score": b.quality_score if b else None,
                "cost_score": b.cost_score if b else None,
                "delivery_score": b.delivery_score if b else None,
                "reliability_score": b.reliability_score if b else None,
                "returns_score": b.returns_score if b else None,
                "reasons": " | ".join(e.reasons),
            })


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="CipherMesh e-commerce utility optimization demo")
    parser.add_argument("--budget", type=float, default=145.0, help="Maximum landed cost per unit")
    parser.add_argument("--quantity", type=int, default=100, help="Required quantity")
    parser.add_argument("--max-delivery-days", type=int, default=5)
    parser.add_argument("--min-quality", type=float, default=4.0)
    parser.add_argument("--min-reliability", type=float, default=95.0)
    parser.add_argument("--max-return-rate", type=float, default=6.0)
    parser.add_argument("--json-out", type=Path, help="Write a JSON evidence artifact")
    parser.add_argument("--csv-out", type=Path, help="Write a CSV ranking/evaluation table")
    args = parser.parse_args(argv)

    base = default_constraints()
    constraints = OptimizationConstraints(
        max_landed_cost_per_unit=args.budget,
        required_quantity=args.quantity,
        min_quality_rating=args.min_quality,
        max_delivery_days=args.max_delivery_days,
        min_reliability_pct=args.min_reliability,
        max_return_rate_pct=args.max_return_rate,
        return_rate_score_ceiling_pct=max(10.0, args.max_return_rate),
        weights=base.weights,
    )
    result = optimize_offers(OFFERS, constraints)
    print(render_terminal_table(result, constraints))
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        print(f"\nJSON evidence written to {args.json_out}")
    if args.csv_out:
        save_csv(args.csv_out, result)
        print(f"CSV evidence written to {args.csv_out}")


if __name__ == "__main__":
    main()
