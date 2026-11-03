"""Constrained utility evaluator and deterministic offer selection."""
from __future__ import annotations

from typing import Any, Iterable, Sequence

from pydantic import ValidationError

from .models import (
    EvaluationStatus, Offer, OfferEvaluation, OptimizationConstraints,
    OptimizationResult, ScoreBreakdown, option_label,
)


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def score_offer(offer: Offer, constraints: OptimizationConstraints) -> ScoreBreakdown:
    """Score one valid offer on five normalized 0..100 dimensions.

    A caller may inspect scores for infeasible offers, but infeasible candidates
    are never eligible to win. A score is not a substitute for hard constraints.
    """
    w = constraints.weights
    quality = _clamp((offer.quality_rating / 5.0) * 100.0)
    cost = _clamp((1.0 - offer.landed_cost / constraints.max_landed_cost_per_unit) * 100.0)
    if constraints.max_delivery_days == 1:
        delivery = 100.0 if offer.delivery_days <= 1 else 0.0
    else:
        delivery = _clamp(
            (constraints.max_delivery_days - offer.delivery_days)
            / (constraints.max_delivery_days - 1)
            * 100.0
        )
    reliability = _clamp(offer.reliability_pct)
    returns = _clamp(
        (1.0 - offer.return_rate_pct / constraints.return_rate_score_ceiling_pct) * 100.0
    )
    weighted_quality = w.quality * quality
    weighted_cost = w.cost * cost
    weighted_delivery = w.delivery * delivery
    weighted_reliability = w.reliability * reliability
    weighted_returns = w.returns * returns
    utility = _clamp(sum((weighted_quality, weighted_cost, weighted_delivery,
                         weighted_reliability, weighted_returns)))
    return ScoreBreakdown(
        quality_score=round(quality, 4), cost_score=round(cost, 4),
        delivery_score=round(delivery, 4), reliability_score=round(reliability, 4),
        returns_score=round(returns, 4), weighted_quality=round(weighted_quality, 4),
        weighted_cost=round(weighted_cost, 4), weighted_delivery=round(weighted_delivery, 4),
        weighted_reliability=round(weighted_reliability, 4), weighted_returns=round(weighted_returns, 4),
        total_utility=utility,
    )


def compute_score(offer: Offer | dict[str, Any], constraints: OptimizationConstraints | None = None) -> float:
    """Return the utility score for one validated offer."""
    parsed = offer if isinstance(offer, Offer) else Offer.model_validate(offer)
    return score_offer(parsed, constraints or OptimizationConstraints()).total_utility


def _constraint_reasons(offer: Offer, c: OptimizationConstraints) -> list[str]:
    reasons: list[str] = []
    if not offer.active:
        reasons.append("INACTIVE: seller offer is not active")
    # Tiny tolerance avoids floating-point noise for a cost that is mathematically on the boundary.
    if offer.landed_cost > c.max_landed_cost_per_unit + 1e-9:
        reasons.append(f"OVER_BUDGET: landed cost {offer.landed_cost:.2f} exceeds {c.max_landed_cost_per_unit:.2f}")
    if offer.quality_rating < c.min_quality_rating:
        reasons.append(f"QUALITY_BELOW_MINIMUM: {offer.quality_rating:.2f} < {c.min_quality_rating:.2f}")
    if offer.delivery_days > c.max_delivery_days:
        reasons.append(f"DELIVERY_TOO_SLOW: {offer.delivery_days} > {c.max_delivery_days} days")
    if offer.reliability_pct < c.min_reliability_pct:
        reasons.append(f"RELIABILITY_BELOW_MINIMUM: {offer.reliability_pct:.2f}% < {c.min_reliability_pct:.2f}%")
    if offer.return_rate_pct > c.max_return_rate_pct:
        reasons.append(f"RETURN_RATE_ABOVE_MAX: {offer.return_rate_pct:.2f}% > {c.max_return_rate_pct:.2f}%")
    if offer.available_units < c.required_quantity:
        reasons.append(f"INSUFFICIENT_STOCK: {offer.available_units} < required {c.required_quantity} units")
    if not offer.supports_destination:
        reasons.append("REGION_UNSUPPORTED: seller does not serve the destination")
    return reasons


def _tie_key(offer: Offer, utility: float) -> tuple[float, float, int, str]:
    """Lower tuple wins: utility desc, cost asc, delivery days asc, ID asc."""
    return (-utility, offer.landed_cost, offer.delivery_days, offer.option_id.casefold())


def optimize_offers(
    offer_inputs: Iterable[Offer | dict[str, Any]],
    constraints: OptimizationConstraints | None = None,
    *,
    verify: bool = True,
) -> OptimizationResult:
    """Evaluate offers robustly and select the highest-utility feasible option.

    Invalid raw records are isolated as INVALID_DATA rather than crashing all
    evaluations. Duplicate IDs are excluded because accepting either occurrence
    would make the selection ambiguous. Invalid global constraints fail fast at
    model construction. Empty and no-feasible inputs have explicit outcomes.
    """
    c = constraints or OptimizationConstraints()
    raw_options = list(offer_inputs)
    if not raw_options:
        return OptimizationResult(status="NO_OPTIONS", evaluated_count=0, valid_count=0,
                                  feasible_count=0, rejected_count=0,
                                  notes=["No offer records were supplied."])

    parsed: list[tuple[int, Offer]] = []
    evaluation_by_ordinal: dict[int, OfferEvaluation] = {}
    for ordinal, raw in enumerate(raw_options, start=1):
        option_id, seller = option_label(raw, ordinal)
        try:
            offer = raw if isinstance(raw, Offer) else Offer.model_validate(raw)
        except (ValidationError, TypeError, ValueError) as exc:
            if isinstance(exc, ValidationError):
                fields = sorted({".".join(str(x) for x in error["loc"]) or "record" for error in exc.errors()})
                reason = "Invalid fields: " + ", ".join(fields[:8])
            else:
                reason = "Record must be an Offer or a mapping of Offer fields"
            evaluation_by_ordinal[ordinal] = OfferEvaluation(
                option_id=option_id, seller=seller, status=EvaluationStatus.INVALID_DATA,
                reasons=["INVALID_DATA: " + reason], input_errors=[reason],
            )
        else:
            parsed.append((ordinal, offer))

    # A duplicate ID is a data-integrity failure: mark every occurrence invalid.
    id_counts: dict[str, int] = {}
    for _, offer in parsed:
        id_counts[offer.option_id] = id_counts.get(offer.option_id, 0) + 1
    duplicate_ids = {k for k, count in id_counts.items() if count > 1}
    unique_parsed: list[tuple[int, Offer]] = []
    for ordinal, offer in parsed:
        if offer.option_id in duplicate_ids:
            evaluation_by_ordinal[ordinal] = OfferEvaluation(
                option_id=offer.option_id, seller=offer.seller, status=EvaluationStatus.INVALID_DATA,
                landed_cost=round(offer.landed_cost, 4),
                reasons=["INVALID_DATA: duplicate option_id makes selection ambiguous"],
                input_errors=["duplicate option_id"],
            )
        else:
            unique_parsed.append((ordinal, offer))

    valid_count = len(unique_parsed)
    feasible_entries: list[tuple[int, Offer, OfferEvaluation]] = []
    winner: tuple[int, Offer, OfferEvaluation] | None = None

    # O(n) selection: maintain the incumbent as each feasible candidate is evaluated.
    for ordinal, offer in unique_parsed:
        breakdown = score_offer(offer, c)
        reasons = _constraint_reasons(offer, c)
        status = EvaluationStatus.INFEASIBLE if reasons else EvaluationStatus.FEASIBLE
        evaluation = OfferEvaluation(
            option_id=offer.option_id, seller=offer.seller, status=status,
            landed_cost=round(offer.landed_cost, 4), utility=breakdown.total_utility,
            breakdown=breakdown, reasons=reasons,
        )
        evaluation_by_ordinal[ordinal] = evaluation
        if status != EvaluationStatus.FEASIBLE:
            continue
        entry = (ordinal, offer, evaluation)
        feasible_entries.append(entry)
        if winner is None or _tie_key(offer, breakdown.total_utility) < _tie_key(
            winner[1], winner[2].utility if winner[2].utility is not None else 0.0
        ):
            winner = entry

    evaluations = [evaluation_by_ordinal[i] for i in range(1, len(raw_options) + 1)]
    ranking_entries = sorted(feasible_entries, key=lambda x: _tie_key(x[1], x[2].utility or 0.0))
    ranking = [evaluation.option_id for _, _, evaluation in ranking_entries]
    rejected_count = sum(e.status != EvaluationStatus.FEASIBLE for e in evaluations)

    if winner is None:
        return OptimizationResult(
            status="NO_FEASIBLE_OPTION", evaluated_count=len(raw_options), valid_count=valid_count,
            feasible_count=0, rejected_count=rejected_count, evaluations=evaluations,
            notes=["No offer satisfied every hard constraint; no unsafe fallback was selected."],
        )

    _, best_offer, best_eval = winner
    reference_id = None
    verified = False
    if verify:
        reference = exhaustive_reference_winner(unique_parsed, c)
        reference_id = reference.option_id if reference else None
        verified = reference_id == best_offer.option_id

    return OptimizationResult(
        status="SELECTED", selected_option_id=best_offer.option_id,
        selected_seller=best_offer.seller, selected_utility=best_eval.utility,
        selected_landed_cost=best_eval.landed_cost, evaluated_count=len(raw_options),
        valid_count=valid_count, feasible_count=len(feasible_entries), rejected_count=rejected_count,
        evaluations=evaluations, feasible_ranking=ranking,
        optimality_verified=verified, verification_winner_id=reference_id,
        notes=[
            "Hard constraints are applied before a candidate is eligible to win.",
            "The selected option maximizes the defined weighted utility among feasible offers.",
            "Tie-break order: utility descending, landed cost ascending, delivery days ascending, option ID ascending.",
        ],
    )


def exhaustive_reference_winner(
    parsed_offers: Sequence[tuple[int, Offer]] | Iterable[Offer],
    constraints: OptimizationConstraints | None = None,
) -> Offer | None:
    """Independent exhaustive reference used as an optimality oracle in tests/demo."""
    c = constraints or OptimizationConstraints()
    candidates: list[Offer] = []
    for item in parsed_offers:
        offer = item[1] if isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], Offer) else item
        if isinstance(offer, Offer) and not _constraint_reasons(offer, c):
            candidates.append(offer)
    if not candidates:
        return None
    return sorted(candidates, key=lambda offer: _tie_key(offer, score_offer(offer, c).total_utility))[0]


def verify_optimality(
    result: OptimizationResult,
    offers: Sequence[Offer | dict[str, Any]],
    constraints: OptimizationConstraints | None = None,
) -> bool:
    """Compare the selected option with a separate exhaustive feasible ranking."""
    if result.selected_option_id is None:
        return result.status in {"NO_OPTIONS", "NO_FEASIBLE_OPTION"}
    c = constraints or OptimizationConstraints()
    parsed: list[Offer] = []
    seen: set[str] = set()
    duplicates: set[str] = set()
    for raw in offers:
        try:
            offer = raw if isinstance(raw, Offer) else Offer.model_validate(raw)
        except Exception:
            continue
        if offer.option_id in seen:
            duplicates.add(offer.option_id)
        seen.add(offer.option_id)
        parsed.append(offer)
    parsed = [offer for offer in parsed if offer.option_id not in duplicates]
    oracle = exhaustive_reference_winner(parsed, c)
    return oracle is not None and oracle.option_id == result.selected_option_id
