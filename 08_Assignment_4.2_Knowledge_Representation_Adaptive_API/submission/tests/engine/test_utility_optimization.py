"""Tests for mathematical utility optimization and constraint resilience."""
import math
import pytest
from pydantic import ValidationError

from ciphermesh.optimization import (
    Offer, OptimizationConstraints, UtilityWeights, optimize_offers,
    score_offer, verify_optimality,
)
from ciphermesh.optimization.scenarios import OFFERS, default_constraints


def _boundary_offer(option_id="BOUNDARY-01", **overrides):
    payload = {
        "option_id": option_id, "seller": "Boundary Supplier",
        "item_price": 143.0, "shipping_per_unit": 2.0,
        "quality_rating": 4.0, "delivery_days": 5,
        "reliability_pct": 95.0, "return_rate_pct": 6.0,
        "available_units": 100, "active": True, "supports_destination": True,
    }
    payload.update(overrides)
    return payload


def test_ten_option_scenario_selects_proven_optimum():
    result = optimize_offers(OFFERS, default_constraints())
    assert result.evaluated_count == 10
    assert result.valid_count == 10
    assert result.feasible_count == 6
    assert result.rejected_count == 4
    assert result.selected_option_id == "ECO-08"
    assert result.selected_seller == "NorthPeak"
    assert result.selected_landed_cost == 131.0
    assert result.selected_utility == pytest.approx(71.2388)
    assert result.optimality_verified is True
    assert result.verification_winner_id == "ECO-08"
    assert verify_optimality(result, OFFERS, default_constraints())


def test_highest_raw_utility_can_be_rejected_by_hard_constraint():
    result = optimize_offers(OFFERS, default_constraints())
    swift = result.evaluation_for("ECO-04")
    assert swift.utility is not None and swift.utility > result.selected_utility
    assert swift.status.value == "INFEASIBLE"
    assert any("INSUFFICIENT_STOCK" in reason for reason in swift.reasons)
    assert result.selected_option_id != "ECO-04"


def test_utility_equation_components_and_weights_are_applied():
    c = default_constraints()
    offer = next(o for o in OFFERS if o.option_id == "ECO-08")
    b = score_offer(offer, c)
    assert b.quality_score == pytest.approx(94.0)
    assert b.cost_score == pytest.approx((1 - 131 / 145) * 100, abs=0.0001)
    assert b.delivery_score == 100.0
    assert b.reliability_score == 97.5
    assert b.returns_score == 60.0
    expected = 0.30 * b.quality_score + 0.25 * b.cost_score + 0.20 * b.delivery_score + 0.15 * b.reliability_score + 0.10 * b.returns_score
    assert b.total_utility == pytest.approx(expected, abs=0.0001)


def test_exact_constraint_boundaries_are_feasible():
    result = optimize_offers([_boundary_offer()])
    assert result.status == "SELECTED"
    assert result.selected_option_id == "BOUNDARY-01"
    ev = result.evaluation_for("BOUNDARY-01")
    assert ev.status.value == "FEASIBLE"
    assert ev.landed_cost == 145.0


@pytest.mark.parametrize("override,needle", [
    ({"item_price": 143.01}, "OVER_BUDGET"),
    ({"quality_rating": 3.99}, "QUALITY_BELOW_MINIMUM"),
    ({"delivery_days": 6}, "DELIVERY_TOO_SLOW"),
    ({"reliability_pct": 94.99}, "RELIABILITY_BELOW_MINIMUM"),
    ({"return_rate_pct": 6.01}, "RETURN_RATE_ABOVE_MAX"),
    ({"available_units": 99}, "INSUFFICIENT_STOCK"),
    ({"active": False}, "INACTIVE"),
    ({"supports_destination": False}, "REGION_UNSUPPORTED"),
])
def test_one_step_past_each_constraint_is_rejected(override, needle):
    payload = _boundary_offer(**override)
    result = optimize_offers([payload])
    assert result.status == "NO_FEASIBLE_OPTION"
    assert result.selected_option_id is None
    assert any(needle in reason for reason in result.evaluation_for("BOUNDARY-01").reasons)


def test_malformed_record_is_isolated_and_other_options_still_compete():
    bad = _boundary_offer("BAD-OFFER", item_price=float("nan"))
    result = optimize_offers([_boundary_offer("VALID-A"), bad, _boundary_offer("VALID-B", item_price=140, shipping_per_unit=1)])
    assert result.evaluated_count == 3
    assert result.evaluation_for("BAD-OFFER").status.value == "INVALID_DATA"
    assert result.evaluation_for("VALID-A").status.value == "FEASIBLE"
    assert result.evaluation_for("VALID-B").status.value == "FEASIBLE"
    assert result.selected_option_id in {"VALID-A", "VALID-B"}


def test_duplicate_ids_are_all_marked_invalid_not_arbitrarily_chosen():
    a = _boundary_offer("DUPLICATE", item_price=100, shipping_per_unit=5)
    b = _boundary_offer("DUPLICATE", item_price=120, shipping_per_unit=5)
    result = optimize_offers([a, b])
    assert result.status == "NO_FEASIBLE_OPTION"
    assert result.valid_count == 0
    assert all(ev.status.value == "INVALID_DATA" for ev in result.evaluations)


def test_empty_list_returns_explicit_status():
    result = optimize_offers([])
    assert result.status == "NO_OPTIONS"
    assert result.selected_option_id is None
    assert result.evaluated_count == 0


def test_no_feasible_option_does_not_relax_constraints():
    result = optimize_offers([_boundary_offer("TOO-EXPENSIVE", item_price=999)])
    assert result.status == "NO_FEASIBLE_OPTION"
    assert result.selected_option_id is None
    assert "no unsafe fallback" in result.notes[0]


def test_invalid_weights_are_rejected():
    with pytest.raises(ValidationError):
        UtilityWeights(quality=0.5, cost=0.5, delivery=0.5, reliability=0.0, returns=0.0)


def test_invalid_constraints_are_rejected():
    with pytest.raises(ValidationError):
        OptimizationConstraints(max_landed_cost_per_unit=0)
    with pytest.raises(ValidationError):
        OptimizationConstraints(max_return_rate_pct=15, return_rate_score_ceiling_pct=10)


def test_negative_values_and_non_finite_numbers_do_not_enter_evaluator():
    for payload in (
        _boundary_offer("NEG", item_price=-0.01),
        _boundary_offer("INF", shipping_per_unit=float("inf")),
        _boundary_offer("NAN", reliability_pct=float("nan")),
        _boundary_offer("BAD-RATING", quality_rating=5.01),
    ):
        result = optimize_offers([payload])
        assert result.status == "NO_FEASIBLE_OPTION"
        assert result.evaluation_for(payload["option_id"]).status.value == "INVALID_DATA"


def test_tie_break_is_deterministic_by_landed_cost_then_delivery_then_id():
    a = _boundary_offer("TIE-B", item_price=100, shipping_per_unit=5, delivery_days=2)
    b = _boundary_offer("TIE-A", item_price=100, shipping_per_unit=5, delivery_days=2)
    result = optimize_offers([a, b])
    assert result.selected_option_id == "TIE-A"


def test_single_day_delivery_boundary_does_not_divide_by_zero():
    constraints = OptimizationConstraints(max_delivery_days=1)
    offer = Offer(**_boundary_offer("ONE-DAY", item_price=100, shipping_per_unit=20,
                                    delivery_days=1, available_units=100))
    breakdown = score_offer(offer, constraints)
    assert breakdown.delivery_score == 100.0
    assert math.isfinite(breakdown.total_utility)


def test_ranking_is_descending_by_utility_and_excludes_infeasible_ids():
    result = optimize_offers(OFFERS)
    utilities = [result.evaluation_for(oid).utility for oid in result.feasible_ranking]
    assert utilities == sorted(utilities, reverse=True)
    for excluded in ("ECO-03", "ECO-04", "ECO-06", "ECO-07"):
        assert excluded not in result.feasible_ranking
