"""Validated domain models for e-commerce utility optimization.

The model fails closed: non-finite numbers, negative prices, impossible ranges,
unknown fields and invalid utility weights are rejected before scoring.
"""
from __future__ import annotations

from enum import Enum
from math import isclose
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class EvaluationStatus(str, Enum):
    FEASIBLE = "FEASIBLE"
    INFEASIBLE = "INFEASIBLE"
    INVALID_DATA = "INVALID_DATA"


class Offer(StrictModel):
    """One supplier offer; all monetary values are per item/order unit."""
    option_id: str = Field(min_length=1, max_length=40, pattern=r"^[A-Za-z0-9_-]+$")
    seller: str = Field(min_length=1, max_length=100)
    item_price: float = Field(ge=0, le=1_000_000, allow_inf_nan=False)
    shipping_per_unit: float = Field(ge=0, le=1_000_000, allow_inf_nan=False)
    quality_rating: float = Field(ge=0, le=5, allow_inf_nan=False)
    delivery_days: int = Field(ge=1, le=365)
    reliability_pct: float = Field(ge=0, le=100, allow_inf_nan=False)
    return_rate_pct: float = Field(ge=0, le=100, allow_inf_nan=False)
    available_units: int = Field(ge=0, le=10_000_000)
    active: bool = True
    supports_destination: bool = True

    @property
    def landed_cost(self) -> float:
        return self.item_price + self.shipping_per_unit


class UtilityWeights(StrictModel):
    """Weights for the 0-100 score dimensions. Weights must sum to one."""
    quality: float = Field(default=0.30, ge=0, le=1, allow_inf_nan=False)
    cost: float = Field(default=0.25, ge=0, le=1, allow_inf_nan=False)
    delivery: float = Field(default=0.20, ge=0, le=1, allow_inf_nan=False)
    reliability: float = Field(default=0.15, ge=0, le=1, allow_inf_nan=False)
    returns: float = Field(default=0.10, ge=0, le=1, allow_inf_nan=False)

    @model_validator(mode="after")
    def weights_sum_to_one(self):
        total = self.quality + self.cost + self.delivery + self.reliability + self.returns
        if not isclose(total, 1.0, rel_tol=0.0, abs_tol=1e-9):
            raise ValueError(f"utility weights must sum to 1.0, got {total:.12g}")
        return self


class OptimizationConstraints(StrictModel):
    """Hard constraints are applied before an offer is eligible to win."""
    max_landed_cost_per_unit: float = Field(default=145.0, gt=0, le=1_000_000, allow_inf_nan=False)
    required_quantity: int = Field(default=100, ge=1, le=10_000_000)
    min_quality_rating: float = Field(default=4.0, ge=0, le=5, allow_inf_nan=False)
    max_delivery_days: int = Field(default=5, ge=1, le=365)
    min_reliability_pct: float = Field(default=95.0, ge=0, le=100, allow_inf_nan=False)
    max_return_rate_pct: float = Field(default=6.0, ge=0, le=100, allow_inf_nan=False)
    return_rate_score_ceiling_pct: float = Field(default=10.0, gt=0, le=100, allow_inf_nan=False)
    weights: UtilityWeights = Field(default_factory=UtilityWeights)

    @model_validator(mode="after")
    def sensible_return_reference(self):
        if self.max_return_rate_pct > self.return_rate_score_ceiling_pct:
            raise ValueError("max_return_rate_pct cannot exceed return_rate_score_ceiling_pct")
        return self


class ScoreBreakdown(StrictModel):
    quality_score: float = Field(ge=0, le=100)
    cost_score: float = Field(ge=0, le=100)
    delivery_score: float = Field(ge=0, le=100)
    reliability_score: float = Field(ge=0, le=100)
    returns_score: float = Field(ge=0, le=100)
    weighted_quality: float = Field(ge=0, le=100)
    weighted_cost: float = Field(ge=0, le=100)
    weighted_delivery: float = Field(ge=0, le=100)
    weighted_reliability: float = Field(ge=0, le=100)
    weighted_returns: float = Field(ge=0, le=100)
    total_utility: float = Field(ge=0, le=100)


class OfferEvaluation(StrictModel):
    option_id: str
    seller: str
    status: EvaluationStatus
    landed_cost: float | None = None
    utility: float | None = None
    breakdown: ScoreBreakdown | None = None
    reasons: list[str] = Field(default_factory=list)
    input_errors: list[str] = Field(default_factory=list)


class OptimizationResult(StrictModel):
    status: str
    selected_option_id: str | None = None
    selected_seller: str | None = None
    selected_utility: float | None = None
    selected_landed_cost: float | None = None
    evaluated_count: int = Field(ge=0)
    valid_count: int = Field(ge=0)
    feasible_count: int = Field(ge=0)
    rejected_count: int = Field(ge=0)
    evaluations: list[OfferEvaluation] = Field(default_factory=list)
    feasible_ranking: list[str] = Field(default_factory=list)
    algorithm: str = "single_pass_argmax_with_deterministic_tie_breaks"
    complexity: str = "O(n) selection; O(k log k) optional feasible ranking"
    optimality_verified: bool = False
    verification_winner_id: str | None = None
    notes: list[str] = Field(default_factory=list)

    def evaluation_for(self, option_id: str) -> OfferEvaluation | None:
        return next((e for e in self.evaluations if e.option_id == option_id), None)

    def model_dump_json_pretty(self) -> str:
        return self.model_dump_json(indent=2)


def option_label(value: Any, ordinal: int) -> tuple[str, str]:
    """Extract safe display labels from malformed raw input without echoing payloads."""
    if isinstance(value, dict):
        raw_id = value.get("option_id", f"INVALID-{ordinal:02d}")
        raw_seller = value.get("seller", "Unknown seller")
    elif isinstance(value, Offer):
        raw_id, raw_seller = value.option_id, value.seller
    else:
        raw_id, raw_seller = f"INVALID-{ordinal:02d}", "Unknown seller"
    option_id = str(raw_id)[:40] if str(raw_id).strip() else f"INVALID-{ordinal:02d}"
    seller = str(raw_seller)[:100] if str(raw_seller).strip() else "Unknown seller"
    return option_id, seller
