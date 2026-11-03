"""Explainable utility evaluation and constrained offer optimization."""
from .engine import (
    compute_score,
    optimize_offers,
    score_offer,
    exhaustive_reference_winner,
    verify_optimality,
)
from .models import (
    Offer,
    UtilityWeights,
    OptimizationConstraints,
    OfferEvaluation,
    OptimizationResult,
    EvaluationStatus,
)

__all__ = [
    "compute_score", "optimize_offers", "score_offer", "exhaustive_reference_winner",
    "verify_optimality", "Offer", "UtilityWeights", "OptimizationConstraints",
    "OfferEvaluation", "OptimizationResult", "EvaluationStatus",
]
