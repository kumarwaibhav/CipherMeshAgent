"""Reproducible ten-option e-commerce procurement scenario.

All options and metrics are illustrative. They are intentionally diverse so the
scenario exercises price, quality, speed, reliability, returns, stock, status,
and destination constraints.
"""
from __future__ import annotations
from .models import Offer, OptimizationConstraints


OFFERS: list[Offer] = [
    Offer(option_id="ECO-01", seller="Meridian Value", item_price=109, shipping_per_unit=12,
          quality_rating=4.2, delivery_days=4, reliability_pct=96.0, return_rate_pct=5.0,
          available_units=250, active=True, supports_destination=True),
    Offer(option_id="ECO-02", seller="PrimeCart", item_price=125, shipping_per_unit=5,
          quality_rating=4.8, delivery_days=2, reliability_pct=98.0, return_rate_pct=2.0,
          available_units=800, active=True, supports_destination=True),
    Offer(option_id="ECO-03", seller="BudgetBee", item_price=99, shipping_per_unit=9,
          quality_rating=3.7, delivery_days=3, reliability_pct=98.0, return_rate_pct=1.5,
          available_units=400, active=True, supports_destination=False),
    Offer(option_id="ECO-04", seller="SwiftSupply", item_price=138, shipping_per_unit=7,
          quality_rating=4.9, delivery_days=1, reliability_pct=99.5, return_rate_pct=1.0,
          available_units=80, active=True, supports_destination=True),
    Offer(option_id="ECO-05", seller="SolidMart", item_price=118, shipping_per_unit=4,
          quality_rating=4.6, delivery_days=3, reliability_pct=97.0, return_rate_pct=3.0,
          available_units=500, active=True, supports_destination=True),
    Offer(option_id="ECO-06", seller="LuxuryLane", item_price=140, shipping_per_unit=8,
          quality_rating=4.9, delivery_days=1, reliability_pct=99.0, return_rate_pct=1.0,
          available_units=900, active=True, supports_destination=True),
    Offer(option_id="ECO-07", seller="RapidHub", item_price=112, shipping_per_unit=5,
          quality_rating=4.1, delivery_days=2, reliability_pct=94.0, return_rate_pct=2.0,
          available_units=350, active=True, supports_destination=True),
    Offer(option_id="ECO-08", seller="NorthPeak", item_price=128, shipping_per_unit=3,
          quality_rating=4.7, delivery_days=1, reliability_pct=97.5, return_rate_pct=4.0,
          available_units=180, active=True, supports_destination=True),
    Offer(option_id="ECO-09", seller="TrustCart", item_price=120, shipping_per_unit=7,
          quality_rating=4.9, delivery_days=4, reliability_pct=99.0, return_rate_pct=1.0,
          available_units=120, active=True, supports_destination=True),
    Offer(option_id="ECO-10", seller="EconomyPlus", item_price=105, shipping_per_unit=6,
          quality_rating=4.0, delivery_days=5, reliability_pct=95.0, return_rate_pct=6.0,
          available_units=100, active=True, supports_destination=True),
]


def default_constraints() -> OptimizationConstraints:
    return OptimizationConstraints(
        max_landed_cost_per_unit=145.0,
        required_quantity=100,
        min_quality_rating=4.0,
        max_delivery_days=5,
        min_reliability_pct=95.0,
        max_return_rate_pct=6.0,
        return_rate_score_ceiling_pct=10.0,
    )
