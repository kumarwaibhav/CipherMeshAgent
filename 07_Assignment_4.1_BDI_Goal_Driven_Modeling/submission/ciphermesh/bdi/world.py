"""Shared vocabulary for reading the CipherMesh belief base.

Author : Kumar Waibhav Akshat (RA2212704010027)
Course : 21CSE525T Agent Technology, Assignment 4.1 (BDI Goal-Driven Modeling)

Desires, plan contexts and step guards all interpret the same beliefs. Keeping
those interpretations in one module means a desire and the plans it constrains
can never disagree about, for example, what "Indian personal data" means.

Belief keys used by the BDI layer
---------------------------------
request.id / request.status            PENDING, COMPLETED, BLOCKED, RESPONSE_WITHHELD,
                                       PENDING_REVIEW, DEFERRED, FAILED
prompt.sha256 / prompt.bytes           fingerprint of the current prompt (never the text)
prompt.decision / prompt.categories    real detector + policy result (R1..R5)
policy.lockdown                        emergency lockdown flag (bool)
provider.<id>.status                   operational | degraded_performance |
                                       partial_outage | major_outage
provider.<id>.residency / .region      where the provider processes data
provider.<id>.price_per_1k             effective USD price per 1k requests
provider.<id>.kind                     cloud | local
budget.max_cost_per_1k                 spending ceiling used by the router
review.queue_depth / review.limit      human-review backlog and its limit
response.decision / response.findings  real inspection result of the provider reply
response.delivered                     True once a safe reply was returned
threat.level                           normal | elevated | high
guard.secret_contained                 True once a secret risk was contained
"""
from __future__ import annotations

from typing import Any

from ..detector import CRITICAL
from ..routing import INDIA_PERSONAL_DATA

# Provider status vocabulary (mirrors common cloud status pages).
STATUS_OK = frozenset({"operational", "degraded_performance"})
STATUS_WAIT = frozenset({"partial_outage", "unknown"})
STATUS_DOWN = frozenset({"major_outage", "disabled"})

FINAL_STATUSES = frozenset({"COMPLETED", "BLOCKED", "RESPONSE_WITHHELD", "PENDING_REVIEW",
                            "DEFERRED", "FAILED"})
HOME_RESIDENCY = frozenset({"IN", "LOCAL"})
CRITICAL_CATEGORIES = frozenset(CRITICAL)
INDIA_CATEGORIES = frozenset(INDIA_PERSONAL_DATA)


def pkey(provider: str, attribute: str) -> str:
    """Belief key for a provider attribute, e.g. ``provider.aws-bedrock.status``."""
    return f"provider.{provider}.{attribute}"


def request_pending(beliefs: Any) -> bool:
    return beliefs.get("request.status") == "PENDING"


def prompt_categories(beliefs: Any) -> set[str]:
    return set(beliefs.get("prompt.categories", []) or [])


def prompt_has_secret(beliefs: Any) -> bool:
    return bool(prompt_categories(beliefs) & CRITICAL_CATEGORIES)


def india_personal_data(beliefs: Any) -> bool:
    return bool(prompt_categories(beliefs) & INDIA_CATEGORIES)


def lockdown(beliefs: Any) -> bool:
    return bool(beliefs.get("policy.lockdown", False))


def response_has_secret(beliefs: Any) -> bool:
    findings = beliefs.get("response.findings", []) or []
    return any(f.get("severity") == "CRITICAL" for f in findings)


def allowed_residency(beliefs: Any) -> set[str]:
    """Residencies a dispatch may use for the current prompt (D2 constraint)."""
    if india_personal_data(beliefs):
        return set(HOME_RESIDENCY)
    return {"IN", "US", "EU", "LOCAL"}


def provider_status(beliefs: Any, provider: str) -> str:
    return str(beliefs.get(pkey(provider, "status"), "unknown"))


def budget(beliefs: Any) -> float:
    return float(beliefs.get("budget.max_cost_per_1k", 6.0))


def provider_price(beliefs: Any, provider: str) -> float | None:
    value = beliefs.get(pkey(provider, "price_per_1k"))
    return None if value is None else float(value)


def review_capacity(beliefs: Any) -> bool:
    return int(beliefs.get("review.queue_depth", 0)) < int(beliefs.get("review.limit", 25))
