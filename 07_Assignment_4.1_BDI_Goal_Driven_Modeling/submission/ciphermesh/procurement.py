"""In-domain multi-agent procurement: CipherMesh buys inference capacity per provider.

Each provider is represented by its own supplier agent; CipherMesh's buyer agent
runs the Contract-Net-inspired protocol (CFP -> PROPOSAL -> COUNTEROFFERs ->
PREPARE/READY -> COMMIT/COMMIT_ACK) against it. The committed price becomes the
*effective cost* the router scores. A failed negotiation is not hidden: the
provider stays priced at list (on-demand) and may become infeasible on budget.

Price scaling keeps the validated Assignment 3.1 economics shape for every
provider, anchored so the supplier opens at its on-demand list price L:
supplier floor = L*100/176, opening ask = L, buyer target = L*112/176 and
buyer ceiling = min(budget, L*180/176). Agreement therefore lands below list.
"""
from __future__ import annotations

import threading
import time

from pydantic import BaseModel

from .negotiation.agents import InspectionCapacitySupplierAgent, WorkloadBuyerAgent
from .negotiation.models import ContractTerms, NegotiationResult, NegotiationStatus
from .negotiation.protocol import ContractNetNegotiator
from .providers import ProviderProfile


class ProviderCapacitySupplier(InspectionCapacitySupplierAgent):
    def __init__(self, profile: ProviderProfile):
        list_price = profile.cost_per_1k_requests_usd
        super().__init__(agent_id=f"{profile.provider_id.upper()}_SUPPLIER",
                         cost_floor=list_price * 100 / 176, initial_ask=list_price,
                         capacity_rps=profile.capacity_rps, p95_latency_ms=profile.p95_latency_ms,
                         estimated_recall=profile.availability_pct / 100.0)
        self.profile = profile

    def _terms(self, price: float) -> ContractTerms:
        return ContractTerms(service_name=f"{self.profile.display_name} inference capacity",
                             price_per_1000_requests=round(price, 4), capacity_rps=self.capacity_rps,
                             p95_latency_ms=self.p95_latency_ms, estimated_recall=self.estimated_recall,
                             metrics_source="illustrative_planning_profile")


class ContractRecord(BaseModel):
    provider_id: str
    status: str
    price_per_1k_usd: float | None = None
    list_price_per_1k_usd: float
    contract_digest: str | None = None
    rounds: int = 0
    buyer_utility: float | None = None
    supplier_utility: float | None = None
    termination_reason: str
    negotiated_at: float


class ContractBook:
    """Thread-safe cache of committed capacity contracts, one negotiation per provider per TTL."""

    def __init__(self, budget_per_1k_usd: float = 6.0, min_availability_pct: float = 99.0,
                 required_capacity_rps: int = 200, max_p95_latency_ms: float = 1500.0,
                 ttl_s: float = 3600.0, max_rounds: int = 8):
        self.budget = budget_per_1k_usd
        self.min_availability_pct = min_availability_pct
        self.required_capacity_rps = required_capacity_rps
        self.max_p95_latency_ms = max_p95_latency_ms
        self.ttl_s = ttl_s
        self.max_rounds = max_rounds
        self._records: dict[str, ContractRecord] = {}
        self._results: dict[str, NegotiationResult] = {}
        self._lock = threading.Lock()

    def negotiate(self, profile: ProviderProfile) -> tuple[ContractRecord, NegotiationResult]:
        list_price = profile.cost_per_1k_requests_usd
        target = list_price * 112 / 176
        ceiling = min(self.budget, list_price * 180 / 176)
        if ceiling <= target or list_price <= 0:
            record = ContractRecord(provider_id=profile.provider_id, status="SKIPPED",
                                    list_price_per_1k_usd=list_price, negotiated_at=time.time(),
                                    termination_reason="budget ceiling below buyer target; list price applies")
            dummy = NegotiationResult(negotiation_id="skipped", status=NegotiationStatus.FAILED,
                                      rounds_completed=0, message_count=0,
                                      termination_reason=record.termination_reason)
            return record, dummy
        buyer = WorkloadBuyerAgent(agent_id="CIPHERMESH_BUYER", target_price=target, max_price=ceiling,
                                   required_capacity_rps=self.required_capacity_rps,
                                   max_p95_latency_ms=self.max_p95_latency_ms,
                                   min_recall=self.min_availability_pct / 100.0)
        supplier = ProviderCapacitySupplier(profile)
        result = ContractNetNegotiator(buyer, supplier, max_rounds=self.max_rounds).run()
        agreed = result.status == NegotiationStatus.AGREED and result.agreed_terms is not None
        record = ContractRecord(
            provider_id=profile.provider_id, status=result.status.value,
            price_per_1k_usd=result.agreed_terms.price_per_1000_requests if agreed else None,
            list_price_per_1k_usd=list_price, contract_digest=result.contract_digest if agreed else None,
            rounds=result.rounds_completed, buyer_utility=result.buyer_utility,
            supplier_utility=result.supplier_utility, termination_reason=result.termination_reason,
            negotiated_at=time.time())
        return record, result

    def ensure(self, profile: ProviderProfile) -> ContractRecord:
        with self._lock:
            record = self._records.get(profile.provider_id)
            if record and time.time() - record.negotiated_at < self.ttl_s:
                return record
        record, result = self.negotiate(profile)
        with self._lock:
            self._records[profile.provider_id] = record
            self._results[profile.provider_id] = result
        return record

    def ensure_all(self, profiles: list[ProviderProfile]) -> dict[str, float]:
        """Negotiate where needed and return provider_id -> committed price for agreed contracts."""
        prices: dict[str, float] = {}
        for profile in profiles:
            if not profile.enabled:
                continue
            record = self.ensure(profile)
            if record.status == "AGREED" and record.price_per_1k_usd is not None:
                prices[profile.provider_id] = record.price_per_1k_usd
        return prices

    def records(self) -> list[ContractRecord]:
        with self._lock:
            return list(self._records.values())

    def result_for(self, provider_id: str) -> NegotiationResult | None:
        with self._lock:
            return self._results.get(provider_id)
