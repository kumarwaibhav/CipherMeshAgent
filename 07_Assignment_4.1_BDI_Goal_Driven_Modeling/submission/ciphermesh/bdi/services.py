"""Bridge between the BDI layer and the real CipherMesh engine.

Author : Kumar Waibhav Akshat (RA2212704010027)
Course : 21CSE525T Agent Technology, Assignment 4.1 (BDI Goal-Driven Modeling)

Plans never re-implement engine logic. They call the services collected here:

* ``CipherMeshAgent``     detector + policy R1..R5 (``policy.inspect_text``), response
                          inspection, review queue and the SQLite audit log (Units 1-2).
* ``ContractBook``        Contract-Net procurement of provider capacity (Unit 3.1).
* ``routing.route``       constrained utility router + ``derive_constraints`` (Unit 3.2).
* ``ProviderRegistry``    simulated provider adapters with circuit breaker.
* ``EvidenceLedger``      HMAC-SHA256 hash-chained evidence records (vault-like sealing).

The router is always fed a *belief-derived* view of the world: provider status,
residency and price come from the belief base, not from static profiles, so a
belief update immediately changes what the router considers feasible.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..agent import CipherMeshAgent
from ..models import Decision, Finding, InspectionResult
from ..procurement import ContractBook
from ..providers import ProviderProfile, ProviderRegistry, default_registry
from ..review import ReviewQueue
from ..routing import RouteConstraints, RouteDecision, RouteWeights, derive_constraints, route
from . import world


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def sha256_16(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class SealedRecord:
    index: int
    kind: str
    record: dict
    prev_mac: str
    mac: str


class EvidenceLedger:
    """Tamper-evident evidence chain: mac_i = HMAC(key, prev_mac || canonical(record_i)).

    Records hold metadata only (hashes, categories, provider ids, decisions).
    The demo key comes from ``CIPHERMESH_BDI_SEAL_KEY``; a fixed development key
    is used when it is unset so that test runs are reproducible.
    """

    def __init__(self, key: str | None = None) -> None:
        secret = key or os.getenv("CIPHERMESH_BDI_SEAL_KEY") or "ciphermesh-bdi-dev-seal-key"
        self._key = secret.encode("utf-8")
        self._records: list[SealedRecord] = []
        self._lock = threading.Lock()

    @staticmethod
    def _canonical(record: dict) -> bytes:
        return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")

    def seal(self, kind: str, record: dict) -> SealedRecord:
        with self._lock:
            prev = self._records[-1].mac if self._records else "0" * 64
            body = {"kind": kind, **record}
            mac = hmac.new(self._key, prev.encode("ascii") + self._canonical(body), hashlib.sha256).hexdigest()
            sealed = SealedRecord(index=len(self._records), kind=kind, record=body, prev_mac=prev, mac=mac)
            self._records.append(sealed)
            return sealed

    def verify(self) -> bool:
        with self._lock:
            prev = "0" * 64
            for item in self._records:
                expected = hmac.new(self._key, prev.encode("ascii") + self._canonical(item.record),
                                    hashlib.sha256).hexdigest()
                if item.prev_mac != prev or not hmac.compare_digest(item.mac, expected):
                    return False
                prev = item.mac
            return True

    def records(self) -> list[SealedRecord]:
        with self._lock:
            return list(self._records)


@dataclass
class TransmissionRecord:
    """One payload that actually left CipherMesh towards a provider."""
    request_id: str
    provider: str
    residency: str
    payload_sha256: str
    redacted: bool
    ok: bool
    at: str = field(default_factory=_iso_now)
    error: str | None = None


@dataclass
class RequestContext:
    """Private per-request working memory. Raw text never enters the belief base or the trace."""
    request_id: str
    text: str
    inspection: InspectionResult
    payload: str | None = None
    raw_response: str | None = None
    delivered_text: str | None = None
    review_id: str | None = None
    advice: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)


class EngineServices:
    """Everything a BDI plan step may call, wired to the real CipherMesh engine."""

    def __init__(self, agent: CipherMeshAgent | None = None, registry: ProviderRegistry | None = None,
                 contracts: ContractBook | None = None, weights: RouteWeights | None = None,
                 base_constraints: RouteConstraints | None = None, ledger: EvidenceLedger | None = None,
                 review_limit: int = 25, latency_scale: float = 0.0) -> None:
        self.agent = agent or CipherMeshAgent("CIPHERMESH_BDI", ":memory:", review_queue=ReviewQueue())
        self.registry = registry or default_registry(latency_scale=latency_scale, use_ollama=False)
        self.agent.state.provider_allowlist = self.registry.ids()
        self.base_constraints = base_constraints or RouteConstraints()
        self.weights = weights or RouteWeights()
        self.contracts = contracts or ContractBook(
            budget_per_1k_usd=self.base_constraints.max_cost_per_1k_usd,
            min_availability_pct=self.base_constraints.min_availability_pct,
            max_p95_latency_ms=self.base_constraints.max_p95_latency_ms)
        self.ledger = ledger or EvidenceLedger()
        self.review_limit = review_limit
        self.transmissions: list[TransmissionRecord] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ perception helpers
    def perceive_world(self, beliefs: Any, source: str = "engine:registry+procurement") -> None:
        """Seed provider, budget, policy and review beliefs from the live engine."""
        prices = self.contracts.ensure_all(self.registry.profiles())
        for profile in self.registry.profiles():
            pid = profile.provider_id
            beliefs.set(world.pkey(pid, "status"),
                        "major_outage" if self.registry.health.is_open(pid) else "operational", source)
            beliefs.set(world.pkey(pid, "kind"), profile.kind, source)
            beliefs.set(world.pkey(pid, "region"), profile.region, source)
            beliefs.set(world.pkey(pid, "residency"), profile.data_residency, source)
            beliefs.set(world.pkey(pid, "price_per_1k"),
                        prices.get(pid, profile.cost_per_1k_requests_usd), source)
            beliefs.set(world.pkey(pid, "price_source"),
                        "negotiated_contract" if pid in prices else "list_price", source)
        beliefs.set("budget.max_cost_per_1k", self.base_constraints.max_cost_per_1k_usd, "config:route_constraints")
        beliefs.set("policy.lockdown", bool(self.agent.state.force_block_all), "engine:agent_state")
        beliefs.set("review.limit", self.review_limit, "config:review")
        beliefs.set("review.queue_depth", self.review_depth(), "engine:review_queue")
        beliefs.set("threat.level", "normal", "engine:monitor")

    def review_depth(self) -> int:
        return sum(1 for t in self.agent.reviews.list() if t.status.value == "PENDING")

    def inspect(self, text: str) -> InspectionResult:
        """Real detector + policy, without opening a review ticket (plans decide that)."""
        return self.agent.inspect(text, open_review=False)

    # ------------------------------------------------------------------ belief-derived routing
    def world_profiles(self, beliefs: Any) -> list[ProviderProfile]:
        out: list[ProviderProfile] = []
        for profile in self.registry.profiles():
            residency = beliefs.get(world.pkey(profile.provider_id, "residency"), profile.data_residency)
            region = beliefs.get(world.pkey(profile.provider_id, "region"), profile.region)
            out.append(profile.model_copy(update={"data_residency": residency, "region": region}))
        return out

    def unusable(self, beliefs: Any) -> set[str]:
        bad = set()
        for pid in self.registry.ids():
            if world.provider_status(beliefs, pid) not in world.STATUS_OK or self.registry.health.is_open(pid):
                bad.add(pid)
        return bad

    @staticmethod
    def inspection_view(beliefs: Any) -> InspectionResult:
        """Rebuild the inspection seen by ``derive_constraints`` from beliefs."""
        findings = [Finding(category=c, start=0, end=1, confidence=1.0, source="belief")
                    for c in sorted(world.prompt_categories(beliefs))]
        decision = Decision(beliefs.get("prompt.decision", "ALLOW"))
        return InspectionResult(decision=decision, findings=findings)

    def route_view(self, beliefs: Any, require_local: bool = False, hint: str | None = None) -> RouteDecision:
        base = self.base_constraints.model_copy(update={"max_cost_per_1k_usd": world.budget(beliefs),
                                                        "require_local": require_local})
        constraints, notes = derive_constraints(self.inspection_view(beliefs), self.agent.state, base)
        prices = {pid: world.provider_price(beliefs, pid) for pid in self.registry.ids()
                  if world.provider_price(beliefs, pid) is not None}
        decision = route(self.world_profiles(beliefs), constraints, self.weights, prices,
                         self.unusable(beliefs), hint)
        decision.notes = [*notes, *decision.notes]
        return decision

    # ------------------------------------------------------------------ transmission ledger
    def record_transmission(self, record: TransmissionRecord) -> None:
        with self._lock:
            self.transmissions.append(record)

    def transmissions_for(self, request_id: str) -> list[TransmissionRecord]:
        with self._lock:
            return [t for t in self.transmissions if t.request_id == request_id]
