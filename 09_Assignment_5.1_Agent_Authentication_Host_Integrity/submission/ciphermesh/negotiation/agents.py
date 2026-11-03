"""Buyer and supplier negotiating agents with utility-based stance updates."""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Any

from .models import ContractTerms, NegotiationMessage, NegotiationStage

COORDINATOR_ID = "NEGOTIATION_COORDINATOR"


def clamp(value: float, lower: float = 0.0, upper: float = 100.0) -> float:
    return max(lower, min(upper, value))


def canonical_digest(terms: ContractTerms) -> str:
    """Stable SHA-256 digest over canonical contract JSON for the handshake."""
    canonical = json.dumps(terms.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()


class NegotiationParticipant:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.pending_contracts: dict[str, ContractTerms] = {}
        self.committed_contracts: dict[str, ContractTerms] = {}
        self.last_negotiation_id: str | None = None

    def receive(self, message: NegotiationMessage) -> NegotiationMessage:
        if message.recipient != self.agent_id:
            return self._reply(message, NegotiationStage.ERROR,
                               {"error": "recipient mismatch"})
        self.last_negotiation_id = message.negotiation_id
        stage = message.stage
        if stage == NegotiationStage.PREPARE:
            return self._prepare(message)
        if stage == NegotiationStage.COMMIT:
            return self._commit(message)
        if stage == NegotiationStage.ABORT:
            return self._abort(message)
        return self._handle_negotiation_message(message)

    def _handle_negotiation_message(self, message: NegotiationMessage) -> NegotiationMessage:
        return self._reply(message, NegotiationStage.ERROR,
                           {"error": f"unsupported stage {message.stage.value}"})

    def utility(self, price: float) -> float:
        raise NotImplementedError

    def reservation_utility(self) -> float:
        raise NotImplementedError

    def aspiration(self, turn: int) -> float:
        """Utility threshold declines by round, never below a participant's reservation."""
        return max(self.reservation_utility(), 92.0 - 9.0 * turn)

    def _prepare(self, message: NegotiationMessage) -> NegotiationMessage:
        digest = message.payload.get("contract_digest")
        raw_terms = message.payload.get("terms")
        if not isinstance(digest, str) or not isinstance(raw_terms, dict):
            return self._reply(message, NegotiationStage.REJECT,
                               {"reason": "PREPARE requires terms and contract_digest"})
        try:
            terms = ContractTerms.model_validate(raw_terms)
        except Exception:
            return self._reply(message, NegotiationStage.REJECT,
                               {"reason": "contract schema validation failed"})
        calculated = canonical_digest(terms)
        if calculated != digest:
            return self._reply(message, NegotiationStage.REJECT,
                               {"reason": "contract digest mismatch", "expected_digest": calculated})
        if self.utility(terms.price_per_1000_requests) < self.reservation_utility():
            return self._reply(message, NegotiationStage.REJECT,
                               {"reason": "contract violates participant reservation utility",
                                "utility": round(self.utility(terms.price_per_1000_requests), 2)})
        if not self._terms_feasible(terms):
            return self._reply(message, NegotiationStage.REJECT,
                               {"reason": "contract does not satisfy local service constraints"})
        self.pending_contracts[digest] = terms
        return self._reply(message, NegotiationStage.READY,
                           {"contract_digest": digest,
                            "utility": round(self.utility(terms.price_per_1000_requests), 2),
                            "reservation_utility": self.reservation_utility()})

    def _commit(self, message: NegotiationMessage) -> NegotiationMessage:
        digest = message.payload.get("contract_digest")
        if not isinstance(digest, str) or digest not in self.pending_contracts:
            return self._reply(message, NegotiationStage.ERROR,
                               {"error": "COMMIT without matching READY/PREPARE state"})
        self.committed_contracts[digest] = self.pending_contracts.pop(digest)
        return self._reply(message, NegotiationStage.COMMIT_ACK,
                           {"contract_digest": digest, "status": "committed"})

    def _abort(self, message: NegotiationMessage) -> NegotiationMessage:
        digest = message.payload.get("contract_digest")
        if isinstance(digest, str):
            self.pending_contracts.pop(digest, None)
        return self._reply(message, NegotiationStage.ABORT_ACK,
                           {"contract_digest": digest, "status": "aborted_or_cleared"})

    def _terms_feasible(self, terms: ContractTerms) -> bool:
        return True

    def _reply(self, request: NegotiationMessage, stage: NegotiationStage,
               payload: dict[str, Any]) -> NegotiationMessage:
        return NegotiationMessage(
            negotiation_id=request.negotiation_id,
            sender=self.agent_id,
            recipient=request.sender,
            stage=stage,
            turn=request.turn,
            correlation_id=request.message_id,
            payload=payload,
        )


class WorkloadBuyerAgent(NegotiationParticipant):
    """Application-side buyer: trades unit price against budget and service SLOs."""
    def __init__(self, agent_id: str = "WORKLOAD_BUYER", target_price: float = 112.0,
                 max_price: float = 180.0, min_utility: float = 40.0,
                 required_capacity_rps: int = 400, max_p95_latency_ms: float = 30.0,
                 min_recall: float = 0.95):
        super().__init__(agent_id)
        if max_price <= target_price:
            raise ValueError("max_price must be greater than target_price")
        self.target_price = float(target_price)
        self.max_price = float(max_price)
        self.min_utility = float(min_utility)
        self.required_capacity_rps = required_capacity_rps
        self.max_p95_latency_ms = max_p95_latency_ms
        self.min_recall = min_recall
        self.current_offer = float(target_price)

    def utility(self, price: float) -> float:
        # 100 at/below target; declines linearly to zero at the budget ceiling.
        return clamp((self.max_price - price) / (self.max_price - self.target_price) * 100.0)

    def reservation_utility(self) -> float:
        return self.min_utility

    def _terms_feasible(self, terms: ContractTerms) -> bool:
        return (terms.capacity_rps >= self.required_capacity_rps
                and terms.p95_latency_ms <= self.max_p95_latency_ms
                and terms.estimated_recall >= self.min_recall)

    def respond_to_offer(self, offer: NegotiationMessage, turn: int) -> NegotiationMessage:
        def reply(stage: NegotiationStage, payload: dict[str, Any]) -> NegotiationMessage:
            # The negotiation turn is part of the state machine, not inherited from the CFP.
            response = self._reply(offer, stage, payload)
            response.turn = turn
            return response

        raw = offer.payload.get("terms")
        try:
            terms = ContractTerms.model_validate(raw)
        except Exception:
            return reply(NegotiationStage.REJECT, {"reason": "invalid supplier terms"})
        if not self._terms_feasible(terms):
            return reply(NegotiationStage.REJECT,
                         {"reason": "supplier service profile violates buyer SLOs",
                          "required_capacity_rps": self.required_capacity_rps,
                          "max_p95_latency_ms": self.max_p95_latency_ms,
                          "min_recall": self.min_recall})
        price = terms.price_per_1000_requests
        utility = self.utility(price)
        threshold = self.aspiration(turn)
        if utility >= threshold and utility >= self.min_utility:
            return reply(NegotiationStage.ACCEPT,
                         {"terms": terms.model_dump(mode="json"),
                          "buyer_utility": round(utility, 2),
                          "aspiration_utility": round(threshold, 2),
                          "reason": "offer satisfies buyer aspiration and reservation utility"})
        concession = min(0.40, 0.12 + 0.035 * turn)
        next_price = self.current_offer + concession * (price - self.current_offer)
        # A buyer never offers above its explicit budget ceiling.
        self.current_offer = round(min(self.max_price, next_price), 2)
        counter_terms = terms.model_copy(update={"price_per_1000_requests": self.current_offer})
        return reply(NegotiationStage.COUNTEROFFER,
                     {"terms": counter_terms.model_dump(mode="json"),
                      "buyer_utility": round(self.utility(self.current_offer), 2),
                      "received_offer_utility": round(utility, 2),
                      "aspiration_utility": round(threshold, 2),
                      "concession_rate": round(concession, 3),
                      "reason": "counteroffer: utility below current aspiration"})

    def _handle_negotiation_message(self, message: NegotiationMessage) -> NegotiationMessage:
        return self._reply(message, NegotiationStage.ERROR,
                           {"error": f"buyer cannot process {message.stage.value} in receive path"})


class InspectionCapacitySupplierAgent(NegotiationParticipant):
    """Supplier: offers inspection capacity and concedes price while protecting margin."""
    def __init__(self, agent_id: str = "INSPECTION_SUPPLIER", cost_floor: float = 100.0,
                 initial_ask: float = 176.0, min_utility: float = 40.0,
                 capacity_rps: int = 600, p95_latency_ms: float = 18.0,
                 estimated_recall: float = 0.97):
        super().__init__(agent_id)
        if initial_ask <= cost_floor:
            raise ValueError("initial_ask must exceed cost_floor")
        self.cost_floor = float(cost_floor)
        self.initial_ask = float(initial_ask)
        self.min_utility = float(min_utility)
        self.current_ask = float(initial_ask)
        self.capacity_rps = capacity_rps
        self.p95_latency_ms = p95_latency_ms
        self.estimated_recall = estimated_recall

    def utility(self, price: float) -> float:
        # 100 at initial asking price, declines linearly to zero at cost floor.
        return clamp((price - self.cost_floor) / (self.initial_ask - self.cost_floor) * 100.0)

    def reservation_utility(self) -> float:
        return self.min_utility

    def _terms(self, price: float) -> ContractTerms:
        return ContractTerms(price_per_1000_requests=round(price, 2),
                             capacity_rps=self.capacity_rps,
                             p95_latency_ms=self.p95_latency_ms,
                             estimated_recall=self.estimated_recall)

    def _handle_negotiation_message(self, message: NegotiationMessage) -> NegotiationMessage:
        if message.stage == NegotiationStage.CALL_FOR_PROPOSAL:
            buyer_constraints = message.payload.get("constraints", {})
            if not isinstance(buyer_constraints, dict):
                return self._reply(message, NegotiationStage.REJECT,
                                   {"reason": "invalid constraints payload"})
            terms = self._terms(self.current_ask)
            return self._reply(message, NegotiationStage.PROPOSAL,
                               {"terms": terms.model_dump(mode="json"),
                                "supplier_utility": round(self.utility(self.current_ask), 2),
                                "metrics_note": "illustrative configured profile; not a benchmark result"})
        if message.stage == NegotiationStage.COUNTEROFFER:
            try:
                terms = ContractTerms.model_validate(message.payload.get("terms"))
            except Exception:
                return self._reply(message, NegotiationStage.REJECT,
                                   {"reason": "invalid counteroffer contract schema"})
            price = terms.price_per_1000_requests
            utility = self.utility(price)
            threshold = self.aspiration(message.turn)
            if price >= self.cost_floor and utility >= threshold and utility >= self.min_utility:
                return self._reply(message, NegotiationStage.ACCEPT,
                                   {"terms": terms.model_dump(mode="json"),
                                    "supplier_utility": round(utility, 2),
                                    "aspiration_utility": round(threshold, 2),
                                    "reason": "buyer offer meets supplier aspiration and reservation utility"})
            concession = min(0.42, 0.14 + 0.04 * message.turn)
            reservation_price = self.cost_floor + (self.min_utility / 100.0) * (self.initial_ask - self.cost_floor)
            next_ask = self.current_ask - concession * (self.current_ask - price)
            self.current_ask = round(max(reservation_price, next_ask), 2)
            counter_terms = terms.model_copy(update={"price_per_1000_requests": self.current_ask})
            return self._reply(message, NegotiationStage.COUNTEROFFER,
                               {"terms": counter_terms.model_dump(mode="json"),
                                "supplier_utility": round(self.utility(self.current_ask), 2),
                                "received_offer_utility": round(utility, 2),
                                "aspiration_utility": round(threshold, 2),
                                "concession_rate": round(concession, 3),
                                "reason": "counteroffer: offer below current aspiration"})
        if message.stage == NegotiationStage.ACCEPT:
            try:
                terms = ContractTerms.model_validate(message.payload.get("terms"))
            except Exception:
                return self._reply(message, NegotiationStage.REJECT,
                                   {"reason": "invalid accepted terms"})
            utility = self.utility(terms.price_per_1000_requests)
            if terms.price_per_1000_requests < self.cost_floor or utility < self.min_utility:
                return self._reply(message, NegotiationStage.REJECT,
                                   {"reason": "accepted price violates supplier reservation utility",
                                    "supplier_utility": round(utility, 2)})
            return self._reply(message, NegotiationStage.ACCEPT,
                               {"terms": terms.model_dump(mode="json"),
                                "supplier_utility": round(utility, 2),
                                "reason": "supplier confirms buyer acceptance"})
        return self._reply(message, NegotiationStage.ERROR,
                           {"error": f"supplier cannot process {message.stage.value}"})
