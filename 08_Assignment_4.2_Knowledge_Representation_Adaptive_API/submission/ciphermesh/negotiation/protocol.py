"""Contract-Net-inspired multi-turn negotiation and consensus handshake."""
from __future__ import annotations

from uuid import uuid4

from .agents import (COORDINATOR_ID, InspectionCapacitySupplierAgent,
                     WorkloadBuyerAgent, canonical_digest)
from .models import (ContractTerms, NegotiationMessage, NegotiationResult,
                     NegotiationStage, NegotiationStatus)
from .transport import SerializedMessageBus, NegotiationTransportError


class ContractNetNegotiator:
    """Run one bounded negotiation between two independent agent instances."""
    def __init__(self, buyer: WorkloadBuyerAgent | None = None,
                 supplier: InspectionCapacitySupplierAgent | None = None,
                 max_rounds: int = 8, max_message_bytes: int = 64 * 1024):
        if max_rounds < 1 or max_rounds > 100:
            raise ValueError("max_rounds must be between 1 and 100")
        self.buyer = buyer or WorkloadBuyerAgent()
        self.supplier = supplier or InspectionCapacitySupplierAgent()
        if self.buyer.agent_id == self.supplier.agent_id:
            raise ValueError("buyer and supplier must be distinct agent instances with distinct IDs")
        self.max_rounds = max_rounds
        self.negotiation_id = str(uuid4())
        self.bus = SerializedMessageBus([self.buyer, self.supplier], max_message_bytes=max_message_bytes)

    def _count(self) -> int:
        return sum(1 for event in self.bus.events if event.message_bytes > 0)

    def run(self) -> NegotiationResult:
        rounds_completed = 0
        candidate: ContractTerms | None = None
        acceptance_note = ""
        try:
            cfp = NegotiationMessage(
                negotiation_id=self.negotiation_id, sender=self.buyer.agent_id,
                recipient=self.supplier.agent_id, stage=NegotiationStage.CALL_FOR_PROPOSAL,
                turn=0,
                payload={"service_name": "CipherMesh privacy-inspection capacity",
                         "constraints": {"max_budget_per_1000_requests": self.buyer.max_price,
                             "required_capacity_rps": self.buyer.required_capacity_rps,
                             "max_p95_latency_ms": self.buyer.max_p95_latency_ms,
                             "min_recall": self.buyer.min_recall},
                         "buyer_target_price": self.buyer.target_price})
            seller_offer = self.bus.request(cfp)
            if seller_offer.stage != NegotiationStage.PROPOSAL:
                return self._failure(0, f"supplier did not provide a proposal: {seller_offer.stage.value}")

            for turn in range(1, self.max_rounds + 1):
                rounds_completed = turn
                buyer_message = self.buyer.respond_to_offer(seller_offer, turn)
                seller_response = self.bus.request(buyer_message)

                if buyer_message.stage == NegotiationStage.REJECT:
                    return self._failure(turn, buyer_message.payload.get("reason", "buyer rejected service profile"))

                if buyer_message.stage == NegotiationStage.ACCEPT:
                    if seller_response.stage == NegotiationStage.ACCEPT:
                        candidate = ContractTerms.model_validate(buyer_message.payload["terms"])
                        acceptance_note = "buyer accepted supplier offer; supplier confirmed"
                        break
                    return self._failure(turn, seller_response.payload.get("reason", "supplier did not confirm buyer acceptance"))

                if seller_response.stage == NegotiationStage.ACCEPT:
                    candidate = ContractTerms.model_validate(seller_response.payload["terms"])
                    acceptance_note = "supplier accepted buyer counteroffer"
                    break
                if seller_response.stage == NegotiationStage.REJECT:
                    return self._failure(turn, seller_response.payload.get("reason", "supplier rejected counteroffer"))
                if seller_response.stage != NegotiationStage.COUNTEROFFER:
                    return self._failure(turn, f"unexpected supplier response: {seller_response.stage.value}")
                seller_offer = seller_response

            if candidate is None:
                return self._failure(self.max_rounds,
                    f"no agreement after {self.max_rounds} rounds; no participant crossed the other's acceptance threshold")

            buyer_utility = self.buyer.utility(candidate.price_per_1000_requests)
            supplier_utility = self.supplier.utility(candidate.price_per_1000_requests)
            if (buyer_utility < self.buyer.reservation_utility()
                    or supplier_utility < self.supplier.reservation_utility()):
                return self._failure(rounds_completed, "acceptance candidate violates reservation utility")

            handshake = self._consensus_handshake(candidate, rounds_completed + 1)
            if handshake[0] == NegotiationStatus.AGREED:
                digest = handshake[1]
                self.bus.record_coordinator_note(rounds_completed + 1,
                    "CONSENSUS CONFIRMED: both COMMIT_ACK responses matched the canonical contract digest.",
                    "CONSENSUS_CONFIRMED")
                return NegotiationResult(
                    negotiation_id=self.negotiation_id, status=NegotiationStatus.AGREED,
                    rounds_completed=rounds_completed, agreed_terms=candidate,
                    contract_digest=digest, buyer_utility=round(buyer_utility, 2),
                    supplier_utility=round(supplier_utility, 2),
                    message_count=self._count(), timeline=self.bus.events,
                    termination_reason="consensus handshake completed: READY and COMMIT_ACK received from both agents",
                    notes=[acceptance_note,
                           "Utilities are scenario-model outputs, not measured production outcomes."])
            status, digest, note = handshake
            return NegotiationResult(
                negotiation_id=self.negotiation_id, status=status,
                rounds_completed=rounds_completed, agreed_terms=None,
                contract_digest=digest, buyer_utility=round(buyer_utility, 2),
                supplier_utility=round(supplier_utility, 2), message_count=self._count(),
                timeline=self.bus.events, termination_reason=note,
                notes=["No consensus is claimed unless both agents acknowledge the same committed digest."])
        except NegotiationTransportError as exc:
            self.bus.record_coordinator_note(rounds_completed, f"transport/protocol failure: {exc}", "TRANSPORT_ERROR")
            return NegotiationResult(
                negotiation_id=self.negotiation_id, status=NegotiationStatus.FAILED,
                rounds_completed=rounds_completed, message_count=self._count(),
                timeline=self.bus.events, termination_reason=f"transport/protocol failure: {exc}")

    def _consensus_handshake(self, terms: ContractTerms, turn: int):
        digest = canonical_digest(terms)
        for agent in (self.buyer, self.supplier):
            prepare = NegotiationMessage(
                negotiation_id=self.negotiation_id, sender=COORDINATOR_ID,
                recipient=agent.agent_id, stage=NegotiationStage.PREPARE, turn=turn,
                payload={"terms": terms.model_dump(mode="json"), "contract_digest": digest})
            response = self.bus.request(prepare)
            if response.stage != NegotiationStage.READY or response.payload.get("contract_digest") != digest:
                self._send_abort(digest, turn, (self.buyer, self.supplier))
                return (NegotiationStatus.FAILED, digest,
                        f"consensus prepare rejected by {response.sender}: {response.payload.get('reason', response.stage.value)}")

        acknowledgements: list[str] = []
        for agent in (self.buyer, self.supplier):
            commit = NegotiationMessage(
                negotiation_id=self.negotiation_id, sender=COORDINATOR_ID,
                recipient=agent.agent_id, stage=NegotiationStage.COMMIT, turn=turn,
                payload={"contract_digest": digest})
            response = self.bus.request(commit)
            if response.stage != NegotiationStage.COMMIT_ACK or response.payload.get("contract_digest") != digest:
                self.bus.record_coordinator_note(turn,
                    f"commit acknowledgement missing/invalid from {agent.agent_id}; outcome is in doubt.",
                    "IN_DOUBT")
                return (NegotiationStatus.IN_DOUBT, digest,
                        f"in-doubt outcome: missing matching COMMIT_ACK from {agent.agent_id}")
            acknowledgements.append(agent.agent_id)
        if len(acknowledgements) == 2 and len(set(acknowledgements)) == 2:
            return (NegotiationStatus.AGREED, digest, "consensus handshake succeeded")
        return (NegotiationStatus.IN_DOUBT, digest, "in-doubt outcome: two-party commit not confirmed")

    def _send_abort(self, digest: str, turn: int, agents) -> None:
        for agent in agents:
            abort = NegotiationMessage(
                negotiation_id=self.negotiation_id, sender=COORDINATOR_ID,
                recipient=agent.agent_id, stage=NegotiationStage.ABORT, turn=turn,
                payload={"contract_digest": digest})
            try:
                self.bus.request(abort)
            except NegotiationTransportError:
                self.bus.record_coordinator_note(turn, f"abort could not be delivered to {agent.agent_id}", "ABORT_WARNING")

    def _failure(self, turn: int, reason: str) -> NegotiationResult:
        self.bus.record_coordinator_note(turn, f"NEGOTIATION FAILED: {reason}", "TERMINATED")
        return NegotiationResult(
            negotiation_id=self.negotiation_id, status=NegotiationStatus.FAILED,
            rounds_completed=turn, message_count=self._count(),
            timeline=self.bus.events, termination_reason=reason,
            notes=["The protocol terminates within the configured round bound.",
                   "No contract is committed after a failed negotiation."])
