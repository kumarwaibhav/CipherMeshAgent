from ciphermesh.negotiation import (
    ContractNetNegotiator, InspectionCapacitySupplierAgent,
    NegotiationStage, NegotiationStatus, WorkloadBuyerAgent,
)
from ciphermesh.negotiation.agents import canonical_digest
from ciphermesh.negotiation.models import ContractTerms, NegotiationMessage


def test_two_distinct_agents_reach_consensus_and_commit_same_contract():
    buyer = WorkloadBuyerAgent()
    supplier = InspectionCapacitySupplierAgent()
    result = ContractNetNegotiator(buyer, supplier).run()

    assert buyer.agent_id != supplier.agent_id
    assert result.status == NegotiationStatus.AGREED
    assert result.agreed_terms is not None
    assert result.rounds_completed >= 3
    assert result.buyer_utility >= buyer.reservation_utility()
    assert result.supplier_utility >= supplier.reservation_utility()
    assert result.contract_digest in buyer.committed_contracts
    assert result.contract_digest in supplier.committed_contracts
    assert buyer.committed_contracts[result.contract_digest] == supplier.committed_contracts[result.contract_digest]


def test_result_timeline_has_serialized_protocol_messages_and_handshake():
    result = ContractNetNegotiator().run()
    stages = [event.stage for event in result.timeline]
    for stage in ("CALL_FOR_PROPOSAL", "PROPOSAL", "COUNTEROFFER", "PREPARE",
                  "READY", "COMMIT", "COMMIT_ACK", "CONSENSUS_CONFIRMED"):
        assert stage in stages
    assert all(event.message_bytes > 0 for event in result.timeline
               if event.stage not in {"CONSENSUS_CONFIRMED", "TERMINATED"})


def test_restrictive_budget_terminates_without_consensus_within_round_bound():
    result = ContractNetNegotiator(
        buyer=WorkloadBuyerAgent(max_price=120),
        supplier=InspectionCapacitySupplierAgent(),
        max_rounds=6,
    ).run()
    assert result.status == NegotiationStatus.FAILED
    assert result.agreed_terms is None
    assert result.rounds_completed <= 6
    assert "no agreement" in result.termination_reason


def test_unacceptable_supplier_slo_is_rejected():
    supplier = InspectionCapacitySupplierAgent(estimated_recall=0.90)
    result = ContractNetNegotiator(supplier=supplier).run()
    assert result.status == NegotiationStatus.FAILED
    assert "SLOs" in result.termination_reason or "rejected" in result.termination_reason


def test_digest_is_deterministic_for_same_terms():
    terms = ContractTerms(price_per_1000_requests=143.32, capacity_rps=600,
                          p95_latency_ms=18, estimated_recall=0.97)
    assert canonical_digest(terms) == canonical_digest(terms.model_copy())


def test_buyer_supplier_agent_ids_must_be_distinct():
    buyer = WorkloadBuyerAgent(agent_id="same")
    supplier = InspectionCapacitySupplierAgent(agent_id="same")
    try:
        ContractNetNegotiator(buyer, supplier)
    except ValueError as exc:
        assert "distinct" in str(exc)
    else:
        raise AssertionError("same IDs should be rejected")


def test_commit_without_prepare_is_rejected():
    buyer = WorkloadBuyerAgent()
    terms = ContractTerms(price_per_1000_requests=140, capacity_rps=600,
                          p95_latency_ms=18, estimated_recall=0.97)
    msg = NegotiationMessage(negotiation_id="n-test", sender="NEGOTIATION_COORDINATOR",
        recipient=buyer.agent_id, stage=NegotiationStage.COMMIT,
        payload={"contract_digest": canonical_digest(terms)})
    response = buyer.receive(msg)
    assert response.stage == NegotiationStage.ERROR


def test_transport_rejects_oversized_message_and_returns_failure():
    result = ContractNetNegotiator(max_message_bytes=100).run()
    assert result.status == NegotiationStatus.FAILED
    assert result.agreed_terms is None
    assert "message length invalid" in result.termination_reason


def test_prepare_rejects_tampered_contract_digest():
    buyer = WorkloadBuyerAgent()
    terms = ContractTerms(price_per_1000_requests=140, capacity_rps=600,
                          p95_latency_ms=18, estimated_recall=0.97)
    msg = NegotiationMessage(
        negotiation_id="n-tamper", sender="NEGOTIATION_COORDINATOR",
        recipient=buyer.agent_id, stage=NegotiationStage.PREPARE,
        payload={"terms": terms.model_dump(mode="json"), "contract_digest": "0" * 64},
    )
    response = buyer.receive(msg)
    assert response.stage == NegotiationStage.REJECT
    assert "digest mismatch" in response.payload["reason"]
