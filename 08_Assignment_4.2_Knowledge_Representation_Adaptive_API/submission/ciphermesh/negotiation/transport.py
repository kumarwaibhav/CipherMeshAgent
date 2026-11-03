"""Deterministic serialized request/response bus for a local negotiation run."""
from __future__ import annotations

from typing import Protocol

from pydantic import ValidationError

from .models import NegotiationMessage, TimelineEvent

MAX_MESSAGE_BYTES = 64 * 1024


class Endpoint(Protocol):
    agent_id: str
    def receive(self, message: NegotiationMessage) -> NegotiationMessage: ...


class NegotiationTransportError(RuntimeError):
    pass


class SerializedMessageBus:
    """JSON encode/decode on every hop, with schema/size/correlation checks and timeline."""
    def __init__(self, endpoints: list[Endpoint], max_message_bytes: int = MAX_MESSAGE_BYTES):
        self.endpoints = {endpoint.agent_id: endpoint for endpoint in endpoints}
        self.max_message_bytes = max_message_bytes
        self.events: list[TimelineEvent] = []

    def request(self, message: NegotiationMessage) -> NegotiationMessage:
        endpoint = self.endpoints.get(message.recipient)
        if endpoint is None:
            raise NegotiationTransportError(f"unknown recipient: {message.recipient}")
        outbound = message.model_dump_json().encode("utf-8")
        if not outbound or len(outbound) > self.max_message_bytes:
            raise NegotiationTransportError(f"outbound message length invalid: {len(outbound)}")
        try:
            inbound = NegotiationMessage.model_validate_json(outbound)
        except (ValidationError, ValueError) as exc:
            raise NegotiationTransportError(f"outbound serialization validation failed: {exc}") from exc
        self._record(inbound, len(outbound), self._summary(inbound))

        try:
            response = endpoint.receive(inbound)
            response_bytes = response.model_dump_json().encode("utf-8")
            if not response_bytes or len(response_bytes) > self.max_message_bytes:
                raise NegotiationTransportError(f"response length invalid: {len(response_bytes)}")
            response_wire = NegotiationMessage.model_validate_json(response_bytes)
        except (ValidationError, ValueError) as exc:
            raise NegotiationTransportError(f"response schema validation failed: {exc}") from exc
        if (response_wire.sender != message.recipient
                or response_wire.recipient != message.sender
                or response_wire.correlation_id != message.message_id
                or response_wire.negotiation_id != message.negotiation_id):
            raise NegotiationTransportError("response identity/correlation mismatch")
        self._record(response_wire, len(response_bytes), self._summary(response_wire))
        return response_wire

    def record_coordinator_note(self, turn: int, summary: str, stage: str = "COORDINATOR") -> None:
        self.events.append(TimelineEvent(sequence=len(self.events) + 1, turn=turn,
            sender="NEGOTIATION_COORDINATOR", recipient="LOCAL_RUNTIME", stage=stage,
            summary=summary, message_bytes=0))

    def _record(self, message: NegotiationMessage, size: int, summary: str) -> None:
        self.events.append(TimelineEvent(sequence=len(self.events) + 1, turn=message.turn,
            sender=message.sender, recipient=message.recipient, stage=message.stage.value,
            summary=summary, message_bytes=size))

    @staticmethod
    def _summary(message: NegotiationMessage) -> str:
        p = message.payload
        terms = p.get("terms")
        price = terms.get("price_per_1000_requests") if isinstance(terms, dict) else None
        parts: list[str] = []
        if isinstance(price, (int, float)):
            parts.append(f"price=${price:.2f}/1k")
        for metric, label in (("buyer_utility", "buyer U"), ("supplier_utility", "supplier U"),
                              ("utility", "utility"), ("aspiration_utility", "aspiration")):
            value = p.get(metric)
            if isinstance(value, (int, float)):
                parts.append(f"{label}={value:.1f}")
        if p.get("command"):
            parts.append(f"command={p['command']}")
        if p.get("contract_digest"):
            parts.append(f"digest={str(p['contract_digest'])[:12]}...")
        if p.get("status"):
            parts.append(f"status={p['status']}")
        if p.get("reason"):
            parts.append(str(p['reason']))
        if p.get("error"):
            parts.append(str(p['error']))
        if p.get("constraints"):
            parts.append("CFP carries buyer budget/SLO constraints")
        if p.get("metrics_note"):
            parts.append(str(p['metrics_note']))
        return "; ".join(parts) if parts else "typed message"
