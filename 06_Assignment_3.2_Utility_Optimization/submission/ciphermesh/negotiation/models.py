"""Typed message and contract models for CipherMesh multi-agent negotiation."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class NegotiationStage(str, Enum):
    CALL_FOR_PROPOSAL = "CALL_FOR_PROPOSAL"
    PROPOSAL = "PROPOSAL"
    COUNTEROFFER = "COUNTEROFFER"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    PREPARE = "PREPARE"
    READY = "READY"
    COMMIT = "COMMIT"
    COMMIT_ACK = "COMMIT_ACK"
    ABORT = "ABORT"
    ABORT_ACK = "ABORT_ACK"
    ERROR = "ERROR"


class NegotiationStatus(str, Enum):
    AGREED = "AGREED"
    FAILED = "FAILED"
    IN_DOUBT = "IN_DOUBT"


class ContractTerms(BaseModel):
    """The negotiated contract; scenario metrics are illustrative, not benchmarks."""
    model_config = ConfigDict(extra="forbid")

    service_name: str = "CipherMesh privacy-inspection capacity"
    price_per_1000_requests: float = Field(gt=0, le=100_000)
    capacity_rps: int = Field(gt=0, le=1_000_000)
    p95_latency_ms: float = Field(gt=0, le=60_000)
    estimated_recall: float = Field(ge=0, le=1)
    contract_duration_hours: int = Field(default=24, ge=1, le=8760)
    metrics_source: str = "illustrative_demo_profile"


class NegotiationMessage(BaseModel):
    """Serialized protocol envelope. All negotiation stages use the same schema."""
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"] = "1"
    message_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=64)
    negotiation_id: str = Field(min_length=1, max_length=64)
    sender: str = Field(min_length=1, max_length=128)
    recipient: str = Field(min_length=1, max_length=128)
    stage: NegotiationStage
    turn: int = Field(default=0, ge=0, le=1000)
    timestamp: datetime = Field(default_factory=utc_now)
    correlation_id: str | None = Field(default=None, max_length=64)
    payload: dict[str, Any] = Field(default_factory=dict)


class TimelineEvent(BaseModel):
    sequence: int = Field(ge=1)
    turn: int = Field(ge=0)
    sender: str
    recipient: str
    stage: str
    summary: str
    message_bytes: int = Field(ge=0)


class NegotiationResult(BaseModel):
    negotiation_id: str
    status: NegotiationStatus
    rounds_completed: int = Field(ge=0)
    agreed_terms: ContractTerms | None = None
    contract_digest: str | None = None
    buyer_utility: float | None = None
    supplier_utility: float | None = None
    message_count: int = Field(ge=0)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    termination_reason: str
    notes: list[str] = Field(default_factory=list)
