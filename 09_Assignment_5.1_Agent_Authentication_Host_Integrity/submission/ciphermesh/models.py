"""Typed wire and policy models for CipherMesh."""
from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


DECISION_PRIORITY = {Decision.ALLOW: 0, Decision.REDACT: 1, Decision.REVIEW: 2, Decision.BLOCK: 3}


class MessageType(str, Enum):
    PING = "PING"
    STATE_SYNC = "STATE_SYNC"
    INSPECT = "INSPECT"
    PROCESS = "PROCESS"
    COMMAND_INSTRUCTION = "COMMAND_INSTRUCTION"
    POLICY_UPDATE = "POLICY_UPDATE"
    APPROVAL = "APPROVAL"
    ACK = "ACK"
    ERROR = "ERROR"


class Finding(BaseModel):
    """A finding intentionally omits the matched value to avoid echoing secrets."""
    category: str
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    confidence: float = Field(ge=0, le=1)
    source: str = "regex"
    rule: str = ""
    severity: str = ""


class InspectionResult(BaseModel):
    decision: Decision
    findings: list[Finding] = Field(default_factory=list)
    sanitized_text: str | None = None
    safe_preview: str | None = None
    reasons: list[str] = Field(default_factory=list)
    policy_version: str = "1.0"
    review_id: str | None = None
    latency_ms: float | None = None


class AgentState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1, max_length=128)
    policy_version: str = "1.0"
    policy_revision: int = Field(default=1, ge=1)
    provider_allowlist: list[str] = Field(default_factory=lambda: ["local"])
    max_prompt_bytes: int = Field(default=65536, ge=1, le=1048576)
    require_review_for_internal_urls: bool = True
    redact_email_phone_ip: bool = True
    block_critical_secrets: bool = True
    force_block_all: bool = False
    custom_redaction_patterns: list[str] = Field(default_factory=list, max_length=32)
    sequence: int = Field(default=0, ge=0)
    updated_at: datetime = Field(default_factory=utc_now)


class WireMessage(BaseModel):
    """A strict typed JSON envelope carried inside a length-prefixed TCP frame.

    ``signature`` is an optional HMAC-SHA256 over the canonical envelope
    (see :mod:`ciphermesh.security`); ``auth_token`` is the legacy shared token.
    """
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1"] = "1"
    message_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=64)
    message_type: MessageType
    sender: str = Field(min_length=1, max_length=128)
    recipient: str = Field(min_length=1, max_length=128)
    timestamp: datetime = Field(default_factory=utc_now)
    correlation_id: str | None = None
    auth_token: str | None = Field(default=None, repr=False)
    signature: str | None = Field(default=None, repr=False, max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict)


class AuditEvent(BaseModel):
    timestamp: datetime = Field(default_factory=utc_now)
    agent_id: str
    event_type: str
    decision: Decision | None = None
    categories: list[str] = Field(default_factory=list)
    message_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
