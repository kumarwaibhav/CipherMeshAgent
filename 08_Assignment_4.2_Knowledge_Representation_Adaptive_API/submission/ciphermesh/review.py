"""Human-in-the-loop approval queue for REVIEW decisions.

The held original text lives only in process memory, is excluded from every
serialization, and is dropped the moment the ticket is decided or expires. An
approved ticket is released only to providers on the local trust tier, so
internal context never leaves the host even after approval.
"""
from __future__ import annotations

import hashlib
import threading
from datetime import datetime, timedelta
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field, PrivateAttr

from .models import utc_now


class ReviewStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


class ReviewTicket(BaseModel):
    review_id: str = Field(default_factory=lambda: f"rev-{uuid4().hex[:12]}")
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    status: ReviewStatus = ReviewStatus.PENDING
    prompt_sha256: str
    categories: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    safe_preview: str | None = None
    requested_provider: str | None = None
    decided_by: str | None = None
    decided_at: datetime | None = None
    restricted_to_local: bool = True
    _held_text: str | None = PrivateAttr(default=None)


class ReviewError(ValueError):
    pass


class ReviewQueue:
    def __init__(self, ttl_seconds: float = 900.0, max_pending: int = 1000):
        if ttl_seconds <= 0 or max_pending < 1:
            raise ValueError("ttl_seconds and max_pending must be positive")
        self.ttl = timedelta(seconds=ttl_seconds)
        self.max_pending = max_pending
        self._tickets: dict[str, ReviewTicket] = {}
        self._lock = threading.Lock()

    def submit(self, text: str, categories: list[str], reasons: list[str],
               safe_preview: str | None, requested_provider: str | None = None) -> ReviewTicket:
        with self._lock:
            self._expire_locked()
            pending = sum(t.status == ReviewStatus.PENDING for t in self._tickets.values())
            if pending >= self.max_pending:
                raise ReviewError("review queue is full; request blocked (fail closed)")
            ticket = ReviewTicket(
                expires_at=utc_now() + self.ttl,
                prompt_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest()[:16],
                categories=sorted(set(categories)), reasons=list(reasons),
                safe_preview=safe_preview, requested_provider=requested_provider,
            )
            ticket._held_text = text
            self._tickets[ticket.review_id] = ticket
            return ticket

    def decide(self, review_id: str, approved: bool, reviewer: str) -> tuple[ReviewTicket, str | None]:
        """Resolve a ticket. Returns the ticket and, only when approved, the held text."""
        if not reviewer or not reviewer.strip():
            raise ReviewError("reviewer identity is required")
        with self._lock:
            self._expire_locked()
            ticket = self._tickets.get(review_id)
            if ticket is None:
                raise ReviewError("unknown review_id")
            if ticket.status != ReviewStatus.PENDING:
                raise ReviewError(f"review already {ticket.status.value.lower()}")
            held = ticket._held_text
            ticket._held_text = None
            ticket.status = ReviewStatus.APPROVED if approved else ReviewStatus.DENIED
            ticket.decided_by = reviewer.strip()[:128]
            ticket.decided_at = utc_now()
            return ticket, (held if approved else None)

    def get(self, review_id: str) -> ReviewTicket | None:
        with self._lock:
            self._expire_locked()
            return self._tickets.get(review_id)

    def list(self, status: ReviewStatus | None = None) -> list[ReviewTicket]:
        with self._lock:
            self._expire_locked()
            tickets = list(self._tickets.values())
        return [t for t in tickets if status is None or t.status == status]

    def _expire_locked(self) -> None:
        now = utc_now()
        for ticket in self._tickets.values():
            if ticket.status == ReviewStatus.PENDING and ticket.expires_at <= now:
                ticket.status = ReviewStatus.EXPIRED
                ticket._held_text = None
