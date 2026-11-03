"""Envelope authenticity and freshness (Unit 5 hardening).

A shared token proves only that the sender knows a string that also travels in
every frame. HMAC-SHA256 over the canonical envelope proves the message was
produced by a key holder *and* was not modified in transit; a timestamp window
plus message-ID replay cache bounds replay. Keys never travel on the wire.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import timedelta

from .models import WireMessage, utc_now

DEFAULT_MAX_SKEW_S = 120.0
SIGNATURE_PREFIX = "hmac-sha256="


def canonical_bytes(message: WireMessage) -> bytes:
    body = message.model_dump(mode="json", exclude={"signature", "auth_token"})
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def compute_signature(message: WireMessage, key: str) -> str:
    if not key:
        raise ValueError("signing key must be non-empty")
    digest = hmac.new(key.encode("utf-8"), canonical_bytes(message), hashlib.sha256).hexdigest()
    return SIGNATURE_PREFIX + digest


def sign(message: WireMessage, key: str) -> WireMessage:
    return message.model_copy(update={"signature": compute_signature(message, key)})


def verify(message: WireMessage, key: str, max_skew_s: float = DEFAULT_MAX_SKEW_S) -> str | None:
    """Return ``None`` when authentic and fresh, otherwise a non-secret reason."""
    if not message.signature:
        return "missing signature"
    expected = compute_signature(message, key)
    if not hmac.compare_digest(message.signature, expected):
        return "invalid signature"
    skew = abs((utc_now() - message.timestamp).total_seconds())
    if skew > max_skew_s:
        return f"stale or future-dated message (skew {skew:.0f}s > {max_skew_s:.0f}s)"
    return None


def freshness_window(max_skew_s: float = DEFAULT_MAX_SKEW_S) -> timedelta:
    return timedelta(seconds=max_skew_s)
