"""SignedCommand envelope: strict schema, canonical signing input, sign / parse_and_verify.

Assignment 5.1 - Agent Authentication and Host Integrity Verification.
Author: Kumar Waibhav Akshat (RA2212704010027).

Wire form (one length-prefixed frame, see :mod:`ciphermesh.transport`)::

    {"header":  {version, msg_id, sender_host, key_id, recipient, command,
                 issued_at, expires_at, nonce, payload_sha256, integrity},
     "payload": {... command specific, schema checked ...},
     "signature": "<base64 Ed25519 signature, 64 bytes>"}

The signature is Ed25519 (RFC 8032) over::

    DOMAIN_CONTEXT || canonical_json({"header": header, "payload": payload})

``DOMAIN_CONTEXT`` differs for commands, replies and release manifests, so a
signature made for one purpose can never be replayed as another (domain
separation). The receiver re-canonicalises the *parsed* object before
verifying, so whitespace or key order on the wire does not matter, while any
change to a value does.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from . import commands as cmd
from .canonical import StrictJSONError, canonicalize, strict_loads
from .keys import HEX16, HEX64, HOST_ID_PATTERN, SigningIdentity, verify_signature

ENVELOPE_VERSION = "cm-sig/1"
SUPPORTED_VERSIONS = frozenset({ENVELOPE_VERSION})
COMMAND_CONTEXT = b"CipherMesh/SignedCommand/v1\x00"
REPLY_CONTEXT = b"CipherMesh/SignedReply/v1\x00"
DEFAULT_TTL_S = 30
MAX_TTL_S = 120
UUID4 = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
TIMESTAMP = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
SIGNATURE_B64 = r"^[A-Za-z0-9+/]{86}==$"


class EnvelopeError(ValueError):
    """Parsing or verification failure with a stable, non-secret reason code."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# ------------------------------------------------------------------ schema

class Header(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    version: str = Field(pattern=r"^cm-sig/\d{1,3}$")
    msg_id: str = Field(pattern=UUID4)
    sender_host: str = Field(pattern=HOST_ID_PATTERN)
    key_id: str = Field(pattern=HEX16)
    recipient: str = Field(pattern=HOST_ID_PATTERN)
    command: str = Field(min_length=1, max_length=40)
    issued_at: str = Field(pattern=TIMESTAMP)
    expires_at: str = Field(pattern=TIMESTAMP)
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    payload_sha256: str = Field(pattern=HEX64)
    integrity: str = Field(pattern=HEX64)

    @field_validator("command")
    @classmethod
    def _known(cls, value: str) -> str:
        if value not in cmd.KNOWN_COMMANDS:
            raise ValueError(f"unknown command {value!r}")
        return value

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _parsable(cls, value: str) -> str:
        parse_ts(value)
        return value


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ReasonPayload(_Strict):
    reason: str = Field(min_length=1, max_length=200)


class PatternsPayload(_Strict):
    patterns: list[str] = Field(min_length=1, max_length=32)

    @field_validator("patterns")
    @classmethod
    def _sizes(cls, values: list[str]) -> list[str]:
        if any(not (1 <= len(v) <= 128) for v in values):
            raise ValueError("each pattern must be 1..128 characters")
        return values


class EmptyPayload(_Strict):
    pass


class StateSyncPayload(_Strict):
    state: dict[str, Any]


class InspectPayload(_Strict):
    text: str = Field(min_length=1, max_length=65536)


class ReplyPayload(_Strict):
    in_reply_to: str = Field(min_length=1, max_length=64)
    status: str = Field(pattern=r"^(ACCEPTED|REJECTED|FAILED)$")
    incident: str | None = None
    result: dict[str, Any] = Field(default_factory=dict)


PAYLOAD_SCHEMAS: dict[str, type[BaseModel]] = {
    cmd.TRIGGER_EMERGENCY_LOCKDOWN: ReasonPayload,
    cmd.RELEASE_LOCKDOWN: ReasonPayload,
    cmd.UPDATE_REDACTION_PATTERNS: PatternsPayload,
    cmd.REQUEST_TELEMETRY_DUMP: EmptyPayload,
    cmd.STATE_SYNC: StateSyncPayload,
    cmd.INSPECT: InspectPayload,
    cmd.PING: EmptyPayload,
    cmd.REPLY: ReplyPayload,
}


# ---------------------------------------------------------------- helpers

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_ts(value: datetime) -> str:
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def parse_ts(text: str) -> datetime:
    if not re.fullmatch(TIMESTAMP, text):
        raise ValueError("timestamp must be RFC 3339 UTC with milliseconds, e.g. 2026-11-01T10:00:00.000Z")
    return datetime.fromisoformat(text[:-1]).replace(tzinfo=timezone.utc)


def payload_digest(payload: dict) -> str:
    return hashlib.sha256(canonicalize(payload)).hexdigest()


def signing_bytes(header: dict, payload: dict, context: bytes = COMMAND_CONTEXT) -> bytes:
    """Exact bytes covered by the Ed25519 signature."""
    return context + canonicalize({"header": header, "payload": payload})


def new_nonce() -> str:
    return secrets.token_hex(16)


def build_header(identity: SigningIdentity, recipient: str, command: str, payload: dict, integrity: str,
                 ttl_s: int = DEFAULT_TTL_S, now: datetime | None = None,
                 msg_id: str | None = None, nonce: str | None = None) -> dict:
    issued = now or utc_now()
    return {
        "version": ENVELOPE_VERSION,
        "msg_id": msg_id or str(uuid.uuid4()),
        "sender_host": identity.host_id,
        "key_id": identity.key_id,
        "recipient": recipient,
        "command": command,
        "issued_at": format_ts(issued),
        "expires_at": format_ts(issued + timedelta(seconds=ttl_s)),
        "nonce": nonce or new_nonce(),
        "payload_sha256": payload_digest(payload),
        "integrity": integrity,
    }


def sign(identity: SigningIdentity, header: dict, payload: dict, context: bytes = COMMAND_CONTEXT) -> dict:
    """Return a complete envelope dict carrying an Ed25519 signature over header + payload."""
    signature = identity.sign(signing_bytes(header, payload, context))
    return {"header": dict(header), "payload": payload, "signature": base64.b64encode(signature).decode("ascii")}


def create_command(identity: SigningIdentity, recipient: str, command: str, payload: dict, integrity: str,
                   ttl_s: int = DEFAULT_TTL_S, now: datetime | None = None) -> dict:
    header = build_header(identity, recipient, command, payload, integrity, ttl_s=ttl_s, now=now)
    return sign(identity, header, payload)


def encode(envelope: dict) -> bytes:
    """Serialise an envelope for the wire (canonical form keeps frames deterministic)."""
    return canonicalize(envelope)


# ----------------------------------------------------------------- parsing

@dataclass(frozen=True)
class SignedCommand:
    header: Header
    payload: dict
    signature: bytes
    frame_bytes: int

    @property
    def header_dict(self) -> dict:
        return self.header.model_dump()

    def signing_input(self, context: bytes = COMMAND_CONTEXT) -> bytes:
        return signing_bytes(self.header_dict, self.payload, context)

    @property
    def issued_at(self) -> datetime:
        return parse_ts(self.header.issued_at)

    @property
    def expires_at(self) -> datetime:
        return parse_ts(self.header.expires_at)


def _first_error(exc: ValidationError, prefix: str) -> str:
    first = exc.errors()[0]
    where = ".".join(str(p) for p in first.get("loc", ()))
    return f"{prefix}{'.' + where if where else ''}: {first['msg']}"


def parse(raw: bytes) -> SignedCommand:
    """Strict JSON parse + full schema validation (checkpoint C2). Never trusts content yet."""
    try:
        data = strict_loads(raw)
    except StrictJSONError as exc:
        raise EnvelopeError(exc.code, exc.detail) from None
    if not isinstance(data, dict):
        raise EnvelopeError("SCHEMA_VIOLATION", "envelope must be a JSON object")
    expected = {"header", "payload", "signature"}
    missing, unknown = expected - data.keys(), data.keys() - expected
    if missing:
        raise EnvelopeError("SCHEMA_VIOLATION", f"envelope is missing {sorted(missing)}")
    if unknown:
        raise EnvelopeError("SCHEMA_VIOLATION", f"envelope has unknown fields {sorted(unknown)}")
    if not isinstance(data["header"], dict) or not isinstance(data["payload"], dict):
        raise EnvelopeError("SCHEMA_VIOLATION", "header and payload must be JSON objects")
    try:
        header = Header.model_validate(data["header"])
    except ValidationError as exc:
        raise EnvelopeError("SCHEMA_VIOLATION", _first_error(exc, "header")) from None
    schema = PAYLOAD_SCHEMAS[header.command]
    try:
        schema.model_validate(data["payload"])
    except ValidationError as exc:
        raise EnvelopeError("SCHEMA_VIOLATION", _first_error(exc, f"payload[{header.command}]")) from None
    signature_text = data["signature"]
    if not isinstance(signature_text, str) or not re.fullmatch(SIGNATURE_B64, signature_text):
        raise EnvelopeError("SCHEMA_VIOLATION", "signature must be base64 of a 64-byte Ed25519 signature")
    signature = base64.b64decode(signature_text, validate=True)
    try:
        canonicalize(data["payload"])
    except ValueError as exc:
        raise EnvelopeError("SCHEMA_VIOLATION", f"payload is not canonicalisable: {exc}") from None
    return SignedCommand(header, data["payload"], signature, len(raw))


PublicKeyLookup = Callable[[str, str], "Ed25519PublicKey | None"]


def parse_and_verify(raw: bytes, lookup: PublicKeyLookup, context: bytes = COMMAND_CONTEXT) -> SignedCommand:
    """Parse, then verify the Ed25519 signature and payload digest.

    ``lookup(sender_host, key_id)`` must return the trusted public key bound to
    that host, or ``None``. This is the light-weight check used by clients to
    authenticate agent replies; the agent itself uses the full
    :class:`~ciphermesh.trust.verifier.CommandVerifier` pipeline.
    """
    message = parse(raw)
    if message.header.version not in SUPPORTED_VERSIONS:
        raise EnvelopeError("UNSUPPORTED_VERSION", f"version {message.header.version} is not supported")
    public_key = lookup(message.header.sender_host, message.header.key_id)
    if public_key is None:
        raise EnvelopeError("KEY_NOT_BOUND", "no trusted key for this sender/key_id pair")
    if not verify_signature(public_key, message.signature, message.signing_input(context)):
        raise EnvelopeError("BAD_SIGNATURE", "Ed25519 signature does not verify over the canonical bytes")
    if not hmac.compare_digest(payload_digest(message.payload), message.header.payload_sha256):
        raise EnvelopeError("PAYLOAD_HASH_MISMATCH", "payload_sha256 does not match the payload")
    return message


__all__ = [
    "ENVELOPE_VERSION", "SUPPORTED_VERSIONS", "COMMAND_CONTEXT", "REPLY_CONTEXT", "DEFAULT_TTL_S", "MAX_TTL_S",
    "EnvelopeError", "Header", "SignedCommand", "PAYLOAD_SCHEMAS", "build_header", "sign", "create_command",
    "encode", "parse", "parse_and_verify", "payload_digest", "signing_bytes", "format_ts", "parse_ts",
    "utc_now", "new_nonce",
]
