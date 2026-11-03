"""Ed25519 identities, PEM key storage and the schema-validated trust store.

Assignment 5.1 - Agent Authentication and Host Integrity Verification.
Author: Kumar Waibhav Akshat (RA2212704010027).

Trust model
-----------
Assignment 2.2 used one shared HMAC key on every node. Anyone who can *verify*
an HMAC can also *create* one, so a single compromised gateway could forge
commands for the whole mesh, and one host could not be revoked without
re-keying everyone. Here each host owns an Ed25519 key pair (RFC 8032). The
agent keeps only public keys in ``trusted_hosts.json``: it can check a
signature but can never produce one in a host's name. Each key is bound to one
host, has a validity window, and can be revoked on its own.

Private keys are written as PKCS#8 PEM, encrypted with a passphrase when one is
given, with file mode 0600, and are never logged or printed (the identity
object hides them from ``repr``).
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .commands import KNOWN_COMMANDS

HOST_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{2,63}$"
HEX16 = r"^[0-9a-f]{16}$"
HEX64 = r"^[0-9a-f]{64}$"
LOCAL_SOURCE = "local"
TRUST_SCHEMA_VERSION = "cm-trust/1"


class KeyHandlingError(Exception):
    """Raised for unsafe, corrupt or wrongly-typed key material."""


class TrustStoreError(Exception):
    """The trust store file is missing, unsafe or fails schema validation."""


# --------------------------------------------------------------------------- keys

def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def raw_public_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id_for(public_key: Ed25519PublicKey) -> str:
    """Key id = first 16 hex characters of SHA-256 over the 32-byte raw public key."""
    return hashlib.sha256(raw_public_bytes(public_key)).hexdigest()[:16]


def public_key_to_b64(public_key: Ed25519PublicKey) -> str:
    return base64.b64encode(raw_public_bytes(public_key)).decode("ascii")


def public_key_from_b64(text: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as exc:
        raise KeyHandlingError("public key is not valid base64") from exc
    if len(raw) != 32:
        raise KeyHandlingError("Ed25519 public key must be exactly 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def save_private_key(path: str | Path, key: Ed25519PrivateKey, passphrase: bytes | None) -> None:
    """Write a PKCS#8 PEM private key with mode 0600 (encrypted when a passphrase is given)."""
    encryption = (serialization.BestAvailableEncryption(passphrase) if passphrase
                  else serialization.NoEncryption())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    _write_private(Path(path), pem)


def load_private_key(path: str | Path, passphrase: bytes | None) -> Ed25519PrivateKey:
    """Load a private key, refusing files readable by group or others (like OpenSSH does)."""
    path = Path(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise KeyHandlingError(f"private key file {path.name} has unsafe permissions {oct(mode)}; expected 0600")
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=passphrase)
    except (ValueError, TypeError) as exc:
        raise KeyHandlingError(f"cannot load private key {path.name}: wrong passphrase or corrupt file") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyHandlingError(f"{path.name} is not an Ed25519 private key")
    return key


def save_public_key(path: str | Path, public_key: Ed25519PublicKey) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(public_key.public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo))
    os.chmod(path, 0o644)


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise KeyHandlingError(f"{Path(path).name} is not an Ed25519 public key")
    return key


def verify_signature(public_key: Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


@dataclass(frozen=True)
class SigningIdentity:
    """A host's private signing identity. The private key never appears in repr/str."""
    host_id: str
    private_key: Ed25519PrivateKey = field(repr=False)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def key_id(self) -> str:
        return key_id_for(self.public_key)

    @property
    def public_key_b64(self) -> str:
        return public_key_to_b64(self.public_key)

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)

    @classmethod
    def generate(cls, host_id: str) -> "SigningIdentity":
        return cls(host_id, generate_private_key())

    @classmethod
    def load(cls, host_id: str, path: str | Path, passphrase: bytes | None) -> "SigningIdentity":
        return cls(host_id, load_private_key(path, passphrase))


# ------------------------------------------------------------------ trust store

def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamps must carry a timezone (use ...Z for UTC)")
    return value.astimezone(timezone.utc)


class KeyRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key_id: str = Field(pattern=HEX16)
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key: str = Field(min_length=40, max_length=64)
    valid_from: datetime
    valid_until: datetime
    revoked: bool = False
    note: str = Field(default="", max_length=200)

    _tz = field_validator("valid_from", "valid_until")(_aware)

    @model_validator(mode="after")
    def _check(self) -> "KeyRecord":
        try:
            public = public_key_from_b64(self.public_key)
        except KeyHandlingError as exc:
            raise ValueError(str(exc)) from None
        if key_id_for(public) != self.key_id:
            raise ValueError(f"key_id {self.key_id} does not match SHA-256 of its public key")
        if self.valid_until <= self.valid_from:
            raise ValueError(f"key {self.key_id}: valid_until must be after valid_from")
        return self


class TrustedHost(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host_id: str = Field(pattern=HOST_ID_PATTERN)
    display_name: str = Field(min_length=1, max_length=120)
    roles: list[str] = Field(min_length=1, max_length=8)
    allowed_sources: list[str] = Field(min_length=1, max_length=32)
    keys: list[KeyRecord] = Field(min_length=1, max_length=8)
    trusted_release_digests: list[str] = Field(default_factory=list, max_length=8)
    valid_from: datetime
    valid_until: datetime
    revoked: bool = False

    _tz = field_validator("valid_from", "valid_until")(_aware)

    @field_validator("allowed_sources")
    @classmethod
    def _sources(cls, values: list[str]) -> list[str]:
        for value in values:
            if value == LOCAL_SOURCE:
                continue
            try:
                ipaddress.ip_network(value, strict=True)
            except ValueError:
                raise ValueError(f"allowed source {value!r} is not a CIDR block or 'local'") from None
        return values

    @field_validator("trusted_release_digests")
    @classmethod
    def _digests(cls, values: list[str]) -> list[str]:
        for value in values:
            if not re.fullmatch(HEX64, value):
                raise ValueError("trusted_release_digests must be 64-character lowercase hex SHA-256 values")
        return values

    @model_validator(mode="after")
    def _window(self) -> "TrustedHost":
        if self.valid_until <= self.valid_from:
            raise ValueError(f"host {self.host_id}: valid_until must be after valid_from")
        return self


class RevokedKey(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key_id: str = Field(pattern=HEX16)
    revoked_at: datetime
    reason: str = Field(min_length=1, max_length=200)

    _tz = field_validator("revoked_at")(_aware)


class TrustStoreDocument(BaseModel):
    """Schema of ``trusted_hosts.json``. Unknown fields anywhere are rejected."""
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["cm-trust/1"]
    issuer: str = Field(min_length=1, max_length=120)
    generated_at: datetime
    agent_id: str = Field(pattern=HOST_ID_PATTERN)
    roles: dict[str, list[str]]
    hosts: list[TrustedHost] = Field(min_length=1, max_length=256)
    revocation_list: list[RevokedKey] = Field(default_factory=list)

    _tz = field_validator("generated_at")(_aware)

    @model_validator(mode="after")
    def _semantics(self) -> "TrustStoreDocument":
        for role, commands in self.roles.items():
            unknown = set(commands) - KNOWN_COMMANDS
            if unknown:
                raise ValueError(f"role {role!r} grants unknown commands {sorted(unknown)}")
        seen_hosts: set[str] = set()
        seen_keys: dict[str, str] = {}
        for host in self.hosts:
            if host.host_id in seen_hosts:
                raise ValueError(f"duplicate host_id {host.host_id!r}")
            seen_hosts.add(host.host_id)
            for role in host.roles:
                if role not in self.roles:
                    raise ValueError(f"host {host.host_id} uses undefined role {role!r}")
            for key in host.keys:
                if key.key_id in seen_keys:
                    raise ValueError(f"key {key.key_id} is bound to both {seen_keys[key.key_id]} "
                                     f"and {host.host_id}; a key must belong to exactly one host")
                seen_keys[key.key_id] = host.host_id
        if self.agent_id not in seen_hosts:
            raise ValueError(f"agent_id {self.agent_id!r} must itself be listed as a host")
        return self


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class TrustStore:
    """In-memory, indexed view of a validated trust store document."""

    def __init__(self, document: TrustStoreDocument, source: Path | None = None):
        self.document = document
        self.source = source
        self._reindex()

    def _reindex(self) -> None:
        doc = self.document
        self._hosts = {host.host_id: host for host in doc.hosts}
        self._keys = {key.key_id: (host, key) for host in doc.hosts for key in host.keys}
        self._revoked = {entry.key_id: entry for entry in doc.revocation_list}
        self._networks = {
            host.host_id: [ipaddress.ip_network(s) for s in host.allowed_sources if s != LOCAL_SOURCE]
            for host in doc.hosts
        }
        self._public_cache: dict[str, Ed25519PublicKey] = {}

    # ---------------------------------------------------------------- loading
    @classmethod
    def load(cls, path: str | Path) -> "TrustStore":
        path = Path(path)
        if not path.is_file():
            raise TrustStoreError(f"trust store not found: {path}")
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o022:
            raise TrustStoreError(f"trust store {path.name} is writable by group/others ({oct(mode)}); refusing")
        return cls.from_bytes(path.read_bytes(), source=path)

    @classmethod
    def from_bytes(cls, raw: bytes, source: Path | None = None) -> "TrustStore":
        from .canonical import StrictJSONError, strict_loads
        try:
            data = strict_loads(raw)
        except StrictJSONError as exc:
            raise TrustStoreError(f"trust store is not strict JSON: {exc.detail}") from None
        try:
            return cls(TrustStoreDocument.model_validate(data), source)
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(p) for p in first.get("loc", ()))
            raise TrustStoreError(f"trust store schema violation at {where or '<root>'}: {first['msg']}") from None

    def to_json_bytes(self) -> bytes:
        data = self.document.model_dump(mode="json")
        return (json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False) + "\n").encode("utf-8")

    def save(self, path: str | Path) -> Path:
        """Atomic write with mode 0644 (readable by the agent, writable only by the owner)."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(self.to_json_bytes())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        self.source = path
        return path

    def sha256(self) -> str:
        return hashlib.sha256(self.to_json_bytes()).hexdigest()

    # ---------------------------------------------------------------- lookups
    @property
    def agent_id(self) -> str:
        return self.document.agent_id

    def host(self, host_id: str) -> TrustedHost | None:
        return self._hosts.get(host_id)

    def key(self, key_id: str) -> tuple[TrustedHost, KeyRecord] | None:
        return self._keys.get(key_id)

    def revocation(self, key_id: str) -> RevokedKey | None:
        return self._revoked.get(key_id)

    def public_key(self, key_id: str) -> Ed25519PublicKey:
        cached = self._public_cache.get(key_id)
        if cached is None:
            cached = public_key_from_b64(self._keys[key_id][1].public_key)
            self._public_cache[key_id] = cached
        return cached

    def capabilities(self, host: TrustedHost) -> frozenset[str]:
        granted: set[str] = set()
        for role in host.roles:
            granted.update(self.document.roles.get(role, []))
        return frozenset(granted)

    def origin_allowed(self, host: TrustedHost, address: str) -> bool:
        if address == LOCAL_SOURCE:
            return LOCAL_SOURCE in host.allowed_sources
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(ip in network for network in self._networks.get(host.host_id, []))

    # ------------------------------------------------------- key lifecycle
    def add_key(self, host_id: str, public_key: Ed25519PublicKey, valid_from: datetime,
                valid_until: datetime, note: str = "") -> KeyRecord:
        """Key rotation step 1: publish the new key next to the old one."""
        host = self._require(host_id)
        record = KeyRecord(key_id=key_id_for(public_key), public_key=public_key_to_b64(public_key),
                           valid_from=valid_from, valid_until=valid_until, note=note)
        updated = host.model_copy(update={"keys": [*host.keys, record]})
        self._replace_host(updated)
        return record

    def revoke_key(self, key_id: str, reason: str, when: datetime) -> None:
        """Key rotation step 2 (or incident response): revoke a key without touching other hosts."""
        found = self._keys.get(key_id)
        if found is None:
            raise TrustStoreError(f"unknown key {key_id}")
        host, record = found
        keys = [k.model_copy(update={"revoked": True}) if k.key_id == key_id else k for k in host.keys]
        self._replace_host(host.model_copy(update={"keys": keys}))
        if key_id not in self._revoked:
            entry = RevokedKey(key_id=key_id, revoked_at=when, reason=reason)
            self.document = self.document.model_copy(
                update={"revocation_list": [*self.document.revocation_list, entry]})
        self._revalidate()

    def revoke_host(self, host_id: str) -> None:
        host = self._require(host_id)
        self._replace_host(host.model_copy(update={"revoked": True}))

    def _require(self, host_id: str) -> TrustedHost:
        host = self._hosts.get(host_id)
        if host is None:
            raise TrustStoreError(f"unknown host {host_id}")
        return host

    def _replace_host(self, updated: TrustedHost) -> None:
        hosts = [updated if h.host_id == updated.host_id else h for h in self.document.hosts]
        self.document = self.document.model_copy(update={"hosts": hosts})
        self._revalidate()

    def _revalidate(self) -> None:
        self.document = TrustStoreDocument.model_validate(self.document.model_dump(mode="json"))
        self._reindex()


__all__ = [
    "SigningIdentity", "TrustStore", "TrustStoreDocument", "TrustedHost", "KeyRecord", "RevokedKey",
    "TrustStoreError", "KeyHandlingError", "generate_private_key", "key_id_for", "public_key_to_b64",
    "public_key_from_b64", "save_private_key", "load_private_key", "save_public_key", "load_public_key",
    "verify_signature", "LOCAL_SOURCE", "TRUST_SCHEMA_VERSION",
]
