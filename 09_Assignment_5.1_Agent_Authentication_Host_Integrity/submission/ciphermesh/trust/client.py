"""Signing client for trusted hosts: builds SignedCommand envelopes and authenticates replies.

Assignment 5.1 - Agent Authentication and Host Integrity Verification.
Author: Kumar Waibhav Akshat (RA2212704010027).

The client can bind its socket to a chosen local source address (for example
127.0.0.10 for the security console and 127.0.0.66 for an attacker), so the
loopback simulation produces genuinely different peer addresses at the
server's ``accept()``. Replies are accepted only if the agent's Ed25519
signature verifies with the REPLY domain context, the reply is addressed to us,
answers our msg_id, is fresh, and carries a trusted agent integrity digest.
"""
from __future__ import annotations

import argparse
import hmac
import json
import socket
import sys
from dataclasses import dataclass, field
from datetime import timedelta

from . import commands as cmd
from .envelope import REPLY_CONTEXT, EnvelopeError, create_command, encode, parse_and_verify, utc_now
from .integrity import measure
from .keys import SigningIdentity, TrustStore
from ..transport import HEADER, recv_exact

REPLY_MAX_AGE = timedelta(seconds=60)


@dataclass
class ClientReply:
    """``verified`` is True only if the agent signature, addressing, correlation and freshness are all
    correct *and* the agent's attestation digest is a trusted release. ``signature_valid`` reports the
    signature check alone, so a caller can tell a forged reply from a genuine reply sent by an agent
    whose code no longer matches its release (SAFE MODE)."""
    verified: bool
    status: str
    incident: str | None = None
    result: dict = field(default_factory=dict)
    problem: str | None = None
    agent_integrity_trusted: bool = False
    signature_valid: bool = False


def verify_reply(raw: bytes, trust: TrustStore, expected_recipient: str, expected_msg_id: str | None) -> ClientReply:
    def lookup(host_id: str, key_id: str):
        bound = trust.key(key_id)
        if host_id != trust.agent_id or bound is None or bound[0].host_id != host_id:
            return None
        return trust.public_key(key_id)

    try:
        reply = parse_and_verify(raw, lookup, REPLY_CONTEXT)
    except EnvelopeError as exc:
        return ClientReply(False, "UNVERIFIED", problem=exc.code)
    payload = reply.payload
    problem = None
    if reply.header.command != cmd.REPLY:
        problem = "NOT_A_REPLY"
    elif reply.header.recipient != expected_recipient:
        problem = "REPLY_NOT_ADDRESSED_TO_US"
    elif expected_msg_id and payload.get("in_reply_to") != expected_msg_id:
        problem = "REPLY_CORRELATION_MISMATCH"
    elif abs(utc_now() - reply.issued_at) > REPLY_MAX_AGE:
        problem = "REPLY_NOT_FRESH"
    agent_host = trust.host(trust.agent_id)
    trusted = bool(agent_host) and any(hmac.compare_digest(reply.header.integrity, d)
                                       for d in agent_host.trusted_release_digests)
    if problem is None and not trusted:
        problem = "AGENT_INTEGRITY_UNTRUSTED"
    return ClientReply(problem is None and trusted, payload.get("status", "?"), payload.get("incident"),
                       payload.get("result", {}), problem, trusted, signature_valid=True)


class SecureClient:
    def __init__(self, identity: SigningIdentity, trust: TrustStore, port: int, host: str = "127.0.0.1",
                 source_ip: str | None = None, integrity: str | None = None, timeout: float = 5.0):
        self.identity, self.trust = identity, trust
        self.host, self.port, self.source_ip, self.timeout = host, port, source_ip, timeout
        self.integrity = integrity or measure()

    def command(self, command: str, payload: dict | None = None, ttl_s: int = 30, **kwargs) -> dict:
        return create_command(self.identity, self.trust.agent_id, command, payload or {}, self.integrity,
                              ttl_s=ttl_s, **kwargs)

    def send_envelope(self, envelope: dict, recipient_hint: str | None = None) -> ClientReply:
        header = envelope.get("header", {}) if isinstance(envelope, dict) else {}
        return self.send_raw(encode(envelope), expected_recipient=recipient_hint or header.get("sender_host"),
                             expected_msg_id=header.get("msg_id"))

    def send_raw(self, raw: bytes, declared_length: int | None = None, expected_recipient: str | None = None,
                 expected_msg_id: str | None = None) -> ClientReply:
        """Send one frame. ``declared_length`` lets the simulation send a header that lies about size."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            if self.source_ip:
                sock.bind((self.source_ip, 0))
            sock.connect((self.host, self.port))
            length = len(raw) if declared_length is None else declared_length
            sock.sendall(HEADER.pack(length) + (raw if declared_length is None else b""))
            (reply_len,) = HEADER.unpack(recv_exact(sock, HEADER.size))
            reply_raw = recv_exact(sock, reply_len)
        finally:
            sock.close()
        return verify_reply(reply_raw, self.trust, expected_recipient or "unauthenticated-peer", expected_msg_id)


def main(argv: list[str] | None = None) -> int:
    from .provision import DEFAULT_KEYS_DIR, DEFAULT_TRUST_DIR, ensure_provisioned, passphrase_from_env
    sys.dont_write_bytecode = True
    parser = argparse.ArgumentParser(description="Send a signed command to a CipherMesh secure agent")
    parser.add_argument("--as", dest="host_id", required=True, help="trusted host identity to sign as")
    parser.add_argument("--port", type=int, default=9061)
    parser.add_argument("--source", default=None, help="local source IP to bind, e.g. 127.0.0.10")
    parser.add_argument("--trust-dir", default=str(DEFAULT_TRUST_DIR))
    parser.add_argument("--keys-dir", default=str(DEFAULT_KEYS_DIR))
    parser.add_argument("command", choices=sorted(cmd.INBOUND_COMMANDS))
    parser.add_argument("--payload", default="{}", help="JSON payload, e.g. '{\"reason\": \"incident 42\"}'")
    args = parser.parse_args(argv)
    from pathlib import Path
    ensure_provisioned(Path(args.trust_dir), Path(args.keys_dir))
    trust = TrustStore.load(Path(args.trust_dir) / "trusted_hosts.json")
    identity = SigningIdentity.load(args.host_id, Path(args.keys_dir) / f"{args.host_id}.key.pem",
                                    passphrase_from_env())
    client = SecureClient(identity, trust, args.port, source_ip=args.source)
    reply = client.send_envelope(client.command(args.command, json.loads(args.payload)))
    print(json.dumps(reply.__dict__, indent=2))
    return 0 if reply.verified and reply.status == "ACCEPTED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
