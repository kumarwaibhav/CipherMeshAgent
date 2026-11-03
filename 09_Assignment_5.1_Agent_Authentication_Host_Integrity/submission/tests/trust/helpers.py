"""Helpers for the Assignment 5.1 trust-layer tests.

Author: Kumar Waibhav Akshat (RA2212704010027).
"""
from __future__ import annotations

from datetime import timedelta

from ciphermesh.trust import commands as cmd
from ciphermesh.trust.envelope import build_header, encode, sign, utc_now
from ciphermesh.trust.verifier import Origin

PASS = b"unit-test-passphrase"
ADMIN_IP, OBSERVER_IP, PEER_IP = "127.0.0.10", "127.0.0.20", "127.0.0.30"


def tcp(ip: str = ADMIN_IP) -> Origin:
    return Origin("tcp", ip, "40000")


def frame(prov, identity, command=cmd.TRIGGER_EMERGENCY_LOCKDOWN, payload=None, *, shift_s: float = 0.0,
          ttl_s: int = 30, integrity: str | None = None, recipient: str | None = None, nonce: str | None = None,
          msg_id: str | None = None, mutate_header=None, mutate_payload=None, raw_env: bool = False):
    """Build (and optionally corrupt) a signed command frame."""
    if payload is None:
        payload = {"reason": "unit test"} if command in (cmd.TRIGGER_EMERGENCY_LOCKDOWN, cmd.RELEASE_LOCKDOWN) else {}
    header = build_header(identity, recipient or prov.trust_store.agent_id, command, payload,
                          integrity or prov.release_digest, ttl_s=ttl_s, now=utc_now() + timedelta(seconds=shift_s),
                          nonce=nonce, msg_id=msg_id)
    if mutate_header:
        mutate_header(header)
    env = sign(identity, header, payload)
    if mutate_payload:
        mutate_payload(env)
    return env if raw_env else encode(env)
