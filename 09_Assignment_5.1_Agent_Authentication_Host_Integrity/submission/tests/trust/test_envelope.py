"""SignedCommand envelope tests: signing input, tamper detection, schemas, domain separation.

Author: Kumar Waibhav Akshat (RA2212704010027).
"""
import json

import pytest

from ciphermesh.trust import commands as cmd
from ciphermesh.trust.envelope import (COMMAND_CONTEXT, REPLY_CONTEXT, EnvelopeError, create_command, encode, parse,
                                       parse_and_verify, payload_digest, signing_bytes)


def lookup_for(identity):
    return lambda host, key_id: identity.public_key if (host, key_id) == (identity.host_id, identity.key_id) else None


def test_create_parse_and_verify_round_trip(prov, ids):
    admin = ids["sec-console-01"]
    env = create_command(admin, "ciphermesh-node-01", cmd.UPDATE_REDACTION_PATTERNS, {"patterns": ["PRJ-[0-9]{4}"]},
                         prov.release_digest)
    msg = parse_and_verify(encode(env), lookup_for(admin))
    assert msg.header.command == cmd.UPDATE_REDACTION_PATTERNS and msg.payload == {"patterns": ["PRJ-[0-9]{4}"]}
    assert msg.header.payload_sha256 == payload_digest(msg.payload)
    assert (msg.expires_at - msg.issued_at).total_seconds() == 30


def test_whitespace_and_member_order_on_the_wire_do_not_matter(prov, ids):
    admin = ids["sec-console-01"]
    env = create_command(admin, "ciphermesh-node-01", cmd.PING, {}, prov.release_digest)
    reordered = {"signature": env["signature"], "payload": env["payload"],
                 "header": dict(reversed(list(env["header"].items())))}
    raw = json.dumps(reordered, indent=3).encode()
    assert parse_and_verify(raw, lookup_for(admin)).header.msg_id == env["header"]["msg_id"]


@pytest.mark.parametrize("field,value", [
    ("command", "RELEASE_LOCKDOWN"), ("recipient", "ciphermesh-node-02"), ("sender_host", "observer-01"),
    ("nonce", "0" * 32), ("issued_at", "2026-01-01T00:00:00.000Z"), ("integrity", "a" * 64),
    ("msg_id", "00000000-0000-4000-8000-000000000000"),
])
def test_changing_any_signed_header_field_breaks_the_signature(prov, ids, field, value):
    admin = ids["sec-console-01"]
    env = create_command(admin, "ciphermesh-node-01", cmd.TRIGGER_EMERGENCY_LOCKDOWN, {"reason": "x"},
                         prov.release_digest)
    env["header"][field] = value
    with pytest.raises(EnvelopeError) as err:
        parse_and_verify(encode(env), lambda h, k: admin.public_key)
    assert err.value.code == "BAD_SIGNATURE"


def test_command_signature_is_not_valid_as_a_reply_domain_separation(prov, ids):
    admin = ids["sec-console-01"]
    env = create_command(admin, "ciphermesh-node-01", cmd.PING, {}, prov.release_digest)
    with pytest.raises(EnvelopeError) as err:
        parse_and_verify(encode(env), lookup_for(admin), REPLY_CONTEXT)
    assert err.value.code == "BAD_SIGNATURE"
    assert signing_bytes(env["header"], {}, COMMAND_CONTEXT) != signing_bytes(env["header"], {}, REPLY_CONTEXT)


@pytest.mark.parametrize("command,payload", [
    (cmd.UPDATE_REDACTION_PATTERNS, {"patterns": "PRJ-1"}),
    (cmd.UPDATE_REDACTION_PATTERNS, {"patterns": []}),
    (cmd.UPDATE_REDACTION_PATTERNS, {"patterns": ["x"] * 33}),
    (cmd.UPDATE_REDACTION_PATTERNS, {"patterns": ["P"], "extra": 1}),
    (cmd.TRIGGER_EMERGENCY_LOCKDOWN, {}),
    (cmd.REQUEST_TELEMETRY_DUMP, {"dump_secrets": True}),
    (cmd.INSPECT, {"text": 42}),
    (cmd.STATE_SYNC, {"state": "all"}),
])
def test_payload_schema_is_strict_per_command(prov, ids, command, payload):
    env = create_command(ids["sec-console-01"], "ciphermesh-node-01", command, payload, prov.release_digest)
    with pytest.raises(EnvelopeError) as err:
        parse(encode(env))
    assert err.value.code == "SCHEMA_VIOLATION"


def test_header_types_and_formats_are_strict(prov, ids):
    env = create_command(ids["sec-console-01"], "ciphermesh-node-01", cmd.PING, {}, prov.release_digest)
    for field, value in [("nonce", 1234), ("issued_at", "2026-11-01 10:00:00"), ("key_id", "ABC"),
                         ("command", "FORMAT_DISK"), ("msg_id", "not-a-uuid")]:
        bad = json.loads(encode(env))
        bad["header"][field] = value
        with pytest.raises(EnvelopeError):
            parse(json.dumps(bad).encode())


def test_unknown_signer_and_digest_mismatch(prov, ids):
    admin = ids["sec-console-01"]
    env = create_command(admin, "ciphermesh-node-01", cmd.PING, {}, prov.release_digest)
    with pytest.raises(EnvelopeError) as err:
        parse_and_verify(encode(env), lambda h, k: None)
    assert err.value.code == "KEY_NOT_BOUND"
