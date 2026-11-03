"""Ed25519 key handling, trust store schema, rotation and revocation tests.

Author: Kumar Waibhav Akshat (RA2212704010027).
"""
import hashlib
import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

from ciphermesh.trust import commands as cmd
from ciphermesh.trust.keys import (KeyHandlingError, SigningIdentity, TrustStore, TrustStoreError, key_id_for,
                                   load_private_key, load_public_key, raw_public_bytes, save_private_key,
                                   save_public_key)
from ciphermesh.trust.verifier import CommandVerifier, FailureLimiter

from .helpers import frame, tcp


def test_key_id_is_first_16_hex_of_sha256_of_raw_public_key():
    ident = SigningIdentity.generate("observer-01")
    expected = hashlib.sha256(raw_public_bytes(ident.public_key)).hexdigest()[:16]
    assert ident.key_id == key_id_for(ident.public_key) == expected and len(expected) == 16


def test_private_key_saved_encrypted_with_0600_and_round_trips(tmp_path):
    ident = SigningIdentity.generate("sec-console-01")
    path = tmp_path / "k.pem"
    save_private_key(path, ident.private_key, b"pw")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert b"ENCRYPTED PRIVATE KEY" in path.read_bytes()
    loaded = load_private_key(path, b"pw")
    assert key_id_for(loaded.public_key()) == ident.key_id


def test_wrong_passphrase_and_unsafe_permissions_are_refused(tmp_path):
    ident = SigningIdentity.generate("sec-console-01")
    path = tmp_path / "k.pem"
    save_private_key(path, ident.private_key, b"pw")
    with pytest.raises(KeyHandlingError):
        load_private_key(path, b"wrong")
    os.chmod(path, 0o644)
    with pytest.raises(KeyHandlingError, match="unsafe permissions"):
        load_private_key(path, b"pw")


def test_public_key_round_trip_and_identity_repr_hides_private_key(tmp_path):
    ident = SigningIdentity.generate("observer-01")
    save_public_key(tmp_path / "p.pem", ident.public_key)
    assert key_id_for(load_public_key(tmp_path / "p.pem")) == ident.key_id
    assert "private" not in repr(ident).lower()


def test_trust_store_loads_and_indexes_hosts(store):
    admin = store.host("sec-console-01")
    assert admin is not None and "security-admin" in admin.roles
    assert cmd.TRIGGER_EMERGENCY_LOCKDOWN in store.capabilities(admin)
    assert store.capabilities(store.host("observer-01")) == {cmd.REQUEST_TELEMETRY_DUMP, cmd.PING}
    assert store.origin_allowed(admin, "127.0.0.13") and not store.origin_allowed(admin, "127.0.0.16")
    assert store.origin_allowed(admin, "local") and not store.origin_allowed(store.host("observer-01"), "local")
    assert len(store.document.revocation_list) == 1


def test_trust_store_serialisation_is_stable(store, tmp_path):
    path = store.save(tmp_path / "t.json")
    again = TrustStore.load(path)
    assert again.sha256() == store.sha256() and again.to_json_bytes() == path.read_bytes()


def _mutations():
    def root_unknown(d): d["backdoor"] = True
    def host_unknown(d): d["hosts"][1]["is_admin"] = True
    def bad_cidr(d): d["hosts"][1]["allowed_sources"] = ["10.0.0.300/8"]
    def key_id_mismatch(d): d["hosts"][1]["keys"][-1]["key_id"] = "0" * 16
    def duplicate_host(d): d["hosts"].append(dict(d["hosts"][2]))
    def shared_key(d): d["hosts"][2]["keys"] = [d["hosts"][1]["keys"][-1]]
    def undefined_role(d): d["hosts"][2]["roles"] = ["superuser"]
    def unknown_command(d): d["roles"]["observer"].append("FORMAT_DISK")
    def naive_time(d): d["hosts"][1]["valid_from"] = "2026-01-01T00:00:00"
    def agent_missing(d): d["agent_id"] = "ciphermesh-node-77"
    def window_inverted(d): d["hosts"][1]["valid_until"] = "2020-01-01T00:00:00Z"
    def wrong_schema(d): d["schema_version"] = "cm-trust/9"
    def bad_digest(d): d["hosts"][1]["trusted_release_digests"] = ["xyz"]
    return [root_unknown, host_unknown, bad_cidr, key_id_mismatch, duplicate_host, shared_key, undefined_role,
            unknown_command, naive_time, agent_missing, window_inverted, wrong_schema, bad_digest]


@pytest.mark.parametrize("mutate", _mutations(), ids=lambda f: f.__name__)
def test_trust_store_schema_violations_are_rejected(store, mutate):
    data = json.loads(store.to_json_bytes())
    mutate(data)
    with pytest.raises(TrustStoreError):
        TrustStore.from_bytes(json.dumps(data).encode())


def test_trust_store_rejects_duplicate_keys_and_world_writable_file(store, tmp_path):
    with pytest.raises(TrustStoreError, match="strict JSON"):
        TrustStore.from_bytes(b'{"schema_version":"cm-trust/1","schema_version":"cm-trust/1"}')
    path = store.save(tmp_path / "t.json")
    os.chmod(path, 0o666)
    with pytest.raises(TrustStoreError, match="writable"):
        TrustStore.load(path)


def test_key_rotation_then_revocation(prov, store, ids):
    now = datetime.now(timezone.utc)
    new_admin = SigningIdentity.generate("sec-console-01")
    store.add_key("sec-console-01", new_admin.public_key, now - timedelta(minutes=1), now + timedelta(days=90))
    verifier = CommandVerifier(store, limiter=FailureLimiter(threshold=1000))
    old_frame = frame(prov, ids["sec-console-01"], cmd.PING)
    assert verifier.verify(frame(prov, new_admin, cmd.PING), tcp()).accepted
    assert verifier.verify(old_frame, tcp()).accepted          # overlap period: both keys valid
    store.revoke_key(ids["sec-console-01"].key_id, "rotation complete", now)
    verdict = verifier.verify(frame(prov, ids["sec-console-01"], cmd.PING), tcp())
    assert (verdict.checkpoint, verdict.reason) == ("C6", "KEY_REVOKED")
    assert verifier.verify(frame(prov, new_admin, cmd.PING), tcp()).accepted
    assert verifier.verify(frame(prov, ids["observer-01"], cmd.PING), tcp("127.0.0.20")).accepted


def test_revoking_unknown_key_and_host(store):
    with pytest.raises(TrustStoreError):
        store.revoke_key("f" * 16, "x", datetime.now(timezone.utc))
    store.revoke_host("observer-01")
    assert store.host("observer-01").revoked
