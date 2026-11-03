"""Provisioning: generate host keys, write the trust store and sign the release manifest.

Assignment 5.1 - Agent Authentication and Host Integrity Verification.
Author: Kumar Waibhav Akshat (RA2212704010027).

This is the "release engineering" step. It creates:

* ``<keys_dir>/<host>.key.pem`` - Ed25519 private keys, PKCS#8, passphrase
  encrypted, mode 0600 (never shipped, never logged);
* ``<keys_dir>/<host>.pub.pem`` - matching public keys;
* ``<trust_dir>/trusted_hosts.json`` - public keys, roles, allowed sources,
  validity windows, revocations and trusted release digests;
* ``<trust_dir>/release_signer.pub`` - the pinned release (trust-anchor) key;
* ``<trust_dir>/release_manifest.json`` - SHA-256 of every source file, the
  Python version and the trust store hash, signed by the release key.

The security console gets two keys to model a rotation: the old one is kept in
the store but revoked (and listed in the revocation list), the new one is live.
"""
from __future__ import annotations

import argparse
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .commands import DEFAULT_ROLES
from .integrity import build_manifest, measure, package_root, save_signed_manifest, sign_manifest
from .keys import (KeyRecord, RevokedKey, SigningIdentity, TrustedHost, TrustStore, TrustStoreDocument,
                   public_key_to_b64, save_private_key, save_public_key)

LOG = logging.getLogger("ciphermesh.trust.provision")
DEFAULT_TRUST_DIR = Path(__file__).resolve().parent
DEFAULT_KEYS_DIR = Path(__file__).resolve().parents[2] / "demo" / "keys"
DEMO_PASSPHRASE = b"ciphermesh-demo-only-passphrase"
AGENT_ID = "ciphermesh-node-01"

# host_id, display name, roles, allowed sources
HOST_PLAN: list[tuple[str, str, list[str], list[str]]] = [
    (AGENT_ID, "CipherMesh agent node 01 (this gateway)", ["agent"], ["127.0.0.1/32", "local"]),
    ("sec-console-01", "Security operations console (SOC)", ["security-admin"], ["127.0.0.8/29", "local"]),
    ("observer-01", "Monitoring / observability host", ["observer"], ["127.0.0.20/32"]),
    ("peer-gateway-01", "Peer CipherMesh gateway (Mumbai)", ["peer-gateway"], ["127.0.0.30/32"]),
    ("legacy-console-02", "Decommissioned admin console", ["security-admin"], ["127.0.0.40/32"]),
]
REVOKED_HOSTS = {"legacy-console-02"}


def passphrase_from_env() -> bytes:
    value = os.environ.get("CIPHERMESH_KEY_PASSPHRASE")
    if value:
        return value.encode("utf-8")
    LOG.warning("CIPHERMESH_KEY_PASSPHRASE not set; using the built-in demo passphrase (demo use only)")
    return DEMO_PASSPHRASE


@dataclass
class Provisioned:
    trust_dir: Path
    keys_dir: Path
    trust_store: TrustStore
    identities: dict[str, SigningIdentity]
    old_admin_identity: SigningIdentity
    release_identity: SigningIdentity
    release_digest: str
    manifest: dict

    @property
    def trust_path(self) -> Path:
        return self.trust_dir / "trusted_hosts.json"

    @property
    def manifest_path(self) -> Path:
        return self.trust_dir / "release_manifest.json"

    @property
    def release_pub_path(self) -> Path:
        return self.trust_dir / "release_signer.pub"


def _ts(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def provision(trust_dir: str | Path = DEFAULT_TRUST_DIR, keys_dir: str | Path = DEFAULT_KEYS_DIR,
              passphrase: bytes | None = DEMO_PASSPHRASE, code_root: str | Path | None = None,
              now: datetime | None = None) -> Provisioned:
    trust_dir, keys_dir = Path(trust_dir), Path(keys_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(keys_dir, 0o700)
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    root = Path(code_root) if code_root else package_root()
    release_digest = measure(root)

    identities: dict[str, SigningIdentity] = {}
    hosts: list[TrustedHost] = []
    old_admin = SigningIdentity.generate("sec-console-01")
    for host_id, display, roles, sources in HOST_PLAN:
        identity = SigningIdentity.generate(host_id)
        identities[host_id] = identity
        save_private_key(keys_dir / f"{host_id}.key.pem", identity.private_key, passphrase)
        save_public_key(keys_dir / f"{host_id}.pub.pem", identity.public_key)
        keys = []
        if host_id == "sec-console-01":
            save_private_key(keys_dir / "sec-console-01.old.key.pem", old_admin.private_key, passphrase)
            keys.append(KeyRecord(key_id=old_admin.key_id, public_key=old_admin.public_key_b64,
                                  valid_from=now - timedelta(days=180), valid_until=now + timedelta(days=185),
                                  revoked=True, note="rotated out; superseded by current console key"))
        keys.append(KeyRecord(key_id=identity.key_id, public_key=public_key_to_b64(identity.public_key),
                              valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=365),
                              note="current signing key"))
        hosts.append(TrustedHost(host_id=host_id, display_name=display, roles=roles, allowed_sources=sources,
                                 keys=keys, trusted_release_digests=[release_digest],
                                 valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=365),
                                 revoked=host_id in REVOKED_HOSTS))

    document = TrustStoreDocument(
        schema_version="cm-trust/1", issuer="CipherMesh Security Engineering - Kumar Waibhav Akshat",
        generated_at=now, agent_id=AGENT_ID, roles={k: list(v) for k, v in DEFAULT_ROLES.items()}, hosts=hosts,
        revocation_list=[RevokedKey(key_id=old_admin.key_id, revoked_at=now - timedelta(hours=1),
                                    reason="scheduled key rotation (NIST SP 800-57 cryptoperiod)")])
    store = TrustStore(document)
    store.save(trust_dir / "trusted_hosts.json")

    release = SigningIdentity.generate("release-signer")
    save_private_key(keys_dir / "release-signer.key.pem", release.private_key, passphrase)
    save_public_key(trust_dir / "release_signer.pub", release.public_key)
    manifest = build_manifest(root, trust_store_sha256=store.sha256(), now=now)
    save_signed_manifest(trust_dir / "release_manifest.json", sign_manifest(manifest, release))
    LOG.info("provisioned %d hosts, release digest %s..., manifest over %d files", len(hosts),
             release_digest[:16], manifest["file_count"])
    return Provisioned(trust_dir, keys_dir, TrustStore.load(trust_dir / "trusted_hosts.json"), identities,
                       old_admin, release, release_digest, manifest)


def ensure_provisioned(trust_dir: Path = DEFAULT_TRUST_DIR, keys_dir: Path = DEFAULT_KEYS_DIR) -> None:
    """Provision on first use (private keys are never shipped, so a fresh checkout has none)."""
    needed = [trust_dir / "trusted_hosts.json", trust_dir / "release_manifest.json", keys_dir / f"{AGENT_ID}.key.pem"]
    if not all(path.exists() for path in needed):
        LOG.info("no provisioned key material found; running provisioning first")
        provision(trust_dir, keys_dir, passphrase_from_env())


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Provision CipherMesh host keys, trust store and release manifest")
    parser.add_argument("--trust-dir", default=str(DEFAULT_TRUST_DIR))
    parser.add_argument("--keys-dir", default=str(DEFAULT_KEYS_DIR))
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-7s | %(message)s")
    result = provision(args.trust_dir, args.keys_dir, passphrase_from_env())
    for host in result.trust_store.document.hosts:
        print(f"{host.host_id:20s} roles={','.join(host.roles):15s} keys={[k.key_id for k in host.keys]}"
              f"{'  REVOKED' if host.revoked else ''}")
    print(f"trust store : {result.trust_path}")
    print(f"manifest    : {result.manifest_path} ({result.manifest['file_count']} files)")


if __name__ == "__main__":
    main()
