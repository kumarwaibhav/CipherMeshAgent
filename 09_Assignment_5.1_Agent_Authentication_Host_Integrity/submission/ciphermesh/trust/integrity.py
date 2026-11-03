"""Host integrity verification: signed release manifest, self-attestation and peer evidence.

Assignment 5.1 - Agent Authentication and Host Integrity Verification.
Author: Kumar Waibhav Akshat (RA2212704010027).

Roles follow the IETF RATS architecture (RFC 9334):

* **Reference values** - the release manifest: SHA-256 of every ``*.py`` file in
  the ``ciphermesh`` package plus the Python minor version, signed by a
  separate *release key* at build time.
* **Evidence** - a host's *attestation digest*: SHA-256 over the canonical JSON
  of ``{release, python, files}`` measured on that host. Every signed command
  carries the sender's digest in ``header.integrity``; because the header is
  signed, the claim cannot be altered in transit.
* **Verifier** - the agent: at start-up it measures its *own* code and compares
  it with the signed manifest (self-attestation); for every inbound command it
  compares the sender's digest with the reference digests the trust store
  lists for that host (checkpoint C12).

On a self-attestation failure the agent either refuses to start (``strict``)
or enters SAFE MODE, in which only read-only telemetry is executed. A changed
trust store always stops start-up. Bytecode caches and native modules under
the package also fail attestation (see ``collect_code_artefacts``).

Limitation (stated honestly in the report): this is software attestation. A
fully compromised host could lie about its own digest; hardware roots of trust
(TPM quotes, measured boot) are needed to close that gap.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import platform
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import StrictJSONError, canonicalize, strict_loads
from .keys import SigningIdentity, key_id_for, verify_signature

MANIFEST_SCHEMA = "cm-release/1"
MANIFEST_CONTEXT = b"CipherMesh/ReleaseManifest/v1\x00"
RELEASE_NAME = "ciphermesh-5.1.0"
MODE_NORMAL = "NORMAL"
MODE_SAFE = "SAFE_MODE"


class IntegrityError(Exception):
    """Raised when the manifest is unsigned/forged or when strict start-up attestation fails."""


def package_root() -> Path:
    return Path(__file__).resolve().parent.parent


def python_version() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}"


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_sources(root: str | Path) -> dict[str, str]:
    """SHA-256 of every Python source file under ``root`` (relative POSIX paths, sorted)."""
    root = Path(root)
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts or not path.is_file():
            continue
        files[path.relative_to(root).as_posix()] = hash_file(path)
    return files


# Files Python can import *instead of* the reviewed source: bytecode caches and native extensions.
# CPython trusts a timestamp-based .pyc whenever its recorded mtime and size match the source, so a
# planted __pycache__/policy.cpython-313.pyc would run while every .py hash still matches. The
# release policy is therefore "source only": the agent runs with PYTHONDONTWRITEBYTECODE=1 / -B and
# any such artefact under the package is an attestation failure.
CODE_ARTEFACT_SUFFIXES = (".pyc", ".pyo", ".so", ".pyd", ".pth")


def collect_code_artefacts(root: str | Path) -> list[str]:
    """Bytecode caches, native modules and .pth hooks found under ``root`` (relative POSIX paths)."""
    root = Path(root)
    found = set()
    for path in root.rglob("*"):
        rel = path.relative_to(root).as_posix()
        if path.is_dir() and path.name == "__pycache__":
            found.add(rel + "/")
        elif path.suffix in CODE_ARTEFACT_SUFFIXES or "__pycache__" in path.parts:
            found.add(rel)
    return sorted(found)


def code_measurement(root: str | Path, release: str = RELEASE_NAME, python: str | None = None) -> dict:
    return {"release": release, "python": python or python_version(), "files": collect_sources(root)}


def attestation_digest(measurement: dict) -> str:
    """Evidence value carried in every signed command header."""
    body = {"release": measurement["release"], "python": measurement["python"], "files": measurement["files"]}
    return hashlib.sha256(canonicalize(body)).hexdigest()


def measure(root: str | Path | None = None) -> str:
    """Attestation digest of the code tree at ``root`` (default: the running package)."""
    return attestation_digest(code_measurement(root or package_root()))


def build_manifest(root: str | Path, trust_store_sha256: str | None = None, release: str = RELEASE_NAME,
                   now: datetime | None = None) -> dict:
    measurement = code_measurement(root, release)
    return {
        "schema": MANIFEST_SCHEMA,
        "release": release,
        "python": measurement["python"],
        "built_on": platform.system(),
        "created_at": (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "file_count": len(measurement["files"]),
        "files": measurement["files"],
        "attestation_digest": attestation_digest(measurement),
        "trust_store_sha256": trust_store_sha256,
    }


def sign_manifest(manifest: dict, release_identity: SigningIdentity) -> dict:
    signature = release_identity.sign(MANIFEST_CONTEXT + canonicalize(manifest))
    return {"manifest": manifest, "signer": release_identity.host_id, "signer_key_id": release_identity.key_id,
            "signature": base64.b64encode(signature).decode("ascii")}


def save_signed_manifest(path: str | Path, signed: dict) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(signed, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o644)
    return path


def load_signed_manifest(path: str | Path) -> dict:
    try:
        data = strict_loads(Path(path).read_bytes())
    except StrictJSONError as exc:
        raise IntegrityError(f"release manifest is not strict JSON: {exc.detail}") from None
    if not isinstance(data, dict) or set(data) != {"manifest", "signer", "signer_key_id", "signature"}:
        raise IntegrityError("release manifest envelope has missing or unknown fields")
    return data


def verify_manifest_signature(signed: dict, release_public_key: Ed25519PublicKey) -> dict:
    """Return the manifest if the release signature is valid, otherwise raise IntegrityError."""
    if signed.get("signer_key_id") != key_id_for(release_public_key):
        raise IntegrityError("manifest was signed by a key other than the pinned release key")
    try:
        signature = base64.b64decode(signed["signature"], validate=True)
    except (ValueError, TypeError):
        raise IntegrityError("manifest signature is not valid base64") from None
    manifest = signed["manifest"]
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        raise IntegrityError("manifest schema is missing or unsupported")
    if not verify_signature(release_public_key, signature, MANIFEST_CONTEXT + canonicalize(manifest)):
        raise IntegrityError("release manifest signature is INVALID (manifest was modified or forged)")
    return manifest


@dataclass
class IntegrityReport:
    ok: bool
    mode: str
    release: str = ""
    files_checked: int = 0
    python_expected: str = ""
    python_actual: str = ""
    manifest_signature_ok: bool = False
    trust_store_ok: bool | None = None
    expected_digest: str = ""
    measured_digest: str = ""
    mismatched: list[dict] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    bytecode: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def self_attest(root: str | Path, signed_manifest: dict, release_public_key: Ed25519PublicKey,
                trust_store_path: str | Path | None = None) -> IntegrityReport:
    """Measure the code at ``root`` and compare it with the signed release manifest."""
    report = IntegrityReport(ok=False, mode=MODE_SAFE, python_actual=python_version())
    try:
        manifest = verify_manifest_signature(signed_manifest, release_public_key)
    except IntegrityError as exc:
        report.reasons.append(str(exc))
        return report
    report.manifest_signature_ok = True
    report.release = manifest.get("release", "")
    report.python_expected = manifest.get("python", "")
    report.expected_digest = manifest.get("attestation_digest", "")
    expected_files: dict[str, str] = manifest.get("files", {})
    actual_files = collect_sources(root)
    report.files_checked = len(actual_files)
    for rel, expected_hash in sorted(expected_files.items()):
        actual_hash = actual_files.get(rel)
        if actual_hash is None:
            report.missing.append(rel)
        elif not hmac.compare_digest(actual_hash, expected_hash):
            report.mismatched.append({"file": rel, "expected": expected_hash, "actual": actual_hash})
    report.unexpected = sorted(set(actual_files) - set(expected_files))
    report.bytecode = collect_code_artefacts(root)
    report.measured_digest = attestation_digest(
        {"release": report.release, "python": report.python_actual, "files": actual_files})
    if report.python_expected != report.python_actual:
        report.reasons.append(f"python version {report.python_actual} differs from release {report.python_expected}")
    if report.mismatched:
        report.reasons.append(f"{len(report.mismatched)} source file(s) modified since release")
    if report.missing:
        report.reasons.append(f"{len(report.missing)} source file(s) missing")
    if report.unexpected:
        report.reasons.append(f"{len(report.unexpected)} unexpected source file(s) present")
    if report.bytecode:
        report.reasons.append(f"{len(report.bytecode)} bytecode/native artefact(s) present (source-only release; "
                              "run with PYTHONDONTWRITEBYTECODE=1 or python -B and remove __pycache__)")
    if trust_store_path is not None and manifest.get("trust_store_sha256"):
        actual = hash_file(Path(trust_store_path))
        report.trust_store_ok = hmac.compare_digest(actual, manifest["trust_store_sha256"])
        if not report.trust_store_ok:
            report.reasons.append("trusted_hosts.json differs from the copy sealed in the release manifest")
    digest_ok = hmac.compare_digest(report.measured_digest, report.expected_digest)
    if not digest_ok and not report.reasons:
        report.reasons.append("attestation digest differs from the release manifest")
    report.ok = not report.reasons and digest_ok
    report.mode = MODE_NORMAL if report.ok else MODE_SAFE
    return report


__all__ = [
    "IntegrityError", "IntegrityReport", "MANIFEST_SCHEMA", "MANIFEST_CONTEXT", "RELEASE_NAME", "MODE_NORMAL",
    "MODE_SAFE", "attestation_digest", "build_manifest", "code_measurement", "collect_sources", "hash_file",
    "load_signed_manifest", "measure", "collect_code_artefacts", "CODE_ARTEFACT_SUFFIXES", "package_root",
    "python_version", "save_signed_manifest", "self_attest", "sign_manifest", "verify_manifest_signature",
]
