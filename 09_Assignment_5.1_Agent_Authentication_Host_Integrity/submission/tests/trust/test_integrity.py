"""Host integrity: release manifest signing, self-attestation and tamper detection.

Author: Kumar Waibhav Akshat (RA2212704010027).
"""
import copy
import json
import shutil

import pytest

from ciphermesh.trust.attack_sim import tamper_copy
from ciphermesh.trust.integrity import (IntegrityError, attestation_digest, build_manifest, code_measurement,
                                        load_signed_manifest, measure, package_root, self_attest, sign_manifest,
                                        verify_manifest_signature)
from ciphermesh.trust.keys import SigningIdentity, load_public_key


@pytest.fixture
def signed(prov):
    return load_signed_manifest(prov.manifest_path)


@pytest.fixture
def release_pub(prov):
    return load_public_key(prov.release_pub_path)


def test_manifest_covers_every_python_source_and_is_deterministic(prov):
    manifest = prov.manifest
    sources = sorted(p.relative_to(package_root()).as_posix() for p in package_root().rglob("*.py")
                     if "__pycache__" not in p.parts)
    assert sorted(manifest["files"]) == sources and manifest["file_count"] == len(sources)
    assert manifest["attestation_digest"] == measure() == prov.release_digest
    assert attestation_digest(code_measurement(package_root())) == measure()


def test_manifest_signature_valid_and_tamper_evident(signed, release_pub):
    assert verify_manifest_signature(signed, release_pub)["release"] == "ciphermesh-5.1.0"
    edited = copy.deepcopy(signed)
    edited["manifest"]["files"]["policy.py"] = "0" * 64
    with pytest.raises(IntegrityError, match="INVALID"):
        verify_manifest_signature(edited, release_pub)
    resigned = sign_manifest(edited["manifest"], SigningIdentity.generate("rogue-release"))
    with pytest.raises(IntegrityError, match="pinned release key"):
        verify_manifest_signature(resigned, release_pub)


def test_self_attestation_of_clean_tree_passes(prov, signed, release_pub):
    report = self_attest(package_root(), signed, release_pub, prov.trust_path)
    assert report.ok and report.mode == "NORMAL" and report.trust_store_ok
    assert report.measured_digest == report.expected_digest and not report.reasons


def test_backdoored_file_is_detected(tmp_path, signed, release_pub):
    report = self_attest(tamper_copy(package_root(), tmp_path), signed, release_pub)
    assert not report.ok and report.mode == "SAFE_MODE"
    assert [m["file"] for m in report.mismatched] == ["policy.py"]
    assert report.measured_digest != report.expected_digest


def test_missing_and_unexpected_files_are_detected(tmp_path, signed, release_pub):
    root = tmp_path / "ciphermesh"
    shutil.copytree(package_root(), root, ignore=shutil.ignore_patterns("__pycache__"))
    (root / "trust" / "verifier.py").unlink()
    (root / "hook.py").write_text("print('persist')\n")
    report = self_attest(root, signed, release_pub)
    assert report.missing == ["trust/verifier.py"] and report.unexpected == ["hook.py"] and not report.ok


def test_trust_store_change_is_detected(prov, tmp_path, signed, release_pub):
    data = json.loads(prov.trust_path.read_bytes())
    data["hosts"][2]["roles"] = ["security-admin"]          # silent privilege escalation of observer-01
    rogue = tmp_path / "trusted_hosts.json"
    rogue.write_text(json.dumps(data, indent=2))
    report = self_attest(package_root(), signed, release_pub, rogue)
    assert report.trust_store_ok is False and not report.ok


def test_invalid_manifest_files_are_refused(tmp_path, signed):
    path = tmp_path / "m.json"
    path.write_text(json.dumps({**signed, "extra": 1}))
    with pytest.raises(IntegrityError):
        load_signed_manifest(path)
    path.write_text('{"manifest": 1, "manifest": 2}')
    with pytest.raises(IntegrityError):
        load_signed_manifest(path)


def test_build_manifest_records_trust_store_hash():
    manifest = build_manifest(package_root(), trust_store_sha256="a" * 64)
    assert manifest["trust_store_sha256"] == "a" * 64 and manifest["schema"] == "cm-release/1"


def test_planted_bytecode_cache_is_detected_even_though_sources_match(tmp_path, signed, release_pub):
    from ciphermesh.trust.integrity_check import plant_backdoored_pyc
    root = tmp_path / "ciphermesh"
    shutil.copytree(package_root(), root, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    assert self_attest(root, signed, release_pub).ok
    pyc = plant_backdoored_pyc(root)
    report = self_attest(root, signed, release_pub)
    assert not report.ok and report.mode == "SAFE_MODE" and not report.mismatched
    assert pyc.relative_to(root).as_posix() in report.bytecode and "__pycache__/" in report.bytecode


@pytest.mark.parametrize("name", ["trust/verifier.cpython-313-x86_64-linux-gnu.so", "evil.pth", "policy.pyc"])
def test_native_modules_and_path_hooks_are_detected(tmp_path, signed, release_pub, name):
    root = tmp_path / "ciphermesh"
    shutil.copytree(package_root(), root, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (root / name).write_bytes(b"\x7fELF")
    report = self_attest(root, signed, release_pub)
    assert not report.ok and name in report.bytecode
