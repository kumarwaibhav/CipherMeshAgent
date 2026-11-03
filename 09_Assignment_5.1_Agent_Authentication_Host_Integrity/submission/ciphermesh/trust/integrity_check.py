"""Host integrity verification run: signed manifest check, self-attestation and tamper detection.

Assignment 5.1 - Agent Authentication and Host Integrity Verification.
Author: Kumar Waibhav Akshat (RA2212704010027).

Writes ``logs/integrity_check.log``. Every tamper experiment works on a
*temporary copy* of the package or of the trust files; the real tree is never
modified. Expected result: the clean tree passes, every tampering is detected.
"""
from __future__ import annotations

import argparse
import copy
import importlib.util
import logging
import marshal
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from datetime import timedelta
from pathlib import Path

from .attack_sim import tamper_copy
from .envelope import utc_now
from .integrity import (IntegrityError, collect_sources, hash_file, load_signed_manifest, measure, package_root,
                        self_attest, sign_manifest, verify_manifest_signature)
from .keys import SigningIdentity, TrustStore, TrustStoreDocument, load_public_key
from .secure_agent import AgentConfig, SecureCipherMeshAgent

LOG = logging.getLogger("ciphermesh.trust.integrity_check")
RULE = "-" * 96


def _report(report) -> None:
    LOG.info("  result    : ok=%s mode=%s files_checked=%d", report.ok, report.mode, report.files_checked)
    for item in report.mismatched:
        LOG.info("  MODIFIED  : %-28s expected %s...  actual %s...", item["file"], item["expected"][:20],
                 item["actual"][:20])
    for item in report.missing:
        LOG.info("  MISSING   : %s", item)
    for item in report.unexpected:
        LOG.info("  UNEXPECTED: %s", item)
    for item in report.bytecode:
        LOG.info("  BYTECODE  : %s", item)
    if report.trust_store_ok is False:
        LOG.info("  TRUST FILE: trusted_hosts.json hash differs from the value sealed in the manifest")
    for reason in report.reasons:
        LOG.info("  reason    : %s", reason)
    if report.measured_digest:
        LOG.info("  digest    : measured %s... vs release %s...", report.measured_digest[:24],
                 report.expected_digest[:24])


def plant_backdoored_pyc(package: Path) -> Path:
    """Write a timestamp-based .pyc for policy.py that CPython will load instead of the clean source.

    The .pyc records the source's real mtime and size, so the import system's staleness check passes
    and the bytecode runs, although policy.py itself is untouched.
    """
    src = package / "policy.py"
    st = src.stat()
    evil = src.read_text(encoding="utf-8").replace("def inspect_text(", "def _orig_inspect_text(", 1) + (
        "\n\ndef inspect_text(text, *a, **k):\n"
        "    r = _orig_inspect_text(text, *a, **k)\n"
        "    if '#cm-override' in text:\n"
        "        r = r.model_copy(update={'decision': Decision.ALLOW})\n"
        "    return r\n")
    code = compile(evil, str(src), "exec")
    target = Path(importlib.util.cache_from_source(str(src)))
    target.parent.mkdir(exist_ok=True)
    header = importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, int(st.st_mtime) & 0xFFFFFFFF,
                                                       st.st_size & 0xFFFFFFFF)
    target.write_bytes(header + marshal.dumps(code))
    return target


def _decision_in_subprocess(parent: Path) -> str:
    probe = ("import sys; sys.path.insert(0, sys.argv[1]); from ciphermesh.policy import inspect_text; "
             "from ciphermesh.models import AgentState; "
             "print(inspect_text('#cm-override AKIAIOSFODNN7EXAMPLE', AgentState(agent_id='probe')).decision.value)")
    out = subprocess.run([sys.executable, "-B", "-c", probe, str(parent)], capture_output=True, text=True,
                         timeout=60, cwd=str(parent))
    return out.stdout.strip().splitlines()[-1] if out.stdout.strip() else f"error: {out.stderr.strip()[-80:]}"


def run(trust_dir: Path, keys_dir: Path, passphrase: bytes) -> dict:
    trust_path = trust_dir / "trusted_hosts.json"
    signed = load_signed_manifest(trust_dir / "release_manifest.json")
    release_pub = load_public_key(trust_dir / "release_signer.pub")
    root = package_root()
    results: list[tuple[str, str, bool]] = []
    tmp = Path(tempfile.mkdtemp(prefix="cm-integrity-"))
    LOG.info("=" * 96)
    LOG.info("CipherMesh Assignment 5.1 - host integrity verification run (all times UTC)")
    LOG.info("=" * 96)
    manifest = signed["manifest"]
    LOG.info("release         : %s (schema %s, python %s, built on %s at %s)", manifest["release"], manifest["schema"],
             manifest["python"], manifest["built_on"], manifest["created_at"])
    LOG.info("files sealed    : %d python source files", manifest["file_count"])
    LOG.info("release digest  : %s", manifest["attestation_digest"])
    LOG.info("trust store hash: %s", manifest["trust_store_sha256"])
    LOG.info("release signer  : %s key_id=%s (pinned in release_signer.pub)", signed["signer"], signed["signer_key_id"])

    LOG.info(RULE)
    LOG.info("[IC1] Verify the release manifest signature (Ed25519, domain 'CipherMesh/ReleaseManifest/v1')")
    started = time.perf_counter()
    verify_manifest_signature(signed, release_pub)
    LOG.info("  result    : signature VALID (%.2f ms)", (time.perf_counter() - started) * 1000)
    results.append(("IC1", "Release manifest signature verifies", True))

    LOG.info(RULE)
    LOG.info("[IC2] Self-attestation of the running package (%s)", root.name)
    started = time.perf_counter()
    report = self_attest(root, signed, release_pub, trust_path)
    elapsed = (time.perf_counter() - started) * 1000
    for rel, digest in collect_sources(root).items():
        status = "OK " if manifest["files"].get(rel) == digest else "BAD"
        LOG.info("  %s %-34s sha256=%s...", status, rel, digest[:24])
    LOG.info("  trusted_hosts.json sealed hash: %s", "MATCH" if report.trust_store_ok else "MISMATCH")
    _report(report)
    LOG.info("  time      : %.2f ms to hash and compare %d files", elapsed, report.files_checked)
    LOG.info("  verdict   : %s", "PASS - agent may start in NORMAL mode" if report.ok else "FAIL")
    results.append(("IC2", "Clean package matches signed manifest (NORMAL mode)", report.ok))

    def backdoor(dest: Path) -> Path:
        return tamper_copy(root, dest)

    def extra_file(dest: Path) -> Path:
        copy_root = dest / "ciphermesh"
        shutil.copytree(root, copy_root, ignore=shutil.ignore_patterns("__pycache__"))
        (copy_root / "trust" / "evil_hook.py").write_text("import os  # planted persistence hook\n")
        return copy_root

    def missing_file(dest: Path) -> Path:
        copy_root = dest / "ciphermesh"
        shutil.copytree(root, copy_root, ignore=shutil.ignore_patterns("__pycache__"))
        (copy_root / "trust" / "verifier.py").unlink()
        return copy_root

    experiments = [
        ("IC3", "Backdoor injected into policy.py", backdoor),
        ("IC4", "Unexpected file planted (trust/evil_hook.py)", extra_file),
        ("IC5", "Security module deleted (trust/verifier.py)", missing_file),
    ]
    for cid, title, make in experiments:
        LOG.info(RULE)
        LOG.info("[%s] %s - attestation of a modified copy", cid, title)
        dest = tmp / cid
        dest.mkdir()
        bad_root = make(dest)
        bad = self_attest(bad_root, signed, release_pub, trust_path)
        _report(bad)
        detected = not bad.ok and bad.mode == "SAFE_MODE"
        LOG.info("  verdict   : %s", "TAMPERING DETECTED -> SAFE MODE" if detected else "NOT DETECTED (FAIL)")
        results.append((cid, title, detected))

    LOG.info(RULE)
    LOG.info("[IC6] Attacker edits the manifest to 'approve' the backdoored policy.py")
    (tmp / "IC6").mkdir()
    bad_root = tamper_copy(root, tmp / "IC6")
    forged = copy.deepcopy(signed)
    forged["manifest"]["files"]["policy.py"] = hash_file(bad_root / "policy.py")
    try:
        verify_manifest_signature(forged, release_pub)
        detected = False
    except IntegrityError as exc:
        detected = True
        LOG.info("  result    : %s", exc)
    LOG.info("  verdict   : %s", "TAMPERING DETECTED" if detected else "NOT DETECTED (FAIL)")
    results.append(("IC6", "Edited manifest (hash swapped) rejected", detected))

    LOG.info(RULE)
    LOG.info("[IC7] Attacker re-signs a forged manifest with their own key")
    attacker = SigningIdentity.generate("rogue-release")
    resigned = sign_manifest(forged["manifest"], attacker)
    try:
        verify_manifest_signature(resigned, release_pub)
        detected = False
    except IntegrityError as exc:
        detected = True
        LOG.info("  result    : %s (attacker key_id %s)", exc, attacker.key_id)
    LOG.info("  verdict   : %s", "TAMPERING DETECTED" if detected else "NOT DETECTED (FAIL)")
    results.append(("IC7", "Manifest re-signed by attacker key rejected", detected))

    LOG.info(RULE)
    LOG.info("[IC8] Attacker adds a rogue admin host to a copy of trusted_hosts.json")
    store = TrustStore.load(trust_path)
    rogue = SigningIdentity.generate("rogue-admin-77")
    doc = store.document.model_dump(mode="json")
    template = dict(doc["hosts"][1])
    template.update(host_id="rogue-admin-77", display_name="Rogue admin", allowed_sources=["0.0.0.0/0"],
                    keys=[{"key_id": rogue.key_id, "algorithm": "Ed25519", "public_key": rogue.public_key_b64,
                           "valid_from": doc["generated_at"],
                           "valid_until": (utc_now() + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                           "revoked": False, "note": ""}])
    doc["hosts"].append(template)
    rogue_store = TrustStore(TrustStoreDocument.model_validate(doc))
    rogue_path = rogue_store.save(tmp / "trusted_hosts.json")
    bad = self_attest(root, signed, release_pub, rogue_path)
    _report(bad)
    agent_key = SigningIdentity.load(store.agent_id, keys_dir / f"{store.agent_id}.key.pem", passphrase)
    try:
        SecureCipherMeshAgent(agent_key, rogue_store, signed_manifest=signed, release_public_key=release_pub,
                              trust_store_path=rogue_path, config=AgentConfig(strict_integrity=False))
        refused = False
    except IntegrityError as exc:
        refused = True
        LOG.info("  start-up  : IntegrityError even with strict_integrity=False - %s", exc)
    detected = bad.trust_store_ok is False and not bad.ok and refused
    LOG.info("  verdict   : %s", "TAMPERING DETECTED -> START REFUSED" if detected else "NOT DETECTED (FAIL)")
    results.append(("IC8", "Rogue host in trust store: start refused", detected))

    LOG.info(RULE)
    LOG.info("[IC9] Strict start-up: agent pointed at the backdoored tree must refuse to start")
    try:
        SecureCipherMeshAgent(agent_key, store, signed_manifest=signed, release_public_key=release_pub,
                              code_root=bad_root, trust_store_path=trust_path,
                              config=AgentConfig(strict_integrity=True))
        refused = False
    except IntegrityError as exc:
        refused = True
        LOG.info("  result    : IntegrityError - %s", exc)
    LOG.info("  verdict   : %s", "START REFUSED" if refused else "STARTED (FAIL)")
    results.append(("IC9", "Strict mode refuses to start on tampered code", refused))

    LOG.info(RULE)
    LOG.info("[IC10] Peer evidence: digest a compromised console would place in header.integrity")
    bad_digest = measure(bad_root)
    trusted = store.host("sec-console-01").trusted_release_digests
    accepted = bad_digest in trusted
    LOG.info("  console digest %s... trusted list %s -> C12 %s", bad_digest[:24], [d[:24] + "..." for d in trusted],
             "would ACCEPT (FAIL)" if accepted else "REJECTS (ATTESTATION_MISMATCH)")
    results.append(("IC10", "Tampered peer digest not in trusted releases (C12)", not accepted))

    LOG.info(RULE)
    LOG.info("[IC11] Bytecode cache tampered: backdoored __pycache__/policy.*.pyc with the source's mtime and size")
    (tmp / "IC11").mkdir()
    clean_copy = tmp / "IC11" / "ciphermesh"
    shutil.copytree(root, clean_copy, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    pyc = plant_backdoored_pyc(clean_copy)
    LOG.info("  planted   : %s (every .py file is still byte-identical to the release)",
             pyc.relative_to(clean_copy.parent).as_posix())
    loaded = _decision_in_subprocess(clean_copy.parent)
    LOG.info("  python    : importing the copy and inspecting '#cm-override AKIA...' gives %s "
             "(an AWS key should be BLOCK) - the planted bytecode really runs", loaded)
    bad = self_attest(clean_copy, signed, release_pub)
    _report(bad)
    detected = not bad.ok and bool(bad.bytecode) and not bad.mismatched
    LOG.info("  verdict   : %s", "TAMPERING DETECTED -> SAFE MODE" if detected else "NOT DETECTED (FAIL)")
    results.append(("IC11", "Bytecode cache tampered (planted .pyc) detected", detected and loaded == "ALLOW"))

    shutil.rmtree(tmp, ignore_errors=True)
    LOG.info("=" * 96)
    LOG.info("SUMMARY")
    for cid, title, ok in results:
        LOG.info("  %-5s %-58s %s", cid, title, "PASS" if ok else "FAIL")
    passed = sum(ok for _, _, ok in results)
    LOG.info("  %d/%d integrity checks passed - %s", passed, len(results), "OVERALL PASS" if passed == len(results)
             else "OVERALL FAIL")
    return {"passed": passed, "total": len(results), "checks": [{"id": c, "title": t, "passed": o} for c, t, o in results]}


def main(argv: list[str] | None = None) -> int:
    sys.dont_write_bytecode = True
    from .attack_sim import configure_logging
    from .provision import DEFAULT_KEYS_DIR, DEFAULT_TRUST_DIR, ensure_provisioned, passphrase_from_env
    parser = argparse.ArgumentParser(description="CipherMesh host integrity verification run")
    parser.add_argument("--trust-dir", default=str(DEFAULT_TRUST_DIR))
    parser.add_argument("--keys-dir", default=str(DEFAULT_KEYS_DIR))
    parser.add_argument("--log-dir", default="logs")
    args = parser.parse_args(argv)
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    configure_logging(log_dir / "integrity_check.log")
    ensure_provisioned(Path(args.trust_dir), Path(args.keys_dir))
    logging.getLogger("ciphermesh.trust.agent").setLevel(logging.ERROR)
    result = run(Path(args.trust_dir), Path(args.keys_dir), passphrase_from_env())
    return 0 if result["passed"] == result["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
