"""Micro-benchmark: Ed25519 sign/verify, canonical JSON, per-checkpoint verifier cost, TCP round trip.

Assignment 5.1 - Agent Authentication and Host Integrity Verification.
Author: Kumar Waibhav Akshat (RA2212704010027).

Writes ``logs/crypto_benchmark.txt`` (readable) and ``logs/crypto_benchmark.json``
(raw numbers used for the report chart). Keys are provisioned into a temporary
directory so the benchmark never touches the real trust store.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import platform
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

import cryptography
from cryptography.hazmat.backends.openssl import backend as openssl_backend

from . import commands as cmd
from .client import SecureClient
from .canonical import canonicalize
from .envelope import COMMAND_CONTEXT, create_command, encode, parse, signing_bytes, utc_now
from .integrity import load_signed_manifest, measure, package_root, self_attest
from .keys import SigningIdentity, load_public_key
from .provision import provision
from .secure_agent import AgentConfig, SecureCipherMeshAgent
from .secure_server import BackgroundServer
from .verifier import CHECKPOINT_ORDER, CommandVerifier, FailureLimiter, Origin


def _stats(samples_ns: list[int]) -> dict:
    us = sorted(s / 1000.0 for s in samples_ns)
    pick = lambda q: us[min(len(us) - 1, int(q * len(us)))]  # noqa: E731
    return {"n": len(us), "mean_us": statistics.fmean(us), "p50_us": pick(0.50), "p95_us": pick(0.95),
            "p99_us": pick(0.99), "min_us": us[0]}


def _time(fn, n: int) -> dict:
    samples = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        samples.append(time.perf_counter_ns() - t0)
    return _stats(samples)


def run(n: int = 3000) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="cm-bench-"))
    prov = provision(tmp / "trust", tmp / "keys", passphrase=None)
    admin = prov.identities["sec-console-01"]
    digest = prov.release_digest
    payload = {"patterns": ["PRJ-[0-9]{4}"]}
    sample = create_command(admin, prov.trust_store.agent_id, cmd.UPDATE_REDACTION_PATTERNS, payload, digest)
    data = signing_bytes(sample["header"], sample["payload"], COMMAND_CONTEXT)
    signature = admin.sign(data)
    hkey = b"k" * 32
    results: dict = {"environment": {
        "python": sys.version.split()[0], "cryptography": cryptography.__version__,
        "openssl": openssl_backend.openssl_version_text(),
        "platform": platform.platform(), "machine": platform.machine(), "iterations": n,
        "signed_bytes": len(data), "frame_bytes": len(encode(sample)),
    }}
    results["keygen"] = _time(lambda: SigningIdentity.generate("x"), 300)
    results["ed25519_sign"] = _time(lambda: admin.sign(data), n)
    results["ed25519_verify"] = _time(lambda: admin.public_key.verify(signature, data), n)
    results["hmac_sha256_sign"] = _time(lambda: hmac.new(hkey, data, hashlib.sha256).digest(), n)
    tag = hmac.new(hkey, data, hashlib.sha256).digest()
    results["hmac_sha256_verify"] = _time(
        lambda: hmac.compare_digest(hmac.new(hkey, data, hashlib.sha256).digest(), tag), n)
    results["canonical_json"] = _time(lambda: canonicalize({"header": sample["header"], "payload": payload}), n)
    raw = encode(sample)
    results["strict_parse_schema"] = _time(lambda: parse(raw), n)
    results["create_command"] = _time(lambda: create_command(admin, prov.trust_store.agent_id,
                                                             cmd.UPDATE_REDACTION_PATTERNS, payload, digest), n)

    verifier = CommandVerifier(prov.trust_store, limiter=FailureLimiter(threshold=10**9))
    origin = Origin("tcp", "127.0.0.10", "50000")
    frames = [encode(create_command(admin, prov.trust_store.agent_id, cmd.UPDATE_REDACTION_PATTERNS, payload,
                                    digest)) for _ in range(n)]
    totals, per_cp = [], {cp: [] for cp in CHECKPOINT_ORDER}
    for frame in frames:
        verdict = verifier.verify(frame, origin)
        assert verdict.accepted, verdict.reason
        totals.append(int(verdict.latency_us * 1000))
        for cp, ns in verdict.timings_ns.items():
            per_cp[cp].append(ns)
    results["verify_accepted_total"] = _stats(totals)
    results["per_checkpoint"] = {cp: _stats(v) for cp, v in per_cp.items() if v}
    results["verify_throughput_per_s"] = 1e6 / results["verify_accepted_total"]["mean_us"]

    attacker = SigningIdentity.generate("rogue")
    forged = create_command(attacker, prov.trust_store.agent_id, cmd.TRIGGER_EMERGENCY_LOCKDOWN, {"reason": "x"},
                            digest)
    forged["header"]["sender_host"], forged["header"]["key_id"] = "sec-console-01", admin.key_id
    forged_raw = encode(forged)
    results["reject_C1_oversize"] = _time(lambda: verifier.verify(b"", origin, declared_length=10**6), n)
    results["reject_C2_malformed"] = _time(lambda: verifier.verify(b'{"header": ', origin), n)
    results["reject_C7_origin"] = _time(lambda: verifier.verify(forged_raw, Origin("tcp", "127.0.0.66")), n)
    results["reject_C8_forged"] = _time(lambda: verifier.verify(forged_raw, origin), n)

    signed = load_signed_manifest(prov.manifest_path)
    release_pub = load_public_key(prov.release_pub_path)
    results["self_attestation"] = _time(lambda: self_attest(package_root(), signed, release_pub, prov.trust_path), 50)
    results["measure_digest"] = _time(lambda: measure(), 50)

    agent = SecureCipherMeshAgent(prov.identities[prov.trust_store.agent_id], prov.trust_store,
                                  signed_manifest=signed, release_public_key=release_pub,
                                  trust_store_path=prov.trust_path, config=AgentConfig(lockout_threshold=10**9))
    logging.getLogger("ciphermesh.trust").setLevel(logging.ERROR)
    with BackgroundServer(agent) as server:
        client = SecureClient(prov.identities["observer-01"], prov.trust_store, server.port, source_ip="127.0.0.20",
                              integrity=digest)
        samples = []
        for _ in range(300):
            env = client.command(cmd.REQUEST_TELEMETRY_DUMP)
            t0 = time.perf_counter_ns()
            reply = client.send_envelope(env)
            samples.append(time.perf_counter_ns() - t0)
            assert reply.verified and reply.status == "ACCEPTED"
        results["tcp_round_trip_signed"] = _stats(samples)
    shutil.rmtree(tmp, ignore_errors=True)
    results["generated_at"] = utc_now().isoformat(timespec="seconds").replace("+00:00", "Z")
    return results


LABELS = [
    ("keygen", "Ed25519 key generation"),
    ("ed25519_sign", "Ed25519 sign (command signing input)"),
    ("ed25519_verify", "Ed25519 verify"),
    ("hmac_sha256_sign", "HMAC-SHA256 sign (Unit 2.2 baseline)"),
    ("hmac_sha256_verify", "HMAC-SHA256 verify (Unit 2.2 baseline)"),
    ("canonical_json", "Canonical JSON (RFC 8785 style)"),
    ("strict_parse_schema", "Strict parse + schema (C2 work)"),
    ("create_command", "Client: build + sign SignedCommand"),
    ("verify_accepted_total", "CommandVerifier.verify (accepted, 13/13)"),
    ("reject_C1_oversize", "Reject at C1 (oversized frame)"),
    ("reject_C2_malformed", "Reject at C2 (malformed JSON)"),
    ("reject_C7_origin", "Reject at C7 (untrusted origin)"),
    ("reject_C8_forged", "Reject at C8 (forged signature)"),
    ("measure_digest", "Attestation digest (hash all sources)"),
    ("self_attestation", "Self-attestation (manifest sig + files)"),
    ("tcp_round_trip_signed", "TCP round trip, signed cmd + signed reply"),
]


def render(results: dict) -> str:
    env = results["environment"]
    out = ["CipherMesh Assignment 5.1 - cryptographic micro-benchmark",
           f"generated {results['generated_at']} | Python {env['python']} | cryptography {env['cryptography']} | "
           f"{env['openssl']}", f"platform {env['platform']} | iterations {env['iterations']} | signed input "
           f"{env['signed_bytes']} bytes | frame {env['frame_bytes']} bytes", "",
           f"{'Operation':46} {'n':>6} {'mean us':>9} {'p50 us':>9} {'p95 us':>9} {'p99 us':>9}", "-" * 92]
    for key, label in LABELS:
        s = results[key]
        out.append(f"{label:46} {s['n']:>6} {s['mean_us']:>9.1f} {s['p50_us']:>9.1f} {s['p95_us']:>9.1f} "
                   f"{s['p99_us']:>9.1f}")
    out += ["", f"Verifier throughput (single thread, accepted path): {results['verify_throughput_per_s']:,.0f} "
            "commands/s", "", "Per-checkpoint cost on the accepted path (mean of all iterations):",
            f"{'Checkpoint':12} {'mean us':>9} {'p95 us':>9} {'share':>7}", "-" * 41]
    total = sum(s["mean_us"] for s in results["per_checkpoint"].values())
    for cp, s in results["per_checkpoint"].items():
        out.append(f"{cp:12} {s['mean_us']:>9.2f} {s['p95_us']:>9.2f} {100 * s['mean_us'] / total:>6.1f}%")
    out.append(f"{'sum':12} {total:>9.2f}")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CipherMesh 5.1 crypto micro-benchmark")
    parser.add_argument("--log-dir", default="logs")
    parser.add_argument("-n", type=int, default=3000)
    args = parser.parse_args(argv)
    results = run(args.n)
    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    text = render(results)
    (log_dir / "crypto_benchmark.txt").write_text(text, encoding="utf-8")
    (log_dir / "crypto_benchmark.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
