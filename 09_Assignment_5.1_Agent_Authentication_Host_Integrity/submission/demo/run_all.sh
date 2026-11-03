#!/usr/bin/env bash
# Assignment 5.1 - reproduce every log in logs/ (Kumar Waibhav Akshat, RA2212704010027).
# Usage: bash demo/run_all.sh [python-interpreter]
# Source-only release: no bytecode is written (PYTHONDONTWRITEBYTECODE=1) and stale caches are removed,
# because self-attestation treats any .pyc under ciphermesh/ as tampering.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${1:-python3}"
export PYTHONDONTWRITEBYTECODE=1
ERR="$(mktemp)"; trap 'rm -f "$ERR"' EXIT
step() { local label="$1"; shift; echo "$label"; "$@" > /dev/null 2> "$ERR" || { cat "$ERR"; exit 1; }; }
find ciphermesh -name __pycache__ -type d -prune -exec rm -rf {} +
mkdir -p logs
step "[1/5] provisioning host keys, trust store and signed release manifest" "$PY" -B -m ciphermesh.trust.provision
step "[2/5] host integrity verification run      -> logs/integrity_check.log" "$PY" -B demo/run_integrity_check.py
step "[3/5] breach simulation over TCP + spool   -> logs/security_runtime.log, security_events.jsonl, breach_simulation_summary.*" "$PY" -B demo/run_breach_simulation.py
step "[4/5] crypto micro-benchmark               -> logs/crypto_benchmark.txt/.json" "$PY" -B demo/run_crypto_benchmark.py
echo "[5/5] full test suite                      -> logs/pytest_results.txt"
"$PY" -B -m pytest tests -o addopts="" -v --no-header -p no:cacheprovider > logs/pytest_results.txt 2>&1 || { tail -30 logs/pytest_results.txt; exit 1; }
tail -1 logs/pytest_results.txt
