# Assignment 5.1 - Agent Authentication and Host Integrity Verification

**CipherMesh - The Privacy Control Plane for Enterprise AI**
*Protect every prompt. Across every model. Before data leaves.*

| | |
|---|---|
| Student | Kumar Waibhav Akshat (RA2212704010027) |
| Programme | M.Tech (Integrated) CSE with specialization in Data Science, SRM Institute of Science and Technology, Kattankulathur |
| Course | 21CSE525T Agent Technology |
| Guide | Dr. Prabhu Kavin B, Assistant Professor, Department of Data Science and Business Systems |
| Date | November 2026 |

## What this is

Up to Assignment 2.2, CipherMesh nodes trusted any command carrying a valid HMAC-SHA256 made with one key shared by every
node. Anyone who can verify such a MAC can also create one, so a single compromised gateway could forge an emergency
lockdown or new redaction patterns for the whole mesh, and no single host could be revoked.

This assignment replaces that model with:

* **Per-host Ed25519 identities** (RFC 8032). The agent stores only public keys in `ciphermesh/trust/trusted_hosts.json`,
  so it can verify but never forge. Each key is bound to one host, has a validity window and can be revoked or rotated alone.
* **A strict SignedCommand envelope** signed over RFC 8785-style canonical JSON, with domain separation for commands,
  replies and release manifests.
* **Thirteen ordered, fail-closed checkpoints** (`CommandVerifier`, plus an L0 lockout gate) that every payload from the
  TCP loop or the local system-command spool passes *before* it is turned into an action:
  C1 frame size, C2 strict schema, C3 version, C4 recipient, C5 host trust, C6 key binding, C7 network origin,
  C8 Ed25519 signature, C9 payload hash, C10 freshness, C11 replay, C12 host integrity attestation, C13 authorization
  (commands per role, and field-level rules for STATE_SYNC so a peer gateway cannot weaken detection).
  The lockout is keyed on (address, claimed host) and cleared by a request that passes C8; the TCP server also
  enforces a 5 s per-frame deadline and at most 4 connections per address.
* **Host integrity verification**: a release manifest (SHA-256 of every source file, Python version, trust store hash)
  signed by a release key; the agent attests its own code at start-up and refuses to start or runs in SAFE MODE on a
  mismatch (a changed trust store always stops start-up); peers carry their attestation digest in every signed
  command (C12). The release is **source-only**: any `.pyc`, `__pycache__`, `.so`, `.pyd` or `.pth` under
  `ciphermesh/` fails attestation, because CPython would load a planted timestamp-based `.pyc` whose recorded source
  mtime and size match. Everything therefore runs with `PYTHONDONTWRITEBYTECODE=1` / `python -B`.
* **A breach simulation** over real TCP loopback with distinct source addresses and over the spool channel: 10 legitimate
  requests accepted, 41 unauthorised requests blocked at the expected checkpoint, engine state unchanged by every one.

## Quick start

```bash
pip install -r requirements.txt          # cryptography, pydantic, pytest (+ engine deps)
bash demo/run_all.sh python3             # reproduces every file in logs/
```

**Platform note.** The simulation binds client sockets to several loopback addresses (127.0.0.8 to 127.0.0.99). On
Linux the whole 127.0.0.0/8 block is routed to `lo`, so nothing needs to be set up. On macOS only 127.0.0.1 exists by
default; add aliases first, e.g. `for i in 8 9 10 11 12 13 14 15 20 30 40 66 67 68 69 70 71 72 99; do sudo ifconfig lo0
alias 127.0.0.$i up; done`.

`run_all.sh` provisions fresh keys, then runs the integrity check, the breach simulation, the benchmark and the full test
suite. Private keys are generated locally into `demo/keys/` (encrypted PKCS#8, mode 0600) and are **not** shipped. Set
`CIPHERMESH_KEY_PASSPHRASE` to choose the key passphrase; without it a demo passphrase is used and a warning is logged.

## Deliverables map

Brief lines are quoted verbatim, one per row.

| Brief line (verbatim) | Where it is satisfied | Evidence |
|---|---|---|
| Objective: Build cryptographic validation checkpoints protecting your agent's data payload from unauthorized access or modification. | `ciphermesh/trust/verifier.py` (`CommandVerifier`, L0 + C1-C13, fail closed) | `logs/security_runtime.log` |
| Implement secure payload parsing inside your agent via a signature system (e.g., verifying a sender's public keys before processing commands). | `trust/envelope.py`, `trust/canonical.py`, `trust/keys.py`; C2, C5, C6, C8, C9 run before any action | `tests/trust/test_envelope.py`, `test_verifier.py`, `test_keys.py` |
| Set up authentication checks verifying that payloads received via network loops or system commands originate from a trusted host environment. | C7 (kernel peer IP vs CIDR; spool file owner, mode, `O_NOFOLLOW`), C12, `trust/integrity.py` self-attestation | `logs/integrity_check.log`; A12, A21, A23, I01, I02 in the runtime log |
| Simulate an untrusted input breach and demonstrate how your agent safely handles or rejects unauthorized commands. | `trust/attack_sim.py` | `logs/breach_simulation_summary.json`, `.txt` |
| Deliverables: Cryptographically enhanced agent code module along with verified runtime test logs capturing a blocked unauthorized request event. | `ciphermesh/trust/` (`secure_agent.py`, `secure_server.py`, `client.py`, ...); 41 `BLOCKED UNAUTHORIZED REQUEST` entries with checkpoint, reason and `STATE UNCHANGED` | `logs/security_runtime.log`, `logs/security_events.jsonl`, `logs/pytest_results.txt` |

Supporting material: micro-benchmark `trust/benchmark.py` -> `logs/crypto_benchmark.txt`, `.json`; report
`docs/Assignment_5.1_Agent_Authentication_Host_Integrity_Report.docx` / `.pdf` (source and build notes in
`docs/report_src/`).

## Results of the submitted run

* Breach simulation: 51 cases; legitimate accepted 10/10; attacks blocked 41/41, all at the expected checkpoint;
  state unchanged by every rejected command; prompts still classified correctly 6/6; 4 security alerts
  (1 HOST_INTEGRITY_FAILURE, 3 SOURCE_LOCKOUT). Every checkpoint C1-C13 and L0 stopped at least one attack.
  New since the review: A26 peer STATE_SYNC weakening policy (C13 STATE_FIELD_NOT_PERMITTED), A27 forged burst to
  lock out the console followed by S09 (real console accepted, lock cleared), A28 slow-drip connections
  (L0 FRAME_TIMEOUT, CONNECTION_LIMIT).
* Host integrity run: 11/11 checks (backdoor, planted file, deleted file, edited manifest, re-signed manifest,
  rogue trust-store host refuses start, strict refusal, peer digest, planted bytecode cache).
* Tests: 269 passed (112 engine tests from Units 1-3 unchanged + 157 new tests in `tests/trust/`).
* Cost: accepted verification 301 us median; C8 (canonical re-encoding + Ed25519 verify) is about 68 % of the mean
  cost; rejection at C1/C2 in 5-12 us.

## Commands that produced each log

| Log | Command (from the deliverable root) |
|---|---|
| `ciphermesh/trust/trusted_hosts.json`, `release_manifest.json`, `release_signer.pub` | `python -B -m ciphermesh.trust.provision` |
| `logs/integrity_check.log` | `python -B demo/run_integrity_check.py` |
| `logs/security_runtime.log`, `logs/security_events.jsonl`, `logs/breach_simulation_summary.json`, `logs/breach_simulation_summary.txt` | `python -B demo/run_breach_simulation.py` |
| `logs/crypto_benchmark.txt`, `logs/crypto_benchmark.json` | `python -B demo/run_crypto_benchmark.py` |
| `logs/pytest_results.txt` | `python -B -m pytest tests -o addopts="" -v --no-header -p no:cacheprovider > logs/pytest_results.txt` |
| `docs/figures/chart_*.png` | `python docs/figures/make_charts.py <reportkit>/chart_style.py` (needs matplotlib); full report build steps in `docs/report_src/README.md` |

## Interactive use

Keys, trust store and manifest are provisioned automatically on first run (a fresh copy has no private keys).
The interactive server and spool agent write their audit trail to `logs/interactive_events.jsonl`.

```bash
export PYTHONDONTWRITEBYTECODE=1
python -B -m ciphermesh.trust.secure_server --port 9061                    # agent on TCP
python -B -m ciphermesh.trust.client --as sec-console-01 --source 127.0.0.10 \
       TRIGGER_EMERGENCY_LOCKDOWN --payload '{"reason": "drill"}'           # accepted
python -B -m ciphermesh.trust.client --as sec-console-01 --source 127.0.0.66 \
       TRIGGER_EMERGENCY_LOCKDOWN --payload '{"reason": "drill"}'           # rejected at C7
python -B -m ciphermesh.trust.secure_agent --spool /path/to/spool           # local system-command channel
```

## Layout

```
ciphermesh/            Units 1-3 engine (unchanged) + new trust/ subpackage
  trust/               canonical, keys, commands, envelope, verifier, integrity, secure_agent,
                       secure_server, client, provision, attack_sim, integrity_check, benchmark
tests/engine/          112 engine tests        tests/trust/   157 new tests
demo/                  run_all.sh and the three run_*.py scripts
logs/                  real outputs of the submitted run
docs/                  report (.docx/.pdf), figures/ (PNGs, diagrams.html, make_charts.py), report_src/ (content.js, build notes)
```

## Known limitations

Attestation is software-only (a fully compromised host could lie about its digest; TPM-backed quotes would close this);
the simulation uses loopback addresses (production should back C7 with mutual TLS); the replay cache is in memory
(C10's 60 s window bounds the exposure after a restart); a forger inside an allowed range can still lock an
(address, host) key until the real host's next authentic request clears it, and each forged request to a locked
key still costs one signature check.
