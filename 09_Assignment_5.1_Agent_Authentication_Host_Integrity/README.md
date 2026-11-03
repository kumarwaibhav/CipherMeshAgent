<p align="left"><img src="../assets/brand/app-icon.svg" alt="CipherMesh" width="56"></p>

# Assignment 5.1: Agent Authentication and Host Integrity Verification

**Objective.** Protect the agent with cryptographic checks and show it rejecting unauthorized commands.

## What was delivered

- Ed25519-signed command envelopes with 13 ordered checkpoints.
- Trusted-host registry, replay protection and code self-attestation.
- Breach simulation over TCP: 41 of 41 attacks blocked, 10 of 10 legitimate commands accepted.
- 269 tests passing.

## Evidence

| Item | File |
|---|---|
| Report (PDF) | [`submission/docs/Assignment_5.1_Agent_Authentication_Host_Integrity_Report.pdf`](submission/docs/Assignment_5.1_Agent_Authentication_Host_Integrity_Report.pdf) |
| Runtime log with blocked requests | [`submission/logs/security_runtime.log`](submission/logs/security_runtime.log) |
| Code | [`submission/ciphermesh/trust/`](submission/ciphermesh/trust/) |
| Tests | [`submission/logs/pytest_results.txt`](submission/logs/pytest_results.txt) |

[← Back to all assignments](../README.md#-assignments)

---
Kumar Waibhav Akshat (RA2212704010027) · 21CSE525T Agent Technology
