# CipherMesh — Assignment 4.1: Belief-Desire-Intention (BDI) Goal-Driven Modeling

**Student:** Kumar Waibhav Akshat (RA2212704010027)
**Programme:** M.Tech (Integrated) CSE with specialization in Data Science, SRM Institute of Science and Technology, Kattankulathur
**Course:** 21CSE525T Agent Technology. **Guide:** Dr. Prabhu Kavin B, Assistant Professor, Department of Data Science and Business Systems
**Date:** November 2026

CipherMesh is *the privacy control plane for enterprise AI*: it inspects every prompt, blocks secrets, redacts personal data,
keeps Indian personal data in India and routes the prompt to the best feasible AI provider.
This assignment adds a **cognitive layer** (`ciphermesh/bdi/`) with explicit Beliefs, Desires and Intentions. The agent runs a
classic BDI deliberation cycle and **recalculates its plan when a belief changes mid-execution** (provider outage, emergency
lockdown, leaking reply, price spike, budget cut, data-residency change, prompt correction, review backlog).
Every plan step calls the real CipherMesh engine from Units 1 to 3 (detector + policy R1–R5, Contract-Net procurement,
constrained utility router, provider adapters, response inspection, review queue, audit log).

## Quick start

```bash
# Python 3.13 with the packages in requirements.txt
python demo/bdi_verification_run.py --latency-scale 0.05 --idle-wait 0.02   # verification run -> logs/
python -m pytest tests -vv -p no:cacheprovider > logs/pytest_results.txt     # 188 tests (112 engine + 76 BDI)
```

## Deliverables map

| Brief requirement | Where it is satisfied | Evidence |
|---|---|---|
| Cognitive-layer state machine tracking beliefs, desires, intentions | `ciphermesh/bdi/engine.py` (`BDIAgent.run`), `ciphermesh/bdi/intentions.py` (ACTIVE/SUSPENDED/SUCCEEDED/FAILED/DROPPED) | `logs/bdi_trace.jsonl` |
| **Beliefs** collection | `ciphermesh/bdi/beliefs.py` — `Belief`, `BeliefBase` (set/get/has/retract/subscribe/snapshot/history, thread-safe) | `tests/bdi/test_beliefs.py` |
| **Desires** collection | `ciphermesh/bdi/desires.py` — `Desire`, `DesireSet`, D1–D5 with priorities and conflicts | `tests/bdi/test_desires.py` |
| **Intentions** (step-by-step pipelines) | `ciphermesh/bdi/plans.py` (`PlanStep`, `Plan`, `PlanLibrary`), `ciphermesh/bdi/intentions.py` (`Intention`, `IntentionStack`) | `tests/bdi/test_plans.py`, `tests/bdi/test_intentions.py` |
| Dynamic plan recalculation when beliefs change | `BDIAgent._revise_and_reconsider` / `_reconsider` (subscription-driven, three-valued check, DROP/SUSPEND/RESUME, re-plan) | `tests/bdi/test_reconsideration.py` |
| Deliverable: source code of the BDI objects | `ciphermesh/bdi/` (public API in `__init__.py`) | — |
| Deliverable: verification run with an intention shift after an unexpected belief update | `demo/bdi_verification_run.py`, scenarios in `ciphermesh/bdi/scenarios.py` | `logs/bdi_verification_run.log` (INTENTION SHIFT blocks), `logs/bdi_summary.json` |
| Tests | `tests/bdi/` (76) + `tests/engine/` (112) | `logs/pytest_results.txt` |
| Report | `docs/Assignment_4.1_BDI_Goal_Driven_Modeling_Report.docx` / `.pdf` | figures in `docs/figures/` |

## Scenarios in the verification run

| ID | Unexpected belief update | Intention shift |
|---|---|---|
| S0 | none (control run) | none — proves the shifts below are caused by the belief updates |
| S1 | `provider.gcp-vertex.status = major_outage` after routing | `allow_then_dispatch(gcp-vertex)` → `allow_then_dispatch(aws-bedrock)` |
| S2 | `policy.lockdown = true` before dispatch | D1 pre-empts D3 → `enforce_lockdown_block`, nothing transmitted |
| S3 | `response.findings` contains a CRITICAL secret | deliver dropped → `withhold_reply_and_alert` |
| S4 | GCP price spikes above budget, then budget cut to $1.00 | gcp-vertex → aws-bedrock → `dispatch_local_only(local)` |
| S5 | Aadhaar prompt; Bedrock residency changes IN → US | aws-bedrock → azure-ai (IN) |
| S6 | user amends the prompt and adds a PAN | `allow_then_dispatch(gcp-vertex)` → `redact_then_dispatch(aws-bedrock)` |
| S7 | partial outage, then recovery | SUSPEND → RESUME on the same provider (no re-plan) |
| S8 | review queue fills to its limit | `hold_for_review` (D3) → `decline_review_overflow` (D5) |
| S1-BLIND, S2-BLIND | same as S1/S2 with blind commitment | ablation: the stale intention is not reconsidered; its dispatch step runs and is refused by the interlock (FAILED), then re-plan |

## Commands that produced each log

| File | Command |
|---|---|
| `logs/bdi_verification_run.log`, `logs/bdi_trace.jsonl`, `logs/bdi_summary.json` | `python demo/bdi_verification_run.py --latency-scale 0.05 --idle-wait 0.02` |
| `logs/pytest_results.txt` | `python -m pytest tests -vv -p no:cacheprovider > logs/pytest_results.txt` (run from a copy of this folder at `/tmp/CipherMesh_Assignment_4.1`; the file is unedited) |
| `docs/figures/fig_timeline_s1.png`, `fig_timelines_all.png`, `fig_ablation.png` | `python docs/figures/make_charts.py` (reads the logs; needs matplotlib) |
| `docs/figures/fig_bdi_architecture.png`, `fig_cycle.png`, `fig_states.png` | rendered from `docs/figures/diagrams.html` |
| `docs/Assignment_4.1_*.docx/.pdf` | built from `docs/report_src/content.js` with the course report kit |

## Folder layout

```
ciphermesh/            engine from Units 1-3 + new subpackage ciphermesh/bdi/
  bdi/beliefs.py       Belief, BeliefBase
  bdi/desires.py       Desire, DesireSet, ciphermesh_desires()
  bdi/plans.py         Condition, PlanStep, Plan, PlanLibrary, ciphermesh_plans()
  bdi/intentions.py    Intention, IntentionStack, IntentionStatus
  bdi/engine.py        BDIAgent, CommitmentStrategy, RunResult
  bdi/services.py      EngineServices (bridge to the real engine), EvidenceLedger (HMAC chain)
  bdi/world.py         shared interpretation of belief keys
  bdi/trace.py         Tracer (JSONL + readable lines)
  bdi/scenarios.py     Disturbance, Trigger, Environment, scenario catalogue
demo/                  bdi_verification_run.py
tests/                 engine/ (112 tests) and bdi/ (76 tests)
logs/                  real outputs of the commands above
docs/                  report (.docx/.pdf), figures/, report_src/
```

## Design notes

* **Commitment strategy:** OPEN_MINDED with event-driven reconsideration. An intention is re-evaluated only when a changed
  belief is one its *remaining* steps or the desires depend on. Conditions are three-valued: HOLDS (keep), UNCERTAIN
  (suspend, bounded wait) or VIOLATED (drop and re-plan). BLIND and SINGLE_MINDED exist for comparison.
* **No step runs on stale beliefs:** pending belief changes are revised immediately before every step, and the step's guard
  conditions are re-checked at execution time (a failing guard triggers reconsideration instead of the step).
* **Safety does not rely on deliberation alone:** the `dispatch` step re-checks lockdown, residency and believed provider
  status before transmitting.
* **Privacy:** raw prompt text never enters beliefs, logs or the trace; only hashes, categories and decisions.
## Limitations

* The evidence ledger reads its HMAC key from `CIPHERMESH_BDI_SEAL_KEY`; a fixed development fallback key is used only
  when that environment variable is unset (test and demo runs), so production must always set it.
* Disturbances are scripted at chosen steps; a deployment would feed beliefs from live status and price feeds.
* Cloud providers are simulated adapters with illustrative prices and latencies; the local tier calls a real Ollama server
  only when `CIPHERMESH_OLLAMA=1`.
