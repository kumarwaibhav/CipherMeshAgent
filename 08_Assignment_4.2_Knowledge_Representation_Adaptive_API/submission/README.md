# CipherMesh - Assignment 4.2: Knowledge Representation and Adaptive API Integration

| | |
|---|---|
| Student | Kumar Waibhav Akshat |
| Register No. | RA2212704010027 |
| Programme | M.Tech (Integrated) CSE with specialization in Data Science, SRM Institute of Science and Technology, Kattankulathur |
| Course | 21CSE525T Agent Technology |
| Guide | Dr. Prabhu Kavin B, Assistant Professor, Department of Data Science and Business Systems |
| Date | November 2026 |

CipherMesh is "The Privacy Control Plane for Enterprise AI": a provider-neutral agent that inspects every prompt
(25 detectors, policy R1-R5) and routes it to AWS Bedrock (ap-south-1, IN), Azure AI Foundry (centralindia, IN),
GCP Vertex AI (us-central1, US) or a local Ollama runtime.

This unit gives the agent a **formal knowledge base** and connects it to **six live public REST/RSS endpoints**.
Live facts become graph triples and agent properties, and the agent's plan for the same prompt changes immediately.

## What was built

| Part | Location | What it does |
|---|---|---|
| Ontology (JSON-LD 1.1 style) | `ciphermesh/knowledge/ontology.json` | 29 classes, 24 object + 44 datatype properties, providers, regions, jurisdictions, all 25 detector categories in 12 families, DPDP Act 2023 / Aadhaar Act / GDPR, residency policy, rules R1-R5, threat classes, threat postures, live sources, currencies |
| JSON Schema | `ciphermesh/knowledge/ontology.schema.json` | Draft 2020-12 structural contract for the ontology file |
| Loader + validation | `ciphermesh/knowledge/ontology.py` | Schema check, semantic checks (undefined IRIs, rdfs:range, functional properties, subclass cycles), JSON-LD type coercion into triples |
| Triple store | `ciphermesh/knowledge/graph.py` | SPO/POS/OSP indexes, provenance per triple, pattern and conjunctive queries, RDFS inference, residency derivation, JSON / JSON-LD / SVG export |
| Live connectors | `ciphermesh/knowledge/feeds/` | GCP status JSON, Azure status RSS, AWS Health JSON (UTF-16), CISA KEV JSON, Frankfurter FX JSON, AI Incident Database RSS; TLS, timeout + overall deadline, retries, size cap, guarded redirects, TTL cache, parse-before-snapshot, text-free derived snapshots, stale-snapshot down-weighting, offline fallback, DTD refusal |
| Normaliser | `ciphermesh/knowledge/feeds/normalize.py` | Region and service names from ontology aliases, severity keywords, HTML cleaning, date parsing |
| Adapter | `ciphermesh/knowledge/adapter.py` | Facts -> triples (old live facts expired), signals -> properties, derived rules (INR budget -> USD cap, threat posture -> policy) with timing chain |
| Posture rule + calibration | `ciphermesh/knowledge/posture.py`, `calibration.py` | Three independent signal groups, HIGH needs two, hysteresis, leave-one-feed-out attribution; one-year KEV backtest |
| Properties | `ciphermesh/knowledge/properties.py` | `PropertySink` protocol (`set(key, value, source, confidence=1.0) -> bool`, `get(key, default=None)`) and `AgentProperties` with history and subscribers |
| Adaptive agent | `ciphermesh/knowledge/adaptive_agent.py` | Re-plans on every property change; `plan_for(prompt)` uses the real policy engine and router |
| Demonstration | `demo/live_adaptation_demo.py` | Phases A (defaults), B (live), C (re-plan, diff, attribution), D (pinned, labelled replay) |
| Backtest / replay pinning | `demo/kev_backtest.py`, `demo/pin_replay_inputs.py` | Threshold calibration check; pins replay inputs with a SHA-256 manifest |

## Brief (verbatim) -> evidence

| Brief line (verbatim) | Where it is satisfied | Evidence |
|---|---|---|
| Objective: "Enhance your agent's knowledge base through semantic knowledge representation or integration with external data APIs." | `ciphermesh/knowledge/` | report sections 3-5; `logs/live_feed_run.log` |
| Direction: "Implement a structured configuration format (JSON, Dictionary objects, or an ontological graph) to formally store your agent's domain knowledge." | `ontology.json`, `ontology.schema.json`, `ontology.py`, `graph.py` | `tests/knowledge/test_ontology.py`, `test_graph.py`; Phase A in the run log |
| Direction: "Integrate an external real-world REST API to feed the agent real knowledge maps (e.g., real live OpenWeather API maps for Travel planners, or real Geolocation maps for WiFi searches)." | `ciphermesh/knowledge/feeds/*` (6 live endpoints) | `logs/live_endpoints_report.json` (status, bytes, latency, SHA-256), `data/snapshots/*.meta.json` |
| Direction: "Enable the agent to dynamically adapt its internal plans based on the live unstructured data ingested." | `feeds/ai_incidents.py`, `normalize.py`, `adapter.py`, `posture.py`, `adaptive_agent.py` | Phase C diff + leave-one-feed-out attribution in the run log and `logs/demo_record.json`; `test_adaptive_agent.py` |
| Deliverables: "Code integration module demonstrating active connection to live endpoints and a parsing module changing agent properties instantly based on live feeds." | `feeds/base.py` + connectors; parsers, `adapter.py`, `properties.py` | Phase B of the run log; `logs/adaptation_events.jsonl` (property changes with timestamps and fetch -> parse -> property -> plan latencies); `test_live_endpoints.py` |
| Additional design requirement (not in brief): residency rule derivable from the graph | `KnowledgeGraph.derive_residency` | `test_graph.py` equivalence tests (25 categories, 300 pairs); `EQUAL=True` in the run log |

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt            # includes pytest

# live demonstration (contacts the six public endpoints; writes logs/ and data/snapshots/)
python demo/live_adaptation_demo.py

# same demonstration without network (saved snapshots only; the log is labelled OFFLINE)
python demo/live_adaptation_demo.py --offline --logs /tmp/a42_offline_logs

# KEV backtest and threshold check -> logs/kev_backtest.json
python demo/kev_backtest.py

# full test suite (engine + knowledge); the live test is skipped automatically when offline
python -m pytest -o addopts= -v -rs tests
```

## Commands that produced each log

| File | Command |
|---|---|
| `logs/live_feed_run.log`, `logs/adaptation_events.jsonl`, `logs/live_endpoints_report.json`, `logs/demo_record.json`, `logs/knowledge_graph_export.json`, `logs/knowledge_graph_live.svg`, `logs/knowledge_graph_replay.svg`, `data/snapshots/*` | `python demo/live_adaptation_demo.py` (run 2026-11-02 21:42 UTC, all six endpoints live) |
| `logs/kev_backtest.json` | `python demo/kev_backtest.py` |
| `data/replay/*` | `python demo/pin_replay_inputs.py` (run once; pinned files are part of the submission) |
| `logs/pytest_results.txt` | `python -m pytest -o addopts= -v -rs -p no:cacheprovider tests` |
| `docs/figures/fig_*.png` charts | `python3 docs/figures/make_charts.py <reportkit dir>` |
| `docs/figures/fig_ontology.png`, `fig_pipeline.png`, `fig_graph_*.png` | `python3 docs/figures/make_diagrams.py` then the report kit's `render_diagrams.js` |

## Report

`docs/Assignment_4.2_Knowledge_Representation_Adaptive_API_Report.pdf` and `.docx` are the built outputs. They were
built with the shared course report kit (`dsl.js`, `build_report.js`, `render_diagrams.js`), which is **not** part of
this folder. To rebuild, set `REPORTKIT=<path to the kit>`; see `docs/report_src/README.md`.

## Live endpoints

| Feed | Endpoint | Knowledge extracted |
|---|---|---|
| Google Cloud Service Health | `https://status.cloud.google.com/incidents.json` | Vertex AI incidents in us-central1 / global -> `provider.gcp-vertex.status` |
| Azure status | `https://azure.status.microsoft/en-us/status/feed/` | Unstructured RSS -> service + region + severity -> `provider.azure-ai.status` |
| AWS Health Dashboard | `https://health.aws.amazon.com/public/currentevents` | UTF-16 JSON events -> Bedrock / multiple services in ap-south-1 -> `provider.aws-bedrock.status` |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 30-day additions vs 12-month median, watched vendors, AI/ML products, ransomware -> threat posture |
| Frankfurter (ECB rates) | `https://api.frankfurter.dev/v1/latest?from=USD&to=INR` | USD/INR -> INR budget converted into `max_cost_per_1k_usd` |
| AI Incident Database | `https://incidentdatabase.ai/rss.xml` | Keyword classes in free-text news items -> privacy reports per covered day -> threat posture |

The AWS endpoint backs the public Health Dashboard page; it is not a documented API, so its parser is defensive and
the connector falls back to the saved snapshot if the format changes.

## Results of the recorded run (2026-11-02)

* 6/6 endpoints answered HTTP 200 over verified TLS (69 B to 1.83 MB, 162-660 ms).
* Live USD/INR 94.91: INR 300 per 1k requests -> USD 3.1609 cap; Azure (USD 3.30) becomes over budget and the
  local runtime becomes the best feasible route for all routed prompts.
* Live posture **ELEVATED**, caused by unstructured text: 11 privacy-related AI incident reports over 18.9 covered
  days (0.58 per day >= 0.5). The KEV catalog (ratio 1.404, 3 watched-vendor hits) stays below its calibrated
  thresholds. Effect: R5 limit 65,536 -> 32,768 bytes and two extra redaction patterns (AWS ARNs, Kubernetes DNS).
* All 5 demonstration prompts changed plan. Leave-one-feed-out: without the AI-incident feed the posture is LOW and
  the P4 (ARN redaction) and P5 (byte-limit block) changes disappear; without the FX feed the route changes disappear.
  Property change -> new plan took 0.11-0.80 ms.
* KEV backtest (122 dates, 2025-11-01..2026-10-30): uncalibrated thresholds gave HIGH on 46 % of days; calibrated
  thresholds with two-signal HIGH and hysteresis give HIGH 0.8 %, ELEVATED 23 %, LOW 76 %.
* Replay (pinned, labelled, not live) at 2026-02-27T13:00Z: the real Vertex Gemini API incident degrades gcp-vertex,
  the written what-if fixture puts Azure in outage; AWS and the AI-incident feed contribute no events at that date and
  the KEV catalog stays below threshold. A second replay at the backtest peak (2026-09-24) gives posture HIGH.

## Folder layout

```
README.md  requirements.txt  pytest.ini
ciphermesh/                engine (Units 1-3) + knowledge/ (this unit)
tests/engine/              112 engine tests      tests/knowledge/  130 tests for this unit
demo/                      live_adaptation_demo.py, kev_backtest.py, pin_replay_inputs.py
data/snapshots/            latest live data: text-free derivatives (raw only for FX) + .meta.json
                           (original URL, status, bytes, SHA-256, fetched_at)
data/replay/               pinned replay inputs + MANIFEST.json (SHA-256 per file)
logs/                      real run outputs and pytest_results.txt
docs/                      report (.docx, .pdf), figures/, report_src/
```

## Honest limitations

* Provider prices, latencies and quality scores are illustrative planning numbers (as in Units 3.1-3.2); the INR 300
  budget is an illustrative organisational setting.
* The live posture change rests on one weak signal: keyword classes over news text. Its threshold cannot be
  backtested (the feed has no history), it can reach ELEVATED alone but never HIGH, and lockdown stays operator-only.
* Today's provider feeds were quiet, so provider-status adaptation is shown with the pinned, labelled replay; the
  Azure item in that replay is a hand-written what-if fixture.
* Raw payloads that contain third-party prose are not redistributed. Each `.meta.json` keeps the original URL,
  status, bytes, SHA-256 and fetch time; the stored derivative keeps only structured fields and the tokens the parser
  read, and parses to the same signals. Re-fetch to reproduce the raw data.
* The India residency rule is CipherMesh's conservative organisational policy. The DPDP Act 2023 itself permits
  transfers abroad except to countries the government restricts (Section 16).
