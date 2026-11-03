# CipherMesh
## Multi-Cloud LLM Privacy Gateway + Distributed Agent Messaging

**Student:** Kumar Waibhav Akshat  
**Registration ID:** RA2212704010027  
**Programme:** Integrated M.Tech, Computer Science & Engineering (Data Science)  
**Section:** AG1  
**Implementation version:** 0.3.0

CipherMesh is a local-first educational prototype that places a deterministic privacy inspection boundary in front of LLM requests and demonstrates networked agent messaging using raw TCP sockets. The most important assessed path is a two-terminal run in which **Agent-A transfers typed policy state to Agent-B**, which validates the envelope, applies approved policy parameters, and acknowledges the result.

## Core capabilities

- Typed JSON message envelope with schema version, UUID-like message ID, timestamp, sender, recipient, optional correlation ID, and message type.
- TCP framing uses a four-byte unsigned big-endian byte length followed by UTF-8 JSON. Exact-read loops handle fragmented TCP deliveries.
- Bounded worker concurrency, socket timeouts, frame-size limits, message-ID replay rejection, and explicit ACK/ERROR responses.
- Validated and revisioned policy-state synchronization. Receiver identity, sequence counters, and emergency lockdown state are locally controlled and cannot be overwritten by a state-sync payload.
- Proactive command handling: `TRIGGER_EMERGENCY_LOCKDOWN`, `UPDATE_REDACTION_PATTERNS`, and `REQUEST_TELEMETRY_DUMP`.
- Decision engine: `BLOCK > REVIEW > REDACT > ALLOW`.
- Metadata-only SQLite audit trail; findings include categories and character offsets, not the matched sensitive values.
- Optional FastAPI interface and provider-neutral preflight boundary. No external model provider is called by this prototype.

## Architecture at a glance

```text
Developer / Application
        |
        v
Privacy inspection boundary ----------------> Future provider adapter (not included)
        |                                       AWS Bedrock / Azure AI / Vertex AI / local
        |
Agent-A CLI -- length-prefixed JSON over TCP --> Agent-B TCP listener
                                                   |-- validate and authenticate
                                                   |-- dispatch typed message
                                                   |-- apply approved state / command
                                                   |-- metadata audit
                                                   `-- ACK or ERROR response
```

## Requirements

- Python 3.10 or later.
- Core runtime dependency: Pydantic 2.6+.
- No cloud credentials or paid API calls are required for the socket demonstration.
- Optional REST integration uses FastAPI and Uvicorn.
- SQLite is included in the Python standard library.

## Install

### Windows PowerShell

```powershell
cd ciphermesh
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev,api]"
```

For only the TCP demonstration, `pip install -e ".[dev]"` is sufficient. If packaging tools are already installed, an offline local install may use `python -m pip install -e ".[dev]" --no-build-isolation`.

### macOS / Linux

```bash
cd ciphermesh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev,api]"
```

## Required dual-terminal demonstration

The default receiver port is **9052**, matching the reference specification. The server binds to loopback (`127.0.0.1`) by default.

### Terminal 1 — start Agent-B

```powershell
$env:CIPHERMESH_SHARED_TOKEN="demo-change-this-token"
python -m ciphermesh.server --host 127.0.0.1 --port 9052 --agent-id AGENT_B_NODE_01 --audit-path agent_b_audit.db
```

Expected startup line:

```text
[AGENT_B_NODE_01] listening on 127.0.0.1:9052; Ctrl+C to stop
```

### Terminal 2 — send messages from Agent-A

```powershell
$env:CIPHERMESH_SHARED_TOKEN="demo-change-this-token"
python -m ciphermesh.client --host 127.0.0.1 --port 9052 ping
python -m ciphermesh.client --host 127.0.0.1 --port 9052 sync-state
python -m ciphermesh.client --host 127.0.0.1 --port 9052 inspect --text "Contact alice@example.com"
python -m ciphermesh.client --host 127.0.0.1 --port 9052 inspect --text "aws_access_key=AKIA1234567890ABCDEF"
python -m ciphermesh.client --host 127.0.0.1 --port 9052 update-patterns "PROJECT-CODE-[A-Z]{4}"
python -m ciphermesh.client --host 127.0.0.1 --port 9052 inspect --text "Reference PROJECT-CODE-ABCD in this stack trace"
python -m ciphermesh.client --host 127.0.0.1 --port 9052 telemetry
```

Run lockdown last, because it deliberately blocks all subsequent content at that agent:

```powershell
python -m ciphermesh.client --host 127.0.0.1 --port 9052 lockdown
python -m ciphermesh.client --host 127.0.0.1 --port 9052 inspect --text "ordinary clean text"
```

Use the same token in both terminals. These sample credentials and tokens are synthetic. Never paste actual credentials into terminal commands or screenshots.

### Unix shell variant

Replace PowerShell environment assignment with:

```bash
export CIPHERMESH_SHARED_TOKEN='demo-change-this-token'
```

The client commands are otherwise the same.

## Expected behavior

| Client command | Receiver behavior | Expected response |
|---|---|---|
| `ping` | Validates and acknowledges a message | `ACK`, `status: ok` |
| `sync-state` | Applies higher policy revision and approved fields | `ACK`, `state_applied` (or `state_unchanged` if repeated) |
| `inspect` with email | Detects and masks PII | Decision `REDACT`; matched email is not returned |
| `inspect` with AWS-like key | Detects critical pattern | Decision `BLOCK` |
| `update-patterns` | Validates, then appends bounded custom regex patterns | `ACK`, `patterns_updated` |
| `telemetry` | Returns allow-listed configuration/counters only | `ACK`, `telemetry_ready` |
| `lockdown` | Activates `FORCE_BLOCK_ALL` | `ACK`, `lockdown_enabled`; subsequent content is blocked |

## Optional REST API

Install the API extra, then run:

```bash
uvicorn ciphermesh.api:app --host 127.0.0.1 --port 8000
```

Endpoints: `GET /health`, `GET /state`, `POST /inspect`, `POST /gateway/prepare`. Interactive docs are served at `http://127.0.0.1:8000/docs`. The preflight route does not call a model; it returns a decision and only prepares content for `ALLOW` or sanitized `REDACT` decisions.

Example:

```bash
curl -X POST http://127.0.0.1:8000/gateway/prepare \
  -H "Content-Type: application/json" \
  -d '{"text":"Email alice@example.com","provider":"local"}'
```

## Tests

```bash
python -m pytest -q
```

The test suite exercises core policy decisions, oversized and fragmented frames, malformed typed envelopes, live loopback TCP state synchronization, remote inspection, pattern updates, lockdown, telemetry scrubbing, replay-safe policy revisions, and gateway enforcement.

## Configuration

| Variable / argument | Default | Purpose |
|---|---:|---|
| `CIPHERMESH_HOST` / `--host` | `127.0.0.1` | Listener address; loopback is safest for the demo |
| `CIPHERMESH_PORT` / `--port` | `9052` | Agent-B sync endpoint |
| `CIPHERMESH_MAX_BYTES` / `--max-frame` | `65536` | Maximum JSON frame size |
| `CIPHERMESH_MAX_WORKERS` / `--max-workers` | `32` | Bounded concurrent client handlers |
| `CIPHERMESH_SHARED_TOKEN` / `--token` | empty | Optional shared token for the local demonstration |

## Security and engineering limitations

This is a learning and demonstration baseline, not a production gateway.

- TCP is not encrypted. Keep the server on loopback. Remote/private-network operation requires TLS or mTLS, identity-aware authorization, and firewall controls.
- A shared token is only a demonstration control; it is not a substitute for mutual TLS, rotation, or per-agent identities.
- Custom regular expressions are length/count-limited, compiled before application, and screened for common high-risk constructs. This is defense-in-depth, not a formal proof against regex denial of service.
- A remote policy sender must be trusted. Production policy updates should use signed bundles, role-based authorization, stronger replay protection, key rotation, and auditable approvals.
- The detector is an explicit regex baseline. It can miss credential formats and generate false positives. Microsoft Presidio is identified as a possible future integration but is not active in this execution path.
- The system does not yet execute real calls to AWS Bedrock, Azure AI, Google Vertex AI, or Ollama. An adapter must call the preflight boundary and refuse transmission for `REVIEW` and `BLOCK`, and use sanitized text for `REDACT`.
- Review decisions are returned as `REVIEW`; a full queue and human approval UI are future work. The `APPROVAL` message handler records a correlated boolean but does not yet connect that state to an external queue.
- The four-byte frame length detects message boundaries, not cryptographic integrity. TLS and/or message signing are necessary across trust boundaries.

## Project files

```text
ciphermesh/
  ciphermesh/
    models.py       typed schemas and policy state
    transport.py    TCP frame encoding/decoding and request client
    server.py       bounded Agent-B TCP server
    client.py       Agent-A message CLI
    agent.py        autonomous handlers, state sync, replay checks, metrics
    detector.py     baseline and validated custom regex detectors
    policy.py       ordered ALLOW/REDACT/REVIEW/BLOCK policy
    gateway.py      provider-neutral preflight boundary
    audit.py        metadata-only SQLite audit
    api.py          optional REST API
  tests/            unit, transport, gateway, and live TCP integration tests
  docs/             implementation report in Markdown / DOCX / PDF, plus illustrations
  README.md
  pyproject.toml
```


## Multi-agent coordination protocol (new in v0.3.0)

CipherMesh includes a second demonstration: two distinct agent instances negotiate an inspection-capacity service using a Contract-Net-inspired protocol. The `WORKLOAD_BUYER` evaluates price and service-level constraints; the `INSPECTION_SUPPLIER` offers configured capacity and performance metrics. A coordinator bounds the number of turns and runs an explicit consensus handshake.

### Run the negotiation

```bash
python -m ciphermesh.negotiation.demo
```

Export the complete terminal result as JSON as well:

```bash
python -m ciphermesh.negotiation.demo --json-out docs/examples/negotiation_result.json
```

To demonstrate bounded failure when the buyer's budget is too restrictive:

```bash
python -m ciphermesh.negotiation.demo --buyer-max-price 120 --max-rounds 6
```

The successful default scenario uses a deterministic profile and normally converges in five offer rounds, followed by PREPARE/READY and COMMIT/COMMIT_ACK. The settlement and utilities are generated by utility functions, not hard-coded as an expected answer.

### Protocol and economics

- `CALL_FOR_PROPOSAL` -> `PROPOSAL` -> alternating `COUNTEROFFER` messages.
- Each agent uses a linear utility function and a turn-sensitive aspiration threshold; concession rates increase with turn number while remaining bounded.
- The buyer checks required capacity, maximum p95 latency, and minimum estimated recall before evaluating price.
- A candidate must satisfy both agents' reservation utilities before the handshake starts.
- Both participants validate the exact same contract payload and SHA-256 digest during PREPARE, then COMMIT, and return matching COMMIT_ACK messages. Consensus is only reported after both acknowledgements match.
- Negotiation messages are Pydantic-typed and JSON serialized/deserialized through a bounded local message bus. This is a deterministic in-process coordination demo, not a remote socket protocol; the separate CipherMesh TCP client/server demo remains the network-transport exercise.

The full design, utility derivation, turn-by-turn terminal timeline, test evidence, and implementation files are documented in `docs/Multi_Agent_Coordination_Report.md`. A saved sample timeline is in `docs/examples/multi_agent_negotiation_timeline.txt`.

