<p align="left"><img src="../assets/brand/app-icon.svg" alt="CipherMesh" width="56"></p>

# Assignment 2.1: Concurrent Task Daemonization using Threads and Workers

**Objective.** Run background processing so the agent never blocks its core loop.

## What was delivered

- Configurable worker pool with a bounded request queue and result queue.
- Background monitor daemon that polls provider health.
- Thread-safe shared state with locks and queues.
- Benchmark: throughput rose from 39.7 to 302.3 requests per second with 8 workers (7.6×).

## Evidence

| Item | File |
|---|---|
| Report (PDF) | [`submission/docs/Assignment_2.1_CipherMesh_Concurrent_Task_Daemonization_Report.pdf`](submission/docs/Assignment_2.1_CipherMesh_Concurrent_Task_Daemonization_Report.pdf) |
| Latency and benchmark logs | [`submission/logs/`](submission/logs/) |
| Code | [`submission/ciphermesh_concurrent_agent.py`](submission/ciphermesh_concurrent_agent.py) |
| Tests | [`submission/tests/`](submission/tests/) |

[← Back to all assignments](../README.md#-assignments)

---
Kumar Waibhav Akshat (RA2212704010027) · 21CSE525T Agent Technology
