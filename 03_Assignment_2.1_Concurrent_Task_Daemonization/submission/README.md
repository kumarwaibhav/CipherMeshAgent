# CipherMesh - Assignment 2.1
## Concurrent Task Daemonization using Threads and Workers

**Student:** Kumar Waibhav Akshat  
**Register No.:** RA2212704010027  
**Programme:** M.Tech Integrated - CSE Data Science  
**Section:** AG1  
**Course:** 21CSE525T - Agent Technology  
**Faculty:** Dr. Prabhu Kavin B

This package continues the Assignment 1.2 CipherMesh reflex privacy agent and adds a concurrent execution layer without changing its security policy. Requests are placed into a bounded `queue.Queue`, processed by worker threads, observed by a daemon monitor, and written to a privacy-safe audit log by a separate background writer.

## Assignment mapping

- **Multi-threading / Worker Infrastructure:** configurable worker pool, bounded request queue, result queue, asynchronous audit writer.
- **Daemon Monitoring Functionality:** `MonitorDaemon` periodically samples worker health, queue depth, decisions, throughput and latency without blocking the primary thread.
- **Thread Safety & Concurrency Handling:** `queue.Queue`, `threading.Lock`, `threading.Event`, immutable detector policy, sentinels, `task_done()/join()`, graceful worker shutdown.
- **Performance evidence:** `execution_latency.log`, `benchmark_results.csv`, `benchmark_results.json`, `benchmark_summary.txt`, and benchmark charts in the report.

## Run the concurrent agent

```bash
python ciphermesh_concurrent_agent.py --workers 4 --monitor-interval 0.10 --simulate-provider-ms 120
```

The default input is `mock_llm_requests_2_1.jsonl`. No real LLM or cloud endpoint is contacted. `--simulate-provider-ms` is an explicit mock I/O wait used only to demonstrate how threads overlap I/O-bound provider latency.

## Run the benchmark

```bash
python benchmark_concurrency.py --requests 80 --io-ms 25 --workers 1 2 4 8
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Important implementation choice

The request workers are **non-daemon threads** so accepted tasks and audit events can be completed cleanly before process exit. The periodic **monitor is a daemon thread**, because it is observational rather than transactional, but it still receives a `threading.Event` and is stopped cleanly. This avoids relying on abrupt daemon termination for critical work.

## Folder contents

- `ciphermesh_concurrent_agent.py` - complete Assignment 2.1 implementation.
- `mock_llm_requests_2_1.jsonl` - synthetic multi-provider event stream.
- `benchmark_concurrency.py` - sequential vs threaded performance benchmark.
- `tests/test_concurrency.py` - concurrency, shutdown, policy and privacy tests.
- `logs/` - execution, monitoring, audit and benchmark evidence.
- `docs/` - formatted submission report in DOCX and PDF, with architecture and performance figures.
