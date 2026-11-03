"""Benchmark sequential vs threaded CipherMesh processing with simulated I/O.

The mock wait models downstream provider/network latency. It is explicit so the
benchmark does not pretend CPU-bound regular-expression work is accelerated by
Python threads. Threads are used here to overlap I/O-bound waiting and to keep
the primary event loop responsive.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import time
from dataclasses import dataclass
from pathlib import Path

from ciphermesh_concurrent_agent import CipherMeshConcurrentAgent, LLMRequest, process_request


@dataclass
class BenchmarkRow:
    mode: str
    workers: int
    requests: int
    simulated_io_ms: float
    wall_ms: float
    throughput_req_s: float
    avg_service_ms: float
    p95_service_ms: float
    avg_end_to_end_ms: float
    p95_end_to_end_ms: float
    speedup_vs_sequential: float


def percentile(values: list[float], p: float) -> float:
    values = sorted(values)
    if not values:
        return 0.0
    return values[int(round((len(values) - 1) * p))]


def build_requests(count: int) -> list[LLMRequest]:
    templates = [
        ("ollama-local", "gemma3", "Explain concurrency and worker queues."),
        ("azure-ai", "gpt-demo", "Summarize for analyst@example.com and call +91 9876543210."),
        ("aws-bedrock", "demo-model", "Check AKIAIOSFODNN7EXAMPLE before sending this prompt."),
        ("gcp-vertex", "gemini-demo", "Summarize https://payments.internal/debug from 10.20.30.40."),
    ]
    result: list[LLMRequest] = []
    for i in range(count):
        provider, model, prompt = templates[i % len(templates)]
        result.append(
            LLMRequest(
                timestamp="2026-09-02T10:00:00+05:30",
                request_id=f"BENCH-{i + 1:04d}",
                provider=provider,
                model=model,
                prompt=prompt,
            )
        )
    return result


def run_sequential(requests: list[LLMRequest], io_ms: float) -> tuple[float, list]:
    started = time.perf_counter_ns()
    results = []
    for request in requests:
        now = time.perf_counter_ns()
        results.append(process_request(request, worker_name="sequential-main", enqueued_ns=now, simulate_provider_ms=io_ms))
    wall_ms = (time.perf_counter_ns() - started) / 1e6
    return wall_ms, results


def run_threaded(requests: list[LLMRequest], workers: int, io_ms: float, log_dir: Path) -> tuple[float, list]:
    agent = CipherMeshConcurrentAgent(
        worker_count=workers,
        queue_size=max(64, len(requests)),
        monitor_interval_s=0.05,
        simulate_provider_ms=io_ms,
        log_dir=log_dir,
        console_enabled=False,
    )
    agent.start()
    started = time.perf_counter_ns()
    for request in requests:
        agent.state.mark_parsed()
        agent.submit_request(request)
    agent.wait_until_idle(heartbeat_interval_s=0.01)
    results = agent.collect_results()
    agent.close()
    wall_ms = (time.perf_counter_ns() - started) / 1e6
    return wall_ms, results


def summarize(mode: str, workers: int, requests: list[LLMRequest], io_ms: float, wall_ms: float, results: list, baseline_ms: float) -> BenchmarkRow:
    service = [r.service_ms for r in results]
    e2e = [r.end_to_end_ms for r in results]
    return BenchmarkRow(
        mode=mode,
        workers=workers,
        requests=len(requests),
        simulated_io_ms=io_ms,
        wall_ms=round(wall_ms, 3),
        throughput_req_s=round(len(requests) / (wall_ms / 1000.0), 3),
        avg_service_ms=round(statistics.fmean(service), 3),
        p95_service_ms=round(percentile(service, 0.95), 3),
        avg_end_to_end_ms=round(statistics.fmean(e2e), 3),
        p95_end_to_end_ms=round(percentile(e2e, 0.95), 3),
        speedup_vs_sequential=round(baseline_ms / wall_ms, 3),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=80)
    parser.add_argument("--io-ms", type=float, default=25.0)
    parser.add_argument("--workers", type=int, nargs="+", default=[1, 2, 4, 8])
    parser.add_argument("--output-dir", default=str(Path(__file__).with_name("logs")))
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    requests = build_requests(args.requests)

    baseline_ms, baseline_results = run_sequential(requests, args.io_ms)
    rows = [summarize("sequential", 0, requests, args.io_ms, baseline_ms, baseline_results, baseline_ms)]

    for workers in args.workers:
        wall_ms, results = run_threaded(requests, workers, args.io_ms, output_dir / f"bench_workers_{workers}")
        rows.append(summarize("threaded", workers, requests, args.io_ms, wall_ms, results, baseline_ms))

    csv_path = output_dir / "benchmark_results.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=list(BenchmarkRow.__annotations__.keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row.__dict__)

    json_path = output_dir / "benchmark_results.json"
    json_path.write_text(json.dumps([row.__dict__ for row in rows], indent=2), encoding="utf-8")

    text_path = output_dir / "benchmark_summary.txt"
    with text_path.open("w", encoding="utf-8") as target:
        target.write("CipherMesh Assignment 2.1 - Concurrency Benchmark\n")
        target.write(f"requests={args.requests} simulated_io_ms={args.io_ms:g}\n\n")
        for row in rows:
            line = (
                f"{row.mode:10s} workers={row.workers:<2d} wall_ms={row.wall_ms:8.3f} "
                f"throughput={row.throughput_req_s:8.3f} req/s "
                f"avg_e2e_ms={row.avg_end_to_end_ms:8.3f} p95_e2e_ms={row.p95_end_to_end_ms:8.3f} "
                f"speedup={row.speedup_vs_sequential:.3f}x\n"
            )
            target.write(line)
            print(line, end="")
        target.write("\nInterpretation: the mock wait is I/O-bound; worker threads overlap waiting time.\n")
        target.write("The benchmark does not claim speedup for CPU-bound regex execution under the CPython GIL.\n")

    print(f"CSV={csv_path}")
    print(f"JSON={json_path}")
    print(f"SUMMARY={text_path}")


if __name__ == "__main__":
    main()
