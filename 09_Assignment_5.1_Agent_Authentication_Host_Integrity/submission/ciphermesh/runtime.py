"""Concurrent execution layer (Assignment 2.1, integrated into the unified agent).

* Bounded ``queue.Queue`` gives back-pressure: ``submit`` blocks (or times out)
  instead of letting memory grow without limit.
* Non-daemon worker threads own every accepted request until it completes, so
  shutdown never drops work. Shutdown is sentinel-based and joins every worker.
* A daemon monitor periodically samples queue pressure, latency percentiles and
  decision counts, and actively polls each provider's health endpoint, feeding
  the circuit breaker the router reads. It is observational, so it is a daemon,
  but it still stops cooperatively through a ``threading.Event``.
* Shared counters sit behind one lock. Provider I/O happens outside the agent's
  inspection lock, which is where the concurrency speed-up comes from.
"""
from __future__ import annotations

import json
import queue
import statistics
import threading
import time
from concurrent.futures import Future
from dataclasses import dataclass
from pathlib import Path

from .orchestrator import CipherMeshOrchestrator, ProcessOutcome
from .providers import ProviderUnavailable

_STOP = object()


@dataclass
class _Job:
    text: str
    provider: str | None
    request_id: str | None
    future: Future
    enqueued: float


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * pct)))
    return ordered[index]


class RuntimeMetrics:
    def __init__(self):
        self._lock = threading.Lock()
        self.started = time.perf_counter()
        self.counters = {"submitted": 0, "rejected_full": 0, "started": 0, "completed": 0,
                         "failed": 0, "in_flight": 0}
        self.status_counts: dict[str, int] = {}
        self.queue_wait_ms: list[float] = []
        self.total_ms: list[float] = []

    def inc(self, key: str, amount: int = 1) -> None:
        with self._lock:
            self.counters[key] += amount

    def finish(self, outcome: ProcessOutcome | None, wait_ms: float, total_ms: float) -> None:
        with self._lock:
            self.counters["in_flight"] -= 1
            if outcome is None:
                self.counters["failed"] += 1
            else:
                self.counters["completed"] += 1
                self.status_counts[outcome.status.value] = self.status_counts.get(outcome.status.value, 0) + 1
            self.queue_wait_ms.append(wait_ms)
            self.total_ms.append(total_ms)

    def snapshot(self) -> dict:
        with self._lock:
            elapsed = max(time.perf_counter() - self.started, 1e-9)
            done = self.counters["completed"] + self.counters["failed"]
            return {**self.counters, "status_counts": dict(self.status_counts),
                    "uptime_s": round(elapsed, 3), "throughput_req_s": round(done / elapsed, 3),
                    "avg_queue_wait_ms": round(statistics.fmean(self.queue_wait_ms), 3) if self.queue_wait_ms else 0.0,
                    "p95_queue_wait_ms": round(_percentile(self.queue_wait_ms, 0.95), 3),
                    "avg_end_to_end_ms": round(statistics.fmean(self.total_ms), 3) if self.total_ms else 0.0,
                    "p50_end_to_end_ms": round(_percentile(self.total_ms, 0.50), 3),
                    "p95_end_to_end_ms": round(_percentile(self.total_ms, 0.95), 3)}


class ConcurrentRuntime:
    def __init__(self, orchestrator: CipherMeshOrchestrator, workers: int = 4, queue_size: int = 64,
                 monitor_interval_s: float = 1.0, metrics_path: Path | str | None = None,
                 probe_providers: bool = True, on_sample=None):
        if workers < 1 or queue_size < 1 or monitor_interval_s <= 0:
            raise ValueError("workers, queue_size and monitor_interval_s must be positive")
        self.orchestrator = orchestrator
        self.metrics = RuntimeMetrics()
        self.queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self.monitor_interval_s = monitor_interval_s
        self.metrics_path = Path(metrics_path) if metrics_path else None
        self.probe_providers = probe_providers
        self.on_sample = on_sample
        self.samples: list[dict] = []
        self._stop = threading.Event()
        self._workers = [threading.Thread(target=self._worker, name=f"cm-worker-{i + 1}", daemon=False)
                         for i in range(workers)]
        self._monitor = threading.Thread(target=self._monitor_loop, name="cm-monitor", daemon=True)
        self._started = self._closed = False
        self._state_lock = threading.Lock()

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> "ConcurrentRuntime":
        with self._state_lock:
            if self._started:
                return self
            if self.metrics_path:
                self.metrics_path.parent.mkdir(parents=True, exist_ok=True)
                self.metrics_path.write_text("", encoding="utf-8")
            for worker in self._workers:
                worker.start()
            self._monitor.start()
            self._started = True
        return self

    def submit(self, text: str, provider: str | None = None, request_id: str | None = None,
               timeout: float | None = 5.0) -> Future:
        if not self._started or self._closed:
            raise RuntimeError("runtime must be started and not closed")
        future: Future = Future()
        try:
            self.queue.put(_Job(text, provider, request_id, future, time.perf_counter()), timeout=timeout)
        except queue.Full:
            self.metrics.inc("rejected_full")
            raise
        self.metrics.inc("submitted")
        return future

    def close(self, timeout_s: float = 30.0) -> dict:
        with self._state_lock:
            if self._closed:
                return self.metrics.snapshot()
            self._closed = True
        for _ in self._workers:
            self.queue.put(_STOP)
        for worker in self._workers:
            worker.join(timeout=timeout_s)
            if worker.is_alive():
                raise RuntimeError(f"{worker.name} did not terminate cleanly")
        self._stop.set()
        self._monitor.join(timeout=max(2.0, self.monitor_interval_s * 3))
        self._sample("STOPPED")
        return self.metrics.snapshot()

    def __enter__(self):
        return self.start()

    def __exit__(self, *_exc):
        self.close()

    # ---------------------------------------------------------------- threads
    def _worker(self) -> None:
        while True:
            job = self.queue.get()
            try:
                if job is _STOP:
                    return
                begun = time.perf_counter()
                wait_ms = (begun - job.enqueued) * 1000
                self.metrics.inc("started")
                self.metrics.inc("in_flight")
                if not job.future.set_running_or_notify_cancel():
                    self.metrics.finish(None, wait_ms, 0.0)
                    continue
                try:
                    outcome = self.orchestrator.process(job.text, job.provider, job.request_id)
                except Exception as exc:  # contain faults per request; the worker keeps serving
                    self.metrics.finish(None, wait_ms, (time.perf_counter() - job.enqueued) * 1000)
                    job.future.set_exception(exc)
                else:
                    self.metrics.finish(outcome, wait_ms, (time.perf_counter() - job.enqueued) * 1000)
                    job.future.set_result(outcome)
            finally:
                self.queue.task_done()

    def _sample(self, status: str) -> dict:
        record = {"epoch_ms": int(time.time() * 1000), "status": status, "queue_depth": self.queue.qsize(),
                  "workers_alive": sum(w.is_alive() for w in self._workers), **self.metrics.snapshot(),
                  "provider_health": self.orchestrator.registry.health.snapshot()}
        self.samples.append(record)
        if self.metrics_path:
            with self.metrics_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        if self.on_sample:
            self.on_sample(record)
        return record

    def _probe(self) -> None:
        health = self.orchestrator.registry.health
        for profile in self.orchestrator.registry.profiles():
            adapter = self.orchestrator.registry.get(profile.provider_id)
            try:
                latency = adapter.health_check(timeout_s=min(2.0, self.monitor_interval_s))
            except (ProviderUnavailable, TimeoutError, OSError):
                health.record_failure(profile.provider_id)
            else:
                health.record_success(profile.provider_id, latency)

    def _monitor_loop(self) -> None:
        self._sample("STARTING")
        while not self._stop.wait(self.monitor_interval_s):
            if self.probe_providers:
                self._probe()
            self._sample("RUNNING")


def benchmark(orchestrator_factory, texts: list[str], worker_counts: list[int]) -> list[dict]:
    """Sequential baseline vs threaded runs over identical work."""
    rows: list[dict] = []
    seq = orchestrator_factory()
    t0 = time.perf_counter()
    for text in texts:
        seq.process(text)
    seq_ms = (time.perf_counter() - t0) * 1000
    rows.append({"mode": "sequential", "workers": 1, "requests": len(texts),
                 "wall_ms": round(seq_ms, 3), "throughput_req_s": round(len(texts) / (seq_ms / 1000), 3),
                 "speedup_vs_sequential": 1.0})
    for count in worker_counts:
        runtime = ConcurrentRuntime(orchestrator_factory(), workers=count, queue_size=max(len(texts), 1),
                                    monitor_interval_s=0.5, probe_providers=False).start()
        t0 = time.perf_counter()
        futures = [runtime.submit(text) for text in texts]
        for future in futures:
            future.result(timeout=120)
        wall = (time.perf_counter() - t0) * 1000
        snap = runtime.close()
        rows.append({"mode": "threaded", "workers": count, "requests": len(texts), "wall_ms": round(wall, 3),
                     "throughput_req_s": round(len(texts) / (wall / 1000), 3),
                     "p95_end_to_end_ms": snap["p95_end_to_end_ms"],
                     "speedup_vs_sequential": round(seq_ms / wall, 3)})
    return rows
