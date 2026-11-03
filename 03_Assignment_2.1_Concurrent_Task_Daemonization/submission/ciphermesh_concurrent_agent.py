"""CipherMesh Assignment 2.1 - Concurrent Task Daemonization using Threads and Workers.

Student: Kumar Waibhav Akshat
Register No.: RA2212704010027
Programme: M.Tech Integrated - CSE Data Science | Section: AG1
Course: 21CSE525T Agent Technology
Faculty: Dr. Prabhu Kavin B

Continuation of Assignment 1.2:
    PERCEIVE -> PARSE -> DETECT -> DECIDE -> PROTECT -> AUDIT

Assignment 2.1 adds:
    * a bounded, thread-safe request queue;
    * a configurable pool of non-daemon request workers;
    * a daemon health/latency monitor;
    * a dedicated asynchronous audit writer;
    * lock-protected shared runtime metrics;
    * Event/sentinel based graceful shutdown;
    * privacy-safe execution latency logging.

The implementation intentionally uses only the Python standard library. No real
cloud or LLM endpoint is contacted; provider latency can be simulated so the
concurrency behaviour can be demonstrated at zero cost.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import queue
import re
import statistics
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Pattern

SUPPORTED_PROVIDERS = {"aws-bedrock", "azure-ai", "gcp-vertex", "ollama-local"}
ACTION_PRIORITY = {"ALLOW": 0, "REDACT": 1, "REVIEW": 2, "BLOCK": 3}
STOP = object()


@dataclass(frozen=True)
class LLMRequest:
    timestamp: str
    request_id: str
    provider: str
    model: str
    prompt: str

    @classmethod
    def parse(cls, line: str) -> "LLMRequest":
        """Parse and validate one request envelope without modifying shared state."""
        try:
            raw = json.loads(line)
            item = cls(
                timestamp=str(raw["timestamp"]),
                request_id=str(raw["request_id"]),
                provider=str(raw["provider"]).lower(),
                model=str(raw["model"]),
                prompt=str(raw["prompt"]),
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid request envelope: {exc}") from exc
        if item.provider not in SUPPORTED_PROVIDERS:
            raise ValueError(f"unsupported provider '{item.provider}'")
        if not item.request_id.strip() or not item.model.strip() or not item.prompt.strip():
            raise ValueError("request_id, model, and prompt must be non-empty")
        if len(item.prompt) > 20_000:
            raise ValueError("prompt exceeds the 20,000-character prototype limit")
        return item


@dataclass(frozen=True)
class Detector:
    detector_id: str
    label: str
    severity: str
    action: str
    pattern: Pattern[str]
    replacement: str


# Immutable detector policy carried forward from Assignment 1.2.
DETECTORS: tuple[Detector, ...] = (
    Detector("D1", "AWS_ACCESS_KEY_ID", "CRITICAL", "BLOCK", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[AWS_ACCESS_KEY_REDACTED]"),
    Detector("D2", "GCP_PRIVATE_KEY", "CRITICAL", "BLOCK", re.compile(r"-----BEGIN PRIVATE KEY-----", re.I), "[PRIVATE_KEY_REDACTED]"),
    Detector("D3", "AZURE_SAS_SIGNATURE", "CRITICAL", "BLOCK", re.compile(r"[?&]sig=[A-Za-z0-9%+/=_-]{16,}", re.I), "&sig=[AZURE_SAS_REDACTED]"),
    Detector("D4", "GENERIC_API_TOKEN", "CRITICAL", "BLOCK", re.compile(r"\b(?:sk|ghp|xoxb)-[A-Za-z0-9_-]{16,}\b"), "[API_TOKEN_REDACTED]"),
    Detector("D5", "EMAIL_ADDRESS", "SENSITIVE", "REDACT", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "[EMAIL_REDACTED]"),
    Detector("D6", "INDIA_PHONE_NUMBER", "SENSITIVE", "REDACT", re.compile(r"(?<!\d)(?:\+91[- ]?)?[6-9]\d{9}(?!\d)"), "[PHONE_REDACTED]"),
    Detector("D7", "IP_ADDRESS", "SENSITIVE", "REDACT", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP_REDACTED]"),
    Detector("D8", "INTERNAL_URL", "CONFIDENTIAL", "REVIEW", re.compile(r"https?://(?:[\w-]+\.)*(?:internal|corp|local)(?::\d+)?(?:/\S*)?", re.I), "[INTERNAL_URL_REDACTED]"),
)


@dataclass(frozen=True)
class Finding:
    detector_id: str
    label: str
    severity: str
    action: str
    count: int


@dataclass(frozen=True)
class WorkItem:
    request: LLMRequest
    enqueued_ns: int


@dataclass(frozen=True)
class TaskResult:
    request_id: str
    provider: str
    model: str
    decision: str
    explanation: str
    findings: tuple[Finding, ...]
    sanitized_preview: str | None
    prompt_sha256: str
    worker: str
    queue_wait_ms: float
    service_ms: float
    end_to_end_ms: float


class ThreadSafeConsole:
    """Prevents multi-threaded console lines from interleaving."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._lock = threading.Lock()

    def write(self, message: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            print(message, flush=True)


class RuntimeState:
    """Single lock-protected source of truth for mutable shared metrics."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started_ns = time.perf_counter_ns()
        self._counters = {
            "parsed": 0,
            "rejected": 0,
            "enqueued": 0,
            "started": 0,
            "completed": 0,
            "in_flight": 0,
            "ALLOW": 0,
            "REDACT": 0,
            "REVIEW": 0,
            "BLOCK": 0,
        }
        self._service_ms: list[float] = []
        self._queue_wait_ms: list[float] = []
        self._end_to_end_ms: list[float] = []

    def mark_parsed(self) -> None:
        with self._lock:
            self._counters["parsed"] += 1

    def mark_rejected(self) -> None:
        with self._lock:
            self._counters["rejected"] += 1

    def mark_enqueued(self) -> None:
        with self._lock:
            self._counters["enqueued"] += 1

    def mark_started(self) -> None:
        with self._lock:
            self._counters["started"] += 1
            self._counters["in_flight"] += 1

    def mark_finished(self, result: TaskResult) -> None:
        with self._lock:
            self._counters["completed"] += 1
            self._counters["in_flight"] -= 1
            self._counters[result.decision] += 1
            self._service_ms.append(result.service_ms)
            self._queue_wait_ms.append(result.queue_wait_ms)
            self._end_to_end_ms.append(result.end_to_end_ms)

    @staticmethod
    def _percentile(values: list[float], percentile: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        index = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * percentile))))
        return ordered[index]

    def snapshot(self) -> dict[str, float | int]:
        with self._lock:
            elapsed_s = max((time.perf_counter_ns() - self._started_ns) / 1e9, 1e-9)
            completed = self._counters["completed"]
            return {
                **self._counters,
                "uptime_s": round(elapsed_s, 4),
                "throughput_req_s": round(completed / elapsed_s, 3),
                "avg_service_ms": round(statistics.fmean(self._service_ms), 3) if self._service_ms else 0.0,
                "p95_service_ms": round(self._percentile(self._service_ms, 0.95), 3),
                "avg_queue_wait_ms": round(statistics.fmean(self._queue_wait_ms), 3) if self._queue_wait_ms else 0.0,
                "p95_queue_wait_ms": round(self._percentile(self._queue_wait_ms, 0.95), 3),
                "avg_end_to_end_ms": round(statistics.fmean(self._end_to_end_ms), 3) if self._end_to_end_ms else 0.0,
                "p95_end_to_end_ms": round(self._percentile(self._end_to_end_ms, 0.95), 3),
            }


def inspect(prompt: str) -> tuple[tuple[Finding, ...], str]:
    """Detect secrets/PII and return findings plus a privacy-safe preview."""
    findings: list[Finding] = []
    sanitized = prompt
    for detector in DETECTORS:
        matches = detector.pattern.findall(sanitized)
        if matches:
            findings.append(
                Finding(
                    detector_id=detector.detector_id,
                    label=detector.label,
                    severity=detector.severity,
                    action=detector.action,
                    count=len(matches),
                )
            )
            sanitized = detector.pattern.sub(detector.replacement, sanitized)
    return tuple(findings), sanitized


def decide(findings: tuple[Finding, ...]) -> tuple[str, str]:
    """Highest-risk-wins policy retained from Assignment 1.2."""
    if not findings:
        return "ALLOW", "Forward unchanged under the selected provider adapter"
    decision = max((finding.action for finding in findings), key=ACTION_PRIORITY.__getitem__)
    messages = {
        "BLOCK": "Do not transmit; notify developer to revoke/rotate exposed credential",
        "REVIEW": "Hold request for developer approval using the redacted preview",
        "REDACT": "Forward only the sanitized prompt",
        "ALLOW": "Forward unchanged under the selected provider adapter",
    }
    return decision, messages[decision]


def process_request(request: LLMRequest, *, worker_name: str, enqueued_ns: int, simulate_provider_ms: float = 0.0) -> TaskResult:
    """Pure request processing plus optional mock I/O wait used for concurrency demonstration."""
    started_ns = time.perf_counter_ns()
    queue_wait_ms = (started_ns - enqueued_ns) / 1e6
    findings, sanitized = inspect(request.prompt)
    decision, explanation = decide(findings)

    # Represents provider/network or downstream I/O. No external request is made.
    if simulate_provider_ms > 0:
        time.sleep(simulate_provider_ms / 1000.0)

    finished_ns = time.perf_counter_ns()
    service_ms = (finished_ns - started_ns) / 1e6
    end_to_end_ms = (finished_ns - enqueued_ns) / 1e6
    fingerprint = hashlib.sha256(request.prompt.encode("utf-8")).hexdigest()[:16]
    safe_preview = sanitized if decision in {"REDACT", "REVIEW", "BLOCK"} else None
    return TaskResult(
        request_id=request.request_id,
        provider=request.provider,
        model=request.model,
        decision=decision,
        explanation=explanation,
        findings=findings,
        sanitized_preview=safe_preview,
        prompt_sha256=fingerprint,
        worker=worker_name,
        queue_wait_ms=round(queue_wait_ms, 3),
        service_ms=round(service_ms, 3),
        end_to_end_ms=round(end_to_end_ms, 3),
    )


class AuditWriter:
    """Asynchronous privacy-safe disk writer so request workers never block on file I/O."""

    def __init__(self, path: Path, console: ThreadSafeConsole) -> None:
        self.path = path
        self.console = console
        self.queue: queue.Queue[dict | object] = queue.Queue()
        self.thread = threading.Thread(target=self._run, name="audit-writer", daemon=False)

    def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        self.thread.start()

    def submit(self, event: dict) -> None:
        self.queue.put(event)

    def _run(self) -> None:
        with self.path.open("a", encoding="utf-8") as target:
            while True:
                event = self.queue.get()
                try:
                    if event is STOP:
                        return
                    target.write(json.dumps(event, ensure_ascii=True) + "\n")
                    target.flush()
                finally:
                    self.queue.task_done()

    def close(self) -> None:
        self.queue.put(STOP)
        self.queue.join()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("audit writer did not terminate cleanly")


class MonitorDaemon:
    """Periodic background monitor for queue pressure, health, decisions and latency."""

    def __init__(
        self,
        *,
        state: RuntimeState,
        request_queue: queue.Queue,
        workers: list[threading.Thread],
        stop_event: threading.Event,
        interval_s: float,
        metrics_path: Path,
        console: ThreadSafeConsole,
    ) -> None:
        self.state = state
        self.request_queue = request_queue
        self.workers = workers
        self.stop_event = stop_event
        self.interval_s = interval_s
        self.metrics_path = metrics_path
        self.console = console
        self.thread = threading.Thread(target=self._run, name="monitor-daemon", daemon=True)

    def start(self) -> None:
        self.metrics_path.parent.mkdir(parents=True, exist_ok=True)
        self.metrics_path.write_text("", encoding="utf-8")
        self.thread.start()

    def _sample(self, status: str) -> dict:
        snapshot = self.state.snapshot()
        return {
            "epoch_ms": int(time.time() * 1000),
            "status": status,
            "queue_depth": self.request_queue.qsize(),
            "workers_alive": sum(1 for worker in self.workers if worker.is_alive()),
            **snapshot,
        }

    def _write(self, record: dict) -> None:
        with self.metrics_path.open("a", encoding="utf-8") as target:
            target.write(json.dumps(record, ensure_ascii=True) + "\n")

    def _run(self) -> None:
        self._write(self._sample("STARTING"))
        while not self.stop_event.wait(self.interval_s):
            record = self._sample("RUNNING")
            self._write(record)
            self.console.write(
                "[MONITOR] "
                f"queue={record['queue_depth']} in_flight={record['in_flight']} "
                f"completed={record['completed']} workers_alive={record['workers_alive']} "
                f"avg_service_ms={record['avg_service_ms']}"
            )
        self._write(self._sample("STOPPED"))

    def close(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=max(2.0, self.interval_s * 4))


class CipherMeshConcurrentAgent:
    """Threaded orchestration layer added in Assignment 2.1."""

    def __init__(
        self,
        *,
        worker_count: int = 4,
        queue_size: int = 64,
        monitor_interval_s: float = 0.25,
        simulate_provider_ms: float = 0.0,
        log_dir: Path | str = Path("logs"),
        console_enabled: bool = True,
    ) -> None:
        if worker_count < 1:
            raise ValueError("worker_count must be at least 1")
        if queue_size < 1:
            raise ValueError("queue_size must be at least 1")
        if monitor_interval_s <= 0:
            raise ValueError("monitor_interval_s must be positive")

        self.worker_count = worker_count
        self.simulate_provider_ms = simulate_provider_ms
        self.log_dir = Path(log_dir)
        self.console = ThreadSafeConsole(console_enabled)
        self.state = RuntimeState()
        self.request_queue: queue.Queue[WorkItem | object] = queue.Queue(maxsize=queue_size)
        self.result_queue: queue.Queue[TaskResult] = queue.Queue()
        self.stop_event = threading.Event()
        self.workers = [
            threading.Thread(target=self._worker_loop, name=f"cipher-worker-{i + 1}", daemon=False)
            for i in range(worker_count)
        ]
        self.audit_writer = AuditWriter(self.log_dir / "audit_events.jsonl", self.console)
        self.monitor = MonitorDaemon(
            state=self.state,
            request_queue=self.request_queue,
            workers=self.workers,
            stop_event=self.stop_event,
            interval_s=monitor_interval_s,
            metrics_path=self.log_dir / "monitor_metrics.jsonl",
            console=self.console,
        )
        self._started = False
        self._closed = False

    def start(self) -> None:
        if self._started:
            return
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.audit_writer.start()
        for worker in self.workers:
            worker.start()
        self.monitor.start()
        self._started = True
        self.console.write(
            "CipherMesh Concurrent Agent | STATUS=ONLINE | "
            f"workers={self.worker_count} monitor_daemon=ON audit_worker=ON "
            f"mock_provider_ms={self.simulate_provider_ms:g}"
        )

    def submit_request(self, request: LLMRequest, timeout: float | None = None) -> None:
        if not self._started or self._closed:
            raise RuntimeError("agent must be started and not closed before submit")
        item = WorkItem(request=request, enqueued_ns=time.perf_counter_ns())
        self.request_queue.put(item, timeout=timeout)
        self.state.mark_enqueued()
        self.console.write(f"[MAIN] ENQUEUE id={request.request_id} provider={request.provider} queue={self.request_queue.qsize()}")

    def submit_line(self, line: str, line_number: int) -> bool:
        try:
            request = LLMRequest.parse(line)
        except ValueError as exc:
            self.state.mark_rejected()
            self.console.write(f"[INPUT-{line_number:02d}] PARSE_ERROR | {exc} | ACTION=REJECT_ENVELOPE")
            return False
        self.state.mark_parsed()
        self.submit_request(request)
        return True

    def _worker_loop(self) -> None:
        worker_name = threading.current_thread().name
        while True:
            item = self.request_queue.get()
            try:
                if item is STOP:
                    return
                assert isinstance(item, WorkItem)
                self.state.mark_started()
                result = process_request(
                    item.request,
                    worker_name=worker_name,
                    enqueued_ns=item.enqueued_ns,
                    simulate_provider_ms=self.simulate_provider_ms,
                )
                self.state.mark_finished(result)
                self.result_queue.put(result)
                self.audit_writer.submit(self._audit_event(result))
                self.console.write(
                    f"[{worker_name}] COMPLETE id={result.request_id} action={result.decision} "
                    f"queue_wait_ms={result.queue_wait_ms:.3f} service_ms={result.service_ms:.3f} "
                    f"e2e_ms={result.end_to_end_ms:.3f}"
                )
            except Exception as exc:  # defensive worker containment for the demonstration
                self.console.write(f"[{worker_name}] ERROR {type(exc).__name__}: {exc}")
            finally:
                self.request_queue.task_done()

    @staticmethod
    def _audit_event(result: TaskResult) -> dict:
        # Never include the original prompt. Only a hash and sanitized preview are persisted.
        return {
            "request_id": result.request_id,
            "provider": result.provider,
            "model": result.model,
            "decision": result.decision,
            "finding_types": [finding.label for finding in result.findings],
            "finding_count": sum(finding.count for finding in result.findings),
            "safe_preview": result.sanitized_preview,
            "prompt_sha256": result.prompt_sha256,
            "worker": result.worker,
            "queue_wait_ms": result.queue_wait_ms,
            "service_ms": result.service_ms,
            "end_to_end_ms": result.end_to_end_ms,
        }

    def wait_until_idle(self, heartbeat_interval_s: float = 0.10) -> None:
        """Keep the primary thread responsive while background workers drain the queue."""
        last_completed = -1
        while True:
            snapshot = self.state.snapshot()
            if snapshot["completed"] >= snapshot["enqueued"] and snapshot["in_flight"] == 0:
                break
            if snapshot["completed"] != last_completed:
                self.console.write(
                    "[MAIN] CORE_EVENT_LOOP=RESPONSIVE | "
                    f"completed={snapshot['completed']}/{snapshot['enqueued']} "
                    f"in_flight={snapshot['in_flight']} queue={self.request_queue.qsize()}"
                )
                last_completed = int(snapshot["completed"])
            time.sleep(heartbeat_interval_s)
        self.request_queue.join()

    def collect_results(self) -> list[TaskResult]:
        results: list[TaskResult] = []
        while True:
            try:
                results.append(self.result_queue.get_nowait())
            except queue.Empty:
                break
        return results

    def close(self) -> dict[str, float | int]:
        if self._closed:
            return self.state.snapshot()
        if not self._started:
            raise RuntimeError("agent was never started")

        self.wait_until_idle()
        for _ in self.workers:
            self.request_queue.put(STOP)
        self.request_queue.join()
        for worker in self.workers:
            worker.join(timeout=5)
            if worker.is_alive():
                raise RuntimeError(f"worker {worker.name} did not terminate cleanly")

        self.audit_writer.close()
        self.monitor.close()
        self._closed = True
        snapshot = self.state.snapshot()
        self.console.write(
            "STREAM_COMPLETE | "
            f"parsed={snapshot['parsed']} rejected={snapshot['rejected']} completed={snapshot['completed']} "
            f"ALLOW={snapshot['ALLOW']} REDACT={snapshot['REDACT']} REVIEW={snapshot['REVIEW']} BLOCK={snapshot['BLOCK']} "
            f"avg_service_ms={snapshot['avg_service_ms']} p95_service_ms={snapshot['p95_service_ms']} "
            "STATUS=STANDBY"
        )
        return snapshot


def run_stream(
    stream: Iterable[str],
    *,
    worker_count: int,
    queue_size: int,
    monitor_interval_s: float,
    simulate_provider_ms: float,
    log_dir: Path,
    console_enabled: bool = True,
) -> tuple[dict[str, float | int], list[TaskResult]]:
    agent = CipherMeshConcurrentAgent(
        worker_count=worker_count,
        queue_size=queue_size,
        monitor_interval_s=monitor_interval_s,
        simulate_provider_ms=simulate_provider_ms,
        log_dir=log_dir,
        console_enabled=console_enabled,
    )
    agent.start()
    for line_number, line in enumerate(stream, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        agent.submit_line(line, line_number)
    agent.wait_until_idle()
    results = agent.collect_results()
    snapshot = agent.close()
    return snapshot, results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CipherMesh Assignment 2.1 concurrent privacy agent")
    parser.add_argument("stream", nargs="?", default=str(Path(__file__).with_name("mock_llm_requests_2_1.jsonl")))
    parser.add_argument("--workers", type=int, default=4, help="number of request worker threads")
    parser.add_argument("--queue-size", type=int, default=64, help="bounded request queue capacity")
    parser.add_argument("--monitor-interval", type=float, default=0.25, help="daemon monitor interval in seconds")
    parser.add_argument("--simulate-provider-ms", type=float, default=120.0, help="mock I/O latency per accepted request")
    parser.add_argument("--log-dir", default=str(Path(__file__).with_name("logs")), help="directory for privacy-safe logs")
    args = parser.parse_args()

    started_ns = time.perf_counter_ns()
    with Path(args.stream).open(encoding="utf-8") as source:
        snapshot, results = run_stream(
            source,
            worker_count=args.workers,
            queue_size=args.queue_size,
            monitor_interval_s=args.monitor_interval,
            simulate_provider_ms=args.simulate_provider_ms,
            log_dir=Path(args.log_dir),
            console_enabled=True,
        )
    wall_ms = (time.perf_counter_ns() - started_ns) / 1e6

    latency_path = Path(args.log_dir) / "execution_latency.log"
    ordered = sorted(results, key=lambda item: item.request_id)
    with latency_path.open("w", encoding="utf-8") as target:
        target.write("CipherMesh Assignment 2.1 - Execution Latency Log\n")
        target.write(f"workers={args.workers} mock_provider_ms={args.simulate_provider_ms:g} total_wall_ms={wall_ms:.3f}\n")
        target.write("request_id,worker,decision,queue_wait_ms,service_ms,end_to_end_ms\n")
        for result in ordered:
            target.write(
                f"{result.request_id},{result.worker},{result.decision},"
                f"{result.queue_wait_ms:.3f},{result.service_ms:.3f},{result.end_to_end_ms:.3f}\n"
            )
        target.write("\nFINAL_SNAPSHOT=" + json.dumps(snapshot, sort_keys=True) + "\n")

    print(f"LATENCY_LOG={latency_path}")
    print(f"MONITOR_LOG={Path(args.log_dir) / 'monitor_metrics.jsonl'}")
    print(f"AUDIT_LOG={Path(args.log_dir) / 'audit_events.jsonl'}")
    print(f"TOTAL_WALL_MS={wall_ms:.3f}")


if __name__ == "__main__":
    main()
