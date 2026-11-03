"""Provider profiles, adapters and health tracking.

Every number in the default registry is an illustrative planning assumption,
not a published price or a measured benchmark. Cloud adapters are simulated;
the local adapter talks to a real Ollama endpoint only when explicitly enabled
(``CIPHERMESH_OLLAMA=1``), so the default build makes zero paid or external calls.
"""
from __future__ import annotations

import json
import os
import random
import threading
import time
import urllib.error
import urllib.request
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field


class ProviderProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")
    display_name: str
    kind: Literal["cloud", "local"]
    region: str
    data_residency: Literal["IN", "US", "EU", "LOCAL"]
    cost_per_1k_requests_usd: float = Field(ge=0, allow_inf_nan=False)
    p95_latency_ms: float = Field(gt=0, allow_inf_nan=False)
    quality_score: float = Field(ge=0, le=5, allow_inf_nan=False)
    availability_pct: float = Field(ge=0, le=100, allow_inf_nan=False)
    capacity_rps: int = Field(gt=0)
    enabled: bool = True
    metrics_source: str = "illustrative_planning_profile"


class ProviderResponse(BaseModel):
    provider_id: str
    text: str
    latency_ms: float
    simulated: bool


class ProviderUnavailable(RuntimeError):
    pass


class ProviderAdapter(Protocol):
    profile: ProviderProfile
    def complete(self, prompt: str, timeout_s: float = 20.0) -> ProviderResponse: ...
    def health_check(self, timeout_s: float = 2.0) -> float: ...


class MockProviderAdapter:
    """Deterministic simulated provider with optional latency and fault injection."""

    def __init__(self, profile: ProviderProfile, latency_scale: float = 0.0,
                 failure_rate: float = 0.0, seed: int = 7, response_suffix: str = ""):
        if not 0 <= failure_rate <= 1:
            raise ValueError("failure_rate must be within [0, 1]")
        self.profile = profile
        self.latency_scale = max(0.0, latency_scale)
        self.failure_rate = failure_rate
        self.response_suffix = response_suffix
        self._fail_next = 0
        self._rng = random.Random(seed)
        self._lock = threading.Lock()

    def fail_next(self, count: int = 1) -> None:
        with self._lock:
            self._fail_next += count

    def _should_fail(self) -> bool:
        with self._lock:
            if self._fail_next > 0:
                self._fail_next -= 1
                return True
            return self._rng.random() < self.failure_rate

    def complete(self, prompt: str, timeout_s: float = 20.0) -> ProviderResponse:
        started = time.perf_counter()
        delay = self.profile.p95_latency_ms / 1000.0 * self.latency_scale
        if delay:
            time.sleep(min(delay, timeout_s))
        if self._should_fail():
            raise ProviderUnavailable(f"{self.profile.provider_id}: simulated upstream failure")
        words = len(prompt.split())
        preview = " ".join(prompt.split()[:16])
        text = (f"[{self.profile.display_name} | simulated] Processed {words} words. "
                f"Context received: \"{preview}{'...' if words > 16 else ''}\"{self.response_suffix}")
        return ProviderResponse(provider_id=self.profile.provider_id, text=text,
                                latency_ms=round((time.perf_counter() - started) * 1000, 3), simulated=True)

    def health_check(self, timeout_s: float = 2.0) -> float:
        started = time.perf_counter()
        delay = self.profile.p95_latency_ms / 1000.0 * self.latency_scale * 0.2
        if delay:
            time.sleep(min(delay, timeout_s))
        return round((time.perf_counter() - started) * 1000, 3)


class OllamaAdapter:
    """Real local inference through Ollama's HTTP API (loopback only by default)."""

    def __init__(self, profile: ProviderProfile, base_url: str | None = None, model: str | None = None):
        self.profile = profile
        self.base_url = (base_url or os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.2")

    def complete(self, prompt: str, timeout_s: float = 60.0) -> ProviderResponse:
        started = time.perf_counter()
        body = json.dumps({"model": self.model, "prompt": prompt, "stream": False}).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}/api/generate", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            raise ProviderUnavailable(f"ollama unavailable: {type(exc).__name__}") from exc
        return ProviderResponse(provider_id=self.profile.provider_id, text=str(payload.get("response", "")),
                                latency_ms=round((time.perf_counter() - started) * 1000, 3), simulated=False)

    def health_check(self, timeout_s: float = 2.0) -> float:
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=timeout_s):
                pass
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProviderUnavailable(f"ollama health check failed: {type(exc).__name__}") from exc
        return round((time.perf_counter() - started) * 1000, 3)


class ProviderHealth:
    """Thread-safe circuit breaker with EWMA latency per provider."""

    def __init__(self, failure_threshold: int = 3, cooldown_s: float = 30.0, alpha: float = 0.3):
        self.failure_threshold = failure_threshold
        self.cooldown_s = cooldown_s
        self.alpha = alpha
        self._lock = threading.Lock()
        self._state: dict[str, dict] = {}

    def _entry(self, provider_id: str) -> dict:
        return self._state.setdefault(provider_id, {"consecutive_failures": 0, "opened_at": None,
                                                    "ewma_latency_ms": None, "successes": 0, "failures": 0})

    def record_success(self, provider_id: str, latency_ms: float) -> None:
        with self._lock:
            e = self._entry(provider_id)
            e["consecutive_failures"] = 0
            e["opened_at"] = None
            e["successes"] += 1
            prev = e["ewma_latency_ms"]
            e["ewma_latency_ms"] = latency_ms if prev is None else self.alpha * latency_ms + (1 - self.alpha) * prev

    def record_failure(self, provider_id: str) -> None:
        with self._lock:
            e = self._entry(provider_id)
            e["consecutive_failures"] += 1
            e["failures"] += 1
            if e["consecutive_failures"] >= self.failure_threshold and e["opened_at"] is None:
                e["opened_at"] = time.monotonic()

    def is_open(self, provider_id: str) -> bool:
        with self._lock:
            e = self._entry(provider_id)
            if e["opened_at"] is None:
                return False
            if time.monotonic() - e["opened_at"] >= self.cooldown_s:
                e["opened_at"] = None  # half-open: allow the next attempt to probe
                e["consecutive_failures"] = self.failure_threshold - 1
                return False
            return True

    def snapshot(self) -> dict[str, dict]:
        with self._lock:
            out: dict[str, dict] = {}
            for pid, e in self._state.items():
                ewma = e["ewma_latency_ms"]
                out[pid] = {"circuit": "OPEN" if e["opened_at"] is not None else "CLOSED",
                            "consecutive_failures": e["consecutive_failures"],
                            "successes": e["successes"], "failures": e["failures"],
                            "ewma_latency_ms": None if ewma is None else round(ewma, 3)}
            return out


class ProviderRegistry:
    def __init__(self, health: ProviderHealth | None = None):
        self._adapters: dict[str, ProviderAdapter] = {}
        self.health = health or ProviderHealth()

    def register(self, adapter: ProviderAdapter) -> None:
        self._adapters[adapter.profile.provider_id] = adapter

    def get(self, provider_id: str) -> ProviderAdapter | None:
        return self._adapters.get(ALIASES.get(provider_id, provider_id))

    def profiles(self) -> list[ProviderProfile]:
        return [a.profile for a in self._adapters.values()]

    def ids(self) -> list[str]:
        return list(self._adapters)


ALIASES = {"ollama-local": "local", "ollama": "local", "bedrock": "aws-bedrock",
           "azure": "azure-ai", "vertex": "gcp-vertex"}

DEFAULT_PROFILES: tuple[ProviderProfile, ...] = (
    ProviderProfile(provider_id="local", display_name="Ollama (local)", kind="local", region="on-host",
                    data_residency="LOCAL", cost_per_1k_requests_usd=0.40, p95_latency_ms=1200,
                    quality_score=3.4, availability_pct=99.0, capacity_rps=300),
    ProviderProfile(provider_id="aws-bedrock", display_name="AWS Bedrock", kind="cloud", region="ap-south-1",
                    data_residency="IN", cost_per_1k_requests_usd=2.80, p95_latency_ms=650,
                    quality_score=4.6, availability_pct=99.9, capacity_rps=800),
    ProviderProfile(provider_id="azure-ai", display_name="Azure AI Foundry", kind="cloud", region="centralindia",
                    data_residency="IN", cost_per_1k_requests_usd=3.30, p95_latency_ms=600,
                    quality_score=4.7, availability_pct=99.9, capacity_rps=700),
    ProviderProfile(provider_id="gcp-vertex", display_name="GCP Vertex AI", kind="cloud", region="us-central1",
                    data_residency="US", cost_per_1k_requests_usd=2.20, p95_latency_ms=580,
                    quality_score=4.7, availability_pct=99.95, capacity_rps=900),
)


def default_registry(latency_scale: float = 0.0, use_ollama: bool | None = None,
                     health: ProviderHealth | None = None) -> ProviderRegistry:
    registry = ProviderRegistry(health)
    if use_ollama is None:
        use_ollama = os.getenv("CIPHERMESH_OLLAMA", "0") == "1"
    for profile in DEFAULT_PROFILES:
        if profile.provider_id == "local" and use_ollama:
            registry.register(OllamaAdapter(profile))
        else:
            registry.register(MockProviderAdapter(profile, latency_scale=latency_scale))
    return registry
