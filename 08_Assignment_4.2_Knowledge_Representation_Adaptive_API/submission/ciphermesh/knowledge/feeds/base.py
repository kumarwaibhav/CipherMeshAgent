"""Shared plumbing for live knowledge connectors.

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

* :class:`HttpFetcher` - urllib with TLS verification, per-attempt timeout and an
  overall deadline, response-size cap, bounded retries with exponential back-off
  (network errors, HTTP 429 and 5xx), a redirect guard (HTTPS only, same host), a
  descriptive User-Agent and an in-memory TTL cache.
* :class:`SnapshotStore` - after a live response has been **parsed successfully** it
  is stored in ``data/snapshots/``. Payloads that contain third-party prose are not
  redistributed: only a text-free *derivative* is written, and the ``.meta.json``
  side-car records the original URL, HTTP status, bytes, SHA-256 and fetch time.
* :class:`FeedConnector` - ``collect()`` = fetch -> parse -> save snapshot. If the
  network fails **or the response cannot be parsed**, the previous snapshot is used,
  marked as a fallback, and down-weighted if it is older than the feed's maximum age.
"""
from __future__ import annotations

import hashlib
import json
import os
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

USER_AGENT = "CipherMesh-KnowledgeFeeds/4.2 (21CSE525T academic project; urllib)"
DEFAULT_SNAPSHOT_DIR = Path(os.environ.get("CIPHERMESH_SNAPSHOT_DIR",
                                           Path(__file__).resolve().parents[3] / "data" / "snapshots"))
LOOPBACK = ("127.0.0.1", "localhost", "::1")
STALE_CONFIDENCE_SCALE = 0.4     # 0.8-1.0 x 0.4 < 0.5 acceptance gate: stale data cannot change properties


class FeedError(RuntimeError):
    """Raised when neither the live endpoint nor a snapshot can supply data."""


class ParseError(ValueError):
    """Raised when a payload cannot be parsed at all (individual bad records are skipped instead)."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class FetchResult:
    feed: str
    url: str
    mode: str                  # live | cache | snapshot | replay-file | failed
    status: int | None
    body: bytes = field(repr=False, default=b"")
    bytes: int = 0
    sha256: str = ""           # hash of ``body`` (the bytes actually parsed)
    latency_ms: float = 0.0
    fetched_at: str = ""
    content_type: str = ""
    attempts: int = 0
    error: str | None = None
    snapshot_path: str | None = None
    final_url: str | None = None
    original_sha256: str | None = None    # hash of the payload as served by the endpoint
    original_bytes: int | None = None
    age_s: float | None = None
    stale: bool = False
    t_start_ns: int = 0
    t_done_ns: int = 0

    def summary(self) -> dict:
        d = asdict(self)
        d.pop("body")
        return d


@dataclass(frozen=True)
class Fact:
    """One extracted statement with provenance. ``obj_is_iri`` marks graph references."""
    subject: str
    predicate: str
    obj: Any
    obj_is_iri: bool
    source: str
    fetched_at: str
    confidence: float = 1.0
    evidence: str = ""


@dataclass
class ParseReport:
    feed: str
    items_seen: int = 0
    items_relevant: int = 0
    facts: list[Fact] = field(default_factory=list)
    signals: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    parse_ms: float = 0.0
    t_done_ns: int = 0
    confidence_scale: float = 1.0      # < 1 when the data came from a stale snapshot
    source_iri: str = ""


class TTLCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._data: dict[str, tuple[float, FetchResult]] = {}

    def get(self, url: str, ttl_s: float) -> FetchResult | None:
        with self._lock:
            hit = self._data.get(url)
        if hit and time.monotonic() - hit[0] < ttl_s:
            return hit[1]
        return None

    def put(self, url: str, result: FetchResult) -> None:
        with self._lock:
            self._data[url] = (time.monotonic(), result)


class SnapshotStore:
    def __init__(self, root: str | Path = DEFAULT_SNAPSHOT_DIR):
        self.root = Path(root)

    def paths(self, feed: str, ext: str) -> tuple[Path, Path]:
        return self.root / f"{feed}.{ext}", self.root / f"{feed}.meta.json"

    def derived_path(self, feed: str, ext: str) -> Path:
        return self.root / f"{feed}.derived.{ext}"

    def save(self, result: FetchResult, ext: str, derivative: bytes | None = None) -> str:
        """Store a parsed live payload. With ``derivative`` the raw bytes are NOT written; only the
        text-free derivative is kept and the meta file records the original payload's hash."""
        self.root.mkdir(parents=True, exist_ok=True)
        raw, meta = self.paths(result.feed, ext)
        info = {"feed": result.feed, "url": result.url, "final_url": result.final_url,
                "http_status": result.status, "original_bytes": result.bytes,
                "original_sha256": result.sha256, "fetched_at": result.fetched_at,
                "content_type": result.content_type}
        if derivative is None:
            target, data = raw, result.body
            info.update({"raw_redistributed": True, "file": raw.name})
        else:
            target, data = self.derived_path(result.feed, ext), derivative
            if raw.exists():
                raw.unlink()                       # never leave an older raw copy behind
            info.update({"raw_redistributed": False,
                         "note": "raw payload not redistributed (third-party content); re-fetch to reproduce",
                         "file": target.name})
        info.update({"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, target)
        meta.write_text(json.dumps(info, indent=1), encoding="utf-8")
        return str(target)

    def load(self, feed: str, ext: str) -> tuple[bytes, dict] | None:
        _raw, meta = self.paths(feed, ext)
        if not meta.exists():
            return None
        info = json.loads(meta.read_text(encoding="utf-8"))
        path = self.root / info.get("file", f"{feed}.{ext}")
        if not path.exists():
            return None
        body = path.read_bytes()
        if hashlib.sha256(body).hexdigest() != info.get("sha256"):
            raise FeedError(f"snapshot {path.name} failed its SHA-256 integrity check")
        return body, info

    def file_for(self, feed: str, ext: str) -> Path:
        """The stored file for a feed: the raw snapshot or, if withheld, its text-free derivative."""
        _raw, meta = self.paths(feed, ext)
        if meta.exists():
            return self.root / json.loads(meta.read_text(encoding="utf-8")).get("file", f"{feed}.{ext}")
        return self.paths(feed, ext)[0]


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only if the target passes the HTTPS check and stays on the same host."""

    def __init__(self, fetcher: "HttpFetcher", origin_host: str):
        super().__init__()
        self.fetcher, self.origin_host = fetcher, origin_host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.fetcher.check_url(newurl)
        if (urlparse(newurl).hostname or "") != self.origin_host:
            raise FeedError(f"refusing off-host redirect to {urlparse(newurl).hostname}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpFetcher:
    """Hardened GET client. HTTPS only, except plain HTTP to loopback (used by the tests)."""

    def __init__(self, timeout_s: float = 15.0, max_bytes: int = 8 * 1024 * 1024, retries: int = 2,
                 backoff_s: float = 0.5, user_agent: str = USER_AGENT, cache: TTLCache | None = None,
                 deadline_s: float = 60.0):
        self.timeout_s = timeout_s
        self.max_bytes = max_bytes
        self.retries = max(0, retries)
        self.backoff_s = backoff_s
        self.user_agent = user_agent
        self.deadline_s = deadline_s
        self.cache = cache or TTLCache()
        self._ssl = ssl.create_default_context()          # certificate + hostname verification ON
        self._ssl.minimum_version = ssl.TLSVersion.TLSv1_2

    def _opener(self, url: str):
        host = urlparse(url).hostname or ""
        handlers: list = [urllib.request.HTTPSHandler(context=self._ssl), _GuardedRedirect(self, host)]
        if host in LOOPBACK:
            handlers.append(urllib.request.ProxyHandler({}))     # never send loopback traffic to a proxy
        return urllib.request.build_opener(*handlers)

    def check_url(self, url: str) -> None:
        u = urlparse(url)
        if u.scheme == "https":
            return
        if u.scheme == "http" and u.hostname in LOOPBACK:
            return
        raise FeedError(f"refusing non-HTTPS URL: {url}")

    def get(self, feed: str, url: str, ttl_s: float = 0.0, accept: str = "*/*") -> FetchResult:
        self.check_url(url)
        if ttl_s > 0:
            cached = self.cache.get(url, ttl_s)
            if cached is not None:
                return FetchResult(**{**cached.summary(), "body": cached.body, "mode": "cache",
                                      "latency_ms": 0.0, "t_start_ns": time.perf_counter_ns(),
                                      "t_done_ns": time.perf_counter_ns()})
        start_ns = time.perf_counter_ns()
        deadline = time.monotonic() + self.deadline_s
        last_error = "unknown error"
        opener = self._opener(url)
        attempt = 0
        for attempt in range(1, self.retries + 2):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                last_error = f"overall deadline of {self.deadline_s:.0f} s exceeded"
                break
            t0 = time.perf_counter()
            req = urllib.request.Request(url, headers={"User-Agent": self.user_agent, "Accept": accept,
                                                       "Accept-Encoding": "identity"})
            try:
                with opener.open(req, timeout=min(self.timeout_s, remaining)) as resp:
                    declared = resp.headers.get("Content-Length")
                    if declared and declared.isdigit() and int(declared) > self.max_bytes:
                        raise FeedError(f"declared size {declared} exceeds cap {self.max_bytes}")
                    chunks, total = [], 0
                    while True:
                        if time.monotonic() > deadline:
                            raise FeedError(f"overall deadline of {self.deadline_s:.0f} s exceeded")
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > self.max_bytes:
                            raise FeedError(f"response exceeds size cap of {self.max_bytes} bytes")
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    result = FetchResult(feed=feed, url=url, mode="live", status=resp.status, body=body,
                                         bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                                         latency_ms=round((time.perf_counter() - t0) * 1000, 1),
                                         fetched_at=iso(utc_now()), final_url=resp.geturl(),
                                         content_type=resp.headers.get("Content-Type", ""), attempts=attempt,
                                         original_sha256=hashlib.sha256(body).hexdigest(),
                                         original_bytes=len(body),
                                         t_start_ns=start_ns, t_done_ns=time.perf_counter_ns())
                    if ttl_s > 0:
                        self.cache.put(url, result)
                    return result
            except urllib.error.HTTPError as exc:
                last_error = f"HTTP {exc.code}"
                if exc.code not in (429, 500, 502, 503, 504):
                    break
            except FeedError as exc:
                last_error = str(exc)
                break
            except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
                reason = getattr(exc, "reason", exc)
                if isinstance(reason, FeedError):            # raised inside the redirect guard
                    last_error = str(reason)
                    break
                last_error = f"{type(exc).__name__}: {reason}"
            if attempt <= self.retries:
                time.sleep(min(self.backoff_s * (2 ** (attempt - 1)), max(0.0, deadline - time.monotonic())))
        return FetchResult(feed=feed, url=url, mode="failed", status=None, error=last_error,
                           attempts=attempt, fetched_at=iso(utc_now()), t_start_ns=start_ns,
                           t_done_ns=time.perf_counter_ns(),
                           latency_ms=round((time.perf_counter_ns() - start_ns) / 1e6, 1))


def charset_of(content_type: str) -> str | None:
    for part in (content_type or "").split(";")[1:]:
        k, _, v = part.strip().partition("=")
        if k.lower() == "charset" and v:
            return v.strip().strip('"').lower()
    return None


class FeedConnector:
    """Base connector: subclasses set name/url/ext and implement ``parse`` (and ``derivative``)."""
    name = "feed"
    source_iri = "cm:feed/unknown"
    url = ""
    ext = "json"
    ttl_s = 300.0
    max_age_s = 86400.0              # snapshots older than this are treated as stale
    accept = "application/json"
    redistribute_raw = False         # True only for payloads without third-party prose (e.g. FX rates)

    def __init__(self, fetcher: HttpFetcher | None = None, snapshots: SnapshotStore | None = None,
                 url: str | None = None):
        self.fetcher = fetcher or HttpFetcher()
        self.snapshots = snapshots or SnapshotStore()
        if url:
            self.url = url

    def configure_from(self, graph, keep_url: bool = False) -> None:
        """Read endpoint, TTL and maximum snapshot age from the source node in the ontology."""
        node = self.source_iri
        if not keep_url:
            self.url = str(graph.value(node, "cm:endpointUrl", self.url))
        self.ttl_s = float(graph.value(node, "cm:ttlSeconds", self.ttl_s))
        self.max_age_s = float(graph.value(node, "cm:maxSnapshotAgeSeconds", self.max_age_s))

    # -- parsing ------------------------------------------------------------------
    def parse(self, body: bytes, fetched_at: str, as_of: datetime | None = None) -> ParseReport:
        raise NotImplementedError

    def derivative(self, body: bytes) -> bytes:
        """Text-free copy of a payload that may be redistributed; must parse to the same signals."""
        return body

    def _body_for_parse(self, body: bytes, content_type: str) -> bytes:
        """Honour a declared non-UTF-8 charset for JSON payloads (XML declares its own encoding)."""
        cs = charset_of(content_type)
        if self.ext == "json" and cs and cs not in ("utf-8", "utf8", "utf-16") \
                and not body.startswith((b"\xef\xbb\xbf", b"\xfe\xff", b"\xff\xfe")):
            try:
                return body.decode(cs).encode("utf-8")
            except (LookupError, UnicodeDecodeError):
                return body
        return body

    def _timed_parse(self, body: bytes, fetched_at: str, as_of: datetime | None) -> ParseReport:
        t0 = time.perf_counter()
        report = self.parse(body, fetched_at, as_of)
        report.source_iri = self.source_iri
        report.parse_ms = round((time.perf_counter() - t0) * 1000, 2)
        report.t_done_ns = time.perf_counter_ns()
        return report

    # -- fetch + parse + snapshot ---------------------------------------------------
    def collect(self, offline: bool = False, as_of: datetime | None = None) -> tuple[FetchResult, ParseReport]:
        if offline:
            error = "offline mode requested"
        else:
            result = self.fetcher.get(self.name, self.url, self.ttl_s, self.accept)
            if result.mode in ("live", "cache") and result.status == 200:
                try:
                    report = self._timed_parse(self._body_for_parse(result.body, result.content_type),
                                               result.fetched_at, as_of)
                except (ParseError, ValueError) as exc:          # unparseable 200: keep the old snapshot
                    error = f"HTTP 200 but unparseable payload ({str(exc)[:120]})"
                else:
                    if result.mode == "live":
                        derived = None if self.redistribute_raw else self.derivative(result.body)
                        result.snapshot_path = self.snapshots.save(result, self.ext, derived)
                    return result, report
            else:
                error = result.error or f"HTTP {result.status}"
        return self._fallback(error, as_of)

    def _fallback(self, error: str, as_of: datetime | None) -> tuple[FetchResult, ParseReport]:
        start = time.perf_counter_ns()
        loaded = self.snapshots.load(self.name, self.ext)
        if loaded is None:
            raise FeedError(f"{self.name}: live data unusable ({error}) and no snapshot is available")
        body, info = loaded
        fetched = datetime.fromisoformat(info["fetched_at"])
        age = (utc_now() - fetched).total_seconds()
        result = FetchResult(feed=self.name, url=info["url"], mode="snapshot", status=info.get("http_status"),
                             body=body, bytes=len(body), sha256=info["sha256"], latency_ms=0.0,
                             fetched_at=info["fetched_at"], content_type=info.get("content_type", ""),
                             error=error, snapshot_path=str(self.snapshots.file_for(self.name, self.ext)),
                             final_url=info.get("final_url"), original_sha256=info.get("original_sha256"),
                             original_bytes=info.get("original_bytes"), age_s=round(age, 1),
                             stale=age > self.max_age_s, t_start_ns=start, t_done_ns=time.perf_counter_ns())
        report = self._timed_parse(body, result.fetched_at, as_of)
        report.warnings.append(f"fallback to snapshot ({error}); snapshot age {age / 3600:.1f} h")
        if result.stale:
            report.confidence_scale = STALE_CONFIDENCE_SCALE
            report.warnings.append(f"snapshot older than max age {self.max_age_s / 3600:.0f} h: confidence x"
                                   f"{STALE_CONFIDENCE_SCALE}, below the property acceptance gate")
        return result, report

    def collect_file(self, path: str | Path, as_of: datetime | None = None,
                     fetched_at: str | None = None) -> tuple[FetchResult, ParseReport]:
        """Deterministic replay of a saved payload (pinned replay input or what-if fixture)."""
        start = time.perf_counter_ns()
        body = Path(path).read_bytes()
        result = FetchResult(feed=self.name, url=f"file:{Path(path).name}", mode="replay-file", status=None,
                             body=body, bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                             fetched_at=fetched_at or iso(utc_now()), snapshot_path=str(path), t_start_ns=start,
                             t_done_ns=time.perf_counter_ns())
        return result, self._timed_parse(body, result.fetched_at, as_of)

    def fact(self, s: str, p: str, o: Any, iri: bool, fetched_at: str, confidence: float = 1.0,
             evidence: str = "") -> Fact:
        return Fact(subject=s, predicate=p, obj=o, obj_is_iri=iri, source=self.source_iri,
                    fetched_at=fetched_at, confidence=round(confidence, 3), evidence=evidence[:240])


def decode_text(body: bytes) -> str:
    """Decode a payload honouring BOMs (the AWS feed is UTF-16 with a BOM)."""
    if body.startswith(b"\xef\xbb\xbf"):
        return body[3:].decode("utf-8")
    if body.startswith((b"\xfe\xff", b"\xff\xfe")):
        return body.decode("utf-16")
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return body.decode("latin-1")


def load_json(body: bytes, feed: str) -> Any:
    try:
        return json.loads(decode_text(body))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ParseError(f"{feed}: payload is not valid JSON ({type(exc).__name__}: {str(exc)[:80]})") from exc


def derived_json(payload: Any) -> bytes:
    """Canonical encoding for derived JSON snapshots."""
    return json.dumps(payload, indent=1, ensure_ascii=True, sort_keys=False).encode("utf-8")
