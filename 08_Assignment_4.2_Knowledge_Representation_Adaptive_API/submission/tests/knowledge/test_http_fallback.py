"""HTTP client hardening and offline snapshot fallback, against a local test server.

Author: Kumar Waibhav Akshat (RA2212704010027)
"""
import hashlib
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ciphermesh.knowledge.feeds import (AiIncidentConnector, FeedError, FxRateConnector, GcpStatusConnector,
                                        HttpFetcher, SnapshotStore)

FX = b'{"amount":1.0,"base":"USD","date":"2026-10-30","rates":{"INR":94.95}}'
AIID = (b'<?xml version="1.0"?><rss version="2.0"><channel><title>t</title><item><guid>g1</guid>'
        b'<title>Clinic chatbot leaked patient personal data</title><description>Third-party text.</description>'
        b'<pubDate>Thu, 29 Oct 2026 00:00:00 GMT</pubDate></item></channel></rss>')


class Handler(BaseHTTPRequestHandler):
    hits: dict = {}
    seen_agents: list = []

    def log_message(self, *_):
        pass

    def do_GET(self):  # noqa: N802
        Handler.hits[self.path] = Handler.hits.get(self.path, 0) + 1
        Handler.seen_agents.append(self.headers.get("User-Agent"))
        if self.path == "/fx":
            self._send(200, FX)
        elif self.path == "/flaky":                       # fails twice, then succeeds
            self._send(503, b"busy") if Handler.hits[self.path] <= 2 else self._send(200, FX)
        elif self.path == "/aiid":
            self._send(200, AIID)
        elif self.path == "/html":                        # a captive portal / error page served as 200
            self._send(200, b"<html><body>Service temporarily unavailable</body></html>", "text/html")
        elif self.path == "/latin1":
            self._send(200, '{"amount":1.0,"base":"USD","date":"2026-10-30","rates":{"INR":94.95},'
                            '"note":"caf\u00e9"}'.encode("latin-1"), "application/json; charset=iso-8859-1")
        elif self.path == "/redir-same":
            self._redirect("/fx")
        elif self.path == "/redir-offhost":
            self._redirect(f"http://localhost:{self.server.server_address[1]}/fx")
        elif self.path == "/redir-plain":
            self._redirect("http://example.com/fx")
        elif self.path == "/big":
            self._send(200, b"x" * 5000)
        elif self.path == "/notfound":
            self._send(404, b"no")
        else:
            self._send(500, b"err")

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    Handler.hits, Handler.seen_agents = {}, []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def _closed_port_url():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}/fx"


def test_fetch_success_records_hash_latency_and_user_agent(server):
    r = HttpFetcher(timeout_s=3).get("fx", server + "/fx")
    assert r.mode == "live" and r.status == 200 and r.bytes == len(FX)
    assert r.sha256 == hashlib.sha256(FX).hexdigest() and r.latency_ms >= 0
    assert "CipherMesh-KnowledgeFeeds" in Handler.seen_agents[0]


def test_retries_on_503_then_succeeds(server):
    r = HttpFetcher(timeout_s=3, retries=2, backoff_s=0.01).get("fx", server + "/flaky")
    assert r.status == 200 and r.attempts == 3 and Handler.hits["/flaky"] == 3


def test_no_retry_on_404_and_size_cap(server):
    f = HttpFetcher(timeout_s=3, retries=3, backoff_s=0.01, max_bytes=1000)
    nf = f.get("x", server + "/notfound")
    assert nf.mode == "failed" and nf.error == "HTTP 404" and Handler.hits["/notfound"] == 1
    big = f.get("x", server + "/big")
    assert big.mode == "failed" and "exceeds" in big.error


def test_ttl_cache_avoids_second_request(server):
    f = HttpFetcher(timeout_s=3)
    a = f.get("fx", server + "/fx", ttl_s=60)
    b = f.get("fx", server + "/fx", ttl_s=60)
    assert a.mode == "live" and b.mode == "cache" and Handler.hits["/fx"] == 1 and b.sha256 == a.sha256


def test_plain_http_to_non_loopback_is_refused():
    with pytest.raises(FeedError):
        HttpFetcher().get("x", "http://example.com/feed")
    with pytest.raises(FeedError):
        HttpFetcher().get("x", "ftp://example.com/feed")


def test_live_fetch_saves_snapshot_then_network_failure_falls_back(server, tmp_path, graph):
    store = SnapshotStore(tmp_path)
    live = FxRateConnector(graph, fetcher=HttpFetcher(timeout_s=3), snapshots=store, url=server + "/fx")
    fetch, report = live.collect()
    assert fetch.mode == "live" and report.signals["rate"] == 94.95
    meta = json.loads((tmp_path / "fx_usd_inr.meta.json").read_text())
    assert meta["sha256"] == hashlib.sha256(FX).hexdigest() and meta["http_status"] == 200
    dead = FxRateConnector(graph, fetcher=HttpFetcher(timeout_s=1, retries=1, backoff_s=0.01), snapshots=store,
                           url=_closed_port_url())
    fetch2, report2 = dead.collect()
    assert fetch2.mode == "snapshot" and fetch2.error and report2.signals["rate"] == 94.95
    assert fetch2.fetched_at == fetch.fetched_at                 # provenance keeps the original fetch time


def test_no_snapshot_and_no_network_raises(tmp_path, graph):
    conn = GcpStatusConnector(graph, fetcher=HttpFetcher(timeout_s=1, retries=0), snapshots=SnapshotStore(tmp_path),
                              url=_closed_port_url())
    with pytest.raises(FeedError):
        conn.collect()


def test_tampered_snapshot_fails_integrity_check(server, tmp_path, graph):
    store = SnapshotStore(tmp_path)
    FxRateConnector(graph, fetcher=HttpFetcher(timeout_s=3), snapshots=store, url=server + "/fx").collect()
    (tmp_path / "fx_usd_inr.json").write_bytes(FX.replace(b"94.95", b"9.99"))
    with pytest.raises(FeedError, match="SHA-256"):
        FxRateConnector(graph, snapshots=store).collect(offline=True)


def test_withheld_raw_payload_keeps_meta_and_falls_back_to_derivative(server, tmp_path, graph):
    store = SnapshotStore(tmp_path)
    conn = AiIncidentConnector(graph, fetcher=HttpFetcher(timeout_s=3), snapshots=store, url=server + "/aiid")
    fetch, live = conn.collect()
    assert fetch.mode == "live" and not (tmp_path / "aiid_rss.xml").exists()
    meta = json.loads((tmp_path / "aiid_rss.meta.json").read_text())
    assert meta["raw_redistributed"] is False and meta["original_sha256"] == hashlib.sha256(AIID).hexdigest()
    assert meta["original_bytes"] == len(AIID)
    assert meta["note"] == "raw payload not redistributed (third-party content); re-fetch to reproduce"
    derived = (tmp_path / "aiid_rss.derived.xml").read_bytes()
    assert b"Clinic chatbot" not in derived and meta["sha256"] == hashlib.sha256(derived).hexdigest()
    assert meta["bytes"] == len(derived)
    fetch2, offline = AiIncidentConnector(graph, snapshots=store).collect(offline=True)
    assert fetch2.mode == "snapshot" and offline.signals["privacy_incidents"] == live.signals["privacy_incidents"]
    assert fetch2.original_sha256 == hashlib.sha256(AIID).hexdigest() and fetch2.sha256 == meta["sha256"]
    assert store.file_for("aiid_rss", "xml").name == "aiid_rss.derived.xml"


def test_unparseable_200_does_not_overwrite_snapshot_and_falls_back(server, tmp_path, graph):
    store = SnapshotStore(tmp_path)
    FxRateConnector(graph, fetcher=HttpFetcher(timeout_s=3), snapshots=store, url=server + "/fx").collect()
    before = (tmp_path / "fx_usd_inr.json").read_bytes()
    conn = FxRateConnector(graph, fetcher=HttpFetcher(timeout_s=3), snapshots=store, url=server + "/html")
    fetch, report = conn.collect()
    assert fetch.mode == "snapshot" and "unparseable" in fetch.error
    assert (tmp_path / "fx_usd_inr.json").read_bytes() == before        # the good snapshot survived
    assert report.signals["rate"] == 94.95 and any("fallback" in w for w in report.warnings)


def test_redirects_are_followed_only_on_the_same_host_and_scheme(server):
    f = HttpFetcher(timeout_s=3, retries=0)
    ok = f.get("fx", server + "/redir-same")
    assert ok.mode == "live" and ok.final_url == server + "/fx"
    off = f.get("fx", server + "/redir-offhost")
    assert off.mode == "failed" and "off-host redirect" in off.error
    plain = f.get("fx", server + "/redir-plain")
    assert plain.mode == "failed" and "non-HTTPS" in plain.error


def test_declared_charset_is_honoured(server, graph):
    conn = FxRateConnector(graph, fetcher=HttpFetcher(timeout_s=3), snapshots=SnapshotStore(server and "/nonexistent"),
                           url=server + "/latin1")
    conn.snapshots.save = lambda *a, **k: "not saved"           # keep the test free of disk writes
    fetch, report = conn.collect()
    assert fetch.mode == "live" and report.signals["rate"] == 94.95


def test_overall_deadline_stops_retries(tmp_path):
    f = HttpFetcher(timeout_s=1, retries=5, backoff_s=5, deadline_s=1.5)
    r = f.get("x", _closed_port_url())
    assert r.mode == "failed" and r.latency_ms < 4000


def test_stale_snapshot_is_flagged_and_down_weighted(server, tmp_path, graph):
    store = SnapshotStore(tmp_path)
    FxRateConnector(graph, fetcher=HttpFetcher(timeout_s=3), snapshots=store, url=server + "/fx").collect()
    meta_path = tmp_path / "fx_usd_inr.meta.json"
    meta = json.loads(meta_path.read_text())
    meta["fetched_at"] = "2026-01-01T00:00:00.000+00:00"            # far older than the 7-day maximum age
    meta_path.write_text(json.dumps(meta))
    fetch, report = FxRateConnector(graph, snapshots=store).collect(offline=True)
    assert fetch.stale and fetch.age_s > 7 * 86400 and report.confidence_scale == 0.4
    assert any("older than max age" in w for w in report.warnings)
