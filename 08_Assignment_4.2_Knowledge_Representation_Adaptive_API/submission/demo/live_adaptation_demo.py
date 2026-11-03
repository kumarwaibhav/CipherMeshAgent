"""Assignment 4.2 demonstration: live knowledge feeds change the CipherMesh agent's plans.

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Knowledge Representation and Adaptive API Integration

Phases
------
A  Load and validate the ontology, print the knowledge summary, plan five prompts.
B  Connect to six LIVE public endpoints, parse them, update graph + properties.
C  Re-plan the same prompts and print what changed and why.
   C also attributes every change to a feed (leave-one-feed-out re-runs).
D  Deterministic REPLAY at a past instant (as_of = 2026-02-27T13:00Z) using the pinned,
   hash-checked inputs in data/replay/, so an outage/advisory is visible even when
   today's feeds are quiet. Phase D is labelled as replay; Phase B is live unless --offline.

Usage:  python demo/live_adaptation_demo.py [--offline] [--logs logs]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ciphermesh.knowledge import AdaptiveCipherMeshAgent, load_graph, summary  # noqa: E402
from ciphermesh.knowledge.feeds import (AwsHealthConnector, AzureStatusConnector, CisaKevConnector,  # noqa: E402
                                        GcpStatusConnector, AiIncidentConnector, FeedError, HttpFetcher,
                                        Normaliser, ParseError, SnapshotStore, default_connectors)
from ciphermesh.knowledge.ontology import load_document, schema_errors  # noqa: E402
from ciphermesh.routing import INDIA_PERSONAL_DATA  # noqa: E402

REPLAY_AS_OF = datetime(2026, 2, 27, 13, 0, tzinfo=timezone.utc)
PEAK_AS_OF = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)     # HIGH date in the KEV backtest
REPLAY_DIR = ROOT / "data" / "replay"


def pinned(name: str) -> tuple[Path, str]:
    """Return (path, original fetch time) of a pinned replay input after checking its SHA-256."""
    manifest = json.loads((REPLAY_DIR / "MANIFEST.json").read_text(encoding="utf-8"))
    entry = manifest["files"][name]
    path = REPLAY_DIR / name
    if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
        raise SystemExit(f"replay input {name} does not match its pinned SHA-256")
    return path, entry.get("source_fetched_at", manifest["pinned_at"])

PROMPTS = {
    "P1 clean": "Summarise the attached quarterly product roadmap in five bullet points for the leadership team.",
    "P2 email": "Draft a polite reply to priya.sharma@example.com explaining that the March invoice is delayed.",
    "P3 Aadhaar": "Complete KYC for the customer with Aadhaar 2345 6789 0124 and update the onboarding record.",
    "P4 cloud ARN": "Why does arn:aws:iam::123456789012:role/prod-deployer fail to assume the build role?",
    "P5 40 KB log": "Explain the failure pattern in this service log:\n"
                    + "worker heartbeat ok, queue depth nominal, batch committed\n" * 700,
}


class UTCFormatter(logging.Formatter):
    converter = time.gmtime

    def formatTime(self, record, datefmt=None):  # noqa: N802
        return time.strftime("%Y-%m-%d %H:%M:%S", self.converter(record.created)) + f".{int(record.msecs):03d}Z"


def setup_logging(log_dir: Path) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    log = logging.getLogger("ciphermesh.a42")
    log.setLevel(logging.INFO)
    log.handlers.clear()
    fmt = UTCFormatter("%(asctime)s | %(levelname)-5s | %(message)s")
    fh = logging.FileHandler(log_dir / "live_feed_run.log", mode="w", encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(fh)
    log.addHandler(sh)
    return log


def banner(log, text: str) -> None:
    log.info("=" * 96)
    log.info(text)
    log.info("=" * 96)


def plan_all(agent: AdaptiveCipherMeshAgent, log, title: str) -> dict:
    log.info(f"{title}  (plan version {agent.context.version}, posture {agent.context.posture})")
    log.info(f"  {'prompt':<14}{'decision':<9}{'route':<13}{'utility':>8}  {'budget USD':>10}  "
             f"{'residency':<20}{'R5 bytes':>9}")
    plans = {}
    for label, text in PROMPTS.items():
        p = agent.plan_for(text, label)
        plans[label] = p.to_dict()
        util = f"{p.utility:.2f}" if p.utility is not None else "-"
        log.info(f"  {label:<14}{p.decision:<9}{(p.selected or p.route_status):<13}{util:>8}  "
                 f"{p.constraints['max_cost_per_1k_usd']:>10.4f}  {','.join(p.constraints['allowed_residency']):<20}"
                 f"{p.constraints['max_prompt_bytes']:>9}")
    return plans


def explain(before: dict, after: dict) -> str:
    """Human-readable reason for a plan difference, computed from the two plans."""
    why = []
    if before["decision"] != after["decision"]:
        why.append(f"policy {before['decision']}->{after['decision']} ({after['reasons'][0]})")
    if before["constraints"]["max_cost_per_1k_usd"] != after["constraints"]["max_cost_per_1k_usd"]:
        why.append(f"budget USD {before['constraints']['max_cost_per_1k_usd']:.2f}->"
                   f"{after['constraints']['max_cost_per_1k_usd']:.2f}")
    if before["constraints"]["allowed_residency"] != after["constraints"]["allowed_residency"]:
        why.append(f"residency {','.join(after['constraints']['allowed_residency'])}")
    old, new = before.get("selected"), after.get("selected")
    if old and old != new and old in after["evaluations"]:
        ev = after["evaluations"][old]
        if ev["reasons"]:
            why.append(f"{old}: {ev['reasons'][0]}")
        else:
            why.append(f"{old} utility {before['utility']:.2f}->{ev['utility']:.2f}")
    if new and new != old:
        why.append(f"{new} now best (U={after['utility']:.2f})")
    return "; ".join(why) or "no change"


def diff(log, before: dict, after: dict, title: str) -> list[dict]:
    log.info(title)
    log.info(f"  {'prompt':<14}{'before':<26}{'after':<26}why")
    rows = []
    for label in PROMPTS:
        b, a = before[label], after[label]
        fmt = lambda p: f"{p['decision']} -> {p['selected'] or p['route_status']}"  # noqa: E731
        changed = (b["decision"], b["selected"], b["route_status"]) != (a["decision"], a["selected"], a["route_status"])
        reason = explain(b, a)
        log.info(f"  {label:<14}{fmt(b):<26}{fmt(a):<26}{'CHANGED: ' + reason if changed else 'unchanged' + ('' if reason == 'no change' else f' (constraints: {reason})')}")
        rows.append({"prompt": label, "before": fmt(b), "after": fmt(a), "changed": changed, "why": reason,
                     "utility_before": b["utility"], "utility_after": a["utility"]})
    return rows


def signal_line(sig: dict) -> str:
    if "provider_status" in sig:
        st = "; ".join(f"{p}={v['status']} (conf {v['confidence']})" for p, v in sig["provider_status"].items())
        return (f"{st}; active incidents in feed={sig['active_total']}, recent={sig['recent_total']}, "
                f"regions={','.join(sig['regions_seen'][:6]) or '-'}")
    if "ratio" in sig:
        rel = ", ".join(f"{r['vendor']} {r['product']} ({r['cve']})" for r in sig["relevant"][:4])
        return (f"KEV catalog {sig['catalog_version']}: {sig['recent']} added in 30 d vs median "
                f"{sig['baseline_monthly_median']} -> ratio {sig['ratio']}; relevant={sig['relevant_hits']} "
                f"[{rel}]; ai_ml={sig['ai_ml_hits']}; ransomware={sig['ransomware_hits']}")
    if "rate" in sig:
        return f"{sig['pair']} = {sig['rate']} (ECB reference date {sig['rate_date']})"
    if "privacy_incidents" in sig:
        return (f"{sig['items_in_window']} reports in {sig['window_days']} d; privacy={sig['privacy_incidents']}, "
                f"intrusion={sig['intrusion_incidents']} (counts only; report text is not stored)")
    return "-"


def attribute(log, results, plans_c: dict) -> dict:
    """Leave-one-feed-out: rebuild the agent from the same parsed reports minus one feed and re-plan."""
    out = {}
    log.info("Attribution (leave-one-feed-out re-runs on the same parsed data):")
    for feed in [f for f, _x, _y in results]:
        agent = AdaptiveCipherMeshAgent(load_graph())
        for name, fetch, report in results:
            if name != feed:
                agent.adapter.ingest(fetch, report)
        plans = {k: agent.plan_for(t, k).to_dict() for k, t in PROMPTS.items()}
        diffs = [f"{k.split()[0]} {plans[k]['decision']}->{plans_c[k]['decision']}"
                 + (f" {plans[k]['selected'] or '-'}->{plans_c[k]['selected'] or '-'}"
                    if plans[k]["selected"] != plans_c[k]["selected"] else "")
                 for k in PROMPTS if (plans[k]["decision"], plans[k]["selected"]) !=
                 (plans_c[k]["decision"], plans_c[k]["selected"])]
        posture = agent.properties.get("threat.posture", "LOW")
        out[feed] = {"posture_without": posture, "plans_caused": diffs}
        log.info(f"  without {feed:<12} -> posture {posture:<8} | plan changes caused by {feed}: "
                 f"{', '.join(diffs) if diffs else 'none'}")
    return out


def log_event(log, ev, events_fh) -> None:
    t = ev.timings_ms
    log.info(f"  [{ev.feed}] {ev.mode.upper()} url={ev.url}")
    log.info(f"      http={ev.http_status} bytes={ev.bytes} fetch={t['fetch_ms']}ms parse={t['parse_ms']}ms "
             f"sha256={(ev.original_sha256 or ev.sha256)[:16]}... fetched_at={ev.fetched_at}"
             + (" STALE" if ev.stale else ""))
    log.info(f"      items={ev.items_seen} relevant={ev.items_relevant} facts={ev.facts} "
             f"triples_added={ev.triples_added} replaced={ev.triples_replaced} "
             f"plan v{ev.plan_version_before}->v{ev.plan_version_after}")
    log.info(f"      extracted: {signal_line(ev.signals)}")
    for c in ev.property_changes:
        new = c["new"] if not isinstance(c["new"], list) else f"[{len(c['new'])} items]"
        old = c["old"] if not isinstance(c["old"], list) else f"[{len(c['old'])} items]"
        log.info(f"      property {c['key']}: {old!r} -> {new!r}  (src={c['source']}, conf={c['confidence']}, "
                 f"at={c['at']})")
    log.info(f"      latency: fetch->parsed {t['fetch_to_parsed_ms']}ms | parsed->property "
             f"{t['parsed_to_property_ms']}ms | property->plan {t['property_to_plan_ms']}ms | "
             f"end-to-end {t['end_to_end_ms']}ms")
    for w in ev.warnings[:3]:
        log.info(f"      warning: {w}")
    events_fh.write(json.dumps({"logged_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                                **ev.to_dict()}, default=str) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--offline", action="store_true", help="skip the network and use saved snapshots only")
    ap.add_argument("--logs", default=str(ROOT / "logs"))
    args = ap.parse_args()
    log_dir = Path(args.logs)
    log = setup_logging(log_dir)
    events_fh = open(log_dir / "adaptation_events.jsonl", "w", encoding="utf-8")
    snapshots = SnapshotStore(ROOT / "data" / "snapshots")
    fetcher = HttpFetcher(timeout_s=20.0, retries=2)
    record: dict = {"started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "mode": "offline" if args.offline else "live"}

    # ------------------------------------------------------------------ Phase A
    banner(log, "PHASE A - load the formal knowledge base and plan with ontology defaults")
    t0 = time.perf_counter()
    errs = schema_errors(load_document())
    graph = load_graph()
    log.info(f"ontology.json validated against ontology.schema.json: {len(errs)} schema errors; "
             f"loaded + inferred in {(time.perf_counter() - t0) * 1000:.1f} ms")
    s = summary(graph)
    for k in ("version", "triples", "by_asserted", "by_inferred", "classes", "providers", "regions",
              "jurisdictions", "data_categories", "detector_families", "legal_instruments", "policy_rules",
              "threat_classes", "live_sources", "watched_vendors"):
        log.info(f"  knowledge  {k:<18} {s.get(k)}")
    derived = graph.residency_restricted_categories()
    log.info(f"  residency rule derived from graph : {sorted(derived)} -> {graph.derive_residency(derived).allowed_jurisdictions}")
    log.info(f"  engine hard-coded INDIA_PERSONAL_DATA: {sorted(INDIA_PERSONAL_DATA)} -> ['IN', 'LOCAL']  "
             f"EQUAL={derived == INDIA_PERSONAL_DATA}")
    for chain in graph.derive_residency(["aadhaar", "phone_in"]).chain:
        log.info(f"  inference chain: {chain}")
    agent = AdaptiveCipherMeshAgent(graph)
    plans_a = plan_all(agent, log, "Phase A plans")
    record["phase_a"] = {"summary": s, "plans": plans_a, "context": agent.context.summary()}

    # ------------------------------------------------------------------ Phase B
    if args.offline:
        banner(log, "PHASE B - OFFLINE: saved snapshots only (NOT live data), parse, update graph and properties")
    else:
        banner(log, "PHASE B - LIVE: connect to public REST/RSS endpoints, parse, update graph and properties")
    endpoints, results = [], []
    triples_before = len(graph)
    for conn in default_connectors(graph, fetcher, snapshots):
        try:
            fetch, report = conn.collect(offline=args.offline)
            ev = agent.adapter.ingest(fetch, report)
        except (FeedError, ParseError, ValueError) as exc:
            log.info(f"  [{conn.name}] FAILED: {exc}")
            endpoints.append({"feed": conn.name, "url": conn.url, "mode": "failed", "error": str(exc)})
            continue
        results.append((conn.name, fetch, report))
        log_event(log, ev, events_fh)
        endpoints.append({"feed": ev.feed, "url": ev.url, "doc": str(graph.value(conn.source_iri, "cm:docUrl")),
                          "mode": ev.mode, "http_status": ev.http_status, "bytes": ev.bytes,
                          "latency_ms": ev.timings_ms["fetch_ms"], "parse_ms": ev.timings_ms["parse_ms"],
                          "sha256_stored": ev.sha256, "original_sha256": ev.original_sha256,
                          "final_url": ev.final_url, "stale": ev.stale,
                          "fetched_at": ev.fetched_at, "facts_extracted": ev.facts,
                          "triples_added": ev.triples_added, "property_changes": len(ev.property_changes),
                          "items_seen": ev.items_seen, "items_relevant": ev.items_relevant, "signals": ev.signals,
                          "snapshot": str(snapshots.file_for(conn.name, conn.ext).relative_to(ROOT)),
                          "warnings": ev.warnings})
    log.info(f"graph grew from {triples_before} to {len(graph)} triples; properties now: "
             f"{json.dumps({k: v for k, v in agent.properties.snapshot().items() if not k.startswith('policy.custom')})}")
    record["phase_b"] = {"endpoints": endpoints, "properties": agent.properties.snapshot(),
                         "context": agent.context.summary()}

    # ------------------------------------------------------------------ Phase C
    banner(log, "PHASE C - re-plan the same prompts after the live update")
    plans_c = plan_all(agent, log, "Phase C plans")
    for note in agent.context.notes:
        log.info(f"  context note: {note}")
    rows_c = diff(log, plans_a, plans_c, "Phase A -> Phase C differences")
    posture_att = agent.adapter.posture_attribution()
    log.info("Posture attribution (evidence of one feed removed / alone): "
             + "; ".join(f"{k} -> {v}" for k, v in posture_att.items()))
    if agent.adapter.last_decision is not None:
        log.info(f"  posture {agent.adapter.last_decision.label} because {agent.adapter.last_decision.reason()}")
    plan_att = attribute(log, results, plans_c)
    record["phase_c"] = {"plans": plans_c, "diff": rows_c, "context": agent.context.summary(),
                         "posture_attribution": posture_att, "plan_attribution": plan_att,
                         "posture_reason": agent.adapter.last_decision.reason() if agent.adapter.last_decision
                         else None}
    (log_dir / "knowledge_graph_live.svg").write_text(graph.to_svg(), encoding="utf-8")
    (log_dir / "knowledge_graph_export.json").write_text(json.dumps(graph.to_json(include_inferred=False),
                                                                    indent=1, default=str), encoding="utf-8")

    # ------------------------------------------------------------------ Phase D
    banner(log, f"PHASE D - REPLAY (deterministic what-if, as_of={REPLAY_AS_OF.isoformat()}); NOT live data")
    manifest = json.loads((REPLAY_DIR / "MANIFEST.json").read_text(encoding="utf-8"))
    log.info(f"  inputs pinned in data/replay/ (MANIFEST.json, pinned {manifest['pinned_at']}); every SHA-256 checked:")
    for name, f in manifest["files"].items():
        log.info(f"    {name:<30} {f['bytes']:>8} B  sha256={f['sha256'][:16]}...  {f['kind']}")
    replay = AdaptiveCipherMeshAgent(load_graph())
    plans_d0 = plan_all(replay, log, "Replay baseline (ontology defaults)")
    norm = Normaliser(replay.graph)
    kw = dict(fetcher=fetcher, snapshots=snapshots)
    log.info("Step D.1 - provider incidents at as_of")
    for conn, path in ((GcpStatusConnector(replay.graph, norm, **kw), pinned("gcp_status.derived.json")),
                       (AzureStatusConnector(replay.graph, norm, **kw), pinned("whatif_azure_status.xml")),
                       (AwsHealthConnector(replay.graph, norm, **kw), pinned("aws_health.derived.json"))):
        log_event(log, replay.replay_file(conn, path[0], as_of=REPLAY_AS_OF, fetched_at=path[1]), events_fh)
    plans_d1 = plan_all(replay, log, "Replay plans after D.1")
    for note in replay.context.notes:
        log.info(f"  context note: {note}")
    rows_d1 = diff(log, plans_d0, plans_d1, "Replay baseline -> D.1 differences")
    log.info("Step D.2 - threat posture at as_of")
    for conn, path in ((CisaKevConnector(replay.graph, **kw), pinned("cisa_kev.derived.json")),
                       (AiIncidentConnector(replay.graph, **kw), pinned("aiid_rss.derived.xml"))):
        log_event(log, replay.replay_file(conn, path[0], as_of=REPLAY_AS_OF, fetched_at=path[1]), events_fh)
    plans_d2 = plan_all(replay, log, "Replay plans after D.2")
    for note in replay.context.notes:
        log.info(f"  context note: {note}")
    rows_d2 = diff(log, plans_d1, plans_d2, "D.1 -> D.2 differences")
    if replay.adapter.last_decision is not None:
        log.info(f"  replay posture {replay.adapter.last_decision.label} because "
                 f"{replay.adapter.last_decision.reason()}")
    log.info(f"Step D.3 - threat posture at the KEV backtest peak, as_of={PEAK_AS_OF.isoformat()} "
             "(fresh agent, KEV evidence only)")
    peak = AdaptiveCipherMeshAgent(load_graph())
    kev_path, kev_at = pinned("cisa_kev.derived.json")
    log_event(log, peak.replay_file(CisaKevConnector(peak.graph, **kw), kev_path, as_of=PEAK_AS_OF,
                                    fetched_at=kev_at), events_fh)
    plans_d3 = plan_all(peak, log, "Replay plans after D.3")
    for note in peak.context.notes:
        log.info(f"  context note: {note}")
    rows_d3 = diff(log, plans_d0, plans_d3, "Replay baseline -> D.3 differences")
    if peak.adapter.last_decision is not None:
        log.info(f"  peak posture {peak.adapter.last_decision.label} because {peak.adapter.last_decision.reason()}")
    (log_dir / "knowledge_graph_replay.svg").write_text(
        replay.graph.to_svg("CipherMesh knowledge graph after REPLAY (as_of 2026-02-27T13:00Z, not live)"),
        encoding="utf-8")
    record["phase_d"] = {"as_of": REPLAY_AS_OF.isoformat(), "baseline": plans_d0, "d1": plans_d1, "d2": plans_d2,
                         "diff_d1": rows_d1, "diff_d2": rows_d2, "context": replay.context.summary(),
                         "peak_as_of": PEAK_AS_OF.isoformat(), "d3": plans_d3, "diff_d3": rows_d3,
                         "peak_reason": peak.adapter.last_decision.reason() if peak.adapter.last_decision else None,
                         "peak_context": peak.context.summary(),
                         "replay_reason": replay.adapter.last_decision.reason() if replay.adapter.last_decision
                         else None,
                         "properties": replay.properties.snapshot()}

    # ------------------------------------------------------------------ outputs
    events_fh.close()
    (log_dir / "live_endpoints_report.json").write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "mode": record["mode"],
        "transport": "HTTPS (TLS 1.2+, certificate verification on), urllib, timeout 20 s, 2 retries, 8 MiB cap",
        "endpoints": endpoints}, indent=1), encoding="utf-8")
    (log_dir / "demo_record.json").write_text(json.dumps(record, indent=1, default=str), encoding="utf-8")
    live_ok = sum(1 for e in endpoints if e.get("mode") == "live")
    source = "saved-snapshot data (offline run)" if args.offline else "live data"
    banner(log, f"DONE - {live_ok}/{len(endpoints)} endpoints live; {sum(r['changed'] for r in rows_c)} of "
                f"{len(rows_c)} plans changed by {source}; replay changed "
                f"{sum(r['changed'] for r in rows_d1)} (D.1), {sum(r['changed'] for r in rows_d2)} (D.2) and "
                f"{sum(r['changed'] for r in rows_d3)} (D.3)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
