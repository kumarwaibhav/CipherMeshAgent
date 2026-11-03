"""AWS Health Dashboard connector (https://health.aws.amazon.com/public/currentevents).

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

This public endpoint backs the AWS Health Dashboard page. It is not a documented
API, so the parser is deliberately defensive:

* the body is UTF-16 with a byte-order mark (decoded by ``decode_text``);
* each event has a service key such as ``bedrock-ap-south-1`` or
  ``multipleservices-me-central-1`` - the region is read from the key, then from
  ``region_name`` ("Oregon", "UAE"), then from the free-text messages;
* the event log carries numeric statuses (1 informational, 2 degradation,
  3 disruption; a top-level status of "0" means resolved), cross-checked with
  severity words in the message text.

An event affects ``aws-bedrock`` when the service is Bedrock (or "multiple
services") in ap-south-1.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from .base import ParseError, ParseReport, derived_json, iso, load_json
from .normalize import AWS_REGION, clean_text, parse_date
from .status_common import StatusConnector

LOG_STATUS = {1: "advisory", 2: "degraded", 3: "outage"}


class AwsHealthConnector(StatusConnector):
    name = "aws_health"
    source_iri = "cm:feed/aws-health"
    url = "https://health.aws.amazon.com/public/currentevents"
    ext = "json"

    def parse(self, body: bytes, fetched_at: str, as_of: datetime | None = None) -> ParseReport:
        data = load_json(body, self.name) if body.strip() else []
        if isinstance(data, dict):           # tolerate a wrapped list
            data = next((v for v in data.values() if isinstance(v, list)), [])
        if not isinstance(data, list):
            raise ParseError(f"{self.name}: expected a list of events, got {type(data).__name__}")
        now = self.as_of(as_of)
        report = self.new_report()
        window = timedelta(days=self.lookback_days)
        for idx, ev in enumerate(data):
            report.items_seen += 1
            if not isinstance(ev, dict):
                report.warnings.append(f"event {idx}: not an object; skipped")
                continue
            begin = parse_date(str(ev.get("date") or ""))
            if begin is None:
                report.warnings.append(f"event {idx}: missing/invalid 'date'; skipped")
                continue
            if begin > now:
                continue
            end = parse_date(str(ev.get("end_time") or ""))
            log = [e for e in ev.get("event_log") or [] if isinstance(e, dict)]
            stamps = [parse_date(str(e.get("timestamp") or "")) or begin for e in log]
            log_now = [e for e, t in zip(log, stamps) if t <= now]
            if end is None and str(ev.get("status", "")) == "0":
                end = max(stamps, default=begin)      # resolved without end_time: last update closes it
            active = end is None or now < end
            recent = not active and (end or begin) is not None and now - (end or begin) <= window
            if not (active or recent):
                continue
            key = str(ev.get("service") or "")
            m = AWS_REGION.search(key)
            region = m.group(1).lower() if m else self.norm.region(str(ev.get("region_name") or ""))
            view = ev.get("derived_text") if isinstance(ev.get("derived_text"), dict) else self.text_view(
                clean_text(" ".join([str(ev.get("summary") or "")] +
                                    [f"{e.get('summary', '')} {e.get('message', '')}" for e in log_now[-3:]])))
            regions = {region} if region else set(view.get("regions", []))
            report.signals["regions_seen"].extend(r for r in regions if r)
            codes = [LOG_STATUS.get(int(e.get("status", 0)) if str(e.get("status", "")).isdigit() else 0)
                     for e in log_now]
            impact = max((c for c in codes if c), key=lambda c: ["advisory", "degraded", "outage"].index(c),
                         default=None) or str(view.get("impact_class", "advisory"))
            if impact == "resolved":
                active = False
            name = f"{key} {ev.get('service_name', '')}"
            iid = self.incident_id("aws", str(ev.get("arn") or key), str(ev.get("date")))
            affected = set()
            for pid in self.monitored:
                bedrock = "bedrock" in name.lower() or bool(self.norm.find_providers(name) & {pid})
                multi = "multipleservices" in key.lower() or "multiple services" in name.lower()
                if (bedrock or multi) and any(self.norm.is_provider_region(pid, r) for r in regions):
                    affected.add(pid)
                    conf = 0.9 if bedrock else 0.7
                    if active:
                        self.mark(report, pid, impact, conf, iid,
                                  f"event_log_max={impact}; service_key={key}")
                    else:
                        report.signals["recent_incidents"][pid] += 1
            report.signals["active_total" if active else "recent_total"] += 1
            if affected:
                report.items_relevant += 1
            self.incident_facts(report, iid, f"AWS Health event {key}", impact if active else "resolved",
                                regions, affected, fetched_at, 0.85, iso(begin))
        return self.finish(report, fetched_at)

    def derivative(self, body: bytes) -> bytes:
        """Structured fields and status codes only; summaries and messages become their parsed view."""
        data = load_json(body, self.name) if body.strip() else []
        if isinstance(data, dict):
            data = next((v for v in data.values() if isinstance(v, list)), [])
        out = []
        for ev in data if isinstance(data, list) else []:
            if not isinstance(ev, dict):
                continue
            log = [e for e in ev.get("event_log") or [] if isinstance(e, dict)]
            d = {k: ev[k] for k in ("date", "arn", "region_name", "status", "service", "service_name", "end_time")
                 if k in ev}
            d["event_log"] = [{"status": e.get("status"), "timestamp": e.get("timestamp")} for e in log]
            d["derived_text"] = self.text_view(clean_text(" ".join(
                [str(ev.get("summary") or "")] + [f"{e.get('summary', '')} {e.get('message', '')}" for e in log[-3:]])))
            out.append(d)
        return derived_json(out)
