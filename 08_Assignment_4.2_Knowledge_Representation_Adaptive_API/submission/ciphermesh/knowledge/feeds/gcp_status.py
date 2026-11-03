"""Google Cloud Service Health connector (https://status.cloud.google.com/incidents.json).

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

The feed is semi-structured JSON: a list of incidents with begin/end times, a
``status_impact`` code, affected products and locations, plus free-text
descriptions. An incident affects ``gcp-vertex`` when one of the provider's service
aliases (Vertex AI, Vertex Gemini API, ...) appears among the products or text and
the incident names the provider's region (us-central1) - or the "global" location,
which is accepted with lower confidence. ``as_of`` lets a saved snapshot be replayed
at any past instant (deterministic what-if).
"""
from __future__ import annotations

from datetime import datetime, timedelta

from .base import ParseError, ParseReport, derived_json, iso, load_json
from .normalize import clean_text, parse_date
from .status_common import StatusConnector

IMPACT = {"SERVICE_OUTAGE": "outage", "SERVICE_DISRUPTION": "degraded"}


class GcpStatusConnector(StatusConnector):
    name = "gcp_status"
    source_iri = "cm:feed/gcp-status"
    url = "https://status.cloud.google.com/incidents.json"
    ext = "json"

    def parse(self, body: bytes, fetched_at: str, as_of: datetime | None = None) -> ParseReport:
        data = load_json(body, self.name)
        if not isinstance(data, list):
            raise ParseError(f"{self.name}: expected a JSON list of incidents, got {type(data).__name__}")
        now = self.as_of(as_of)
        report = self.new_report()
        window = timedelta(days=self.lookback_days)
        for idx, inc in enumerate(data):
            report.items_seen += 1
            if not isinstance(inc, dict):
                report.warnings.append(f"item {idx}: not an object; skipped")
                continue
            begin = parse_date(str(inc.get("begin") or ""))
            if begin is None:
                report.warnings.append(f"item {idx}: missing/invalid 'begin'; skipped")
                continue
            if begin > now:
                continue                                   # in the future relative to as_of
            end = parse_date(str(inc.get("end") or ""))
            active = end is None or now < end
            recent = not active and end is not None and now - end <= window
            if not (active or recent):
                continue
            products = [str(p.get("title", "")) for p in inc.get("affected_products") or [] if isinstance(p, dict)]
            view = inc.get("derived_text") if isinstance(inc.get("derived_text"), dict) else \
                self.text_view(clean_text(str(inc.get("external_desc") or "")))
            names = " | ".join([str(inc.get("service_name") or ""), *products])
            locs = list(inc.get("currently_affected_locations") or []) if active else []
            if not locs:
                locs = list(inc.get("previously_affected_locations") or []) + list(
                    inc.get("currently_affected_locations") or [])
            regions = set()
            for loc in locs:
                if isinstance(loc, dict):
                    code = self.norm.region(str(loc.get("id") or "")) or self.norm.region(str(loc.get("title") or ""))
                    if code:
                        regions.add(code)
                    elif str(loc.get("id", "")).lower() == "global":
                        regions.add("global")
            if not regions:                                # unstructured fallback: read the prose
                regions = set(view.get("regions", []))
            report.signals["regions_seen"].extend(r for r in regions)
            code = str(inc.get("status_impact") or "")
            text_class = str(view.get("impact_class", "advisory"))
            impact = IMPACT.get(code) or ("degraded" if text_class in ("degraded", "outage") else "advisory")
            providers = (self.norm.find_providers(names) | set(view.get("providers", []))) & set(self.monitored)
            iid = self.incident_id("gcp", str(inc.get("id") or idx))
            affected: set[str] = set()
            for pid in providers:
                if any(self.norm.is_provider_region(pid, r) for r in regions):
                    affected.add(pid)
                    conf = 0.9
                elif "global" in regions:
                    affected.add(pid)
                    conf = 0.6
                else:
                    continue
                if active:
                    self.mark(report, pid, impact, conf, iid,
                              f"status_impact={code or 'n/a'}; text_class={text_class}; "
                              f"regions={','.join(sorted(regions))}")
                else:
                    report.signals["recent_incidents"][pid] += 1
            report.signals["active_total" if active else "recent_total"] += 1
            if affected or active:
                report.items_relevant += 1 if affected else 0
                self.incident_facts(report, iid, f"GCP incident {str(inc.get('id') or idx)[:24]}", impact if active else "resolved",
                                    regions, affected, fetched_at, 0.9, iso(begin))
        return self.finish(report, fetched_at)

    def derivative(self, body: bytes) -> bytes:
        """Structured fields only; the prose description is replaced by what the parser reads from it."""
        data = load_json(body, self.name)
        keep = ("id", "begin", "end", "created", "modified", "severity", "status_impact", "service_name",
                "service_key", "currently_affected_locations", "previously_affected_locations")
        out = []
        for inc in data if isinstance(data, list) else []:
            if not isinstance(inc, dict):
                continue
            d = {k: inc[k] for k in keep if k in inc}
            d["affected_products"] = [{"title": p.get("title", "")} for p in inc.get("affected_products") or []
                                      if isinstance(p, dict)]
            d["derived_text"] = self.text_view(clean_text(str(inc.get("external_desc") or "")))
            out.append(d)
        return derived_json(out)
