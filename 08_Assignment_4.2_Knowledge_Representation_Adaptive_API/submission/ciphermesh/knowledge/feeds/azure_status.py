"""Azure status RSS connector (https://azure.status.microsoft/en-us/status/feed/).

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

This feed is unstructured: each RSS item is a human-written title and an HTML
description. The parser cleans the HTML, then extracts

* service names  -> provider (via ``cm:serviceAlias``: "Azure AI Foundry", ...),
* region names   -> canonical code (via ``cm:alias`` and the extra region table),
* severity words -> outage / degraded / resolved (keyword classes).

An item affects ``azure-ai`` when an Azure AI service alias and the provider's region
("Central India") are both mentioned, or when the text says the impact spans multiple
or all regions (lower confidence). The channel is empty when Azure has no active
incident, which the parser reports as "operational" with confidence 0.8.
"""
from __future__ import annotations

import re
from xml.sax.saxutils import escape
from datetime import datetime, timedelta

from .base import ParseReport, iso
from .normalize import classify_impact, clean_text, parse_date
from .safe_xml import parse_rss
from .status_common import StatusConnector

BROAD = re.compile(r"\b(multiple regions|all regions|global(?:ly)?|worldwide)\b", re.I)


class AzureStatusConnector(StatusConnector):
    name = "azure_status"
    source_iri = "cm:feed/azure-status"
    url = "https://azure.status.microsoft/en-us/status/feed/"
    ext = "xml"
    accept = "application/rss+xml, application/xml;q=0.9, */*;q=0.5"

    def parse(self, body: bytes, fetched_at: str, as_of: datetime | None = None) -> ParseReport:
        _title, items = parse_rss(body)
        now = self.as_of(as_of)
        report = self.new_report()
        window = timedelta(days=self.lookback_days)
        for idx, item in enumerate(items):
            report.items_seen += 1
            text = clean_text(f"{item.title}. {item.description}")
            if not text:
                report.warnings.append(f"item {idx}: empty title and description; skipped")
                continue
            published = parse_date(item.pub_date)
            if published is None:
                report.warnings.append(f"item {idx}: unparseable pubDate {item.pub_date!r}; using fetch time")
            elif published > now or now - published > window:
                continue
            impact = classify_impact(text)
            regions = self.norm.find_regions(text)
            report.signals["regions_seen"].extend(regions)
            providers = self.norm.find_providers(text) & set(self.monitored)
            iid = (f"cm:incident/azure-{item.guid[2:]}" if item.guid.startswith("h:")
                   else self.incident_id("azure", item.guid or item.title))
            affected = set()
            for pid in providers:
                if any(self.norm.is_provider_region(pid, r) for r in regions):
                    conf = 0.85
                elif BROAD.search(text):
                    conf = 0.6
                else:
                    continue
                affected.add(pid)
                if impact == "resolved":
                    report.signals["recent_incidents"][pid] += 1
                else:
                    self.mark(report, pid, impact, conf, iid,
                              f"text_class={impact}; regions={','.join(sorted(regions))}")
            report.signals["recent_total" if impact == "resolved" else "active_total"] += 1
            if affected:
                report.items_relevant += 1
            self.incident_facts(report, iid, f"Azure status item {iid.rsplit('-', 1)[-1]}", impact, regions, affected, fetched_at,
                                0.85 if affected else 0.7, iso(published) if published else fetched_at)
        return self.finish(report, fetched_at)

    def derivative(self, body: bytes) -> bytes:
        """Text-free RSS: each item keeps a hashed id, its pubDate and the tokens the parser extracted
        (provider label, region codes, severity class, broad-scope marker)."""
        _title, items = parse_rss(body)
        labels = {pid: self.graph.label(node) for pid, node in self.graph.providers().items()}
        out = ['<?xml version="1.0" encoding="utf-8"?>', '<rss version="2.0"><channel>',
               "<title>Azure status feed - derived token summary</title>",
               "<description>Derived by CipherMesh: item prose removed; tokens reproduce the parser view"
               "</description>"]
        for item in items:
            text = clean_text(f"{item.title}. {item.description}")
            view = self.text_view(text)
            tokens = [labels[p] for p in view["providers"] if p in labels] + view["regions"] + [view["impact_class"]]
            if BROAD.search(text):
                tokens.append("multiple regions")
            iid = self.incident_id("azure", item.guid or item.title).rsplit("-", 1)[-1]
            out.append(f"<item><guid>h:{iid}</guid><pubDate>{escape(item.pub_date)}</pubDate>"
                       f"<title>{escape(' | '.join(tokens))}</title></item>")
        out.append("</channel></rss>")
        return "\n".join(out).encode("utf-8")
