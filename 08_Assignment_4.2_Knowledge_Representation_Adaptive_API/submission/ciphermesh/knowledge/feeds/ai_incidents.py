"""AI Incident Database RSS connector (https://incidentdatabase.ai/rss.xml).

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

Each RSS item is a news report about a real-world AI harm: free text in many
languages. The parser keeps items from the last ``lookbackDays`` and assigns
keyword classes that matter to a privacy gateway:

* ``privacy``  - data breach / leak / personal data / biometric / home address ...
* ``intrusion`` - prompt injection, jailbreak, rogue agent, unauthorised access ...

Only dates, keyword classes and counts become agent knowledge; headline and
description text is never stored in the graph, the properties or the logs. The raw
feed is third-party editorial content, so it is not redistributed: the snapshot store
keeps a *derivative* RSS in which every item is reduced to a hashed id, its pubDate and
its keyword-class tags. Parsing that derivative gives exactly the same counts.
"""
from __future__ import annotations

import hashlib
import re
from xml.sax.saxutils import escape
from datetime import datetime, timedelta, timezone

from ..graph import KnowledgeGraph
from .base import FeedConnector, ParseReport
from .normalize import clean_text, parse_date
from .safe_xml import parse_rss

PRIVACY = re.compile(r"\b(privacy|personal data|personal information|data (?:breach|leak|protection|exposure)|"
                     r"leak(?:ed|s|age)?|exposed|biometric|home address|doxx\w*|surveillance|"
                     r"confidential (?:data|information))\b", re.I)
INTRUSION = re.compile(r"\b(prompt injection|jailbreak\w*|rogue (?:AI )?agents?|unauthori[sz]ed access|"
                       r"broke into|compromis\w*|exfiltrat\w*|supply chain)\b", re.I)


TAG_TEXT = {"privacy": "privacy", "intrusion": "unauthorized access"}


def classify(text: str) -> list[str]:
    classes = []
    if PRIVACY.search(text):
        classes.append("privacy")
    if INTRUSION.search(text):
        classes.append("intrusion")
    return classes


def item_id(guid: str, title: str) -> str:
    return guid[2:] if guid.startswith("h:") else hashlib.sha1((guid or title).encode()).hexdigest()[:12]


class AiIncidentConnector(FeedConnector):
    name = "aiid_rss"
    source_iri = "cm:feed/aiid"
    url = "https://incidentdatabase.ai/rss.xml"
    ext = "xml"
    ttl_s = 3600.0
    accept = "application/rss+xml, application/xml;q=0.9, */*;q=0.5"
    redistribute_raw = False

    def __init__(self, graph: KnowledgeGraph | None = None, **kw):
        super().__init__(**kw)
        self.lookback_days = 30
        if graph is not None:
            self.lookback_days = int(graph.value(self.source_iri, "cm:lookbackDays", 30))
            self.configure_from(graph, keep_url=bool(kw.get("url")))

    def parse(self, body: bytes, fetched_at: str, as_of: datetime | None = None) -> ParseReport:
        _title, items = parse_rss(body)
        now = (as_of or datetime.now(timezone.utc)).astimezone(timezone.utc)
        report = ParseReport(feed=self.name)
        window = timedelta(days=self.lookback_days)
        recent, privacy, intrusion, oldest = 0, 0, 0, None
        for idx, item in enumerate(items):
            report.items_seen += 1
            published = parse_date(item.pub_date)
            if published is None:
                report.warnings.append(f"item {idx}: unparseable pubDate; skipped")
                continue
            if published > now or now - published > window:
                continue
            recent += 1
            oldest = published if oldest is None or published < oldest else oldest
            classes = classify(clean_text(f"{item.title}. {item.description}", limit=4000))
            privacy += "privacy" in classes
            intrusion += "intrusion" in classes
            if not classes:
                continue
            report.items_relevant += 1
            node = "cm:incident/aiid-" + item_id(item.guid, item.title)
            f = report.facts
            f.append(self.fact(node, "rdf:type", "cm:Incident", True, fetched_at, 0.7, "+".join(classes)))
            f.append(self.fact(node, "cm:reportedBy", self.source_iri, True, fetched_at, 0.7))
            f.append(self.fact(node, "cm:statusImpact", "+".join(classes), False, fetched_at, 0.7))
            f.append(self.fact(node, "cm:observedAt", published.isoformat(), False, fetched_at, 0.7))
        # The feed is capped at its newest items, so it may cover fewer days than the window.
        # Rates are normalised by the days actually covered (oldest item in the window -> as_of).
        covered = self.lookback_days if oldest is None else min(
            float(self.lookback_days), max(1.0, (now - oldest).total_seconds() / 86400))
        report.signals = {"items_in_window": recent, "privacy_incidents": privacy,
                          "intrusion_incidents": intrusion, "window_days": self.lookback_days,
                          "covered_days": round(covered, 2), "privacy_per_day": round(privacy / covered, 4),
                          "intrusion_per_day": round(intrusion / covered, 4)}
        return report

    def derivative(self, body: bytes) -> bytes:
        """Text-free copy: hashed id + pubDate + keyword-class tags per item (no third-party wording)."""
        _title, items = parse_rss(body)
        out = ['<?xml version="1.0" encoding="utf-8"?>', '<rss version="2.0"><channel>',
               "<title>AI Incident Database feed - derived keyword-class summary</title>",
               "<description>Derived by CipherMesh: item text removed; tags reproduce the parser classes"
               "</description>"]
        for item in items:
            classes = classify(clean_text(f"{item.title}. {item.description}", limit=4000))
            tags = "; ".join(TAG_TEXT[c] for c in classes) or "other"
            out.append(f"<item><guid>h:{item_id(item.guid, item.title)}</guid>"
                       f"<pubDate>{escape(item.pub_date)}</pubDate><title>{tags}</title></item>")
        out.append("</channel></rss>")
        return "\n".join(out).encode("utf-8")
