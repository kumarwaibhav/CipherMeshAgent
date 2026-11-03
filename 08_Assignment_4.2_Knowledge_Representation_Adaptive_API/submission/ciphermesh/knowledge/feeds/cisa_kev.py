"""CISA Known Exploited Vulnerabilities (KEV) connector.

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

Endpoint: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

The parser turns the catalog into threat-posture evidence:

* ``recent``      - entries added in the last ``lookbackDays`` (30) before ``as_of``;
* ``baseline``    - median monthly additions over the 12 preceding 30-day windows
                    (self-calibrating base rate, so the signal is "busier than usual",
                    not an absolute number);
* ``ratio``       - recent / baseline;
* ``relevant``    - recent entries whose vendor is on the watch list in the ontology
                    (``cm:feed/cisa-kev cm:watchesVendor ...``; matched via ``cm:kevMatch``);
* ``ai_ml``       - recent entries whose product or description names AI/ML software;
* ``ransomware``  - relevant entries with ``knownRansomwareCampaignUse == "Known"``.
"""
from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from statistics import median

from ..graph import KnowledgeGraph
from .base import FeedConnector, ParseError, ParseReport, derived_json, load_json

AI_ML = re.compile(r"\b(artificial intelligence|machine learning|large language model|LLM|Langflow|Ollama|"
                   r"TensorFlow|PyTorch|MLflow|Triton Inference|model serving|Jupyter)\b", re.I)
AI_ACRONYM = re.compile(r"\bAI\b")


class CisaKevConnector(FeedConnector):
    name = "cisa_kev"
    source_iri = "cm:feed/cisa-kev"
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    ext = "json"
    ttl_s = 3600.0

    def __init__(self, graph: KnowledgeGraph, **kw):
        super().__init__(**kw)
        self.graph = graph
        node = self.source_iri
        self.configure_from(graph, keep_url=bool(kw.get("url")))
        self.lookback_days = int(graph.value(node, "cm:lookbackDays", 30))
        self.watch: list[tuple[str, str]] = []           # (lowercase kev vendor name, vendor node)
        for vendor in graph.objects(node, "cm:watchesVendor"):
            for name in graph.values(vendor, "cm:kevMatch"):
                self.watch.append((str(name).lower(), vendor))

    def vendor_of(self, vendor_project: str) -> str | None:
        vp = vendor_project.lower().strip()
        for name, node in self.watch:
            if vp == name or vp.startswith(name + " "):
                return node
        return None

    @staticmethod
    def is_ai_ml(v: dict) -> bool:
        text = " ".join(str(v.get(k, "")) for k in ("product", "vulnerabilityName", "shortDescription"))
        return bool(AI_ML.search(text) or AI_ACRONYM.search(text))

    def derivative(self, body: bytes) -> bytes:
        """Identifiers, vendor/product, dates and flags only; vulnerability names and descriptions are
        replaced by the AI/ML flag the parser derives from them."""
        data = load_json(body, self.name)
        rows = []
        for v in data.get("vulnerabilities", []) if isinstance(data, dict) else []:
            if isinstance(v, dict):
                rows.append({k: v.get(k) for k in ("cveID", "vendorProject", "product", "dateAdded",
                                                   "knownRansomwareCampaignUse")} | {"derived_ai_ml": self.is_ai_ml(v)})
        return derived_json({"catalogVersion": data.get("catalogVersion"), "dateReleased": data.get("dateReleased"),
                             "count": len(rows), "vulnerabilities": rows})

    def parse(self, body: bytes, fetched_at: str, as_of: datetime | None = None) -> ParseReport:
        data = load_json(body, self.name)
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise ParseError(f"{self.name}: expected an object with a 'vulnerabilities' list")
        today: date = (as_of or datetime.now(timezone.utc)).astimezone(timezone.utc).date()
        report = ParseReport(feed=self.name)
        entries = []
        for idx, v in enumerate(data["vulnerabilities"]):
            report.items_seen += 1
            if not isinstance(v, dict):
                report.warnings.append(f"entry {idx}: not an object; skipped")
                continue
            try:
                added = date.fromisoformat(str(v.get("dateAdded", ""))[:10])
            except ValueError:
                report.warnings.append(f"entry {idx}: invalid dateAdded {v.get('dateAdded')!r}; skipped")
                continue
            if added <= today:
                entries.append((added, v))
        n = self.lookback_days
        recent = [(d, v) for d, v in entries if 0 <= (today - d).days < n]
        months = []
        for m in range(1, 13):
            lo, hi = today - timedelta(days=n * (m + 1)), today - timedelta(days=n * m)
            months.append(sum(1 for d, _ in entries if lo < d <= hi))
        baseline = max(1.0, float(median(months))) if months else 1.0
        relevant, ai_ml, ransomware = [], [], []
        for d, v in sorted(recent, key=lambda x: (x[0], str(x[1].get("cveID"))), reverse=True):
            vendor = self.vendor_of(str(v.get("vendorProject", "")))
            is_ai = bool(v["derived_ai_ml"]) if "derived_ai_ml" in v else self.is_ai_ml(v)
            if not (vendor or is_ai):
                continue
            report.items_relevant += 1
            cve = str(v.get("cveID", "unknown"))
            rec = {"cve": cve, "vendor": str(v.get("vendorProject", "")), "product": str(v.get("product", "")),
                   "date_added": d.isoformat(), "ransomware": str(v.get("knownRansomwareCampaignUse", ""))}
            if vendor:
                relevant.append(rec)
                if rec["ransomware"].lower() == "known":
                    ransomware.append(rec)
            if is_ai:
                ai_ml.append(rec)
            node = f"cm:vuln/{cve}"
            f = report.facts
            f.append(self.fact(node, "rdf:type", "cm:Vulnerability", True, fetched_at, 1.0))
            f.append(self.fact(node, "cm:cveId", cve, False, fetched_at, 1.0))
            f.append(self.fact(node, "rdfs:label", f"{cve} ({rec['vendor']} {rec['product']})"[:160], False, fetched_at))
            f.append(self.fact(node, "cm:dateAdded", d.isoformat(), False, fetched_at))
            f.append(self.fact(node, "cm:reportedBy", self.source_iri, True, fetched_at))
            if vendor:
                f.append(self.fact(node, "cm:affectsVendor", vendor, True, fetched_at, 1.0,
                                   f"{rec['vendor']} {rec['product']}"))
        ratio = round(len(recent) / baseline, 3)
        report.signals = {"catalog_version": str(data.get("catalogVersion", "")),
                          "catalog_count": len(data["vulnerabilities"]), "as_of": today.isoformat(),
                          "recent": len(recent), "baseline_monthly_median": baseline, "monthly_counts": months,
                          "ratio": ratio, "relevant_hits": len(relevant), "ai_ml_hits": len(ai_ml),
                          "ransomware_hits": len(ransomware), "relevant": relevant[:12], "ai_ml": ai_ml[:6],
                          "top_vendors_recent": _top([str(v.get("vendorProject", "")) for _, v in recent])}
        report.facts.append(self.fact(self.source_iri, "cm:observedAt", fetched_at, False, fetched_at))
        return report


def _top(names: list[str], k: int = 6) -> list[list]:
    counts: dict[str, int] = {}
    for n in names:
        counts[n] = counts.get(n, 0) + 1
    return [[n, c] for n, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:k]]
