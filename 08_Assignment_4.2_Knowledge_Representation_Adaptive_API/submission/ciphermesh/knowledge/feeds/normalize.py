"""Normalisation of messy, human-written status text.

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

Vendor feeds name the same thing many ways: "Central India", "centralindia",
"Asia Pacific (Mumbai)", "AP-SOUTH-1", "us-central1-b" (a zone). The ``Normaliser``
builds its lookup tables from the knowledge graph (``cm:alias`` and
``cm:serviceAlias`` literals), so teaching the agent a new spelling is a data change
in ontology.json, not a code change. A small table of additional public cloud region
names lets the parser recognise regions that host no CipherMesh provider (so they
can be logged and safely ignored).
"""
from __future__ import annotations

import html
import re
import unicodedata
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

from ..graph import KnowledgeGraph

# Additional region spellings (public vendor region names) -> canonical region code.
EXTRA_REGIONS = {
    "south india": "southindia", "west india": "westindia", "jio india west": "jioindiawest",
    "east us": "eastus", "east us 2": "eastus2", "west us": "westus", "west us 2": "westus2",
    "west us 3": "westus3", "central us": "centralus", "north europe": "northeurope",
    "west europe": "westeurope", "uk south": "uksouth", "southeast asia": "southeastasia",
    "east asia": "eastasia", "japan east": "japaneast", "australia east": "australiaeast",
    "uae north": "uaenorth", "qatar central": "qatarcentral",
    "oregon": "us-west-2", "n. virginia": "us-east-1", "northern virginia": "us-east-1",
    "ohio": "us-east-2", "frankfurt": "eu-central-1", "ireland": "eu-west-1", "london": "eu-west-2",
    "singapore": "ap-southeast-1", "hyderabad": "ap-south-2", "uae": "me-central-1",
    "bahrain": "me-south-1", "tokyo": "ap-northeast-1",
}
AWS_REGION = re.compile(r"\b((?:us|eu|ap|sa|ca|me|af|il|mx)-(?:gov-)?(?:north|south|east|west|central|"
                        r"northeast|northwest|southeast|southwest)-\d)\b", re.IGNORECASE)
GCP_REGION = re.compile(r"\b((?:us|europe|asia|australia|northamerica|southamerica|me|africa)-"
                        r"(?:north|south|east|west|central|northeast|northwest|southeast|southwest)\d)"
                        r"(?:-[a-f])?\b", re.IGNORECASE)

OUTAGE = re.compile(r"\b(outage|unavailable|unavailability|down|not available|failures? to connect|"
                    r"service disruption|cannot access|unable to access|region availability)\b", re.I)
DEGRADED = re.compile(r"\b(degrad\w*|elevated (?:error|latenc)\w*|increased (?:error|latenc)\w*|"
                      r"intermittent\w*|partial\w*|slow\w*|timeouts?|errors? rates?|latenc(?:y|ies)|"
                      r"impaired|disruption)\b", re.I)
RESOLVED = re.compile(r"\b(resolved|mitigated|recovered|restored|operating normally|full recovery|"
                      r"has been fixed|post incident review|incident report)\b", re.I)
TAG = re.compile(r"<[^>]{0,2000}>")
SPACE = re.compile(r"\s+")


def clean_text(raw: str, limit: int = 20000) -> str:
    """Strip HTML tags, decode entities, NFKC-normalise and collapse whitespace."""
    text = TAG.sub(" ", raw[:limit * 2])
    text = html.unescape(text)
    text = unicodedata.normalize("NFKC", text)
    return SPACE.sub(" ", text).strip()[:limit]


def classify_impact(text: str) -> str:
    """Return outage | degraded | resolved | advisory from free text (resolution wins if stated)."""
    if RESOLVED.search(text):
        return "resolved"
    if OUTAGE.search(text):
        return "outage"
    if DEGRADED.search(text):
        return "degraded"
    return "advisory"


def parse_date(raw: str) -> datetime | None:
    """Parse RFC 822 (RSS), ISO-8601 or epoch-seconds strings to an aware UTC datetime."""
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        if raw.isdigit():
            return datetime.fromtimestamp(int(raw), tz=timezone.utc)
        if re.match(r"^\d{4}-\d{2}-\d{2}", raw):
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        else:
            dt = parsedate_to_datetime(raw.replace(" Z", " +0000"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, OverflowError, IndexError):
        return None


class Normaliser:
    def __init__(self, graph: KnowledgeGraph):
        self.graph = graph
        self.region_alias: dict[str, str] = {}      # lower alias -> region code
        self.region_node: dict[str, str] = {}       # region code -> node
        for node in graph.instances_of("cm:CloudRegion"):
            code = str(graph.value(node, "cm:regionCode"))
            self.region_node[code.lower()] = node
            self.region_alias[code.lower()] = code
            for alias in graph.values(node, "cm:alias"):
                self.region_alias[str(alias).lower()] = code
        for alias, code in EXTRA_REGIONS.items():
            self.region_alias.setdefault(alias, code)
            self.region_alias.setdefault(code, code)        # canonical codes are valid spellings too
        self.service_alias: list[tuple[re.Pattern, str]] = []
        for pid, node in graph.providers().items():
            for alias in sorted(graph.values(node, "cm:serviceAlias"), key=lambda a: -len(str(a))):
                self.service_alias.append((re.compile(rf"(?<![\w-]){re.escape(str(alias))}(?![\w-])", re.I), pid))
        self.provider_region = {pid: str(graph.value(graph.value(node, "cm:hostedIn"), "cm:regionCode"))
                                for pid, node in graph.providers().items()}
        names = sorted(self.region_alias, key=len, reverse=True)
        self._alias_re = re.compile(r"(?<![\w-])(" + "|".join(re.escape(n) for n in names) + r")(?![\w-])", re.I)

    def region(self, raw: str) -> str | None:
        """Canonical region code for one location string (zones collapse to their region)."""
        if not raw:
            return None
        s = clean_text(raw).strip()
        m = re.search(r"\(([^)]+)\)\s*$", s)            # "Iowa (us-central1)" -> us-central1
        for cand in ([m.group(1)] if m else []) + [s]:
            low = cand.lower()
            g = GCP_REGION.fullmatch(low) or GCP_REGION.fullmatch(re.sub(r"-[a-f]$", "", low))
            if g:
                return g.group(1)
            a = AWS_REGION.fullmatch(low)
            if a:
                return a.group(1)
            if low in self.region_alias:
                return self.region_alias[low]
        return None

    def find_regions(self, text: str) -> set[str]:
        """All region codes mentioned anywhere in free text."""
        found = {m.group(1).lower() for m in AWS_REGION.finditer(text)}
        found |= {m.group(1).lower() for m in GCP_REGION.finditer(text)}
        found |= {self.region_alias[m.group(1).lower()] for m in self._alias_re.finditer(text)}
        return found

    def find_providers(self, text: str) -> set[str]:
        """Provider ids whose service aliases appear in the text."""
        return {pid for rx, pid in self.service_alias if rx.search(text)}

    def is_provider_region(self, provider_id: str, region_code: str) -> bool:
        return self.provider_region.get(provider_id, "").lower() == (region_code or "").lower()
