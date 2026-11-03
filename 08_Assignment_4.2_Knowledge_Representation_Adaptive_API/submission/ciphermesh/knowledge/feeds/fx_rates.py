"""Exchange-rate connector (Frankfurter API, ECB reference rates).

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

Endpoint: https://api.frankfurter.dev/v1/latest?from=USD&to=INR
Response: {"amount":1.0,"base":"USD","date":"YYYY-MM-DD","rates":{"INR":<float>}}

Provider prices in the engine are in USD; the organisation budgets in INR. The live
rate lets the adapter convert the INR budget into the router's
``max_cost_per_1k_usd`` constraint. A sanity band (10..1000 INR per USD) rejects
corrupted values instead of silently mis-pricing every route.
"""
from __future__ import annotations

import math
from datetime import date, datetime

from ..graph import KnowledgeGraph
from .base import FeedConnector, ParseError, ParseReport, load_json

SANE_BAND = (10.0, 1000.0)


class FxRateConnector(FeedConnector):
    name = "fx_usd_inr"
    source_iri = "cm:feed/frankfurter"
    url = "https://api.frankfurter.dev/v1/latest?from=USD&to=INR"
    ext = "json"
    ttl_s = 3600.0
    max_age_s = 7 * 86400.0
    redistribute_raw = True          # a number and a date: no third-party prose

    def __init__(self, graph: KnowledgeGraph | None = None, base: str = "USD", quote: str = "INR", **kw):
        super().__init__(**kw)
        self.base, self.quote = base, quote
        if graph is not None:
            self.configure_from(graph, keep_url=bool(kw.get("url")))

    def parse(self, body: bytes, fetched_at: str, as_of: datetime | None = None) -> ParseReport:
        data = load_json(body, self.name)
        report = ParseReport(feed=self.name, items_seen=1)
        if not isinstance(data, dict) or not isinstance(data.get("rates"), dict):
            raise ParseError(f"{self.name}: expected an object with a 'rates' map")
        if str(data.get("base", "")).upper() != self.base:
            raise ParseError(f"{self.name}: base currency is {data.get('base')!r}, expected {self.base}")
        raw = data["rates"].get(self.quote)
        try:
            rate = float(raw) / float(data.get("amount", 1.0) or 1.0)
        except (TypeError, ValueError) as exc:
            raise ParseError(f"{self.name}: rate for {self.quote} is not numeric: {raw!r}") from exc
        if not math.isfinite(rate) or not SANE_BAND[0] <= rate <= SANE_BAND[1]:
            raise ParseError(f"{self.name}: rate {rate} outside sanity band {SANE_BAND}")
        try:
            rate_date = date.fromisoformat(str(data.get("date", ""))).isoformat()
        except ValueError:
            rate_date = ""
            report.warnings.append("missing or invalid rate date")
        report.items_relevant = 1
        node = f"cm:fxrate/{self.base}-{self.quote}"
        report.facts.append(self.fact(node, "cm:rateValue", round(rate, 6), False, fetched_at, 1.0,
                                      f"{self.base}/{self.quote}={rate} on {rate_date}"))
        report.facts.append(self.fact(node, "cm:observedAt", fetched_at, False, fetched_at))
        report.signals = {"pair": f"{self.base}/{self.quote}", "rate": round(rate, 6), "rate_date": rate_date}
        return report
