"""Live knowledge connectors for CipherMesh (Assignment 4.2).

Author: Kumar Waibhav Akshat (RA2212704010027)
"""
from __future__ import annotations

from ..graph import KnowledgeGraph
from .ai_incidents import AiIncidentConnector
from .aws_health import AwsHealthConnector
from .azure_status import AzureStatusConnector
from .base import (FeedConnector, FeedError, FetchResult, Fact, HttpFetcher, ParseError, ParseReport,
                   SnapshotStore, TTLCache)
from .cisa_kev import CisaKevConnector
from .fx_rates import FxRateConnector
from .gcp_status import GcpStatusConnector
from .normalize import Normaliser
from .safe_xml import UnsafeXMLError, parse_rss, parse_xml

__all__ = ["AiIncidentConnector", "AwsHealthConnector", "AzureStatusConnector", "CisaKevConnector",
           "FeedConnector", "FeedError", "FetchResult", "Fact", "FxRateConnector", "GcpStatusConnector",
           "HttpFetcher", "Normaliser", "ParseError", "ParseReport", "SnapshotStore", "TTLCache",
           "UnsafeXMLError", "default_connectors", "parse_rss", "parse_xml"]


def default_connectors(graph: KnowledgeGraph, fetcher: HttpFetcher | None = None,
                       snapshots: SnapshotStore | None = None) -> list[FeedConnector]:
    """The six live connectors, in the order the demo runs them."""
    fetcher = fetcher or HttpFetcher()
    snapshots = snapshots or SnapshotStore()
    norm = Normaliser(graph)
    kw = dict(fetcher=fetcher, snapshots=snapshots)
    return [GcpStatusConnector(graph, norm, **kw), AzureStatusConnector(graph, norm, **kw),
            AwsHealthConnector(graph, norm, **kw), CisaKevConnector(graph, **kw),
            FxRateConnector(graph, **kw), AiIncidentConnector(graph, **kw)]
