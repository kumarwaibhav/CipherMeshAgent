"""Optional live test: really contacts the public endpoints. Skipped when the network is unavailable.

Author: Kumar Waibhav Akshat (RA2212704010027)
Run only this test:  pytest -m live
"""
import os
import socket

import pytest

from ciphermesh.knowledge import AdaptiveCipherMeshAgent
from ciphermesh.knowledge.feeds import HttpFetcher, SnapshotStore, default_connectors


def _online() -> bool:
    if os.environ.get("CIPHERMESH_OFFLINE") == "1":
        return False
    try:
        socket.getaddrinfo("api.frankfurter.dev", 443)
        return HttpFetcher(timeout_s=8, retries=0).get("probe", "https://api.frankfurter.dev/v1/latest?from=USD&to=INR"
                                                       ).status == 200
    except OSError:
        return False


@pytest.mark.live
@pytest.mark.skipif(not _online(), reason="network unavailable (or CIPHERMESH_OFFLINE=1)")
def test_all_six_live_endpoints_respond_and_update_the_agent(tmp_path):
    agent = AdaptiveCipherMeshAgent()
    connectors = default_connectors(agent.graph, HttpFetcher(timeout_s=20, retries=1), SnapshotStore(tmp_path))
    events = [agent.update_from(c) for c in connectors]
    assert all(e.mode == "live" and e.http_status == 200 and e.bytes > 0 and len(e.sha256) == 64 for e in events)
    assert len(list(tmp_path.glob("*.meta.json"))) == 6
    assert 10 < agent.properties.get("fx.usd_inr") < 1000
    assert agent.properties.get("threat.posture") in {"LOW", "ELEVATED", "HIGH"}
    assert {agent.properties.get(f"provider.{p}.status") for p in ("gcp-vertex", "azure-ai", "aws-bedrock")} <= {
        "operational", "advisory", "degraded", "outage"}
