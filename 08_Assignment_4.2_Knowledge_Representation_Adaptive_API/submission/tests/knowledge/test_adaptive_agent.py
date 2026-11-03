"""Scenario tests: the same prompt is planned differently after live knowledge changes.

Author: Kumar Waibhav Akshat (RA2212704010027)
"""
import pytest

from ciphermesh.agent import CipherMeshAgent
from ciphermesh.knowledge import AdaptiveCipherMeshAgent
from ciphermesh.knowledge.feeds import (AwsHealthConnector, AzureStatusConnector, CisaKevConnector,
                                        GcpStatusConnector, Normaliser)
from ciphermesh.providers import DEFAULT_PROFILES
from ciphermesh.routing import RouteConstraints, route

from .conftest import REPLAY_AS_OF, WHATIF

CLEAN = "Summarise the attached quarterly product roadmap in five bullet points."
EMAIL = "Reply to priya.sharma@example.com about the delayed invoice."
AADHAAR = "Complete KYC for Aadhaar 2345 6789 0124 and update the record."
ARN = "Why does arn:aws:iam::123456789012:role/prod-deployer fail?"
BIG = "worker heartbeat ok, queue depth nominal\n" * 1000          # ~41 KB


@pytest.fixture
def agent(graph):
    return AdaptiveCipherMeshAgent(graph)


def test_profiles_from_graph_reproduce_engine_routing(agent):
    mine = {p.provider_id: p for p in agent.base_profiles()}
    for p in DEFAULT_PROFILES:
        q = mine[p.provider_id]
        assert (q.region, q.data_residency, q.cost_per_1k_requests_usd, q.p95_latency_ms, q.quality_score,
                q.availability_pct, q.kind) == (p.region, p.data_residency, p.cost_per_1k_requests_usd,
                                                p.p95_latency_ms, p.quality_score, p.availability_pct, p.kind)
    engine = route(list(DEFAULT_PROFILES), RouteConstraints())
    assert agent.plan_for(CLEAN).selected == engine.selected == "gcp-vertex"


def test_baseline_plans(agent):
    assert (agent.plan_for(CLEAN).decision, agent.plan_for(CLEAN).selected) == ("ALLOW", "gcp-vertex")
    e = agent.plan_for(EMAIL)
    assert (e.decision, e.selected, e.residency) == ("REDACT", "gcp-vertex", None)
    a = agent.plan_for(AADHAAR)
    assert (a.decision, a.selected, a.residency) == ("REDACT", "aws-bedrock", ["IN", "LOCAL"])
    assert "RESIDENCY_NOT_ALLOWED: US" in a.evaluations["gcp-vertex"]["reasons"]


def test_outage_excludes_and_degraded_penalises(agent):
    v0 = agent.context.version
    agent.properties.set("provider.gcp-vertex.status", "degraded", "test", 0.9)
    assert agent.context.version == v0 + 1                         # re-planned inside set()
    p = agent.plan_for(CLEAN)
    assert p.selected == "aws-bedrock"
    assert p.evaluations["gcp-vertex"]["feasible"] and p.evaluations["gcp-vertex"]["utility"] == pytest.approx(71.16, abs=0.01)
    agent.properties.set("provider.aws-bedrock.status", "outage", "test", 0.9)
    p2 = agent.plan_for(AADHAAR)
    assert "DISABLED" in p2.evaluations["aws-bedrock"]["reasons"] and p2.selected == "azure-ai"
    agent.properties.set("provider.aws-bedrock.status", "operational", "test", 0.9)
    assert agent.plan_for(AADHAAR).selected == "aws-bedrock"        # recovery restores the plan


def test_fx_budget_changes_route_and_feasibility(agent):
    agent.properties.set("fx.usd_inr", 94.95, "test")
    agent.adapter.derive()
    p = agent.plan_for(AADHAAR)
    assert p.constraints["max_cost_per_1k_usd"] == round(300 / 94.95, 4)
    assert any(r.startswith("OVER_BUDGET") for r in p.evaluations["azure-ai"]["reasons"])
    assert p.selected == "local"


def test_elevated_posture_tightens_policy(agent):
    assert agent.plan_for(ARN).decision == "ALLOW" and agent.plan_for(BIG).decision == "ALLOW"
    for k, v in (("threat.kev.ratio", 1.75), ("threat.kev.relevant_hits", 3)):
        agent.properties.set(k, v, "test")
    agent.adapter.derive()
    arn = agent.plan_for(ARN)
    assert arn.decision == "REDACT" and "custom_redaction" in arn.categories
    big = agent.plan_for(BIG)
    assert big.decision == "BLOCK" and big.route_status == "NOT_ROUTED" and big.reasons[0].startswith("R5")


def test_high_posture_restricts_residency_and_recommends_lockdown(agent):
    agent.properties.set("threat.kev.ratio", 2.5, "test")
    agent.properties.set("threat.kev.relevant_hits", 12, "test")
    agent.adapter.derive()
    p = agent.plan_for(CLEAN)
    assert p.constraints["allowed_residency"] == ["IN", "LOCAL"] and p.selected == "aws-bedrock"
    assert any("lockdown RECOMMENDED" in n for n in p.notes)


def test_review_plan_is_local_only(agent):
    p = agent.plan_for("See http://wiki.corp.local/runbook for the steps")
    assert p.decision == "REVIEW" and p.route_status == "PREVIEW_AFTER_APPROVAL" and p.selected == "local"


def test_replay_at_as_of_is_deterministic(graph, fix):
    def run():
        a = AdaptiveCipherMeshAgent()
        n = Normaliser(a.graph)
        a.replay_file(GcpStatusConnector(a.graph, n), fix / "gcp_incidents_real_sample.json", REPLAY_AS_OF)
        a.replay_file(AzureStatusConnector(a.graph, n), WHATIF, REPLAY_AS_OF)
        a.replay_file(AwsHealthConnector(a.graph, n), fix / "aws_currentevents_real_sample.json", REPLAY_AS_OF)
        return [(p.decision, p.selected, p.utility) for p in (a.plan_for(CLEAN), a.plan_for(AADHAAR))], a
    first, a = run()
    second, _ = run()
    assert first == second == [("ALLOW", "aws-bedrock", 75.1167), ("REDACT", "aws-bedrock", 75.1167)]
    assert a.context.provider_status == {"aws-bedrock": "operational", "azure-ai": "outage",
                                         "gcp-vertex": "degraded", "local": "operational"}
    assert a.properties.source_of("provider.azure-ai.status")[0] == "azure_status:replay-file:replay"


def test_event_timings_cover_fetch_parse_property_plan(agent, fix):
    ev = agent.replay_file(GcpStatusConnector(agent.graph), fix / "gcp_incidents_real_sample.json", REPLAY_AS_OF)
    t = ev.timings_ms
    assert ev.replay and ev.mode == "replay-file" and ev.plan_version_after > ev.plan_version_before
    assert t["parsed_to_property_ms"] >= 0 and t["property_to_plan_ms"] is not None and t["property_to_plan_ms"] < 50
    assert agent.replans[-1]["property_to_plan_ms"] == t["property_to_plan_ms"]


def test_sync_engine_agent_pushes_policy_into_running_agent(agent):
    engine = CipherMeshAgent("ENGINE", ":memory:")
    agent.properties.set("threat.kev.ratio", 1.75, "test")
    agent.adapter.derive()
    out = agent.sync_engine_agent(engine)
    assert engine.state.max_prompt_bytes == 32768 == out["max_prompt_bytes"]
    assert len(engine.state.custom_redaction_patterns) == 2 and engine.state.policy_revision == 2
    assert engine.inspect(ARN, open_review=False).decision.value == "REDACT"


def test_invalid_custom_pattern_is_rejected_by_engine_guardrail(agent):
    agent.properties.set("policy.custom_redaction_patterns", ["(a+)+$", r"TICKET-[0-9]{6}"], "test")
    assert agent.context.state.custom_redaction_patterns == ["TICKET-[0-9]{6}"]
    assert any("rejected by engine guardrail" in n for n in agent.context.notes)


def test_pinned_replay_inputs_match_manifest_and_contain_no_prose():
    import hashlib
    import json
    from pathlib import Path
    replay = Path(__file__).resolve().parents[2] / "data" / "replay"
    manifest = json.loads((replay / "MANIFEST.json").read_text())
    assert set(manifest["files"]) == {"gcp_status.derived.json", "aws_health.derived.json", "cisa_kev.derived.json",
                                      "aiid_rss.derived.xml", "whatif_azure_status.xml"}
    for name, entry in manifest["files"].items():
        body = (replay / name).read_bytes()
        assert hashlib.sha256(body).hexdigest() == entry["sha256"], name
        if name != "whatif_azure_status.xml":
            assert b"<description><![CDATA[" not in body and b"external_desc" not in body
            assert b"shortDescription" not in body and b'"message"' not in body
