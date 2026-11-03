"""Unified agent: review queue, routing, procurement, orchestrator invariants, runtime."""
import threading
import time
from datetime import timedelta

import pytest

from ciphermesh.models import AgentState, Decision, InspectionResult, Finding
from ciphermesh.orchestrator import ProcessStatus, build_default_orchestrator
from ciphermesh.procurement import ContractBook
from ciphermesh.providers import DEFAULT_PROFILES, ProviderHealth, ProviderUnavailable
from ciphermesh.review import ReviewError, ReviewQueue, ReviewStatus
from ciphermesh.routing import RouteConstraints, RouteWeights, derive_constraints, route
from ciphermesh.runtime import ConcurrentRuntime


@pytest.fixture
def orch():
    return build_default_orchestrator(audit_path=":memory:")


# ----------------------------------------------------------------------- review queue
def test_review_holds_text_only_in_memory_and_releases_once():
    q = ReviewQueue()
    t = q.submit("secret context https://x.corp.local", ["internal_url"], ["R3"], "preview")
    assert "secret context" not in t.model_dump_json()
    ticket, held = q.decide(t.review_id, True, "lead")
    assert held == "secret context https://x.corp.local" and ticket.status == ReviewStatus.APPROVED
    with pytest.raises(ReviewError):
        q.decide(t.review_id, True, "lead")


def test_review_denial_and_expiry_drop_text():
    q = ReviewQueue(ttl_seconds=60)
    denied = q.submit("a", [], [], None)
    _, held = q.decide(denied.review_id, False, "lead")
    assert held is None
    expiring = q.submit("b", [], [], None)
    expiring.expires_at = expiring.created_at - timedelta(seconds=1)
    assert q.get(expiring.review_id).status == ReviewStatus.EXPIRED
    with pytest.raises(ReviewError):
        q.decide(expiring.review_id, True, "lead")


def test_review_queue_full_fails_closed(tmp_path):
    from ciphermesh.agent import CipherMeshAgent
    agent = CipherMeshAgent("A", ":memory:", review_queue=ReviewQueue(max_pending=1))
    assert agent.inspect("https://a.corp.local").decision == Decision.REVIEW
    assert agent.inspect("https://b.corp.local").decision == Decision.BLOCK


def test_reviewer_identity_required():
    q = ReviewQueue()
    t = q.submit("x", [], [], None)
    with pytest.raises(ReviewError):
        q.decide(t.review_id, True, "  ")


# ----------------------------------------------------------------------- routing
def test_routing_respects_residency_and_verifies_optimum():
    profiles = list(DEFAULT_PROFILES)
    inspection = InspectionResult(decision=Decision.REDACT,
                                  findings=[Finding(category="aadhaar", start=0, end=12, confidence=0.9)])
    state = AgentState(agent_id="x", provider_allowlist=[p.provider_id for p in profiles])
    constraints, notes = derive_constraints(inspection, state, RouteConstraints())
    decision = route(profiles, constraints)
    gcp = next(e for e in decision.evaluations if e.provider_id == "gcp-vertex")
    assert not gcp.feasible and any("RESIDENCY" in r for r in gcp.reasons)
    assert decision.selected in {"aws-bedrock", "azure-ai", "local"}
    assert decision.verified and notes


def test_routing_require_local_and_allowlist():
    profiles = list(DEFAULT_PROFILES)
    c = RouteConstraints(require_local=True, allowlist=[p.provider_id for p in profiles])
    assert route(profiles, c).selected == "local"
    c2 = RouteConstraints(allowlist=["azure-ai"])
    assert route(profiles, c2).selected == "azure-ai"


def test_routing_no_feasible_route_transmits_nothing():
    c = RouteConstraints(max_cost_per_1k_usd=0.01, allowlist=[p.provider_id for p in DEFAULT_PROFILES])
    decision = route(list(DEFAULT_PROFILES), c)
    assert decision.status == "NO_FEASIBLE_ROUTE" and decision.selected is None


def test_route_weights_must_sum_to_one():
    with pytest.raises(ValueError):
        RouteWeights(quality=0.9)


def test_infeasible_hint_falls_back_to_utility_winner():
    profiles = list(DEFAULT_PROFILES)
    c = RouteConstraints(allowed_residency=["IN", "LOCAL"], allowlist=[p.provider_id for p in profiles])
    decision = route(profiles, c, provider_hint="gcp-vertex")
    assert decision.selected != "gcp-vertex" and "infeasible" in decision.notes[0]


# ----------------------------------------------------------------------- procurement
def test_every_provider_contract_lands_below_list_with_matching_digests():
    book = ContractBook()
    prices = book.ensure_all(list(DEFAULT_PROFILES))
    assert set(prices) == {p.provider_id for p in DEFAULT_PROFILES}
    for p in DEFAULT_PROFILES:
        assert prices[p.provider_id] < p.cost_per_1k_requests_usd
        result = book.result_for(p.provider_id)
        assert result.status.value == "AGREED" and result.contract_digest


def test_low_budget_keeps_list_price_and_reports_reason():
    book = ContractBook(budget_per_1k_usd=0.5)
    record = book.ensure(next(p for p in DEFAULT_PROFILES if p.provider_id == "azure-ai"))
    assert record.status in {"SKIPPED", "FAILED"} and record.price_per_1k_usd is None


# ----------------------------------------------------------------------- orchestrator
def test_block_never_reaches_any_adapter(orch):
    calls = []
    for pid in orch.registry.ids():
        adapter = orch.registry.get(pid)
        original = adapter.complete
        adapter.complete = lambda prompt, timeout_s=20.0, _o=original: calls.append(prompt) or _o(prompt, timeout_s)
    out = orch.process("deploy with AKIAIOSFODNN7EXAMPLE")
    assert out.status == ProcessStatus.BLOCKED and not calls


def test_redacted_payload_is_what_the_provider_sees(orch):
    seen = []
    for pid in orch.registry.ids():
        adapter = orch.registry.get(pid)
        original = adapter.complete
        adapter.complete = lambda prompt, timeout_s=20.0, _o=original: seen.append(prompt) or _o(prompt, timeout_s)
    out = orch.process("email rahul@example.com please")
    assert out.status == ProcessStatus.COMPLETED and seen
    assert all("rahul@example.com" not in p for p in seen)


def test_review_approval_routes_local_only_and_denial_sends_nothing(orch):
    pending = orch.process("summarise https://wiki.corp.local/sec")
    assert pending.status == ProcessStatus.PENDING_REVIEW
    approved = orch.decide_review(pending.review_id, True, "lead")
    assert approved.status == ProcessStatus.COMPLETED and approved.provider == "local"
    pending2 = orch.process("summarise https://wiki.corp.local/other")
    denied = orch.decide_review(pending2.review_id, False, "lead")
    assert denied.status == ProcessStatus.DENIED and denied.provider is None


def test_lockdown_after_queueing_blocks_approved_review(orch):
    pending = orch.process("see https://jira.corp.local/1")
    orch.agent.state.force_block_all = True
    out = orch.decide_review(pending.review_id, True, "lead")
    assert out.status == ProcessStatus.BLOCKED


def test_provider_failure_falls_back_and_opens_circuit(orch):
    first = orch.process("Explain recursion").provider
    orch.registry.get(first).fail_next(10)
    out = orch.process("Explain recursion again")
    assert out.status == ProcessStatus.COMPLETED and out.provider != first
    assert [a.ok for a in out.attempts] == [False, True]
    for _ in range(3):
        orch.process("Explain sorting")
    assert orch.registry.health.is_open(first) or orch.registry.health.snapshot()[first]["failures"] >= 3


def test_all_providers_failing_reports_provider_failed(orch):
    for pid in orch.registry.ids():
        orch.registry.get(pid).fail_next(10)
    out = orch.process("Explain heaps")
    assert out.status == ProcessStatus.PROVIDER_FAILED and out.response_text is None


def test_response_side_inspection_withholds_leaked_secret(orch):
    for pid in orch.registry.ids():
        orch.registry.get(pid).response_suffix = " Use key AKIAIOSFODNN7EXAMPLE to retry."
    out = orch.process("How do I authenticate?")
    assert out.status == ProcessStatus.RESPONSE_BLOCKED and out.response_text is None


def test_response_side_inspection_masks_pii(orch):
    for pid in orch.registry.ids():
        orch.registry.get(pid).response_suffix = " Contact help@example.com."
    out = orch.process("Who do I contact?")
    assert out.status == ProcessStatus.COMPLETED
    assert "help@example.com" not in out.response_text and out.response_decision == Decision.REDACT


def test_india_identifiers_never_routed_out_of_country(orch):
    out = orch.process("KYC for Aadhaar 2345 6789 0124")
    assert out.provider in {"aws-bedrock", "azure-ai", "local"}


def test_audit_contains_no_raw_prompt(tmp_path):
    o = build_default_orchestrator(audit_path=str(tmp_path / "a.db"))
    o.process("email secret.person@example.com")
    o.process("key AKIAIOSFODNN7EXAMPLE")
    dump = str(o.agent.audit.recent(100))
    assert "secret.person@example.com" not in dump and "AKIAIOSFODNN7EXAMPLE" not in dump


# ----------------------------------------------------------------------- health + runtime
def test_circuit_breaker_half_opens_after_cooldown():
    h = ProviderHealth(failure_threshold=2, cooldown_s=0.05)
    h.record_failure("p"); h.record_failure("p")
    assert h.is_open("p")
    time.sleep(0.06)
    assert not h.is_open("p")


def test_runtime_completes_all_work_and_shuts_down_cleanly():
    o = build_default_orchestrator(audit_path=":memory:", latency_scale=0.01)
    samples = []
    with ConcurrentRuntime(o, workers=4, queue_size=8, monitor_interval_s=0.05, on_sample=samples.append) as rt:
        futures = [rt.submit(f"text {i} user{i}@example.com") for i in range(20)]
        outcomes = [f.result(timeout=30) for f in futures]
    snap = rt.metrics.snapshot()
    assert snap["completed"] == 20 and snap["in_flight"] == 0
    assert all(o.status == ProcessStatus.COMPLETED for o in outcomes)
    assert samples[0]["status"] == "STARTING" and samples[-1]["status"] == "STOPPED"
    assert not any(t.name.startswith("cm-worker") for t in threading.enumerate())


def test_runtime_backpressure_rejects_when_queue_full():
    import queue as q
    o = build_default_orchestrator(audit_path=":memory:", latency_scale=0.5)
    rt = ConcurrentRuntime(o, workers=1, queue_size=1, monitor_interval_s=1, probe_providers=False).start()
    try:
        rt.submit("a"); rt.submit("b")
        with pytest.raises(q.Full):
            for _ in range(3):
                rt.submit("c", timeout=0.01)
        assert rt.metrics.snapshot()["rejected_full"] >= 1
    finally:
        rt.close()


def test_runtime_rejects_submit_after_close():
    rt = ConcurrentRuntime(build_default_orchestrator(audit_path=":memory:"), workers=1).start()
    rt.close()
    with pytest.raises(RuntimeError):
        rt.submit("x")


def test_monitor_probe_marks_unhealthy_provider():
    o = build_default_orchestrator(audit_path=":memory:")
    adapter = o.registry.get("local")
    def broken(timeout_s=2.0):
        raise ProviderUnavailable("down")
    adapter.health_check = broken
    rt = ConcurrentRuntime(o, workers=1, monitor_interval_s=0.02).start()
    time.sleep(0.15)
    rt.close()
    assert o.registry.health.snapshot()["local"]["failures"] >= 3
