"""Plan library: option generation from the real router, contexts, bindings and step metadata.

Author: Kumar Waibhav Akshat (RA2212704010027)
"""
from ciphermesh.bdi.plans import Verdict, ciphermesh_plans
from ciphermesh.bdi.world import pkey

from .conftest import AADHAAR, REVIEW, SECRET


def test_library_has_required_plans_and_unique_ids(make_agent):
    lib = make_agent().library
    ids = [p.id for p in lib.plans()]
    for required in ("block_and_advise_rotation", "hold_for_review", "redact_then_dispatch",
                     "allow_then_dispatch", "dispatch_local_only", "withhold_reply_and_alert"):
        assert required in ids
    assert len(ids) == len(set(ids))
    assert {p.achieves for p in ciphermesh_plans()} == {"D1", "D3", "D5"}


def test_clean_prompt_options_follow_router_utility(make_agent):
    agent = make_agent()
    opts = agent.library.options_for(agent.desires.get("D3"), agent.beliefs)
    assert [o.label() for o in opts] == ["allow_then_dispatch(provider=gcp-vertex)",
                                         "allow_then_dispatch(provider=aws-bedrock)",
                                         "allow_then_dispatch(provider=azure-ai)",
                                         "dispatch_local_only(provider=local)"]
    assert [o.utility for o in opts] == sorted((o.utility for o in opts), reverse=True)
    assert opts[0].utility == 77.9333


def test_aadhaar_prompt_only_in_or_local_redacting_plans(make_agent):
    agent = make_agent(AADHAAR)
    opts = agent.library.options_for(agent.desires.get("D3"), agent.beliefs)
    assert [o.label() for o in opts] == ["redact_then_dispatch(provider=aws-bedrock)",
                                         "redact_then_dispatch(provider=azure-ai)",
                                         "dispatch_local_only(provider=local)"]
    for o in opts:
        assert agent.beliefs.get(pkey(o.params["provider"], "residency")) in {"IN", "LOCAL"}


def test_secret_prompt_has_no_dispatch_option_and_d1_block_plan(make_agent):
    agent = make_agent(SECRET)
    assert agent.library.options_for(agent.desires.get("D3"), agent.beliefs) == []
    d1 = agent.library.options_for(agent.desires.get("D1"), agent.beliefs)
    assert [o.label() for o in d1] == ["block_and_advise_rotation"]


def test_review_prompt_uses_hold_for_review_until_backlog_full(make_agent):
    agent = make_agent(REVIEW)
    d3 = agent.desires.get("D3")
    assert [o.label() for o in agent.library.options_for(d3, agent.beliefs)] == ["hold_for_review"]
    agent.beliefs.set("review.queue_depth", 25, "test")
    assert agent.library.options_for(d3, agent.beliefs) == []
    assert [o.label() for o in agent.library.options_for(agent.desires.get("D5"), agent.beliefs)] == \
        ["decline_review_overflow"]


def test_budget_belief_filters_bindings(make_agent):
    agent = make_agent()
    agent.beliefs.set("budget.max_cost_per_1k", 2.0, "finance")
    opts = agent.library.options_for(agent.desires.get("D3"), agent.beliefs)
    assert {o.params["provider"] for o in opts} == {"gcp-vertex", "local"}


def test_outage_belief_removes_provider(make_agent):
    agent = make_agent()
    agent.beliefs.set(pkey("gcp-vertex", "status"), "major_outage", "feed")
    labels = [o.label() for o in agent.library.options_for(agent.desires.get("D3"), agent.beliefs)]
    assert "allow_then_dispatch(provider=gcp-vertex)" not in labels
    assert labels[0] == "allow_then_dispatch(provider=aws-bedrock)"


def test_context_is_three_valued(make_agent):
    agent = make_agent()
    plan = agent.library.get("allow_then_dispatch")
    params = {"provider": "gcp-vertex"}
    assert plan.context(agent.beliefs, params)
    agent.beliefs.set(pkey("gcp-vertex", "status"), "partial_outage", "feed")
    verdicts = dict((c.describe(params), v) for c, v in plan.check(agent.beliefs, params))
    assert verdicts["provider gcp-vertex is usable"] == Verdict.UNCERTAIN and not plan.context(agent.beliefs, params)
    agent.beliefs.set(pkey("gcp-vertex", "status"), "major_outage", "feed")
    assert "provider gcp-vertex is usable: VIOLATED" in plan.violations(agent.beliefs, params)


def test_step_relevant_beliefs_are_bound_to_parameters(make_agent):
    plan = make_agent().library.get("allow_then_dispatch")
    dispatch = next(s for s in plan.steps if s.name == "dispatch")
    keys = dispatch.relevant_for({"provider": "aws-bedrock"})
    assert {"provider.aws-bedrock.status", "provider.aws-bedrock.residency", "policy.lockdown"} <= keys
    assert dispatch.transmits and not any(s.transmits for s in plan.steps if s.name != "dispatch")


def test_rejected_for_explains_failed_contexts(make_agent):
    agent = make_agent(SECRET)
    rejected = dict(agent.library.rejected_for(agent.desires.get("D3"), agent.beliefs))
    assert rejected["allow_then_dispatch"] == ["no feasible binding from router"]
