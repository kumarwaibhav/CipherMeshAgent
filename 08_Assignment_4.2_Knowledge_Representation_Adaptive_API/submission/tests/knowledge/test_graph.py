"""Triple store: provenance, queries, inference, residency derivation equivalence, export.

Author: Kumar Waibhav Akshat (RA2212704010027)
"""
from itertools import combinations

import pytest

from ciphermesh.detector import PATTERNS
from ciphermesh.knowledge.graph import KnowledgeGraph, Literal, Provenance
from ciphermesh.models import AgentState, Decision, Finding, InspectionResult
from ciphermesh.providers import DEFAULT_PROFILES
from ciphermesh.routing import INDIA_PERSONAL_DATA, RouteConstraints, derive_constraints

CATEGORIES = [name for name, *_ in PATTERNS]


def test_add_remove_with_provenance_and_indexes():
    g = KnowledgeGraph()
    p = Provenance(source="cm:feed/test", fetched_at="2026-10-30T10:00:00+00:00", confidence=0.7, method="live")
    assert g.add("cm:a", "cm:rel", "cm:b", p) is True
    assert g.add("cm:a", "cm:rel", "cm:b", p) is False
    assert g.provenance("cm:a", "cm:rel", "cm:b").confidence == 0.7
    assert [t.o for t in g.triples(s="cm:a")] == ["cm:b"]
    assert [t.s for t in g.triples(o="cm:b")] == ["cm:a"]
    assert [t.s for t in g.triples(p="cm:rel", o="cm:b")] == ["cm:a"]
    assert g.remove("cm:a", "cm:rel", "cm:b") is True and len(g) == 0
    assert g.remove("cm:a", "cm:rel", "cm:b") is False
    assert [h["op"] for h in g.history] == ["add", "remove"]


def test_provenance_rejects_bad_confidence():
    with pytest.raises(ValueError):
        Provenance(confidence=1.5)


def test_fresher_evidence_replaces_provenance_of_same_fact():
    g = KnowledgeGraph()
    g.add("cm:a", "cm:p", Literal(1, "xsd:integer"), Provenance(fetched_at="2026-01-01T00:00:00+00:00"))
    newer = Provenance(source="live", fetched_at="2026-10-30T00:00:00+00:00", method="live")
    g.add("cm:a", "cm:p", Literal(1, "xsd:integer"), newer)
    assert g.provenance("cm:a", "cm:p", Literal(1, "xsd:integer")).source == "live"


def test_set_value_is_functional_replacement(graph):
    node = "cm:provider/gcp-vertex"
    removed = graph.set_value(node, "cm:hasStatus", "cm:status/outage",
                              Provenance(source="cm:feed/gcp-status", method="live"))
    assert removed == ["cm:status/operational"]
    assert graph.objects(node, "cm:hasStatus") == ["cm:status/outage"]


def test_conjunctive_query_finds_in_country_providers(graph):
    rows = graph.query([("?p", "cm:hostedIn", "?r"), ("?r", "cm:locatedIn", "cm:jur/IN"),
                        ("?p", "cm:providerId", "?id")])
    assert sorted(str(r["?id"]) for r in rows) == ["aws-bedrock", "azure-ai"]


def test_subclass_transitivity_and_type_propagation(graph):
    assert graph.superclasses("cm:ResidencyPolicy") == {"cm:OrganisationalPolicy", "cm:LegalInstrument",
                                                        "cm:Resource"}
    assert ("cm:policy/india-residency", "rdf:type", "cm:LegalInstrument") in graph
    prov = graph.provenance("cm:policy/india-residency", "rdf:type", "cm:LegalInstrument")
    assert prov.method == "inferred" and prov.source == "inference:rdfs9"
    assert "cm:provider/local" in graph.instances_of("cm:Provider")
    assert graph.infer() == 0                       # idempotent
    removed = graph.clear_inferred()
    assert removed > 0 and ("cm:policy/india-residency", "rdf:type", "cm:LegalInstrument") not in graph
    assert graph.is_instance("cm:policy/india-residency", "cm:LegalInstrument")   # still answerable by closure


def test_residency_restricted_categories_equal_engine_rule(graph):
    assert graph.residency_restricted_categories() == INDIA_PERSONAL_DATA


def _engine_residency(categories):
    findings = [Finding(category=c, start=0, end=1, confidence=1.0) for c in categories]
    insp = InspectionResult(decision=Decision.REDACT, findings=findings)
    c, _ = derive_constraints(insp, AgentState(agent_id="t"), RouteConstraints())
    return sorted(c.allowed_residency)


def test_graph_derived_constraints_equal_engine_for_every_single_and_pair(graph):
    base = RouteConstraints().allowed_residency
    cases = [[c] for c in CATEGORIES] + [list(p) for p in combinations(CATEGORIES, 2)]
    for cats in cases:
        d = graph.derive_residency(cats)
        derived = sorted(base if d.allowed_jurisdictions is None
                         else [r for r in base if r in d.allowed_jurisdictions])
        assert derived == _engine_residency(cats), cats


def test_residency_derivation_explains_chain_and_providers(graph):
    d = graph.derive_residency(["email", "aadhaar"])
    assert d.restricted_categories == ["aadhaar"] and d.allowed_jurisdictions == ["IN", "LOCAL"]
    assert d.allowed_providers == ["aws-bedrock", "azure-ai", "local"]
    assert "via family cm:family/D10" in d.chain[0]
    assert graph.derive_residency(["email"]).allowed_providers == sorted(p.provider_id for p in DEFAULT_PROFILES)


def test_json_roundtrip_preserves_triples_and_provenance(graph):
    data = graph.to_json()
    g2 = KnowledgeGraph.from_json(data)
    assert len(g2) == len(graph)
    t = ("cm:provider/aws-bedrock", "cm:costPer1kUsd", Literal(2.8, "xsd:decimal"))
    assert t in g2 and g2.provenance(*t).source == "ontology.json"


def test_jsonld_and_svg_export(graph):
    nodes = graph.to_jsonld_nodes(["cm:provider/local"])
    assert nodes[0]["@id"] == "cm:provider/local" and nodes[0]["cm:hostedIn"] == {"@id": "cm:region/on-host"}
    svg = graph.to_svg()
    assert svg.startswith("<svg") and svg.count("<rect") >= 17 and "aws-bedrock" in svg and "</svg>" in svg
