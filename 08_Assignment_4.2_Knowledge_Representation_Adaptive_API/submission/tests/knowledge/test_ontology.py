"""Ontology file: schema validation, semantic validation, and agreement with the engine.

Author: Kumar Waibhav Akshat (RA2212704010027)
"""
import copy

import pytest

from ciphermesh.detector import PATTERNS, POLICY_RULE
from ciphermesh.knowledge.ontology import (OntologyError, compile_graph, load_document, load_graph,
                                           schema_errors, semantic_errors, summary)
from ciphermesh.providers import DEFAULT_PROFILES


def test_ontology_document_passes_json_schema():
    assert schema_errors(load_document()) == []


def test_compiled_graph_has_no_semantic_errors():
    assert semantic_errors(compile_graph(load_document())) == []


def test_summary_counts_match_design():
    s = summary(load_graph())
    assert s["version"] == "4.2.0"
    assert (s["providers"], s["regions"], s["jurisdictions"]) == (4, 4, 4)
    assert (s["data_categories"], s["detector_families"], s["policy_rules"]) == (25, 12, 6)
    assert s["live_sources"] == 6 and s["by_inferred"] > 0


@pytest.mark.parametrize("mutate, fragment", [
    (lambda d: d.pop("owl:versionInfo"), "owl:versionInfo"),
    (lambda d: d.update({"owl:versionInfo": "v4"}), "does not match"),
    (lambda d: d["@graph"][0].update({"@id": "bad id with spaces"}), "does not match"),
    (lambda d: d["@graph"][0].pop("label"), "label"),
    (lambda d: d["@context"].update({"cm": "http://wrong/"}), "does not match"),
    (lambda d: d["@graph"].append({"@id": "cm:x", "@type": "cm:Provider", "costPer1kUsd": [{"bad": 1}]}),
     "is not valid"),
])
def test_schema_rejects_invalid_documents(mutate, fragment):
    doc = copy.deepcopy(load_document())
    mutate(doc)
    errors = schema_errors(doc)
    assert errors and any(fragment in e for e in errors)


def test_semantic_validation_catches_undefined_iri_and_range_violation():
    doc = copy.deepcopy(load_document())
    node = next(n for n in doc["@graph"] if n["@id"] == "cm:provider/aws-bedrock")
    node["hostedIn"] = "cm:region/does-not-exist"
    errs = semantic_errors(compile_graph(doc))
    assert any("undefined IRI cm:region/does-not-exist" in e for e in errs)
    doc2 = copy.deepcopy(load_document())
    node = next(n for n in doc2["@graph"] if n["@id"] == "cm:provider/azure-ai")
    node["hostedIn"] = "cm:jur/IN"                         # a Jurisdiction is not a CloudRegion
    assert any("is not a cm:CloudRegion" in e for e in semantic_errors(compile_graph(doc2)))


def test_semantic_validation_catches_functional_violation_and_cycles():
    doc = copy.deepcopy(load_document())
    node = next(n for n in doc["@graph"] if n["@id"] == "cm:provider/gcp-vertex")
    node["hostedIn"] = ["cm:region/us-central1", "cm:region/ap-south-1"]
    assert any("functional property cm:hostedIn" in e for e in semantic_errors(compile_graph(doc)))
    doc2 = copy.deepcopy(load_document())
    root = next(n for n in doc2["@graph"] if n["@id"] == "cm:Resource")
    root["subClassOf"] = "cm:Provider"
    assert any("subclass cycle" in e for e in semantic_errors(compile_graph(doc2)))


def test_load_graph_raises_on_invalid_file(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"@id": "cm:ontology"}', encoding="utf-8")
    with pytest.raises(OntologyError):
        load_graph(bad)


def test_all_25_detector_categories_are_mapped_with_family_severity_and_rule(graph):
    by_label = {graph.value(n, "rdfs:label"): n for n in graph.instances_of("cm:DataCategory")}
    assert set(by_label) == {name for name, *_ in PATTERNS}
    for name, _pattern, _conf, rule, severity, _v in PATTERNS:
        node = by_label[name]
        assert graph.value(graph.value(node, "cm:memberOf"), "cm:detectorRule") == rule
        assert graph.value(node, "cm:severity") == severity
        assert graph.value(graph.value(node, "cm:triggersRule"), "cm:ruleCode") == POLICY_RULE[name]


def test_provider_individuals_match_engine_profiles(graph):
    nodes = graph.providers()
    assert set(nodes) == {p.provider_id for p in DEFAULT_PROFILES}
    for p in DEFAULT_PROFILES:
        n = nodes[p.provider_id]
        region = graph.value(n, "cm:hostedIn")
        assert graph.value(region, "cm:regionCode") == p.region
        assert graph.provider_jurisdiction(n) == p.data_residency
        assert graph.value(n, "cm:kind") == p.kind
        assert graph.value(n, "cm:costPer1kUsd") == p.cost_per_1k_requests_usd
        assert graph.value(n, "cm:p95LatencyMs") == p.p95_latency_ms
        assert graph.value(n, "cm:qualityScore") == p.quality_score
        assert graph.value(n, "cm:availabilityPct") == p.availability_pct


def test_rule_priority_order_matches_strictest_wins(graph):
    order = sorted(graph.instances_of("cm:PolicyRule"), key=lambda r: graph.value(r, "cm:priority"))
    assert [graph.value(r, "cm:ruleCode") for r in order] == ["LOCKDOWN", "R5", "R1", "R3", "R2", "R4"]
    assert graph.value(graph.value("cm:rule/R3", "cm:yieldsDecision"), "rdfs:label") == "REVIEW"
