"""Load, validate and compile the CipherMesh ontology (ontology.json) into a KnowledgeGraph.

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

Validation happens in two layers:
1. Structural - JSON Schema (draft 2020-12) in ``ontology.schema.json``.
2. Semantic   - checks a schema cannot express: every referenced IRI is defined,
   no subclass cycles, object-property values respect rdfs:range, and every
   functional property has at most one value per subject.

JSON-LD 1.1 term definitions in ``@context`` decide how a plain JSON value is read:
a term declared with ``"@type": "@id"`` turns strings into IRIs, a term declared
with an ``xsd:`` type turns values into typed literals (type coercion).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .graph import FUNCTIONAL, LABEL, RDF_TYPE, KnowledgeGraph, Literal, Provenance

HERE = Path(__file__).resolve().parent
ONTOLOGY_PATH = HERE / "ontology.json"
SCHEMA_PATH = HERE / "ontology.schema.json"
BUILTIN_PREFIXES = ("rdf:", "rdfs:", "owl:", "xsd:", "dcterms:")


class OntologyError(ValueError):
    """Raised when the ontology document fails structural or semantic validation."""


def load_document(path: str | Path = ONTOLOGY_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def schema_errors(doc: dict, schema_path: str | Path = SCHEMA_PATH) -> list[str]:
    import jsonschema  # imported lazily so the runtime path does not depend on it

    with open(schema_path, "r", encoding="utf-8") as fh:
        schema = json.load(fh)
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    return [f"{'/'.join(str(x) for x in e.absolute_path) or '<root>'}: {e.message}"
            for e in sorted(validator.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))]


def _coerce(term: str, raw: Any, ctx: dict) -> Any:
    """Apply JSON-LD type coercion for one value."""
    if isinstance(raw, dict):
        if "@id" in raw:
            return raw["@id"]
        return Literal(raw["@value"], raw.get("@type", "xsd:string"))
    definition = ctx.get(term)
    if isinstance(definition, dict):
        kind = definition.get("@type")
        if kind == "@id":
            return raw
        if kind:
            return Literal(_cast(raw, kind), kind)
    if isinstance(raw, bool):
        return Literal(raw, "xsd:boolean")
    if isinstance(raw, int):
        return Literal(raw, "xsd:integer")
    if isinstance(raw, float):
        return Literal(raw, "xsd:decimal")
    return Literal(raw, "xsd:string")


def _cast(raw: Any, datatype: str) -> Any:
    if datatype == "xsd:decimal":
        return float(raw)
    if datatype == "xsd:integer":
        if isinstance(raw, bool) or float(raw) != int(raw):
            raise OntologyError(f"value {raw!r} is not an xsd:integer")
        return int(raw)
    if datatype == "xsd:boolean":
        if not isinstance(raw, bool):
            raise OntologyError(f"value {raw!r} is not an xsd:boolean")
        return raw
    return raw


def _predicate(term: str, ctx: dict) -> str:
    if term in ("label",):
        return LABEL
    if term == "comment":
        return "rdfs:comment"
    definition = ctx.get(term)
    if isinstance(definition, dict):
        return definition["@id"]
    if isinstance(definition, str) and ":" in definition:
        return definition
    return term


def compile_graph(doc: dict, source: str = "ontology.json") -> KnowledgeGraph:
    """Turn the JSON-LD document into triples (no validation here; see :func:`load_graph`)."""
    ctx = doc["@context"]
    stamp = doc.get("dcterms:modified", "1970-01-01") + "T00:00:00+00:00"
    prov = Provenance(source=source, fetched_at=stamp, confidence=1.0, method="asserted")
    graph = KnowledgeGraph()
    graph.version = str(doc.get("owl:versionInfo", "unversioned"))
    for node in doc["@graph"]:
        sid = node["@id"]
        types = node["@type"] if isinstance(node["@type"], list) else [node["@type"]]
        for t in types:
            graph.add(sid, RDF_TYPE, t, prov)
        for term, raw in node.items():
            if term.startswith("@"):
                continue
            pred = _predicate(term, ctx)
            for item in (raw if isinstance(raw, list) else [raw]):
                graph.add(sid, pred, _coerce(term, item, ctx), prov)
    graph.functional = set(graph.subjects(RDF_TYPE, FUNCTIONAL))
    return graph


def semantic_errors(graph: KnowledgeGraph) -> list[str]:
    errors: list[str] = []
    defined = {t.s for t in graph.triples(p=RDF_TYPE)}
    object_props = set(graph.subjects(RDF_TYPE, "owl:ObjectProperty"))
    data_props = set(graph.subjects(RDF_TYPE, "owl:DatatypeProperty"))
    for t in graph.triples():
        for term in (t.p, t.o):
            if isinstance(term, str) and term.startswith("cm:") and term not in defined:
                errors.append(f"undefined IRI {term} used in ({t.s}, {t.p})")
        if t.p.startswith("cm:") and t.p not in object_props | data_props:
            errors.append(f"predicate {t.p} is not declared as an object or datatype property")
    for cls in graph.subjects(RDF_TYPE, "owl:Class"):
        seen, stack = set(), list(graph.objects(cls, "rdfs:subClassOf"))
        while stack:
            parent = stack.pop()
            if parent == cls:
                errors.append(f"subclass cycle through {cls}")
                break
            if parent not in seen:
                seen.add(parent)
                stack.extend(graph.objects(parent, "rdfs:subClassOf"))
    for prop in sorted(object_props):
        rng = graph.value(prop, "rdfs:range")
        for t in graph.triples(p=prop):
            if isinstance(t.o, Literal):
                errors.append(f"{prop} on {t.s} must reference an IRI, got literal {t.o.value!r}")
            elif rng and not graph.is_instance(t.o, rng):
                errors.append(f"{prop} on {t.s}: {t.o} is not a {rng}")
    for prop in sorted(data_props):
        for t in graph.triples(p=prop):
            if not isinstance(t.o, Literal):
                errors.append(f"{prop} on {t.s} must be a literal")
    for prop in graph.functional:
        counts: dict[str, int] = {}
        for t in graph.triples(p=prop):
            counts[t.s] = counts.get(t.s, 0) + 1
        errors += [f"functional property {prop} has {n} values on {s}" for s, n in counts.items() if n > 1]
    return sorted(set(errors))


def load_graph(path: str | Path = ONTOLOGY_PATH, infer: bool = True) -> KnowledgeGraph:
    """Validate ontology.json (schema + semantics) and return the compiled, inferred graph."""
    doc = load_document(path)
    errs = schema_errors(doc)
    if errs:
        raise OntologyError("schema validation failed: " + "; ".join(errs[:5]))
    graph = compile_graph(doc, source=Path(path).name)
    errs = semantic_errors(graph)
    if errs:
        raise OntologyError("semantic validation failed: " + "; ".join(errs[:5]))
    if infer:
        graph.infer()
    return graph


def summary(graph: KnowledgeGraph) -> dict[str, Any]:
    count = lambda cls: len(graph.instances_of(cls))  # noqa: E731
    return {"version": graph.version, **graph.stats(),
            "providers": count("cm:Provider"), "regions": count("cm:CloudRegion"),
            "jurisdictions": count("cm:Jurisdiction"), "data_categories": count("cm:DataCategory"),
            "detector_families": count("cm:DetectorFamily"), "legal_instruments": count("cm:LegalInstrument"),
            "policy_rules": count("cm:PolicyRule"), "threat_classes": count("cm:Threat"),
            "live_sources": count("cm:InformationSource"), "watched_vendors": count("cm:Vendor")}
