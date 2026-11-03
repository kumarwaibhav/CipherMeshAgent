"""CipherMesh knowledge subsystem (Assignment 4.2: Knowledge Representation and Adaptive API Integration).

Author: Kumar Waibhav Akshat (RA2212704010027)

* ``ontology.json`` / ``ontology.schema.json`` - formal domain knowledge (JSON-LD 1.1 style) + JSON Schema
* ``graph``        - triple store with provenance, pattern queries, inference and export
* ``feeds``        - live REST/RSS connectors with snapshot fallback
* ``adapter``      - live facts -> triples -> agent properties (observed + derived)
* ``properties``   - ``PropertySink`` protocol and the observable ``AgentProperties``
* ``adaptive_agent`` - agent wrapper that re-plans whenever a property changes
"""
from .adapter import AdaptationEvent, KnowledgeAdapter
from .adaptive_agent import AdaptiveCipherMeshAgent, Plan, PlanContext
from .graph import KnowledgeGraph, Literal, Provenance, ResidencyDerivation
from .ontology import OntologyError, load_graph, summary
from .properties import AgentProperties, PropertyChange, PropertySink

__all__ = ["AdaptationEvent", "AdaptiveCipherMeshAgent", "AgentProperties", "KnowledgeAdapter", "KnowledgeGraph",
           "Literal", "OntologyError", "Plan", "PlanContext", "PropertyChange", "PropertySink", "Provenance",
           "ResidencyDerivation", "load_graph", "summary"]
