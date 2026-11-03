"""In-memory knowledge graph (triple store) for the CipherMesh agent.

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

What it does
------------
* Stores (subject, predicate, object) triples. Subjects and predicates are compact
  IRIs (CURIEs) such as ``cm:provider/aws-bedrock``; objects are either CURIEs or
  typed :class:`Literal` values.
* Every triple carries :class:`Provenance` - where it came from, when it was
  observed, how confident we are, and whether it was asserted, ingested from a live
  feed, or inferred.
* Three hash indexes (SPO, POS, OSP) make any single-pattern query a dictionary
  lookup instead of a scan.
* Inference: rdfs:subClassOf transitivity, type propagation to super-classes
  (RDFS entailment rules rdfs9/rdfs11), and a residency derivation that walks
  category -> family -> legal instrument -> required jurisdictions -> providers.
* Export: provenance-preserving JSON, a JSON-LD node list, and an SVG figure of the
  provider / region / jurisdiction / status sub-graph.
"""
from __future__ import annotations

import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html import escape
from typing import Any, Iterable, Iterator

RDF_TYPE = "rdf:type"
SUBCLASS = "rdfs:subClassOf"
LABEL = "rdfs:label"
FUNCTIONAL = "owl:FunctionalProperty"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class Literal:
    """A typed literal value (xsd:string, xsd:decimal, xsd:integer, xsd:boolean, ...)."""
    value: Any
    datatype: str = "xsd:string"

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True)
class Provenance:
    source: str = "ontology.json"
    fetched_at: str = field(default_factory=_now_iso)
    confidence: float = 1.0
    method: str = "asserted"          # asserted | live | inferred | derived
    evidence: str = ""

    def __post_init__(self):
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be within [0, 1]")


@dataclass(frozen=True)
class Triple:
    s: str
    p: str
    o: Any  # str (CURIE) or Literal


@dataclass
class ResidencyDerivation:
    """Result of residency inference for a set of detector categories."""
    categories: list[str]
    restricted_categories: list[str]
    policies: list[str]
    allowed_jurisdictions: list[str] | None   # None = no residency limit
    allowed_providers: list[str]
    chain: list[str]


class KnowledgeGraph:
    """Thread-safe triple store with provenance, pattern queries, inference and export."""

    def __init__(self, functional_predicates: Iterable[str] = ()):
        self._lock = threading.RLock()
        self._prov: dict[Triple, Provenance] = {}
        self._spo: dict[str, dict[str, set]] = {}
        self._pos: dict[str, dict[Any, set]] = {}
        self._osp: dict[Any, dict[str, set]] = {}
        self.functional: set[str] = set(functional_predicates)
        self.history: list[dict] = []          # add/remove/replace log for live triples
        self.version = "unversioned"

    # ------------------------------------------------------------------ core store
    def __len__(self) -> int:
        return len(self._prov)

    def __contains__(self, t) -> bool:
        return Triple(*t) in self._prov if not isinstance(t, Triple) else t in self._prov

    def add(self, s: str, p: str, o: Any, prov: Provenance | None = None) -> bool:
        """Add a triple. Returns False if it already existed (provenance is refreshed if newer)."""
        t = Triple(s, p, o)
        prov = prov or Provenance()
        with self._lock:
            if t in self._prov:
                old = self._prov[t]
                if prov.method != "inferred" and (old.method == "inferred" or prov.fetched_at >= old.fetched_at):
                    self._prov[t] = prov   # keep the freshest evidence for the same fact
                return False
            self._prov[t] = prov
            self._spo.setdefault(s, {}).setdefault(p, set()).add(o)
            self._pos.setdefault(p, {}).setdefault(o, set()).add(s)
            self._osp.setdefault(o, {}).setdefault(s, set()).add(p)
            if prov.method in ("live", "derived"):
                self.history.append({"op": "add", "s": s, "p": p, "o": _term_json(o), "source": prov.source,
                                     "at": prov.fetched_at, "confidence": prov.confidence})
            return True

    def remove(self, s: str, p: str, o: Any) -> bool:
        t = Triple(s, p, o)
        with self._lock:
            prov = self._prov.pop(t, None)
            if prov is None:
                return False
            self._spo[s][p].discard(o)
            self._pos[p][o].discard(s)
            self._osp[o][s].discard(p)
            for idx, a, b in ((self._spo, s, p), (self._pos, p, o), (self._osp, o, s)):
                if not idx[a][b]:
                    del idx[a][b]
                if not idx[a]:
                    del idx[a]
            self.history.append({"op": "remove", "s": s, "p": p, "o": _term_json(o), "source": prov.source,
                                 "at": _now_iso(), "confidence": prov.confidence})
            return True

    def set_value(self, s: str, p: str, o: Any, prov: Provenance | None = None) -> list[Any]:
        """Functional update: replace every existing object of (s, p) with o. Returns removed objects."""
        with self._lock:
            removed = [x for x in list(self.objects(s, p)) if x != o]
            for x in removed:
                self.remove(s, p, x)
            self.add(s, p, o, prov)
            return removed

    def provenance(self, s: str, p: str, o: Any) -> Provenance | None:
        return self._prov.get(Triple(s, p, o))

    # ------------------------------------------------------------------ queries
    def triples(self, s: str | None = None, p: str | None = None, o: Any = None) -> Iterator[Triple]:
        """Pattern query; None is a wildcard. Uses the most selective index."""
        with self._lock:
            if s is not None:
                preds = self._spo.get(s, {})
                for pp in ([p] if p is not None else list(preds)):
                    for oo in list(preds.get(pp, ())):
                        if o is None or oo == o:
                            yield Triple(s, pp, oo)
            elif p is not None:
                objs = self._pos.get(p, {})
                for oo in ([o] if o is not None else list(objs)):
                    for ss in list(objs.get(oo, ())):
                        yield Triple(ss, p, oo)
            elif o is not None:
                for ss, preds in list(self._osp.get(o, {}).items()):
                    for pp in list(preds):
                        yield Triple(ss, pp, o)
            else:
                yield from list(self._prov)

    def objects(self, s: str, p: str) -> list[Any]:
        with self._lock:
            return sorted(self._spo.get(s, {}).get(p, ()), key=_sort_key)

    def subjects(self, p: str, o: Any) -> list[str]:
        with self._lock:
            return sorted(self._pos.get(p, {}).get(o, ()))

    def value(self, s: str, p: str, default: Any = None) -> Any:
        """First object of (s, p); literals are unwrapped to their Python value."""
        objs = self.objects(s, p)
        if not objs:
            return default
        o = objs[0]
        return o.value if isinstance(o, Literal) else o

    def values(self, s: str, p: str) -> list[Any]:
        return [o.value if isinstance(o, Literal) else o for o in self.objects(s, p)]

    def label(self, s: str) -> str:
        return str(self.value(s, LABEL, s))

    def query(self, patterns: list[tuple]) -> list[dict[str, Any]]:
        """Conjunctive query over triple patterns; strings starting with '?' are variables.

        Example: [("?p", "cm:hostedIn", "?r"), ("?r", "cm:locatedIn", "cm:jur/IN")]
        """
        results: list[dict[str, Any]] = [{}]
        for pat in patterns:
            nxt: list[dict[str, Any]] = []
            for binding in results:
                bound = [binding.get(x, x) if isinstance(x, str) and x.startswith("?") else x for x in pat]
                q = [None if isinstance(x, str) and x.startswith("?") else x for x in bound]
                for t in self.triples(*q):
                    b = dict(binding)
                    ok = True
                    for var, val in zip(bound, (t.s, t.p, t.o)):
                        if isinstance(var, str) and var.startswith("?"):
                            if var in b and b[var] != val:
                                ok = False
                                break
                            b[var] = val
                    if ok:
                        nxt.append(b)
            results = nxt
        return results

    # ------------------------------------------------------------------ inference
    def superclasses(self, cls: str) -> set[str]:
        """Transitive closure of rdfs:subClassOf (excluding cls itself); cycle-safe."""
        seen: set[str] = set()
        stack = [cls]
        while stack:
            for parent in self.objects(stack.pop(), SUBCLASS):
                if parent not in seen and parent != cls:
                    seen.add(parent)
                    stack.append(parent)
        return seen

    def subclasses(self, cls: str) -> set[str]:
        seen: set[str] = set()
        stack = [cls]
        while stack:
            for child in self.subjects(SUBCLASS, stack.pop()):
                if child not in seen and child != cls:
                    seen.add(child)
                    stack.append(child)
        return seen

    def types_of(self, s: str) -> set[str]:
        direct = set(self.objects(s, RDF_TYPE))
        out = set(direct)
        for t in direct:
            out |= self.superclasses(t)
        return out

    def is_instance(self, s: str, cls: str) -> bool:
        return cls in self.types_of(s)

    def instances_of(self, cls: str) -> list[str]:
        classes = {cls} | self.subclasses(cls)
        out: set[str] = set()
        for c in classes:
            out.update(self.subjects(RDF_TYPE, c))
        return sorted(out)

    def infer(self) -> int:
        """Materialise RDFS subclass transitivity (rdfs11) and type propagation (rdfs9). Idempotent."""
        added = 0
        when = _now_iso()
        classes = {t.s for t in self.triples(p=SUBCLASS)} | {t.o for t in self.triples(p=SUBCLASS)}
        for c in sorted(classes):
            for sup in sorted(self.superclasses(c)):
                if Triple(c, SUBCLASS, sup) not in self._prov:
                    added += self.add(c, SUBCLASS, sup, Provenance(source="inference:rdfs11", fetched_at=when,
                                                                   method="inferred"))
        for t in list(self.triples(p=RDF_TYPE)):
            if not isinstance(t.o, str) or t.o.startswith("owl:"):
                continue
            for sup in sorted(self.superclasses(t.o)):
                if Triple(t.s, RDF_TYPE, sup) not in self._prov:
                    added += self.add(t.s, RDF_TYPE, sup, Provenance(source="inference:rdfs9", fetched_at=when,
                                                                     method="inferred"))
        return added

    def clear_inferred(self) -> int:
        doomed = [t for t, pv in self._prov.items() if pv.method == "inferred"]
        for t in doomed:
            self.remove(t.s, t.p, t.o)
        return len(doomed)

    # ------------------------------------------------------------------ domain inference
    def category_id(self, name: str) -> str:
        return name if name.startswith("cm:") else f"cm:cat/{name}"

    def provider_jurisdiction(self, provider: str) -> str | None:
        region = self.value(provider, "cm:hostedIn")
        jur = self.value(region, "cm:locatedIn") if region else None
        return self.value(jur, "cm:jurisdictionCode") if jur else None

    def providers(self) -> dict[str, str]:
        """provider_id -> provider node."""
        return {str(self.value(n, "cm:providerId")): n for n in self.instances_of("cm:Provider")
                if self.value(n, "cm:providerId")}

    def derive_residency(self, categories: Iterable[str]) -> ResidencyDerivation:
        """category -> (family) -> governing policy -> required jurisdictions -> allowed providers.

        The allowed set is the intersection over every residency policy that applies,
        so adding a category can only narrow the set (monotone, strictest wins).
        """
        cats = sorted({c.split("/")[-1] for c in categories})
        allowed: set[str] | None = None
        restricted: list[str] = []
        policies: set[str] = set()
        chain: list[str] = []
        for name in cats:
            node = self.category_id(name)
            holders = [node] + self.objects(node, "cm:memberOf")
            for holder in holders:
                for inst in self.objects(holder, "cm:governedBy"):
                    jurs = self.objects(inst, "cm:requiresResidency")
                    if not jurs or not self.is_instance(inst, "cm:ResidencyPolicy"):
                        continue
                    codes = {str(self.value(j, "cm:jurisdictionCode")) for j in jurs}
                    policies.add(inst)
                    if name not in restricted:
                        restricted.append(name)
                    via = "" if holder == node else f" (via family {holder})"
                    chain.append(f"{node}{via} --governedBy--> {inst} --requiresResidency--> "
                                 f"{sorted(codes)}")
                    allowed = codes if allowed is None else allowed & codes
        provs = []
        for pid, node in sorted(self.providers().items()):
            jur = self.provider_jurisdiction(node)
            if allowed is None or jur in allowed:
                provs.append(pid)
        return ResidencyDerivation(categories=cats, restricted_categories=sorted(restricted),
                                   policies=sorted(policies),
                                   allowed_jurisdictions=None if allowed is None else sorted(allowed),
                                   allowed_providers=provs, chain=chain)

    def residency_restricted_categories(self) -> set[str]:
        """Every detector category for which a residency policy applies (used to prove engine equivalence)."""
        out = set()
        for node in self.instances_of("cm:DataCategory"):
            name = str(self.value(node, LABEL))
            if self.derive_residency([name]).allowed_jurisdictions is not None:
                out.add(name)
        return out

    # ------------------------------------------------------------------ export
    def stats(self) -> dict[str, int]:
        methods: dict[str, int] = {}
        for pv in self._prov.values():
            methods[pv.method] = methods.get(pv.method, 0) + 1
        return {"triples": len(self), "subjects": len(self._spo), "predicates": len(self._pos),
                "classes": len(self.subjects(RDF_TYPE, "owl:Class")), **{f"by_{k}": v for k, v in sorted(methods.items())}}

    def to_json(self, include_inferred: bool = True) -> dict:
        rows = []
        for t, pv in sorted(self._prov.items(), key=lambda kv: (kv[0].s, kv[0].p, _sort_key(kv[0].o))):
            if not include_inferred and pv.method == "inferred":
                continue
            rows.append({"s": t.s, "p": t.p, "o": _term_json(t.o), "provenance": asdict(pv)})
        by_method: dict[str, int] = {}
        for r in rows:
            m = r["provenance"]["method"]
            by_method[m] = by_method.get(m, 0) + 1
        stats = {"triples": len(rows), "subjects": len({r["s"] for r in rows}),
                 "predicates": len({r["p"] for r in rows}), **{f"by_{k}": v for k, v in sorted(by_method.items())},
                 "inferred_included": include_inferred}
        return {"version": self.version, "stats": stats, "triples": rows}

    @classmethod
    def from_json(cls, data: dict, functional_predicates: Iterable[str] = ()) -> "KnowledgeGraph":
        g = cls(functional_predicates)
        g.version = data.get("version", "unversioned")
        for row in data["triples"]:
            o = row["o"]
            obj = Literal(o["@value"], o.get("@type", "xsd:string")) if isinstance(o, dict) else o
            g.add(row["s"], row["p"], obj, Provenance(**row["provenance"]))
        return g

    def to_jsonld_nodes(self, subjects: Iterable[str] | None = None) -> list[dict]:
        out = []
        for s in sorted(subjects or self._spo):
            node: dict[str, Any] = {"@id": s}
            for p, objs in sorted(self._spo.get(s, {}).items()):
                key = "@type" if p == RDF_TYPE else p
                vals = [(_term_json(o) if isinstance(o, Literal) else ({"@id": o} if key != "@type" else o))
                        for o in sorted(objs, key=_sort_key)]
                node[key] = vals[0] if len(vals) == 1 else vals
            out.append(node)
        return out

    def to_svg(self, title: str = "CipherMesh knowledge graph: provider placement and live status") -> str:
        """Render Provider -> Region -> Jurisdiction (+ status) as a layered SVG with no crossing edges."""
        provs = sorted(self.providers().items(),
                       key=lambda kv: (str(self.provider_jurisdiction(kv[1])), kv[0]))
        rows = []
        for pid, node in provs:
            region = self.value(node, "cm:hostedIn")
            jur = self.value(region, "cm:locatedIn") if region else None
            status = self.value(node, "cm:hasStatus", "cm:status/unknown")
            pv = self.provenance(node, "cm:hasStatus", status)
            rows.append((pid, self.label(node), self.label(region) if region else "?",
                         self.label(jur) if jur else "?", str(self.value(jur, "cm:jurisdictionCode", "?")),
                         self.label(status), pv.source if pv else "?"))
        colors = {"operational": "#176A2E", "advisory": "#0058B0", "degraded": "#9A4300", "outage": "#B0101A",
                  "unknown": "#636369"}
        W, top, rh = 1150, 70, 92
        H = top + rh * len(rows) + 30
        cols = [(30, 240, "Provider"), (320, 260, "hostedIn  CloudRegion"), (630, 230, "locatedIn  Jurisdiction"),
                (910, 225, "hasStatus  (from feed)")]
        parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
                 f'font-family="Inter, Arial, sans-serif">',
                 f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
                 f'<text x="30" y="32" font-size="17" font-weight="700" fill="#1D1D1F">{escape(title)}</text>']
        for x, w, head in cols:
            parts.append(f'<text x="{x}" y="58" font-size="15" font-weight="700" fill="#636369" '
                         f'letter-spacing="1">{escape(head.upper())}</text>')
        for i, (pid, plab, rlab, jlab, jcode, slab, src) in enumerate(rows):
            y = top + i * rh + 8
            boxes = [(cols[0], plab, pid), (cols[1], rlab, ""), (cols[2], jlab, jcode), (cols[3], slab, src)]
            for j, ((x, w, _), main, sub) in enumerate(boxes):
                stroke = colors.get(main, "#C7C7CC") if j == 3 else "#C7C7CC"
                parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="64" rx="10" fill="#FFFFFF" '
                             f'stroke="{stroke}" stroke-width="{2.2 if j == 3 else 1.5}"/>')
                size = min(16.0, round((w - 26) / (0.6 * max(len(main), 1)), 1))   # shrink long labels to fit
                parts.append(f'<text x="{x + 14}" y="{y + 27}" font-size="{size}" font-weight="700" '
                             f'fill="{stroke if j == 3 else "#1D1D1F"}">{escape(main)}</text>')
                if sub:
                    parts.append(f'<text x="{x + 14}" y="{y + 50}" font-size="15" fill="#636369" '
                                 f'font-family="JetBrains Mono, monospace">{escape(sub)}</text>')
                if j < 3:
                    nx = cols[j + 1][0]
                    x1, x2, yy = x + w, nx, y + 32
                    parts.append(f'<line x1="{x1 + 4}" y1="{yy}" x2="{x2 - 10}" y2="{yy}" stroke="#8E8E93" '
                                 f'stroke-width="1.6"/>')
                    parts.append(f'<path d="M{x2 - 10},{yy - 5} L{x2 - 2},{yy} L{x2 - 10},{yy + 5} Z" '
                                 f'fill="#8E8E93"/>')
        parts.append("</svg>")
        return "\n".join(parts)


def _term_json(o: Any) -> Any:
    if isinstance(o, Literal):
        return {"@value": o.value, "@type": o.datatype}
    return o


def _sort_key(o: Any):
    return (1, str(o.value)) if isinstance(o, Literal) else (0, str(o))

