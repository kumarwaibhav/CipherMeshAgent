"""Generates docs/figures/diagrams.html (hand-placed ontology and pipeline diagrams).

Author: Kumar Waibhav Akshat (RA2212704010027)
Render: NODE_PATH=$(npm root -g) node <reportkit>/render_diagrams.js diagrams.html . fig_ontology fig_pipeline fig_graph_live fig_graph_replay
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIVE = "#C26A00"


def box(x, y, w, h, title, lines, accent="#C7C7CC", sub=None, mono=False, fill="#FFFFFF", join=False):
    if join:
        lines = [" ".join(lines)]
    body = "".join(f'<p class="{"mono" if mono else ""}">{ln}</p>' for ln in lines)
    s = f'<div class="nb" style="left:{x}px;top:{y}px;width:{w}px;height:{h}px;border-color:{accent};background:{fill}">'
    s += f'<h4>{title}</h4>' + (f'<div class="sub">{sub}</div>' if sub else "") + body + "</div>"
    return s


def arrow(x1, y1, x2, y2, live=False):
    color = LIVE if live else "#6E6E73"
    dash = ' stroke-dasharray="7 5"' if live else ""
    mk = "url(#al)" if live else "url(#a)"
    return f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="2"{dash} marker-end="{mk}"/>'


def label(x, y, text, anchor="middle", live=False):
    color = LIVE if live else "#48484D"
    return (f'<text x="{x}" y="{y}" text-anchor="{anchor}" font-size="15" font-style="italic" '
            f'fill="{color}" font-family="Inter, Arial">{text}</text>')


SVG_DEFS = ('<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" '
            'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#6E6E73"/></marker>'
            f'<marker id="al" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" '
            f'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{LIVE}"/></marker></defs>')


def ontology() -> str:
    W, G, H, RG = 196, 156, 132, 62
    X = [0, W + G, 2 * (W + G), 3 * (W + G)]
    Y = [0, H + RG, 2 * (H + RG), 3 * (H + RG)]
    C = {"blue": "#0058B0", "green": "#176A2E", "purple": "#4B48C4", "red": "#B0101A", "grey": "#8E8E93",
         "orange": LIVE}
    nodes = [
        (0, 0, "DataCategory", ["25 detector categories, e.g.", "aadhaar, pan, email, llm_api_key"], C["purple"]),
        (1, 0, "PolicyRule", ["LOCKDOWN, R5, R1, R3, R2, R4.", "Ordered by priority (strictest wins)"], C["purple"]),
        (2, 0, "Decision", ["ALLOW, REDACT,", "REVIEW, BLOCK"], C["purple"]),
        (3, 0, "Vendor", ["14 watched: Amazon, Microsoft,", "Google, Linux, Python, OpenSSL ..."], C["red"]),
        (0, 1, "DetectorFamily", ["12 families D1-D12,", "e.g. D10 Aadhaar, D11 PAN"], C["purple"]),
        (1, 1, "LegalInstrument", ["Regulation: DPDP 2023, Aadhaar", "Act, GDPR; ResidencyPolicy"], C["green"]),
        (2, 1, "Jurisdiction", ["IN, US, EU, LOCAL"], C["green"]),
        (3, 1, "ThreatFeed", ["InformationSource subclass:", "CISA KEV, AI Incident DB"], C["red"]),
        (0, 2, "Threat", ["VulnerabilityClass (6),", "Vulnerability (live KEV records)"], C["red"]),
        (1, 2, "ThreatPosture", ["LOW, ELEVATED, HIGH", "with thresholds and policy effects"], C["red"]),
        (2, 2, "CloudRegion", ["ap-south-1, centralindia,", "us-central1, on-host"], C["blue"]),
        (3, 2, "ProviderStatus", ["operational, advisory, degraded,", "outage (+ routing penalties)"], C["orange"]),
        (0, 3, "AgentProfile", ["cm:agent/ciphermesh;", "budget INR 300 per 1k requests"], C["grey"]),
        (1, 3, "Currency", ["USD, INR and the live", "USD-INR ExchangeRate"], C["orange"]),
        (2, 3, "Provider", ["CloudProvider / LocalProvider:", "aws-bedrock, azure-ai, gcp-vertex, local"], C["blue"]),
        (3, 3, "StatusSource", ["InformationSource subclass:", "GCP, Azure, AWS status feeds"], C["blue"]),
    ]
    html = [f'<div class="canvas" style="width:{X[3] + W}px;height:{Y[3] + H + 70}px">']
    for c, r, t, lines, acc in nodes:
        html.append(box(X[c], Y[r], W, H, t, lines, accent=acc, join=True))
    s = [f'<svg class="ov" width="{X[3] + W}" height="{Y[3] + H + 70}">', SVG_DEFS]
    mid = lambda r: Y[r] + H / 2  # noqa: E731
    cx = lambda c: X[c] + W / 2  # noqa: E731

    def h(c1, c2, r, text, live=False):
        a, b = (X[c1] + W + 3, X[c2] - 3) if c2 > c1 else (X[c1] - 3, X[c2] + W + 3)
        s.append(arrow(a, mid(r), b, mid(r), live))
        s.append(label((a + b) / 2, mid(r) - 10, text, live=live))

    def v(c, r1, r2, text, live=False, left=False):
        a, b = (Y[r1] - 3, Y[r2] + H + 3) if r2 < r1 else (Y[r1] + H + 3, Y[r2] - 3)
        s.append(arrow(cx(c), a, cx(c), b, live))
        s.append(label(cx(c) + (-10 if left else 10), (a + b) / 2 + 5, text, anchor="end" if left else "start",
                       live=live))

    h(0, 1, 0, "triggersRule")
    h(1, 2, 0, "yieldsDecision")
    v(0, 0, 1, "memberOf")
    h(0, 1, 1, "governedBy")
    h(1, 2, 1, "requiresResidency")
    v(3, 1, 0, "watchesVendor", left=True)
    h(0, 1, 2, "mitigatedBy")
    v(2, 2, 1, "locatedIn")
    v(2, 3, 2, "hostedIn")
    h(2, 1, 3, "priceCurrency")
    h(2, 3, 3, "monitoredBy")
    # diagonals in empty gap cells (labels offset away from the line)
    x1, y1, x2, y2 = X[0] + W + 3, Y[3] - 3, X[1] - 3, Y[2] + H + 3
    s.append(arrow(x1, y1, x2, y2, live=True))
    s.append(label(x1 + 44, y1 + 2, "hasPosture", anchor="start", live=True))
    x1, y1, x2, y2 = X[2] + W + 3, Y[3] - 3, X[3] - 3, Y[2] + H + 3
    s.append(arrow(x1, y1, x2, y2, live=True))
    s.append(label(x1 + 48, y1 + 2, "hasStatus", anchor="start", live=True))
    ly = Y[3] + H + 44
    s.append(f'<line x1="0" y1="{ly}" x2="44" y2="{ly}" stroke="#6E6E73" stroke-width="2" marker-end="url(#a)"/>')
    s.append(label(54, ly + 5, "asserted in ontology.json (JSON-LD), validated by ontology.schema.json", "start"))
    s.append(f'<line x1="640" y1="{ly}" x2="684" y2="{ly}" stroke="{LIVE}" stroke-width="2" stroke-dasharray="7 5" '
             f'marker-end="url(#al)"/>')
    s.append(label(694, ly + 5, "updated at run time from live feeds (with provenance)", "start", live=True))
    s.append("</svg>")
    html += s
    html.append("</div>")
    return "".join(html)


def pipeline() -> str:
    EPW, CW, PW, AW, RW, G = 296, 214, 178, 178, 186, 38
    xs = [0, EPW + G, EPW + G + CW + G, EPW + CW + PW + 3 * G, EPW + CW + PW + AW + 4 * G]
    RH, RGAP = 74, 16
    total = 6 * RH + 5 * RGAP
    eps = [("Google Cloud Service Health", "status.cloud.google.com", "JSON", "GcpStatusConnector"),
           ("Azure status", "azure.status.microsoft", "RSS", "AzureStatusConnector"),
           ("AWS Health Dashboard", "health.aws.amazon.com", "JSON", "AwsHealthConnector"),
           ("CISA KEV catalog", "www.cisa.gov", "JSON", "CisaKevConnector"),
           ("Frankfurter FX (ECB)", "api.frankfurter.dev", "JSON", "FxRateConnector"),
           ("AI Incident Database", "incidentdatabase.ai", "RSS", "AiIncidentConnector")]
    html = [f'<div class="canvas" style="width:{xs[4] + RW}px;height:{total + 8}px">']
    s = [f'<svg class="ov" width="{xs[4] + RW}" height="{total + 8}">', SVG_DEFS]
    for i, (name, host, fmt, conn) in enumerate(eps):
        y = i * (RH + RGAP)
        html.append(f'<div class="nb ep" style="left:0;top:{y}px;width:{EPW}px;height:{RH}px">'
                    f'<h4>{name}</h4><p class="mono">{host} <span class="fmt">{fmt}</span></p></div>')
        html.append(f'<div class="nb" style="left:{xs[1]}px;top:{y}px;width:{CW}px;height:{RH}px;border-color:#0058B0">'
                    f'<p class="mono strong">{conn}</p><p>TLS, retry, size cap</p></div>')
        cy = y + RH / 2
        s.append(arrow(EPW + 3, cy, xs[1] - 3, cy))
        s.append(arrow(xs[1] + CW + 3, cy, xs[2] - 3, cy))
    html.append(box(xs[2], 0, PW, total, "Parse &amp; normalise",
                    ["Safe JSON / RSS (DTD and entities refused)", "BOM-aware decoding",
                     "Region and service names mapped with ontology aliases",
                     "Severity keywords: outage, degraded, resolved", "as_of time window",
                     "Every Fact carries source, fetched_at, confidence"], accent="#4B48C4", fill="#F7F7FD"))
    html.append(box(xs[3], 0, AW, total, "Knowledge adapter",
                    ["1. Facts become triples (functional predicates replace old values)",
                     "2. Signals become observed properties",
                     "3. Derived rules from ontology parameters: INR budget to USD cap, threat posture",
                     "Snapshot fallback is flagged in the event"], accent="#176A2E", fill="#F4FAF5"))
    s.append(arrow(xs[2] + PW + 3, total / 2, xs[3] - 3, total / 2))
    BH, BG = 144, (total - 3 * 144) / 2
    right = [("Knowledge graph", ["ontology + live triples, provenance on each"], "#0058B0"),
             ("Agent properties", ["observed + derived values, change history, subscribers"], LIVE),
             ("Plan", ["R1-R5 policy, derived residency, constrained route"], "#B0101A")]
    for j, (t, lines, acc) in enumerate(right):
        y = j * (BH + BG)
        html.append(box(xs[4], y, RW, BH, t, lines, accent=acc))
    for j in (0, 1):
        cy = j * (BH + BG) + BH / 2
        s.append(arrow(xs[3] + AW + 3, cy, xs[4] - 3, cy, live=(j == 1)))
    for j, txt in ((0, "rules"), (1, "re-plan")):
        a, b = j * (BH + BG) + BH + 3, (j + 1) * (BH + BG) - 3
        s.append(arrow(xs[4] + RW / 2, a, xs[4] + RW / 2, b, live=(j == 1)))
        s.append(label(xs[4] + RW / 2 + 10, (a + b) / 2 + 5, txt, "start", live=(j == 1)))
    s.append("</svg>")
    html += s + ["</div>"]
    return "".join(html)


CSS = """
.canvas{position:relative}
.ov{position:absolute;left:0;top:0;overflow:visible}
.nb{position:absolute;border:1.8px solid #C7C7CC;border-radius:12px;background:#fff;padding:11px 13px;overflow:hidden}
.nb h4{font-size:18px;font-weight:700;margin-bottom:5px;color:#1D1D1F}
.nb p{font-size:15px;color:#48484D;line-height:1.38;margin-bottom:5px}
.nb p.mono{font-family:"JetBrains Mono",ui-monospace,monospace;font-size:15px;color:#1D1D1F;white-space:nowrap}
.nb p.strong{font-weight:700;color:#0058B0}
.nb.ep{border-color:#8E8E93;background:#F5F5F7;padding:9px 11px}
.nb.ep h4{font-size:16.5px;margin-bottom:3px}
.fmt{font-family:Inter,Arial;font-size:15px;font-weight:700;color:#636369;border:1px solid #C7C7CC;border-radius:5px;padding:1px 5px;margin-left:4px}
"""


def main():
    graph_svg = (HERE.parents[1] / "logs" / "knowledge_graph_live.svg").read_text(encoding="utf-8")
    replay_svg = (HERE.parents[1] / "logs" / "knowledge_graph_replay.svg").read_text(encoding="utf-8")
    page = f"""<!doctype html><html><head><meta charset="utf-8"><title>CipherMesh A4.2 diagrams</title>
<link rel="stylesheet" href="diagram_base.css"><style>{CSS}</style></head><body>
<div class="d" id="fig_ontology"><div class="t">CipherMesh ontology: classes and typed relations</div>{ontology()}</div><br>
<div class="d" id="fig_pipeline"><div class="t">Live knowledge pipeline: endpoint to plan</div>{pipeline()}</div><br>
<div class="d" id="fig_graph_live" style="padding:10px">{graph_svg}</div><br>
<div class="d" id="fig_graph_replay" style="padding:10px">{replay_svg}</div>
</body></html>"""
    (HERE / "diagrams.html").write_text(page, encoding="utf-8")
    print("wrote", HERE / "diagrams.html")


if __name__ == "__main__":
    main()
