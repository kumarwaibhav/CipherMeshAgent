"""Charts for the Assignment 4.2 report, built from the real logs. Author: Kumar Waibhav Akshat (RA2212704010027).
Run: python3 docs/figures/make_charts.py  (needs matplotlib; uses the shared report chart style)"""
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
KIT = Path(sys.argv[1]) if len(sys.argv) > 1 else None
if KIT:
    exec(open(KIT / "chart_style.py").read())
else:
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    BLUE, LIGHTBLUE, TEAL, GREY, ORANGE, RED, PURPLE, GREEN = '#0068D6', '#64AAFF', '#2A7F62', '#8E8E93', '#C26A00', '#B0101A', '#4B48C4', '#176A2E'
import numpy as np
rec = json.loads((ROOT / "logs" / "demo_record.json").read_text())
out = Path(__file__).resolve().parent

# 1. before / after utility per prompt
labels = list(rec["phase_a"]["plans"])
fig, ax = plt.subplots(figsize=(7.6, 3.4))
x = np.arange(len(labels)); w = 0.36
for k, (phase, col, name) in enumerate(((rec["phase_a"]["plans"], GREY, "Phase A (ontology defaults)"),
                                        (rec["phase_c"]["plans"], BLUE, "Phase C (after live update)"))):
    for i, lab in enumerate(labels):
        p = phase[lab]; xi = x[i] + (k - 0.5) * w
        if p["utility"] is None:
            ax.bar(xi, 4, w, color="white", edgecolor=RED, hatch="//", linewidth=1)
            ax.text(xi, 6, p["decision"], ha="center", va="bottom", fontsize=8, color=RED, rotation=90)
        else:
            ax.bar(xi, p["utility"], w, color=col, label=name if i == 0 else None)
            ax.text(xi, p["utility"] + 1.2, p["selected"], ha="center", va="bottom", fontsize=7.5, rotation=90, color="#1D1D1F")
ax.set_xticks(x); ax.set_xticklabels([l.replace(" ", "\n", 1) for l in labels])
ax.set_ylabel("Route utility U (0-100)"); ax.set_ylim(0, 112)
ax.legend(loc="upper center", ncol=2, frameon=False, fontsize=8.5, bbox_to_anchor=(0.5, 1.12))
fig.tight_layout(); fig.savefig(out / "fig_before_after.png"); plt.close(fig)

# 2. endpoint latency and size
eps = [e for e in rec["phase_b"]["endpoints"] if e.get("mode") == "live"]
names = [e["feed"] for e in eps]
fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.6, 2.9), sharey=True)
y = np.arange(len(names))
a1.barh(y, [e["latency_ms"] for e in eps], color=BLUE)
for i, e in enumerate(eps): a1.text(e["latency_ms"] + 8, i, f"{e['latency_ms']:.0f} ms", va="center", fontsize=8)
a1.set_yticks(y); a1.set_yticklabels(names); a1.invert_yaxis(); a1.set_xlabel("HTTPS fetch latency (ms)")
a1.set_xlim(0, max(e["latency_ms"] for e in eps) * 1.35)
a2.barh(y, [e["bytes"] / 1024 for e in eps], color=TEAL); a2.set_xscale("log")
for i, e in enumerate(eps): a2.text(e["bytes"] / 1024 * 1.15, i, f"{e['bytes']/1024:,.1f} KiB", va="center", fontsize=8)
a2.set_xlabel("Payload size (KiB, log scale)"); a2.set_xlim(0.03, 2e4)
fig.tight_layout(); fig.savefig(out / "fig_endpoints.png"); plt.close(fig)

# 3. adaptation timing chain from adaptation_events.jsonl (live events only)
evs = [json.loads(l) for l in (ROOT / "logs" / "adaptation_events.jsonl").read_text().splitlines()]
evs = [e for e in evs if not e["replay"]]
fig, ax = plt.subplots(figsize=(7.6, 2.9))
keys = [("fetch_ms", "network fetch", BLUE, "o"), ("parse_ms", "parse", PURPLE, "s"),
        ("parsed_to_property_ms", "parsed to property change", ORANGE, "D"), ("property_to_plan_ms", "property change to new plan", RED, "^")]
for j, (k, lab, col, m) in enumerate(keys):
    vals = [e["timings_ms"][k] for e in evs]
    ax.scatter([max(v, 1e-3) for v in vals], np.arange(len(evs)) + (j - 1.5) * 0.12, color=col, marker=m, s=34, label=lab, zorder=3)
ax.set_xscale("log"); ax.set_yticks(np.arange(len(evs))); ax.set_yticklabels([e["feed"] for e in evs]); ax.invert_yaxis()
ax.set_xlabel("Milliseconds (log scale)"); ax.legend(fontsize=7.5, frameon=False, ncol=2, loc="upper center", bbox_to_anchor=(0.5, 1.22))
fig.tight_layout(); fig.savefig(out / "fig_timing.png"); plt.close(fig)
print("charts written")

# 4. KEV backtest: ratio and watched-vendor hits with calibrated thresholds and resulting posture
import datetime as _dt
bt = json.loads((ROOT / "logs" / "kev_backtest.json").read_text())
dates = [_dt.date.fromisoformat(r["date"]) for r in bt["series"]]
fig, (b1, b2) = plt.subplots(2, 1, figsize=(7.6, 3.9), sharex=True, gridspec_kw={"height_ratios": [3, 2]})
b1.plot(dates, [r["ratio"] for r in bt["series"]], color=BLUE, lw=1.6, label="KEV 30-day ratio")
for lab, col, ls in (("ELEVATED", ORANGE, "--"), ("HIGH", RED, ":")):
    b1.axhline(bt["calibrated"][lab]["minKevRatio"], color=col, ls=ls, lw=1.2, label=f"{lab} threshold")
b1.set_ylabel("ratio"); b1.set_ylim(0.2, 2.6); b1.legend(fontsize=7.5, frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.18))
b1b = b1.twinx(); b1b.plot(dates, [r["relevant_hits"] for r in bt["series"]], color=TEAL, lw=1, alpha=0.7)
b1b.set_ylabel("watched-vendor hits", color=TEAL); b1b.grid(False); b1b.spines["right"].set_visible(True)
level = {"LOW": 0, "ELEVATED": 1, "HIGH": 2}
seq = {s["date"]: s["posture"] for s in bt["non_low_dates"]}
post = [level[seq.get(r["date"], "LOW")] for r in bt["series"]]
b2.step(dates, post, where="mid", color=PURPLE, lw=1.6)
b2.set_yticks([0, 1, 2]); b2.set_yticklabels(["LOW", "ELEV.", "HIGH"]); b2.set_ylabel("posture")
fig.tight_layout(); fig.savefig(out / "fig_backtest.png"); plt.close(fig)
print("backtest chart written")
