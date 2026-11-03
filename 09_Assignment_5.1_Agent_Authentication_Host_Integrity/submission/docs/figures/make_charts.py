"""Charts for the Assignment 5.1 report, drawn from the real logs in ../../logs.

Author: Kumar Waibhav Akshat (RA2212704010027).
Usage: python docs/figures/make_charts.py <reportkit chart_style.py>
"""
import json
import sys
from pathlib import Path

exec(open(sys.argv[1]).read())  # noqa: S102 - shared report chart style (plt, colours)

HERE = Path(__file__).resolve().parent
LOGS = HERE.parents[1] / "logs"
summary = json.loads((LOGS / "breach_simulation_summary.json").read_text())
bench = json.loads((LOGS / "crypto_benchmark.json").read_text())
ORDER = ["L0"] + [f"C{i}" for i in range(1, 14)]
NAMES = {"L0": "source lockout", "C1": "frame size", "C2": "strict schema", "C3": "version", "C4": "recipient",
         "C5": "host trust", "C6": "key binding", "C7": "network origin", "C8": "signature", "C9": "payload hash",
         "C10": "freshness", "C11": "replay", "C12": "host integrity", "C13": "authorization"}

# 1. which checkpoint stopped which attack
attacks = [c for c in summary["cases"] if c["kind"] == "ATTACK"]
by_cp = {cp: [c["sid"] for c in attacks if c["checkpoint"] == cp] for cp in ORDER}
fig, ax = plt.subplots(figsize=(7.6, 4.6))
ys = list(range(len(ORDER)))[::-1]
counts = [len(by_cp[cp]) for cp in ORDER]
colours = [GREY if cp == "L0" else (RED if cp in ("C8", "C12") else BLUE) for cp in ORDER]
ax.barh(ys, counts, color=colours, height=0.62)
ax.set_yticks(ys, [f"{cp}  {NAMES[cp]}" for cp in ORDER])
for y, cp, n in zip(ys, ORDER, counts):
    ids = by_cp[cp]
    label = ", ".join(ids) if len(ids) <= 4 else f"{ids[0]} … {ids[-1]}"
    ax.text(n + 0.12, y, label, va="center", fontsize=8.5, color="#48484D")
ax.set_xlabel(f"attack requests stopped ({len(attacks)} in total, all at the expected checkpoint)")
ax.set_xlim(0, max(counts) + 4.2)
ax.xaxis.get_major_locator().set_params(integer=True)
ax.grid(axis="y", visible=False)
fig.tight_layout()
fig.savefig(HERE / "chart_blocked_by_checkpoint.png")
plt.close(fig)

# 2. per-checkpoint cost (accepted path) and cost of early rejection
per = bench["per_checkpoint"]
fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.6, 3.9), gridspec_kw={"width_ratios": [1.35, 1]})
vals = [per[cp]["mean_us"] for cp in ORDER]
a1.bar(range(len(ORDER)), vals, color=[RED if cp == "C8" else (ORANGE if cp == "C2" else BLUE) for cp in ORDER])
a1.set_xticks(range(len(ORDER)), ORDER, rotation=0, fontsize=8)
a1.set_ylabel("mean time per checkpoint (µs)")
for i, v in enumerate(vals):
    if v > 9:
        a1.text(i, v + 3, f"{v:.0f}", ha="center", fontsize=8.5)
a1.grid(axis="x", visible=False)
keys = [("reject_C1_oversize", "reject at C1"), ("reject_C2_malformed", "reject at C2"),
        ("reject_C7_origin", "reject at C7"), ("reject_C8_forged", "reject at C8"),
        ("verify_accepted_total", "accept (13/13)")]
p50 = [bench[k]["p50_us"] for k, _ in keys]
a2.barh(range(len(keys))[::-1], p50, color=[TEAL, TEAL, TEAL, RED, GREEN], height=0.6)
a2.set_yticks(range(len(keys))[::-1], [lbl for _, lbl in keys])
for y, v in zip(range(len(keys))[::-1], p50):
    a2.text(v + 6, y, f"{v:.0f} µs", va="center", fontsize=8.5)
a2.set_xlabel("median verifier time per request (µs)")
a2.set_xlim(0, max(p50) * 1.3)
a2.grid(axis="y", visible=False)
fig.tight_layout()
fig.savefig(HERE / "chart_checkpoint_cost.png")
plt.close(fig)

# 3. timeline of the breach simulation (every request, in order)
cases = [c for c in summary["cases"] if c["latency_us"] > 0]   # A28 connection-level cases have no verifier run
fig, ax = plt.subplots(figsize=(9.6, 3.4))
for i, c in enumerate(cases):
    colour = GREEN if c["accepted"] else RED
    marker = "o" if c["accepted"] else "X"
    ax.scatter(i, c["latency_us"], color=colour, marker=marker, s=46, zorder=3)
ax.set_yscale("log")
ax.set_ylabel("verifier latency (µs, log)")
ax.set_xticks(range(len(cases)), [c["sid"] for c in cases], rotation=90, fontsize=7)
bounds = [i for i, c in enumerate(cases) if c["sid"] in ("A01", "A25.1", "S08", "I02a")]
labels = ["Part A: legitimate", "Part B: attacks A01–A24", "B: A25–A27", "C", "D"]
starts = [0] + bounds
for k, s in enumerate(starts):
    if s:
        ax.axvline(s - 0.5, color="#C7C7CC", lw=1, zorder=1)
ymax = max(c["latency_us"] for c in cases) * 2.2
for k, (s, e) in enumerate(zip(starts, starts[1:] + [len(cases)])):
    ax.text((s + e - 1) / 2, ymax, labels[k], ha="center", fontsize=8.5, color="#48484D")
ax.set_ylim(min(c["latency_us"] for c in cases) / 2, ymax * 2.2)
ax.scatter([], [], color=GREEN, marker="o", label="ACCEPTED")
ax.scatter([], [], color=RED, marker="X", label="REJECTED (state unchanged)")
ax.legend(loc="lower left", fontsize=8.5, frameon=False, ncol=2)
ax.grid(axis="x", visible=False)
fig.tight_layout()
fig.savefig(HERE / "chart_simulation_timeline.png")
plt.close(fig)
print("charts written")
