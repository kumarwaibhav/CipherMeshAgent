"""Build the report charts from the real verification-run logs.

Author : Kumar Waibhav Akshat (RA2212704010027)
Course : 21CSE525T Agent Technology, Assignment 4.1

Inputs : logs/bdi_trace.jsonl, logs/bdi_summary.json
Outputs: docs/figures/fig_timeline_s1.png, fig_timelines_all.png, fig_ablation.png
Usage  : python docs/figures/make_charts.py
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager as fm  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

for _f in fm.findSystemFonts():
    if "Inter" in _f:
        fm.fontManager.addfont(_f)
plt.rcParams.update({"font.family": "Inter", "font.size": 10, "axes.spines.top": False,
                     "axes.spines.right": False, "axes.edgecolor": "#8E8E93", "xtick.color": "#48484D",
                     "ytick.color": "#48484D", "axes.grid": True, "grid.color": "#E5E5EA",
                     "axes.axisbelow": True, "savefig.dpi": 220})
BLUE, TEAL, GREY, ORANGE, RED, PURPLE, GREEN = "#0068D6", "#2A7F62", "#8E8E93", "#C26A00", "#B0101A", "#4B48C4", "#176A2E"
INTENTION_COLOURS = [BLUE, GREEN, PURPLE, TEAL]
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
SHORT = {"prepare_payload": "prepare", "procure_contract": "procure", "route_and_verify": "route",
         "seal_dispatch_record": "seal", "dispatch": "dispatch", "inspect_response": "inspect",
         "deliver": "deliver", "apply_lockdown": "lockdown", "seal_evidence": "evidence",
         "notify_user": "notify", "discard_reply": "discard", "raise_alert": "alert",
         "advise_rotation": "advise", "open_review_ticket": "ticket"}

events = [json.loads(line) for line in (ROOT / "logs/bdi_trace.jsonl").read_text().splitlines()]
summary = json.loads((ROOT / "logs/bdi_summary.json").read_text())
by_run: dict[str, list[dict]] = {}
for e in events:
    by_run.setdefault(e["run"], []).append(e)


def intention_order(run_events):
    return [e["intention"] for e in run_events if e["event"] == "INTEND"]


def box(ax, x, y, w, h, colour, text, alpha=0.9, fs=8.2, tc="white"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.08", fc=colour, ec="none",
                                alpha=alpha))
    if text:
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=tc, fontweight="600")


# ------------------------------------------------------------------ 1. S1 swimlane
def timeline_s1():
    ev = by_run["S1"]
    order = intention_order(ev)
    names = {e["intention"]: e["params"].get("provider", e["plan"]) for e in ev if e["event"] == "INTEND"}
    lanes = ["environment"] + order
    ypos = {lane: len(lanes) - 1 - i for i, lane in enumerate(lanes)}
    last = max(e["cycle"] for e in ev)
    fig, ax = plt.subplots(figsize=(7.4, 3.2))
    for e in ev:
        if e["event"] == "STEP":
            i = order.index(e["intention"])
            txt = SHORT.get(e["step"], e["step"])
            if e["duration_ms"] >= 1:
                txt += f"\n{e['duration_ms']:.0f} ms"
            box(ax, e["cycle"] - 0.45, ypos[e["intention"]] - 0.3, 0.9, 0.6,
                INTENTION_COLOURS[i] if e["ok"] else RED, txt, fs=6.6)
    trig = next(e for e in ev if e["event"] == "BELIEF" and e["key"] == "provider.gcp-vertex.status")
    drop = next(e for e in ev if e["event"] == "DROP")
    intend2 = [e for e in ev if e["event"] == "INTEND"][1]
    ax.axvline(trig["cycle"], color=RED, lw=1.3, ls=(0, (5, 4)), zorder=0)
    ax.scatter([trig["cycle"]], [ypos["environment"]], marker="D", s=60, color=RED, zorder=3)
    ax.text(trig["cycle"] + 0.3, ypos["environment"],
            f"gcp-vertex.status: operational → major_outage  (+{trig['t_ms']:.1f} ms)",
            va="center", fontsize=8.4, color=RED, fontweight="600")
    ax.scatter([drop["cycle"]], [ypos[drop["intention"]]], marker="X", s=130, color=RED, zorder=3)
    ax.text(drop["cycle"] + 0.3, ypos[drop["intention"]], "I1 DROPPED before 'seal' (3/7 done)\n"
            "provider gcp-vertex is usable: VIOLATED", va="center", fontsize=8.2, color=RED)
    ax.text(intend2["cycle"] - 0.6, ypos[intend2["intention"]],
            f"cycle {intend2['cycle']}: INTEND I2, REPLAN →", ha="right", va="center",
            fontsize=8.2, color=GREEN, fontweight="600")
    ax.set_yticks([ypos[l] for l in lanes])
    ax.set_yticklabels(["belief feed"] + [f"{i} · {names[i]}" for i in order], fontsize=8.6)
    ax.set_xlim(0.4, last + 0.6)
    ax.set_ylim(-0.6, len(lanes) - 0.4)
    ax.set_xticks(range(1, last + 1))
    ax.set_xlabel("deliberation cycle (one step per cycle)")
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    fig.savefig(OUT / "fig_timeline_s1.png")
    plt.close(fig)


# ------------------------------------------------------------------ 2. all scenarios
def timelines_all():
    runs = [s for s in summary["scenarios"]]
    fig, ax = plt.subplots(figsize=(7.6, 5.4))
    names = []
    maxc = 0
    for row, s in enumerate(runs):
        y = len(runs) - 1 - row
        ev = by_run[s["scenario"]]
        order = intention_order(ev)
        step_cycles = {e["cycle"] for e in ev if e["event"] == "STEP"}
        drop_x = lambda c: c + 0.5 if c in step_cycles else c  # noqa: E731
        for e in ev:
            if e["event"] == "STEP":
                colour = INTENTION_COLOURS[order.index(e["intention"]) % 4] if e["ok"] else RED
                box(ax, e["cycle"] - 0.42, y - 0.28, 0.84, 0.56, colour, "", alpha=0.85)
                maxc = max(maxc, e["cycle"])
            elif e["event"] == "PERCEIVE" and e["msg"].startswith("environment"):
                ax.plot([e["cycle"] - 0.5, e["cycle"] - 0.5], [y - 0.42, y + 0.42], color=RED, lw=2.2)
            elif e["event"] == "DROP":
                ax.scatter([drop_x(e["cycle"])], [y + (0.42 if e["cycle"] in step_cycles else 0)], marker="X", s=60, color=RED, zorder=4, edgecolor="white", lw=0.6)
            elif e["event"] == "SUSPEND":
                ax.scatter([e["cycle"]], [y], marker="s", s=44, color=ORANGE, zorder=4)
            elif e["event"] == "RESUME":
                ax.scatter([e["cycle"] - 0.64], [y], marker=">", s=50, color=ORANGE, zorder=4)
        final = s["final_intention"]["label"].replace("provider=", "") if s["final_intention"] else "-"
        ax.text(maxc_row(ev) + 0.75, y, f"{s['outcome']}  ·  {final}", va="center", fontsize=8)
        names.append(f"{s['scenario']}  {short_title(s['title'])}")
    ax.set_yticks(list(range(len(runs) - 1, -1, -1)))
    ax.set_yticklabels(names, fontsize=8.4)
    ax.set_xlim(0.3, maxc + 11.5)
    ax.set_xticks(range(1, maxc + 1))
    ax.set_xlabel("deliberation cycle")
    ax.grid(axis="y", visible=False)
    handles = [plt.Line2D([], [], marker="s", ls="", color=c, ms=9, label=l) for c, l in
               [(BLUE, "step of 1st intention"), (GREEN, "2nd intention"), (PURPLE, "3rd intention"),
                (RED, "failed step")]]
    handles += [plt.Line2D([], [], color=RED, lw=2.2, label="belief update arrives"),
                plt.Line2D([], [], marker="X", ls="", color=RED, ms=8, label="intention dropped"),
                plt.Line2D([], [], marker="s", ls="", color=ORANGE, ms=7, label="suspend / resume")]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=4, frameon=False, fontsize=8.2)
    fig.tight_layout()
    fig.savefig(OUT / "fig_timelines_all.png")
    plt.close(fig)


def maxc_row(ev):
    return max(e["cycle"] for e in ev if e["event"] == "STEP")


def short_title(t):
    return {"Baseline: no disturbance": "baseline", "Provider outage mid-dispatch": "provider outage",
            "Emergency lockdown mid-execution": "lockdown", "Provider reply leaks a secret": "reply leak",
            "Price spike, then budget cut": "price + budget",
            "Indian data residency: provider region changes": "region change",
            "Indian data residency: prompt correction reveals PAN": "PAN correction",
            "Transient partial outage: suspend and resume": "partial outage",
            "Review backlog fills up": "review backlog"}.get(t, t.replace(" (blind commitment)", " (blind)")
                                                              .replace("Provider outage mid-dispatch", "outage")
                                                              .replace("Emergency lockdown mid-execution", "lockdown"))


# ------------------------------------------------------------------ 3. ablation
def ablation():
    rows = {s["scenario"]: s for s in summary["scenarios"]}
    pairs = [("S1", "S1-BLIND", "S1 provider outage"), ("S2", "S2-BLIND", "S2 emergency lockdown")]
    for r in rows.values():
        r["failed_steps"] = r["reconsideration"]["failed"]
    metrics = [("provider_attempts", "provider\ncalls"), ("failed_attempts", "failed\ncalls"),
               ("failed_steps", "failed\nsteps"), ("steps_executed", "steps\nexecuted")]
    fig, axes = plt.subplots(1, 2, figsize=(7.4, 2.9), sharey=True)
    for ax, (a, b, title) in zip(axes, pairs):
        xs = range(len(metrics))
        va = [rows[a][m] for m, _ in metrics]
        vb = [rows[b][m] for m, _ in metrics]
        ax.bar([x - 0.19 for x in xs], va, width=0.36, color=BLUE, label="open-minded (reconsider)")
        ax.bar([x + 0.19 for x in xs], vb, width=0.36, color=GREY, label="blind (no reconsideration)")
        for x, v in zip(xs, va):
            ax.text(x - 0.19, v + 0.2, str(v), ha="center", fontsize=8.5)
        for x, v in zip(xs, vb):
            ax.text(x + 0.19, v + 0.2, str(v), ha="center", fontsize=8.5)
        ax.set_xticks(list(xs))
        ax.set_xticklabels([l for _, l in metrics])
        ax.set_xlabel(title)
        ax.grid(axis="x", visible=False)
        ax.yaxis.set_major_locator(matplotlib.ticker.MaxNLocator(integer=True))
    axes[0].set_ylabel("count")
    axes[0].legend(frameon=False, fontsize=8.3, loc="upper left")
    fig.tight_layout()
    fig.savefig(OUT / "fig_ablation.png")
    plt.close(fig)


if __name__ == "__main__":
    timeline_s1()
    timelines_all()
    ablation()
    print("charts written to", OUT)
