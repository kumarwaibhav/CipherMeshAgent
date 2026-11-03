"""Assignment 4.1 verification run: intention shifts under unexpected belief updates.

Author : Kumar Waibhav Akshat (RA2212704010027)
Course : 21CSE525T Agent Technology, Assignment 4.1 (BDI Goal-Driven Modeling)

Runs every scenario of ``ciphermesh.bdi.scenarios`` end to end on a fresh
CipherMesh engine (real detector/policy, Contract-Net procurement, constrained
router, simulated provider adapters, response inspection, review queue and HMAC
evidence ledger) and writes:

    logs/bdi_verification_run.log   readable, timestamped, one INTENTION SHIFT block per shift
    logs/bdi_trace.jsonl            every PERCEIVE / BELIEF / DESIRE / ... / FINISH event
    logs/bdi_summary.json           per-scenario summary (initial intention, trigger, drop, adoption)

Usage:
    python demo/bdi_verification_run.py [--latency-scale 0.05] [--idle-wait 0.02] [--out logs]
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ciphermesh.bdi import ciphermesh_desires, ciphermesh_plans  # noqa: E402
from ciphermesh.bdi.scenarios import ablation_scenarios, build_scenarios, run_scenario  # noqa: E402
from ciphermesh.bdi.services import EngineServices  # noqa: E402

RULE = "=" * 100
THIN = "-" * 100


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _value(v) -> str:
    text = json.dumps(v) if not isinstance(v, str) else v
    return text if len(text) <= 90 else text[:87] + "..."


def compact(label: str | None) -> str:
    return (label or "-").replace("provider=", "")


def main_trigger(shift: dict) -> str:
    keys = [t["key"] for t in shift["trigger"]]
    text = " ".join(shift["reasons"])
    return next((k for k in keys if k in text), keys[0] if keys else "-")


def safe_view(prompt: str) -> str:
    """Prompt as it may appear in a log: the real policy's masked preview when it found anything."""
    result = EngineServices().inspect(prompt)
    return result.safe_preview or prompt


BLOCK_WIDTH = 86      # every line of an INTENTION SHIFT block fits in 88 characters with its indent


def _wrap(text: str, indent: int = 9) -> list[str]:
    """Wrap one block line at BLOCK_WIDTH, continuing under the value column."""
    out, line = [], text
    while len(line) > BLOCK_WIDTH:
        cut = line.rfind(" ", indent + 20, BLOCK_WIDTH)
        cut = BLOCK_WIDTH if cut == -1 else cut
        out.append(line[:cut].rstrip())
        line = " " * indent + line[cut:].lstrip()
    out.append(line)
    return out


def shift_block(n: int, total: int, shift) -> list[str]:
    d, a = shift.dropped, shift.adopted
    title = f" INTENTION SHIFT {n}/{total} (cycle {shift.cycle}, +{shift.at_ms:.2f} ms) "
    side = (BLOCK_WIDTH - len(title)) // 2
    raw = ["=" * side + title + "=" * (BLOCK_WIDTH - side - len(title))]
    raw.append(f"BEFORE   {d['id']} {d['label']}  desire {d['desire']}  U={d['utility']:.2f}  "
               f"progress {d['progress']}  next step '{shift.before_step}'")
    for t in shift.trigger or [{"key": "deliberation", "old": "", "new": "", "source": "-", "confidence": 1.0}]:
        conf = t.get("confidence")
        raw.append(f"TRIGGER  {t['key']}: {_value(t['old'])} -> {_value(t['new'])}  "
                   f"[source {t['source']}{'' if conf is None else f', confidence {conf:.2f}'}]")
    for i, reason in enumerate(shift.reasons):
        raw.append(f"{shift.status if i == 0 else '':<8} {d['id']}: {reason}")
    if a:
        raw.append(f"AFTER    {a['id']} {a['label']}  desire {a['desire']}  U={a['utility']:.2f}  "
                   f"adopted at cycle {shift.adopted_cycle} (+{shift.adopted_at_ms:.2f} ms, "
                   f"reaction {shift.adopted_at_ms - shift.at_ms:.2f} ms)")
    else:
        raw.append("AFTER    no replacement intention (no applicable plan)")
    raw.append("=" * BLOCK_WIDTH)
    return ["  " + line for item in raw for line in _wrap(item)]


def summarise(scenario, agent, result, environment) -> dict:
    events = agent.tracer.events
    first = result.intentions[0] if result.intentions else None
    final = next((i for i in reversed(result.intentions) if i["status"] == "SUCCEEDED"), None)
    fired = [{"cycle": c, "label": lbl} for c, lbl in environment.log]
    disturbances = {d.label: d for d in scenario.disturbances}
    step_events = [e for e in events if e["event"] == "STEP"]
    expectation = (first is not None and first["label"] == scenario.expect_initial
                   and result.final_status == scenario.expect_status
                   and final is not None and final["label"] == scenario.expect_final_plan)
    return {
        "scenario": scenario.id, "title": scenario.title, "commitment": result.commitment,
        "request_id": result.request_id, "prompt_sha256": agent.beliefs.get("prompt.sha256"),
        "initial_intention": first and {k: first[k] for k in ("id", "desire", "label", "utility")},
        "disturbances": [{"label": f["label"], "cycle": f["cycle"],
                          "description": disturbances[f["label"]].description,
                          "trigger": disturbances[f["label"]].trigger.describe()} for f in fired],
        "shifts": [{"cycle": s.cycle, "at_ms": s.at_ms, "dropped": s.dropped["label"],
                    "dropped_id": s.dropped["id"], "dropped_progress": s.dropped["progress"],
                    "status": s.status, "before_step": s.before_step, "reasons": s.reasons,
                    "trigger": [{k: t.get(k) for k in ("key", "old", "new", "source", "confidence")}
                                for t in s.trigger],
                    "adopted": s.adopted and s.adopted["label"], "adopted_id": s.adopted and s.adopted["id"],
                    "adopted_desire": s.adopted and s.adopted["desire"],
                    "reaction_ms": None if s.adopted_at_ms is None else round(s.adopted_at_ms - s.at_ms, 3)}
                   for s in result.shifts],
        "suspensions": [{"event": e["event"], "cycle": e["cycle"], "t_ms": e["t_ms"], "intention": e["intention"],
                         "trigger": e.get("trigger", []), "msg": e["msg"]}
                        for e in events if e["event"] in {"SUSPEND", "RESUME"}],
        "final_intention": final and {k: final[k] for k in ("id", "desire", "label", "utility")},
        "outcome": result.final_status, "delivered": result.delivered,
        "intentions": [{k: i[k] for k in ("id", "desire", "label", "status", "progress")}
                       for i in result.intentions],
        "steps_executed": result.steps_executed, "cycles": result.cycles, "elapsed_ms": result.elapsed_ms,
        "step_time_ms": round(sum(e["duration_ms"] for e in step_events), 3),
        "transmissions": [{k: t[k] for k in ("provider", "residency", "ok", "redacted", "payload_sha256")}
                          for t in result.transmissions],
        "provider_attempts": len(result.transmissions),
        "failed_attempts": sum(1 for t in result.transmissions if not t["ok"]),
        "reconsideration": result.reconsideration, "ledger_records": result.ledger_records,
        "ledger_verified": result.ledger_verified, "advice": result.advice, "alerts": result.alerts,
        "expected": {"initial": scenario.expect_initial, "final_plan": scenario.expect_final_plan,
                     "status": scenario.expect_status},
        "expectation_met": expectation,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--latency-scale", type=float, default=0.05,
                        help="simulated provider latency as a fraction of the profile p95 (default 0.05)")
    parser.add_argument("--idle-wait", type=float, default=0.02, help="seconds per idle cycle (default 0.02)")
    parser.add_argument("--out", default=str(ROOT / "logs"))
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    log: list[str] = []
    trace_path = out / "bdi_trace.jsonl"
    trace_path.write_text("", encoding="utf-8")
    started = time.perf_counter()
    log += [RULE, "CipherMesh - Assignment 4.1 - Belief-Desire-Intention (BDI) Goal-Driven Modeling",
            "Verification run: intention shift when an unexpected environmental belief update arrives", RULE,
            "Student      : Kumar Waibhav Akshat (RA2212704010027)",
            "Course       : 21CSE525T Agent Technology, SRM Institute of Science and Technology",
            f"Started (UTC): {_now()}",
            f"Python       : {platform.python_version()} on {platform.system()} {platform.machine()}",
            f"Command      : python demo/bdi_verification_run.py --latency-scale {args.latency_scale} "
            f"--idle-wait {args.idle_wait}",
            "Commitment   : OPEN_MINDED, event-driven reconsideration (BLIND used only for the ablation)",
            "Engine calls : policy.inspect_text (R1-R5), ContractBook.ensure (Contract-Net), routing.route +",
            "               derive_constraints (U=0.30Q+0.25C+0.20L+0.15A+0.10P), MockProviderAdapter.complete,",
            "               CipherMeshAgent.inspect_response, ReviewQueue.submit, HMAC evidence ledger, AuditLog",
            "Privacy      : raw prompt text is never written here; prompts are shown as the policy's masked view",
            THIN, "DESIRES (higher priority constrains lower)"]
    for d in ciphermesh_desires():
        log.append(f"  {d.id}  p{d.priority:<4} {d.kind:<8} {d.description}"
                   + (f"  -> {d.constrains}" if d.constrains else "")
                   + (f"  [conflicts: {', '.join(sorted(d.conflicts_with))}]" if d.conflicts_with else ""))
    log += [THIN, "PLAN LIBRARY"]
    for p in ciphermesh_plans():
        log.append(f"  {p.id:<26} achieves {p.achieves}  steps: {' -> '.join(s.name for s in p.steps)}")
    log.append(RULE)

    summaries = []
    runs = [(s, False) for s in build_scenarios()] + [(s, True) for s in ablation_scenarios()]
    for scenario, is_ablation in runs:
        agent, result, env = run_scenario(scenario, latency_scale=args.latency_scale, idle_wait_s=args.idle_wait)
        agent.tracer.write_jsonl(trace_path, append=True)
        summary = summarise(scenario, agent, result, env)
        summary["ablation"] = is_ablation
        summaries.append(summary)
        log += ["", RULE, f"SCENARIO {scenario.id} - {scenario.title}", RULE,
                f"Commitment   : {result.commitment}",
                f"Prompt (safe): {safe_view(scenario.prompt)}",
                f"Disturbances : " + ("none" if not scenario.disturbances else
                                      "; ".join(f"{d.description} [{d.trigger.describe()}]"
                                                for d in scenario.disturbances)),
                f"Expected     : start {scenario.expect_initial}; finish {scenario.expect_final_plan}; "
                f"status {scenario.expect_status}" + (f" ({scenario.note})" if scenario.note else ""), THIN]
        log += ["  " + line for line in agent.tracer.lines]
        log.append(THIN)
        if result.shifts:
            for n, shift in enumerate(result.shifts, 1):
                log += shift_block(n, len(result.shifts), shift)
        else:
            if summary["suspensions"]:
                log.append("  NO RE-PLAN: the intention was suspended and resumed, then completed on the same plan.")
            else:
                log.append("  NO INTENTION SHIFT: the initial intention ran to completion unchanged.")
        tx = ", ".join(f"{t['provider']}({t['residency']}, {'ok' if t['ok'] else 'FAILED'}"
                       f"{', redacted' if t['redacted'] else ''})" for t in result.transmissions) or "none"
        log += [f"  OUTCOME  status={result.final_status}  delivered={result.delivered}  cycles={result.cycles}  "
                f"steps={result.steps_executed}  elapsed={result.elapsed_ms:.2f} ms",
                f"           transmissions: {tx}",
                f"           evidence ledger: {result.ledger_records} sealed record(s), chain verified="
                f"{result.ledger_verified}",
                f"           reconsideration: {result.reconsideration}"]
        if result.advice:
            log.append(f"           advice: {result.advice}")
        if result.alerts:
            log.append(f"           alerts: {result.alerts}")
        log.append(f"  CHECK    expectation met: {'PASS' if summary['expectation_met'] else 'FAIL'}")

    # ------------------------------------------------------------------ summary tables
    log += ["", RULE, "SUMMARY OF ALL SCENARIOS (open-minded commitment)", RULE,
            f"  {'ID':<4} {'Initial intention':<34} {'Trigger belief':<34} {'Adopted intention(s)':<60} "
            f"{'Outcome':<18} {'Steps':>5} {'ms':>7}  Check"]
    for s in summaries:
        if s["ablation"]:
            continue
        if s["shifts"]:
            trig = main_trigger(s["shifts"][0])
            adopted = " -> ".join(compact(x["adopted"]) for x in s["shifts"])
        elif s["suspensions"]:
            trig = (s["suspensions"][0]["trigger"] or ["-"])[0]
            adopted = "(suspended, resumed, unchanged)"
        else:
            trig, adopted = "-", "(unchanged)"
        log.append(f"  {s['scenario']:<4} {compact(s['initial_intention']['label']):<34} {trig:<34} {adopted:<60} "
                   f"{s['outcome']:<18} {s['steps_executed']:>5} {s['elapsed_ms']:>7.2f}  "
                   f"{'PASS' if s['expectation_met'] else 'FAIL'}")
    log += ["", "ABLATION: commitment strategy under the same disturbance",
            f"  {'Run':<10} {'Commitment':<12} {'Provider attempts':>17} {'Failed attempts':>15} "
            f"{'Steps':>6} {'Final status':<14} How the old intention ended"]
    for s in summaries:
        if s["scenario"] in {"S1", "S2", "S1-BLIND", "S2-BLIND"}:
            how = "; ".join(f"{x['dropped_id']} {x['status']} {'at' if x['status'] == 'FAILED' else 'before'} "
                            f"'{x['before_step']}'" for x in s["shifts"])
            log.append(f"  {s['scenario']:<10} {s['commitment']:<12} {s['provider_attempts']:>17} "
                       f"{s['failed_attempts']:>15} {s['steps_executed']:>6} {s['outcome']:<14} {how}")
    passed = sum(1 for s in summaries if s["expectation_met"])
    total_ms = (time.perf_counter() - started) * 1000
    log += ["", f"Result: {passed}/{len(summaries)} runs met their expected behaviour; "
                f"total wall time {total_ms:.1f} ms; finished {_now()}", RULE]

    (out / "bdi_verification_run.log").write_text("\n".join(log) + "\n", encoding="utf-8")
    (out / "bdi_summary.json").write_text(json.dumps({
        "assignment": "4.1 Belief-Desire-Intention (BDI) Goal-Driven Modeling",
        "student": "Kumar Waibhav Akshat (RA2212704010027)", "generated_at": _now(),
        "settings": {"latency_scale": args.latency_scale, "idle_wait_s": args.idle_wait,
                     "commitment": "per scenario (see scenarios[].commitment)"},
        "passed": passed, "runs": len(summaries), "scenarios": summaries}, indent=2), encoding="utf-8")
    print(f"{passed}/{len(summaries)} runs met expectations; logs written to {out}")
    for s in summaries:
        print(f"  {s['scenario']:<9} {s['outcome']:<18} shifts={len(s['shifts'])} "
              f"{'PASS' if s['expectation_met'] else 'FAIL'}")
    return 0 if passed == len(summaries) else 1


if __name__ == "__main__":
    raise SystemExit(main())
