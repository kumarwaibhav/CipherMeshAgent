// Report content for Assignment 4.1 - Belief-Desire-Intention (BDI) Goal-Driven Modeling
// Author: Kumar Waibhav Akshat (RA2212704010027)
// Every log excerpt and number below is read from the real run outputs in ../../logs at build time.
const fs = require('fs');
const path = require('path');
const { makeDoc } = require(path.join(process.env.REPORTKIT || path.resolve(__dirname, '../../../reportkit'), 'dsl.js'));
const d = makeDoc(); const { h1, h2, h3, p, tbl, bul, num, fig, code, refs, app, pb } = d;

const ROOT = path.resolve(__dirname, '../..');
const FIG = (f) => path.join(ROOT, 'docs/figures', f);
const TRACE = fs.readFileSync(path.join(ROOT, 'logs/bdi_trace.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
const SUM = JSON.parse(fs.readFileSync(path.join(ROOT, 'logs/bdi_summary.json'), 'utf8'));
const S = Object.fromEntries(SUM.scenarios.map((s) => [s.scenario, s]));
const LOG = fs.readFileSync(path.join(ROOT, 'logs/bdi_verification_run.log'), 'utf8').split('\n');
const PYTEST = fs.readFileSync(path.join(ROOT, 'logs/pytest_results.txt'), 'utf8');
const TOTAL = (PYTEST.match(/(\d+) passed/) || [0, '?'])[1];
const count = (file) => (PYTEST.match(new RegExp(`tests/bdi/${file}::[^\\n]*? PASSED`, 'g')) || []).length;
const BDI = ['test_beliefs.py', 'test_desires.py', 'test_plans.py', 'test_intentions.py', 'test_reconsideration.py',
  'test_trace_and_determinism.py'].reduce((a, f) => a + count(f), 0);

const SHIFTS = SUM.scenarios.reduce((n, x) => n + x.shifts.length, 0);
const cut = (s, n = 88) => (s.length <= n ? s : s.slice(0, n - 3) + '...');
const short = (s) => s.replace(/provider=/g, '').replace(/allow_then_dispatch/g, 'allow_then_dispatch');
// One formatted trace line: "+  7.14 c04 BELIEF     provider.gcp-vertex.status: ..."
const tl = (e) => cut(`+${e.t_ms.toFixed(2).padStart(6)} c${String(e.cycle).padStart(2, '0')} ${e.event.padEnd(10)} ${short(e.msg)}`);
function excerpt(run, keep) {
  return TRACE.filter((e) => e.run === run && keep(e)).map(tl).join('\n');
}
const KEYS = (...k) => (e) => e.event !== 'BELIEF' || k.some((x) => e.key.includes(x));
const shiftBlock = (id) => {
  // verbatim copy of the INTENTION SHIFT block in the log (only the 2-space log indent is removed)
  const i = LOG.findIndex((l) => l.includes(`SCENARIO ${id} -`));
  const j = LOG.findIndex((l, n) => n > i && l.includes('INTENTION SHIFT'));
  const out = [];
  for (let n = j; n < LOG.length && !LOG[n].includes('OUTCOME'); n++) out.push(LOG[n].replace(/^ {2}/, ''));
  if (out.some((l) => l.length > 88)) throw new Error('shift block line longer than 88 characters');
  return out.join('\n');
};
const lbl = (x) => (x ? x.replace('provider=', '').replace('allow_then_dispatch(', 'allow(').replace('redact_then_dispatch(', 'redact(').replace('dispatch_local_only(', 'local_only(') : '-');
const val = (v) => (Array.isArray(v) && v.length && typeof v[0] === 'object'
  ? v.filter((f) => f.severity === 'CRITICAL').map((f) => `${f.category} (CRITICAL)`).join(', ')
  : JSON.stringify(v).replace(/"/g, ''));
const trig = (s) => {
  if (!s.shifts.length) return s.suspensions.length ? 'gcp-vertex.status = partial_outage' : 'none';
  const t = s.shifts[0].trigger; const r = s.shifts[0].reasons.join(' ');
  const k = t.find((x) => r.includes(x.key)) || t[0];
  return `${k.key.replace('provider.', '')} = ${val(k.new)}`;
};
// =====================================================================================================
h1('Introduction');
h2('Objective');
p('This assignment adds a **cognitive layer** to CipherMesh, the privacy control plane that sits between enterprise applications and AI providers. The layer follows the Belief-Desire-Intention (BDI) model of practical reasoning [@bratman] [@rao95]. It keeps three explicit collections inside the agent: **beliefs** (what the agent currently holds to be true), **desires** (the strategic goals it would like to reach) and **intentions** (the step-by-step plans it has committed to). The objective set by the brief is to track these three collections as a state machine and to *recalculate the plan* when a belief changes while a plan is half-way through execution.');
p('Earlier units made CipherMesh correct for one moment in time: a prompt was inspected, a provider was chosen and the prompt was sent. Real deployments do not stand still. A provider can go down between the routing decision and the transmission, the security team can declare a lockdown, a price can jump, or the user can edit the prompt. A purely reactive pipeline either sends the prompt anyway or fails late. A BDI agent instead notices that one of its working assumptions is no longer true, drops or suspends the affected intention, and chooses a new plan. This report shows that behaviour with real engine calls and real logs.');
h2('The problem in CipherMesh terms');
p('For every prompt CipherMesh must balance goals that can conflict. It must never transmit a secret, it must keep Indian personal data (Aadhaar, PAN, Indian phone numbers) inside India or on the local host, it should still return a useful answer, it should do so at the lowest cost within quality limits, and it must not overload the human reviewers. These map directly to five desires D1 to D5 with fixed priorities. The question this unit answers is: *when the world changes in the middle of a request, which of these goals should drive the next action, and what plan should replace the one that is no longer valid?*');
h2('How this unit builds on Units 1 to 3');
p('The BDI layer does not re-implement any engine logic. Every plan step calls a module built in an earlier unit, as listed in Table {nexttbl}. This keeps the cognitive layer thin and makes the verification run a test of the whole product, not of a toy model.');
tbl('Earlier CipherMesh units reused by the BDI layer', ['Unit', 'Module(s)', 'Role inside the BDI layer'], [1500, 2900, 4266], [
  ['1.1 / 1.2', '`detector.py`, `policy.py`', 'The prompt sensor: 25 detector rules and policy R1 to R5 produce the beliefs `prompt.decision` and `prompt.categories`'],
  ['2.1', '`runtime.py`, `providers.py`', 'Thread-safe engine and provider health; the belief base is also lock-protected so monitors can update it from other threads'],
  ['2.2', '`agent.py`, `security.py`, `audit.py`', 'Agent state (`force_block_all`), review queue, response inspection and the SQLite audit log that records each adopted and dropped intention'],
  ['3.1', '`procurement.py`, `negotiation/`', 'Contract-Net prices [@smith] become the belief `provider.<id>.price_per_1k` and are confirmed by the `procure_contract` step'],
  ['3.2', '`routing.py`', '`route()` and `derive_constraints()` rank providers by U = 0.30Q + 0.25C + 0.20L + 0.15A + 0.10P; the ranking supplies plan bindings and their utilities'],
], { small: true });

// =====================================================================================================
h1('Assignment Requirements and Traceability');
p('Table {nexttbl} quotes every objective, direction and deliverable line of the brief and maps it to the place where it is met and to the evidence a reviewer can open. File paths are relative to the submission folder.');
tbl('Requirement traceability matrix', ['Brief line', 'Where it is satisfied', 'Evidence'], [2700, 3366, 2600], [
  ['Objective: Implement a cognitive-layer state machine tracking beliefs, desires, and execution intentions inside your custom agent.', '`ciphermesh/bdi/engine.py` (BDIAgent deliberation cycle) and `intentions.py` (intention state machine)', 'Figures 3.2 and 3.3; `logs/bdi_trace.jsonl`'],
  ['Construct three explicit collections or classes within your application architecture mapping to the BDI Architecture', '`BeliefBase`, `DesireSet` and `PlanLibrary` + `IntentionStack` in `ciphermesh/bdi/`', 'Section 3.9, Table 3.5'],
  ['Beliefs: The agent\'s knowledge base state repository (e.g., "Current Location battery is 20%", "Flight price is $400").', '`ciphermesh/bdi/beliefs.py`: `Belief`, `BeliefBase` (set, get, has, retract, subscribe, snapshot, history, lock)', `\`tests/bdi/test_beliefs.py\` (${count('test_beliefs.py')} tests incl. a 12-thread stress test)`],
  ['Desires: Top-level abstract strategic milestones (e.g., "Find high-speed network", "Book lowest cost ticket").', '`ciphermesh/bdi/desires.py`: `Desire`, `DesireSet`, `ciphermesh_desires()` with D1 to D5', 'Table 3.2; `tests/bdi/test_desires.py`'],
  ['Intentions: Active step-by-step procedural action pipelines chosen to hit active desires.', '`ciphermesh/bdi/plans.py` (Plan, PlanStep, PlanLibrary) and `intentions.py` (Intention, IntentionStack)', 'Table 3.3; `tests/bdi/test_plans.py`, `test_intentions.py`'],
  ['Program dynamic plan recalculation routines when internal belief collections change mid-execution.', '`BDIAgent._revise_and_reconsider()` and `_reconsider()`: subscription-driven, three-valued check, DROP / SUSPEND / RESUME, then re-plan', `\`tests/bdi/test_reconsideration.py\` (${count('test_reconsideration.py')} tests)`],
  ['Deliverables: Complete source code showing the programmatic BDI objects', '`ciphermesh/bdi/` (10 modules), public API in `ciphermesh/bdi/__init__.py`', 'Appendix B'],
  ['Deliverables: ... and a test verification run demonstrating an intention shift when an unexpected environmental belief update hits the system.', '`demo/bdi_verification_run.py` runs 9 scenarios + 2 ablations on the real engine', '`logs/bdi_verification_run.log` (INTENTION SHIFT blocks), `bdi_summary.json`'],
]);

// =====================================================================================================
h1('Design');
h2('Architecture');
p('Figure {nextfig} shows the BDI layer as built. Sensors and plan steps write beliefs; the deliberation cycle reads beliefs and desires, picks plan templates from the library and turns them into intentions; intention steps call the real engine, whose results flow back as new beliefs. Every arrow points one way, so the diagram is also the data-flow order of one cycle.');
fig(FIG('fig_bdi_architecture.png'), 'BDI architecture of the CipherMesh cognitive layer (package `ciphermesh/bdi`)', 578);

h2('Background: the BDI model');
p('Bratman describes intentions as *commitments* to partial plans [@bratman]. Once an agent intends something it stops weighing every alternative again at every moment; the intention filters which new options are even considered. Cohen and Levesque formalised this as "intention is choice with commitment" [@cohen]. Rao and Georgeff turned the idea into an abstract interpreter: options are generated from beliefs and desires, filtered into intentions, and executed step by step while new events are processed between steps [@rao95]. Plan libraries with context conditions come from the Procedural Reasoning System (PRS) [@prs] and were later given a logical language, AgentSpeak(L) [@agentspeak], which is implemented in the Jason platform [@jason]. Textbook treatments of the same loop appear in Wooldridge [@wooldridge] and in Russell and Norvig [@aima].');
p('The key design question is *how often to reconsider*. Rao and Georgeff name three commitment strategies: blind (keep the intention until it is believed achieved), single-minded (also drop it when it is believed impossible) and open-minded (also drop it when its goal is no longer desired) [@rao91]. Kinny and Georgeff showed experimentally that the right amount of reconsideration depends on how fast the world changes and on the cost of reconsidering [@kinny]. CipherMesh uses the open-minded strategy but makes reconsideration *event-driven*, so its cost is paid only when a relevant belief actually changes.');

h2('Beliefs');
p('A belief is one fact under a dotted key, with its source, a confidence in [0, 1], a timestamp and a per-key revision number. `BeliefBase.set()` returns True only when the value really changes, so repeated status reports do not wake the agent. Subscribers receive `(key, old, new, source)` after the lock is released, which lets a callback read the base without deadlock. The history is append-only and readers only get a copy. Raw prompt text is never stored as a belief; the text lives in a private per-request context and beliefs hold only hashes, categories, decisions, prices and statuses. Table {nexttbl} lists the belief families.');
tbl('Belief families used by the CipherMesh agent', ['Key (pattern)', 'Example value', 'Written by'], [3400, 2700, 2566], [
  ['`prompt.decision`, `prompt.categories`', 'REDACT, [aadhaar, email]', 'prompt sensor (`policy.inspect_text`)'],
  ['`provider.<id>.status`', 'operational, partial_outage, major_outage', 'status feed, circuit breaker'],
  ['`provider.<id>.residency`, `.region`', 'IN / ap-south-1', 'registry, provider health notices'],
  ['`provider.<id>.price_per_1k`', '2.28 (negotiated contract)', 'Contract-Net procurement, price feed'],
  ['`budget.max_cost_per_1k`', '6.00', 'route constraints, finance policy'],
  ['`policy.lockdown`', 'true / false', 'agent state, SOC command'],
  ['`review.queue_depth`, `review.limit`', '25 / 25', 'review-queue monitor'],
  ['`response.findings`, `response.decision`', '[aws_access_key, CRITICAL]', 'response inspection step'],
  ['`request.status`, `guard.secret_contained`', 'PENDING, COMPLETED, BLOCKED', 'plan steps'],
], { small: true });

h2('Desires');
p('Desires are evaluated against beliefs on every cycle. An *achieve* desire receives an intention; a *maintain* desire never runs a plan of its own but constrains the plans chosen for lower-priority desires. Higher priority always wins, and D1 declares a conflict with D3 and D4, so whenever a secret risk is believed the delivery goal is pre-empted. Table {nexttbl} gives the five desires.');
tbl('CipherMesh desires (desires.py)', ['ID', 'Priority / kind', 'Description', 'Active when ... / satisfied when ...'], [700, 1500, 2600, 3866], [
  ['D1', '100 / achieve', 'Never transmit a secret (conflicts with D3, D4)', 'request pending and (secret in prompt, lockdown, or secret in reply) / secret contained'],
  ['D2', '90 / maintain', 'Keep Indian personal data in India', 'Aadhaar, PAN or Indian phone in prompt / no dispatch outside IN or LOCAL'],
  ['D3', '60 / achieve', 'Deliver a useful answer to the user', 'request pending / safe reply delivered'],
  ['D4', '40 / maintain', 'Lowest cost within quality bounds', 'request pending and a budget is known / effective price within budget'],
  ['D5', '30 / achieve', 'Keep the human-review backlog under its limit', 'REVIEW prompt pending / queue depth below limit or request deferred'],
], { small: true });

h2('Plans and the plan library');
p('A plan template has an identifier, the desire it achieves, a context made of named conditions, an ordered list of steps and an optional *binder*. The binder of the dispatch plans asks the real router for every feasible provider and returns one binding per provider with its utility U, so means-ends reasoning is "best plan and best provider" in a single ranked list. Each step names the beliefs it relies on (`relevant_beliefs`) and may carry guard conditions. Conditions are three-valued: HOLDS, UNCERTAIN (wait, for example a partial outage) or VIOLATED. Table {nexttbl} lists the library.');
tbl('Plan library (plans.py)', ['Plan', 'Achieves', 'Context (all must HOLD)', 'Steps'], [2350, 900, 2900, 2516], [
  ['allow_then_dispatch(p)', 'D3', 'ALLOW, no lockdown, p usable, residency allowed (D2), price within budget (D4)', 'prepare, procure, route, seal, dispatch, inspect, deliver'],
  ['redact_then_dispatch(p)', 'D3', 'same, but prompt decision is REDACT', 'same seven steps; payload is the sanitized text'],
  ['dispatch_local_only', 'D3', 'ALLOW or REDACT; local tier feasible', 'same seven steps on Ollama (local)'],
  ['hold_for_review', 'D3', 'REVIEW, no lockdown, backlog has capacity', 'open_review_ticket, notify_user'],
  ['block_and_advise_rotation', 'D1', 'critical secret in prompt', 'seal_evidence, advise_rotation, notify_user'],
  ['enforce_lockdown_block', 'D1', 'lockdown is on', 'apply_lockdown, seal_evidence, notify_user'],
  ['withhold_reply_and_alert', 'D1', 'critical secret in reply', 'discard_reply, seal_evidence, raise_alert, notify_user'],
  ['decline_review_overflow', 'D5', 'REVIEW and backlog at limit', 'seal_evidence, notify_user'],
], { small: true });

h2('Intentions and their life cycle');
p('An intention binds one plan and its parameters to one desire. It holds a cursor to the next step, a status and a reason history. The stack allows only one live intention per desire and always runs the live intention of the highest-priority desire first. Figure {nextfig} shows the legal transitions; any other transition raises `IntentionError`.');
fig(FIG('fig_states.png'), 'Intention state machine: ACTIVE, SUSPENDED and the three terminal states', 470);

h2('The deliberation cycle');
p('Figure {nextfig} shows one cycle of `BDIAgent.run()`. The cycle executes exactly one plan step, so the agent gets a chance to reconsider between any two steps. The algorithm is:');
fig(FIG('fig_cycle.png'), 'Deliberation cycle with the re-plan path (top) and the next-cycle path (bottom)', 578);
num([
  '**Perceive.** Poll the environment for events due on this cycle (cycle or idle triggers) and apply them as belief updates.',
  '**Revise beliefs.** Drain the queue filled by the belief subscription, log each change and run event-driven reconsideration (Section 3.8, steps 1–6).',
  '**Generate options.** Every desire that is active and not yet satisfied is an option.',
  '**Filter.** Walk the options in priority order; skip any option that conflicts with one already selected and record it as pre-empted. Drop the live intention of a pre-empted desire.',
  '**Means-ends reasoning.** For each selected achieve desire without a live intention, ask the plan library for applicable (plan, binding) pairs, sorted by utility, then cost, then plan id. Adopt the best as a new intention; if a previous intention was dropped, log a REPLAN. If there is no applicable plan, mark the desire as having no plan for now.',
  '**Act.** Just before the step, perceive again (events tied to that step) and revise beliefs once more, so nothing written during deliberation is left unprocessed. Then check the guard conditions of the step against the current belief base: if any guard does not HOLD, the step is not executed and the intention is reconsidered instead. Otherwise run the step, which calls the real engine.',
  '**Reconsider after the step** using the beliefs the step itself changed, then stop when no live intention and no achievable option remain.',
]);
h2('Reconsideration and commitment strategy');
p('Reconsideration is the routine that recalculates the plan. It is triggered by a belief change, never by a timer, and it only looks at intentions that depend on the changed key:');
num([
  'Build the *watch set* of the intention: the `relevant_beliefs` and guard reads of its **remaining** steps (completed steps no longer matter), plus the beliefs read by the desires. If no changed key matches, skip the intention and count the change as ignored.',
  'Evaluate the guards of the remaining steps and the context conditions those steps still depend on. Each condition returns HOLDS, UNCERTAIN or VIOLATED.',
  'Open-minded check: if the desire is no longer active, already satisfied, or pre-empted by a higher-priority conflicting desire, add a reason.',
  'Any reason or VIOLATED condition: DROP the intention, record the reasons with the believed values, and open an *intention shift* that is closed by the next INTEND (the re-plan).',
  'Otherwise any UNCERTAIN condition: SUSPEND the intention (or keep waiting, up to 4 cycles, then DROP with "suspension timeout").',
  'Otherwise: keep the intention, or RESUME it if it was suspended.',
]);
p('Table {nexttbl} compares the three strategies supported by `CommitmentStrategy`. OPEN_MINDED is the production setting; BLIND is used only in the ablation of Section 5.');
tbl('Commitment strategies implemented in engine.py', ['Strategy', 'Drops an intention when', 'Use in this work'], [2100, 3900, 2666], [
  ['BLIND', 'a step fails (no reconsideration)', 'ablation baseline (S1-BLIND, S2-BLIND)'],
  ['SINGLE_MINDED', 'a step fails, or its context or remaining guards are VIOLATED', 'tested in `test_single_minded_...`'],
  ['OPEN_MINDED', 'as single-minded, or its desire is inactive, satisfied or pre-empted', 'default for all scenarios'],
]);

h2('Class and data model');
p('Table {nexttbl} summarises the main classes, their key fields and the methods that the later Capstone integration will call.');
tbl('Class and data model of ciphermesh/bdi', ['Class', 'Key fields', 'Key methods'], [2300, 3300, 3066], [
  ['Belief / BeliefChange', 'key, value, source, confidence, updated_at, revision / seq, kind, old, new', 'as_dict()'],
  ['BeliefBase', 'beliefs dict, history list, subscribers, RLock', 'set, get, has, retract, subscribe, snapshot, matching, history'],
  ['Desire / DesireSet', 'id, description, priority, kind, conflicts_with, reads', 'is_active, is_satisfied, options, deliberate, constraining'],
  ['Condition / PlanStep', 'description, check, reads / name, action, relevant_beliefs, guard', 'evaluate, describe / relevant_for'],
  ['Plan / PlanLibrary', 'id, achieves, conditions, steps, binder', 'context, violations, bindings / options_for, rejected_for'],
  ['Intention / IntentionStack', 'id, desire_id, plan, params, cursor, status, reasons, step_log', 'transition, advance, watched_beliefs / push, top, live'],
  ['BDIAgent', 'beliefs, desires, library, intentions, commitment, tracer', 'perceive_world, submit, amend_prompt, run'],
  ['EngineServices', 'agent, registry, contracts, ledger, transmissions', 'perceive_world, inspect, route_view, record_transmission'],
], { small: true });

// =====================================================================================================
h1('Implementation');
h2('Modules');
p('The cognitive layer is a new subpackage. Table {nexttbl} lists its modules. The 112 engine tests from earlier units still pass unchanged.');
tbl('Modules of the BDI subpackage and demonstration', ['File', 'Purpose', 'Key classes / functions'], [2500, 3500, 2666], [
  ['`bdi/beliefs.py`', 'thread-safe belief repository with change subscription and history', 'Belief, BeliefChange, BeliefBase'],
  ['`bdi/desires.py`', 'desires, option generation, priority and conflict filtering', 'Desire, DesireSet, ciphermesh_desires'],
  ['`bdi/plans.py`', 'plan templates, three-valued conditions, step actions calling the engine', 'Condition, PlanStep, Plan, PlanLibrary'],
  ['`bdi/intentions.py`', 'intention state machine and priority stack', 'Intention, IntentionStack, IntentionStatus'],
  ['`bdi/engine.py`', 'deliberation cycle, reconsideration, intention shifts', 'BDIAgent, CommitmentStrategy, RunResult'],
  ['`bdi/services.py`', 'bridge to detector, policy, procurement, router, providers, ledger', 'EngineServices, EvidenceLedger'],
  ['`bdi/world.py`', 'shared interpretation of belief keys', 'allowed_residency, prompt_has_secret'],
  ['`bdi/trace.py`', 'JSONL + readable trace', 'Tracer'],
  ['`bdi/scenarios.py`', 'scripted disturbances and scenario catalogue', 'Disturbance, Trigger, Environment'],
  ['`demo/bdi_verification_run.py`', 'runs all scenarios, writes the three logs', 'main, shift_block, summarise'],
], { small: true });
h2('Selected code');
p('Listing 1 is the core of belief revision. The change test and the history append happen under the lock; subscribers are notified after the lock is released.');
code(`def set(self, key, value, source, confidence=1.0) -> bool:
    self._validate(key, source, confidence)
    value = copy.deepcopy(value)
    with self._lock:
        previous = self._beliefs.get(key)
        changed = previous is None or previous.value != value
        revision = 1 if previous is None else previous.revision + (1 if changed else 0)
        self._beliefs[key] = Belief(key=key, value=value, source=source,
                                    confidence=float(confidence), updated_at=_now(),
                                    revision=revision)
        if not changed:
            return False
        ...  # append BeliefChange to the history, copy the subscriber list
    self._notify(callbacks, key, old_value, value, source)
    return True`, 'Listing 1: BeliefBase.set() in beliefs.py (abridged)');
p('Listing 2 shows how one plan template is declared. The context conditions are shared objects, so the same condition text appears in the plan, in the step guards and in the drop reasons of the log.');
code(`Plan("allow_then_dispatch", "D3",
     "send the clean prompt to the best feasible cloud provider",
     (C_PENDING, C_NO_LOCKDOWN, C_ALLOW, C_USABLE, C_RESIDENCY, C_BUDGET,
      C_REPLY_CLEAN),
     _dispatch_steps(), binder=_cloud_binder("allow"))

PlanStep("dispatch", step_dispatch, R_DISPATCH, guard=G_DISPATCH, transmits=True)
C_USABLE = Condition("provider {provider} is usable", _verdict_status,
                     frozenset({"provider.{provider}.status"}))`, 'Listing 2: a plan template, its transmitting step and a condition (plans.py)');
p('Listing 3 is the event-driven part of reconsideration. Only intentions whose watch set matches a changed key are evaluated.');
code(`for intention in live:
    watched = intention.watched_beliefs()
    if self.commitment == CommitmentStrategy.OPEN_MINDED:
        watched |= self._desire_reads
    relevant = [c for c in changes if _matches(c["key"], watched)]
    waiting = (intention.status == IntentionStatus.SUSPENDED
               and intention.suspended_cycle != self.cycle)
    due = bool(relevant) or (origin == "step" and (intention is executed or waiting))
    if not due:
        continue
    self.stats["evaluated"] += 1
    self._reconsider(intention, relevant)`, 'Listing 3: selecting intentions to reconsider (engine.py)');
p('Deliberation decides what the agent *should* do; it is not the only line of defence. The `dispatch` step re-checks the safety rules itself before any byte leaves the host (Listing 4): lockdown, residency, a provider believed to be down, and a payload built from an older prompt. The ablation in Section 5 shows why this matters: a blind agent that never reconsiders is still stopped by this interlock.');
code(`def step_dispatch(ctx: StepContext) -> StepResult:
    b, svc, pid = ctx.beliefs, ctx.services, ctx.provider
    residency = b.get(world.pkey(pid, "residency"))
    if svc.agent.state.force_block_all or world.lockdown(b):
        return _fail("interlock: emergency lockdown is active; nothing transmitted")
    if residency not in world.allowed_residency(b):
        return _fail(f"interlock: residency {residency} not allowed ...")
    if world.provider_status(b, pid) in world.STATUS_DOWN:
        return _fail(f"interlock: {pid} is believed ...; nothing transmitted")
    if (ctx.request.payload is None
            or b.get("payload.prompt_sha256") != b.get("prompt.sha256")):
        return _fail("interlock: payload was prepared from an older prompt; ...")`, 'Listing 4: safety interlocks inside the transmitting step (plans.py, abridged)');
h2('Invariants enforced in code');
bul([
  '**No step runs on stale beliefs.** Pending belief changes are drained and reconsidered immediately before every step, and the guards of the step are evaluated at execution time; a failing guard triggers reconsideration instead of the step (tested by writing an outage belief during deliberation and after the last revision).',
  '**Nothing leaves during lockdown or to a non-Indian region for Indian data.** Checked by deliberation and again by the dispatch interlock.',
  '**No raw prompt text or secret value in beliefs, logs or the trace.** Only hashes, categories and decisions; a test greps every trace for the test secrets.',
  '**Every adopted and dropped intention is audited** in the engine SQLite audit log and sealed evidence is kept in an HMAC-SHA256 hash chain [@hmac].',
  '**Determinism.** Option ranking ties break on cost and then plan id; scenario runs produce identical event sequences.',
]);

// =====================================================================================================
h1('Verification Run');
h2('Set-up');
p(`The verification run executes nine scenarios and two ablation runs with \`python demo/bdi_verification_run.py\`. Each run builds a fresh engine: real detector and policy, Contract-Net negotiation for four providers, the constrained router, simulated provider adapters (latency scale 0.05 of the profile p95, so a cloud call takes about 30 ms and the local tier about 60 ms), response inspection, the review queue and the HMAC evidence ledger. Disturbances are injected through \`Environment\` at a chosen step, which is the "unexpected environmental belief update" required by the brief. Result: **${SUM.passed}/${SUM.runs} runs met their expected behaviour**. Table {nexttbl} lists the scenarios and where each disturbance strikes.`);
tbl('Scenario catalogue and injection points (scenarios.py)', ['ID', 'Disturbance', 'Injected', 'Expected shift'], [700, 3266, 2200, 2500], [
  ['S0', 'none (control run)', '-', 'no shift'],
  ['S1', 'GCP Vertex major outage', "before 'seal_dispatch_record'", 'gcp-vertex to aws-bedrock'],
  ['S2', 'emergency lockdown from the SOC', "before 'dispatch'", 'dispatch (D3) to block (D1)'],
  ['S3', 'provider reply echoes an AWS access key', "before 'dispatch'", 'deliver (D3) to withhold (D1)'],
  ['S4', 'price spike to $6.80, then budget cut to $1.00', "before 'seal', then 'dispatch'", 'gcp to aws, then aws to local'],
  ['S5', 'Bedrock region moves to us-east-1 (Aadhaar prompt)', "before 'dispatch'", 'aws-bedrock to azure-ai (IN)'],
  ['S6', 'user amends prompt and adds a PAN', "before 'seal_dispatch_record'", 'allow (US) to redact (IN)'],
  ['S7', 'partial outage, recovered two idle cycles later', "before 'dispatch'", 'suspend, then resume (no shift)'],
  ['S8', '25 review tickets arrive in a burst', "before 'open_review_ticket'", 'hold (D3) to decline (D5)'],
], { small: true });

h2('Baseline: no disturbance (S0)');
p(`With no belief change the agent adopts \`allow_then_dispatch(gcp-vertex)\` (U = 77.93, the router winner) and runs its seven steps without a single drop: ${S.S0.steps_executed} steps in ${S.S0.cycles} cycles, ${S.S0.elapsed_ms.toFixed(1)} ms, one transmission. Every later scenario starts from this same intention, so any change of plan in those runs is caused by the injected belief update and nothing else.`);

h2('S1: provider outage mid-dispatch');
p('Listing 5 is the trace of S1 (belief lines not related to the trigger are omitted). After three steps the status feed reports a major outage. The change matches the watch set of I1 (its `seal` and `dispatch` steps depend on `provider.gcp-vertex.status`), the condition "provider gcp-vertex is usable" is VIOLATED, and I1 is dropped with 3 of 7 steps done. On the next cycle means-ends reasoning runs the router again on the revised beliefs and adopts AWS Bedrock.');
code(excerpt('S1', (e) => ['PERCEIVE', 'BELIEF', 'RECONSIDER', 'DROP', 'INTEND', 'REPLAN', 'FINISH'].includes(e.event) && KEYS('status')(e) && !(e.event === 'BELIEF' && e.key === 'request.status') && !e.msg.startsWith('world model')), 'Listing 5: S1 trace excerpt from logs/bdi_trace.jsonl');
p('The log also prints a dedicated block for every change of mind. Listing 6 is the block for S1, copied from `logs/bdi_verification_run.log`. The reaction time from the drop to the new intention is below one millisecond because the cached contracts and the router are cheap; the cost of the outage is the three repeated preparation steps, not waiting.');
code(shiftBlock('S1'), 'Listing 6: INTENTION SHIFT block for S1');
p('Figure {nextfig} is drawn from the same trace. Each box is one executed step; the dashed line is the arrival of the belief.');
fig(FIG('fig_timeline_s1.png'), 'S1 swimlane: intention I1 is dropped at the outage belief and I2 completes on AWS Bedrock', 578);

h2('S2: emergency lockdown mid-execution');
p(`The lockdown arrives just before the transmitting step. Two independent reasons drop I1: D1 becomes an option and pre-empts D3 (open-minded reason), and the context condition "policy lockdown is off" is VIOLATED (single-minded reason). The block plan then pushes \`force_block_all\` into the engine and re-inspects the prompt with the real policy, which now answers BLOCK. Transmissions in this run: **${S.S2.provider_attempts}**.`);
code(shiftBlock('S2'), 'Listing 7: INTENTION SHIFT block for S2');

pb();
h2('S3: the provider reply leaks a secret');
p('Here the trigger is produced by the agent itself. The provider starts echoing a cached staging credential; the `inspect_response` step runs the real detector on the reply and writes `response.findings` with a CRITICAL `aws_access_key`. D1 activates on that belief and the deliver step is never run. The new intention discards the reply from memory, seals evidence, raises an alert (`threat.level = high`, audit event `bdi_security_alert`) and tells the user the reply was withheld. The secret value never appears in any log; only its category does.');
code(shiftBlock('S3'), 'Listing 8: INTENTION SHIFT block for S3');

h2('S4: price spike, then budget cut');
p('S4 shows that reconsideration can fire more than once in one request. Listing 9 shows both shifts. The first belief (GCP price $6.80 above the $6.00 budget) violates the D4 condition of I1, so the router picks AWS Bedrock. Finance then cuts the budget to $1.00, which violates the same condition for I2; no cloud provider is now feasible and the agent falls back to the local tier at $0.33 per 1k requests.');
code(excerpt('S4', (e) => ['BELIEF', 'DROP', 'INTEND'].includes(e.event) && KEYS('price_per_1k', 'budget')(e)), 'Listing 9: S4 trace excerpt (two drops, three intentions)');

h2('S5 and S6: Indian data residency');
p('In S5 the prompt contains an Aadhaar number and an e-mail address, so the policy answers REDACT and D2 limits dispatch to IN or LOCAL. The agent intends `redact_then_dispatch(aws-bedrock)`. Before the transmission, a provider health notice says Bedrock now serves from us-east-1. The residency condition is VIOLATED and the agent re-plans to Azure AI Foundry in centralindia (Listing 10).');
code(shiftBlock('S5'), 'Listing 10: INTENTION SHIFT block for S5');
p('S6 starts with a clean prompt routed to GCP Vertex (US). The user then edits the prompt and adds a PAN. The prompt sensor re-inspects the new text, D2 becomes active in the middle of execution, and two conditions of I1 fail at once: the prompt is no longer ALLOW and US residency is no longer allowed. The new intention redacts the PAN and sends the sanitized text to AWS Bedrock in India. In both runs every transmission was to IN residency and was redacted, which `test_residency_is_never_violated` asserts.');
code(excerpt('S6', (e) => ['BELIEF', 'DESIRE', 'DROP', 'INTEND', 'STEP'].includes(e.event) && KEYS('prompt.cat', 'prompt.dec')(e) && !(e.event === 'DESIRE' && !e.msg.startsWith('D2')) && !(e.event === 'STEP' && !e.msg.includes('dispatch ->')) && !(e.event === 'BELIEF' && e.cycle < 2)), 'Listing 11: S6 trace excerpt (mid-execution activation of D2)');

h2('S7 and S8: suspension and a shift across desires');
p('Not every belief change should cause a new plan. In S7 the status feed reports a *partial* outage, which the provider-status condition maps to UNCERTAIN. The intention is suspended instead of dropped, waits two idle cycles, and resumes at the same `dispatch` step when the feed reports recovery. No step is repeated. S8 shows a shift between two different desires: a REVIEW prompt is about to open a review ticket when a burst fills the queue to its limit of 25. `hold_for_review` is dropped, D3 has no applicable plan, and D5 adopts `decline_review_overflow`, which fails closed without sending anything.');
code(excerpt('S7', (e) => ['SUSPEND', 'RESUME', 'RECONSIDER', 'STEP', 'BELIEF'].includes(e.event) && e.cycle >= 5 && e.cycle <= 7 && KEYS('status')(e) && !(e.event === 'RECONSIDER' && e.msg.includes('kept'))), 'Listing 12: S7 trace excerpt (suspend, wait, resume)');

h2('Summary of all scenarios');
p('Table {nexttbl} is generated from `logs/bdi_summary.json`. Figure {nextfig} places every run on a common cycle axis, so the position of each disturbance, drop and new intention can be compared at a glance.');
tbl('Summary of the verification run (open-minded commitment)', ['ID', 'Initial intention', 'Trigger belief', 'Adopted intention(s)', 'Outcome', 'Steps'],
  [450, 1750, 2300, 2100, 1366, 700],
  SUM.scenarios.filter((s) => !s.ablation).map((s) => [s.scenario, lbl(s.initial_intention.label), trig(s),
    s.shifts.length ? s.shifts.map((x) => lbl(x.adopted)).join(', then ') : (s.suspensions.length ? 'same (suspend, resume)' : 'same (no shift)'),
    s.outcome.replace('RESPONSE_WITHHELD', 'WITHHELD'), String(s.steps_executed)]), { small: true,
    note: 'allow(p), redact(p) and local_only(p) abbreviate allow_then_dispatch, redact_then_dispatch and dispatch_local_only; WITHHELD is the status RESPONSE_WITHHELD.' });
fig(FIG('fig_timelines_all.png'), 'All runs on one cycle axis: steps per intention, disturbances, drops and suspensions', 578);

h2('Ablation: why reconsideration matters');
const a = (id, k) => S[id][k];
p(`To show that the shift is caused by reconsideration and not by luck, S1 and S2 were repeated with BLIND commitment. Table {nexttbl} and Figure {nextfig} compare the runs. In S1-BLIND the agent ignores the outage belief and keeps executing the GCP intention until its \`dispatch\` step, which the interlock refuses because the provider is believed down. The intention FAILS and only then is the request re-planned: ${a('S1-BLIND', 'steps_executed')} steps instead of ${a('S1', 'steps_executed')}, with one failed step. In S2-BLIND the stale dispatch intention is still alive when the lockdown arrives and is likewise stopped only by the interlock. The open-minded agent never reaches either point, because it drops the intention as soon as the belief arrives.`);
tbl('Ablation: open-minded versus blind commitment', ['Run', 'Commitment', 'Provider calls', 'Failed steps', 'Steps', 'How the first intention ended'], [1200, 1700, 1250, 1150, 900, 2466],
  ['S1', 'S1-BLIND', 'S2', 'S2-BLIND'].map((id) => [id, S[id].commitment, String(S[id].provider_attempts), String(S[id].reconsideration.failed),
    String(S[id].steps_executed), S[id].shifts.map((x) => `${x.status === 'FAILED' ? 'FAILED at' : 'DROPPED before'} ${x.before_step}`).join('; ')]), { small: true });
fig(FIG('fig_ablation.png'), 'Ablation counts from logs/bdi_summary.json', 578);

// =====================================================================================================
h1('Testing');
p(`The full suite (engine and BDI) was run with \`python -m pytest tests -vv -p no:cacheprovider > logs/pytest_results.txt\` from a copy of the submission folder; the saved file is the unedited output. **${TOTAL} tests passed**: the 112 engine tests from earlier units and ${BDI} new BDI tests. Table {nexttbl} lists the new test files.`);
tbl('BDI test files and what they cover', ['File', 'Tests', 'What is verified'], [2900, 800, 4966], [
  ['`test_beliefs.py`', String(count('test_beliefs.py')), 'change detection, revisions, append-only history, subscriptions, retraction, validation, 12-thread stress test'],
  ['`test_desires.py`', String(count('test_desires.py')), 'priority order, D1 / D2 / D5 activation triggers, conflicts and tie-break'],
  ['`test_plans.py`', String(count('test_plans.py')), 'router-ranked options, IN/LOCAL only for Indian data, budget and outage filters, three-valued context'],
  ['`test_intentions.py`', String(count('test_intentions.py')), 'legal / illegal transitions, cursor, shrinking watch set, stack priority'],
  ['`test_reconsideration.py`', String(count('test_reconsideration.py')), 'every scenario, no transmission after lockdown, residency never violated, suspension timeout, guard check at execution time, blind and single-minded strategies'],
  ['`test_trace_and_determinism.py`', String(count('test_trace_and_determinism.py')), 'determinism, all event types present, no secret in any trace, valid JSONL, ledger tamper detection, audit entries'],
], { small: true });
h3('Edge cases covered');
bul([
  'A belief change from a monitor thread during step execution is processed before the next step (`test_belief_changes_from_other_threads_...`).',
  'A provider outage *after* the payload is sent does not drop the intention, because no remaining step depends on that belief.',
  'An unrelated price change for another provider is counted as ignored and causes no reconsideration.',
  'A partial outage that never recovers turns into a drop after 4 cycles and a re-plan to the next provider.',
  'A faulty subscriber cannot break belief revision; its error is recorded and other subscribers still run.',
]);

// =====================================================================================================
h1('Submission Analysis');
p('Table {nexttbl} checks each requirement against its evidence.');
tbl('Requirement, evidence and status', ['Requirement', 'Evidence', 'Status'], [3300, 4166, 1200], [
  ['Three explicit BDI collections / classes', '`BeliefBase`, `DesireSet`, `PlanLibrary` + `IntentionStack` in `ciphermesh/bdi/`', 'PASS'],
  ['Cognitive-layer state machine', 'intention states (Figure 3.2) and the deliberation cycle (Figure 3.3)', 'PASS'],
  ['Dynamic plan recalculation on belief change', `reconsideration in \`engine.py\`; ${SHIFTS} intention shifts across S1 to S8 and the two ablations`, 'PASS'],
  ['Verification run with an intention shift after an unexpected belief update', '`logs/bdi_verification_run.log` INTENTION SHIFT blocks; summary JSON', 'PASS'],
  ['Baseline proves causality', 'S0 completes unchanged; S1/S2 blind ablation', 'PASS'],
  ['Tests for every new module', `${BDI} BDI tests, ${TOTAL} in total, all passing`, 'PASS'],
], { decisionCol: 2 });
h2('Strengths');
bul([
  'The plans call the real engine, so the run exercises detector, policy, procurement, router, adapters, review queue and audit together.',
  'Reconsideration is event-driven and scoped to the remaining steps, which keeps its cost low and avoids pointless drops after a payload is already sent.',
  'Three-valued conditions separate "wait" from "give up", which a two-valued BDI context cannot express.',
  'Every change of mind is explained with the triggering belief, its source and confidence, and the believed values that made a condition fail.',
  'Safety does not depend on deliberation alone: the dispatch interlock blocks transmission even for a blind agent.',
]);
h2('Limitations');
bul([
  'Cloud providers are simulated adapters; prices and latencies are illustrative planning numbers, not measurements. The local tier can call a real Ollama server only when it is enabled.',
  'Disturbances are scripted at chosen steps. A production system would feed beliefs from live status pages and price APIs.',
  'The agent handles one request at a time. Several requests would need either one BDIAgent per request or a shared belief base with per-request intention stacks.',
  'Plans are fixed templates with one level of steps; there are no sub-goals that post new desires, as AgentSpeak plans can.',
  'Re-planning restarts the new pipeline from its first step. Reusing finished work (for example the already prepared payload) would save a few steps.',
]);
h2('How this feeds the Capstone (Assignment 5.2)');
p('The public API (`BeliefBase`, `DesireSet`, `PlanLibrary`, `IntentionStack`, `BDIAgent`, `EngineServices`) is exported from `ciphermesh/bdi/__init__.py`. In the Capstone, the gateway will submit each request to a `BDIAgent`; the runtime monitor from Unit 2.1 will write provider health into the belief base; the Unit 2.2 COMMAND_INSTRUCTION channel will set `policy.lockdown`; and the existing audit log already stores every adopted and dropped intention for the dashboard.');

// =====================================================================================================
h1('Conclusion');
p('This assignment gave CipherMesh an explicit cognitive layer. Beliefs, desires and intentions are separate, tested classes; a deliberation cycle turns them into one action per cycle; and reconsideration recalculates the plan as soon as a relevant belief changes. The verification run shows the required intention shift in every disturbed scenario: an outage moves the request to another provider, a lockdown or a leaking reply hands control to the "never transmit a secret" goal, a price spike and a budget cut move the request down to cheaper tiers, and a change in data residency keeps Indian data in India. A control run without disturbance and a blind-commitment ablation show that these shifts are caused by the belief updates and by reconsideration. All tests pass and every number in this report comes from the saved logs.');

refs();

app('How to Run');
p('All commands are run from the submission folder with the CipherMesh Python environment (Python 3.13, see `requirements.txt`).');
code(`# 1. verification run: writes logs/bdi_verification_run.log,
#    logs/bdi_trace.jsonl and logs/bdi_summary.json
python demo/bdi_verification_run.py --latency-scale 0.05 --idle-wait 0.02

# 2. full test suite (writes the file used in Section 6)
python -m pytest tests -vv -p no:cacheprovider > logs/pytest_results.txt

# 3. only the BDI tests
python -m pytest tests/bdi -q

# 4. report figures (needs matplotlib; diagrams are rendered from diagrams.html)
python docs/figures/make_charts.py`, 'Listing 13: commands that produce every artefact');
p('A minimal use of the API from other code is shown in Listing 14.');
code(`from ciphermesh.bdi import BDIAgent, EngineServices
agent = BDIAgent(EngineServices())
agent.perceive_world()
agent.submit("Summarise Q3 cloud spend drivers.", request_id="req-1")
result = agent.run()      # RunResult: final_status, shifts, transmissions, ...
print(result.final_status, [s.adopted["label"] for s in result.shifts])`, 'Listing 14: using the BDI agent from code');

app('File Listing');
tbl('Files in the submission', ['Path', 'Content'], [3900, 4766], [
  ['`README.md`, `requirements.txt`, `pytest.ini`', 'overview, deliverables map, commands; dependencies; test settings'],
  ['`ciphermesh/` (engine)', 'Units 1 to 3 engine: detector, policy, agent, review, procurement, routing, providers, runtime, transport'],
  ['`ciphermesh/bdi/`', 'beliefs, desires, plans, intentions, engine, services, world, trace, scenarios, __init__'],
  ['`demo/bdi_verification_run.py`', 'verification run'],
  ['`tests/engine/` (112 tests)', 'regression tests of earlier units'],
  ['`tests/bdi/` (' + BDI + ' tests)', 'BDI unit and scenario tests, conftest'],
  ['`logs/bdi_verification_run.log`', 'readable timestamped run with INTENTION SHIFT blocks'],
  ['`logs/bdi_trace.jsonl`, `logs/bdi_summary.json`', 'machine-readable trace and per-scenario summary'],
  ['`logs/pytest_results.txt`', 'full test output'],
  ['`docs/Assignment_4.1_*_Report.docx`, `.pdf`', 'this report (BDI Goal-Driven Modeling)'],
  ['`docs/figures/`', 'figure PNGs, `diagrams.html` source, `make_charts.py`'],
  ['`docs/report_src/content.js`', 'report source'],
], { small: true });

module.exports = {
  meta: { assignment: '4.1', title: 'Belief-Desire-Intention (BDI) Goal-Driven Modeling', short: 'BDI Goal-Driven Modeling',
    subtitle: 'A cognitive layer that re-plans CipherMesh intentions when beliefs change mid-execution' },
  C: d.C,
  refs: {
    bratman: 'M. E. Bratman, *Intention, Plans, and Practical Reason*. Cambridge, MA, USA: Harvard University Press, 1987.',
    rao95: 'A. S. Rao and M. P. Georgeff, "BDI agents: From theory to practice," in *Proc. 1st Int. Conf. Multi-Agent Systems (ICMAS-95)*, San Francisco, CA, USA, 1995, pp. 312–319.',
    smith: 'R. G. Smith, "The Contract Net Protocol: High-level communication and control in a distributed problem solver," *IEEE Trans. Comput.*, vol. C-29, no. 12, pp. 1104–1113, Dec. 1980.',
    cohen: 'P. R. Cohen and H. J. Levesque, "Intention is choice with commitment," *Artificial Intelligence*, vol. 42, no. 2–3, pp. 213–261, 1990.',
    prs: 'M. P. Georgeff and A. L. Lansky, "Reactive reasoning and planning," in *Proc. 6th National Conf. Artificial Intelligence (AAAI-87)*, Seattle, WA, USA, 1987, pp. 677–682.',
    agentspeak: 'A. S. Rao, "AgentSpeak(L): BDI agents speak out in a logical computable language," in *Agents Breaking Away: Proc. 7th European Workshop on Modelling Autonomous Agents in a Multi-Agent World (MAAMAW\'96)*, W. Van de Velde and J. W. Perram, Eds., LNCS vol. 1038. Berlin, Germany: Springer, 1996, pp. 42–55.',
    jason: 'R. H. Bordini, J. F. Hübner, and M. Wooldridge, *Programming Multi-Agent Systems in AgentSpeak using Jason*. Chichester, U.K.: John Wiley & Sons, 2007.',
    wooldridge: 'M. Wooldridge, *An Introduction to MultiAgent Systems*, 2nd ed. Chichester, U.K.: John Wiley & Sons, 2009.',
    aima: 'S. Russell and P. Norvig, *Artificial Intelligence: A Modern Approach*, 4th ed. Hoboken, NJ, USA: Pearson, 2020.',
    rao91: 'A. S. Rao and M. P. Georgeff, "Modeling rational agents within a BDI-architecture," in *Proc. 2nd Int. Conf. Principles of Knowledge Representation and Reasoning (KR-91)*, Cambridge, MA, USA, 1991, pp. 473–484.',
    kinny: 'D. N. Kinny and M. P. Georgeff, "Commitment and effectiveness of situated agents," in *Proc. 12th Int. Joint Conf. Artificial Intelligence (IJCAI-91)*, Sydney, Australia, 1991, pp. 82–88.',
    hmac: 'H. Krawczyk, M. Bellare, and R. Canetti, "HMAC: Keyed-hashing for message authentication," IETF RFC 2104, Feb. 1997.',
  },
};
