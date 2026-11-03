// Report content for Assignment 4.2 - Knowledge Representation and Adaptive API Integration
// Author: Kumar Waibhav Akshat (RA2212704010027)
// Every number, log excerpt and code excerpt below is read from the real files in ../.. at build time.
const fs = require('fs');
const path = require('path');
const { makeDoc } = require(path.join(process.env.REPORTKIT || path.resolve(__dirname, '../../../reportkit'), 'dsl.js'));
const d = makeDoc(); const { h1, h2, h3, p, tbl, bul, num, fig, code, call, refs, app } = d;

const ROOT = path.resolve(__dirname, '../..');
const FIG = (f) => path.join(ROOT, 'docs/figures', f);
const read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8');
const REC = JSON.parse(read('logs/demo_record.json'));
const EPR = JSON.parse(read('logs/live_endpoints_report.json'));
const EVENTS = read('logs/adaptation_events.jsonl').trim().split('\n').map(JSON.parse);
const LOG = read('logs/live_feed_run.log').split('\n');
const BT = JSON.parse(read('logs/kev_backtest.json'));
const PYTEST = read('logs/pytest_results.txt');
const TOTAL = (PYTEST.match(/(\d+) passed/) || [0, '?'])[1];
const count = (pfx) => (PYTEST.match(new RegExp(`${pfx}[^\\n]*? PASSED`, 'g')) || []).length;
const KN = count('tests/knowledge/'); const EN = count('tests/engine/');
const S = REC.phase_a.summary; const PB = REC.phase_b; const PROPS = PB.properties;
const EP = Object.fromEntries(EPR.endpoints.map((e) => [e.feed, e]));
const LIVE_EV = EVENTS.filter((e) => !e.replay); const REP_EV = EVENTS.filter((e) => e.replay);
const fmt = (n, k = 1) => Number(n).toLocaleString('en-US', { maximumFractionDigits: k, minimumFractionDigits: k });
const kib = (b) => (b >= 1024 ? `${fmt(b / 1024)} KiB` : `${b} B`);

// ---- helpers for real excerpts -------------------------------------------------------------------
const wrap = (line, n = 86) => { const r = []; let t = line;
  while (t.length > n) { let k = t.lastIndexOf(' ', n); if (k < 30) k = n; r.push(t.slice(0, k)); t = '      ' + t.slice(k).trimStart(); }
  r.push(t); return r; };
const clean = (l) => l.replace(/^\d{4}-\d{2}-\d{2} (\d{2}:\d{2}:\d{2}\.\d{3})Z \| INFO  \| /, '$1 ');
function logBlock(startPat, endPat, keep = () => true, max = 40, squeeze = false) {
  const i = LOG.findIndex((l) => l.includes(startPat));
  const out = [];
  for (let n = i; n < LOG.length && out.length < max; n++) {
    if (n > i && endPat && LOG[n].includes(endPat)) break;
    if (!keep(LOG[n])) continue;
    const line = clean(LOG[n]);
    out.push(...wrap(squeeze ? line.replace(/ {3,}/g, '  ') : line));
  }
  return out.join('\n');
}
function src(file, startPat, nLines, dedent = 0, before = 0) {
  const L = read(file).split('\n'); const i = L.findIndex((l) => l.includes(startPat));
  if (i < 0) throw new Error(`pattern not found in ${file}: ${startPat}`);
  return L.slice(i - before, i + nLines).map((l) => l.slice(dedent)).join('\n');
}
const plan = (ph, k) => (ph === 'a' ? REC.phase_a.plans[k] : REC.phase_c.plans[k]);
const rt = (p) => (p.selected ? `${p.selected}` : p.route_status);
// Same rounding as the Python log (round-half-even on the binary value): 76.225 -> 76.22
const r2 = (x) => (Math.round(x * 100 - 1e-7) / 100).toFixed(2);
const U = (p) => (p.utility === null || p.utility === undefined ? '-' : r2(p.utility));
const PROMPTS = Object.keys(REC.phase_a.plans);
const kev = EP.cisa_kev.signals; const fx = EP.fx_usd_inr.signals; const ai = EP.aiid_rss.signals;
const replayKev = REP_EV.find((e) => e.feed === 'cisa_kev').signals;
const PD = REC.phase_d; const PC = REC.phase_c;
const lines = (dir) => { let n = 0; for (const f of fs.readdirSync(path.join(ROOT, dir), { recursive: true }))
  if (String(f).endsWith('.py')) n += read(path.join(dir, String(f))).split('\n').length - 1; return n; };
const SRC_LINES = lines('ciphermesh/knowledge'); const TEST_LINES = lines('tests/knowledge');

// =====================================================================================================
h1('Introduction');
h2('Objective');
p('This assignment gives CipherMesh, the privacy control plane that sits between enterprise applications and AI providers, a **formal knowledge base** and connects that knowledge base to **live public data**. The brief asks for three things: a structured format that stores the agent\'s domain knowledge, an integration with real-world REST endpoints that feed the agent real knowledge, and a parsing module that changes the agent\'s properties and plans as soon as new live data arrives.');
p('The knowledge base is an ontology written as a JSON-LD 1.1 style document [@jsonld] with classes, individuals and typed relations in the spirit of OWL 2 [@owl2] and RDF Schema [@rdfs]. Following Gruber\'s definition of an ontology as an explicit specification of a shared conceptualisation [@gruber], every fact the router and the policy engine previously kept as Python constants (where each provider runs, which data categories are regulated, what each rule decides) is now stated once, in a file that a program can validate and reason over [@aima].');
h2('The problem in CipherMesh terms');
p('Up to Unit 3.2 CipherMesh planned with frozen assumptions. The router always believed that every provider was healthy, that prices in US dollars matched an Indian budget, and that the security climate never changed. The rule "Aadhaar, PAN or an Indian phone number may only go to an Indian or local provider" was a hard-coded Python set. None of this is true in production. Vertex AI has incidents, the rupee moves, and new exploited vulnerabilities appear every week. A privacy gateway that ignores these facts either sends data to a degraded endpoint or keeps a loose policy while attackers are busy.');
p('This unit answers the question: *how can the agent learn about the outside world, store that knowledge with its source and age, and change its plan at once?* The answer has four parts: an ontology, six live connectors, an adapter that turns parsed facts into properties, and an adaptive agent that re-plans whenever a property changes.');
h2('How this unit builds on Units 1-3');
p('Table {nexttbl} shows what is reused. Nothing in the engine was rewritten; the new subpackage `ciphermesh/knowledge/` calls the existing modules, and all ' + EN + ' engine tests still pass.');
tbl('Earlier CipherMesh units reused by Assignment 4.2', ['Unit', 'Engine part', 'How 4.2 uses it'], [1500, 2900, 4266], [
  ['1.1 / 1.2', 'PEAS model, detector (25 rules, D1-D12), policy R1-R5', 'Every detector category and rule is an ontology individual; `plan_for` calls the real `inspect_text`'],
  ['2.1', 'Threads, locks, daemon runtime', '`AgentProperties` and `KnowledgeGraph` are thread-safe (RLock) and tested with concurrent writers'],
  ['2.2', 'Typed wire models, `AgentState`, `CipherMeshAgent`', 'Derived policy settings are written into a real `AgentState`; `sync_engine_agent` pushes them into a running agent'],
  ['3.1', 'Contract-Net procurement', 'Not used in this unit\'s demo (list prices). Capstone hook: negotiated prices enter the same `route` call through `contract_prices`, under the live FX budget'],
  ['3.2', 'Constrained utility router U = 0.30Q + 0.25C + 0.20L + 0.15A + 0.10P', 'Called unchanged; live knowledge changes its inputs: profiles, budget, residency, exclusions'],
], { small: true });

// =====================================================================================================
h1('Assignment Requirements and Traceability');
p('Table {nexttbl} quotes each line of the brief word for word and maps it to the code that satisfies it and to the evidence file a reviewer can open. The last row is an extra design requirement set for this project; it is not part of the brief.');
tbl('Requirement traceability', ['Brief line (verbatim)', 'Where satisfied', 'Evidence'], [3300, 2700, 2666], [
  ['Objective: "Enhance your agent\'s knowledge base through semantic knowledge representation or integration with external data APIs."', '`ciphermesh/knowledge/` (ontology + live feeds)', 'Sections 3-5; `logs/live_feed_run.log`'],
  ['Direction: "Implement a structured configuration format (JSON, Dictionary objects, or an ontological graph) to formally store your agent\'s domain knowledge."', '`ontology.json` (JSON-LD), `ontology.schema.json`, `ontology.py`, `graph.py`', '`test_ontology.py`, `test_graph.py`; Phase A of the run log'],
  ['Direction: "Integrate an external real-world REST API to feed the agent real knowledge maps (e.g., real live OpenWeather API maps for Travel planners, or real Geolocation maps for WiFi searches)."', '`knowledge/feeds/`: six connectors on public endpoints', '`logs/live_endpoints_report.json`, `data/snapshots/*.meta.json`'],
  ['Direction: "Enable the agent to dynamically adapt its internal plans based on the live unstructured data ingested."', '`feeds/ai_incidents.py`, `normalize.py`, `adapter.py`, `posture.py`, `adaptive_agent.py`', 'Phase C diff and leave-one-feed-out attribution; `test_adaptive_agent.py`'],
  ['Deliverables: "Code integration module demonstrating active connection to live endpoints and a parsing module changing agent properties instantly based on live feeds."', '`feeds/base.py` + connectors; parsers, `KnowledgeAdapter`, `AgentProperties`', 'Phase B log; `logs/adaptation_events.jsonl` (property changes, latencies)'],
  ['Additional design requirement (not in brief): residency rule derivable from the graph', '`KnowledgeGraph.derive_residency`', 'Equivalence tests (25 categories, 300 pairs); `EQUAL=True` in the log'],
], { small: true, split: true });

// =====================================================================================================
h1('Design');
h2('Architecture');
p('Figure {nextfig} shows the live data path. Each public endpoint has one connector. Connectors share a hardened HTTP client, a time-to-live cache and a snapshot store. Their raw bytes go through a safe parser and a normaliser whose vocabulary comes from the ontology itself. The adapter turns every parsed **fact** into a graph triple and every **signal** into an agent property, then evaluates two derived rules whose thresholds are also stored in the ontology. The adaptive agent subscribes to the properties and rebuilds its plan context inside the same call that changed the property.');
fig(FIG('fig_pipeline.png'), 'Live knowledge pipeline from public endpoint to agent plan', 578);
p('The design keeps three kinds of state apart. The **knowledge graph** holds what the agent knows, with provenance. The **properties** hold the few control values that plans depend on. The **plan context** is derived from both and is never edited by hand. This separation makes every plan change explainable: a changed plan always has a property change behind it, and every property change names its source feed and confidence.');
h2('Ontology');
p('Table {nexttbl} lists the main individuals of the ontology, and Figure {nextfig} shows its 16 most important classes with the typed relations between them. Solid arrows are asserted in `ontology.json`; dashed orange arrows are relations whose value is replaced at run time from live feeds. Sub-classes are listed inside the boxes (for example `ResidencyPolicy` is a sub-class of `OrganisationalPolicy`, which is a sub-class of `LegalInstrument`).');
p(`The file declares ${S.classes} classes, 24 object properties and 44 datatype properties, and ${S.subjects} subjects in total. After loading, the graph holds ${fmt(S.triples, 0)} triples: ${S.by_asserted} asserted and ${S.by_inferred} inferred by RDFS rules. Every provider individual matches the engine profile in \`providers.py\` field by field, and a test checks this.`);
p('The ontology is validated in two layers. The JSON Schema (draft 2020-12 [@jsonschema]) checks structure: required header fields, a semantic version, CURIE syntax for every identifier, and the allowed value shapes. Semantic validation then checks what a schema cannot express: every referenced IRI is defined, every object-property value is an instance of the declared `rdfs:range`, functional properties have one value per subject, and there are no sub-class cycles.');
tbl('Main individuals in ontology.json', ['Class', 'Count', 'Individuals (examples)'], [2300, 900, 5466], [
  ['Provider', String(S.providers), 'aws-bedrock (ap-south-1, IN), azure-ai (centralindia, IN), gcp-vertex (us-central1, US), local (on-host, LOCAL)'],
  ['CloudRegion / Jurisdiction', `${S.regions} / ${S.jurisdictions}`, 'ap-south-1, centralindia, us-central1, on-host / IN, US, EU, LOCAL'],
  ['DataCategory / DetectorFamily', `${S.data_categories} / ${S.detector_families}`, 'aadhaar memberOf D10, pan memberOf D11, phone_in memberOf D6, llm_api_key memberOf D4 ...'],
  ['LegalInstrument', String(S.legal_instruments), 'DPDP Act 2023 [@dpdp], Aadhaar Act 2016 [@aadhaar], GDPR [@gdpr], CipherMesh India residency policy'],
  ['PolicyRule / Decision', `${S.policy_rules} / 4`, 'LOCKDOWN, R5, R1, R3, R2, R4 (priority + precedes) / ALLOW, REDACT, REVIEW, BLOCK'],
  ['Threat / ThreatPosture', `${S.threat_classes} / 3`, 'credential-leak, pii-exposure, cross-border-transfer ... / LOW, ELEVATED, HIGH with thresholds'],
  ['InformationSource / Vendor', `${S.live_sources} / ${S.watched_vendors}`, 'gcp-status, azure-status, aws-health, cisa-kev, frankfurter, aiid / Amazon, Microsoft, Google, Linux ...'],
], { small: true, split: true });
fig(FIG('fig_ontology.png'), 'CipherMesh ontology: main classes and typed relations', 578);
p('Listing 1 is the real provider node for AWS Bedrock. The `@context` declares `hostedIn` with `"@type": "@id"`, so the string value is read as a link to the region node; `costPer1kUsd` is declared as `xsd:decimal`, so 2.8 becomes a typed literal. This is JSON-LD type coercion [@jsonld], and it lets the file stay plain JSON [@rfc8259] while still meaning a graph.');
code(src('ciphermesh/knowledge/ontology.json', '"@id": "cm:provider/aws-bedrock"', 20, 2, 1), 'Listing 1: provider individual in ontology.json');
h2('Data model');
p('Table {nexttbl} lists the run-time data structures. Each one carries enough provenance to answer "where did this come from and when?".');
tbl('Run-time data model', ['Structure', 'Fields', 'Purpose'], [1900, 3700, 3066], [
  ['`Provenance`', 'source, fetched_at, confidence, method (asserted / live / inferred / derived), evidence', 'Attached to every triple in the graph'],
  ['`Fact`', 'subject, predicate, obj, obj_is_iri, source, fetched_at, confidence, evidence', 'One statement extracted by a parser'],
  ['`ParseReport`', 'items_seen, items_relevant, facts, signals, warnings, parse_ms', 'Parser output for one feed'],
  ['`FetchResult`', 'url, final_url, mode (live / cache / snapshot / replay-file), status, bytes, sha256, original_sha256, latency_ms, fetched_at, age_s, stale', 'Network evidence for one request'],
  ['`PropertyChange`', 'seq, key, old, new, source, confidence, at, mono_ns', 'One entry in the property history'],
  ['`AdaptationEvent`', 'fetch evidence, facts, triples added / replaced, property changes, plan versions, timings_ms', 'One line in `adaptation_events.jsonl`'],
  ['`PlanContext` / `Plan`', 'effective profiles, constraints, policy state, posture / decision, route, utility, reasons', 'What the agent will do with a prompt'],
], { small: true });
h2('Algorithms');
h3('A1. Residency derivation from the graph');
num([
  'Detect categories in the prompt with the engine detector (for example `aadhaar`, `email`).',
  'For each category, collect the category node and the family it is `memberOf`.',
  'For each of these holders, follow `governedBy` to legal instruments. Keep only instruments that are (by inference) a `ResidencyPolicy` and that have `requiresResidency` values.',
  'Map the required jurisdictions to codes and intersect them across all applicable policies (strictest wins, so adding data can only narrow the set).',
  'Return the allowed jurisdictions, the list of allowed providers (provider -> hostedIn -> locatedIn) and a human-readable inference chain.',
]);
p('Only `aadhaar` (via family D10), `pan` (via family D11) and `phone_in` (directly) reach the residency policy, so the derived set is exactly the engine\'s `INDIA_PERSONAL_DATA`. A test checks this for all 25 single categories and all 300 pairs. Regulations such as the DPDP Act and GDPR are also linked to categories, but they carry no residency requirement, which matches the law: Section 16 of the DPDP Act allows transfers except to countries the government restricts [@dpdp]. The India-only rule is therefore modelled honestly as an organisational policy that is `basedOn` the statutes.');
h3('A2. Fetch, parse, then snapshot (with fallback)');
num([
  'Refuse any URL that is not HTTPS (plain HTTP is accepted only for loopback test servers). A redirect handler applies the same check to every hop and refuses redirects to another host; the final URL is recorded.',
  'Return the cached response if it is younger than the feed TTL from the ontology (`cm:ttlSeconds`).',
  'Send a GET with a descriptive User-Agent, TLS 1.2 or newer and certificate verification, a per-attempt timeout and an overall deadline (60 s); read the body in 64 KiB chunks up to a size cap (8 MiB).',
  'Retry network errors and HTTP 429 / 5xx with exponential back-off; do not retry other 4xx codes [@rfc9110].',
  '**Parse first.** Only a payload that parses is stored. Feeds with third-party prose keep a text-free *derivative* (structured fields plus the tokens the parser read); the meta file records the original URL, status, bytes, SHA-256 and fetch time. The exchange rate (a number and a date) is stored raw.',
  'If the network fails or a 200 response cannot be parsed (for example an HTML error page), load the previous snapshot, verify its hash and mark the result as a fallback. A snapshot older than `cm:maxSnapshotAgeSeconds` (24 h for status feeds, 7 days otherwise) is marked stale and its confidence is multiplied by 0.4, which puts it below the 0.5 acceptance gate of the properties.',
])
h3('A3. Parsing messy status text');
num([
  'Decode safely: honour UTF-8 and UTF-16 byte-order marks; refuse XML that contains a DTD or entity declaration (billion-laughs and XXE defence [@owasp]).',
  'Keep only records inside the time window: active at `as_of`, or resolved within the feed\'s look-back days.',
  'Clean HTML, decode entities, apply Unicode NFKC and collapse spaces.',
  'Find regions: structured location fields first, then vendor region-code patterns, then display names and aliases taken from the ontology ("Central India", "Asia Pacific (Mumbai)"); zones such as `us-central1-b` collapse to their region.',
  'Find services through the provider\'s `cm:serviceAlias` values, and classify severity with keyword classes (outage, degraded, resolved).',
  'A record affects a provider only if both the service and the provider\'s region match (confidence 0.85-0.9); a "global" or "multiple regions" scope is accepted with confidence 0.6.',
]);
h3('A4. Derived rules: budget and threat posture');
num([
  'Budget: `max_cost_per_1k_usd = budgetPer1k (INR, from the agent profile) / live USD-INR rate`.',
  'Posture evidence is grouped into three independent signals: **KEV volume** (30-day additions divided by the median of the 12 previous 30-day windows), **KEV stack** (watched-vendor, AI/ML-product or ransomware-linked additions) and **AI incidents** (privacy-related reports per covered day; the feed lists only its newest 100 items, so the count is divided by the days those items actually cover).',
  'A group is met when one of its values reaches the posture\'s threshold. ELEVATED needs one group, HIGH needs two (`cm:minSignals`). Postures are visited from the highest level down; LOW is the default.',
  'Hysteresis: while the agent is already at a level, thresholds for that level and below are multiplied by `cm:hysteresisFactor` (0.9), so the posture does not flap.',
  'The chosen posture\'s effects come from the ontology: R5 byte limit, extra redaction patterns, residency limit for all traffic, and a lockdown recommendation. Lockdown is never applied automatically; a human decides.',
])
p(`The KEV thresholds were calibrated, not guessed. The parser was run on the pinned catalog every 3 days from ${BT.from} to ${BT.to} (${BT.dates} dates), and each threshold is the smallest value reached on at most 10 % (ELEVATED) or 3 % (HIGH) of those dates. Table {nexttbl} shows the result and Figure {nextfig} the posture the rule would have produced. The first, uncalibrated thresholds put the agent in HIGH on ${Math.round(BT.before.share.HIGH * 100)} % of days, which made the signal useless; the calibrated rule is HIGH on ${(BT.after.share.HIGH * 100).toFixed(1)} % and ELEVATED on ${Math.round(BT.after.share.ELEVATED * 100)} %. The AI-incident threshold (0.5 privacy reports per day for ELEVATED, 1.0 for HIGH) cannot be backtested because the feed has no history; it is a stated judgement value and can supply only one of the two signals HIGH needs.`);
tbl('KEV backtest and calibrated thresholds (logs/kev_backtest.json)', ['Signal', 'p50', 'p90', 'p97', 'Max', 'ELEVATED >=', 'HIGH >=', 'Days >= E / H'], [2400, 750, 750, 750, 750, 1150, 1000, 1116],
  [['ratio', 'minKevRatio', 'KEV volume ratio'], ['relevant_hits', 'minRelevantHits', 'Watched-vendor hits'],
    ['ai_ml_hits', 'minAiMlHits', 'AI/ML-product hits'], ['ransomware_hits', 'minRansomwareHits', 'Ransomware-linked hits']]
    .map(([k, attr, name]) => { const q = BT.percentiles[k]; const ex = BT.exceedance[k];
      return [name, String(q.p50), String(q.p90), String(q.p97), String(q.max), String(BT.calibrated.ELEVATED[attr]),
        String(BT.calibrated.HIGH[attr]), `${(ex.elevated * 100).toFixed(1)} / ${(ex.high * 100).toFixed(1)} %`]; })
    .concat([['Posture share (uncalibrated)', '', '', '', '', `${Math.round(BT.before.share.ELEVATED * 100)} %`, `${Math.round(BT.before.share.HIGH * 100)} %`, `LOW ${Math.round(BT.before.share.LOW * 100)} %`],
      ['Posture share (calibrated)', '', '', '', '', `${Math.round(BT.after.share.ELEVATED * 100)} %`, `${(BT.after.share.HIGH * 100).toFixed(1)} %`, `LOW ${Math.round(BT.after.share.LOW * 100)} %`]]),
  { small: true });
fig(FIG('fig_backtest.png'), 'KEV backtest: 30-day ratio, watched-vendor hits and the calibrated posture over one year', 560);
h3('A5. Reactive re-planning');
p('`AgentProperties.set` stores the value, appends a `PropertyChange` and calls subscribers synchronously. The adaptive agent\'s subscriber rebuilds the plan context: provider profiles adjusted by status (`cm:availabilityPenalty`, `cm:latencyFactor`, `cm:excludesProvider` from the status individual), the policy state (byte limit, custom patterns re-checked by the engine\'s own regex guardrail), and the routing constraints (budget, residency). The latency from the property change to the new plan is measured with a monotonic clock.');

// =====================================================================================================
h1('Implementation');
h2('Modules');
p(`Table {nexttbl} lists the new subpackage. It adds ${fmt(SRC_LINES, 0)} lines of source code and ${fmt(TEST_LINES, 0)} lines of tests; the engine modules from Units 1-3 are untouched.`);
tbl('Modules of ciphermesh/knowledge/', ['File', 'Purpose', 'Key classes / functions'], [2700, 3100, 2866], [
  ['`ontology.json`, `ontology.schema.json`', 'Formal knowledge base and its JSON Schema', `${S.subjects} nodes; draft 2020-12 schema`],
  ['`ontology.py`', 'Load, validate, compile to triples', '`load_graph`, `schema_errors`, `semantic_errors`, `summary`'],
  ['`graph.py`', 'Triple store with provenance, inference and export', '`KnowledgeGraph`, `Literal`, `Provenance`, `derive_residency`, `to_svg`'],
  ['`properties.py`', 'Property sink protocol and observable store', '`PropertySink`, `AgentProperties`, `PropertyChange`'],
  ['`adapter.py`', 'Facts to triples, signals to properties, derived rules', '`KnowledgeAdapter.ingest`, `derive`, `AdaptationEvent`'],
  ['`posture.py`, `calibration.py`', 'Posture rule (signal groups, hysteresis, attribution); KEV backtest', '`decide`, `attribution`, `kev_series`, `calibrate`'],
  ['`adaptive_agent.py`', 'Agent wrapper that re-plans on change', '`AdaptiveCipherMeshAgent.plan_for`, `update_from`, `replay_file`'],
  ['`feeds/base.py`', 'HTTP client, cache, snapshots, connector base', '`HttpFetcher`, `TTLCache`, `SnapshotStore`, `FeedConnector`'],
  ['`feeds/safe_xml.py`, `normalize.py`', 'Hostile-input-safe RSS; text normalisation', '`parse_rss`, `UnsafeXMLError`, `Normaliser`, `classify_impact`'],
  ['`feeds/gcp_status.py`, `azure_status.py`, `aws_health.py`', 'Provider status connectors', '`GcpStatusConnector`, `AzureStatusConnector`, `AwsHealthConnector`'],
  ['`feeds/cisa_kev.py`, `fx_rates.py`, `ai_incidents.py`', 'Threat and market connectors', '`CisaKevConnector`, `FxRateConnector`, `AiIncidentConnector`'],
], { small: true });
h2('Key code');
p('Listing 2 is the core of the residency derivation in `graph.py`. It walks the graph instead of reading a Python constant, so adding a new regulated category is a one-line change in the ontology.');
code(src('ciphermesh/knowledge/graph.py', 'for name in cats:', 17, 4), 'Listing 2: residency derivation (graph.py)');
p('Listing 3 shows how the threat posture is chosen. Thresholds, the number of independent signals and the hysteresis factor are read from the ontology, so the policy can be tuned without changing code.');
code(src('ciphermesh/knowledge/posture.py', 'for spec in specs:', 18, 4), 'Listing 3: posture rule (posture.py)');
p('Listing 4 shows the two-pass XML guard. The raw bytes are rejected if they contain a DTD, and the expat handlers raise as a second layer before the element tree is built.');
code(src('ciphermesh/knowledge/feeds/safe_xml.py', 'def parse_xml', 15), 'Listing 4: refusing DTDs and entities (safe_xml.py)');
p('Table {nexttbl} lists the agent properties written by the adapter. Observed properties come straight from a feed; derived properties name the rule or ontology node that produced them.');
tbl('Agent properties and their sources', ['Property key', 'Kind', 'Source', 'Value after live run'], [3500, 1000, 2400, 1766], [
  ['`provider.<id>.status`', 'observed', 'gcp / azure / aws status feeds', 'operational (x3)'],
  ['`fx.usd_inr`', 'observed', 'Frankfurter (ECB rates)', String(PROPS['fx.usd_inr'])],
  ['`threat.kev.ratio`, `.relevant_hits`', 'observed', 'CISA KEV', `${PROPS['threat.kev.ratio']}, ${PROPS['threat.kev.relevant_hits']}`],
  ['`threat.aiid.privacy_incidents` / `_per_day`', 'observed', 'AI Incident Database', `${PROPS['threat.aiid.privacy_incidents']} / ${PROPS['threat.aiid.privacy_per_day']}`],
  ['`router.max_cost_per_1k_usd`', 'derived', 'budget rule', String(PROPS['router.max_cost_per_1k_usd'])],
  ['`threat.posture`', 'derived', 'posture rule', PROPS['threat.posture']],
  ['`policy.max_prompt_bytes`', 'derived', 'cm:posture/' + PROPS['threat.posture'], String(PROPS['policy.max_prompt_bytes'])],
  ['`policy.custom_redaction_patterns`', 'derived', 'cm:posture/' + PROPS['threat.posture'], `${PROPS['policy.custom_redaction_patterns'].length} (ARN, k8s DNS)`],
  ['`policy.lockdown_recommended`', 'derived', 'cm:posture/' + PROPS['threat.posture'], String(PROPS['policy.lockdown_recommended'])],
], { small: true });
call('PropertySink and the Capstone', ['The adapter depends only on `set(key, value, source, confidence=1.0) -> bool` and `get(key, default=None)`. This is the same shape as the BDI belief base of Assignment 4.1 [@rao95], so in the Capstone (5.2) live feeds can write beliefs directly and trigger intention reconsideration. A test checks that a belief-base-like class satisfies the protocol.']);

// =====================================================================================================
h1('Verification Run');
h2('Set-up');
p(`The demonstration was run once with \`python demo/live_adaptation_demo.py\` on ${EPR.generated_at.slice(0, 10)} (UTC). All network traffic used ${EPR.transport}. The run prints a timestamped log (\`logs/live_feed_run.log\`), writes one JSON line per adaptation (\`logs/adaptation_events.jsonl\`) and a per-endpoint report (\`logs/live_endpoints_report.json\`), and keeps snapshots in \`data/snapshots/\`. Five prompts are planned in each phase: a clean request, a request with an email address, a KYC request with an Aadhaar number, a question containing an AWS ARN, and a 40 KB service log.`);
h2('Phase A: knowledge base and default plans');
p('Listing 5 is the start of the run. The ontology passes the schema, and the residency rule derived from the graph equals the engine\'s hard-coded rule.');
code(logBlock('ontology.json validated', 'Phase A plans', (l) => !/knowledge  (subjects|predicates|classes|regions|jurisdictions|detector|legal|policy_rules|threat|watched)/.test(l)), 'Listing 5: Phase A excerpt from logs/live_feed_run.log');
h2('Phase B: live endpoints');
p('Table {nexttbl} is taken from `live_endpoints_report.json`. Every endpoint answered HTTP 200 over verified TLS. The hash in the table is the SHA-256 of the payload as served. Five of the feeds contain third-party prose (incident descriptions, vulnerability write-ups, news headlines), so their raw payloads are not redistributed: each snapshot keeps the original hash in its meta file and stores only a text-free derivative that parses to exactly the same signals (a test checks this for every feed). No parser copies feed headlines or descriptions into the graph, the properties or the logs; incident labels are built from ids and codes.');
tbl('Live endpoints contacted in Phase B', ['Feed', 'Status', 'Bytes', 'Fetch ms', 'Parse ms', 'Items / relevant', 'Facts', 'SHA-256 (prefix)'], [1500, 800, 1150, 950, 900, 1300, 700, 1366],
  EPR.endpoints.map((e) => [e.feed, String(e.http_status), fmt(e.bytes, 0), fmt(e.latency_ms), fmt(e.parse_ms, 2), `${e.items_seen} / ${e.items_relevant}`, String(e.facts_extracted), (e.original_sha256 || e.sha256_stored).slice(0, 12)]), { small: true });
p('Figure {nextfig} plots the same run. Payloads range from 69 bytes (the exchange rate) to 1.8 MB (the full KEV catalog); fetch latency stayed under one second for every feed. Table {nexttbl}, placed first, shows what each parser extracted from the live data.');
tbl('Knowledge extracted from the live feeds', ['Feed', 'What the parser found', 'Effect on the agent'], [1600, 4400, 2666], [
  ['gcp_status', `${EP.gcp_status.items_seen} incidents; none active; ${EP.gcp_status.signals.recent_total} resolved within 30 days (europe-west2; a Cloud Storage incident in us-central1 that does not name Vertex AI)`, 'gcp-vertex = operational (confidence 0.8)'],
  ['azure_status', 'Empty channel: no active Azure incident', 'azure-ai = operational (0.8)'],
  ['aws_health', `${EP.aws_health.items_seen} events, both in the Middle East (${EP.aws_health.signals.regions_seen.join(', ')}); none in ap-south-1`, 'aws-bedrock = operational (0.8); incidents stored as graph facts'],
  ['cisa_kev', `Catalog ${kev.catalog_version}: ${kev.recent} additions in 30 days vs median ${kev.baseline_monthly_median} (ratio ${kev.ratio}); watched vendors: ${kev.relevant.map((r) => `${r.vendor} ${r.product}`).join(', ')}`, 'below the calibrated thresholds (KEV alone gives LOW)'],
  ['fx_usd_inr', `USD/INR = ${fx.rate} (ECB reference date ${fx.rate_date}) [@ecb]`, `budget USD ${PROPS['router.max_cost_per_1k_usd']} per 1k`],
  ['aiid_rss', `${ai.items_in_window} reports covering ${ai.covered_days} days; keyword classes in free text: ${ai.privacy_incidents} privacy, ${ai.intrusion_incidents} intrusion (report text is not stored)`, `${ai.privacy_per_day} privacy reports per day >= 0.5: posture ${PROPS['threat.posture']}`],
], { small: true, split: true });
fig(FIG('fig_endpoints.png'), 'Fetch latency and payload size of the six live endpoints (real run)', 560);
p('Listing 6 is the real log of the AI Incident Database update: unstructured news text, classified by keywords, raises the posture. One fetch produces seven property changes: two observations, then the posture rule and its effects. Each change carries its source, confidence and time.');
code(logBlock('[aiid_rss] LIVE', 'graph grew from', (l) => !/extracted:/.test(l)), 'Listing 6: AI Incident Database update in Phase B');
h2('Property changes and timing');
p('Figure {nextfig} shows the timing chain for each live feed, read from `adaptation_events.jsonl`. The network fetch dominates (hundreds of milliseconds). Parsing takes from 0.1 ms (exchange rate) to about 12 ms (1.8 MB KEV catalog). The step that matters for "instant" adaptation, from a property change to a recomputed plan, stays well under one millisecond for every feed. Table {nexttbl} gives the exact numbers.');
fig(FIG('fig_timing.png'), 'Fetch, parse, property-change and re-plan latency per live feed (log scale)', 560);
tbl('Adaptation latency per live feed (ms)', ['Feed', 'Fetch', 'Parse', 'Parsed to property', 'Property to plan', 'End to end', 'Plan version'], [1500, 1000, 1000, 1400, 1300, 1166, 1300],
  LIVE_EV.map((e) => [e.feed, fmt(e.timings_ms.fetch_ms), fmt(e.timings_ms.parse_ms, 2), fmt(e.timings_ms.parsed_to_property_ms, 3), fmt(e.timings_ms.property_to_plan_ms, 3), fmt(e.timings_ms.end_to_end_ms), `v${e.plan_version_before} -> v${e.plan_version_after}`]), { small: true });
h2('Phase C: the same prompts after the live update');
p('Table {nexttbl} compares the plans and Figure {nextfig} shows the same data as a chart. Every one of the five prompts was planned differently, and every difference is traced to a named live fact.');
const why = Object.fromEntries(REC.phase_c.diff.map((r) => [r.prompt, r.why]));
tbl('Plans before (Phase A) and after (Phase C) the live update', ['Prompt', 'Phase A', 'U', 'Phase C', 'U', 'Why it changed'], [1350, 1650, 700, 1650, 700, 2616],
  PROMPTS.map((k) => [k, `${plan('a', k).decision} -> ${rt(plan('a', k))}`, U(plan('a', k)), `${plan('c', k).decision} -> ${rt(plan('c', k))}`, U(plan('c', k)), why[k].replace(/\(R\d[^)]*\)/, '').replace('; gcp-vertex utility', '; gcp-vertex U').slice(0, 120)]),
  { small: true, decisionCol: 1 });
fig(FIG('fig_before_after.png'), 'Route utility and chosen provider per prompt, Phase A versus Phase C', 560);
p('Two live inputs explain all of it, as the leave-one-feed-out re-runs in Table {nexttbl} confirm:');
bul([
  `**Exchange rate (structured).** INR 300 per 1,000 requests at ${fx.rate} INR/USD is USD ${PROPS['router.max_cost_per_1k_usd']}. Azure (USD 3.30) now fails \`OVER_BUDGET\`, and the cost score of every cloud provider falls, so the local runtime (USD 0.40) becomes the best feasible choice (U = ${U(plan('c', 'P1 clean'))}).`,
  `**AI incident reports (unstructured text).** The keyword parser found ${ai.privacy_incidents} privacy-related reports in ${ai.covered_days} days of free-text news items, ${ai.privacy_per_day} per day, above the 0.5 threshold. Posture ELEVATED adds two redaction patterns, so the AWS ARN in P4 is redacted (R2) instead of sent in clear, and halves the R5 limit to 32,768 bytes, so the 40 KB log dump in P5 is blocked.`,
  '**Not causes today:** the three status feeds reported no active incident for the providers, and the KEV catalog stayed below its calibrated thresholds.',
]);
tbl('Attribution: each feed removed in turn (same parsed data, re-planned)', ['Feed removed', 'Posture without it', 'Plan changes that disappear without it'], [1900, 1800, 4966],
  Object.entries(PC.plan_attribution).map(([f, a]) => [f, a.posture_without, a.plans_caused.length ? a.plans_caused.join('; ') : 'none']), { small: true });
h2('Phase D: deterministic replay (not live)');
p('Today\'s provider feeds were quiet, so the provider-status path is shown with a **replay**. The replay reads only the files pinned in `data/replay/`; each is checked against the SHA-256 in `MANIFEST.json` before use, so the result is the same on every run. Four inputs are text-free derivatives of real payloads saved from live runs, and one is a hand-written Azure what-if fixture in the feed\'s format (marked as such inside the file) that reports an Azure AI Foundry outage in Central India. The demo evaluates them as if the clock read **2026-02-27 13:00 UTC**. At that moment the real GCP feed contains an active Vertex Gemini API incident (status impact SERVICE_INFORMATION, with degradation keywords in its description). The AWS feed and the AI Incident Database contribute **no events** at that date: the AWS events are later and in other regions, and the 100 newest AI incident items all date from October 2026. Table {nexttbl} shows the plans at each step.');
tbl('Replay: plans at each step', ['Prompt', 'Baseline', 'D.1 incidents (Feb 27)', 'D.2 KEV (Feb 27)', 'D.3 KEV (Sep 24)'], [1300, 1900, 1900, 1800, 1766],
  PROMPTS.map((k) => { const f = (p) => `${p.decision} -> ${rt(p)}${p.utility ? ` (${r2(p.utility)})` : ''}`;
    return [k, f(PD.baseline[k]), f(PD.d1[k]), f(PD.d2[k]), f(PD.d3[k])]; }), { small: true, decisionCol: 1, split: true });
p('In step D.1 the GCP parser marks gcp-vertex **degraded** (confidence 0.9). The status individual in the ontology lowers its availability by 0.8 points and multiplies its p95 latency by 1.5, so its utility falls from 76.22 to 71.16 and aws-bedrock wins four prompts. The Azure outage sets `excludesProvider`, so azure-ai is reported as `DISABLED` in every route. In step D.2 the real KEV catalog at the same date shows ' + `${replayKev.recent} additions (ratio ${replayKev.ratio}) and ${replayKev.relevant_hits} watched-vendor hits` + ', which is below the calibrated thresholds, so the posture stays LOW and no plan changes. Step D.3 replays the KEV catalog at 2026-09-24, the single HIGH date of the backtest: ' + PD.peak_reason.replace(/kev\./g, '') + '. Two independent signals are met, so HIGH restricts all traffic to IN and LOCAL, cuts the byte limit to 16,384, redacts the ARN, blocks the log dump and raises a lockdown recommendation for the operator (Listing 7). Figure {nextfig} is the provider sub-graph exported by `graph.to_svg()` after step D.2.');
fig(FIG('fig_graph_replay.png'), 'Provider placement and status sub-graph exported by the agent after the replay', 560);
code(logBlock('Replay plans after D.3', 'Replay baseline -> D.3 differences', (l) => /context note|plans after|prompt  /.test(l) || /P\d /.test(l), 40, true), 'Listing 7: replay step D.3 from logs/live_feed_run.log');
p('Taken together, the replay checks the three adaptation paths that the live run could not show on the day: a degraded provider is penalised but kept, a provider in outage is excluded, and the strictest posture only appears when two independent threat signals agree. Because every replay input is pinned and hash-checked, these results are identical on every run and on any machine, and the run log shows the hash of each file before it is used.');

// =====================================================================================================
h1('Testing');
p(`The full suite has **${TOTAL} tests and all pass**: ${EN} engine tests from Units 1-3 (unchanged) and ${KN} new tests for this unit. Table {nexttbl} summarises the new tests; \`logs/pytest_results.txt\` lists every test by name.`);
tbl('New tests in tests/knowledge/', ['File', 'Tests', 'What is checked'], [2600, 800, 5266], [
  ['`test_ontology.py`', String(count('tests/knowledge/test_ontology.py')), 'Schema passes; six kinds of invalid document rejected; undefined IRI, wrong range, functional violation and sub-class cycle caught; 25 categories, rule codes and provider profiles match the engine'],
  ['`test_graph.py`', String(count('tests/knowledge/test_graph.py')), 'Add / remove with provenance, indexes, conjunctive query, RDFS inference and idempotence, residency equivalence for all 25 categories and 300 pairs, JSON round trip, JSON-LD and SVG export'],
  ['`test_parsers.py`', String(count('tests/knowledge/test_parsers.py')), 'Region / service normalisation; each parser on saved samples (a synthetic AI-incident feed with invented wording); time travel; malformed JSON, bad records, corrupt FX values; billion-laughs, XXE and HTML doctype refused; derivatives text-free and signal-identical; no feed prose stored'],
  ['`test_http_fallback.py`', String(count('tests/knowledge/test_http_fallback.py')), 'Local HTTP server: User-Agent and hash, retries, size cap, cache, non-HTTPS refused, guarded redirects, charset, overall deadline, fallback on network failure and on an HTML 200 page, stale snapshot down-weighted, withheld raw payload, tampered snapshot rejected'],
  ['`test_adapter_properties.py`', String(count('tests/knowledge/test_adapter_properties.py')), 'PropertySink protocol (also for a belief-base-like class), history, confidence gate, subscribers, concurrent writers, triples with provenance, expiry of old live facts, budget rule, posture thresholds, two-signal HIGH, hysteresis, stale data rejected'],
  ['`test_adaptive_agent.py`', String(count('tests/knowledge/test_adaptive_agent.py')), 'Graph profiles reproduce engine routing; degraded penalises, outage excludes, recovery restores; FX budget; ELEVATED and HIGH policies; REVIEW local only; deterministic replay; pinned inputs match manifest; timing; engine sync; unsafe custom pattern rejected'],
  ['`test_calibration.py`', String(count('tests/knowledge/test_calibration.py')), 'Ontology thresholds equal the backtest calibration; posture shares bounded; tie handling; two-signal HIGH, hysteresis and attribution'],
  ['`test_live_endpoints.py`', String(count('tests/knowledge/test_live_endpoints.py')), 'Marked `live`: contacts all six endpoints and checks status, hash and properties; skipped automatically without network'],
], { small: true, split: true });
p('Edge cases were chosen from the failure modes of real feeds: an empty RSS channel (Azure today), an HTML error page served with status 200, a redirect to another host, a UTF-16 body with a byte-order mark (AWS), incidents with no location (prose fallback), resolved events without an end time, KEV records with bad dates, exchange rates outside a sanity band, and a snapshot whose bytes no longer match its recorded hash. The live test ran and passed during the recorded test run because the network was available.');

// =====================================================================================================
h1('Submission Analysis');
p('Table {nexttbl} checks each requirement against its evidence.');
tbl('Requirement status', ['Requirement', 'Evidence', 'Status'], [3300, 4166, 1200], [
  ['Structured knowledge format', `\`ontology.json\` + schema; ${fmt(S.triples, 0)} triples; validation tests`, 'PASS'],
  ['Live REST API integration', '6/6 endpoints HTTP 200 with hashes and snapshots', 'PASS'],
  ['Parse live unstructured data', 'Azure RSS prose, GCP descriptions, AWS messages, AI-incident news text (keyword classes)', 'PASS'],
  ['Properties change instantly', `${LIVE_EV.reduce((a, e) => a + e.property_changes.length, 0)} live property changes; property to plan under 1 ms`, 'PASS'],
  ['Plans adapt from live unstructured data', 'Attribution: without the AI-incident text feed, P4 and P5 revert (posture LOW); budget changes come from the structured FX feed', 'PASS'],
  ['Threat signal calibrated', `Backtest of ${BT.dates} dates; HIGH ${(BT.after.share.HIGH * 100).toFixed(1)} % of days (was ${Math.round(BT.before.share.HIGH * 100)} %)`, 'PASS'],
  ['Residency derivable from graph', 'Equivalence tests and log line `EQUAL=True`', 'PASS'],
  ['Tests', `${TOTAL} passed (${KN} new)`, 'PASS'],
], { small: true, decisionCol: 2 });
h2('Strengths');
bul([
  'One source of truth: providers, regions, legal links, rule order, status penalties, posture thresholds and the budget all live in a validated file, and the router\'s residency rule is derived from it, not duplicated.',
  'Provenance everywhere: every triple and every property records its source, time and confidence; replayed data is labelled as replay in the graph, the properties and the log.',
  'Defensive integration: TLS verification, size caps, retries, DTD refusal, BOM-aware decoding, hash-checked snapshots and an offline mode.',
  'Explainable adaptation: each plan change in the log has a reason computed from the before and after plans.',
]);
h2('Limitations');
bul([
  'Provider prices, latencies and quality scores remain illustrative planning numbers, as in Units 3.1 and 3.2. The INR 300 budget is an illustrative organisational setting.',
  'The AWS endpoint backs the public Health Dashboard page and is not a documented API; if its format changes the connector falls back to the saved snapshot.',
  'The live posture change rests on one weak signal: keyword classes over news text. It can miss unusual wording or other languages (the feed carries Arabic, Spanish and Chinese reports) and it cannot be backtested, so its threshold is a judgement value. It can reach ELEVATED alone but never HIGH, and lockdown stays operator-only.',
  'The ontology uses a JSON-LD style and RDFS-level inference implemented in Python; it is not processed by a full OWL reasoner.',
  'Provider-status adaptation was not visible live on the day of the run, so it is demonstrated with the labelled replay; the Azure item in that replay is a written fixture.',
]);
h2('How this feeds the Capstone (5.2)');
p('The Capstone combines the BDI layer of 4.1 with this knowledge layer. Because `KnowledgeAdapter` writes through the `PropertySink` interface, the BDI belief base can be passed in directly: a live Vertex AI incident becomes a belief, the BDI agent reconsiders an intention that depends on gcp-vertex, and the knowledge graph keeps the evidence. `sync_engine_agent` already pushes posture-driven policy into a running `CipherMeshAgent`, so the network server of Unit 2.2 can serve the adapted policy without restarting.');

// =====================================================================================================
h1('Conclusion');
p('CipherMesh now knows *where* its providers are, *which law* applies to which data, and *how* the outside world looks right now. The ontology stores this knowledge formally and can be validated and reasoned over; the six connectors bring in real provider-health, threat and market data from public REST and RSS endpoints [@fielding] [@rss]; and the adapter turns that data into properties that change the agent\'s plan in well under a millisecond. In the recorded live run, the exchange rate moved the budget and keyword parsing of the AI Incident Database\'s free-text reports [@aiid] raised the threat posture, so all five test prompts were planned differently; leave-one-feed-out re-runs confirm both causes. The CISA KEV catalog [@kev] stayed below thresholds calibrated on a one-year backtest. The pinned replay showed the provider-health path using real status data from the Google Cloud [@gcpstatus], AWS [@awshealth] and Azure [@azurestatus] feeds. Every change is explained, logged with provenance and covered by tests.');
refs();

// =====================================================================================================
app('How to Run');
p('These are the same commands as in the README. The report itself is built with the shared course report kit (`dsl.js`, `build_report.js`, `render_diagrams.js`), which is not part of this folder; `docs/report_src/README.md` explains how to rebuild it.');
code(['python -m venv .venv && . .venv/bin/activate',
  'pip install -r requirements.txt            # includes pytest',
  '',
  '# live demonstration: phases A-D, writes logs/ and data/snapshots/',
  'python demo/live_adaptation_demo.py',
  '',
  '# same run without network (saved snapshots only, labelled OFFLINE)',
  'python demo/live_adaptation_demo.py --offline --logs /tmp/a42_offline_logs',
  '',
  '# KEV backtest and threshold check -> logs/kev_backtest.json',
  'python demo/kev_backtest.py',
  '',
  '# re-pin the replay inputs (only when deliberately updating them)',
  'python demo/pin_replay_inputs.py',
  '',
  '# full test suite; the live test is skipped automatically when offline',
  'python -m pytest -o addopts= -v -rs tests',
  'python -m pytest -m live -v          # only the live endpoint test',
  '',
  '# regenerate figures (needs matplotlib and the report kit)',
  'python3 docs/figures/make_charts.py <reportkit>',
  'python3 docs/figures/make_diagrams.py'].join('\n'), 'Listing 8: commands');
app('File Listing');
p('Table {nexttbl} lists the files in the submission folder.');
tbl('Deliverable files', ['Path', 'Contents'], [3900, 4766], [
  ['`ciphermesh/knowledge/`', 'ontology.json, ontology.schema.json, ontology.py, graph.py, properties.py, adapter.py, posture.py, calibration.py, adaptive_agent.py, data/whatif_azure_status.xml'],
  ['`ciphermesh/knowledge/feeds/`', 'base.py, safe_xml.py, normalize.py, status_common.py, gcp_status.py, azure_status.py, aws_health.py, cisa_kev.py, fx_rates.py, ai_incidents.py'],
  ['`ciphermesh/` (other modules)', 'Engine from Units 1-3 (unchanged)'],
  ['`demo/`', 'live_adaptation_demo.py (phases A-D), kev_backtest.py, pin_replay_inputs.py'],
  ['`tests/knowledge/` + `fixtures/`', `${KN} tests; saved samples of each feed (synthetic wording for AI incidents)`],
  ['`tests/engine/`', `${EN} engine tests`],
  ['`data/snapshots/`', 'Latest live data: text-free derivatives (raw only for FX) + .meta.json with the original URL, status, bytes, SHA-256, fetched_at'],
  ['`data/replay/`', 'Pinned replay inputs + MANIFEST.json (SHA-256 of each file)'],
  ['`logs/live_feed_run.log`', 'Timestamped run log (phases A-D)'],
  ['`logs/adaptation_events.jsonl`', 'One JSON line per adaptation with property changes and timings'],
  ['`logs/live_endpoints_report.json`', 'Per-endpoint status, latency, bytes, hash, facts'],
  ['`logs/demo_record.json`, `knowledge_graph_export.json`, `knowledge_graph_*.svg`', 'Plans, properties, attribution, graph export with provenance, graph figures'],
  ['`logs/kev_backtest.json`', 'One-year KEV backtest and calibrated thresholds'],
  ['`logs/pytest_results.txt`', 'Full test output'],
  ['`docs/Assignment_4.2_Knowledge_Representation_Adaptive_API_Report.docx/.pdf`', 'This report'],
  ['`docs/figures/`, `docs/report_src/content.js`', 'Figures with their sources; report source'],
], { small: true });

module.exports = {
  meta: { assignment: '4.2', title: 'Knowledge Representation and Adaptive API Integration', short: 'Knowledge Representation & Adaptive APIs',
    subtitle: 'A validated ontology and six live public feeds that change CipherMesh plans as the world changes' },
  C: d.C,
  refs: {
    jsonld: 'M. Sporny, D. Longley, G. Kellogg, M. Lanthaler, P.-A. Champin, and N. Lindström, "JSON-LD 1.1: A JSON-based serialization for linked data," W3C Recommendation, Jul. 16, 2020. [Online]. Available: https://www.w3.org/TR/json-ld11/ (accessed Oct. 31, 2026).',
    owl2: 'W3C OWL Working Group, "OWL 2 Web Ontology Language document overview (second edition)," W3C Recommendation, Dec. 11, 2012. [Online]. Available: https://www.w3.org/TR/owl2-overview/ (accessed Oct. 31, 2026).',
    rdfs: 'D. Brickley and R. V. Guha, "RDF Schema 1.1," W3C Recommendation, Feb. 25, 2014. [Online]. Available: https://www.w3.org/TR/rdf-schema/ (accessed Oct. 31, 2026).',
    gruber: 'T. R. Gruber, "A translation approach to portable ontology specifications," *Knowledge Acquisition*, vol. 5, no. 2, pp. 199-220, 1993.',
    aima: 'S. Russell and P. Norvig, *Artificial Intelligence: A Modern Approach*, 4th ed. Hoboken, NJ, USA: Pearson, 2020.',
    rfc8259: 'T. Bray, Ed., "The JavaScript Object Notation (JSON) data interchange format," IETF RFC 8259, Dec. 2017.',
    jsonschema: 'A. Wright, H. Andrews, B. Hutton, and G. Dennis, "JSON Schema: A media type for describing JSON documents," IETF Internet-Draft draft-bhutton-json-schema-01 (JSON Schema 2020-12), Jun. 2022.',
    dpdp: 'Government of India, *The Digital Personal Data Protection Act, 2023* (Act No. 22 of 2023), Gazette of India, Ministry of Law and Justice, Aug. 11, 2023.',
    aadhaar: 'Government of India, *The Aadhaar (Targeted Delivery of Financial and Other Subsidies, Benefits and Services) Act, 2016* (Act No. 18 of 2016).',
    gdpr: 'European Parliament and Council, "Regulation (EU) 2016/679 (General Data Protection Regulation)," *Official Journal of the European Union*, L 119, pp. 1-88, May 4, 2016.',
    rfc9110: 'R. Fielding, M. Nottingham, and J. Reschke, Eds., "HTTP semantics," IETF RFC 9110, Jun. 2022.',
    owasp: 'OWASP Foundation, "XML External Entity prevention cheat sheet," OWASP Cheat Sheet Series. [Online]. Available: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html (accessed Oct. 31, 2026).',
    rao95: 'A. S. Rao and M. P. Georgeff, "BDI agents: From theory to practice," in *Proc. 1st Int. Conf. Multi-Agent Systems (ICMAS-95)*, San Francisco, CA, USA, 1995, pp. 312-319.',
    ecb: 'European Central Bank, "Euro foreign exchange reference rates." [Online]. Available: https://www.ecb.europa.eu/stats/policy_and_exchange_rates/euro_reference_exchange_rates/html/index.en.html; served through the Frankfurter API, https://frankfurter.dev/ (accessed Oct. 31, 2026).',
    fielding: 'R. T. Fielding, "Architectural styles and the design of network-based software architectures," Ph.D. dissertation, Dept. Inf. Comput. Sci., Univ. California, Irvine, CA, USA, 2000.',
    rss: 'RSS Advisory Board, "RSS 2.0 specification," version 2.0.11, Mar. 30, 2009. [Online]. Available: https://www.rssboard.org/rss-specification (accessed Oct. 31, 2026).',
    kev: 'Cybersecurity and Infrastructure Security Agency, "Known Exploited Vulnerabilities catalog." [Online]. Available: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (accessed Oct. 31, 2026).',
    aiid: 'S. McGregor, "Preventing repeated real world AI failures by cataloging incidents: The AI Incident Database," in *Proc. AAAI Conf. Artificial Intelligence*, vol. 35, no. 17, 2021, pp. 15458-15463.',
    gcpstatus: 'Google Cloud, "Google Cloud Service Health," incidents.json feed. [Online]. Available: https://status.cloud.google.com/ (accessed Oct. 31, 2026).',
    awshealth: 'Amazon Web Services, "AWS Health Dashboard." [Online]. Available: https://health.aws.amazon.com/health/status (accessed Oct. 31, 2026).',
    azurestatus: 'Microsoft, "Azure status," RSS feed. [Online]. Available: https://azure.status.microsoft/en-us/status/ (accessed Oct. 31, 2026).',
  },
};
