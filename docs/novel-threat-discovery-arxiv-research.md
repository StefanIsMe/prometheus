# Novel threat discovery research for Prometheus

Generated: 3 June 2026, 10:56 GMT+7

## Goal

Make Prometheus better at finding novel web security threats on authorized target websites.

Novel means the scanner is not only matching CVEs, nuclei templates, headers, and known payloads. It forms target specific vulnerability hypotheses from behavior, code paths, workflow state, auth state, and differential responses. It then turns those hypotheses into executable proof of concepts with negative controls.

## Bottom line

Prometheus already has the right base: multi agent orchestration, skills, target memory, threat feeds, coverage tracking, deep audit helpers, and validation logic.

The missing layer is a hypothesis driven discovery engine.

Current Prometheus is still biased toward known issues: CVE lookup, nuclei, standard payloads, and endpoint by vulnerability type coverage. That will find common and known bugs. It will miss novel bugs because novel bugs usually require chained behavior, state changes, role differences, business logic, and repeated exploration of strange response differences.

## Papers reviewed

1. MAPTA, arXiv 2508.20816

   Relevant idea: coordinator, sandbox agents, and independent validation agent. Every candidate exploit is validated end to end before reporting. The paper reports 76.9 percent success on 104 XBOW web challenges and 19 vulnerabilities across 10 open source web applications.

   Prometheus takeaway: every finding candidate needs a separate validation path with an explicit oracle. Reporting without validation should be blocked.

2. What Makes a Good LLM Agent for Real world Penetration Testing, arXiv 2602.17622

   Relevant idea: most failures are not tool failures. The paper separates failures into Type A capability gaps and Type B complexity barriers. It reports 42 percent Type A and 58 percent Type B in analyzed failures. Adding task difficulty assessment reduced Type B failures from 58 percent to 27 percent.

   Prometheus takeaway: add difficulty assessment and exploration control. Agents need to know when to continue, pivot, split work, or abandon a rabbit hole.

3. Teams of LLM Agents can Exploit Zero Day Vulnerabilities, arXiv 2406.01637

   Relevant idea: hierarchical planner plus task specific expert agents outperformed earlier single agent designs by up to 4.3x on a zero day benchmark. Specialist agents covered XSS, SQL injection, CSRF, SSTI, ZAP, and generic web exploitation.

   Prometheus takeaway: keep specialist agents, but spawn them from a central hypothesis portfolio. Do not spawn generic agents. Do not let specialists pick random targets.

4. PentestAgent, arXiv 2411.05185

   Relevant idea: reconnaissance agent, search agent, and exploitation agent. It stores environment knowledge in a central database and builds a hierarchical knowledge tree from online research and exploit procedures.

   Prometheus takeaway: query target memory at scan start, use previous successes and failures, and store structured environment facts continuously.

5. CVE Bench, arXiv 2503.17332

   Relevant idea: realistic web exploitation benchmark with 40 critical CVEs in sandboxed web applications. The paper reports that state of the art agents exploited up to 13 percent of the vulnerabilities.

   Prometheus takeaway: use CVE Bench as a regression benchmark. If a code change does not improve validated exploit rate, it is probably prompt theatre.

6. FuzzingBrain V2, arXiv 2605.21779

   Relevant idea: reproducible reports through fuzzing, Suspicious Point abstraction for vulnerability localization, hierarchical function analysis, and dynamic feedback. The paper reports 90 percent detection on the AIxCC 2025 final C and C plus plus dataset and 29 confirmed zero days across 12 open source projects.

   Prometheus takeaway: for web targets, translate Suspicious Points into suspicious web states: endpoint plus parameter plus auth role plus workflow step plus response anomaly. Then fuzz around those states.

7. Synthesizing Multi Agent Harnesses for Vulnerability Discovery, arXiv 2604.20801

   Relevant idea: agent harness design strongly affects success. AgentFlow models the harness as agents, communication topology, message schemas, tool allocation, and coordination protocol. It rejects malformed harnesses before expensive runs. The paper reports about 20 percent of proposed harnesses rejected before inference by well formedness checks.

   Prometheus takeaway: agent spawning should be typed. A child agent should require task, target surface, accepted tools, oracle, stop condition, and expected output schema.

8. Co RedTeam, arXiv 2602.02164

   Relevant idea: code aware analysis, execution grounded reasoning, and long term memory. The framework separates discovery and exploitation, then iterates using execution feedback.

   Prometheus takeaway: black box and white box modes both need a discovery stage that produces hypotheses, and an exploitation stage that proves or kills them.

9. RapidPen, arXiv 2502.16730

   Relevant idea: success case reuse and strict task trees. The paper reports 60 percent success when reusing prior success case data versus 30 percent without it in its evaluation setting.

   Prometheus takeaway: store successful attack trajectories, not just findings. Reuse them when a new target has similar tech, endpoint patterns, or response behavior.

10. PentestGPT, arXiv 2308.06782

   Relevant idea: context loss and depth first fixation are major causes of failure. The Penetration Testing Task Tree reduces loss of global state.

   Prometheus takeaway: Prometheus needs a global hypothesis tree and coverage state outside the LLM context, not only todos and chat history.

## Current Prometheus state observed in source

1. Multi agent orchestration exists.

   Files:
   `prometheus/tools/agents_graph/tools.py`
   `prometheus/agents/prompts/includes/multi_agent_system.jinja`

   `create_agent` already coerces skills from string or list, validates skills, and supports acceptance criteria. The earlier skill passing bug appears fixed in this source.

2. Threat intelligence exists and is mandatory.

   Files:
   `prometheus/agents/prompts/includes/execution_guidelines.jinja`
   `prometheus/tools/threat_intel/tool.py`
   `prometheus/tools/web_search/tool.py`

   This is useful for known threats, but it does not create novel hypotheses.

3. Cross scan knowledge exists.

   Files:
   `prometheus/tools/knowledge/tool.py`
   `prometheus/tools/knowledge/store.py`

   The tools can save tech stacks, endpoints, vulnerabilities, failed approaches, and successful techniques. The gap is automatic retrieval and use at scan start.

4. Coverage tracking exists.

   File:
   `prometheus/tools/coverage/tool.py`

   Current coverage is endpoint by vulnerability type. That is too coarse for novel discovery. It misses role, parameter, method, request body field, workflow step, and response oracle.

5. Deep audit primitives exist.

   Files:
   `prometheus/core/deep_audit.py`
   `prometheus/tools/deep_audit/tool.py`

   Differential response analysis, auth flow tracing, response fingerprinting, rate limit probing, and PoC generation already exist. These should become the execution backend for hypothesis testing.

6. Validation logic exists.

   Files:
   `prometheus/core/validation_judge.py`
   `prometheus/core/poc_validation.py`
   `prometheus/core/live_verification.py`

   The gap is earlier validation. Candidate hypotheses should be validated before report creation, not only judged after report creation.

## Main design change

Add a Novel Discovery Phase after known CVE and nuclei checks.

The phase should do this loop:

1. Build an attack surface graph.
2. Create target specific vulnerability hypotheses.
3. Score each hypothesis for novelty, exploitability, difficulty, and evidence quality.
4. Select the next hypothesis using exploration versus exploitation control.
5. Run web workflow fuzzing and differential tests.
6. If anomalous behavior appears, spawn a validation agent with a strict oracle.
7. If validation passes twice and negative controls fail, allow reporting.
8. Save the successful or failed trajectory to cross scan memory.

## Proposed data model

Create:

`prometheus/core/hypotheses.py`

Core object:

```python
@dataclass
class Hypothesis:
    id: str
    target_id: str
    endpoint: str
    method: str
    parameter: str
    auth_state: str
    role: str
    workflow_step: str
    vulnerability_class: str
    exploit_goal: str
    oracle: str
    preconditions: list[str]
    payload_family: str
    source: str
    novelty_score: float
    exploitability_score: float
    difficulty_score: float
    evidence_score: float
    status: str
    attempts: int
    evidence: list[dict[str, Any]]
    negative_controls: list[dict[str, Any]]
    last_error: str
    created_at: float
    updated_at: float
```

Required statuses:

```python
new
selected
testing
needs_validation
validated
dead_end
abandoned
reported
```

Required persisted file per run:

`hypotheses.json`

Required optional database table:

`hypothesis_trajectories`

Fields:

```text
target_id
tech_stack_hash
surface_signature
vulnerability_class
steps_json
result
evidence_json
created_at
```

## New agent tools

Create:

`prometheus/tools/hypotheses/tool.py`

Expose these tools:

1. `create_hypothesis`

   Creates a structured hypothesis. It must require endpoint, vulnerable input, class, exploit goal, and oracle.

2. `score_hypothesis`

   Scores:

   `novelty_score`: not known CVE, not simple template match, target specific behavior.

   `exploitability_score`: direct impact, auth bypass potential, sensitive data path, write primitive, server side execution, cross user access.

   `difficulty_score`: estimated remaining steps, dependency count, auth complexity, state complexity, context load, unknowns.

   `evidence_score`: response anomaly strength, repeatability, negative controls, side effects.

3. `select_next_hypothesis`

   Chooses next work item. Use high exploitability and evidence, moderate difficulty, and enough novelty. Force periodic exploration so the scan does not get stuck depth first.

4. `record_hypothesis_evidence`

   Stores request, response fingerprint, timing, headers, body hash, side effect, and notes.

5. `mark_hypothesis_status`

   Moves a hypothesis through the lifecycle.

6. `get_hypothesis_portfolio`

   Returns active, validated, dead end, and abandoned hypotheses with scores.

7. `get_reusable_trajectories`

   Searches cross scan memory for similar attack paths by tech stack, endpoint pattern, vulnerability class, and response behavior.

## Task difficulty index

Use a practical version of the TDI idea from arXiv 2602.17622.

```text
TDI = 0.30 * horizon + 0.25 * unknowns + 0.20 * context_load + 0.15 * state_complexity + 0.10 * tool_risk
```

Definitions:

1. `horizon`: estimated remaining steps to proof.
2. `unknowns`: missing preconditions, missing credentials, unknown tech, unknown endpoint schema.
3. `context_load`: amount of state that must be remembered across steps.
4. `state_complexity`: role changes, multi request workflows, races, token freshness, browser state.
5. `tool_risk`: flaky tool, rate limit risk, Tor compatibility, external callback requirement.

Policy:

```text
TDI below 0.35: execute directly.
TDI 0.35 to 0.70: spawn a specialist or validation agent.
TDI above 0.70: split into smaller hypotheses or park until stronger evidence exists.
```

## Attack surface graph

Create:

`prometheus/core/attack_surface.py`

Track nodes:

1. Host.
2. Path.
3. HTTP method.
4. Parameter.
5. Request body field.
6. Header.
7. Cookie.
8. Auth state.
9. Role.
10. Workflow step.
11. Client side route.
12. JavaScript API call.
13. WebSocket channel.
14. File upload sink.
15. Redirect sink.
16. External callback sink.

Track edges:

1. Links from crawl.
2. Form submission.
3. API call from JavaScript.
4. Redirect.
5. Auth transition.
6. Object reference.
7. Parent child resource relationship.
8. Server side fetch behavior.
9. WebSocket message flow.
10. Cache relationship.

Feed from existing sources:

1. Caido sitemap tools.
2. Browser auth flow traces.
3. Katana crawl results.
4. HTTP proxy history.
5. JavaScript endpoint extraction.
6. `save_knowledge` entries.
7. Previous target profile.

## Web workflow fuzzing

Do not only fuzz one request. Novel web bugs are often workflow bugs.

Add an executor that can mutate sequences:

1. Remove auth then replay.
2. Swap user identifiers between two sessions.
3. Change method GET, POST, PUT, PATCH, DELETE.
4. Change content type JSON, form encoded, text plain, multipart.
5. Duplicate parameters.
6. Move parameters between query, body, cookie, and header.
7. Replay old CSRF tokens.
8. Race two or more state changing requests.
9. Follow redirect chains into internal URLs.
10. Mutate OAuth redirect URI and PKCE fields.
11. Mutate GraphQL object IDs and introspection.
12. Mutate WebSocket messages.
13. Upload polyglot files and test retrieval paths.
14. Poison cache keys with host, origin, x forwarded host, and query variants.

Use existing functions from `deep_audit.py` for fingerprints and differential analysis.

## Validation gate

Before `create_vulnerability_report`, require:

1. Executable PoC.
2. Positive test passes twice.
3. Negative control fails.
4. Clean session test if auth is involved.
5. Evidence contains request and response fingerprints.
6. Business impact is explicit.
7. Independent validation agent result is attached.

This maps directly to MAPTA validation and reduces false positives.

## Prompt changes

Edit:

`prometheus/agents/prompts/includes/execution_guidelines.jinja`

Add a section after the known CVE and nuclei phase:

```text
NOVEL DISCOVERY PHASE:
Known CVE and nuclei checks are not enough. After known issue testing, build a hypothesis portfolio from target behavior.
For each interesting endpoint or workflow, create at least one hypothesis with an exploit goal and oracle.
Use differential testing and workflow mutation.
Do not report a hypothesis until a validation agent proves it with positive and negative controls.
Save all successful and failed trajectories to knowledge.
```

Edit:

`prometheus/agents/prompts/includes/multi_agent_system.jinja`

Replace open ended persistence language with bounded hypothesis rules. Current text says to expect 2000 plus steps and try 10 more approaches. That encourages waste. Use difficulty aware control instead.

Better rule:

```text
Do not continue a dead path blindly. Score each hypothesis. If difficulty is high and evidence is weak, split, park, or abandon it. If evidence is strong, spawn a validator. Always preserve the reasoning in the hypothesis portfolio.
```

## Evaluation plan

Use benchmarks before claiming improvement.

1. CVE Bench for real web application exploitation.
2. XBOW challenge set if available in the local environment.
3. Existing Prometheus scans on allowed Bugcrowd targets, using validated findings only.
4. Local deliberately vulnerable apps only if already present. Do not download large Docker images to the SSD.

Metrics:

1. Validated findings per scan.
2. Confirmed false positive rate.
3. Hypotheses created.
4. Hypothesis to validation conversion rate.
5. Validation pass rate.
6. Time to first validated issue.
7. Tool calls per validated issue.
8. LLM cost per validated issue.
9. Coverage depth by endpoint, parameter, role, and workflow.
10. Reuse gain from prior trajectories.

## Implementation order

1. Add `prometheus/core/hypotheses.py` with JSON persistence and unit tests.
2. Add `prometheus/tools/hypotheses/tool.py` and register tools in `prometheus/agents/factory.py`.
3. Add hypothesis persistence initialization in `prometheus/core/runner.py` beside coverage hydration.
4. Extend prompt with Novel Discovery Phase.
5. Extend coverage model from endpoint by vulnerability type to endpoint by input by role by workflow by vulnerability type.
6. Connect deep audit fingerprints to `record_hypothesis_evidence`.
7. Add validation gate before report creation.
8. Add reusable trajectory search over the existing knowledge store.
9. Add a benchmark runner for CVE Bench compatible targets.
10. Run regression scans and compare metrics.

## Non goals

1. Do not add large model downloads.
2. Do not add heavy Docker images to the SSD.
3. Do not make the scanner more aggressive by default.
4. Do not report theoretical issues.
5. Do not hardcode CMS specific paths or vendor logic. Keep the system target agnostic.

## Short version

Prometheus should shift from scanner plus agent to hypothesis engine plus validator.

Known threat flow finds known bugs.
Novel threat flow should find strange behavior, turn it into a structured hypothesis, fuzz the workflow around it, validate with an oracle, and save the trajectory for future scans.
