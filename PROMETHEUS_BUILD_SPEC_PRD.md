# Prometheus Build Spec PRD

Status: Draft build spec based on live codebase audit
Date: 2026-06-03
Repo root: `$PROMETHEUS_SOURCE`
Primary runtime DB: `$HOME/.prometheus/prometheus.db`
Hermes config source of truth: `$HOME/.hermes/config.yaml`

## 1. Goal

Turn Prometheus from a broad multi agent pentest shell into a narrow evidence first bug bounty validation and reporting pipeline.

The product to build is not "an autonomous hacker".
It is a system that:

1. ingests scanner and agent findings
2. normalizes them into structured candidates
3. rejects obvious garbage cheaply
4. runs focused validation with stored evidence
5. produces HackerOne or Bugcrowd ready report artifacts
6. keeps a full lifecycle trail from candidate to outcome
7. always uses the currently active Hermes model provider and model by default

## 2. Non negotiable decisions

1. Hermes is the LLM source of truth.
   Prometheus must not own a separate default model, provider, or base URL.

2. Deterministic tooling first.
   Cheap scanners, replay, diffing, request capture, and browser traces come before LLM reasoning.

3. Human review is mandatory before submission.
   No auto submit.

4. Evidence beats prose.
   Raw requests, raw responses, diffs, PoC output, and control runs are the core artifacts.

5. Narrow scope for v1.
   Focus on reportable bug bounty classes with clean validation.

6. One canonical persistence layer.
   Stop splitting scan and target state across overlapping stores.

7. No silent fallback to local or hardcoded model endpoints.
   If Hermes model resolution fails, Prometheus must fail loud.

## 3. Live audit summary

This spec is based on the current repo and current machine state, not assumptions.

### 3.1 Current Hermes active model

From `$HOME/.hermes/config.yaml:1-4`

```yaml
model:
  base_url: https://chatgpt.com/backend-api/codex
  default: gpt-5.4
  provider: openai-codex
```

From Hermes loader `$PROMETHEUS_SOURCE/../hermes-agent/hermes_cli/config.py:4905-5001`

- `load_config()` is the authoritative config loader
- it already handles profile aware config lookup
- it deep merges defaults and user config
- it caches safely
- Prometheus should use this instead of parsing Hermes YAML itself

### 3.2 Current repo structure

Measured at repo root:

```text
DIR prometheus 362 files
DIR tests 12 files
DIR docs 32 files
DIR prometheus_runs 692 files
```

Entry point:
- `run_prometheus.py:1-7` calls `prometheus.interface.main.main`

CLI argument and run setup:
- `prometheus/interface/main.py:274-507`

Scan runtime orchestration:
- `prometheus/core/runner.py:138-205`
- `prometheus/core/runner.py:565-589`

Agent build and tool surface:
- `prometheus/agents/factory.py:822-900`
- `prometheus/agents/factory.py:903-992`

### 3.3 Current persistence layout

There are three overlapping persistence layers.
This is a problem.

1. `prometheus/core/scan_persistence.py:27-126`
   - owns `scans` table
   - used by orchestrator and scheduler

2. `prometheus/core/target_registry.py:29-73`
   - owns `targets` table
   - used by scheduler, cross target logic, TUI automation panels

3. `prometheus/tools/knowledge/store.py:165-183`
   - owns `report_status`, `scan_history`, `target_profiles`, `programs`, `knowledge`, `finding_comments`
   - already acts like the real product database

Actual current database tables in `$HOME/.prometheus/prometheus.db`:

```text
programs
targets
scans
scan_history
report_status
knowledge
finding_comments
target_profiles
cve
cve_packages
cve_references
feed_status
seen_advisories
check_log
```

Actual current row counts:

```text
programs 8
targets 9
scans 194
scan_history 30
report_status 53
knowledge 548
finding_comments 8
```

This means migrations must preserve real data. Do not wipe or recreate the DB.

### 3.4 Current reporting and validation assets

Existing useful modules:

- `prometheus/tools/reporting/tool.py`
  - real time sync into `report_status`
  - CVE and CWE validation
  - Bugcrowd VRT integration
  - duplicate check hook

- `prometheus/core/hypotheses.py`
  - strong candidate structure for positive and negative controls
  - report gate already exists

- `prometheus/core/attack_surface.py`
  - useful for structured surface mapping

- `prometheus/core/scan_goals.py`
  - useful for long running validation goals

- `prometheus/core/live_verification.py`
  - curl based replay helpers already exist

- `prometheus/core/poc_validation.py`
  - PoC validation exists but needs hardening

- `prometheus/core/oauth_validation.py`
  - reusable targeted validator

- `prometheus/core/validation_judge.py`
  - useful as a secondary heuristic layer only

### 3.5 Current blockers discovered during audit

Current file `prometheus/config/models.py` is broken.

From `prometheus/config/models.py:1-34`:
- file ends in `_OL...`
- this is invalid syntax

Verified by real compile run:

```text
python3 -m compileall $PROMETHEUS_SOURCE/prometheus

Result:
SyntaxError in prometheus/config/models.py line 34
```

Verified by test collection:

```text
`PYTHONPATH=$PROMETHEUS_SOURCE/../pytest-site:$PROMETHEUS_SOURCE python3 -m pytest -q tests/test_hermes_model_config.py`

Result:
collection fails with SyntaxError in prometheus/config/models.py line 34
```

This is the first fix. Nothing else matters until the repo imports again.

### 3.6 Current model configuration split is wrong

Current Prometheus settings layer:
- `prometheus/config/settings.py:20-66`
- `prometheus/config/loader.py:24-143`

Problems:

1. Prometheus owns `prometheus_LLM`, `LLM_API_BASE`, `LLM_API_KEY`, and `prometheus_USE_HERMES_MODEL`
2. Prometheus persists its own JSON config at `~/.prometheus/cli-config.json`
3. Hermes already has the real active provider and model
4. current gpt4free migration already complete — test files removed and model config cleaned up.
5. current runtime comments in `interface/main.py:79-83` show Hermes mode is treated as optional, not canonical

This must be inverted.
Hermes must become the default and canonical model source.

### 3.7 Current lifecycle status model is too shallow

Current TUI status labels in `prometheus/interface/tui/findings_library.py:36-54`:
- `new`
- `reviewing`
- `needs_info`
- `submitted`
- `accepted`
- `rejected`
- `dismissed`

Desired pipeline needs more precise states:
- `new`
- `needs_review`
- `validating`
- `verified`
- `rejected`
- `archived`
- `ready_to_submit`
- `submitted`
- `duplicate`
- `accepted`

## 4. Product direction for v1

Prometheus v1 should do one job well:

Take noisy findings from scans or agents and turn the good ones into evidence backed submission drafts.

### 4.1 In scope for v1

Focus on these classes first:

1. IDOR
2. auth bypass
3. account enumeration with clear differential evidence
4. SSRF with internal reachability or controlled callback evidence
5. CORS only when readable data or state changing impact is proven
6. exposed unauthenticated endpoints with real sensitive access
7. source map or client bundle leakage only when chained to a real exploit path

### 4.2 Out of scope for v1

Do not spend time on these for the first build:

1. generic header only findings
2. internal hostname disclosure without exploit chain
3. public API data with free keys
4. normal OAuth behavior presented as a bug
5. vague informational disclosures
6. autonomous submission bots
7. another general purpose pentest orchestrator
8. LinkedIn or content tooling

## 5. Required architecture

## 5.1 Model routing architecture

Prometheus must become Hermes native.

### Required behavior

1. At startup, Prometheus resolves model settings from Hermes active profile using the official Hermes config loader.
2. It reads the effective Hermes `model.provider`, `model.default`, and `model.base_url`.
3. It bridges any required credentials from the current Hermes environment.
4. It configures the OpenAI Agents SDK defaults from that resolved Hermes config.
5. If Hermes config is invalid or missing required model fields, Prometheus stops with a clear error.
6. Prometheus does not silently fall back to local gpt4free, Nous, Ollama, or any hardcoded default. (Migration complete — gpt4free already removed.)

### Required implementation shape

Add a new module:
- `prometheus/config/hermes_bridge.py`

This module should:

1. import Hermes loader from `hermes_cli.config`
2. call `load_config()`
3. resolve a small normalized structure like:

```python
@dataclass
class HermesModelResolution:
    provider: str
    model: str
    base_url: str | None
    api_key_env_name: str | None
    api_key_present: bool
    source_profile: str | None
```

4. expose one function:

```python
def resolve_active_hermes_model() -> HermesModelResolution:
    ...
```

5. expose one SDK setup function:

```python
def apply_hermes_model_defaults() -> HermesModelResolution:
    ...
```

### Required code changes

1. Replace `prometheus/config/models.py` completely.
2. Remove hardcoded default model constants.
3. Stop treating Hermes model use as an optional branch.
4. Make `interface/main.py` and `core/runner.py` call the new Hermes bridge path.
5. Keep one small compatibility path for unit tests only.
6. (Complete — gpt4free test file already deleted, model config cleaned.)

### LLM config ownership rule

After this change:

- Hermes owns provider, model, base URL, and credentials
- Prometheus owns only Prometheus specific runtime settings
- `~/.prometheus/cli-config.json` must no longer be treated as authoritative for LLM routing

## 5.2 Persistence architecture

Use `KnowledgeStore` as the canonical product database layer.

Why:

1. it already owns the richest schema
2. it already backs reporting and target profiles
3. the live DB already contains real `report_status`, `scan_history`, `targets`, and `programs` data
4. duplicating scan and target persistence in separate modules is already creating split brain behavior

### Required direction

Do not keep `ScanPersistence` and `TargetRegistry` as separate sources of truth.

Required end state:

1. `KnowledgeStore` owns the schema and database connection
2. `ScanPersistence` becomes either:
   - a thin compatibility wrapper over `KnowledgeStore`, or
   - deleted after callers are migrated
3. `TargetRegistry` becomes either:
   - a thin compatibility wrapper over `KnowledgeStore`, or
   - deleted after callers are migrated

### New canonical tables to add

Add these normalized tables.
Do not use `full_finding_json` blob as the primary data model anymore.

#### `finding_candidates`

One row per normalized candidate.

Required fields:

- `id TEXT PRIMARY KEY`
- `domain TEXT NOT NULL`
- `scan_id TEXT NOT NULL`
- `source_tool TEXT NOT NULL`
- `source_type TEXT NOT NULL`
- `title TEXT NOT NULL`
- `vuln_type TEXT NOT NULL`
- `severity TEXT`
- `confidence REAL`
- `endpoint TEXT`
- `method TEXT`
- `parameter TEXT`
- `auth_state TEXT`
- `role TEXT`
- `workflow_step TEXT`
- `fingerprint TEXT NOT NULL`
- `lifecycle_status TEXT NOT NULL`
- `rejection_reason TEXT`
- `raw_finding_json TEXT NOT NULL`
- `created_at TEXT NOT NULL`
- `updated_at TEXT NOT NULL`
- `last_seen_at TEXT NOT NULL`

Unique index:
- `(domain, fingerprint)`

#### `finding_evidence`

One row per stored evidence artifact.

Required fields:

- `id TEXT PRIMARY KEY`
- `finding_id TEXT NOT NULL`
- `evidence_kind TEXT NOT NULL`
- `summary TEXT`
- `path TEXT`
- `inline_json TEXT`
- `metadata_json TEXT`
- `created_at TEXT NOT NULL`

Evidence kinds for v1:
- `request`
- `response`
- `diff`
- `control`
- `screenshot`
- `code_location`
- `note`
- `payload_result`
- `browser_trace`

#### `validation_runs`

One row per validation attempt.

Required fields:

- `id TEXT PRIMARY KEY`
- `finding_id TEXT NOT NULL`
- `validator TEXT NOT NULL`
- `status TEXT NOT NULL`
- `confidence REAL`
- `output_json TEXT NOT NULL`
- `started_at TEXT NOT NULL`
- `finished_at TEXT`

Validators for v1:
- `deterministic_gate`
- `live_verification`
- `poc_execution`
- `browser_validation`
- `manual_review`
- `heuristic_judge`

#### `submission_artifacts`

Versioned artifacts for a candidate.

Required fields:

- `id TEXT PRIMARY KEY`
- `finding_id TEXT NOT NULL`
- `platform TEXT NOT NULL`
- `artifact_type TEXT NOT NULL`
- `version INTEGER NOT NULL`
- `path TEXT NOT NULL`
- `sha256 TEXT NOT NULL`
- `created_at TEXT NOT NULL`

Artifact types for v1:
- `report_markdown`
- `bugcrowd_json`
- `h1_markdown`
- `poc_script`
- `evidence_bundle`

#### `submission_events`

Immutable lifecycle log.

Required fields:

- `id INTEGER PRIMARY KEY AUTOINCREMENT`
- `finding_id TEXT NOT NULL`
- `event_type TEXT NOT NULL`
- `from_status TEXT`
- `to_status TEXT`
- `actor TEXT NOT NULL`
- `payload_json TEXT`
- `created_at TEXT NOT NULL`

### Compatibility requirement

Keep `report_status` as a projection table for the TUI during migration.
Do not break current browse mode while the richer model is introduced.

## 5.3 Candidate pipeline architecture

Prometheus v1 pipeline should be:

### Phase A: Ingest

Inputs:
- scan results
- agent findings
- manual findings
- replay or deep audit results

Output:
- normalized `finding_candidates` rows

Add modules:
- `prometheus/core/candidate_schema.py`
- `prometheus/core/candidate_normalizer.py`
- `prometheus/core/candidate_fingerprint.py`
- `prometheus/core/candidate_store.py`

Rules:

1. every finding gets a deterministic fingerprint
2. raw source payload is preserved
3. normalized fields are extracted once
4. dedupe happens before expensive validation

### Phase B: Deterministic gate

Reject garbage early using hard rules.

Examples of immediate reject rules:

- missing security headers without concrete exploit path
- internal hostname only
- public information with no security impact
- generic version disclosure with no exploit chain
- CORS preflight only evidence
- source map without sensitive or exploitable code
- rate limit issue on low value endpoint

Output statuses:
- `rejected`
- `needs_review`

### Phase C: Validation

For non rejected candidates:

1. create validation plan
2. run positive controls
3. run negative controls
4. run live replay if needed
5. run browser validation if curl is not enough
6. store all evidence
7. produce structured validation verdict

Output statuses:
- `validating`
- `verified`
- `rejected`
- `ready_to_submit`

### Phase D: Reporting

For verified findings:

1. generate report draft from stored evidence
2. generate PoC artifact
3. generate evidence bundle
4. generate platform specific submission draft
5. wait for human review

### Phase E: Outcome feedback

After submission:

1. store accepted, duplicate, informative, or N/A outcome
2. store analyst comments
3. feed that back into rejection and scoring rules

## 6. Validation rules for v1 classes

These are hard acceptance gates.

### IDOR

Required:
- at least 2 positive controls
- at least 1 negative control
- proof of unauthorized read or write

Reject if:
- only guessable identifier theory
- only sequential IDs without unauthorized access

### Auth bypass

Required:
- protected action or resource accessed without valid auth
- stable replay
- control showing expected denial under normal conditions

### Account enumeration

Required:
- stable differential response classes
- at least 2 distinct response fingerprints
- practical impact note

Reject if:
- tiny wording change with no workflow impact
- only timing jitter without stable pattern

### SSRF

Required:
- internal reachability, controlled callback, or trusted internal metadata access
- exact request and response evidence

Reject if:
- only theoretical URL reflection
- only blocked request attempt with no internal effect

### CORS

Required:
- readable protected response body, or
- state changing CSRF with real authenticated action

Reject if:
- only reflected origin on OPTIONS or preflight
- no readable data
- no authenticated impact

### Exposed unauthenticated endpoint

Required:
- real sensitive access or privileged action
- endpoint reachable without auth

Reject if:
- public documentation endpoint
- intended public asset or public API response

### Source map or bundle leak

Required:
- leaked code enables exploit chain or sensitive discovery
- chain is documented and testable

Reject if:
- only source visibility with no exploit path

## 7. Required refactors of existing modules

## 7.1 `prometheus/config/models.py`

Action: replace completely.

Required end state:
- valid syntax
- Hermes backed resolver
- no hardcoded local default model
- one clean SDK setup path

## 7.2 `prometheus/config/settings.py`

Action: simplify.

Required end state:
- `llm` section only contains Prometheus specific overrides if they are truly needed
- default path is Hermes backed
- if `use_hermes_model` remains, default it to `True` and treat `False` as a test or escape hatch only

Preferred end state:
- remove `prometheus_LLM` from primary runtime path entirely

## 7.3 `prometheus/config/loader.py`

Action: stop persisting Prometheus owned LLM config as authoritative state.

Required end state:
- `~/.prometheus/cli-config.json` only stores Prometheus specific runtime settings
- it does not compete with Hermes model config

## 7.4 `prometheus/core/runner.py`

Action: keep it as the main scan orchestrator, but move candidate ingestion and validation into explicit stages.

Required changes:
- use canonical candidate store
- sync scan start and end through canonical persistence
- after vulnerabilities are produced, normalize and ingest them before report sync
- stop treating raw `vulnerabilities.json` as the only real artifact

## 7.5 `prometheus/tools/reporting/tool.py`

Action: keep the public report tool, change the backend.

Required end state:
- generate reports from `finding_id` plus stored evidence
- no dependence on ad hoc in memory fields only
- write versioned report artifacts
- keep duplicate detection, CVE and CWE validation, VRT classification

## 7.6 `prometheus/core/validation_judge.py`

Action: demote from primary gate to secondary heuristic judge.

Reason:
- current design is mostly keyword criteria and text heuristics
- that is not enough to decide reportability by itself

Required end state:
- it can score or annotate
- it cannot be the only reason a finding becomes `ready_to_submit`

## 7.7 `prometheus/core/poc_validation.py`

Action: harden.

Current issue:
- it extracts curl commands and runs them with `shell=True`

Required end state:
- no arbitrary shell execution path from raw PoC text
- execute only structured commands or generated scripts under controlled runner
- every run stores stdout, stderr, exit code, and timing in `validation_runs`

## 7.8 `prometheus/core/live_verification.py`

Action: keep and extend.

Required end state:
- replay helpers return structured evidence objects
- verification results are stored, not just returned
- support request pairs for positive and negative controls

## 7.9 `prometheus/interface/tui/findings_library.py`

Action: migrate to the new lifecycle model.

Required end state:
- show candidate queue and validation state
- show evidence and artifact versions
- allow manual status transitions only through legal workflow paths

## 8. Ordered implementation plan

Do this in order.
Do not jump to later phases before the earlier one is green.

### Phase 0: Repair the baseline

Tasks:

1. Replace broken `prometheus/config/models.py`
2. Make repo importable again
3. Make compile smoke pass
4. (Complete — gpt4free already removed from codebase.)

Definition of done:

- `python3 -m compileall $PROMETHEUS_SOURCE/prometheus` passes
- model config tests pass
- no syntax errors remain in the package

### Phase 1: Hermes native model resolution

Tasks:

1. Add `prometheus/config/hermes_bridge.py`
2. Resolve current active Hermes model through official loader
3. Apply SDK defaults from Hermes resolution
4. Remove hardcoded model fallback logic
5. Update startup health checks in `interface/main.py`
6. Update runtime resolution in `core/runner.py`

Definition of done:

- Prometheus logs effective Hermes provider, model, and base URL at startup
- current active Hermes profile resolves to `openai-codex / gpt-5.4 / https://chatgpt.com/backend-api/codex`
- Prometheus no longer requires separate `prometheus_LLM` to run in normal mode
- failure to read Hermes config stops startup loudly

### Phase 2: Canonical persistence and migrations

Tasks:

1. Add migration framework for Prometheus DB
2. Add normalized candidate and evidence tables
3. Backfill compatibility projection for `report_status`
4. Wrap or retire `ScanPersistence`
5. Wrap or retire `TargetRegistry`

Definition of done:

- existing DB data is preserved
- current TUI still opens
- scans, targets, and reports all resolve through one canonical DB layer

### Phase 3: Candidate normalization and ingest

Tasks:

1. Add normalized candidate schema
2. Add fingerprinting and dedupe
3. Ingest raw findings into `finding_candidates`
4. Add deterministic rejection rules
5. Write migration from current `full_finding_json` blobs where needed

Definition of done:

- every new finding gets a candidate row
- duplicates are prevented by fingerprint before deeper validation
- obvious junk is rejected before LLM work

### Phase 4: Evidence first validation

Tasks:

1. Formalize validation plan per finding type
2. Use `HypothesisManager` as the control evidence gate for novel or complex findings
3. Store positive and negative controls in DB
4. Refactor `live_verification.py` to emit structured evidence
5. Refactor `poc_validation.py` to safe execution model
6. Keep `validation_judge.py` as annotation only

Definition of done:

- findings can only become `ready_to_submit` after stored evidence exists
- every verified finding has exact evidence rows tied to it
- no reportable finding depends only on free form prose

### Phase 5: Report artifact generation

Tasks:

1. Generate versioned report markdown from stored evidence
2. Generate versioned PoC artifacts
3. Generate versioned evidence bundle
4. Generate Bugcrowd or HackerOne specific drafts
5. Keep duplicate detection and VRT classification

Definition of done:

- each ready finding has a stable artifact directory
- the TUI can open the latest report version without re generating from memory
- platform specific drafts are reproducible

### Phase 6: TUI workflow migration

Tasks:

1. Replace shallow statuses with new lifecycle states
2. Add queues for review, validating, ready to submit, submitted, outcomes
3. Add evidence pane and artifact version view
4. Add manual review actions with reason capture

Definition of done:

- the operator can work the full submission pipeline from the TUI
- status transitions are explicit and auditable

### Phase 7: Outcome feedback loop

Tasks:

1. Store submission results and comments
2. Feed those outcomes into heuristics and rejection rules
3. Add summary views for false positives, duplicates, and accepted reports

Definition of done:

- Prometheus learns from accepted versus rejected patterns in its own DB
- future triage becomes stricter and cheaper

## 9. File level change list

This is the minimum planned file map.

### Replace

- `prometheus/config/models.py`

### Add

- `prometheus/config/hermes_bridge.py`
- `prometheus/core/candidate_schema.py`
- `prometheus/core/candidate_normalizer.py`
- `prometheus/core/candidate_fingerprint.py`
- `prometheus/core/candidate_store.py`
- `prometheus/db/migrations.py` or equivalent migration module
- new tests for Hermes model resolution, candidate normalization, evidence persistence, lifecycle rules

### Refactor heavily

- `prometheus/config/settings.py`
- `prometheus/config/loader.py`
- `prometheus/core/runner.py`
- `prometheus/tools/knowledge/store.py`
- `prometheus/tools/reporting/tool.py`
- `prometheus/core/validation_judge.py`
- `prometheus/core/poc_validation.py`
- `prometheus/core/live_verification.py`
- `prometheus/interface/tui/findings_library.py`
- `prometheus/core/orchestrator.py`
- `prometheus/core/scheduler.py`

### Keep and integrate, do not throw away

- `prometheus/core/hypotheses.py`
- `prometheus/core/attack_surface.py`
- `prometheus/core/scan_goals.py`
- `prometheus/core/deep_audit.py`
- `prometheus/core/oauth_validation.py`
- `prometheus/core/vrt_classifier.py`

## 10. Required tests

Add and run these categories.

### Model routing tests

1. resolves active Hermes provider and model from loader
2. applies Hermes base URL to SDK defaults
3. fails loud on invalid Hermes config
4. does not silently fall back to local default model

### Persistence tests

1. candidate insert and fingerprint dedupe
2. evidence insert and retrieval
3. migration preserves existing `report_status`, `targets`, `scans`, `programs`
4. compatibility projection still feeds TUI lists

### Validation tests

1. IDOR control gate
2. account enumeration differential response gate
3. CORS readable data gate
4. SSRF internal reachability gate
5. auth bypass gate
6. PoC execution stores structured result rows

### Reporting tests

1. generate report artifact from stored evidence only
2. generate Bugcrowd draft with VRT mapping
3. duplicate detection blocks repeat artifact generation when appropriate

### Smoke tests

1. package compile
2. TUI browse mode startup
3. one sample candidate end to end from ingest to report draft

## 11. Validation commands to use during implementation

Use real commands. Do not claim green without running them.

### Compile smoke

```bash
python3 -m compileall $PROMETHEUS_SOURCE/prometheus
```

### Pytest on this machine if `pytest` is not on PATH

```bash
`PYTHONPATH=$PROMETHEUS_SOURCE/../pytest-site:$PROMETHEUS_SOURCE python3 -m pytest -q tests/test_hermes_model_config.py`
```

### Minimal targeted test during model repair

```bash
`PYTHONPATH=$PROMETHEUS_SOURCE/../pytest-site:$PROMETHEUS_SOURCE python3 -m pytest -q tests/test_hermes_model_config.py`
```

Rename that test file after refactor. The command here is only the current baseline reference.

## 12. Migration rules

1. Never wipe `$HOME/.prometheus/prometheus.db`
2. Migrate in place with explicit schema versioning
3. Backfill new candidate and evidence tables from existing report records where possible
4. Keep current `report_status` readable during migration
5. Do not break browse mode while the schema is evolving

## 13. Repo safety rules for the implementation agent

1. The repo is dirty right now.
   `git status` shows many unrelated modified files and new files.
   Do not reset the repo.
   Do not mass format unrelated files.
   Only touch files required for this build.

2. Do not delete existing data files under `prometheus_runs/`.

3. Do not introduce a second model source of truth.

4. Do not keep shell based arbitrary PoC execution.

5. Do not replace real evidence with LLM summaries.

## 14. Acceptance criteria for the whole project

This project is done when all of these are true:

1. Prometheus starts and runs using the active Hermes model configuration by default.
2. There is no hardcoded local model fallback in the normal runtime path.
3. The repo compiles cleanly.
4. Findings are stored as normalized candidates, not only raw blobs.
5. Validation evidence is stored in structured tables.
6. `ready_to_submit` requires real stored evidence and control runs.
7. Report artifacts are generated from stored evidence, versioned on disk, and reproducible.
8. Existing DB data is preserved.
9. The TUI supports the new lifecycle model.
10. A human still has to approve submission.

## 15. Short execution summary for the next Hermes agent

If another Hermes agent is told to execute this file, the order should be:

1. fix `prometheus/config/models.py`
2. make Prometheus Hermes native for model routing
3. consolidate persistence around `KnowledgeStore`
4. add normalized candidate and evidence tables
5. refactor validation to evidence first gates
6. refactor report generation to artifact based workflow
7. migrate TUI lifecycle states
8. run compile and tests after each phase
9. stop only when the artifact is working, not when the plan looks good

## 16. Audit evidence references

Useful file references from this audit:

- `run_prometheus.py:1-7`
- `prometheus/interface/main.py:34-39`
- `prometheus/interface/main.py:77-84`
- `prometheus/interface/main.py:219-223`
- `prometheus/interface/main.py:274-507`
- `prometheus/core/runner.py:138-146`
- `prometheus/core/runner.py:152-180`
- `prometheus/core/runner.py:565-589`
- `prometheus/agents/factory.py:822-900`
- `prometheus/agents/factory.py:903-992`
- `prometheus/config/settings.py:20-66`
- `prometheus/config/loader.py:24-143`
- `prometheus/config/models.py:1-34`
- `$PROMETHEUS_SOURCE/../hermes-agent/hermes_cli/config.py:4905-5001`
- `$HOME/.hermes/config.yaml:1-4`
- `prometheus/tools/knowledge/store.py:165-183`
- `prometheus/tools/knowledge/store.py:646-867`
- `prometheus/tools/reporting/tool.py:856-982`
- `prometheus/core/hypotheses.py:22-31`
- `prometheus/core/hypotheses.py:99-109`
- `prometheus/core/validation_judge.py:21-45`
- `prometheus/core/validation_judge.py:831-1060`
- `prometheus/core/poc_validation.py:24-27`
- `prometheus/core/poc_validation.py:167-191`
- `prometheus/core/poc_validation.py:243-350`
- `prometheus/core/live_verification.py:37-120`
- `prometheus/core/scan_persistence.py:27-126`
- `prometheus/core/target_registry.py:29-73`
- `prometheus/interface/tui/findings_library.py:36-54`

End of spec.
