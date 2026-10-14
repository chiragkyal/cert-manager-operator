---
name: /opsx-e2e
id: opsx-e2e
category: QE
description: Generate E2E test plans and code from ADR, EP, PR, or any combination
argument-hint: "[change-name] [--pr <URL>] [--adr <path-or-URL>] [--ep <path-or-URL>]"
---

Generate E2E test plans and executable test code. Supports **three input modes** — the
pipeline depth adapts based on what is provided.

**When to use:** after OpenSpec development (change name + PR from `/opsx-apply`) **or**
standalone when you already have a PR and/or ADR/EP — no prior `/opsx-new` workflow required.

| Input | Mode | Pipeline |
|-------|------|----------|
| **PR only** | PR Mode | Full: pre-analysis → plan → consolidation → codegen → execute → push |
| **ADR or EP only** | Design Mode | pre-analysis → plan → consolidation → codegen → [optional local execute] |
| **ADR/EP + PR** | Combined Mode | Full pipeline with enriched design context |
| **Change name** (from `/opsx-apply`) | Change Mode | Resolves PR from `state.yaml`, then runs Full |

**Design Mode** (ADR/EP without PR) generates the test plan and code. After code
generation, it checks whether the ADR implementation already exists in the target repo
and offers optional local execution if the user has a cluster with the implementation
deployed. Push is never available in Design Mode (there is no PR branch to push to).
The developer reviews the plan and code, then runs `/opsx-e2e --pr <URL>` later when
a PR exists to execute and push.

**Input**: At least one of: change name, `--pr <URL>`, `--adr <path-or-URL>`, `--ep <path-or-URL>`.

## Telemetry

This command emits QE telemetry events throughout execution. Events are written to:
```
openspec/changes/<name>/telemetry/e2e-events.jsonl
```

At completion, a `qe-metrics.json` report is generated with 7 key metrics:
- AC → scenario coverage %
- Automation coverage %
- E2E first-pass pass rate
- Flake rate
- Bugs found / verified
- Triage accuracy %
- QE tokens / $ / wall time

Use the same token estimation approach as the development workflow (`openspec/telemetry/tokens.py`).

**Note:** `/opsx-e2e` does NOT ask for time-saved, story points, or feedback —
that is collected once, centrally, by `/opsx-archive` (which asks the QE
questions only if this change has an E2E run, i.e. this events file exists).
`/opsx-e2e` only needs to emit lifecycle/stage/execution events; `qe-metrics.json`
will show `qe_feedback: null` and `qe_report_status.complete: false` until
`/opsx-archive` runs.

**Telemetry module:** `openspec/telemetry/qe_events.py` (event emission),
`openspec/telemetry/qe_metrics.py` (report generation)

## Schema package

| Role | Path |
|------|------|
| E2E workflow templates | `{schema_root}/e2e-workflow/` |
| Pre-analysis gate | `{schema_root}/e2e-workflow/pre-analysis-gate.md` |
| Test plan generation | `{schema_root}/e2e-workflow/test-plan-generation.md` |
| QE behaviour (generic rules) | `{schema_root}/e2e-workflow/qe-behaviour.md` (Sections 1-5: universal QE rules) |
| QE behaviour (operator-specific) | `<operator-repo>/qe-e2e/qe-behaviour.md` (Sections 3a/3b: deployment + quality gates) |
| Test helpers (operator-specific) | `<operator-repo>/qe-e2e/helpers.md` (optional: helper function signatures) |

## Steps

### 0. HARD GUARDRAIL — Operator context check (MANDATORY, NON-SKIPPABLE)

**Before ANY other step, you MUST read and verify these operator context files exist.
Do NOT proceed past this step without them.**

#### 0a. Check `agents.md`

Look for `agents.md` (or `AGENTS.md`) at the **operator repo root** (the `target_repo`
from `inputs/jira.yaml`, or the repo inferred from the PR URL).

- **If found:** Read it in full. This is the primary agentic context for the operator.
  It defines agent routing, controller patterns, test conventions, and coding rules.
  All downstream stages MUST respect these conventions.
- **If NOT found:**
  STOP and output:
  **"BLOCKED: `agents.md` not found at the operator repo root. This file defines
  the operator's agentic conventions (controller patterns, test style, coding rules)
  and is required for accurate E2E generation.**
  **Action: Create `agents.md` at your operator repo root, or run `/opsx-constitute`
  to bootstrap operator context. Then re-run `/opsx-e2e`."**
  Do NOT proceed.

#### 0b. Check `harness-evals/` documentation

Check for the `harness-evals/` directory in the openspec workspace:

1. **`harness-evals/constitution.md`** — the operator's constitution (governance guardrails)
2. **`harness-evals/harness-docs/`** — operator documentation (architecture guides, conventions)
3. **`harness-evals/evals/`** — stage eval YAML files (if present, used for eval-aware test gen)

- **If `harness-evals/constitution.md` exists:** Read it. This provides non-negotiable
  guardrails for the operator. Pass these constraints to all downstream stages.
- **If `harness-evals/constitution.md` does NOT exist:**
  STOP and output:
  **"BLOCKED: `harness-evals/constitution.md` not found. The constitution defines
  non-negotiable operator guardrails (coding conventions, test patterns, architecture rules)
  that E2E generation must respect.**
  **Action: Run `/opsx-constitute` to generate constitution.md from your harness-docs,
  then re-run `/opsx-e2e`."**
  Do NOT proceed.
- **If `harness-evals/harness-docs/` exists:** Read all `.md` files. These provide
  operator-specific context (architecture, testing patterns, deployment constraints).
- **If `harness-evals/harness-docs/` does NOT exist or is empty:**
  WARN: **"No harness documentation found in `harness-evals/harness-docs/`.
  E2E generation will proceed with agents.md and constitution.md only.
  For richer context, add operator docs to `harness-evals/harness-docs/`."**
  Proceed (this is a warning, not a blocker).
- **If `harness-evals/evals/` exists:** Note available stage evals. These may inform
  which patterns the eval-loop has identified as important for this operator.

#### 0c. Check operator `qe-e2e/` directory

Look for `qe-e2e/` at the **operator repo root** (same location as `agents.md`):

1. **`qe-e2e/qe-behaviour.md`** — operator-specific deployment context (Section 3a) and quality
   gates (Section 3b). This is the operator team's filled-in version of the generic template
   from `{schema_root}/e2e-workflow/qe-behaviour.md`.
   - **If found:** Read it. This provides the operator's deployment model, namespace, CR kinds,
     quality gates, and domain-specific observables. Pass to Stage 1 (pre-analysis) as operator
     context — it will be embedded into `e2e-analysis.md` for downstream stages.
   - **If NOT found:** WARN (not a blocker). Derive deployment context from `agents.md` and
     quality gates from `constitution.md`. Output:
     **"⚠ `qe-e2e/qe-behaviour.md` not found. Deriving operator context from agents.md.
     For richer E2E context, create `qe-e2e/qe-behaviour.md` using the template in
     `{schema_root}/e2e-workflow/qe-behaviour.md` Section 3a/3b."**

2. **`qe-e2e/helpers.md`** (optional) — operator-specific test helper function signatures for
   code generation (e.g., `NewTestPod(...)`, `SetupTestEnvironment(...)`).
   - **If found:** Read it. Pass to Stage 4 (code generation) for helper discovery.
   - **If NOT found:** Not a problem. Stage 4 will discover helpers from `test/e2e/utils/` in
     the target repo and from `agents.md`.

#### 0d. Preflight output

After reading all context files, output a preflight summary:

```
======================================================================
/opsx-e2e — Operator Context Preflight
======================================================================
agents.md:                  ✓ Found (<path>)
constitution.md:            ✓ Found (harness-evals/constitution.md)
harness-docs/:              ✓ Found (N files) | ⚠ Not found (warning only)
harness-evals/evals/:       ✓ Found (N stage evals) | — Not found (optional)
qe-e2e/qe-behaviour.md:    ✓ Found (<path>) | ⚠ Not found (deriving from agents.md)
qe-e2e/helpers.md:          ✓ Found (<path>) | — Not found (will discover from repo)
======================================================================
```

Proceed to Step 1 only after this preflight passes (agents.md + constitution.md both found).

### 1. Resolve inputs and determine mode

Parse the user's arguments to determine which input mode applies:

| Argument | What it provides |
|----------|-----------------|
| `<change-name>` | Resolves PR from `state.yaml` (Change Mode) |
| `--pr <URL>` | Direct PR URL |
| `--adr <path-or-URL>` | ADR document (local path, GitHub URL, or Google Docs URL) |
| `--ep <path-or-URL>` | Enhancement Proposal (same input formats as ADR) |
| `--phase N` | Phase number (for phase-iterative changes) |

#### Mode resolution

Apply in this order:

1. **If `--pr` is provided or a PR is resolved from change name:**
   - If `--adr` or `--ep` also provided → **Combined Mode** (full pipeline, design-enriched)
   - If neither ADR nor EP → **PR Mode** (full pipeline, infer from diff)

2. **If `--adr` or `--ep` is provided but NO PR:**
   → **Design Mode** (plan-only pipeline — stops after code generation, no execute/push)

3. **If only a change name and no PR can be resolved:**
   - Check `state.yaml` for `phase_pr_urls` for PR URL
   - If found → treat as PR Mode (or Combined if ADR/EP also given)
   - If not found → ASK: **"No PR found for this change. Provide an ADR, EP, or PR URL
     to proceed, or run `/opsx-apply` first to raise a PR."**

4. **If nothing provided:**
   → STOP: **"At least one input required: `--pr <URL>`, `--adr <path>`, `--ep <path>`,
   or a change name with an existing PR. See `/opsx-e2e --help`."**

#### Fetching inputs

**PR (when available):**
```bash
gh pr view <PR-NUMBER> --repo <org/repo> --json title,body,state,labels,files
gh pr diff <PR-NUMBER> --repo <org/repo>
gh api repos/<org>/<repo>/pulls/<PR-NUMBER>/comments
gh api repos/<org>/<repo>/pulls/<PR-NUMBER>/reviews
```

**ADR / EP:**
- Accept Google Docs URL, GitHub file URL, local file path, or pasted markdown
- If fetch fails → ASK the user to paste the content
- ADR and EP are treated identically for scoping purposes; the label is for traceability

**Target repo:**
- From `inputs/jira.yaml → target_repo` (if change exists)
- From PR URL (extract `org/repo`)
- From ADR/EP content (if it references a repo)
- If none resolved → ASK: **"What is the target GitHub repository URL?"**

**Telemetry:** Emit `e2e_run_start` event with `pr_url` (or null), `adr_provided`, `ep_provided`,
`mode` (pr/design/combined), and `phase`.

### 2. Set up working directory

Create E2E artifacts directory:
```
openspec/changes/<name>/e2e/
```

If no change name exists (Design Mode without prior `/opsx-new`):
- Derive a name from the ADR/EP title (kebab-case)
- Create `openspec/changes/<name>/e2e/` for artifacts

All E2E artifacts are written here: `e2e-analysis.md`, `test-plan.md`, generated code.

### 3. Stage 1 — Pre-Analysis

Read and follow **`{schema_root}/e2e-workflow/pre-analysis-gate.md`** in full.

The pre-analysis template already supports ADR Mode, PR Mode, and ADR+PR Mode.
Pass the correct inputs based on the resolved mode:

**Stage 1 is the HEAVY READ stage.** All operator context is consumed here and distilled
into `e2e-analysis.md` with an embedded Operator Context section. Downstream stages read
only `e2e-analysis.md` — they do NOT re-read the raw operator files.

**All mode inputs (common):**
- `agents.md` content (full — from step 0a)
- `harness-evals/constitution.md` content (full — from step 0b)
- `{schema_root}/e2e-workflow/qe-behaviour.md` Sections 1-5 (generic QE rules)
- `qe-e2e/qe-behaviour.md` Sections 3a/3b (operator-specific deployment + quality gates — from step 0c, if present)
- `harness-docs/*.md` (from step 0b, if present)
- `harness-evals/evals/` (from step 0b, if present — for eval-aware pattern coverage)
- Target repo (from step 1)

**PR Mode additional inputs:**
- PR URL, diff, review comments

**Design Mode additional inputs (ADR/EP only):**
- ADR or EP document content

**Combined Mode:**
- All PR Mode inputs PLUS ADR/EP document content

**Process:**
1. In PR Mode / Combined: fetch PR metadata, diff, and review comments via `gh`
2. In Design Mode: read ADR/EP document; use it as the primary scoping source
3. Classify change type
4. Perform impact analysis, coverage assessment, blast radius, regression risk
5. Cross-check proposed tests against `agents.md` conventions and `constitution.md` guardrails
6. If `harness-evals/evals/` stage evals exist: review them for patterns the eval-loop has
   flagged — ensure proposed E2E tests cover those patterns where relevant
7. Produce proposed test cases (priority-ordered, scales with complexity per pre-analysis budget rules)
8. **Embed operator context into the output:** Populate the "Operator Context (Embedded)" section
   in `e2e-analysis.md` with deployment model, quality gates, and constraints extracted from
   `qe-e2e/qe-behaviour.md` (or derived from `agents.md`/`constitution.md` if qe-e2e not present)
9. Write `openspec/changes/<name>/e2e/e2e-analysis.md`

**Approval gate:**
- Present the analysis to the user
- STOP and wait for: **Approved** / **Approved with changes** / **Rejected**
- On reject → re-run with feedback
- On approve → proceed to Stage 2

**Telemetry:** Emit `e2e_stage_start` (stage=1, stage_name="pre_analysis") before processing.
On approval, emit `e2e_stage_end` with `tokens_in` (PR diff / ADR content + agents.md +
constitution.md + qe-e2e/qe-behaviour.md + harness-docs + generic qe-behaviour.md token count),
`tokens_out` (e2e-analysis.md token count), `duration_s`, and `refinement_rounds`
(0 if approved first time).

### 4. Stage 2 — Test Plan Generation

Read and follow **`{schema_root}/e2e-workflow/test-plan-generation.md`** in full.

**Inputs (NARROW — no raw operator docs):**
- Approved `e2e-analysis.md` (from stage 1 — carries all scoping decisions + embedded operator context)
- `{schema_root}/e2e-workflow/qe-behaviour.md` Sections 1-5 (generic QE writing rules — precision, traceability, surgical scope)
- PR diff (for traceability to specific file:line — PR Mode / Combined Mode only)

**Do NOT re-read** `agents.md` or `constitution.md` at this stage. The operator context
they provided is already embedded in `e2e-analysis.md` Section "Operator Context (Embedded)".

**Process:**
1. Read approved `e2e-analysis.md` as scoping input (includes embedded operator context)
2. Read `{schema_root}/e2e-workflow/qe-behaviour.md` Sections 1-5 for QE writing discipline
3. Expand proposed test cases into full test steps (preconditions, steps, expected outcomes, cleanup)
4. Build traceability matrix
5. Run quality gates (Section 8 of template) — revise until all pass
6. Write `openspec/changes/<name>/e2e/test-plan.md`

**Approval gate:**
- Present test plan summary (test count, tier distribution, quality gate results)
- STOP and wait for user approval
- On reject → revise with feedback
- On approve → proceed to Stage 3

**Telemetry:** Emit `e2e_stage_start` (stage=2, stage_name="test_plan") before processing.
On approval, emit `e2e_stage_end` with `tokens_in` (e2e-analysis.md + generic qe-behaviour.md
Sections 1-5 + PR diff token count), `tokens_out` (test-plan.md token count), `duration_s`,
and `refinement_rounds`.

### 5. Stage 3 — Code Generation

Apply Section 13 of `test-plan-generation.md` (Journey Code Generation).

**Inputs (TARGETED — code-level context only):**
- Approved `test-plan.md` (from stage 2)
- `agents.md` — **helpers/style/framework sections ONLY** (for generating compilable code
  that follows the operator's coding conventions). Do NOT re-read the full architecture
  sections — use the embedded operator context from `e2e-analysis.md` (carried through
  `test-plan.md`) for scoping.
- `qe-e2e/helpers.md` (if found in step 0c — operator-specific test builder function signatures)
- Target repo `test/e2e/` patterns (auto-discovered: framework, helpers, constants)

**Process:**
1. ASK: "Which journeys to generate code for? (all / specific numbers / none)"
2. Read `agents.md` for code style conventions and helper function signatures
3. Read `qe-e2e/helpers.md` if present for operator-specific test builders
4. Detect test framework from target repo (`ginkgo`, `testing`, `testify`)
5. Generate ONE test file per component/CR kind — all journeys for the same component go in a single
   `<component>_e2e_test.go`. Create a separate file only for a genuinely different component.
6. Write generated code to `openspec/changes/<name>/e2e/generated/`

**Approval gate:**
- Present generated code summary (file path, journey count, framework, helpers used)
- STOP and wait for user approval
- On reject → revise code
- On approve → proceed to Stage 4

**Telemetry:** Emit `e2e_stage_start` (stage=3, stage_name="code_generation") before processing.
On approval, emit `e2e_stage_end` with `tokens_in` (test-plan.md + repo patterns token count),
`tokens_out` (sum of all generated *_test.go file token counts), `duration_s`, and `refinement_rounds`.

### 6. Stage 4 — Execute, Evaluate, and Push

**Design Mode gate:** If running in **Design Mode** (ADR/EP only, no PR), proceed to
**Step 6a (Design Mode: Implementation Check & Optional Local Execution)** below.
Do NOT skip to Step 8 immediately — the user may want to run tests locally.

**PR Mode / Combined Mode:** Skip Step 6a and continue with Stage 4 below.

**Telemetry:** Emit `e2e_stage_start` (stage=4, stage_name="execution") before execution.

#### Step 6a — Design Mode: Implementation Check & Optional Local Execution

This step runs ONLY in **Design Mode** (ADR/EP only, no PR), after Stage 4 code generation
is approved. It checks whether the ADR implementation exists in the target repo and offers
optional local test execution.

**Step 6a.1 — Implementation presence check:**

Search the target repo for evidence that the ADR's implementation already exists.
Look for new CRD types, controller files, API changes, or other code referenced in the
ADR and/or `e2e-analysis.md`:

1. Check for new/modified controller files matching the ADR scope
2. Check for new CRD definitions or API types
3. Check for new test helpers or fixtures

Output a clear status:
- **"Implementation FOUND:** detected `<files/CRDs/packages>` matching the ADR scope
  in the target repo at `<repo-path>`."
- **"Implementation NOT FOUND:** no code matching the ADR scope detected in the target
  repo. Tests targeting new behaviour will fail if run without the implementation deployed."

**Step 6a.2 — Local execution prompt (HARD GUARDRAIL — must ASK, never assume):**

ASK the user explicitly:

> **"The generated E2E tests are ready. Would you like to run them locally on your cluster?**
>
> **Prerequisites for local execution:**
> - Your cluster must be running and accessible via KUBECONFIG
> - The operator must be **built and deployed with the ADR implementation**
> - If the implementation is not deployed, tests targeting new behaviour will be skipped or fail
>
> **Implementation status:** [FOUND in repo / NOT FOUND in repo]
>
> **Run E2E tests locally? (Yes / No)"**

- **No** → proceed to the Design Mode completion banner and Step 8 (Final Summary):

```
======================================================================
Design Mode — E2E Pipeline Complete (Plan + Code)
======================================================================
Mode:           Design (ADR/EP only — no PR)
Input:          <ADR/EP title or path>
Implementation: <FOUND / NOT FOUND> in target repo
Artifacts:      e2e-analysis.md, test-plan.md, generated code
Location:       openspec/changes/<name>/e2e/
Local tests:    Skipped (user declined)

No PR exists — push is not available.

Next steps:
  1. Review the generated test plan and code
  2. When a PR is raised, re-run: /opsx-e2e --pr <URL>
     (the existing plan and code will be reused if still valid)
  3. To test locally later: re-run /opsx-e2e --adr <path> with your cluster ready
======================================================================
```

- **Yes** → run the same cluster readiness gate (Step 5.2), execution (Step 5.3), and
  evaluation (Step 5.4) flow that PR Mode uses. **Skip the push step (5.6) entirely**
  since there is no PR branch. After execution, output:

```
======================================================================
Design Mode — E2E Pipeline Complete (Plan + Code + Local Execution)
======================================================================
Mode:           Design (ADR/EP only — no PR)
Input:          <ADR/EP title or path>
Implementation: <FOUND / NOT FOUND> in target repo
Artifacts:      e2e-analysis.md, test-plan.md, generated code
Location:       openspec/changes/<name>/e2e/
Local tests:    <N> run, <M> passed, <K> failed

No PR exists — push is not available.

Next steps:
  1. Review test results and generated code
  2. When a PR is raised, re-run: /opsx-e2e --pr <URL> to push
======================================================================
```

  Then proceed to Step 8 (Final Summary) with execution results included.

**Telemetry (Step 6a):** If local tests were run, emit the same `e2e_execution`,
`e2e_bug_found`, and `e2e_bug_verified` events as in Step 5.3/5.4. Run
`python -m openspec.telemetry.qe_metrics --change <name>` after execution to
generate accurate metrics from the local run.

Time-saved, story points, and feedback are collected later by `/opsx-archive` — not here.

---

#### Step 5.1 — Local execution prompt (PR Mode / Combined Mode)

**HARD GUARDRAIL — must ASK, never assume:**

ASK: **"Run E2E tests locally on your cluster? (Yes / No)"**

Do NOT auto-execute tests. Do NOT assume the answer. If the user declines, skip
directly to Step 5.5 (Push / Feedback / Stop).

- **No** → skip to Step 5.5 (final decision: push / feedback / stop).
- **Yes** → proceed to Step 5.2.

#### Step 5.2 — Cluster readiness gate

Before running tests, validate the target cluster is reachable and the operator is healthy.

1. Read `config.yaml → credentials.cluster.kubeconfig_path`.
   - If empty, ASK: **"Provide the absolute path to your KUBECONFIG file for the target cluster:"**
   - Persist the user's response to `config.yaml → credentials.cluster.kubeconfig_path` for future runs.

2. Export the kubeconfig:
   ```bash
   export KUBECONFIG=<path>
   ```

3. Read `OPERATOR_NAMESPACE` from the repo's Makefile (grep for `OPERATOR_NAMESPACE`).
   Fall back to the `test/e2e/utils/constants.go` `OperatorNamespace` constant if not in Makefile.

4. Run pre-flight checks sequentially. Each check records pass/fail:
   ```bash
   oc whoami --show-server                                        # cluster reachable?
   oc whoami                                                      # authenticated?
   oc get ns <OPERATOR_NAMESPACE>                                 # namespace exists?
   oc get csv -n <OPERATOR_NAMESPACE> -o jsonpath='{.items[0].status.phase}'  # CSV Succeeded?
   ```

5. If **any check fails**, STOP with a checklist showing what passed and what failed:
   ```
   Cluster readiness check failed:
     [x] Cluster reachable: https://api.cluster.example.com:6443
     [x] Authenticated as: user@example.com
     [ ] FAILED: Namespace '<OPERATOR_NAMESPACE>' not found.
         Fix: Install the operator via OLM before running E2E tests.
   ```
   Do NOT proceed to test execution.

6. If **all checks pass**, output:
   ```
   Cluster readiness: OK
     Cluster: <server URL>
     User: <username>
     Namespace: <OPERATOR_NAMESPACE> exists
     Operator CSV: Succeeded
   ```
   Proceed to Step 5.3.

#### Step 5.3 — Execute tests

Run the E2E test suite. Track `attempt` counter starting at 1.

```bash
OPERATOR_NAMESPACE=<ns> make test-e2e 2>&1 | tee /tmp/opsx-e2e-output.log
```

Parse the Go test / Ginkgo output for per-test pass/fail results.

**Telemetry — emit after execution:**
- `e2e_execution` event with:
  - `attempt` (1 for first run, 2+ for retries)
  - `tests_run`, `tests_passed`, `tests_failed`
  - `exit_code` (0 = all pass)
  - `file_hash` (SHA-256 of generated test files — for flake detection)
  - `source: "local"`
- `e2e_bug_found` per distinct test failure with `test_name` and `failure_message`.

**Generate QE metrics:**
```bash
python -m openspec.telemetry.qe_metrics --change <name>
```
This produces `openspec/changes/<name>/telemetry/qe-metrics.json` with accurate first-pass
rate, flake rate, and bug count from the real local execution.

**Metrics completeness check (MANDATORY after every local execution):**

After generating `qe-metrics.json`, read it and verify:
1. `first_pass_rate.tests_executed` is **not null** — if null, the `e2e_execution` event
   was not emitted correctly. Re-emit from the test output log (`/tmp/opsx-e2e-output.log`)
   and regenerate.
2. `first_pass_rate.tests_executed` matches the actual number of tests run (from `make test-e2e` output).
3. If tests failed: `bugs.found` > 0 — if `first_pass_rate.tests_failed_first_run` > 0 but
   `bugs.found` is 0, `e2e_bug_found` events were not emitted. Parse failures from the test
   output log, emit the missing events, and regenerate.
4. `validation.valid` is `true` — if `false`, inspect `validation.warnings` and fix the
   inconsistencies before proceeding.

If any check fails, fix the telemetry gap (re-parse `/tmp/opsx-e2e-output.log`, emit missing
events, regenerate `qe-metrics.json`) before moving to Step 5.4 or 5.5.

If `exit_code == 0` (all tests pass): skip Step 5.4, proceed to Step 5.5.
If `exit_code != 0` (any test failed): proceed to Step 5.4.

#### Step 5.4 — E2E evaluation report (on failures)

Generate an evaluation report analyzing every failure before asking the user to approve or fix.

Write to `openspec/changes/<name>/e2e/e2e-evaluation-report.md`:

```markdown
## E2E Evaluation Report: <change-name>

### Execution Summary
| Metric | Value |
|--------|-------|
| Total tests | N |
| Passed | N |
| Failed | N |
| Exit code | N |
| Duration | Xs |
| Attempt | N |

### Failed Tests

#### 1. TestName / It("description")
- **Error:** <exact error message from go test output>
- **File:** `test/e2e/e2e_test.go:LINE`
- **Root cause analysis:** <analysis of WHY it failed — missing CR, timing issue,
  wrong assertion, code bug in reconciler, etc.>
- **Suggested fix:** <concrete change needed — e.g. "increase timeout in
  WaitForDeploymentAvailable from 2m to 5m" or "reconciler does not set
  status.phase — add status update in controller">
- **Fix location:** <file:line where the fix should be applied>
- **Category:** test_bug | code_bug | environment | flaky

#### 2. ...
(repeat for each failed test)

### Overall Assessment
- **Ready for PR:** Yes / No
- **Blocking issues:** N code bugs, M test bugs, K environment issues
- **Recommendation:** <"Fix N issues before raising PR" or "All failures are
  environment-related — safe to raise PR">
```

Present the report to the user:

ASK: **"E2E evaluation report generated. {N} tests failed ({M code bugs, K test bugs, J environment). Review the report above."**
  - **Approve and proceed to PR** — failures are acceptable (environment/flaky/known)
  - **Fix and re-run** — apply suggested fixes, then re-execute tests

**If user selects "Fix and re-run":**
1. Apply the suggested fixes from the report (edit test files or source code as needed).
2. Increment `attempt` counter.
3. Re-run `make test-e2e` (Step 5.3 again).
4. If previously-failing tests now pass, emit `e2e_bug_verified` events.
5. Regenerate `qe-metrics.json` (includes retry data for flake rate calculation).
6. If triage RCA was provided, ASK: "Was the root cause analysis correct? (y/n)" per bug.
   Emit `e2e_triage` with `user_confirmed: true/false`. Skip if user declines.
7. Re-evaluate: if still failing, regenerate `e2e-evaluation-report.md` and prompt again.
8. **Max 2 fix-and-rerun loops.** After 2 retries, force proceed to Step 5.5 with current results.

**If user selects "Approve and proceed":** proceed to Step 5.5.

#### Step 5.5 — Final decision: Push / Feedback / Stop

After E2E code is generated and tests are executed (or local execution was skipped), present
the overall E2E outcome and ask the user for their decision.

- **If all tests passed (or execution skipped):**
  ASK: **"E2E workflow complete. Generated {N} test files covering {M} journeys. What would you like to do?"**
  - **Push to PR** — push E2E code to the existing PR branch (triggers CI)
  - **Reject with feedback** — provide feedback to revise the generated code
  - **Stop** — end the E2E workflow without pushing (can resume later with `/opsx-e2e`)

- **If tests had failures but user selected "Approve and proceed" in Step 5.4:**
  ASK: **"E2E complete with {N} accepted failures. What would you like to do?"**
  - **Push to PR** — push E2E code to the existing PR branch despite failures
  - **Reject with feedback** — provide feedback to revise the generated code
  - **Stop** — end the E2E workflow without pushing

**On "Reject with feedback":**
1. User provides feedback (e.g. "test X needs to cover edge case Y", "cleanup is missing for CR Z").
2. Analyze the feedback: identify which test files/journeys need changes.
3. Apply the changes to the generated test code in `openspec/changes/<name>/e2e/generated/`.
4. If local execution was done, re-run affected tests to verify fixes.
5. Present updated summary and prompt again with the same three options:
   **"Feedback addressed (round {N}/3): <brief summary of changes>. What would you like to do? (Push to PR / Reject with feedback / Stop)"**
6. Repeat until user selects Push or Stop, or max 3 feedback rounds. On 3rd rejection, force-stop with warning:
   "Max feedback rounds reached. Stopping. Re-run `/opsx-e2e` to resume."

**On "Stop":**
- Write E2E summary to `openspec/changes/<name>/e2e/e2e-summary.md` with status `stopped`.
- Emit telemetry: `e2e_run_end` with status `stopped_by_user`.
- Regenerate `qe-metrics.json`: `python -m openspec.telemetry.qe_metrics --change <name>`
- Output: **"E2E workflow stopped. Generated code is saved in `openspec/changes/<name>/e2e/generated/`. Re-run `/opsx-e2e` to resume and push."**
- STOP. Do not proceed to Step 5.6.

**On "Push to PR":** proceed to Step 5.6.

#### Step 5.6 — Push E2E code to same PR branch

E2E code is pushed to the **same branch and PR** that was raised during `/opsx-apply`.
No separate PR is created — the existing development PR receives the E2E commits.

1. Copy generated test files into the repo test directory:
   ```bash
   cp openspec/changes/<name>/e2e/generated/*_test.go <repo-path>/test/e2e/
   ```
2. Commit and push to the existing PR branch:
   ```bash
   git add test/e2e/
   git commit -m "<ticket_key>: Add E2E tests for <change summary>

   Generated by OpenSpec /opsx-e2e
   - Journeys: N consolidated test journeys
   - Coverage: AC → scenario X%, automation X%
   - Framework: <ginkgo|testing|testify>"
   git push origin HEAD
   ```
   Where `ticket_key` = `plan_phases[N].jira_key` if available (not SKIPPED/PENDING), else `jira_key`.
3. Output: **"E2E test code pushed to the PR branch (<PR_URL>). CI will re-run automatically to validate the new tests."**

#### Step 5.7 — Write summary and close

1. Write E2E summary to `openspec/changes/<name>/e2e/e2e-summary.md`.

**Telemetry (Stage 4 close):**
- Emit `e2e_stage_end` with `tokens_in`, `tokens_out`, `duration_s`.
- Emit `e2e_run_end` with status (`passed`, `failed_approved`, `not_executed`).

### 7. Final Summary

```
## E2E Generation Complete: <change-name>

**Mode:** <PR Mode | Design Mode | Combined Mode>
**Input:** <PR URL | ADR/EP path | both>
**PR (fork):** <PR URL or "N/A — Design Mode">
**PR (upstream):** <upstream PR URL or "not raised" or "N/A">
**Phase:** <N> (or "final" or "N/A")

### Operator Context Used
| Source | Status |
|--------|--------|
| agents.md | ✓ Read (<path>) |
| constitution.md | ✓ Read (harness-evals/constitution.md) |
| harness-docs/ | ✓ N files / ⚠ Not found |
| harness-evals/evals/ | ✓ N stage evals / — Not found |
| qe-e2e/qe-behaviour.md | ✓ Read (<path>) / ⚠ Not found (derived from agents.md) |
| qe-e2e/helpers.md | ✓ Read (<path>) / — Not found (discovered from repo) |
| qe-behaviour.md (generic) | ✓ Read (Sections 1-5) |

### Artifacts Generated
| Stage | Artifact | Path |
|-------|----------|------|
| Pre-analysis | e2e-analysis.md | openspec/changes/<name>/e2e/ |
| Test plan | test-plan.md | openspec/changes/<name>/e2e/ |
| Generated code | <file>_test.go | openspec/changes/<name>/e2e/generated/ |
| Evaluation report | e2e-evaluation-report.md | openspec/changes/<name>/e2e/ (PR/Combined only) |
| QE Metrics | qe-metrics.json | openspec/changes/<name>/telemetry/ |

### Test Results (PR Mode / Combined Mode only)
| Journey | Status |
|---------|--------|
| Journey 1: ... | PASS/FAIL/NOT RUN |

### QE Metrics Summary
| Metric | Value |
|--------|-------|
| AC → Scenario Coverage | X% (N/M criteria covered) |
| Automation Coverage | X% (N automated, M manual) |
| First-Pass Pass Rate | X% (N/M passed first run) | N/A (Design Mode) |
| Flake Rate | X% (N flaky retries) | N/A (Design Mode) |
| Bugs Found / Verified | N found, M verified | N/A (Design Mode) |
| Triage Accuracy | X% (or N/A) |
| QE Cost | $X.XX (N tokens, Xs wall time) |

Time-saved, story points, and feedback are NOT collected here — `/opsx-archive`
will ask for them once this change is archived.

### Next Steps (mode-dependent)
**PR / Combined Mode:**
- Review test code in the PR
- If upstream PR raised: monitor CI on the upstream PR
- Re-run with `/opsx-e2e --phase N` after fixes if tests failed

**Design Mode:**
- Review generated test plan and code in openspec/changes/<name>/e2e/
- When a PR is raised: `/opsx-e2e --pr <URL>` to execute and push
- The existing plan will be reused if still valid for the PR scope
```

## Guardrails

- **HARD GUARDRAIL — `agents.md` required:** Do NOT proceed past Step 0 without reading
  `agents.md` from the operator repo root. This file defines controller patterns, test
  conventions, and coding rules. STOP if missing.
- **HARD GUARDRAIL — `harness-evals/constitution.md` required:** Do NOT proceed past Step 0
  without reading `constitution.md`. This defines non-negotiable operator guardrails. STOP
  if missing.
- **HARD GUARDRAIL — Context-narrowing pipeline:** Operator context flows through stages
  as follows (do NOT violate this pattern):
  - **Stage 1 (Pre-Analysis):** Reads ALL operator context (`agents.md`, `constitution.md`,
    `qe-e2e/qe-behaviour.md`, `harness-docs/`, `harness-evals/evals/`). Distills into
    `e2e-analysis.md` with an embedded "Operator Context" section.
  - **Stage 2 (Test Plan):** Reads `e2e-analysis.md` + generic QE rules only. Does NOT
    re-read `agents.md` or `constitution.md`.
  - **Stage 3 (Code Generation):** Reads `test-plan.md` + `agents.md` (helpers/style
    sections ONLY) + `qe-e2e/helpers.md` (if present). Does NOT re-read `constitution.md`.
- **HARD GUARDRAIL — Local execution opt-in:** In Stage 4 (PR/Combined Mode) Step 5.1
  and Step 6a (Design Mode), you MUST explicitly ASK the user "Run E2E tests locally on
  your cluster? (Yes / No)" before any cluster interaction. Do NOT assume the answer.
  Do NOT auto-execute tests. If the user declines, skip directly to Step 5.5 (PR/Combined)
  or the Design Mode completion banner (Design Mode). In Design Mode, clearly state that
  the ADR implementation must be built and deployed on the cluster for tests to pass.
- **HARD GUARDRAIL — QE metrics generation after local execution:** If local tests were
  executed (user said "Yes" in Step 5.1 or Step 6a.2), you MUST:
  1. Emit an `e2e_execution` event with accurate `tests_run`, `tests_passed`, `tests_failed`,
     `exit_code`, and `file_hash` — parsed from the Go test / Ginkgo output
  2. Emit an `e2e_bug_found` event for EVERY distinct test failure with `test_name` and
     `failure_message`
  3. Run `python -m openspec.telemetry.qe_metrics --change <name>` immediately after
     execution completes
  4. Read the generated `qe-metrics.json` and verify `first_pass_rate.tests_executed` is
     not null and `validation.valid` is true — if either check fails, the events were not
     emitted correctly. STOP, re-parse the test output log, emit missing events, regenerate,
     and re-verify before proceeding
  5. Do NOT proceed to Step 5.4, 5.5, or Step 8 with incomplete execution metrics
- **User approval gate after every stage** — do not advance until approved
- **Design Mode offers optional local execution after code generation** — check for ADR
  implementation in the target repo and prompt the user. Push is never available in
  Design Mode (no PR branch).
- Never skip the pre-analysis gate — it prevents wasted effort
- Respect pre-analysis exclusions in all downstream stages
- Match target repo test style exactly (framework, helpers, constants) — as defined in `agents.md`
- No hardcoded durations — use repo constants
- No inline K8s resource specs — use repo builders/helpers
- DeferCleanup for every created resource
- Generated code must compile — verify before presenting
- If `harness-evals/evals/` stage evals exist, cross-reference them during pre-analysis to
  ensure E2E tests cover patterns the eval-loop has identified as important
- **Do NOT ask the user for time-saved, story points, or feedback anywhere in this command.**
  That is collected exactly once, centrally, by `/opsx-archive` — this keeps QE feedback
  consistent with a single source of truth instead of asking twice (once here, once at archive).
