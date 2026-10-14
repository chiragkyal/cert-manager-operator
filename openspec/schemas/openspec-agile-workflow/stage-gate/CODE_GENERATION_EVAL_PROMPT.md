# Code Generation Eval Gate — Forward workflow (`/opsx-apply` per task)

Score **generated or modified code** in the fork working copy after each task's OAPE command (or manual agent work), **execute real verification and test commands**, **refine code until evals pass and tests pass**, then present for **user code approval**.

Paths below are **relative to the schema root** (`openspec/schemas/openspec-agile-workflow/` when installed).

## Mandatory per-task sequence

**Do not skip steps. Do not ask for user approval before completing the eval + test execution loop.**

```
1. Execute OAPE command (or manual agent work) in fork cwd
2. Execute verification commands (go build, go vet, make targets — capture real exit codes)
3. Run code-generation evals (filter by oape_command)
4. Execute test block (co-generate _test.go for controller tasks; run go test / make test)
5. IF any eval case OR verification OR test fails → fix code → re-run steps 2–4 (up to 2 refinement passes)
6. Present task summary + code eval scorecard + verification results + test results
7. User approves CODE for this task
8. ON APPROVE → write task report → mark task [x] → next task
```

| Step | User approval allowed? |
|------|------------------------|
| 1–5 | **No** — complete eval + verification + test loop first |
| 6–7 | **Yes** — present full results, then ask |
| 8 | After explicit user Approve only |

## Eval source

| Purpose | Path |
|---------|------|
| **Eval cases** | `harness-evals/evals/code-generation_eval.yaml` |
| **Assertion schema** | `eval-generation/eval-generation-workflow/stages/code-generation-eval-spec.yaml` |
| **Do NOT edit** | Eval YAML during forward workflow (read-only; cases added via `/eval-loop`) |

## Step 1 — Resolve filter

From the current task, determine `oape_command`:

| Resolved command | `oape_command` filter |
|------------------|------------------------|
| `/oape:api-generate` | `api-generate` |
| `/oape:api-generate-tests` | `api-generate-tests` |
| `/oape:api-implement` | `api-implement` |
| Manual agent (no OAPE) | `manual` |

Load `harness-evals/evals/code-generation_eval.yaml`. Score only cases where:

- `oape_command` equals the resolved command, **or**
- `oape_command` is `any` (applies to all tasks)

If the file is missing, `evals:` is empty, or no cases match: **skip scoring** but **still execute steps 2 and 4** (verification and test block are mandatory for every task).

**If `harness-evals/evals/code-generation_eval.yaml` does not exist:** skip eval scoring
but **still execute steps 2 and 4** (verification and test block are mandatory for every task).
Log: "Code-generation eval file not found — skipping eval scoring."

## Step 2 — Execute verification commands (mandatory — real execution, not assertions)

After OAPE command output, **actually execute** the following commands in the fork/working
directory. Capture real exit codes, stdout, and stderr. Do NOT report "PASSED" for
commands that were not executed.

### 2a. Minimum verification (every task)

Always run for any package modified by this task:

```bash
go build <package-under-change>/...
go vet <package-under-change>/...
```

Resolve `<package-under-change>` from the task's Target file(s):
- `api/<group>/<version>/<name>_types.go` → `go build ./api/<group>/<version>/...`
- `pkg/controller/<name>/controller.go` → `go build ./pkg/controller/<name>/...`
- `pkg/operator/starter.go` → `go build ./pkg/operator/...`
- Multiple packages modified → run `go build` and `go vet` for each

### 2b. Task-specific verification

Run additional commands from the task's **Acceptance criteria** in `tasks.md §4`.
Refer to `agents.md` "Per-task testing" section for the operator-specific verification
matrix mapping task types to commands.

| Task type | Additional commands |
|-----------|-------------------|
| Codegen (`make generate`, `make manifests`) | `make generate && make manifests && make verify` |
| Feature gate edits | `go test ./<features-package>/... -run <test-pattern>` |
| Bindata / manifest tasks | `make update-bindata && make verify` |
| OLM bundle tasks | `make bundle && hack/verify-bundle.sh` |
| Hack scripts | `bash -n <script-path>` (syntax check) |

### 2c. Record results

Record each command with its real exit code:

```yaml
verification:
  commands:
    - cmd: "go build ./pkg/controller/<name>/..."
      exit_code: 0
      pass: true
    - cmd: "go vet ./pkg/controller/<name>/..."
      exit_code: 0
      pass: true
    - cmd: "go build ./pkg/operator/..."
      exit_code: 2
      pass: false
      stderr_summary: "pkg/operator/starter.go:42: undefined: <name>.SetupManager"
  overall_pass: false
```

If any verification command fails: **do not proceed to evals**. Fix the code first,
then re-run verification. This counts toward the 2-pass refinement budget.

### 2d. Duplicate `package` recovery for Go files (mandatory)

When verification fails for a modified `.go` file and output indicates duplicate package
declarations (for example multiple `package <name>` blocks in one file):

1. Identify the affected file(s) from compiler output.
2. Restore each affected file to the branch `HEAD` version before retrying:
   ```bash
   git checkout -- <path/to/file.go>
   ```
3. Re-apply only the intended task-specific edits using in-place edit operations.
4. Re-run step 2 verification commands before continuing.

Do NOT continue refinement on a duplicated/corrupted Go file body.

## Step 3 — Score each applicable eval case

For each filtered case in `evals:`:

1. Read case `prompt`, `assertions`, `scoring.pass_threshold`
2. Inspect **fork working copy** — `git diff` for this task, changed files, verification output
3. Evaluate against assertion types in `eval-generation/eval-generation-workflow/stages/code-generation-eval-spec.yaml`

| Assertion | Check |
|-----------|--------|
| `must_use_pattern` | String/pattern appears in relevant source files |
| `must_not_use` | Pattern absent (e.g. deprecated client.Create) |
| `must_pass_make_targets` | Listed make targets **actually executed and passed** (use exit code from step 2) |
| `must_match_task_payload` | Code aligns with tasks.md §4 for current Task ID |
| `files_must_exist` | Paths exist in fork |
| `files_must_not_exist` | Paths absent |
| `must_follow_constitution` | No constitution violations in generated code |
| `must_follow_effective_go` | Follow `.cursor/skills/effective-go/SKILL.md` |
| `must_include_tests` | Task-appropriate tests present (co-generated `_test.go` for all Tier 1 tasks) |
| `must_not_violate_non_goals` | Non-goals from task/spec not violated |
| `must_execute_verification` | Verification commands from step 2 all passed (exit code 0) |
| `must_co_generate_tests` | All Tier 1 tasks (controller, API with webhooks/validation, manual Go with logic) produced `_test.go` files following the exemplar pattern defined in `agents.md` |
| `must_colocate_component_code` | All functions for one component (controller, webhook, API type group) are in a single file — no unnecessary splits (e.g. separate reconcile/status/finalizer files for the same controller) |

**`must_pass_make_targets` is now enforced by real execution.** The agent MUST have
actually run the listed make target in step 2 and it MUST have returned exit code 0.
Do NOT mark this assertion as passed based on code inspection alone.

Record per case: `pass`, `score` (0–100), `failures[]`.

Overall task code score: average of applicable case scores. Pass if all cases ≥ their `pass_threshold`.

## Step 4 — Execute test block (mandatory — real execution)

After eval scoring, run the **test execution block**. The test strategy depends on
the task type. Tests are **real `go test` executions** — not agent assertions.

### 4a. Classify the task (tiered)

| Task type | Condition | Test tier | Action |
|-----------|-----------|-----------|--------|
| **Controller logic** | `api-implement` + `pkg/controller/` | Tier 1 | Co-generate `_test.go` + `go test` |
| **API with logic** | `api-generate` + webhook/validation/defaulting code | Tier 1 | Co-generate `_test.go` for validation + `go test` |
| **API structs only** | `api-generate` + pure `*_types.go` definitions | Tier 3 | `go build` + `go vet` |
| **API tests** | `api-generate-tests` | (task IS tests) | `go test` |
| **Manual Go with logic** | manual + creates Go files with exported functions | Tier 1 | Co-generate `_test.go` + `go test` |
| **Manual non-Go** | manual + YAML/scripts | Tier 4 | `make verify` / `bash -n` |
| **Feature gate** | modifies `features.go` | Tier 2 | Run existing tests |
| **Codegen / verify** | `make generate` | Tier 3 | `make verify` |
| **OLM bundle** | modifies bundle/ or CSV | Tier 3 | `make bundle && hack/verify-bundle.sh` |
| **E2E** | handled by `/opsx-e2e` | — | Skipped during OAPE |

### 4b-i. Controller logic tasks — co-generate `_test.go` (Tier 1)

When the task type is **controller logic** (`api-implement` modifying `pkg/controller/`):

1. **Co-generate test file(s)** alongside the production code, in the same package directory.
   Follow the test exemplar pattern defined in **`agents.md`** (section "Tests" or equivalent).
   Each production `.go` file gets a matching `_test.go` file.

2. **First controller task** must also create:
   - Mock/fake client file (e.g. `fakes/` directory) — matching the operator's established mock pattern
   - `test_utils.go` — shared test helpers (factory functions for CR instances, expected objects)

3. **Test structure** — table-driven tests using the operator's mock client:
   - Successful reconciliation case
   - Exists-check failure case
   - Create-when-not-exists case
   - Update-when-spec-changed case (semantic equality)
   - Error propagation cases

4. **Subsequent controller tasks** add test cases to existing `_test.go` files or create
   new ones matching the file being added.

5. Test files are **permanent parts of the codebase** — committed alongside production code.

### 4b-ii. API logic tasks — co-generate `_test.go` (Tier 1)

When the task produces **webhook, validation, or defaulting code** (not just struct definitions):

1. **Co-generate test file(s)** in the same package directory. Follow agents.md test patterns.
2. **Test structure** — table-driven validation tests:
   - Valid input accepted
   - Required field missing → rejected
   - Invalid value → rejected with correct error message
   - Defaulting applied when field absent
   - Webhook admission response correct
3. Run `go test ./<api-package>/... -v -count=1`

### 4b-iii. Manual Go tasks — co-generate `_test.go` (Tier 1)

When the task creates/modifies Go files with **exported functions or methods** (helper packages,
utility functions, shared libraries):

1. **Co-generate test file(s)** for every production `.go` file with exported logic.
   Follow agents.md test patterns. Table-driven where applicable.
2. **Test coverage**: every exported function must have at least one positive and one negative test case.
3. Run `go test ./<package>/... -v -count=1`

### 4c. Execute tests

Run the resolved test command and capture real output:

```bash
# Controller tasks
go test ./pkg/controller/<name>/... -v -count=1

# Feature gate tasks
go test ./<features-package>/... -run <TestPattern> -v

# API test generation tasks
go test ./api/<group>/<version>/... -v -count=1

# Full suite (when task Acceptance criteria specifies)
make test
```

### 4d. Record test results

```yaml
test_execution:
  strategy: co_generated_tests  # or: existing_tests, build_only, make_verify
  commands:
    - cmd: "go test ./pkg/controller/<name>/... -v -count=1"
      exit_code: 0
      pass: true
      summary: "ok  <module>/pkg/controller/<name> 1.234s"
      tests_run: 12
      tests_passed: 12
      tests_failed: 0
    - cmd: "go build ./pkg/operator/..."
      exit_code: 0
      pass: true
  overall_pass: true
  test_files_generated:
    - pkg/controller/<name>/deployments_test.go
    - pkg/controller/<name>/fakes/fake_ctrl_client.go
```

If any test fails: fix code (and/or test), re-run. Counts toward the 2-pass refinement budget
shared with eval refinement.

## Step 5 — Refine code (mandatory when anything fails)

If **any** eval case, verification command, or test execution fails, **do not ask for
user approval yet**. Loop:

1. Load failed case `prompt` + `assertions`, failed verification output, failed test output
2. Load current task §4 payload and design-bundle.md
3. **Fix code (and test files if co-generated) in fork working copy only** — do not modify approved markdown artifacts
4. Re-run verification commands (step 2)
5. Re-score code-generation evals (step 3)
6. Re-run test block (step 4)
7. Repeat until **all pass** OR **2 refinement passes** exhausted

If still failing after 2 passes: proceed to step 6 with scorecard showing remaining
failures; user decides at approval gate.

## Step 6 — Write eval results

```
openspec/changes/<change-name>/eval-results/code-generation-<task-id>.yaml
```

```yaml
task_id: T3_2
oape_command: api-implement
stage: code-generation
stage_eval_file: harness-evals/evals/code-generation_eval.yaml
scored_at: <ISO8601>
refinement_rounds: 1
overall_score: 95
overall_pass: true
verification:
  commands:
    - cmd: "go build ./pkg/controller/<name>/..."
      exit_code: 0
      pass: true
    - cmd: "go vet ./pkg/controller/<name>/..."
      exit_code: 0
      pass: true
  overall_pass: true
test_execution:
  strategy: co_generated_tests
  commands:
    - cmd: "go test ./pkg/controller/<name>/... -v -count=1"
      exit_code: 0
      pass: true
      tests_run: 8
      tests_passed: 8
      tests_failed: 0
  overall_pass: true
  test_files_generated:
    - pkg/controller/<name>/deployments_test.go
cases:
  - id: eval-r001-codegen-001
    score: 95
    pass: true
    failures: []
  - id: eval-r001-codegen-002
    score: 95
    pass: true
    failures: []
```

Update `refinement_rounds` after each code-fix pass.

## Step 7 — Present task summary (code ready for review)

Include all three result sections:

1. **Files touched** — paths changed in fork for this task (including co-generated `_test.go` files)
2. **Verification results** — table of executed commands with real exit codes:

   ```
   ### Verification Results
   | Command | Exit Code | Result |
   |---------|-----------|--------|
   | go build ./pkg/controller/<name>/... | 0 | PASSED |
   | go vet ./pkg/controller/<name>/... | 0 | PASSED |
   ```

3. **Test execution results** — table of test commands with real output:

   ```
   ### Test Execution Results
   | Command | Tests | Passed | Failed | Result |
   |---------|-------|--------|--------|--------|
   | go test ./pkg/controller/<name>/... -v | 8 | 8 | 0 | PASSED |
   ```

4. **Code eval scorecard** — overall %, cases pass/fail, refinement rounds, eval-driven fixes applied
5. **Remaining gaps** — if any cases/tests still fail after max refinement passes
6. **Go package integrity check** — for each changed `.go` file, verify exactly one
   package clause remains (for example with `rg -n "^package " <file>` expecting one match)

## Step 8 — User code approval

**Auto-approve check**: Read `config.yaml → flags.auto_approve`. If `true`, skip the user
prompt below and treat the task as Approved. Still present the scorecard summary
(items 1–6 from Step 7) for logging, but do not wait for user input. Proceed directly
to Step 9.

Ask (skip if `auto_approve: true` — substitute task_id, task_title, verification/test results):

> **Code eval score: {overall_score}%** ({N}/{M} cases pass).
> **Verification: {V_pass}/{V_total} commands pass. Tests: {T_pass}/{T_total} pass.**
> Approve the **code changes** for task {task_id} ({task_title}) and proceed to the next task?
> **(Approve / Reject with feedback)**

- **Approve** (or auto-approved) → step 9
- **Reject** → add REVISION FEEDBACK to design-bundle; re-run task from step 1 (including full eval + verification + test gate)

## Step 9 — On approve (record and advance)

1. Mark task `- [x]` in tasks.md
2. Write **`implementation/task-reports/<task-id>.md`** using `templates/implementation-task-report-template.md`
3. **Collect verification/test metadata** from the eval results recorded in Step 6:
   - `build_status`: `"passed"` if all `go build` + `go vet` commands passed, else `"failed"`
   - `test_status`: `"passed"` if all `go test` commands passed, `"failed"` if any failed,
     `"skipped"` if no tests were applicable (Tier 3/4 tasks)
   - `verify_status`: `"passed"` if all `make verify` / `make targets` passed, `"failed"` if any failed,
     `"skipped"` if no make targets were applicable
   - `eval_score`: the `overall_score` from the eval results YAML
4. Pass metadata to the `on-task-complete` telemetry hook (called by `/opsx-apply`):
   ```bash
   python -m openspec.telemetry.auto on-task-complete --change "<name>" --task-id "<TASK_ID>" --status passed \
     --metadata '{"build_status":"passed","test_status":"passed","verify_status":"skipped","eval_score":95}'
   ```
5. Advance to next pending task

## Guardrails

- **Never** present user approval before running code-generation evals AND verification AND test execution
- **Never** advance to the next task without approval (user Approve or auto-approved via `config.yaml → flags.auto_approve`)
- **Never** report "PASSED" for commands that were not actually executed — capture real exit codes
- **Always** run `go build` + `go vet` for every task that produces or modifies Go source files
- **Always** co-generate `_test.go` files for controller logic tasks (`api-implement` modifying `pkg/controller/`)
- Co-generated test files are **permanent** — committed alongside production code (follow the test exemplar in `agents.md`)
- Score **code in fork cwd** — not markdown under `openspec/changes/`
- Task reports accumulate under `implementation/task-reports/` (one per approved task)
- Refinement budget: **2 passes total** shared across eval failures, verification failures, and test failures
- **Never** use append-based shell edits (`>>`, `tee -a`) for source-file refinements
