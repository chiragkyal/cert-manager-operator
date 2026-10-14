# Pre-Analysis Gate — ADR/PR Scoping & Approval

## Purpose

This rule produces a lean, scannable analysis document from an ADR or PR. The user reviews and approves (or modifies) this document **before** full test plan generation begins. This prevents wasted effort on misaligned test plans.

**Workflow:** User provides ADR/PR → **this rule generates pre-analysis** → user approves → auto-triggers `test-plan-e2e-generation` with the approved scope as input.

---

## 1. Input Handling

This rule supports the same input modes as `test-plan-e2e-generation`:

| Input provided | Mode |
| --- | --- |
| ADR only | ADR Mode |
| ADR + PR | ADR+PR Mode (PR enriches) |
| PR only | PR Mode |
| PR + Repo link | PR Mode (repo enriches) |
| Neither | STOP — ask for ADR or PR |

### How to fetch inputs

**PR:**
```bash
# PR metadata and diff
gh pr view <PR-NUMBER> --repo <org/repo> --json title,body,state,labels,files,additions,deletions,changedFiles
gh pr diff <PR-NUMBER> --repo <org/repo>

# Review comments — captures unresolved discussions, reviewer concerns, and context not in the diff
gh api repos/<org>/<repo>/pulls/<PR-NUMBER>/comments
gh api repos/<org>/<repo>/pulls/<PR-NUMBER>/reviews
```

**Review comments are mandatory input.** Unresolved reviewer concerns (e.g., "should this use runAsUser:65532?", "what about HostIPC?") often reveal scope gaps, contested design decisions, or incomplete implementation. Surface these in the analysis — either as regression risks, exclusions with justification, or items flagged for user clarification.

**ADR:** Accept Google Docs URL, GitHub file URL, local path, or pasted markdown. If fetch fails, ask the user to paste it.

### Stop condition

- No ADR and no PR → **STOP**, ask for input.
- Jira alone is not sufficient → **STOP**, ask for ADR or PR.

---

## 2. Change Type Classification

**Do this FIRST. It drives everything downstream.**

Classify the change into one of these categories based on the PR description/diff or ADR goals:

| Change Type | Testing Strategy |
| --- | --- |
| **Feature** | E2E-heavy — new positive-path + negative-path tests |
| **Bug Fix** | Regression-focused — reproduce the bug, verify the fix, guard against recurrence |
| **Refactor** | Regression-only — existing behavior must not change, minimal new tests |
| **Config** | Deployment/upgrade tests — verify config propagation and rollback |
| **Security** | Negative-heavy — privilege escalation, RBAC boundaries, admission control |
| **CRD Change** | API contract tests — validation, defaulting, backward compatibility |

If the change spans multiple types, pick the dominant one and note secondary concerns.

---

## 3. Impact Analysis (Files Touched)

### PR Mode
List all changed files from the diff. Categorize each:

| Category | File Patterns | Test Implication |
| --- | --- | --- |
| CRD Types | `api/**/*_types.go` | Field validation, status, E2E |
| Controllers | `internal/controller/**` | Reconcile logic, INT + E2E |
| Webhooks | `*_webhook.go` | Admission, INT + negative E2E |
| RBAC | `config/rbac/**` | Security (least privilege) |
| Samples | `config/samples/**` | Become E2E test inputs |
| Tests | `*_test.go` | Understand existing patterns |
| Config | `config/manager/**`, `Dockerfile` | Deployment/upgrade |
| Other | Everything else | Assess individually |

**Output:** Total file count, breakdown by category, new vs. modified vs. deleted.

### ADR Mode
Infer affected file areas from components described in the ADR (CRDs, controllers, operands, APIs). Map each to the category table above.

---

## 4. Existing Test Coverage Assessment

**Before proposing new tests, check what's already covered.**

1. Identify `*_test.go` files in affected directories.
2. For each affected component, determine:
   - Which existing tests cover it (by name/description)?
   - What behaviors are already validated?
   - Which existing tests may need **updating** due to this change?
3. Summarize as:
   - **Already covered:** Components/behaviors with existing test coverage (no new tests needed).
   - **Partially covered:** Existing tests exist but don't cover the new/changed behavior.
   - **Not covered:** No existing tests — net-new tests required.
   - **Needs update:** Existing tests that will break or become stale due to this change.

---

## 5. Blast Radius

### When operator quality gates are available (MANDATORY)

**If `qe-e2e/qe-behaviour.md` exists in the operator repo (read in Step 0c of `/opsx-e2e`), you MUST use its Section 3a/3b before completing this section.** If not present, derive context from `agents.md` and `constitution.md`. Do not infer components or quality gates from the diff alone when operator context is available.

Apply these rules in order:

1. **Component checklist (Section 3b):** Use the operand/component list from the operator's quality gates as the blast-radius checklist. Mark **every** listed component as affected or not affected — do not omit any.
2. **Quality gates table (Section 3b):** Use the domain-specific quality gate categories from the operator's quality gates (e.g., Operator Lifecycle, Operand Health, Core Functionality, Security, Deployment Integration, Resilience) instead of the generic fallback table below.
3. **Deployment context (Section 3a):** Read the operator's deployment context and note deployment constraints (OLM/Helm/manual, namespace, operand CR naming, config patching method) that affect E2E feasibility or step wording. Include these in the output's "Operator Context (Embedded)" section.
4. **Gate → test accountability:** Every quality gate marked **Affected** in this section MUST appear in **either** Section 7 (Proposed Tests) **or** Section 8 (Exclusions) with a code-level justification. Do not mark a gate affected and leave it unaccounted for in both sections.

If no operator quality gates are available (no `qe-e2e/qe-behaviour.md` and no relevant context in `agents.md`), use the generic component and quality gate frameworks below.

### Components Affected

Identify all components, operands, or services in the project that could be affected by this change. Derive the list from the repository structure (CRDs, controllers, operands, managed workloads, APIs).

**When operator quality gates are available:** Start from the operator's Section 3b component/operand list and check every entry.

Format as a checklist:
```
- [ ] <Component A>
- [ ] <Component B>
- [ ] <Component C>
- [ ] Operator Core (deployment, subscription, RBAC)
```

### Quality Gates Impacted

**When operator quality gates are available:** Use the operator's Section 3b quality gate categories and observables — not the generic table below.

**Otherwise**, use the generic quality gate framework:

| Gate Category | Affected? | Specific Gates |
| --- | --- | --- |
| Operator/App Lifecycle | Yes/No | Installation, Health, Recovery |
| Component Health | Yes/No | Which components reach ready state |
| Core Functionality | Yes/No | The primary domain behavior (e.g., identity issuance, data processing, routing) |
| Security | Yes/No | RBAC, admission, privilege boundaries, secrets |
| Deployment Integration | Yes/No | OLM, Helm, GitOps upgrade conditions |
| Resilience | Yes/No | Recovery, config reconciliation, self-healing |

### Risk Assessment

**Overall Risk Level:** Low / Medium / High / Critical

| Factor | Value | Weight |
| --- | --- | --- |
| Components touched | N | More components = higher risk |
| CRD schema changes | Yes/No | Schema changes = High risk |
| RBAC/Security boundaries | Yes/No | Security changes = High risk |
| Breaking change potential | Yes/No | Breaking = Critical risk |
| Upgrade path affected | Yes/No | Upgrade impact = High risk |

### Dependency Map
- **Upstream:** What feeds into the changed components
- **Downstream:** What depends on the changed components — what else could break

---

## 5b. Parse / Filter / Ordering Behaviors (Mandatory)

**After extracting functional claims from Goals/DoD, scan the ADR for internal behaviors that often slip through coverage.**

Look for:
- **Tables with Valid/Invalid rows** (e.g. a tls_config validity matrix, input validation table)
- **Constraint tables** (e.g. profile × operator action, edge-case handling)
- **Phrases:** "filtered", "preserved", "warn", "ignore", "skip", "order", "fallback", "default", "stripped"

For each found, produce a row in this table:

| # | ADR Claim (quote or paraphrase) | Observable? | Tier | Proposed ID or Exclusion |
|---|---|---|---|---|
| 1 | e.g. Insecure ciphers filtered with warning | Yes (log + effective cipher list) | UT or INT | UT-003 or EXCLUDED: internal parse, covered by Custom valid |
| 2 | e.g. Cipher order preserved as declared | Yes (ConfigMap field order probe) | INT | INT-003 or EXCLUDED: not observable without custom tooling |
| 3 | e.g. min 1.2 + only TLS 1.3 curves → startup fail | Yes (CrashLoop observable) | ERR | ERR-005 or merged into ERR-003 sub-assertion |
| 4 | e.g. Adherence change during upgrade prevented | No (Platform APIServer responsibility) | — | EXCLUDED: Platform responsibility, not operator |

**Rules:**
- Each row gets either a proposed test ID or an explicit **EXCLUDED** with a one-line reason.
- "Not observable at E2E/INT without custom tooling" is a valid exclusion for ordering invariants.
- If observable, prefer UT/INT (cheap) over E2E (expensive).
- Platform-owned constraints (upgrade prevention, admission at APIServer) → EXCLUDED with "Platform responsibility, not operator."
- If a Valid/Invalid table row is already covered by an existing REQ from Goals/DoD extraction, note the REQ ID — no duplicate test needed.
- This table feeds into the Coverage Breakdown (Stage 2 Section 11) — every row must be accounted for.

**If no ADR tables or constraint phrases are found:** State "No parse/filter/ordering tables found in this ADR" and skip the table.

---

## 6. Regression Risk Map

**What existing behavior could break?**

| Area | Existing Test(s) | Risk | Why |
| --- | --- | --- | --- |
| e.g., Component readiness | `e2e_test.go:TestComponentReady` | Medium | Controller reconcile logic changed |

- List existing tests likely affected by this change.
- Flag behaviors that existing tests validate which might regress.
- Note API contracts that could break (field renames, type changes, removed defaults).

**Downstream tracing (mandatory):** For every quality gate marked as affected in the Blast Radius (Section 5), there MUST be a corresponding entry in this regression risk table — or an explicit "no risk because..." justification. Do not leave impacted quality gates unaccounted for.

**Cross-check against quality gates:** Use the operator quality gates (from `qe-e2e/qe-behaviour.md` Section 3b, or embedded in the output's Operator Context section) to validate completeness. For example, if Blast Radius says "Core Functionality: Yes" but the regression table has no entry for the affected core behaviors, the table is incomplete. If "Operator Lifecycle: Yes" but no installation/health/recovery entry, the table is incomplete.

**Specificity rule:** Every at-risk test must be referenced by its specific test name and file location (e.g., `e2e_test.go:"SPIRE Agent should be installed successfully"`). Search existing `*_test.go` files in affected directories for real test names — do not invent placeholder names. Never use "same test", "same E2E", "see above", or "multiple E2E contexts".

If no regression risk exists, state: **"No regression risk identified — change is additive."**

---

## 7. Proposed Test Cases (Preview)

**This is a lean preview — Scenario one-liners + Pass-when intent, not full test steps.** Full Scenario / Why / Steps / Pass when / Run on is expanded in Stage 2 (`test-plan.md`).

Present in **priority order** (highest-value, highest-risk tests first):

| # | ID | Tier | Title | Scenario (one line) | Pass when (intent) | Effort | Confidence | Maps To |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | E2E-001 | E2E | Strict ON/OFF four ConfigMaps | Strict ON injects tls_config into all 4 CMs; Strict OFF removes from all 4 | All 4 present or all 4 absent — 3 of 4 = fail | S/M/L | High/Med/Low | ADR §X or PR file:L42 |
| 2 | NEG-001 | NEG | ... | ... | ... | S/M/L | High/Med/Low | ... |

**Priority ordering criteria:**
1. Critical risk + no existing coverage → top priority
2. High risk + partial coverage → high priority
3. New behavior (feature) → medium priority
4. Edge cases and exploratory → lower priority

**Gate coverage rule:** When operator quality gates are available, every quality gate marked **Affected** in Section 5 must have at least one proposed test in this section **unless** it is explicitly excluded in Section 8 with a code-level reason (e.g., function defined but not called from controllers).

**Operand coverage rule:** When a change touches multiple operand controllers, propose at least one E2E test per affected operand using the **primary resource type modified in the PR diff** for that controller (e.g., DaemonSet reconciler change → DaemonSet conflict test, not a tangential SA test).

**Tier discipline:** UT and INT tests cover utility functions and recorder contracts — they do not substitute for E2E tests of operator behavior in a live cluster. Propose UT/INT only for pure functions; keep operand/controller behavior in E2E/NEG tiers.

### Estimated Distribution

**Budget (scenario skeleton — not thin one-assertion cases):**
- **Single ADR/PR:** 12–18 scenarios
- **Multi-ADR OR 3+ named variants OR DoD tooling named:** 18–28 scenarios
- **Config override:** If `config.yaml` has `qe.max_test_cases_initial`, use that as the initial budget
- Count each ERR break+recover pair as **one** scenario slot (not two separate tests)
- The consolidation stage compresses to the hard journey limit (`qe.max_test_cases`, default 12) **without dropping** DoD, variant, transition, compliance, or federation dimensions

| Tier | Proposed Count | Rationale |
| --- | --- | --- |
| E2E | 6–12 | Primary focus — user-facing scenarios; variants may share journey setup |
| NEG | 3–5 | Operator resilience under destructive conditions |
| ERR | 3–5 | Error path + recovery pairs (from Section 7a); one slot per pair |
| INT | 2–4 | Only if reconciler/webhook interactions warrant it |
| UT | 2–4 | Only for new pure utility functions |
| NFT | 0–3 | Thresholds/SLAs (7d) and/or compliance tooling (7c) when named in DoD |
| **Total** | **12–18** (single) / **18–28** (multi/complex) | Per rules above |

### Effort Estimate

| Effort Tag | Meaning | Approximate Time |
| --- | --- | --- |
| **S** | Simple setup, single assertion | < 1 hour |
| **M** | Moderate setup, multiple assertions | 1–4 hours |
| **L** | Complex setup, multi-step scenario | 4+ hours |

**Total estimated effort range:** Sum of individual estimates.

### 7a. Error Path Extraction

For every conditional/branching path in the ADR "How" section or PR diff, systematically ask:

1. **Dependency failure:** What if the external dependency returns an error (API 404, timeout, auth failure, TLS handshake failure)?
2. **Invalid config:** What if user-provided configuration is invalid, missing, or malformed?
3. **Write failure:** What if the operator cannot write to a managed resource (RBAC denied, resource conflict, resource not found)?
4. **Recovery:** For each error above — what is the recovery path? Does the operator self-heal when the condition is fixed?

Propose error + recovery test **pairs** (break it, fix it, verify recovery). These are distinct from NEG tests: NEG tests cover destructive resilience (pod deletion, config corruption); error path tests cover bad input/dependency recovery.

**Target:** 3–5 error/recovery pairs, scaling with ADR complexity.

| Error Scenario | Expected Behavior | Recovery | Proposed Test ID |
|----------------|-------------------|----------|-----------------|
| e.g., Dependency API returns 404 | Operator retries with backoff, status condition shows error | Remove error condition → operator recovers | ERR-001 + ERR-002 |

### 7b. Variant Coverage Extraction

Does this feature define multiple modes, profiles, tiers, or configuration variants?

- If **yes:** list every variant from the ADR.
  - Propose at least one **distinct assertion path** per named variant (may share journey setup later; must not collapse to a single Intermediate-only case).
  - For mutually exclusive variants, propose at least one NEG test verifying the wrong variant is rejected.
  - For TLS/profile-style ADRs: also build a **variant × primary door/listener** table using listeners named in the ADR (e.g. operator metrics/webhook, Server gRPC/federation/Prometheus, Agent Prometheus, OIDC HTTPS, controller-manager webhook).
- If **no:** state "No configuration variants identified."

| Variant | Type | Primary door(s) | Proposed E2E | Proposed NEG |
|---------|------|-----------------|-------------|-------------|
| e.g., Profile: Modern | Config mode | metrics :8443 | E2E-NNN | NEG-NNN (reject if wrong profile set) |

### 7c. Compliance Tooling Check

Does the ADR or PR (especially Testing / Definition of Done) mention verification, compliance, or auditing tools (scanners, validators, health checkers, CLI commands — e.g. `tls-scanner`)?

- If **yes:** propose at least one **E2E (functional probe)** and/or **NFT-Compliance** test that runs the named tool and asserts expected output. Do **not** use MQE — there is no Manual QE tier in this workflow.
- If **no:** state "No compliance tooling identified in scope."

| Tool | What It Checks | Proposed Test |
|------|---------------|--------------|
| e.g., tls-scanner | Listener TLS profile compliance | NFT-001 / E2E-NNN |

### 7d. Threshold and SLA Extraction

Extract every numeric threshold, SLA, or timing requirement from the ADR:

- Restart windows (e.g., "pod must restart within 60s")
- Latency targets (e.g., "response within 500ms")
- Resource limits (e.g., "memory < 256Mi")
- Recovery times (e.g., "self-heal within 5 minutes")
- FIPS/compliance timings

For each threshold, propose one NFT test. If the ADR uses vague language ("quickly", "fast", "promptly"), flag it for user confirmation with a suggested concrete threshold.

| Threshold | Value | Source | Proposed NFT |
|-----------|-------|--------|-------------|
| e.g., Pod restart time | 60s | ADR §Recovery | NFT-001 |
| e.g., "recovers quickly" | **VAGUE — suggest 120s?** | ADR §Resilience | NFT-002 (needs user confirmation) |

If no thresholds exist: state "No numeric thresholds or SLAs identified."

### 7e. Definition of Done / Acceptance Extraction (MANDATORY)

Extract every bullet under ADR sections titled **Testing**, **Definition of Done**, **Acceptance Criteria**, or equivalent.

| DoD / AC Bullet (quote) | Proposed Test ID | Exclusion justification (if none) |
|-------------------------|------------------|-----------------------------------|
| e.g., "CI tls-scanner under Intermediate, Modern" | NFT-001 | — |

**Checklist:** `[ ] Every DoD/AC bullet is mapped to a proposed test OR an explicit exclusion with justification.`

If more than 3 DoD bullets are unmapped with no justification → **STOP** and ask the user before presenting the analysis.

### 7f. Transition / Continuity Scenarios

If Risks, How, or DoD mention rolling restart, config change while running, mid-change identity/workload continuity, or "self-heal after restart":

- Propose **at least one** transition scenario: start workload/in-flight op → apply change → assert continuity during transition → assert final healthy state.
- Prefer embedding these as steps inside an existing E2E journey later (do not invent thin companion-only tests that double the budget).

If none apply: state "No transition/continuity scenarios identified."

---

## 8. What Will NOT Be Tested (Intentional Exclusions)

**Explicitly list what is out of scope and why.**

- Items from ADR Non-Goals section
- Components/files unchanged by the PR
- Behaviors already fully covered by existing tests (from Section 4)
- Areas explicitly excluded by the user

**Code-path verification (mandatory before excluding OR proposing update-path / Day-2 behavior):**

Before proposing tests for update-path, Day-2, or label-removal scenarios — or before excluding them — search the changed controller code to confirm the code path is actually invoked:

```
# Example: verify a utility is called from controllers (not just defined)
rg "FunctionName" pkg/controller/ --glob '*.go' --glob '!*_test.go'
```

- If a function is **defined but not called** from production controller code → exclude the behavior as speculative and cite the grep result.
- If PR description claims Day-2 behavior but the diff only adds create-path handling → exclude Day-2 and note the gap between description and implementation.

Format:
```
- <Excluded item> — Reason: <why it's excluded> (code evidence: <file or grep result>)
```

If the user does not see something they expected here, they should flag it before approval.

**Multi-cluster / federation awareness:** Does the ADR mention cross-cluster behavior (federation, replication, mirroring, multi-site, multi-cluster)? If yes:
- **Default = INCLUDE.** Propose at least one tagged scenario: `Infrastructure: multi-cluster`.
- **Do NOT silently exclude** and do not wait indefinitely — include the proposal in Section 7.
- Exclude **only** after the user explicitly confirms no multi-cluster lab is available.
- Format: `- <test title> — Infrastructure: multi-cluster — <what it tests>`

---

## 9. Analysis Confidence Score

Rate the overall confidence of this analysis:

| Level | Meaning |
| --- | --- |
| **High** | ADR available, clear scope, components well-understood |
| **Medium** | PR-only mode, most behaviors inferable from diff |
| **Low** | PR-only with complex/ambiguous changes, design intent unclear |

**Per-section confidence** (where relevant):
- Impact Analysis: High/Medium/Low
- Blast Radius: High/Medium/Low
- Proposed Tests: High/Medium/Low

**What would increase confidence:**
- e.g., "Provide the ADR for full design context"
- e.g., "Clarify whether field X is backward-compatible"

---

## 10. Output File

Save the generated analysis as:
```
e2e-analysis.md
```

This file is saved in the working directory. It is the **required input** for `test-plan-generation.md` — the test plan generator will not run without an approved `e2e-analysis.md`.

---

## 11. Output Template

Generate the analysis using this template. **Keep it scannable — target ~1 page.**

```markdown
# Pre-Analysis: <Feature/PR Title>

**Source:** <ADR link | PR link | both>
**Date:** <generation date>
**Mode:** ADR Mode | PR Mode | ADR+PR Mode
**Change Type:** Feature | Bug Fix | Refactor | Config | Security | CRD Change

---

## Impact
**Files:** N total (X new, Y modified, Z deleted)

| Category | Count | Key Files |
| --- | --- | --- |
| Controllers | N | `path/to/file.go` |
| CRD Types | N | `path/to/types.go` |
| ... | | |

## Existing Coverage
| Status | Component | Existing Test(s) |
| --- | --- | --- |
| Covered | <component> | `test_file.go:TestName` |
| Needs Update | <component> | `test_file.go:TestName` — reason |
| Not Covered | <component> | — (net-new test needed) |

## Blast Radius
**Components:** <checked list of affected components>
**Quality Gates Impacted:** <list from Section 3b>
**Risk Level:** Low / Medium / High / Critical
**Dependencies:** upstream → [changed component] → downstream

## Regression Risk
| Area | At-Risk Test | Risk Level | Why |
| --- | --- | --- | --- |
| ... | `TestName` | Med/High | ... |

_(or "No regression risk — change is additive.")_

## Proposed Tests (Priority Order)

| # | ID | Tier | Title | Effort | Confidence | Maps To |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | E2E-001 | E2E | ... | M | High | ADR §Goals / PR file:L42 |
| 2 | NEG-001 | NEG | ... | M | High | ... |
| ... | | | | | | |

**Distribution:** E2E: N | NEG: N | ERR: N | INT: N | UT: N | NFT: N | **Total: N**
**Estimated Effort:** X–Y hours

## DoD / Acceptance Mapping (from Section 7e)
| DoD Bullet | Test ID | Status |
|------------|---------|--------|
| <quote> | E2E-NNN / NFT-NNN / ERR-NNN | Mapped / Excluded |

## Exclusions (Will NOT Test)
- <item> — Reason: <justification>
- <item> — Reason: <justification>

## Operator Context (Embedded)

> This section is populated during pre-analysis and carried forward to downstream stages.
> Stages 2-3 read this section instead of re-reading the raw operator files.
> **Default posture:** Red Hat OpenShift + Operator Framework (OLM) unless agents.md / qe-behaviour.md proves otherwise.

### Deployment Model
- **Method:** OLM (default) / Helm / Manual — only override OLM when Operator Context explicitly says so
- **Namespace:** <operator namespace>
- **Operand CRs:** <list of CR kinds and default names>
- **Config patching:** Subscription / CSV patch (never direct Deployment edit when Method=OLM)

### Quality Gates (from qe-e2e/qe-behaviour.md 3b or derived)
| Category | Gate | Observable |
|----------|------|------------|
| Operator Lifecycle | Installation | <observable> |
| Operator Lifecycle | Health | <observable> |
| Operand Health | <Operand1> | <observable> |
| Core Functionality | <gate> | <observable> |
| Security | <gate> | <observable> |
| Resilience | <gate> | <observable> |

### Constraints (from constitution.md)
- <non-negotiable rule 1>
- <non-negotiable rule 2>

### Error Paths (from Section 7a)
| Error Scenario | Expected Behavior | Recovery |
|----------------|-------------------|----------|
| <scenario> | <behavior> | <recovery> |

### Variants (from Section 7b)
| Variant | Type |
|---------|------|
| <variant> | <mode/profile/tier> |

### Thresholds (from Section 7d)
| Threshold | Value | Source |
|-----------|-------|--------|
| <threshold> | <value> | <ADR section> |

## Confidence
**Overall:** High / Medium / Low
**To increase confidence:** <what additional info would help>

---

## ACTION REQUIRED

Review this analysis and respond with one of:
- **Approved** — proceeds to full test plan generation automatically
- **Approved with changes** — specify modifications (add/remove/reorder tests, adjust scope)
- **Rejected** — specify what needs rework

_Once approved, this document becomes the scoping input for test plan generation. The test plan will respect the approved scope, priority ordering, and exclusions._
```

---

## 12. Approval Gate & Auto-Trigger Handoff

### Before approval
- Present the analysis document to the user.
- **STOP. Do not proceed to test plan generation.**
- Wait for the user to respond with Approved, Approved with changes, or Rejected.

### On "Approved with changes"
- Apply the user's modifications to the analysis document.
- Re-present the updated document for final confirmation.

### On "Approved"
1. Save the final approved analysis as `e2e-analysis.md` in the working directory.
2. **Automatically proceed to full test plan generation** using the rules in `test-plan-generation.md`.
3. The test plan generator reads `e2e-analysis.md` as its scoping input. It **MUST**:
   - Use the approved proposed test cases as the starting skeleton.
   - Respect the approved priority ordering.
   - Respect the approved exclusions — do not generate tests for excluded items.
   - Expand each proposed test case into full test steps (preconditions, steps, expected outcomes, cleanup).
   - Stay within the approved tier distribution (may adjust ±1 per tier if justified).
   - Reference the pre-analysis file in the test plan header.

### On "Rejected"
- Ask what needs rework.
- Re-run the analysis with the user's feedback incorporated.

---

## 13. Self-Verification Checklist

Before presenting the analysis to the user, verify:

```
[ ] Change type classified
[ ] All changed files listed and categorized (PR) or components mapped (ADR)
[ ] Existing test coverage assessed — not proposing tests for already-covered behaviors
[ ] Operator context read: qe-e2e/qe-behaviour.md (3a/3b) if present, else derived from agents.md
[ ] Every quality gate from qe-e2e/qe-behaviour.md 3b (or derived) marked affected or not
[ ] Blast radius mapped to operator quality gates
[ ] Every affected quality gate has a proposed test (Section 7) OR an exclusion with code evidence (Section 8)
[ ] Regression risk identified or explicitly marked as none
[ ] Regression risk table cites specific test names and file locations from existing *_test.go — no placeholders
[ ] Update-path / Day-2 behaviors verified against controller call sites before proposing or excluding
[ ] Section 7a: Error paths extracted (3-5 error/recovery pairs)
[ ] Section 7b: Variant coverage extracted (if ADR defines variants)
[ ] Section 7c: Compliance tooling checked
[ ] Section 7d: Thresholds/SLAs extracted (if numeric targets in ADR)
[ ] Proposed tests are priority-ordered with effort and confidence tags
[ ] Every proposed test maps to a specific ADR section or PR diff location
[ ] Multi-operand changes have at least one E2E test per affected operand (primary resource type from diff)
[ ] UT/INT proposed only for pure utilities — not as substitutes for operand E2E behavior
[ ] Multi-cluster tests surfaced with Infrastructure tag (not silently excluded)
[ ] Exclusions section lists what will NOT be tested and why (with code evidence where applicable)
[ ] Operator Context (Embedded) section populated with deployment model, quality gates, constraints
[ ] Overall confidence scored
[ ] Total proposed tests within budget (15-20 base, scaled per rules)
[ ] Review comments fetched (gh api pulls/NNN/comments + /reviews) and unresolved concerns surfaced
[ ] Document is scannable (~1 page, no walls of text)
```

If any check fails, fix it before presenting to the user.
