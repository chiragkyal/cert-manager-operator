---
name: /opsx-constitute
id: opsx-constitute
category: Workflow
description: Generate constitution.md from harness-docs (with optional repo structure evidence)
---

Generate `harness-evals/constitution.md` from local operator harness documentation
(`harness-evals/harness-docs/`). Optionally fetches a target GitHub repository for
supplementary repo structure evidence (directory layout, build targets).

`agents.md` is expected at the operator repo root — this command does NOT generate it.

This command is **independent of any change** — it runs before `/opsx-new`. It does NOT
require specs.md, repo-assessment.md, or any other workflow artifact.

## Command syntax

```
/opsx-constitute
/opsx-constitute https://github.com/openshift/cert-manager-operator
/opsx-constitute https://github.com/openshift/cert-manager-operator cert-manager-1.18
```

Arguments:
1. **repo URL** (optional) — GitHub HTTPS URL of the target operator repo for supplementary
   repo structure evidence (directory layout, go.mod, Makefile targets). If omitted, the
   constitution is generated purely from `harness-evals/harness-docs/`.
2. **branch** (optional) — branch to analyze (default: repo default branch)

## Steps

### 1. Read harness-docs (REQUIRED)

Read all `.md` files in `harness-evals/harness-docs/`.

- If the directory exists AND contains at least one `.md` file:
  - Load all documents as the SOLE governance source for constitution generation
  - Proceed to Step 2

- If `harness-evals/harness-docs/` does not exist or is empty:
  STOP and output:
  **"No harness documentation found in `harness-evals/harness-docs/`. Place your
  operator documentation (architecture guides, coding conventions, testing patterns, etc.)
  in that folder and re-run `/opsx-constitute`."**
  Do NOT proceed.

### 2. Fetch repo structure (OPTIONAL — only if repo URL provided)

If a repo URL was provided, fetch lightweight repo structure for supplementary evidence.
If no repo URL was provided, skip to Step 3 (generate purely from harness-docs).

Try `gh api` first for speed. Fall back to shallow clone if `gh` is not authenticated.

**Option A — gh api (preferred):**

```bash
# Fetch repo tree
gh api repos/{org}/{repo}/git/trees/{branch}?recursive=1 --jq '.tree[].path' > /tmp/opsx-constitute-tree.txt

# Fetch structural files only (for evidence, not governance)
gh api repos/{org}/{repo}/contents/go.mod?ref={branch} --jq '.content' | base64 -d
# Repeat for Makefile, Dockerfile, README.md, .golangci.yaml
```

**Option B — shallow clone (fallback):**

```bash
WORK_DIR=$(mktemp -d /tmp/opsx-constitute-XXXXXX)
git clone --depth 1 --single-branch ${BRANCH:+--branch "$BRANCH"} "$REPO_URL" "$WORK_DIR/repo"
```

Record (if repo URL provided):
- Resolved branch name
- HEAD commit SHA (short)

### 2b. Check for existing constitution in repo (only if repo URL provided)

If a repo URL was provided, check if the repo already ships a constitution:
- `{repo}/constitution.md`
- `{repo}/CONSTITUTION.md`

If found:
  ASK: **"This repo already contains constitution.md. Use the existing one
  (copy to harness-evals/) or generate a fresh one from harness-docs?"**
  - **Use existing** → copy directly to `harness-evals/constitution.md`, skip to Step 5
  - **Generate fresh** → proceed to Step 3

### 3. Generate constitution (from harness-docs ONLY)

The constitution is derived exclusively from `harness-evals/harness-docs/`:

Read ALL `.md` files loaded in Step 1. These are operator-owner-defined
architecture guides, coding conventions, testing patterns, and operational rules.
They are the ONLY source for governance principles in the constitution.

If a repo URL was provided (Step 2), repo structure (go.mod, Makefile, directory layout)
serves ONLY as structural evidence for file paths and build targets — NOT as governance rules.

If NO repo URL was provided: generate the constitution purely from harness-docs content
without any repo structure evidence.

### 4. Extract repo structure (EVIDENCE backing only — skip if no repo URL)

If no repo URL was provided, skip this step entirely.

Otherwise, collect the following from the repo. This is NOT for deep analysis —
it provides file-path evidence citations for constitution principles.

| File / Pattern | What to extract |
|---------------|-----------------|
| Directory tree (3 levels) | Directories excluding `.git`, `vendor`, `node_modules` |
| `go.mod` | Go version, module path, key dependency lines |
| `Makefile` | Target names, key variables |
| `Dockerfile` | Base image, USER directive, build constraints |
| `README.md` | First 100 lines (project overview) |
| `.golangci.yaml` / `.golangci.yml` | Linter config, enabled linters, build tags |
| `hack/` listing | Script names (verify/update patterns) |
| `api/` listing | CRD type file names |
| `pkg/` listing (2 levels) | Package structure |
| `config/rbac/` listing | RBAC manifest names |
| `bundle/` listing | OLM bundle presence |
| `bindata/` listing | Embedded manifest structure |
| `.github/workflows/` listing | CI workflow file names |
| Recent git log | `git log --oneline -10` |

### 5. Generate constitution.md

Using the agentic documents (Step 3) as primary source and repo structure
(Step 4) as evidence backing, generate the constitution following the
generation prompt and output structure defined in this command.

---

#### Constitution Generation Prompt

You are the "Constitution Agent": a repository governance analyst bootstrapping
non-negotiable guardrails for a spec-driven development pipeline.

##### Mission

Produce `constitution.md` — a document of core principles, coding conventions,
development workflow, and governance rules derived from the repository's agentic
documents and codebase structure. This document is injected into all downstream
agents (Planning, Task Creation, Code Generation) as non-negotiable guardrails.

##### Why this matters

Downstream agents must follow the repo's EXISTING patterns. The constitution
prevents agents from introducing incompatible patterns, ignoring existing
conventions, or duplicating logic.

##### Inputs

1. **Agentic documents** (PRIMARY) — AGENTS.md, CLAUDE.md, cursor rules,
   CONTRIBUTING.md found in the target repo. These contain the architecture,
   controller patterns, test conventions, coding rules, and agent routing
   defined by the repo maintainers. Derive ALL principles from these.

2. **Repo structure** (EVIDENCE BACKING) — directory tree, go.mod, Makefile,
   Dockerfile, hack/ listing, git log. Use ONLY for `**Evidence:**` citations
   to ground each principle in observable file paths and patterns.

##### Task

1. Derive Core Principles from the agentic documents' ACTUAL conventions —
   each principle must map to a concrete pattern or rule stated in the agentic
   docs, backed by an observable file path or structure in the repo. No generic
   best-practice platitudes. Prefer 5–10 substantive principles over padding.

2. Record Additional Constraints: tech stack requirements (Go version, linter
   config, vendor mode, container base image, import ordering), compliance
   standards, deployment policies — all derived from agentic docs or repo config.

3. Document Development Workflow: code review requirements, testing gates,
   CI/CD process, verification commands, codegen refresh — as actually
   documented in the agentic docs or observable in the Makefile/hack/ scripts.

4. Agent Routing:
   - If AGENTS.md was found: set `AgentRoutingMode: PROVIDED` and record all
     agent IDs, scopes, and routing rules from AGENTS.md.
   - If AGENTS.md was NOT found: set `AgentRoutingMode: PROVISIONAL` and list
     provisional IDs (API_Agent, OperatorController_Agent, ManifestsBindata_Agent,
     WebhookTLS_Agent, RBACSecurity_Agent, OLMRelease_Agent, Testing_Agent,
     Docs_Agent).

5. Governance section: how this constitution relates to companion docs
   (AGENTS.md, CLAUDE.md, CONTRIBUTING.md) — which takes precedence for what.

##### Quality rules

- Every principle must cite evidence from the repo (file path or pattern).
  Do not invent principles not supported by the agentic documents or repo.
- Do not include implementation decisions for any specific feature.
- Do not include file inventories, risk analysis, or target file lists.
- Do not reference specs.md, repo-assessment.md, plan.md, or any workflow
  artifact — this constitution is workflow-independent.

##### Output

Output ONLY the complete constitution.md markdown document.
No preamble, no explanation, no code fences — just the document.
Follow the output structure below exactly.

---

#### Constitution Output Structure

<!-- Generated by /opsx-constitute from {REPO_URL} @ {BRANCH} ({COMMIT_SHA}) -->

The generated constitution MUST follow this exact structure:

```
# [PROJECT_NAME] Constitution

**AgentRoutingMode:** PROVIDED | PROVISIONAL
<!-- PROVIDED when AGENTS.md exists in repo; PROVISIONAL otherwise -->

**Version**: 1.0.0 | **Ratified**: [TODAY_DATE] | **Last Amended**: [TODAY_DATE]

<!--
  Self-check (all must pass):
  - Every principle cites observable repo evidence (file path or pattern).
  - No generic best practices — only patterns from the agentic docs and codebase.
  - AgentRoutingMode matches whether AGENTS.md was found.
  - No feature-specific implementation decisions.
  - No file inventories or risk analysis.
-->

## Core Principles

### I. [PRINCIPLE_NAME]
[PRINCIPLE_DESCRIPTION — what to do and why, grounded in agentic doc content]

**Evidence:** `[path/to/file]` — [one-line observation from actual repo structure]

### II. [PRINCIPLE_NAME]
[PRINCIPLE_DESCRIPTION]

**Evidence:** `[path/to/file]` — [observation]

<!-- 5–10 principles, each with Evidence citation. Only add principles
     supported by the agentic documents and observable repo structure. -->

## Additional Constraints

<!-- Tech stack, compliance, deployment policies, naming conventions -->

- **[Constraint category]:** [Rule derived from agentic docs or repo config] — **Evidence:** `[path]`
- **[Constraint category]:** [Rule] — **Evidence:** `[path]`

## Development Workflow

<!-- How work actually flows: verify, test, lint, codegen, review, CI -->

| Activity | Requirement | Evidence |
|----------|-------------|----------|
| Local unit tests | [e.g., `make test`] | `Makefile` |
| Full verify | [e.g., `make verify` or `hack/verify-*`] | `hack/` |
| Lint | [e.g., `make lint`] | `.golangci.yaml` |
| Codegen refresh | [when required] | `[path]` |
| PR / review | [from agentic docs or CONTRIBUTING.md] | `[path]` |

## Agent Routing

<!-- PROVIDED: summarize AGENTS.md agent IDs and routing rules.
     PROVISIONAL: list provisional IDs. -->

| Agent ID | Scope | When to route |
|----------|-------|---------------|
| [AGENT_ID] | [capability] | [task types] |

## Governance

- This constitution supersedes ad-hoc conventions for downstream Planning, Task Creation, and Code Generation agents.
- **Amendments:** require documented evidence of repo change; bump Version and Last Amended date.
- **Conflicts:** if a feature spec contradicts constitution, escalate — do not silently override.
- **Companion docs:** AGENTS.md / CLAUDE.md / CONTRIBUTING.md — [which takes precedence for what].
- **Complexity:** new patterns must justify deviation from existing repo conventions with explicit rationale.
```

---

### 6. Write outputs

1. **Check for existing file** before writing:
   - If `harness-evals/constitution.md` already exists:
     ASK: **"constitution.md already exists in harness-evals/. Overwrite? (Yes / No)"**

2. **Write constitution**: Save the generated constitution to `harness-evals/constitution.md`

### 7. Cleanup

Remove any temp directories created during clone (Option B).

```bash
rm -rf "$WORK_DIR"
```

### 8. Summary

Present:

```
## Constitution Bootstrap Complete

**Repo:** {org}/{repo} @ {branch} ({commit_sha_short})
**Agentic docs found:** [list of files found]
**AgentRoutingMode:** PROVIDED | PROVISIONAL
**Principles generated:** [count]
**Additional constraints:** [count]

**Files written:**
- harness-evals/constitution.md ✓

**Next:** Ensure `agents.md` exists at your operator repo root, then run `/opsx-new <JIRA-KEY>` to start a change.
```

## Guardrails

- This command is **pre-workflow** — do NOT create a change directory
- Do NOT generate specs.md, repo-assessment.md, plan.md, or any workflow artifact
- Do NOT modify any existing change under `openspec/changes/`
- Do NOT reference or read `templates/constitution-template.md` — this command
  is fully self-contained
- AGENTS.md is the PRIMARY source — repo structure is evidence backing only
- Every principle must be traceable to the agentic documents or repo structure
- Clean up temp clone directory even on failure
- If the repo has no agentic docs, warn the user and proceed with PROVISIONAL mode
- **Template sync note:** If the constitution output structure changes in the
  future, update this command's output structure to match. This command is
  intentionally decoupled from `templates/constitution-template.md` to avoid
  agent confusion during generation.
