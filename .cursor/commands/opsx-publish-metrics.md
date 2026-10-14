---
name: /opsx-publish-metrics
id: opsx-publish-metrics
category: Workflow
description: Publish a change's metrics-report.json and qe-metrics.json to the open-spec-mado GitLab repo as a merge request
argument-hint: "[change-name]"
---

Publish a change's telemetry (`metrics-report.json` and, if present, `qe-metrics.json`) to
[anankuma/open-spec-mado](https://gitlab.cee.redhat.com/anankuma/open-spec-mado) as a merge request:
fork the repo (if not already forked), create a branch, push the files under the correct
operator folder, and open an MR against `main`.

This is a **standalone command**, run manually whenever you want to publish — it is
NOT triggered automatically by `/opsx-archive`. Typically run once a change is fully
archived and its metrics are complete, but it also works on a live (not yet archived)
change if you want to publish interim progress.

**Input**: Optionally specify a change name. If omitted, check conversation context;
if still ambiguous, list both active changes (`openspec list --json`) and archived
changes (`ls openspec/changes/archive/`) and let the user pick via **AskQuestion**.

## Steps

### 1. Resolve the change and locate its telemetry files

The change may already be archived (moved to `openspec/changes/archive/YYYY-MM-DD-<name>/`)
or still live (`openspec/changes/<name>/`). Check both locations, preferring the
archived one if both somehow exist:

```bash
ls openspec/changes/archive/*-<name>/telemetry/ 2>/dev/null
ls openspec/changes/<name>/telemetry/ 2>/dev/null
```

Read whichever of these exist from the resolved directory:
- `telemetry/metrics-report.json` (development metrics)
- `telemetry/qe-metrics.json` (QE/E2E metrics — only if `/opsx-e2e` ran for this change)

**If neither file exists:** STOP — "No telemetry found for `<name>`. Run `/opsx-apply`
(and `/opsx-archive`) first." Do not proceed.

### 2. Check completeness (warn, don't block)

- If `metrics-report.json` exists: check `report_status.complete`.
- If `qe-metrics.json` exists: check `qe_report_status.complete`.

If either is `false`, warn the user:
**"⚠ `<file>` is marked incomplete (`report_status.complete: false` — missing
`<missing_fields>`). This usually means `/opsx-archive` hasn't fully run yet.
Publish anyway?"** — proceed only if the user confirms.

### 3. Determine the operator folder name

Read `operator_name` from `metrics-report.json` (top-level field, set automatically
by `telemetry/report.py` from `git remote get-url origin` at telemetry-generation time).

- **If `metrics-report.json` exists:** use its `operator_name` field.
- **If only `qe-metrics.json` exists** (no dev metrics were ever generated for this
  change): run `git remote get-url origin` directly and derive the name the same way
  (strip `.git`, take the last path segment).

**Normalize** to the dashboard repo's folder convention — lowercase, hyphens → underscores:
```
cert-manager  → cert_manager
ZTWIM         → ztwim
must-gather   → must_gather
```

If the normalized name doesn't match one of the dashboard's existing operator folders,
**that's fine — proceed anyway.** The push will implicitly create the new folder.

### 4. Determine filenames

Read `jira_key` from `metrics-report.json → jira_task_link` (extract the trailing
path segment) or from `inputs/jira.yaml → jira_key` if the change is still live.

Read `codegen_mode` from `openspec/config.yaml → flags.codegen_mode` (default: `direct`).

ASK the user: **"What model was primarily used for this run? (e.g. `composer-2.5`,
`sonnet-5`, `opus`) — press Enter to skip."**
- If provided: `model_slug` = the answer, lowercased, spaces → hyphens.
- If skipped: omit the model segment entirely from the filename.

Build target filenames:

| File | Target path |
|------|-------------|
| `metrics-report.json` | `data/open-spec-matrics/operators/<operator>/<JIRA_KEY>-<codegen_mode>[-<model_slug>]-metrics-report.json` |
| `qe-metrics.json` | `data/open-spec-matrics/operators/<operator>/QE/<JIRA_KEY>-qe-metrics.json` |

Only include a row for a file that actually exists (from step 1).

### 5. Fork and clone the dashboard repo

```bash
GITLAB_UPSTREAM="https://gitlab.cee.redhat.com/anankuma/open-spec-mado.git"
WORK_DIR="$(mktemp -d)"
```

1. **Fork** (if not already forked):
   ```bash
   glab repo fork anankuma/open-spec-mado --clone=false 2>/dev/null || true
   ```
   If `glab` is not available, instruct the user:
   "Fork https://gitlab.cee.redhat.com/anankuma/open-spec-mado via the GitLab UI, then re-run this command."

2. **Determine fork URL** — the fork will be at `https://gitlab.cee.redhat.com/<your-username>/open-spec-mado`:
   ```bash
   GL_USER=$(glab auth status 2>&1 | grep -oP 'Logged in to .* as \K\S+' || git config user.name | tr ' ' '-' | tr '[:upper:]' '[:lower:]')
   FORK_URL="https://gitlab.cee.redhat.com/${GL_USER}/open-spec-mado.git"
   ```

3. **Clone and create branch:**
   ```bash
   git clone --depth 1 "$FORK_URL" "$WORK_DIR/open-spec-mado"
   cd "$WORK_DIR/open-spec-mado"
   git remote add upstream "$GITLAB_UPSTREAM" 2>/dev/null || true
   git fetch upstream main
   git checkout -b "metrics/<jira-key-lowercase>-$(date +%Y%m%d-%H%M)" upstream/main
   ```

### 6. Copy files and commit

```bash
OPERATOR_DIR="data/open-spec-matrics/operators/<operator>"
mkdir -p "$OPERATOR_DIR"
cp <path-to-metrics-report.json> "$OPERATOR_DIR/<dev-filename>"

# Only if qe-metrics.json exists:
mkdir -p "$OPERATOR_DIR/QE"
cp <path-to-qe-metrics.json> "$OPERATOR_DIR/QE/<qe-filename>"

git add "$OPERATOR_DIR/"
git commit -m "Add <JIRA_KEY> metrics for <operator>"
```

### 7. Push and open merge request

```bash
git push -u origin "metrics/<branch-name>"
```

Open a merge request against the upstream repo:
```bash
glab mr create \
  --repo anankuma/open-spec-mado \
  --source-branch "metrics/<branch-name>" \
  --target-branch main \
  --title "Add <JIRA_KEY> metrics — <operator>" \
  --description "$(cat <<'EOF'
## Metrics for <JIRA_KEY> (<operator>)

| Metric | Value |
|--------|-------|
| Story points delivered | <productivity_metrics.story_points_delivered, if present> |
| Time saved | <productivity_metrics.time_saved_hours> hours (est.) |
| Satisfaction | <productivity_metrics.satisfaction_rating>/5 |
| Total tokens | <global_health.total_tokens_consumed> |
| Estimated cost | $<global_health.estimated_cost_usd> |
| QE story points | <qe productivity_metrics.story_points_delivered, if included> |
| QE time saved | <qe productivity_metrics.time_saved_hours> hours (if included) |
| QE satisfaction | <qe productivity_metrics.satisfaction_rating>/5 (if included) |

Generated by `/opsx-publish-metrics`.
EOF
)"
```

**If `glab` is not available**, fall back to the GitLab API:
```bash
curl --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.cee.redhat.com/api/v4/projects/${GL_USER}%2Fopen-spec-mado/merge_requests" \
  --data-urlencode "source_branch=metrics/<branch-name>" \
  --data-urlencode "target_branch=main" \
  --data-urlencode "target_project_id=<upstream-project-id>" \
  --data-urlencode "title=Add <JIRA_KEY> metrics — <operator>" \
  --data-urlencode "description=<summary table>"
```

### 8. Cleanup and report

```bash
rm -rf "$WORK_DIR"
```

Output the MR URL and remind the user:

**"MR opened: `<MR URL>`. The dashboard repo owner needs to merge this MR for the data to appear."**

## Output On Success

```
## Metrics Published

**Change:** <change-name>
**Operator:** <operator folder>
**Files published:**
- data/open-spec-matrics/operators/<operator>/<dev-filename>          (if included)
- data/open-spec-matrics/operators/<operator>/QE/<qe-filename>        (if included)
**Branch:** <your-username>:metrics/<branch-name>
**MR:** <MR URL>
```

## Guardrails

- **Never invent metrics.** Only publish the raw JSON exactly as written by
  `telemetry/report.py` / `telemetry/qe_metrics.py` — do not summarize, reformat,
  round, or edit values before pushing.
- **Do not publish if neither file exists** for the resolved change — stop with a
  clear error (step 1).
- **Warn but don't hard-block on incompleteness** (step 2) — unlike `/opsx-archive`,
  this command is not a compliance gate; the user may legitimately want to publish
  partial/interim data.
- **Required-field parity with the target repo:** ensure non-empty `jira_task_name` and
  `jira_task_link` on every JSON file pushed. Both `metrics-report.json` (via
  `telemetry/jira_metadata.py`) and `qe-metrics.json` already populate these —
  do not push a file where either is empty; if empty, tell the user to ensure
  `inputs/jira.yaml` has `jira_key`/`jira_summary` set, then regenerate the report.
- **Use a single atomic commit** covering both files — do not make two separate
  commits/MRs for one change.
- **This command never merges the MR** — that requires the target repo owner's action.
- **Prefer `glab` CLI** for fork/MR operations. Fall back to the GitLab API with
  `$GITLAB_TOKEN` if `glab` is not installed. If neither is available, complete the
  push and output the URL for the user to create the MR manually.
