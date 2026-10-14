---
name: /opsx-new
id: opsx-new
category: Workflow
description: Start a new agile-workflow change from a Jira ticket (OPSX)
---

Start a new change for the **openspec-agile-workflow** pipeline.

## Inputs — what is required when

| Input | Required at `/opsx-new`? | When |
|-------|--------------------------|------|
| **Jira ticket key or URL** | **YES** | Always the first input |
| **Target GitHub repo URL** (upstream) | **YES** | Asked if not provided inline |
| **Local clone path** | **YES** | Asked if not provided inline — where the fork checkout lives |
| **Change name** (kebab-case) | No | Optional; defaults to lowercase ticket slug (`PROJ-123` → `proj-123`) |

There is **no working-folder mode**. All implementation edits happen in `local_clone_path` on `feature_branch` (fork workflow only).

## Command syntax

```
/opsx-new CM-830
/opsx-new CM-830 my-change-name
/opsx-new CM-830 my-change-name https://github.com/org/repo
/opsx-new CM-830 my-change-name https://github.com/org/repo /home/you/code/my-operator-fork
/opsx-new https://issues.redhat.com/browse/CM-830
/opsx-new https://issues.redhat.com/browse/CM-830 https://github.com/org/repo /home/you/code/my-operator-fork
```

Jira key pattern: `[A-Z][A-Z0-9]+-\d+`.
Jira URL pattern: `https://<host>/browse/<KEY>` — extract the key from the URL.

If no Jira key or URL, ask once. Do **not** proceed without it.

## Steps

1. **AI Disclosure Notice**:
   Output EXACTLY this text to the user before proceeding:
   > "======================================================================"
   > "**You are about to interact with a Red Hat AI agent. This agent uses AI technology to assist you by responding to queries, generating content, or performing tasks. By proceeding, you acknowledge that all AI agent outputs are intended for internal use only and must be reviewed prior to use.**"
   > "======================================================================"
2. Parse Jira key or URL (required), optional change name, optional upstream repo URL, optional local clone path.
   - If a Jira URL is provided (e.g. `https://issues.redhat.com/browse/CM-830`), extract the key from the path.
3. **Ask for target repo URL** (if not provided inline):
   ASK: **"What is the target GitHub repository URL? (e.g. https://github.com/org/repo)"**
   - This is the **upstream** repo (planning reference + PR target).
4. **Ask for local clone path** (if not provided inline):
   ASK: **"Where should the fork be cloned? (absolute path, e.g. /home/you/code/my-operator-fork)"**
5. `openspec new change "<name>"` — uses `openspec-agile-workflow` from `openspec/config.yaml`.
6. **Repo setup** (REQUIRED — see schema `repo_setup`, `fork_repo`):
   - **Reuse** when `local_clone_path` exists, is a git repo, `origin` is the user's **fork** (not upstream), and the fork is verified as a fork of `target_repo` (GitHub MCP or `gh repo view`):
     1. `cd local_clone_path`
     2. Checkout default branch (`main` or `master`), `git pull origin`
     3. Record `fork_repo_url` from `git remote get-url origin`
   - **Fork + clone** when reuse validation fails:
     1. Fork `target_repo` into the user's GitHub account via GitHub MCP (skip if fork already exists)
     2. `git clone <fork_repo_url> <local_clone_path>`
   - **Feature branch** (both paths):
     1. Branch name: `feature/<jira_key_lowercase>-<change_slug>` (e.g. `feature/cm-830-my-change`)
     2. `git checkout -b <feature_branch>` from default branch
     3. Do NOT implement on default branch
   - **Validation failures** (halt and explain):
     - `origin` is upstream `target_repo` directly → do not use upstream clone; fork first
     - Path exists but is not a valid fork of `target_repo` → fork + fresh clone or choose another path
7. Write `openspec/changes/<name>/inputs/jira.yaml` with:
   - `jira_key`, `jira_url`, `target_repo`, `fork_repo_url`, `local_clone_path`, `feature_branch`, `repo_setup_at`, `created_at`
8. **Fetch ticket + epic metadata** → `inputs/jira-spec.md` + enrich `inputs/jira.yaml`:
   - Use Jira MCP `jira_get_issue` with `issue_key: "<JIRA-KEY>"` and
     `fields: "summary,status,issuetype,parent,customfield_10014"`.
   - From the response, extract and persist to `inputs/jira.yaml`:
     - `jira_summary`: issue summary field
     - `jira_issuetype`: from `fields.issuetype.name` (e.g. "Epic", "Story", "Bug", "Task")
     - `jira_url`: `https://issues.redhat.com/browse/<JIRA-KEY>`
     - `epic_key`: from `parent.key` or `customfield_10014` (epic link) when present
     - `epic_name`: from `parent.fields.summary` or a follow-up `jira_get_issue` on the epic key
     - `epic_url`: `https://issues.redhat.com/browse/<epic_key>` when epic_key exists
     - `jira_fetched_at`: current ISO8601 timestamp
   - Write ticket description + acceptance criteria to `inputs/jira-spec.md`.
   - If Jira MCP is unavailable, ask the user to paste ticket content into `inputs/jira-spec.md`
     and manually provide epic info if known (optional).
   - **Note:** Spec-understanding phase telemetry does NOT start here — it begins at
     `/opsx-continue` step 6 (`on-artifact-start --artifact validation`). `/opsx-new` only
     registers the run.
9. **Telemetry — register run** (silent, non-blocking):
   ```bash
   python -m openspec.telemetry.auto on-new --change "<name>" --jira-key "<JIRA-KEY>"
   ```
10. `openspec status --change "<name>"` and `openspec instructions validation --change "<name>"`.
11. **STOP** — do not create artifacts yet.

Present repo setup summary:
```
Repo setup complete:
  upstream:       {target_repo}
  fork:           {fork_repo_url}
  local clone:    {local_clone_path}
  feature branch: {feature_branch}
```

Prompt: `/opsx-continue` to create `validation.json`.

## Guardrails

- Jira key or URL required; extract key from URL if URL provided
- Target repo URL and local clone path required — ask if not provided inline
- Repo setup (fork/reuse + feature branch) MUST complete before STOP
- No working-folder mode — never skip fork workflow or feature branch
- No planning artifacts in this command
