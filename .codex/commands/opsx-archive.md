---
name: /opsx-archive
id: opsx-archive
category: Workflow
description: Archive a completed change in the experimental workflow
---

Archive a completed change in the experimental workflow.

**Input**: Optionally specify a change name after `/opsx:archive` (e.g., `/opsx:archive add-auth`). If omitted, check if it can be inferred from conversation context. If vague or ambiguous you MUST prompt for available changes.

## HARD RULE — FEEDBACK BEFORE ARCHIVE

**You MUST ask the four feedback questions (step 5) and fire the telemetry hook BEFORE performing the archive move (step 6). This is NON-NEGOTIABLE. If the user says "skip" or "just archive", respond: "Feedback collection is mandatory for compliance. It takes 30 seconds. Please answer the four questions to proceed." Do NOT proceed to step 6 until step 5 (and step 5b when applicable) are fully complete.**

**Steps**

1. **If no change name provided, prompt for selection**

   Run `openspec list --json` to get available changes. Use the **AskUserQuestion tool** to let the user select.

   Show only active changes (not already archived).
   Include the schema used for each change if available.

   **IMPORTANT**: Do NOT guess or auto-select a change. Always let the user choose.

2. **Check artifact completion status**

   Run `openspec status --change "<name>" --json` to check artifact completion.

   Parse the JSON to understand:
   - `schemaName`: The workflow being used
   - `artifacts`: List of artifacts with their status (`done` or other)

   **If any artifacts are not `done`:**
   - Display warning listing incomplete artifacts
   - Prompt user for confirmation to continue
   - Proceed if user confirms

3. **Check task completion status**

   Read the tasks file (typically `tasks.md`) to check for incomplete tasks.

   Count tasks marked with `- [ ]` (incomplete) vs `- [x]` (complete).

   **If incomplete tasks found:**
   - Display warning showing count of incomplete tasks
   - Prompt user for confirmation to continue
   - Proceed if user confirms

   **If no tasks file exists:** Proceed without task-related warning.

4. **Assess delta spec sync state**

   Check for delta specs at `openspec/changes/<name>/specs/`. If none exist, proceed without sync prompt.

   **If delta specs exist:**
   - Compare each delta spec with its corresponding main spec at `openspec/specs/<capability>/spec.md`
   - Determine what changes would be applied (adds, modifications, removals, renames)
   - Show a combined summary before prompting

   **Prompt options:**
   - If changes needed: "Sync now (recommended)", "Archive without syncing"
   - If already synced: "Archive now", "Sync anyway", "Cancel"

   If user chooses sync, use Task tool (subagent_type: "general-purpose", prompt: "Use Skill tool to invoke openspec-sync-specs for change '<name>'. Delta spec analysis: <include the analyzed delta spec summary>"). Proceed to archive regardless of choice.

5. **User feedback, time savings, and story points — MANDATORY (NON-SKIPPABLE)**

   **HARD GUARDRAIL: You MUST complete this step before archiving. Do NOT skip, defer, or proceed to step 6 without collecting ALL FOUR responses, writing `user-feedback.md`, and recording the telemetry hook below. If the user says "skip" or "just archive", respond: "Feedback collection is mandatory for compliance (MON-01). It takes 30 seconds. Please answer the four questions to proceed."**

   Present the following four questions to the user. Use the **AskQuestion tool** with all four questions in a single prompt:

   **Question 1:** "How long would this change have taken without the agent? (estimated manual hours)"
   - Options: "< 2 hours", "2–4 hours", "4–8 hours (1 day)", "8–16 hours (2 days)", "16–40 hours (1 week)", "> 40 hours (1+ weeks)"

   **Question 2:** "How satisfied are you with this run? (1 = poor, 5 = excellent)"
   - Options: "1 — Poor (major issues, significant rework)", "2 — Below average (multiple corrections needed)", "3 — Average (some corrections, acceptable output)", "4 — Good (minor corrections only)", "5 — Excellent (minimal or no corrections)"

   **Question 3:** "Any comments on this run? (optional — leave blank if none)"
   - Free text (the user can select "Other" and type a response, or select "No comments")
   - Options: "No comments"

   **Question 4:** "How many story points were delivered for this ticket?" — **MANDATORY, this is the field that determines whether metrics-report.json is considered complete.**
   - Options: "1", "2", "3", "5", "8", "13", "21+"
   - The user can select "Other" and type an exact number instead. Do not accept a blank answer — if the user tries to skip, re-prompt: "Story points delivered is mandatory. Without it, metrics-report.json will be marked incomplete."

   After collecting responses, write `openspec/changes/<name>/user-feedback.md`:

   ```markdown
   # User Feedback — <change-name>

   **Date:** YYYY-MM-DD
   **Change:** <change-name>
   **Jira:** <jira_key from inputs/jira.yaml, if available>

   ## Time Savings
   - **Estimated manual effort:** <user's answer to Q1>
   - **Agent-assisted wall time:** <total elapsed from telemetry if available, otherwise "not recorded">

   ## Satisfaction
   - **Rating:** <user's answer to Q2>

   ## Comments
   <user's answer to Q3, or "None">

   ## Productivity
   - **Story points delivered:** <user's answer to Q4>
   ```

   If step 5b also runs (this change had an E2E run), append a QE section to
   the same `user-feedback.md` after step 5b completes:

   ```markdown

   ## QE / E2E Feedback
   - **Estimated manual effort:** <step 5b Q1 answer>
   - **Satisfaction:** <step 5b Q2 answer>
   - **Story points (QE/test coverage):** <step 5b Q4 answer>
   - **Comments:** <step 5b Q3 answer, or "None">
   ```

   This file will be archived with the change directory in step 6.

   **Telemetry — record archive feedback (mandatory, before step 6):**

   Immediately after writing `user-feedback.md`, run:
   ```bash
   python -m openspec.telemetry.auto on-archive-feedback --change "<name>" \
     --story-points <Q4 answer> --manual-effort "<Q1 answer>" \
     --satisfaction <Q2 answer> --comments "<Q3 answer, or empty string if none>"
   ```
   This writes the `archive_feedback` telemetry event (which sets `run.archived_at`) and regenerates `metrics-report.json` with the `productivity_metrics` block and `report_status.complete: true`. It must run **before** step 6 moves the change directory, so the updated report is archived along with everything else. If this command fails or is skipped, `metrics-report.json` remains `report_status.complete: false` — flag this to the user before proceeding to step 6.

5b. **QE feedback — CONDITIONAL (only if this change had an E2E run)**

   **First, detect whether E2E was run for this change:**
   ```bash
   test -f openspec/changes/<name>/telemetry/e2e-events.jsonl && echo "e2e_ran" || echo "no_e2e"
   ```

   - **If `no_e2e`:** Skip this step entirely — do not ask any QE questions, do not create `qe-metrics.json`. Proceed directly to step 6.
   - **If `e2e_ran`:** This change has at least one `/opsx-e2e` run recorded (possibly more than one, e.g. one per phase). This is now **MANDATORY, NON-SKIPPABLE**, exactly like step 5 — `/opsx-e2e` itself never asks these questions; `/opsx-archive` is the single place they are collected. If the user says "skip", respond: "QE feedback is mandatory for compliance (MON-01) since this change ran E2E. Please answer the four questions to proceed."

   Present the following four questions using the **AskQuestion tool** (all four in a single prompt). These are **identical in structure** to the dev workflow questions (step 5) so both reports produce a uniform `productivity_metrics` block:

   **Question 1:** "How long would the E2E/QE work have taken without the agent? (estimated manual hours for writing and running these tests)"
   - Options: "< 2 hours", "2–4 hours", "4–8 hours (1 day)", "8–16 hours (2 days)", "16–40 hours (1 week)", "> 40 hours (1+ weeks)"

   **Question 2:** "How satisfied are you with the E2E/QE workflow? (1 = poor, 5 = excellent)"
   - Options: "1 — Poor (major issues, significant rework)", "2 — Below average (multiple corrections needed)", "3 — Average (some corrections, acceptable output)", "4 — Good (minor corrections only)", "5 — Excellent (minimal or no corrections)"

   **Question 3:** "Any feedback on the E2E/QE workflow? (optional — leave blank if none)"
   - Free text (the user can select "Other" and type a response, or select "No comments")
   - Options: "No comments"

   **Question 4:** "How many story points (or effort points) does the QE/test coverage for this ticket represent?" — **MANDATORY, this is the field that determines whether `qe-metrics.json` is considered complete.**
   - Options: "1", "2", "3", "5", "8", "13", "21+"
   - The user can select "Other" and type an exact number. Do not accept a blank answer — if the user tries to skip, re-prompt: "QE story points delivered is mandatory. Without it, qe-metrics.json will be marked incomplete."

   The agent computes `time_saved_hours = estimated_manual_hours - actual_wall_time_hours`
   automatically from the Q1 bucket midpoint and the QE agent wall time recorded in telemetry
   (same approach as the dev workflow). No manual time-saved entry needed from the user.

   **Telemetry — record QE archive feedback (mandatory when E2E ran, before step 6):**

   Immediately after collecting the four answers, run:
   ```bash
   python -m openspec.telemetry.auto on-qe-archive-feedback --change "<name>" \
     --story-points <Q4 answer> --manual-effort "<Q1 answer>" \
     --satisfaction <Q2 answer> --comments "<Q3 answer, or empty string if none>"
   ```
   This writes the `qe_archive_feedback` event to `telemetry/e2e-events.jsonl` and regenerates `qe-metrics.json` with the `productivity_metrics` block (including `time_saved_hours` computed from Q1 bucket midpoint minus agent wall time), `qe_started_at`/`qe_completed_at` (IST), and `qe_report_status.complete: true`. It must run **before** step 6 moves the change directory — the hook writes into the live `openspec/changes/<name>/telemetry/` path, which only exists pre-move. If this command fails, `qe-metrics.json` remains `qe_report_status.complete: false` — flag this to the user before proceeding to step 6.

6. **Perform the archive**

   Create the archive directory if it doesn't exist:
   ```bash
   mkdir -p openspec/changes/archive
   ```

   Generate target name using current date: `YYYY-MM-DD-<change-name>`

   **Check if target already exists:**
   - If yes: Fail with error, suggest renaming existing archive or using different date
   - If no: Move the change directory to archive

   ```bash
   mv openspec/changes/<name> openspec/changes/archive/YYYY-MM-DD-<name>
   ```

7. **Display summary**

   Show archive completion summary including:
   - Change name
   - Schema that was used
   - Archive location
   - Spec sync status (synced / sync skipped / no delta specs)
   - Note about any warnings (incomplete artifacts/tasks)

8. **External agent feedback form — prompt at end (MANDATORY display)**

   After showing the step 7 summary, **always** present this closing message to the user.
   Do NOT skip even if the user is in a hurry — it is separate from step 5 (in-chat
   telemetry feedback) and captures quality issues for the OpenSpec maintainers.

   Output verbatim (replace `<change-name>` and `<jira_key>` when available):

   ```
   ## One more step — Agent feedback form

   Archive feedback for this change is saved locally. Please also submit the
   **external agent feedback form** so we can track quality issues, hallucinations,
   and unexpected behavior across operators:

   **Change:** <change-name>
   **Jira:** <jira_key from inputs/jira.yaml, or "n/a">

   **[Submit Agent Feedback Here](https://docs.google.com/spreadsheets/d/1lBhSpvjtceexzHGc-dF37F6ho2y4msUnXm5hg52gMus/edit?usp=sharing)**

   Include your Jira key, a brief description of any problems, and what worked well.
   ```

   If the user says they already submitted the form, acknowledge and close — do not
   block or re-prompt. The form is best-effort; step 5 telemetry feedback remains mandatory.

**Output On Success**

```
## Archive Complete

**Change:** <change-name>
**Schema:** <schema-name>
**Archived to:** openspec/changes/archive/YYYY-MM-DD-<name>/
**Specs:** ✓ Synced to main specs
**Feedback:** ✓ Captured (user-feedback.md)
**Story Points Delivered:** <Q4 answer>
**Time Saved:** <productivity_metrics.time_saved_hours> hours (est.)
**Archived:** <run.archived_at_display, IST>
**Metrics:** ✓ Complete (metrics-report.json → report_status.complete: true)
**QE Metrics:** ✓ Complete (qe-metrics.json → qe_report_status.complete: true) — QE story points: <Q4 answer>, time saved: <productivity_metrics.time_saved_hours>h, satisfaction: <Q2 answer>/5
  *(omit this line entirely if step 5b was skipped — no E2E run for this change)*

All artifacts complete. All tasks complete.

---

**Also submit the external agent feedback form:**
https://docs.google.com/spreadsheets/d/1lBhSpvjtceexzHGc-dF37F6ho2y4msUnXm5hg52gMus/edit?usp=sharing
```

**Output On Success (No Delta Specs)**

```
## Archive Complete

**Change:** <change-name>
**Schema:** <schema-name>
**Archived to:** openspec/changes/archive/YYYY-MM-DD-<name>/
**Specs:** No delta specs
**Feedback:** ✓ Captured (user-feedback.md)
**Story Points Delivered:** <Q4 answer>
**Time Saved:** <productivity_metrics.time_saved_hours> hours (est.)
**Archived:** <run.archived_at_display, IST>
**Metrics:** ✓ Complete (metrics-report.json → report_status.complete: true)
**QE Metrics:** ✓ Complete (qe-metrics.json → qe_report_status.complete: true) — QE story points: <Q4 answer>, time saved: <productivity_metrics.time_saved_hours>h, satisfaction: <Q2 answer>/5
  *(omit this line entirely if step 5b was skipped — no E2E run for this change)*

All artifacts complete. All tasks complete.

---

**Also submit the external agent feedback form:**
https://docs.google.com/spreadsheets/d/1lBhSpvjtceexzHGc-dF37F6ho2y4msUnXm5hg52gMus/edit?usp=sharing
```

**Output On Success With Warnings**

```
## Archive Complete (with warnings)

**Change:** <change-name>
**Schema:** <schema-name>
**Archived to:** openspec/changes/archive/YYYY-MM-DD-<name>/
**Specs:** Sync skipped (user chose to skip)
**Feedback:** ✓ Captured (user-feedback.md)
**Story Points Delivered:** <Q4 answer>
**Time Saved:** <productivity_metrics.time_saved_hours> hours (est.)
**Archived:** <run.archived_at_display, IST>
**Metrics:** ✓ Complete (metrics-report.json → report_status.complete: true)
**QE Metrics:** ✓ Complete (qe-metrics.json → qe_report_status.complete: true) — QE story points: <Q4 answer>, time saved: <productivity_metrics.time_saved_hours>h, satisfaction: <Q2 answer>/5
  *(omit this line entirely if step 5b was skipped — no E2E run for this change)*

**Warnings:**
- Archived with 2 incomplete artifacts
- Archived with 3 incomplete tasks
- Delta spec sync was skipped (user chose to skip)

Review the archive if this was not intentional.

---

**Also submit the external agent feedback form:**
https://docs.google.com/spreadsheets/d/1lBhSpvjtceexzHGc-dF37F6ho2y4msUnXm5hg52gMus/edit?usp=sharing
```

**Output When Metrics Are Incomplete (telemetry hook failed before the move)**

```
## Archive Blocked — Metrics Incomplete

**Change:** <change-name>
**Feedback:** ✓ Captured (user-feedback.md)
**Metrics:** ⚠ Incomplete — metrics-report.json → report_status.complete: false
  Missing: productivity_metrics.story_points_delivered

The on-archive-feedback telemetry hook did not succeed. Do NOT proceed to step 6
(the directory move) until it succeeds — the hook writes into the live change
directory and cannot be run again once it has moved to openspec/changes/archive/.
Retry:
python -m openspec.telemetry.auto on-archive-feedback --change "<name>" --story-points <N> \
  --manual-effort "<Q1 answer>" --satisfaction <Q2 answer> --comments "<Q3 answer>"
```

**Output When QE Metrics Are Incomplete (step 5b telemetry hook failed before the move)**

```
## Archive Blocked — QE Metrics Incomplete

**Change:** <change-name>
**Feedback:** ✓ Captured (user-feedback.md)
**Metrics:** ✓ Complete (metrics-report.json → report_status.complete: true)
**QE Metrics:** ⚠ Incomplete — qe-metrics.json → qe_report_status.complete: false
  Missing: qe_feedback.story_points_delivered

This change had an E2E run, so QE feedback is mandatory. The on-qe-archive-feedback
telemetry hook did not succeed. Do NOT proceed to step 6 until it succeeds — the hook
writes into the live change directory and cannot be run again once archived.
Retry:
python -m openspec.telemetry.auto on-qe-archive-feedback --change "<name>" \
  --story-points <N> --manual-effort "<Q1 answer>" \
  --satisfaction <N> --comments "<Q3 answer>"
```

**Output On Error (Archive Exists)**

```
## Archive Failed

**Change:** <change-name>
**Target:** openspec/changes/archive/YYYY-MM-DD-<name>/

Target archive directory already exists.

**Options:**
1. Rename the existing archive
2. Delete the existing archive if it's a duplicate
3. Wait until a different date to archive
```

**Guardrails**
- Always prompt for change selection if not provided
- Use artifact graph (openspec status --json) for completion checking
- Don't block archive on warnings - just inform and confirm
- Preserve .openspec.yaml when moving to archive (it moves with the directory)
- Show clear summary of what happened
- If sync is requested, use the Skill tool to invoke `openspec-sync-specs` (agent-driven)
- If delta specs exist, always run the sync assessment and show the combined summary before prompting
- **MANDATORY: Step 5 (user feedback + story points) MUST be completed before step 6 (archive). Do NOT skip feedback collection. Do NOT archive without writing `user-feedback.md` AND successfully running the `on-archive-feedback` telemetry hook. If the user attempts to skip, explain that feedback and story points are required for compliance (MON-01) and re-prompt.**
- **Story points delivered (Question 4) is mandatory and gates `metrics-report.json` completeness — `report_status.complete` is `false` until it is recorded. Never invent a story points value; only use what the user provides.**
- **The `on-archive-feedback` telemetry hook MUST run before step 6 moves the change directory** — it writes into the live `openspec/changes/<name>/telemetry/` path, which only exists pre-move.
- **Step 5b (QE feedback) is CONDITIONAL, not universal.** Only run it if `openspec/changes/<name>/telemetry/e2e-events.jsonl` exists (i.e. `/opsx-e2e` ran for this change). If it doesn't exist, skip step 5b silently — do not mention QE metrics at all in the output.
- **`/opsx-e2e` never asks for time-saved, story points, or feedback.** `/opsx-archive` is the single, centralized place both development AND QE feedback are collected — never re-implement a feedback prompt inside `/opsx-e2e`.
- **When step 5b applies, it is just as mandatory as step 5.** Do NOT archive a change that ran E2E without successfully running the `on-qe-archive-feedback` telemetry hook — `qe-metrics.json` would remain `qe_report_status.complete: false`. All four QE questions (estimated_manual_effort, satisfaction, feedback, story_points) must be answered — they mirror the dev workflow questions exactly.
- **The `on-qe-archive-feedback` telemetry hook MUST run before step 6 moves the change directory** (same reasoning as `on-archive-feedback`) — it writes into the live `openspec/changes/<name>/telemetry/` path.
- **If a change has multiple E2E runs (e.g. one per phase in phase-iterative mode), step 5b still asks only once, at final archive** — covering the QE effort as a whole, not per-phase.
- **Step 8 (external agent feedback form) MUST always be shown after a successful archive** — link: https://docs.google.com/spreadsheets/d/1lBhSpvjtceexzHGc-dF37F6ho2y4msUnXm5hg52gMus/edit?usp=sharing — separate from step 5 in-chat feedback; display even when archive completed with warnings.
