## Mode: Skeleton (`pass_mode: skeleton`)

Generate §0 through §3 ONLY. Do NOT generate §4 or §5.

### Phase scope
When `phase_scope` metadata is present, generate §0-§3 for the specified plan
phase ONLY. §0 maps only that phase's spec goals. §1-§3 contain only that
phase's tasks. Task IDs use the phase prefix (T{N}_*).

### Completeness rules
- **Generation priority when space-constrained:** §0 coverage checklist → §3 manifest (all tasks) →
  §2 linear order → §1 DAG.
- Unit test co-generation: every Go implementation task MUST include test co-generation in its
  Acceptance criteria (not separate tasks). Use actual Makefile targets from repo_assessment.

### Output sections — use these EXACT headings

## 0. Input Coverage Checklist
Short bullet list mapping spec goals + plan phases → task coverage (prove nothing obvious was dropped).

### Functional Requirements → Task Coverage
One bullet per spec requirement (FR-xx, SC-xx, AC-xx) and plan phase, each with the Task IDs that
cover it.

### User Stories → Task Coverage
One bullet per US-00x with covering Task IDs.
Every US-00x from specs.md must appear with ≥1 Task ID.
Note any e2e coverage as "e2e — out of OAPE scope".

## 1. Task Dependency Graph (Mermaid)
Use `graph TD` (or `flowchart LR`) with stable node IDs like `T1_1`, `T1_2`, ... matching Task IDs.

```mermaid
graph TD
    subgraph phase1 [Phase 1: PHASE_NAME]
        T1_1[Task 1.1: TITLE]
        T1_2[Task 1.2: TITLE]
        T1_1 --> T1_2
    end

    subgraph phase2 [Phase 2: PHASE_NAME]
        T2_1[Task 2.1: TITLE]
        T2_2[Task 2.2: TITLE]
        T1_2 --> T2_1
        T1_2 --> T2_2
    end
```

## 2. Linear Execution Order (Chronological)
Numbered list of Task IDs in a valid topological order (ties broken by phase order from technical_plan.md).

## 3. Task Execution Manifest (table)
A markdown table with EXACT columns:
| Task ID | Task Title | Assigned Agent | Phase | Depends On | Parallel OK | Complexity | Risk | User Story |
|---------|-----------|---------------|-------|-----------|------------|-----------|------|------------|
| T1_1 | [TITLE] | [AGENT_ID] | [PHASE] | none | No | [1-8] | [Low/Med/High] | US-001 |

### tasks_index.json

Additionally, emit a fenced JSON block labeled `tasks_index.json` at the end of your response
containing a machine-parseable array of all tasks. Schema:

```json
[
  {
    "id": "T1_1",
    "title": "Short task title",
    "summary": "One-line description of what this task accomplishes",
    "phase": "Phase 1: Phase Name",
    "depends_on": ["T1_0"],
    "agent": "OperatorController_Agent",
    "parallel_ok": false,
    "complexity": 3,
    "risk": "Low"
  }
]
```

Required fields: `id`, `title`, `summary`, `phase`, `depends_on` (array, use `[]` for no deps),
`agent`, `parallel_ok` (boolean), `complexity` (integer 1|2|3|5|8), `risk` ("Low"|"Med"|"High").

The `summary` field is a single sentence describing the task's objective — it is used for
human review before detailed payloads are generated.

Output structure:
1. The full markdown for §0, §1, §2, §3
2. A fenced code block: ` ```json tasks_index.json ` containing the JSON array
3. Nothing else — no §4, no §5

### Quality self-check
- [ ] §0 lists every FR-xx, SC-xx, and plan phase with covering Task IDs
- [ ] §0 lists every US-00x from specs.md with ≥1 covering Task ID
- [ ] §0 notes any discarded e2e coverage as "out of OAPE scope"
- [ ] No e2e or Testing_Agent tasks in §3 manifest
- [ ] §3 manifest User Story column is populated for every row
- [ ] AgentRoutingMode matches constitution.md (PROVIDED vs PROVISIONAL)
- [ ] §2 linear order is a valid topological sort of §1 DAG
- [ ] Assigned Agent values exist in agents.md (when PROVIDED) or match provisional IDs exactly
- [ ] §3 manifest row count matches tasks_index.json entry count

### Task sizing
If user message metadata contains `task_sizing`, apply **Task consolidation rules**
from the base tasks-template.md after generating §3. Verify §3 row count is within
[min, max]. Do NOT prompt the user — sizing was already collected.
