# Agentic AI Observability Dashboard

SDLC Observability for the OpenSpec Agile Workflow pipeline. Tracks multi-phase metrics for autonomous LLM agents: quality scores, token consumption, cost estimation, agent success rates, and real-time event streaming.

## Architecture

```
┌─────────────────────────┐     SSE stream      ┌──────────────────────────┐
│  React + TypeScript SPA │ ◄──────────────────► │  FastAPI Backend (8000)  │
│  (Vite, port 5173)      │     REST polling     │  SQLite + SSE Broker     │
└─────────────────────────┘                      └──────────┬───────────────┘
                                                            │
                                               ┌────────────┴────────────┐
                                               │  FileEventPoller        │
                                               │  (background asyncio)   │
                                               │  polls events.jsonl →   │
                                               │  ingests to DB + SSE    │
                                               └────────────┬────────────┘
                                                            │ reads NDJSON
                                                            ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  openspec/changes/<name>/telemetry/events.jsonl                          │
│  (NDJSON — one event per line, written by TelemetryClient)               │
└────────────────────────────────────────────────────────────────────────────┘
                                                            ▲
                                                            │ writes events
                                               ┌────────────┴────────────┐
                                               │  TelemetryClient        │
                                               │  (dual-mode: disk +     │
                                               │   optional HTTP)        │
                                               └────────────┬────────────┘
                                                            │ called by
                           ┌────────────────────────────────┼────────────────────┐
                           │                                │                    │
              ┌────────────┴──────────┐       ┌─────────────┴──────┐   ┌────────┴────────┐
              │  auto.py              │       │  openspec_wrapper  │   │  SKILL.md hooks  │
              │  (lifecycle hooks)    │       │  (CLI wrapper)     │   │  (agent calls)   │
              └───────────────────────┘       └────────────────────┘   └─────────────────┘
```

**Key design principles**:
- **Filesystem-first telemetry**: Events are written as NDJSON to `events.jsonl` on disk, then ingested by a background poller. This works in sandboxed environments where HTTP calls may be blocked.
- **Isolation**: The dashboard never modifies the openspec CLI, schemas, or pipeline artifacts. If the backend is down, events still accumulate on disk and are ingested when the backend starts.
- **Fallback**: If the CLI fails or is not installed, the wrapper falls back to reading artifacts from disk and still emits telemetry.

---

## Getting Started (New Users)

Follow these steps after cloning the repo. Tested on Fedora / RHEL; should work on any Linux or macOS.

### 1. Prerequisites

| Tool | Required version | Install |
|------|-----------------|---------|
| Python | 3.10+ | `sudo dnf install python3` or `brew install python` |
| pip | any | Comes with Python |
| Node.js | 18+ | `sudo dnf install nodejs` or `brew install node` |
| npm | 9+ | Comes with Node.js |
| OpenSpec CLI | 1.4+ | `npm install -g @fission-ai/openspec` |
| Cursor IDE | any | Required for `/opsx-*` commands |

Verify:

```bash
python3 --version   # 3.10+
node --version       # 18+
npm --version        # 9+
openspec --version   # 1.4+
```

### 2. Install dependencies

```bash
# From the repo root:
pip install -r requirements.txt

cd web && npm install && cd ..
```

### 3. Start the dashboard

You need **two terminal tabs** (or use `make`):

```bash
# Terminal 1 — Backend API (port 8000)
make backend
# or: uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2 — Frontend UI (port 5173)
make frontend
# or: cd web && npm run dev
```

### 4. Open the dashboard

Go to **http://localhost:5173** in your browser. You'll see an empty dashboard.

### 5. Run the pipeline in Cursor

In Cursor IDE (with this repo open as workspace):

```
/opsx-new CM-830              # Create a new change from a Jira ticket
/opsx-continue                # Create next artifact (repeat 5-6 times)
/opsx-apply                   # Implement tasks one by one
```

The dashboard updates automatically as you work through each stage. The `FileEventPoller` background task picks up new events from disk every 3 seconds and pushes them via SSE to the frontend.

### 6. Seed from existing artifacts (skip the pipeline)

If you already have artifacts on disk (e.g. from a previous run) and just want to see them in the dashboard:

```bash
# Clean old state
rm -f data/dashboard.db openspec/changes/<name>/.dashboard.json

# Restart backend (Terminal 1), then:
python -m openspec.telemetry.auto on-new --change <name> --jira-key <JIRA-KEY>
python -m openspec.telemetry.auto sync --change <name>

# Populate per-task data for Token Burn chart:
for tid in T1_1 T1_2 T1_3; do
  python -m openspec.telemetry.auto on-task-start --change <name> --task-id "$tid" --title "$tid" --agent "Agent_$tid"
  python -m openspec.telemetry.auto on-task-complete --change <name> --task-id "$tid" --status passed
done
```

### 7. Verify via API

```bash
# List runs
curl -s http://localhost:8000/api/v1/runs | python -m json.tool

# Get phases for a run
RUN_ID=$(python -c "import json; print(json.load(open('openspec/changes/<name>/.dashboard.json'))['run_id'])")
curl -s "http://localhost:8000/api/v1/runs/$RUN_ID/phases" | python -m json.tool
curl -s "http://localhost:8000/api/v1/metrics/global/$RUN_ID" | python -m json.tool
curl -s "http://localhost:8000/api/v1/metrics/token-burn/$RUN_ID" | python -m json.tool
curl -s "http://localhost:8000/api/v1/metrics/artifact-edits/$RUN_ID" | python -m json.tool
```

---

## How It Works

### Telemetry Flow (Filesystem-First)

1. **Event emission**: When the SKILL.md workflow calls `auto.py` hooks (e.g. `on-artifact-start`, `on-artifact-created`, `on-artifact-complete`), the `TelemetryClient` writes each event as a JSON line to `openspec/changes/<name>/telemetry/events.jsonl`.
2. **Background ingestion**: The `FileEventPoller` (started as an asyncio task in `src/main.py`) polls all `events.jsonl` files every 3 seconds, ingests new events into the SQLite database, and publishes them via the SSE broker.
3. **Frontend display**: The React SPA subscribes to SSE for live updates and polls REST endpoints for global metrics, phase data, and artifact edit counts.

### Token Estimation (tiktoken)

Since Cursor doesn't expose actual LLM token usage, we estimate tokens from the artifact files on disk using `tiktoken` with the `cl100k_base` encoding (GPT-4/Claude-class). This gives ~5-10% accuracy for most modern LLMs.

- **Input tokens**: Sum of dependency artifacts + input files the agent reads as context
- **Output tokens**: The generated artifact file itself
- **Cost**: Derived from `config.json > metrics.token_cost_per_million` pricing table

### Phase Detection

| Phase | Name | Completes When |
|-------|------|----------------|
| 1 | spec_understanding | `specs.md` approved (last artifact in phase) |
| 2 | repo_assessment | `repo-assessment.md` approved (last artifact in phase) |
| 3 | arch_planning | `plan.md` approved |
| 4 | subtask_creation | `tasks.md` approved |
| 5 | code_generation | Task reports exist under `implementation/task-reports/` |

### Telemetry Event Types

The `auto.py` module emits the following lifecycle events visible in the Worker Logs panel:

| CLI Hook | Event | Description |
|----------|-------|-------------|
| `on-artifact-start` | Phase started | Signals artifact creation began, starts phase if needed. `--batch` sets batch mode. |
| `on-artifact-created` | Artifact created | Artifact file written to disk, awaiting eval gate. `--batch` skips token-bearing phase_progress. |
| `on-waiting-approval` | Waiting for approval | Eval passed, artifact presented for human decision |
| `on-artifact-complete` | Human approved/rejected | User approves or rejects, phase ends if last artifact. `--batch` uses phase-level token estimate. |
| `on-apply-start` | Phase 5 started | Signals task loop began. `--batch` sets batch mode for all tasks. |
| `on-task-start` | Task started | Individual task execution begins |
| `on-task-complete` | Task completed | Task approved or failed. `--batch` emits zero tokens with `attribution: "phase_aggregate"`. |
| `on-apply-complete` | Phase 5 + run ended | All tasks done. Auto-detects batch mode if not explicitly set. |

### Iteration and Edit Metrics

The dashboard reads refinement data from disk:

| Source | Field | Used for |
|--------|-------|----------|
| `eval-results/<artifact>.yaml` | `refinement_round` / `refinement_rounds` | Phase waterfall **Iterations** column |
| `feedback_stage_artifacts/<artifact>/round-*.yaml` | file count | Added to eval refinements for total edit count |
| `eval-results/code-generation-<task>.yaml` | `refinement_rounds` | Task `self_correction_loops` |

Global Health exposes **Gate Passing Rate** (first-pass phases), **Refinement Iterations** (sum of extra passes), and **Human Rejection Rate** (refinement proxy).

### Per-Artifact Edit Counts

The **Per-Artifact Edit Counts** panel shows a breakdown for each generated artifact:
- **Eval refinements**: How many eval gate passes the artifact went through
- **User feedback rounds**: How many times the user rejected and requested refinement
- **Total edits**: Sum of both (higher values indicate artifacts that needed more iteration)

---

## File Structure

### Backend (`src/`)

| Path | Purpose |
|------|---------|
| `src/main.py` | FastAPI app entry point |
| `src/api/v1/` | REST endpoints (runs, phases, tasks, events, metrics) |
| `src/core/config.py` | Configuration loader (`config.json`) |
| `src/core/sse.py` | Server-Sent Events broker |
| `src/db/` | SQLAlchemy engine, base, seed |
| `src/models/` | ORM models (PipelineRun, PhaseExecution, TaskExecution, AgentEvent) |
| `src/schemas/` | Pydantic request/response schemas |
| `src/services/metrics_service.py` | Global health + token burn + artifact edits computation |
| `src/services/file_event_poller.py` | Background poller: `events.jsonl` → DB + SSE |

### Telemetry (external — `openspec/telemetry/`)

Telemetry emission lives in `openspec/telemetry/` (the sibling package), not inside the dashboard. The dashboard imports `openspec.telemetry.change_metrics` at runtime via `PYTHONPATH`.

| Path (relative to project root) | Purpose |
|------|---------|
| `openspec/telemetry/client.py` | Disk-only NDJSON event writer |
| `openspec/telemetry/auto.py` | Lifecycle hooks called by `/opsx-*` commands |
| `openspec/telemetry/change_metrics.py` | Iteration/edit metrics from eval YAML (imported by dashboard) |
| `openspec/telemetry/tokens.py` | tiktoken-based token estimation |
| `openspec/telemetry/report.py` | Filesystem metrics-report.json generator |

### Frontend (`web/`)

| Path | Purpose |
|------|---------|
| `web/src/App.tsx` | Main app, merges REST + SSE data |
| `web/src/hooks/useRun.ts` | React-query hooks for runs, phases, tasks, events |
| `web/src/hooks/useSSE.ts` | SSE stream hook for live events |
| `web/src/hooks/useMetrics.ts` | Metrics polling hooks (global, token burn, artifact edits) |
| `web/src/services/api.ts` | REST API client |
| `web/src/components/` | UI components (waterfall, metrics, artifact edits, logs, charts) |

### Configuration

| Path | Purpose |
|------|---------|
| `config.json` | Dashboard config (DB URL, SSE, token pricing, telemetry polling) |
| `requirements.txt` | Python dependencies |

### Data (auto-generated, gitignored)

| Path | Purpose |
|------|---------|
| `data/dashboard.db` | SQLite database (created on first backend start) |
| `openspec/changes/<name>/.dashboard.json` | Per-change tracking state (run_id, phase_ids) |
| `openspec/changes/<name>/telemetry/events.jsonl` | NDJSON telemetry event log |

---

## Configuration Reference (`config.json`)

```jsonc
{
  "server": { "port": 8000, "cors_origins": ["http://localhost:5173"] },
  "database": { "url": "sqlite+aiosqlite:///data/dashboard.db" },
  "sse": { "retry_ms": 3000, "heartbeat_interval_s": 15 },
  "telemetry": {
    "endpoint": "http://localhost:8000/api/v1/events",
    "bus_dir": "openspec/changes",
    "poll_interval_s": 3.0
  },
  "metrics": {
    "token_cost_per_million": {
      "claude-sonnet-4": { "input": 3.00, "output": 15.00 },
      "gemini-2.5-pro": { "input": 1.25, "output": 5.00 },
      "default": { "input": 2.00, "output": 8.00 }
    },
    "phase5_close_on": "implementation_report"
  },
  "vertex_ai": { "enabled": false }
}
```

No LLM provider configuration is needed. Token estimation uses tiktoken (local, no API calls). Cost is derived by multiplying token counts by the pricing table above.

---

## Isolation Guarantees

- The dashboard never modifies the openspec CLI, schemas, or pipeline artifacts
- All telemetry calls are wrapped in try/except; failures are silent
- Deleting `src/`, `web/`, `data/`, `config.json` has zero impact on the pipeline

---

## Real-Time End-to-End Testing

Use this to verify live telemetry during a new change:

```bash
# Terminal 1 — backend
uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2 — frontend
cd web && npm run dev

# In Cursor — full pipeline (wrapper is invoked by SKILL.md automatically):
# /opsx-new CM-831
# /opsx-continue   (repeat until all planning artifacts approved)
# /opsx-apply      (task loop)

# Verify after each stage:
curl -s http://localhost:8000/api/v1/runs | python -m json.tool
```

**Acceptance checklist:**

- [ ] Run appears after first `/opsx-new` or `/opsx-continue`
- [ ] Phases 1–4 close with correct iteration counts
- [ ] Phase 2 closes when `repo-assessment.md` is approved
- [ ] Phase 5 closes with partial or full task label; run status becomes `completed`
- [ ] Global Health shows Gate Passing Rate, Refinement Iterations, Agent Success Rate
- [ ] Per-Artifact Edit Counts table populates as artifacts are approved
- [ ] Token burn chart populates as tasks complete
- [ ] Worker logs show artifact_created, waiting_approval, and human_approved events
- [ ] SSE worker logs stream during `/opsx-apply`
- [ ] Logs persist after browser refresh (REST hydration)
- [ ] Cumulative Wall Time is non-zero
