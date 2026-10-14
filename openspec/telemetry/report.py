"""Generate metrics-report.json from events.jsonl and filesystem artifacts.

Reconstructs run, phases, tasks, events, global_health, and artifact_edits
entirely from local files — no database, no server.
"""
from __future__ import annotations

import json
import logging
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .change_metrics import (
    ARTIFACT_PHASE_MAP,
    count_feedback_rounds,
    phase5_iteration_count,
    phase5_should_close,
    phase_duration_s,
    phase_iteration_count,
    read_eval_refinement_round,
    read_task_refinement_rounds,
)

logger = logging.getLogger(__name__)

CHANGES_DIR = Path("openspec/changes")

# Approximate per-token pricing (USD per 1M tokens).
# Uses Claude Sonnet-class rates as the default since Cursor primarily routes
# through Claude. Override by editing this table if your setup differs.
PRICE_TABLE: dict[str, dict[str, float]] = {
    "default": {"input": 3.0, "output": 15.0},
    "claude-sonnet": {"input": 3.0, "output": 15.0},
    "claude-opus": {"input": 15.0, "output": 75.0},
    "gpt-4o": {"input": 2.5, "output": 10.0},
}


def _estimate_cost(tokens_in: int, tokens_out: int, model: str = "default") -> float:
    """Estimate USD cost from token counts using the price table."""
    rates = PRICE_TABLE.get(model, PRICE_TABLE["default"])
    return (tokens_in * rates["input"] + tokens_out * rates["output"]) / 1_000_000


# India Standard Time (UTC+5:30) — all run timestamps are displayed in IST.
IST = timezone(timedelta(hours=5, minutes=30))


def _to_ist_display(iso_str: str | None) -> str:
    """Format an ISO8601 (UTC) timestamp as IST: ``DD-Month-YYYY HH:MM IST``."""
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(str(iso_str).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(IST).strftime("%d-%B-%Y %H:%M IST")
    except (TypeError, ValueError):
        return ""


# Midpoint (hours) for each estimated-manual-effort bucket collected at
# /opsx-archive step 5 Q1. Used only to derive an approximate time_saved_hours
# figure for productivity_metrics — not an exact measurement.
EFFORT_BUCKET_HOURS: dict[str, float] = {
    "< 2 hours": 1.0,
    "2–4 hours": 3.0,
    "2-4 hours": 3.0,
    "4–8 hours (1 day)": 6.0,
    "4-8 hours (1 day)": 6.0,
    "8–16 hours (2 days)": 12.0,
    "8-16 hours (2 days)": 12.0,
    "16–40 hours (1 week)": 28.0,
    "16-40 hours (1 week)": 28.0,
    "> 40 hours (1+ weeks)": 48.0,
}


def _effort_bucket_to_hours(bucket: str) -> float | None:
    """Map an estimated-manual-effort bucket string to its midpoint in hours."""
    if not bucket:
        return None
    if bucket in EFFORT_BUCKET_HOURS:
        return EFFORT_BUCKET_HOURS[bucket]
    return EFFORT_BUCKET_HOURS.get(bucket.replace("\u2013", "-"))


def _detect_operator_name() -> str:
    """Extract the operator/repo name from ``git remote get-url origin``."""
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=5,
        )
        url = result.stdout.strip()
        if not url:
            return ""
        name = url.rstrip("/").rsplit("/", 1)[-1]
        if name.endswith(".git"):
            name = name[:-4]
        return name
    except Exception:
        return ""


def _read_events(change_dir: Path) -> list[dict[str, Any]]:
    events_file = change_dir / "telemetry" / "events.jsonl"
    if not events_file.exists():
        return []
    events = []
    for line in events_file.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _reconstruct_run(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Build run object from the first run_create event."""
    for ev in events:
        if ev.get("type") == "run_create":
            run: dict[str, Any] = {
                "id": ev.get("id", ""),
                "change_name": ev.get("change_name", ""),
                "jira_key": ev.get("jira_key", ""),
                "branch": ev.get("branch", ""),
                "status": "running",
                "started_at": ev.get("ts", ""),
                "completed_at": None,
                "archived_at": None,
                "total_tokens_in": 0,
                "total_tokens_out": 0,
            }
            break
    else:
        return {}

    for ev in events:
        if ev.get("type") == "run_end":
            run["status"] = ev.get("status", "completed")
            run["completed_at"] = ev.get("ts")
        elif ev.get("type") == "archive_feedback":
            # Marks the true end of the workflow — when the user ran
            # /opsx-archive — distinct from completed_at (set earlier, when
            # the last implementation task finished).
            run["archived_at"] = ev.get("ts")
            run["status"] = "archived"
    return run


def _reconstruct_phases(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build phase objects from phase_start / phase_end / phase_progress events."""
    phases: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    for ev in events:
        etype = ev.get("type", "")
        if etype == "phase_start":
            pid = ev.get("id", "")
            if pid and pid not in phases:
                order.append(pid)
            phases[pid] = {
                "id": pid,
                "run_id": ev.get("run_id", ""),
                "phase_number": ev.get("phase_number", 0),
                "phase_name": ev.get("phase_name", ""),
                "model_id": ev.get("model_id", ""),
                "status": "running",
                "started_at": ev.get("ts", ""),
                "completed_at": None,
                "tokens_in": 0,
                "tokens_out": 0,
                "quality_score": 0,
                "quality_label": "",
                "iteration_count": 1,
                "duration_s": 0.0,
            }
        elif etype == "phase_end":
            pid = ev.get("phase_id", "")
            if pid in phases:
                phases[pid].update({
                    "status": ev.get("status", "passed"),
                    "completed_at": ev.get("ts"),
                    "tokens_in": ev.get("tokens_in", phases[pid]["tokens_in"]),
                    "tokens_out": ev.get("tokens_out", phases[pid]["tokens_out"]),
                    "quality_score": ev.get("quality_score", phases[pid]["quality_score"]),
                    "quality_label": ev.get("quality_label", phases[pid]["quality_label"]),
                    "iteration_count": ev.get("iteration_count", phases[pid]["iteration_count"]),
                })
                if ev.get("duration_s") is not None:
                    phases[pid]["duration_s"] = ev["duration_s"]
        elif etype == "phase_progress":
            pid = ev.get("phase_id", "")
            if pid in phases:
                for key in ("tokens_in", "tokens_out", "quality_score", "quality_label", "iteration_count"):
                    if ev.get(key) is not None:
                        phases[pid][key] = ev[key]
                if ev.get("duration_s") is not None:
                    phases[pid]["duration_s"] = ev["duration_s"]

    result = [phases[pid] for pid in order if pid in phases]

    # Fix #3: Compute duration_s from event timestamps when the filesystem
    # fallback returned 0 or a placeholder.
    for p in result:
        if p.get("started_at") and p.get("completed_at"):
            try:
                t0 = datetime.fromisoformat(str(p["started_at"]).replace("Z", "+00:00"))
                t1 = datetime.fromisoformat(str(p["completed_at"]).replace("Z", "+00:00"))
                event_dur = max(0.0, (t1 - t0).total_seconds())
                if p["duration_s"] in (0.0, 60.0, 300.0) or event_dur > p["duration_s"]:
                    p["duration_s"] = round(event_dur, 1)
            except (TypeError, ValueError):
                pass

    # Fix #5: Auto-close orphan "running" phases when later phases are already
    # passed (the on-artifact-complete hook was likely skipped).
    max_passed = max(
        (p["phase_number"] for p in result if p.get("status") == "passed"),
        default=0,
    )
    for p in result:
        if p.get("status") == "running" and p["phase_number"] < max_passed:
            p["status"] = "passed"
            if not p.get("completed_at"):
                next_phases = [
                    q for q in result
                    if q["phase_number"] > p["phase_number"] and q.get("started_at")
                ]
                if next_phases:
                    p["completed_at"] = next_phases[0]["started_at"]
                    try:
                        t0 = datetime.fromisoformat(str(p["started_at"]).replace("Z", "+00:00"))
                        t1 = datetime.fromisoformat(str(p["completed_at"]).replace("Z", "+00:00"))
                        p["duration_s"] = round(max(0.0, (t1 - t0).total_seconds()), 1)
                    except (TypeError, ValueError):
                        pass

    return result


def _reconstruct_tasks(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build task objects from task_start / task_end events.

    Deduplicates by ``task_id``: when a task is started multiple times (e.g.
    agent retry), keep the entry that reached ``passed`` or, failing that,
    the latest one.  This prevents stale "running" duplicates from inflating
    ``tasks_total``.
    """
    tasks: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    for ev in events:
        etype = ev.get("type", "")
        if etype == "task_start":
            tid = ev.get("id", "")
            if tid and tid not in tasks:
                order.append(tid)
            tasks[tid] = {
                "id": tid,
                "run_id": ev.get("run_id", ""),
                "phase_id": ev.get("phase_id", ""),
                "task_id": ev.get("task_id", ""),
                "task_title": ev.get("task_title", ""),
                "agent_id": ev.get("agent_id", ""),
                "status": "running",
                "started_at": ev.get("ts", ""),
                "completed_at": None,
                "tokens_in": 0,
                "tokens_out": 0,
                "self_correction_loops": 0,
                "attribution": None,
                "metadata": None,
            }
        elif etype == "task_end":
            tpk = ev.get("task_pk", "")
            if tpk in tasks:
                update: dict[str, Any] = {
                    "status": ev.get("status", "passed"),
                    "completed_at": ev.get("ts"),
                    "tokens_in": ev.get("tokens_in", 0),
                    "tokens_out": ev.get("tokens_out", 0),
                    "self_correction_loops": ev.get("self_correction_loops", 0),
                }
                if ev.get("attribution"):
                    update["attribution"] = ev["attribution"]
                if ev.get("metadata"):
                    update["metadata"] = ev["metadata"]
                tasks[tpk].update(update)

    all_tasks = [tasks[tid] for tid in order if tid in tasks]
    return _dedupe_tasks(all_tasks)


def _dedupe_tasks(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep one entry per ``task_id``, preferring passed > completed > latest."""
    by_task_id: dict[str, list[dict[str, Any]]] = {}
    for t in tasks:
        by_task_id.setdefault(t["task_id"], []).append(t)

    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for t in tasks:
        tid = t["task_id"]
        if tid in seen:
            continue
        seen.add(tid)
        candidates = by_task_id[tid]
        passed = [c for c in candidates if c["status"] == "passed"]
        best = passed[-1] if passed else candidates[-1]
        deduped.append(best)
    return deduped


def _collect_log_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract log_event entries."""
    return [
        {
            "id": ev.get("id", ""),
            "ts": ev.get("ts", ""),
            "run_id": ev.get("run_id", ""),
            "task_id": ev.get("task_id"),
            "agent_id": ev.get("agent_id", ""),
            "event_type": ev.get("event_type", ""),
            "message": ev.get("message", ""),
            "metadata_json": ev.get("metadata_json"),
        }
        for ev in events
        if ev.get("type") == "log_event"
    ]


def _compute_global_health(
    run: dict[str, Any],
    phases: list[dict[str, Any]],
    tasks: list[dict[str, Any]],
    change_dir: Path,
) -> dict[str, Any]:
    """Compute global health metrics from in-memory data.

    Token counting uses **phase totals only**.  Phase 5 (code_generation)
    already aggregates task-level tokens via ``on-apply-complete``, so adding
    task tokens on top would double-count.
    """
    total_in = sum(p.get("tokens_in", 0) for p in phases)
    total_out = sum(p.get("tokens_out", 0) for p in phases)
    total_tokens = total_in + total_out
    if total_tokens == 0:
        total_tokens = run.get("total_tokens_in", 0) + run.get("total_tokens_out", 0)

    wall_time = 0.0
    started_at = run.get("started_at", "")
    if started_at:
        try:
            start = datetime.fromisoformat(str(started_at).replace("Z", "+00:00"))
            end_raw = run.get("completed_at")
            if end_raw:
                end = datetime.fromisoformat(str(end_raw).replace("Z", "+00:00"))
            else:
                end = datetime.now(timezone.utc)
            wall_time = max(0.0, (end - start).total_seconds())
        except (TypeError, ValueError):
            pass

    total_phases = len(phases)
    first_pass = sum(
        1 for p in phases
        if p.get("iteration_count", 1) == 1 and p.get("status") == "passed"
    )

    scored_phases = [p for p in phases if p.get("quality_score", 0) > 0]
    compliance = (
        sum(p["quality_score"] for p in scored_phases) / len(scored_phases)
        if scored_phases
        else 0.0
    )
    gate_passing = (first_pass / total_phases * 100) if total_phases > 0 else 100.0
    total_refinement = sum(max(0, p.get("iteration_count", 1) - 1) for p in phases)
    human_rejection = (total_refinement / total_phases * 100) if total_phases > 0 else 0.0

    phase_duration = sum(p.get("duration_s", 0) for p in phases)
    if phase_duration > wall_time:
        wall_time = phase_duration

    tasks_total = len(tasks)
    tasks_passed = sum(1 for t in tasks if t.get("status") == "passed")
    success_rate = (tasks_passed / tasks_total * 100) if tasks_total > 0 else 100.0

    estimated_cost = _estimate_cost(total_in, total_out)

    # Fix #2: populate run.total_tokens_in/out so top-level summary is useful
    run["total_tokens_in"] = total_in
    run["total_tokens_out"] = total_out

    return {
        "total_tokens_consumed": total_tokens,
        "estimated_cost_usd": round(estimated_cost, 4),
        "cumulative_wall_time_s": round(wall_time, 1),
        "compliance_index": round(compliance, 1),
        "gate_passing_rate": round(gate_passing, 1),
        "human_rejection_rate": round(human_rejection, 1),
        "total_refinement_iterations": total_refinement,
        "agent_success_rate": round(success_rate, 1),
        "tasks_passed": tasks_passed,
        "tasks_total": tasks_total,
    }


def _compute_artifact_edits(change_dir: Path) -> dict[str, Any]:
    """Compute artifact edit metrics from filesystem."""
    entries: list[dict[str, Any]] = []

    for artifact_id, (_phase_num, phase_name, _is_last) in ARTIFACT_PHASE_MAP.items():
        artifact_path = change_dir / f"{artifact_id}.md"
        if not artifact_path.exists():
            artifact_path = change_dir / f"{artifact_id}.json"
        if not artifact_path.exists():
            continue
        eval_ref = read_eval_refinement_round(change_dir, artifact_id)
        fb = count_feedback_rounds(change_dir, artifact_id)
        entries.append({
            "artifact_id": artifact_id,
            "phase_name": phase_name,
            "eval_refinements": eval_ref,
            "feedback_rounds": fb,
            "total_edits": eval_ref + fb,
        })

    return {
        "artifacts": entries,
        "total_edits": sum(e["total_edits"] for e in entries),
    }


def _reconstruct_productivity_metrics(
    events: list[dict[str, Any]], wall_time_s: float
) -> dict[str, Any] | None:
    """Build productivity_metrics from the ``archive_feedback`` event.

    ``wall_time_s`` is the run's actual agent wall-clock time
    (``global_health.cumulative_wall_time_s``) — used to derive
    ``time_saved_hours`` from the user's estimated-manual-effort bucket.
    Returns ``None`` when /opsx-archive has not yet recorded feedback.
    """
    archive_ev: dict[str, Any] | None = None
    for ev in events:
        if ev.get("type") == "archive_feedback":
            archive_ev = ev  # keep the latest if recorded more than once

    if archive_ev is None:
        return None

    estimated_manual_effort = archive_ev.get("estimated_manual_effort", "") or ""
    estimated_manual_hours = _effort_bucket_to_hours(estimated_manual_effort)
    actual_wall_time_hours = round(wall_time_s / 3600, 2)

    time_saved_hours = None
    if estimated_manual_hours is not None:
        time_saved_hours = round(estimated_manual_hours - actual_wall_time_hours, 2)

    return {
        "story_points_delivered": archive_ev.get("story_points_delivered"),
        "estimated_manual_effort": estimated_manual_effort,
        "estimated_manual_hours": estimated_manual_hours,
        "actual_wall_time_hours": actual_wall_time_hours,
        "time_saved_hours": time_saved_hours,
        "satisfaction_rating": archive_ev.get("satisfaction_rating"),
        "comments": archive_ev.get("comments", ""),
        "captured_at": archive_ev.get("ts", ""),
        "captured_at_display": _to_ist_display(archive_ev.get("ts", "")),
    }


def _compute_report_status(productivity_metrics: dict[str, Any] | None) -> dict[str, Any]:
    """Explicit completeness flag for metrics-report.json.

    Story points delivered is mandatory (collected by /opsx-archive step 5).
    Until it is present, the report is considered incomplete.
    """
    missing: list[str] = []
    if productivity_metrics is None:
        missing.append("productivity_metrics")
        missing.append("productivity_metrics.story_points_delivered")
    elif productivity_metrics.get("story_points_delivered") is None:
        missing.append("productivity_metrics.story_points_delivered")

    return {
        "complete": len(missing) == 0,
        "missing_fields": missing,
    }


def generate_report(change: str) -> Path:
    """Generate metrics-report.json for a single change.

    Returns the path to the written report.
    """
    from .jira_metadata import enrich_run_metadata, read_jira_report_fields

    change_dir = CHANGES_DIR / change
    events = _read_events(change_dir)

    run = _reconstruct_run(events)
    phases = _reconstruct_phases(events)
    tasks = _reconstruct_tasks(events)
    log_events = _collect_log_events(events)

    if run:
        enrich_run_metadata(run, change_dir)

    if run and run.get("started_at"):
        run["started_at_display"] = _to_ist_display(run["started_at"])
    if run and run.get("archived_at"):
        run["archived_at_display"] = _to_ist_display(run["archived_at"])

    global_health = _compute_global_health(run, phases, tasks, change_dir) if run else {
        "total_tokens_consumed": 0,
        "estimated_cost_usd": 0.0,
        "cumulative_wall_time_s": 0.0,
        "compliance_index": 0.0,
        "gate_passing_rate": 100.0,
        "human_rejection_rate": 0.0,
        "total_refinement_iterations": 0,
        "agent_success_rate": 100.0,
        "tasks_passed": 0,
        "tasks_total": 0,
    }
    artifact_edits = _compute_artifact_edits(change_dir)

    productivity_metrics = _reconstruct_productivity_metrics(
        events, global_health.get("cumulative_wall_time_s", 0.0)
    )
    report_status = _compute_report_status(productivity_metrics)

    jira_fields = read_jira_report_fields(change_dir)

    report: dict[str, Any] = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "operator_name": _detect_operator_name(),
        **jira_fields,
        "run": run,
        "phases": phases,
        "tasks": tasks,
        "events": log_events,
        "global_health": global_health,
        "artifact_edits": artifact_edits,
        "productivity_metrics": productivity_metrics,
        "report_status": report_status,
    }

    report_path = change_dir / "telemetry" / "metrics-report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, default=str) + "\n")
    logger.info("Wrote metrics report: %s", report_path)
    return report_path


def main() -> None:
    """CLI entry point: python -m openspec.telemetry.report --change <name>"""
    import argparse
    parser = argparse.ArgumentParser(description="Generate metrics report for an OpenSpec change")
    parser.add_argument("--change", required=True, help="Change slug (e.g. cm-830)")
    args = parser.parse_args()
    path = generate_report(args.change)
    print(json.dumps({"ok": True, "path": str(path)}))


if __name__ == "__main__":
    main()
