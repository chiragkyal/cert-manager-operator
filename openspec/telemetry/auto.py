"""Automatic telemetry hooks for the OpenSpec pipeline.

Wraps key openspec CLI lifecycle events so telemetry is emitted transparently.
After each hook, auto-generates ``metrics-report.json``.

Usage:

    python -m openspec.telemetry.auto on-new    --change cm-830 --jira-key CM-830
    python -m openspec.telemetry.auto on-artifact-complete --change cm-830 --artifact specs --status passed --score 91
    python -m openspec.telemetry.auto on-task-start --change cm-830 --task-id T1_1 --agent API_Agent
    python -m openspec.telemetry.auto on-task-complete --change cm-830 --task-id T1_1 --status passed
    python -m openspec.telemetry.auto on-apply-complete --change cm-830
    python -m openspec.telemetry.auto on-phase-complete --change cm-830 --phase 1 --stage 5
    python -m openspec.telemetry.auto sync --change cm-830
    python -m openspec.telemetry.auto report --change cm-830
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from .change_metrics import (
    ARTIFACT_PHASE_MAP,
    phase5_iteration_count,
    phase5_should_close,
    phase_duration_s,
    phase_iteration_count,
    read_task_refinement_rounds,
)

logger = logging.getLogger(__name__)

CHANGES_DIR = Path("openspec/changes")
STATE_FILE = ".dashboard.json"


def _regenerate_report(change: str) -> None:
    """Re-generate the metrics report after a hook fires."""
    try:
        from .report import generate_report
        generate_report(change)
    except Exception as exc:
        logger.debug("Report generation failed (non-fatal): %s", exc)


def _regenerate_qe_report(change: str) -> None:
    """Re-generate qe-metrics.json after a QE hook fires."""
    try:
        from .qe_metrics import generate_qe_report
        generate_qe_report(change)
    except Exception as exc:
        logger.debug("QE report generation failed (non-fatal): %s", exc)


def _e2e_events_path(change: str) -> Path:
    return CHANGES_DIR / change / "telemetry" / "e2e-events.jsonl"


def _latest_e2e_run_id(change: str) -> str:
    """Best-effort lookup of the most recent e2e_run_start id for this change.

    Used only for traceability on the qe_archive_feedback event — a
    phase-iterative change may have multiple E2E runs by archive time.
    """
    path = _e2e_events_path(change)
    if not path.exists():
        return ""
    run_id = ""
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            if ev.get("type") == "e2e_run_start":
                run_id = ev.get("id", "") or run_id
    except (OSError, json.JSONDecodeError):
        pass
    return run_id


def _state_path(change: str) -> Path:
    return CHANGES_DIR / change / STATE_FILE


def _load_state(change: str) -> dict[str, Any]:
    p = _state_path(change)
    if p.exists():
        return json.loads(p.read_text())
    return {}


def _save_state(change: str, state: dict[str, Any]) -> None:
    p = _state_path(change)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2) + "\n")


def _client(change: str | None = None):
    from .client import TelemetryClient
    return TelemetryClient(change=change)


def _estimate_artifact(change: str, artifact_id: str) -> tuple[int, int]:
    from .tokens import estimate_artifact_tokens
    return estimate_artifact_tokens(CHANGES_DIR / change, artifact_id)


def _estimate_task(change: str, task_id: str) -> tuple[int, int]:
    from .tokens import estimate_task_tokens
    return estimate_task_tokens(CHANGES_DIR / change, task_id)


def _emit_phase_progress(
    change: str,
    state: dict[str, Any],
    phase_key: str,
    client,
    *,
    tokens_in: int = 0,
    tokens_out: int = 0,
    quality_score: float = 0,
    quality_label: str = "",
    iteration_count: int = 1,
    duration_s: float | None = None,
) -> None:
    """Emit a phase_progress event and update cumulative phase state."""
    phases = state.get("phases", {})
    phase_info = phases.get(phase_key)
    if not phase_info or phase_info.get("ended"):
        return

    cum_in = phase_info.get("tokens_in", 0) + tokens_in
    cum_out = phase_info.get("tokens_out", 0) + tokens_out
    phase_info["tokens_in"] = cum_in
    phase_info["tokens_out"] = cum_out

    client.update_phase(
        phase_info["id"],
        tokens_in=cum_in,
        tokens_out=cum_out,
        quality_score=quality_score,
        quality_label=quality_label,
        iteration_count=iteration_count,
        duration_s=duration_s,
    )
    _save_state(change, state)


def _emit_sub_phase_progress(
    change: str,
    state: dict[str, Any],
    sub_key: str,
    client,
    *,
    tokens_in: int = 0,
    tokens_out: int = 0,
    quality_score: float = 0,
    quality_label: str = "",
    iteration_count: int = 1,
    duration_s: float | None = None,
) -> None:
    """Emit a phase_progress event for a plan-phase sub-row."""
    sub_phases = state.get("sub_phases", {})
    sub_info = sub_phases.get(sub_key)
    if not sub_info or sub_info.get("ended"):
        return

    cum_in = sub_info.get("tokens_in", 0) + tokens_in
    cum_out = sub_info.get("tokens_out", 0) + tokens_out
    sub_info["tokens_in"] = cum_in
    sub_info["tokens_out"] = cum_out

    client.update_phase(
        sub_info["id"],
        tokens_in=cum_in,
        tokens_out=cum_out,
        quality_score=quality_score,
        quality_label=quality_label,
        iteration_count=iteration_count,
        duration_s=duration_s,
    )
    _save_state(change, state)


def _out(data: dict[str, Any]) -> None:
    print(json.dumps(data))


def _is_batch_mode(state: dict[str, Any], phase_key: str) -> bool:
    """Check if a phase is running in batch mode."""
    phase_info = state.get("phases", {}).get(phase_key)
    return bool(phase_info and phase_info.get("batch_mode"))


def _set_batch_mode(state: dict[str, Any], phase_key: str) -> None:
    """Mark a phase as running in batch mode."""
    from datetime import datetime, timezone
    phase_info = state.get("phases", {}).get(phase_key)
    if phase_info:
        phase_info["batch_mode"] = True
        phase_info["batch_detected_at"] = datetime.now(timezone.utc).isoformat()


def on_new(args: argparse.Namespace) -> None:
    """Called after a new change directory is created."""
    existing = _load_state(args.change)
    if existing.get("run_id"):
        _out({"ok": True, "run_id": existing["run_id"], "already_exists": True})
        return

    # Read jira metadata if available (enriched by MCP fetch in opsx-new)
    from .jira_metadata import read_jira_metadata
    change_dir = CHANGES_DIR / args.change
    jira_meta = read_jira_metadata(change_dir)

    client = _client(args.change)
    try:
        change_label = f"{args.jira_key} — {args.change}"
        run_id = client.create_run(
            change_name=change_label,
            jira_key=args.jira_key,
            branch=getattr(args, "branch", "") or f"feature/{args.change}",
            metadata=jira_meta if jira_meta else None,
        )
        state: dict[str, Any] = {
            "run_id": run_id,
            "jira_key": args.jira_key,
            "change": args.change,
            "phases": {},
            "tasks": {},
        }
        _save_state(args.change, state)
        _out({"ok": True, "run_id": run_id})
    finally:
        client.close()
    _regenerate_report(args.change)


def _sub_phase_key(stage: int, plan_phase: int) -> str:
    """State key for a plan-phase sub-row under a given stage."""
    return f"{stage}_pp{plan_phase}"


def _ensure_sub_phase(
    change: str,
    state: dict[str, Any],
    run_id: str,
    stage_number: int,
    stage_name: str,
    plan_phase: int,
) -> str:
    """Create a sub-phase row for plan_phase under a stage (idempotent)."""
    sub_key = _sub_phase_key(stage_number, plan_phase)
    sub_phases = state.setdefault("sub_phases", {})
    if sub_key in sub_phases and not sub_phases[sub_key].get("ended"):
        return sub_phases[sub_key]["id"]

    client = _client(change)
    try:
        phase_id = client.start_phase(
            run_id, stage_number, stage_name, plan_phase=plan_phase,
        )
        sub_phases[sub_key] = {
            "id": phase_id,
            "name": stage_name,
            "plan_phase": plan_phase,
            "ended": False,
        }
        _save_state(change, state)
        return phase_id
    finally:
        client.close()


def on_artifact_start(args: argparse.Namespace) -> None:
    """Called when an artifact creation begins."""
    state = _load_state(args.change)
    run_id = state.get("run_id")
    if not run_id:
        _out({"skip": True, "reason": "no run_id"})
        return

    mapping = ARTIFACT_PHASE_MAP.get(args.artifact)
    if not mapping:
        _out({"skip": True, "reason": f"unknown artifact: {args.artifact}"})
        return

    phase_number, phase_name, _ = mapping
    key = str(phase_number)
    phases = state.setdefault("phases", {})
    batch = getattr(args, "batch", False)
    plan_phase = getattr(args, "phase", None)

    if key in phases and not phases[key].get("ended"):
        if batch and not phases[key].get("batch_mode"):
            _set_batch_mode(state, key)
            _save_state(args.change, state)
        _out({"ok": True, "phase_id": phases[key]["id"], "already_running": True})
        if plan_phase is not None:
            _ensure_sub_phase(args.change, state, run_id, phase_number, phase_name, plan_phase)
        return

    client = _client(args.change)
    try:
        phase_id = client.start_phase(run_id, phase_number, phase_name)
        phases[key] = {"id": phase_id, "name": phase_name, "ended": False}
        if batch:
            _set_batch_mode(state, key)
        _save_state(args.change, state)
        _out({"ok": True, "phase_id": phase_id})
    finally:
        client.close()

    if plan_phase is not None:
        _ensure_sub_phase(args.change, state, run_id, phase_number, phase_name, plan_phase)

    _regenerate_report(args.change)


def on_artifact_created(args: argparse.Namespace) -> None:
    """Called when an artifact file is first written to disk (before eval/approval)."""
    state = _load_state(args.change)
    run_id = state.get("run_id")
    if not run_id:
        _out({"skip": True, "reason": "no run_id"})
        return

    mapping = ARTIFACT_PHASE_MAP.get(args.artifact)
    phase_key = str(mapping[0]) if mapping else None
    change_dir = CHANGES_DIR / args.change
    batch = getattr(args, "batch", False) or (phase_key and _is_batch_mode(state, phase_key))

    if batch and phase_key:
        _set_batch_mode(state, phase_key)

    tokens_in, tokens_out = _estimate_artifact(args.change, args.artifact)
    iteration_count = phase_iteration_count(change_dir, mapping[0]) if mapping else 1
    duration_s = phase_duration_s(change_dir, mapping[0]) if mapping else None

    client = _client(args.change)
    try:
        client.log_event(
            run_id=run_id,
            agent_id="Pipeline",
            event_type="state_machine",
            message=f"Artifact '{args.artifact}' created — awaiting eval gate",
        )
        if phase_key and not batch:
            _emit_phase_progress(
                args.change, state, phase_key, client,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                quality_label="artifact_created",
                iteration_count=iteration_count,
                duration_s=duration_s,
            )
        if batch:
            _save_state(args.change, state)
        _out({"ok": True, "tokens_in": tokens_in, "tokens_out": tokens_out, "batch_mode": bool(batch)})
    finally:
        client.close()
    _regenerate_report(args.change)


def on_waiting_approval(args: argparse.Namespace) -> None:
    """Called when an artifact is presented to the user for approval."""
    state = _load_state(args.change)
    run_id = state.get("run_id")
    if not run_id:
        _out({"skip": True, "reason": "no run_id"})
        return

    mapping = ARTIFACT_PHASE_MAP.get(args.artifact)
    phase_key = str(mapping[0]) if mapping else None
    change_dir = CHANGES_DIR / args.change

    iteration_count = phase_iteration_count(change_dir, mapping[0]) if mapping else 1
    duration_s = phase_duration_s(change_dir, mapping[0]) if mapping else None

    score_text = f" (eval score: {args.score}%)" if getattr(args, "score", 0) else ""
    client = _client(args.change)
    try:
        client.log_event(
            run_id=run_id,
            agent_id="Pipeline",
            event_type="state_machine",
            message=f"Artifact '{args.artifact}' ready for approval{score_text} — waiting for human decision",
        )
        if phase_key:
            _emit_phase_progress(
                args.change, state, phase_key, client,
                quality_score=getattr(args, "score", 0) or 0,
                quality_label="awaiting_approval",
                iteration_count=iteration_count,
                duration_s=duration_s,
            )
        _out({"ok": True})
    finally:
        client.close()
    _regenerate_report(args.change)


def on_artifact_complete(args: argparse.Namespace) -> None:
    """Called after an artifact is approved by the user."""
    state = _load_state(args.change)
    mapping = ARTIFACT_PHASE_MAP.get(args.artifact)
    if not mapping:
        _out({"skip": True, "reason": f"unknown artifact: {args.artifact}"})
        return

    phase_number, phase_name, is_last = mapping
    key = str(phase_number)
    phases = state.get("phases", {})
    phase_info = phases.get(key)

    if not phase_info:
        _out({"skip": True, "reason": f"phase {key} not started"})
        return

    run_id = state.get("run_id", "")
    change_dir = CHANGES_DIR / args.change
    batch = getattr(args, "batch", False) or _is_batch_mode(state, key)
    iteration_count = phase_iteration_count(change_dir, phase_number)
    duration_s = phase_duration_s(change_dir, phase_number)

    if batch:
        from .tokens import estimate_artifact_phase_tokens
        cum_in, cum_out = estimate_artifact_phase_tokens(change_dir, phase_number)
    else:
        tokens_in, tokens_out = _estimate_artifact(args.change, args.artifact)
        cum_in = phase_info.get("tokens_in", 0) + tokens_in
        cum_out = phase_info.get("tokens_out", 0) + tokens_out

    status_verb = "approved" if args.status == "passed" else "rejected"
    client = _client(args.change)
    try:
        client.log_event(
            run_id=run_id,
            agent_id="Pipeline",
            event_type="state_machine",
            message=f"Human {status_verb} artifact '{args.artifact}'",
        )
        client.log_event(
            run_id=run_id,
            agent_id="Pipeline",
            event_type="state_machine",
            message=f"Artifact '{args.artifact}' completed with status: {args.status}",
        )

        if is_last or args.status == "failed":
            client.end_phase(
                phase_info["id"],
                status="passed" if args.status == "passed" else "failed",
                quality_score=getattr(args, "score", 0) or 0,
                quality_label=getattr(args, "label", "") or "",
                tokens_in=cum_in,
                tokens_out=cum_out,
                iteration_count=iteration_count,
                duration_s=duration_s,
                batch_mode=batch,
            )
            phases[key]["ended"] = True
            plan_phase = getattr(args, "phase", None)
            if plan_phase is not None:
                sub_key = _sub_phase_key(phase_number, plan_phase)
                sub_phases = state.get("sub_phases", {})
                sub_info = sub_phases.get(sub_key)
                if sub_info and not sub_info.get("ended"):
                    client.end_phase(
                        sub_info["id"],
                        status="passed" if args.status == "passed" else "failed",
                        quality_label=getattr(args, "label", "") or f"plan_phase_{plan_phase}_complete",
                        tokens_in=sub_info.get("tokens_in", 0),
                        tokens_out=sub_info.get("tokens_out", 0),
                    )
                    sub_info["ended"] = True
            _save_state(args.change, state)
            _out({"ok": True, "phase_ended": True, "tokens_in": cum_in, "tokens_out": cum_out, "batch_mode": batch})
        else:
            if not batch:
                phases[key]["tokens_in"] = cum_in
                phases[key]["tokens_out"] = cum_out
                client.update_phase(
                    phase_info["id"],
                    tokens_in=cum_in,
                    tokens_out=cum_out,
                    quality_score=getattr(args, "score", 0) or 0,
                    quality_label=getattr(args, "label", "") or "",
                    iteration_count=iteration_count,
                    duration_s=duration_s,
                )
            _save_state(args.change, state)
            _out({"ok": True, "phase_ended": False, "tokens_in": cum_in, "tokens_out": cum_out, "batch_mode": batch})
    finally:
        client.close()
    _regenerate_report(args.change)


def on_apply_start(args: argparse.Namespace) -> None:
    """Called when the task loop begins (phase 5)."""
    state = _load_state(args.change)
    run_id = state.get("run_id")
    if not run_id:
        _out({"skip": True, "reason": "no run_id"})
        return

    batch = getattr(args, "batch", False)
    plan_phase = getattr(args, "phase", None)
    phases = state.setdefault("phases", {})

    if "5" in phases and phases["5"].get("ended"):
        _out({"ok": True, "phase_id": phases["5"]["id"], "already_completed": True})
        return
    if "5" in phases and not phases["5"].get("ended"):
        if batch and not phases["5"].get("batch_mode"):
            _set_batch_mode(state, "5")
            _save_state(args.change, state)
        _out({"ok": True, "phase_id": phases["5"]["id"], "already_running": True})
        if plan_phase is not None:
            _ensure_sub_phase(args.change, state, run_id, 5, "code_generation", plan_phase)
        return

    client = _client(args.change)
    try:
        phase_id = client.start_phase(run_id, 5, "code_generation")
        phases["5"] = {"id": phase_id, "name": "code_generation", "ended": False}
        if batch:
            _set_batch_mode(state, "5")
        _save_state(args.change, state)
        _out({"ok": True, "phase_id": phase_id})
    finally:
        client.close()

    if plan_phase is not None:
        _ensure_sub_phase(args.change, state, run_id, 5, "code_generation", plan_phase)

    _regenerate_report(args.change)


def on_task_start(args: argparse.Namespace) -> None:
    """Called before each task execution."""
    state = _load_state(args.change)
    run_id = state.get("run_id")
    if not run_id:
        _out({"skip": True, "reason": "no run_id"})
        return

    plan_phase = getattr(args, "phase", None)

    # Use sub-phase id when in phase-iterative mode, else parent stage 5
    if plan_phase is not None:
        sub_key = _sub_phase_key(5, plan_phase)
        sub_info = state.get("sub_phases", {}).get(sub_key)
        phase_id = sub_info["id"] if sub_info else ""
    else:
        phase_info = state.get("phases", {}).get("5")
        phase_id = phase_info["id"] if phase_info else ""

    client = _client(args.change)
    try:
        task_pk = client.start_task(
            run_id=run_id,
            phase_id=phase_id,
            task_id=args.task_id,
            task_title=getattr(args, "title", "") or "",
            agent_id=getattr(args, "agent", "") or "",
        )
        tasks = state.setdefault("tasks", {})
        tasks[args.task_id] = task_pk
        _save_state(args.change, state)
        _out({"ok": True, "task_pk": task_pk})
    finally:
        client.close()
    _regenerate_report(args.change)


def on_task_complete(args: argparse.Namespace) -> None:
    """Called after a task is approved."""
    state = _load_state(args.change)
    tasks = state.get("tasks", {})
    task_pk = tasks.get(args.task_id)

    if not task_pk:
        _out({"skip": True, "reason": f"task {args.task_id} not tracked"})
        return

    batch = getattr(args, "batch", False) or _is_batch_mode(state, "5")
    if batch:
        _set_batch_mode(state, "5")

    plan_phase = getattr(args, "phase", None)
    loops = read_task_refinement_rounds(CHANGES_DIR / args.change, args.task_id)

    metadata: dict[str, Any] | None = None
    raw_meta = getattr(args, "metadata", None)
    if raw_meta:
        try:
            metadata = json.loads(raw_meta)
        except (json.JSONDecodeError, TypeError):
            logger.warning("Invalid --metadata JSON for task %s: %s", args.task_id, raw_meta)

    client = _client(args.change)
    try:
        if batch:
            client.end_task(
                task_pk,
                status=args.status,
                tokens_in=0,
                tokens_out=0,
                cost_usd=0,
                self_correction_loops=loops,
                attribution="phase_aggregate",
                metadata=metadata,
            )
            run_id = state.get("run_id", "")
            client.log_event(
                run_id=run_id,
                agent_id="Pipeline",
                event_type="state_machine",
                message=f"Task {args.task_id} completed (batch mode — tokens attributed at phase level)",
            )
            _save_state(args.change, state)
            _out({"ok": True, "task_pk": task_pk, "tokens_in": 0, "tokens_out": 0, "batch_mode": True})
        else:
            tokens_in, tokens_out = _estimate_task(args.change, args.task_id)
            client.end_task(
                task_pk,
                status=args.status,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                cost_usd=0,
                self_correction_loops=loops,
                metadata=metadata,
            )
            # Emit progress on the sub-phase when in phase-iterative mode
            if plan_phase is not None:
                sub_key = _sub_phase_key(5, plan_phase)
                sub_info = state.get("sub_phases", {}).get(sub_key)
                if sub_info and not sub_info.get("ended"):
                    _emit_sub_phase_progress(
                        args.change, state, sub_key, client,
                        tokens_in=tokens_in,
                        tokens_out=tokens_out,
                        quality_label=f"task_{args.task_id}_{args.status}",
                    )
            # Always update the parent stage 5 progress too
            phase_info = state.get("phases", {}).get("5")
            if phase_info and not phase_info.get("ended"):
                _emit_phase_progress(
                    args.change, state, "5", client,
                    tokens_in=tokens_in,
                    tokens_out=tokens_out,
                    quality_label=f"task_{args.task_id}_{args.status}",
                )
            _out({"ok": True, "task_pk": task_pk, "tokens_in": tokens_in, "tokens_out": tokens_out})
    finally:
        client.close()
    _regenerate_report(args.change)


def _detect_batch_from_tasks(change: str, state: dict[str, Any]) -> bool:
    """Auto-detect batch mode when --batch was not passed explicitly.

    If 2+ tasks were completed and all have near-identical per-task estimates
    (within 5%), the tokens were almost certainly from a shared session.
    """
    task_ids = list(state.get("tasks", {}).keys())
    if len(task_ids) < 2:
        return False
    estimates = [_estimate_task(change, tid)[0] for tid in task_ids]
    if not estimates or estimates[0] == 0:
        return False
    ref = estimates[0]
    return all(abs(e - ref) / ref <= 0.05 for e in estimates[1:])


def on_phase_complete(args: argparse.Namespace) -> None:
    """Called when a plan phase finishes in phase-iterative mode.

    Ends the sub-phase row for the given plan_phase under the specified stage.
    """
    state = _load_state(args.change)
    plan_phase = args.phase
    stage = getattr(args, "stage", 5)
    sub_key = _sub_phase_key(stage, plan_phase)
    sub_phases = state.get("sub_phases", {})
    sub_info = sub_phases.get(sub_key)

    if not sub_info:
        _out({"skip": True, "reason": f"sub-phase {sub_key} not tracked"})
        return

    if sub_info.get("ended"):
        _out({"ok": True, "already_ended": True})
        return

    pr_raised = getattr(args, "pr_raised", "false") == "true"
    label = getattr(args, "label", "") or f"plan_phase_{plan_phase}_complete"
    if pr_raised:
        label = f"{label} (PR raised)"

    client = _client(args.change)
    try:
        client.end_phase(
            sub_info["id"],
            status="passed",
            quality_label=label,
            tokens_in=sub_info.get("tokens_in", 0),
            tokens_out=sub_info.get("tokens_out", 0),
        )
        sub_info["ended"] = True
        _save_state(args.change, state)
        _out({"ok": True, "sub_phase_ended": True, "plan_phase": plan_phase})
    finally:
        client.close()
    _regenerate_report(args.change)


def on_apply_complete(args: argparse.Namespace) -> None:
    """Called after all tasks are approved (phase 5 done)."""
    state = _load_state(args.change)
    phases = state.get("phases", {})
    phase_info = phases.get("5")

    if not phase_info:
        _out({"skip": True, "reason": "phase 5 not tracked"})
        return

    change_dir = CHANGES_DIR / args.change
    batch = _is_batch_mode(state, "5")

    if not batch and _detect_batch_from_tasks(args.change, state):
        batch = True
        _set_batch_mode(state, "5")

    if batch:
        from .tokens import estimate_phase5_tokens
        total_tokens_in, total_tokens_out = estimate_phase5_tokens(change_dir)
    else:
        total_tokens_in = phase_info.get("tokens_in", 0)
        total_tokens_out = phase_info.get("tokens_out", 0)
        if total_tokens_in == 0 and total_tokens_out == 0:
            for task_id in state.get("tasks", {}):
                ti, to = _estimate_task(args.change, task_id)
                total_tokens_in += ti
                total_tokens_out += to

    run_id = state.get("run_id", "")
    iteration_count = phase5_iteration_count(change_dir)
    should_close, label = phase5_should_close(change_dir)
    quality_label = getattr(args, "label", "") or (label if should_close else "all tasks approved")
    if batch and "batch" not in quality_label:
        quality_label = f"batch: {quality_label}"

    client = _client(args.change)
    try:
        if batch:
            client.log_event(
                run_id=run_id,
                agent_id="Pipeline",
                event_type="state_machine",
                message="Phase 5 completing in batch mode — tokens estimated at phase level",
            )
        client.end_phase(
            phase_info["id"],
            status="passed",
            quality_label=quality_label,
            tokens_in=total_tokens_in,
            tokens_out=total_tokens_out,
            iteration_count=iteration_count,
            batch_mode=batch,
        )
        phases["5"]["ended"] = True

        client.end_run(run_id, status="completed")
        _save_state(args.change, state)
        _out({"ok": True, "tokens_in": total_tokens_in, "tokens_out": total_tokens_out, "batch_mode": batch})
    finally:
        client.close()
    _regenerate_report(args.change)


def sync(args: argparse.Namespace) -> None:
    """Sync filesystem state — re-scan artifacts and update phases."""
    state = _load_state(args.change)
    run_id = state.get("run_id")
    if not run_id:
        _out({"skip": True, "reason": "no run_id — run on-new first"})
        return

    change_dir = CHANGES_DIR / args.change
    updated = []

    for artifact_id, (phase_number, phase_name, is_last) in ARTIFACT_PHASE_MAP.items():
        artifact_path = change_dir / f"{artifact_id}.md"
        if not artifact_path.exists():
            artifact_path = change_dir / f"{artifact_id}.json"
        if not artifact_path.exists():
            continue

        key = str(phase_number)
        phases = state.setdefault("phases", {})
        if key in phases and phases[key].get("ended"):
            continue

        tokens_in, tokens_out = _estimate_artifact(args.change, artifact_id)

        client = _client(args.change)
        try:
            if key not in phases:
                phase_id = client.start_phase(run_id, phase_number, phase_name)
                phases[key] = {"id": phase_id, "name": phase_name, "ended": False}

            if is_last:
                eval_path = change_dir / "eval-results" / f"{artifact_id}.yaml"
                score = 0
                if eval_path.exists():
                    import yaml
                    eval_data = yaml.safe_load(eval_path.read_text()) or {}
                    score = eval_data.get("overall_score", 0)

                iteration_count = phase_iteration_count(change_dir, phase_number)
                duration_s = phase_duration_s(change_dir, phase_number)

                client.end_phase(
                    phases[key]["id"],
                    status="passed",
                    quality_score=score,
                    tokens_in=tokens_in,
                    tokens_out=tokens_out,
                    iteration_count=iteration_count,
                    duration_s=duration_s,
                )
                phases[key]["ended"] = True
                updated.append(f"phase {key} ({phase_name})")
        finally:
            client.close()

    phases = state.setdefault("phases", {})
    if not phases.get("5", {}).get("ended"):
        should_close, label = phase5_should_close(change_dir)

        if should_close or (change_dir / "tasks.md").exists():
            if "5" not in phases:
                client = _client(args.change)
                try:
                    phase_id = client.start_phase(run_id, 5, "code_generation")
                    phases["5"] = {"id": phase_id, "name": "code_generation", "ended": False}
                except Exception:
                    pass
                finally:
                    client.close()

            if should_close and "5" in phases and not phases["5"].get("ended"):
                from .tokens import estimate_phase5_tokens

                total_in, total_out = estimate_phase5_tokens(change_dir)
                iteration_count = phase5_iteration_count(change_dir)

                client = _client(args.change)
                try:
                    client.end_phase(
                        phases["5"]["id"],
                        status="passed",
                        quality_label=label,
                        tokens_in=total_in,
                        tokens_out=total_out,
                        iteration_count=iteration_count,
                    )
                    phases["5"]["ended"] = True
                    updated.append("phase 5 (code_generation)")

                    client.end_run(run_id, status="completed")
                    updated.append("run completed")
                except Exception:
                    pass
                finally:
                    client.close()

    _save_state(args.change, state)
    _out({"ok": True, "updated": updated})
    _regenerate_report(args.change)


def on_archive_feedback(args: argparse.Namespace) -> None:
    """Called by /opsx-archive to record mandatory archive-time feedback.

    Captures story points delivered, the estimated-manual-effort bucket,
    satisfaction rating, and comments — the same answers written to
    user-feedback.md — as a structured telemetry event. Must run BEFORE the
    change directory is moved to openspec/changes/archive/, so the event and
    the regenerated metrics-report.json are archived with the rest of the
    change. The event's timestamp becomes the run's ``archived_at``.
    """
    state = _load_state(args.change)
    run_id = state.get("run_id")
    if not run_id:
        _out({"skip": True, "reason": "no run_id"})
        return

    story_points = getattr(args, "story_points", None)
    client = _client(args.change)
    try:
        client.record_archive_feedback(
            run_id,
            story_points_delivered=story_points,
            estimated_manual_effort=getattr(args, "manual_effort", "") or "",
            satisfaction_rating=getattr(args, "satisfaction", None),
            comments=getattr(args, "comments", "") or "",
        )
        _out({"ok": True, "story_points_delivered": story_points})
    finally:
        client.close()
    _regenerate_report(args.change)


def on_qe_archive_feedback(args: argparse.Namespace) -> None:
    """Called by /opsx-archive to record QE feedback — ONLY when this change
    had at least one E2E run (detected by the presence of
    ``telemetry/e2e-events.jsonl``). Unlike development feedback, this is
    NOT collected inside ``/opsx-e2e`` itself — it fires once, at archive
    time, alongside the mandatory development feedback questions. Skips
    silently (not an error) when no E2E run exists for this change.
    """
    if not _e2e_events_path(args.change).exists():
        _out({"skip": True, "reason": "no e2e run for this change"})
        return

    from .qe_events import QETelemetryClient

    story_points = getattr(args, "story_points", None)
    client = QETelemetryClient(args.change)
    client.record_archive_feedback(
        run_id=_latest_e2e_run_id(args.change),
        story_points_delivered=story_points,
        estimated_manual_effort=getattr(args, "manual_effort", "") or "",
        satisfaction_rating=getattr(args, "satisfaction", None),
        user_feedback=getattr(args, "comments", "") or "",
    )
    _out({"ok": True, "story_points_delivered": story_points})
    _regenerate_qe_report(args.change)


def report_cmd(args: argparse.Namespace) -> None:
    """On-demand report regeneration."""
    from .report import generate_report
    path = generate_report(args.change)
    _out({"ok": True, "path": str(path)})


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="openspec-telemetry",
        description="Automatic telemetry hooks for OpenSpec pipeline",
    )
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("on-new", help="Register a new pipeline run")
    r.add_argument("--change", required=True)
    r.add_argument("--jira-key", required=True)
    r.add_argument("--branch", default="")

    sa = sub.add_parser("on-artifact-start", help="Signal artifact creation started")
    sa.add_argument("--change", required=True)
    sa.add_argument("--artifact", required=True)
    sa.add_argument("--batch", action="store_true", help="Batch mode — skip per-artifact token attribution")
    sa.add_argument("--phase", type=int, default=None, help="Plan phase number (phase-iterative mode)")

    acr = sub.add_parser("on-artifact-created", help="Signal artifact file written to disk")
    acr.add_argument("--change", required=True)
    acr.add_argument("--artifact", required=True)
    acr.add_argument("--batch", action="store_true", help="Batch mode — skip token-bearing phase_progress")
    acr.add_argument("--phase", type=int, default=None, help="Plan phase number (phase-iterative mode)")

    wa = sub.add_parser("on-waiting-approval", help="Signal artifact presented for user approval")
    wa.add_argument("--change", required=True)
    wa.add_argument("--artifact", required=True)
    wa.add_argument("--score", type=float, default=0)
    wa.add_argument("--phase", type=int, default=None, help="Plan phase number (phase-iterative mode)")

    ac = sub.add_parser("on-artifact-complete", help="Signal artifact approved/rejected")
    ac.add_argument("--change", required=True)
    ac.add_argument("--artifact", required=True)
    ac.add_argument("--status", required=True, choices=["passed", "failed"])
    ac.add_argument("--score", type=float, default=0)
    ac.add_argument("--label", default="")
    ac.add_argument("--iterations", type=int, default=1)
    ac.add_argument("--batch", action="store_true", help="Batch mode — use phase-level token estimate")
    ac.add_argument("--phase", type=int, default=None, help="Plan phase number (phase-iterative mode)")

    ap = sub.add_parser("on-apply-start", help="Signal task loop started")
    ap.add_argument("--change", required=True)
    ap.add_argument("--batch", action="store_true", help="Batch mode — skip per-task token attribution")
    ap.add_argument("--phase", type=int, default=None, help="Plan phase number (phase-iterative mode)")

    ts = sub.add_parser("on-task-start", help="Signal task execution started")
    ts.add_argument("--change", required=True)
    ts.add_argument("--task-id", required=True)
    ts.add_argument("--title", default="")
    ts.add_argument("--agent", default="")
    ts.add_argument("--phase", type=int, default=None, help="Plan phase number (phase-iterative mode)")

    tc = sub.add_parser("on-task-complete", help="Signal task approved/failed")
    tc.add_argument("--change", required=True)
    tc.add_argument("--task-id", required=True)
    tc.add_argument("--status", required=True, choices=["passed", "failed"])
    tc.add_argument("--loops", type=int, default=0)
    tc.add_argument("--batch", action="store_true", help="Batch mode — zero-token task end, phase-level attribution")
    tc.add_argument("--phase", type=int, default=None, help="Plan phase number (phase-iterative mode)")
    tc.add_argument("--metadata", default=None, help='JSON string with verification/test metadata, e.g. \'{"build_status":"passed","test_status":"passed","verify_status":"passed"}\'')

    apc = sub.add_parser("on-apply-complete", help="Signal all tasks done, end phase 5 + run")
    apc.add_argument("--change", required=True)
    apc.add_argument("--label", default="")
    apc.add_argument("--phase", type=int, default=None, help="Plan phase number (phase-iterative mode)")

    pc = sub.add_parser("on-phase-complete", help="Signal a plan phase completed (phase-iterative mode)")
    pc.add_argument("--change", required=True)
    pc.add_argument("--phase", type=int, required=True, help="Plan phase number that completed")
    pc.add_argument("--stage", type=int, default=5, help="Stage number (4=subtask_creation, 5=code_generation)")
    pc.add_argument("--label", default="")
    pc.add_argument("--pr-raised", choices=["true", "false"], default="false")

    sy = sub.add_parser("sync", help="Sync filesystem state to telemetry")
    sy.add_argument("--change", required=True)

    af = sub.add_parser(
        "on-archive-feedback",
        help="Record mandatory archive-time feedback (story points, time savings, satisfaction, comments)",
    )
    af.add_argument("--change", required=True)
    af.add_argument(
        "--story-points", type=float, default=None,
        help="Story points delivered for this ticket (mandatory per /opsx-archive guardrail)",
    )
    af.add_argument(
        "--manual-effort", default="",
        help="Estimated manual-effort bucket, e.g. '4-8 hours (1 day)'",
    )
    af.add_argument("--satisfaction", type=int, default=None, help="Satisfaction rating 1-5")
    af.add_argument("--comments", default="", help="Free-text comments on this run")

    qaf = sub.add_parser(
        "on-qe-archive-feedback",
        help="Record QE feedback at archive time — only if this change had an E2E run (skips silently otherwise)",
    )
    qaf.add_argument("--change", required=True)
    qaf.add_argument(
        "--story-points", type=float, default=None,
        help="QE story points delivered (mandatory when this change had an E2E run)",
    )
    qaf.add_argument(
        "--manual-effort", default="",
        help="Estimated manual-effort bucket, e.g. '4-8 hours (1 day)' — same buckets as dev workflow",
    )
    qaf.add_argument("--satisfaction", type=int, default=None, help="Satisfaction rating 1-5")
    qaf.add_argument("--comments", default="", help="Free-text feedback on the E2E/QE workflow")

    rp = sub.add_parser("report", help="Regenerate metrics-report.json")
    rp.add_argument("--change", required=True)

    return p


_DISPATCH = {
    "on-new": on_new,
    "on-artifact-start": on_artifact_start,
    "on-artifact-created": on_artifact_created,
    "on-waiting-approval": on_waiting_approval,
    "on-artifact-complete": on_artifact_complete,
    "on-apply-start": on_apply_start,
    "on-task-start": on_task_start,
    "on-task-complete": on_task_complete,
    "on-phase-complete": on_phase_complete,
    "on-apply-complete": on_apply_complete,
    "sync": sync,
    "on-archive-feedback": on_archive_feedback,
    "on-qe-archive-feedback": on_qe_archive_feedback,
    "report": report_cmd,
}


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    handler = _DISPATCH.get(args.command)
    if not handler:
        parser.print_help()
        sys.exit(1)
    try:
        handler(args)
    except Exception as exc:
        print(
            json.dumps({"warning": f"Auto-telemetry unavailable: {exc}"}),
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
