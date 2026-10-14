from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from pathlib import Path

from src.core.config import AppConfig
from src.models.phase import PhaseExecution, PhaseStatus
from src.models.run import PipelineRun
from src.models.task import TaskExecution, TaskStatus
from src.schemas.metrics import (
    ArtifactEditEntry,
    ArtifactEditsOut,
    GlobalHealthMetrics,
    TokenBurnEntry,
    TokenBurnOut,
)
from src.core.paths import get_change_dir
from openspec.telemetry.change_metrics import (
    ARTIFACT_PHASE_MAP,
    count_feedback_rounds,
    read_eval_refinement_round,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    """Treat naive DB timestamps as UTC (SQLite stores UTC without tzinfo)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def compute_global_health(
    db: AsyncSession,
    run_id: str,
    cfg: AppConfig,
) -> GlobalHealthMetrics:
    run = await db.get(PipelineRun, run_id)
    if run is None:
        return GlobalHealthMetrics(
            total_tokens_consumed=0,
            total_run_cost_usd=0.0,
            cumulative_wall_time_s=0.0,
            compliance_index=cfg.fallbacks.default_compliance_index,
            gate_passing_rate=cfg.fallbacks.default_gate_pass_rate,
            human_rejection_rate=0.0,
            total_refinement_iterations=0,
            agent_success_rate=cfg.fallbacks.default_agent_success_rate,
            tasks_passed=0,
            tasks_total=0,
        )

    wall_time = 0.0
    if run.started_at:
        start = _as_utc(run.started_at)
        end = _as_utc(run.completed_at) if run.completed_at else _utc_now()
        wall_time = max(0.0, (end - start).total_seconds())

    phases_q = await db.execute(
        select(PhaseExecution).where(PhaseExecution.run_id == run_id)
    )
    phases = phases_q.scalars().all()

    phase_tokens_in = sum(p.tokens_in for p in phases)
    phase_tokens_out = sum(p.tokens_out for p in phases)
    total_tokens = phase_tokens_in + phase_tokens_out
    if total_tokens == 0:
        total_tokens = run.total_tokens_in + run.total_tokens_out

    total_phases = len(phases)
    first_pass = sum(1 for p in phases if p.iteration_count == 1 and p.status == PhaseStatus.passed)
    gate_passing = (first_pass / total_phases * 100) if total_phases > 0 else cfg.fallbacks.default_gate_pass_rate

    scored_phases = [p for p in phases if p.quality_score > 0]
    compliance = (
        (sum(p.quality_score for p in scored_phases) / len(scored_phases))
        if scored_phases
        else cfg.fallbacks.default_compliance_index
    )
    total_refinement = sum(max(0, p.iteration_count - 1) for p in phases)
    human_rejection = (total_refinement / total_phases * 100) if total_phases > 0 else 0.0

    phase_duration = sum(p.duration_s for p in phases if p.duration_s)
    if phase_duration > wall_time:
        wall_time = phase_duration

    # Agent success rate: tasks passed / tasks total
    tasks_q = await db.execute(
        select(TaskExecution).where(TaskExecution.run_id == run_id)
    )
    tasks = tasks_q.scalars().all()
    tasks_total = len(tasks)
    tasks_passed = sum(1 for t in tasks if t.status == TaskStatus.passed)
    success_rate = (tasks_passed / tasks_total * 100) if tasks_total > 0 else cfg.fallbacks.default_agent_success_rate

    cost = run.total_cost_usd
    if cost == 0 and total_tokens > 0:
        default_cost = cfg.metrics.cost_for_model("default")
        cost = (phase_tokens_in * default_cost.input + phase_tokens_out * default_cost.output) / 1_000_000

    task_cost = sum(t.cost_usd for t in tasks)
    if task_cost > cost:
        cost = task_cost

    if run.total_tokens_in == 0 and total_tokens > 0:
        run.total_tokens_in = phase_tokens_in
        run.total_tokens_out = phase_tokens_out
        run.total_cost_usd = cost
        await db.commit()

    return GlobalHealthMetrics(
        total_tokens_consumed=total_tokens,
        total_run_cost_usd=round(cost, 4),
        cumulative_wall_time_s=wall_time,
        compliance_index=round(compliance, 1),
        gate_passing_rate=round(gate_passing, 1),
        human_rejection_rate=round(human_rejection, 1),
        total_refinement_iterations=total_refinement,
        agent_success_rate=round(success_rate, 1),
        tasks_passed=tasks_passed,
        tasks_total=tasks_total,
    )


async def compute_token_burn(
    db: AsyncSession,
    run_id: str,
    cfg: AppConfig,
) -> TokenBurnOut:
    result = await db.execute(
        select(
            TaskExecution.agent_id,
            func.sum(TaskExecution.tokens_in + TaskExecution.tokens_out).label("tokens"),
            func.sum(TaskExecution.cost_usd).label("cost"),
        )
        .where(TaskExecution.run_id == run_id)
        .where(TaskExecution.token_attribution.is_(None))
        .group_by(TaskExecution.agent_id)
        .order_by(func.sum(TaskExecution.tokens_in + TaskExecution.tokens_out).desc())
    )
    rows = result.all()

    entries = [
        TokenBurnEntry(agent_id=row.agent_id or "Unknown Agent", tokens=int(row.tokens or 0), cost_usd=float(row.cost or 0.0))
        for row in rows
    ]

    default_cost = cfg.metrics.cost_for_model("default")
    for entry in entries:
        if entry.cost_usd == 0 and entry.tokens > 0:
            est_in = int(entry.tokens * 0.4)
            est_out = entry.tokens - est_in
            entry.cost_usd = round(
                (est_in * default_cost.input + est_out * default_cost.output) / 1_000_000, 4
            )

    total_tokens = sum(e.tokens for e in entries)
    total_cost = sum(e.cost_usd for e in entries)

    return TokenBurnOut(entries=entries, total_tokens=total_tokens, total_cost_usd=total_cost)


async def compute_artifact_edits(
    db: AsyncSession,
    run_id: str,
    cfg: AppConfig,
) -> ArtifactEditsOut:
    run = await db.get(PipelineRun, run_id)
    if run is None:
        return ArtifactEditsOut(artifacts=[], total_edits=0)

    change_slug = run.change_name.split(" — ", 1)[-1] if " — " in run.change_name else run.change_name
    change_dir = get_change_dir(cfg, change_slug)
    if not change_dir.is_dir():
        return ArtifactEditsOut(artifacts=[], total_edits=0)

    entries: list[ArtifactEditEntry] = []
    for artifact_id, (_phase_num, phase_name, _is_last) in ARTIFACT_PHASE_MAP.items():
        artifact_path = change_dir / f"{artifact_id}.md"
        if not artifact_path.exists():
            artifact_path = change_dir / f"{artifact_id}.json"
        if not artifact_path.exists():
            continue
        eval_ref = read_eval_refinement_round(change_dir, artifact_id)
        fb = count_feedback_rounds(change_dir, artifact_id)
        entries.append(
            ArtifactEditEntry(
                artifact_id=artifact_id,
                phase_name=phase_name,
                eval_refinements=eval_ref,
                feedback_rounds=fb,
                total_edits=eval_ref + fb,
            )
        )

    return ArtifactEditsOut(
        artifacts=entries,
        total_edits=sum(e.total_edits for e in entries),
    )