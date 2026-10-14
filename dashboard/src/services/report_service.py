from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import AppConfig
from src.models.event import AgentEvent
from src.models.phase import PhaseExecution
from src.models.run import PipelineRun
from src.models.task import TaskExecution
from src.schemas.event import EventOut
from src.schemas.phase import PhaseOut
from src.schemas.report import RunReportOut
from src.schemas.run import RunOut
from src.schemas.task import TaskOut
from src.services.metrics_service import (
    compute_artifact_edits,
    compute_global_health,
    compute_token_burn,
)


async def build_run_report(
    db: AsyncSession,
    run_id: str,
    cfg: AppConfig,
    *,
    event_limit: int = 500,
) -> RunReportOut:
    run = await db.get(PipelineRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    phases_result = await db.execute(
        select(PhaseExecution)
        .where(PhaseExecution.run_id == run_id)
        .order_by(PhaseExecution.phase_number)
    )
    tasks_result = await db.execute(
        select(TaskExecution)
        .where(TaskExecution.run_id == run_id)
        .order_by(TaskExecution.started_at)
    )
    events_result = await db.execute(
        select(AgentEvent)
        .where(AgentEvent.run_id == run_id)
        .order_by(AgentEvent.timestamp.desc())
        .limit(event_limit)
    )

    return RunReportOut(
        exported_at=datetime.now(timezone.utc),
        run=RunOut.model_validate(run),
        phases=[PhaseOut.model_validate(p) for p in phases_result.scalars().all()],
        tasks=[TaskOut.model_validate(t) for t in tasks_result.scalars().all()],
        events=[EventOut.model_validate(e) for e in events_result.scalars().all()],
        global_health=await compute_global_health(db, run_id, cfg),
        token_burn=await compute_token_burn(db, run_id, cfg),
        artifact_edits=await compute_artifact_edits(db, run_id, cfg),
    )
