from __future__ import annotations

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from src.core.dependencies import DBSession
from src.core.sse import sse_broker
from src.models.phase import PhaseExecution
from src.schemas.phase import PhaseCreate, PhaseUpdate, PhaseOut

router = APIRouter(tags=["phases"])


@router.get("/runs/{run_id}/phases", response_model=list[PhaseOut])
async def list_phases(run_id: str, db: DBSession):
    result = await db.execute(
        select(PhaseExecution)
        .where(PhaseExecution.run_id == run_id)
        .order_by(PhaseExecution.phase_number, PhaseExecution.plan_phase.asc().nullsfirst())
    )
    return [PhaseOut.model_validate(p) for p in result.scalars().all()]


@router.post("/phases", response_model=PhaseOut, status_code=201)
async def create_phase(payload: PhaseCreate, db: DBSession):
    phase = PhaseExecution(
        run_id=payload.run_id,
        phase_number=payload.phase_number,
        phase_name=payload.phase_name,
        model_id=payload.model_id,
        plan_phase=payload.plan_phase,
    )
    db.add(phase)
    await db.commit()
    await db.refresh(phase)
    return PhaseOut.model_validate(phase)


@router.patch("/phases/{phase_id}", response_model=PhaseOut)
async def update_phase(phase_id: str, payload: PhaseUpdate, db: DBSession):
    phase = await db.get(PhaseExecution, phase_id)
    if phase is None:
        raise HTTPException(status_code=404, detail="Phase not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(phase, field, value)
    await db.commit()
    await db.refresh(phase)

    await sse_broker.publish(
        "phase_update",
        {
            "phase_name": phase.phase_name.value,
            "status": phase.status.value,
            "iteration_count": phase.iteration_count,
            "tokens_in": phase.tokens_in,
            "tokens_out": phase.tokens_out,
            "quality_score": phase.quality_score,
            "quality_label": phase.quality_label,
            "plan_phase": phase.plan_phase,
        },
        run_id=phase.run_id,
    )

    return PhaseOut.model_validate(phase)
