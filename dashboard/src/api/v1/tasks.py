from __future__ import annotations

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from src.core.dependencies import DBSession
from src.models.task import TaskExecution
from src.schemas.task import TaskCreate, TaskUpdate, TaskOut

router = APIRouter(tags=["tasks"])


@router.get("/runs/{run_id}/tasks", response_model=list[TaskOut])
async def list_tasks(run_id: str, db: DBSession):
    result = await db.execute(
        select(TaskExecution)
        .where(TaskExecution.run_id == run_id)
        .order_by(TaskExecution.started_at.asc().nullslast())
    )
    return [TaskOut.model_validate(t) for t in result.scalars().all()]


@router.post("/tasks", response_model=TaskOut, status_code=201)
async def create_task(payload: TaskCreate, db: DBSession):
    task = TaskExecution(
        run_id=payload.run_id,
        phase_id=payload.phase_id,
        task_id=payload.task_id,
        task_title=payload.task_title,
        agent_id=payload.agent_id,
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)
    return TaskOut.model_validate(task)


@router.patch("/tasks/{task_pk}", response_model=TaskOut)
async def update_task(task_pk: str, payload: TaskUpdate, db: DBSession):
    task = await db.get(TaskExecution, task_pk)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(task, field, value)
    await db.commit()
    await db.refresh(task)
    return TaskOut.model_validate(task)
