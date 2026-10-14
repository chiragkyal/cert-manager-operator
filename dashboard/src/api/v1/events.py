from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from src.core.dependencies import DBSession
from src.core.sse import sse_broker
from src.models.event import AgentEvent
from src.schemas.event import EventCreate, EventOut
from src.services.telemetry_service import ingest_event

router = APIRouter(prefix="/events", tags=["events"])


@router.post("", response_model=EventOut, status_code=201)
async def create_event(payload: EventCreate, db: DBSession):
    return await ingest_event(db, payload)


@router.get("", response_model=list[EventOut])
async def list_events(
    run_id: str,
    db: DBSession,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
):
    result = await db.execute(
        select(AgentEvent)
        .where(AgentEvent.run_id == run_id)
        .order_by(AgentEvent.timestamp.desc())
        .offset(offset)
        .limit(limit)
    )
    return [EventOut.model_validate(e) for e in result.scalars().all()]


@router.get("/stream")
async def event_stream(run_id: str | None = Query(default=None)):
    async def generate():
        async for chunk in sse_broker.subscribe(run_id):
            yield chunk

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
