from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from src.core.sse import sse_broker
from src.models.event import AgentEvent
from src.schemas.event import EventCreate, EventOut

logger = logging.getLogger(__name__)


async def ingest_event(db: AsyncSession, payload: EventCreate) -> EventOut:
    event = AgentEvent(
        run_id=payload.run_id,
        task_id=payload.task_id,
        timestamp=datetime.now(timezone.utc),
        agent_id=payload.agent_id,
        event_type=payload.event_type,
        message=payload.message,
        metadata_json=payload.metadata_json,
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)

    sse_data = {
        "id": event.id,
        "run_id": event.run_id,
        "task_id": event.task_id,
        "timestamp": event.timestamp.isoformat(),
        "agent_id": event.agent_id,
        "event_type": event.event_type.value,
        "message": event.message,
    }
    await sse_broker.publish("agent_log", sse_data, run_id=payload.run_id)

    return EventOut.model_validate(event)
