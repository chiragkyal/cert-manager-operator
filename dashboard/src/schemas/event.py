from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel

from src.models.event import EventType


class EventCreate(BaseModel):
    run_id: str
    task_id: str | None = None
    agent_id: str
    event_type: EventType
    message: str
    metadata_json: dict[str, Any] | None = None


class EventOut(BaseModel):
    id: str
    run_id: str
    task_id: str | None
    timestamp: datetime
    agent_id: str
    event_type: EventType
    message: str
    metadata_json: dict[str, Any] | None

    model_config = {"from_attributes": True}
