from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.base import Base


class EventType(str, enum.Enum):
    tool_call = "tool_call"
    harness_alert = "harness_alert"
    self_correction = "self_correction"
    state_machine = "state_machine"


class AgentEvent(Base):
    __tablename__ = "agent_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id: Mapped[str] = mapped_column(String(36), ForeignKey("pipeline_runs.id"), index=True)
    task_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("task_executions.id"), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    agent_id: Mapped[str] = mapped_column(String(128))
    event_type: Mapped[EventType] = mapped_column(Enum(EventType))
    message: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    run: Mapped["PipelineRun"] = relationship(back_populates="events")  # type: ignore[name-defined]
    task: Mapped["TaskExecution | None"] = relationship(back_populates="events")  # type: ignore[name-defined]
