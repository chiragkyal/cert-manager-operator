from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, JSON, String, BigInteger, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.base import Base


class TaskStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    passed = "passed"
    failed = "failed"
    waiting = "waiting"
    skipped = "skipped"


class TaskExecution(Base):
    __tablename__ = "task_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id: Mapped[str] = mapped_column(String(36), ForeignKey("pipeline_runs.id"), index=True)
    phase_id: Mapped[str] = mapped_column(String(36), ForeignKey("phase_executions.id"), index=True)
    task_id: Mapped[str] = mapped_column(String(32))
    task_title: Mapped[str] = mapped_column(String(512), default="")
    agent_id: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[TaskStatus] = mapped_column(Enum(TaskStatus), default=TaskStatus.pending)
    self_correction_loops: Mapped[int] = mapped_column(Integer, default=0)
    tokens_in: Mapped[int] = mapped_column(BigInteger, default=0)
    tokens_out: Mapped[int] = mapped_column(BigInteger, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    token_attribution: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=None)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    run: Mapped["PipelineRun"] = relationship(back_populates="tasks")  # type: ignore[name-defined]
    phase: Mapped["PhaseExecution"] = relationship(back_populates="tasks")  # type: ignore[name-defined]
    events: Mapped[list["AgentEvent"]] = relationship(back_populates="task", cascade="all, delete-orphan")  # type: ignore[name-defined]
