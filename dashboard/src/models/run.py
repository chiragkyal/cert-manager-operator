from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, String, BigInteger
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.base import Base


class RunStatus(str, enum.Enum):
    running = "running"
    waiting_for_human = "waiting_for_human"
    completed = "completed"
    failed = "failed"


class PipelineRun(Base):
    __tablename__ = "pipeline_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    change_name: Mapped[str] = mapped_column(String(255), index=True)
    jira_key: Mapped[str] = mapped_column(String(64))
    branch: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[RunStatus] = mapped_column(Enum(RunStatus), default=RunStatus.running)
    total_tokens_in: Mapped[int] = mapped_column(BigInteger, default=0)
    total_tokens_out: Mapped[int] = mapped_column(BigInteger, default=0)
    total_cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    phases: Mapped[list["PhaseExecution"]] = relationship(back_populates="run", cascade="all, delete-orphan")  # type: ignore[name-defined]
    tasks: Mapped[list["TaskExecution"]] = relationship(back_populates="run", cascade="all, delete-orphan")  # type: ignore[name-defined]
    events: Mapped[list["AgentEvent"]] = relationship(back_populates="run", cascade="all, delete-orphan")  # type: ignore[name-defined]
