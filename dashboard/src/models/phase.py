from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, BigInteger
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.base import Base


class PhaseName(str, enum.Enum):
    spec_understanding = "spec_understanding"
    repo_assessment = "repo_assessment"
    arch_planning = "arch_planning"
    subtask_creation = "subtask_creation"
    code_generation = "code_generation"


class PhaseStatus(str, enum.Enum):
    running = "running"
    passed = "passed"
    failed = "failed"
    waiting = "waiting"
    skipped = "skipped"


class PhaseExecution(Base):
    __tablename__ = "phase_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id: Mapped[str] = mapped_column(String(36), ForeignKey("pipeline_runs.id"), index=True)
    phase_number: Mapped[int] = mapped_column(Integer)
    phase_name: Mapped[PhaseName] = mapped_column(Enum(PhaseName))
    status: Mapped[PhaseStatus] = mapped_column(Enum(PhaseStatus), default=PhaseStatus.running)
    iteration_count: Mapped[int] = mapped_column(Integer, default=1)
    duration_s: Mapped[float] = mapped_column(Float, default=0.0)
    tokens_in: Mapped[int] = mapped_column(BigInteger, default=0)
    tokens_out: Mapped[int] = mapped_column(BigInteger, default=0)
    model_id: Mapped[str] = mapped_column(String(128), default="")
    quality_score: Mapped[float] = mapped_column(Float, default=0.0)
    quality_label: Mapped[str] = mapped_column(String(255), default="")
    plan_phase: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    run: Mapped["PipelineRun"] = relationship(back_populates="phases")  # type: ignore[name-defined]
    tasks: Mapped[list["TaskExecution"]] = relationship(back_populates="phase", cascade="all, delete-orphan")  # type: ignore[name-defined]
