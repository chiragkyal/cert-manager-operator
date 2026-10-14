from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel

from src.models.phase import PhaseName, PhaseStatus


class PhaseCreate(BaseModel):
    run_id: str
    phase_number: int
    phase_name: PhaseName
    model_id: str = ""
    plan_phase: int | None = None


class PhaseUpdate(BaseModel):
    status: PhaseStatus | None = None
    iteration_count: int | None = None
    duration_s: float | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    quality_score: float | None = None
    quality_label: str | None = None
    completed_at: datetime | None = None


class PhaseOut(BaseModel):
    id: str
    run_id: str
    phase_number: int
    phase_name: PhaseName
    status: PhaseStatus
    iteration_count: int
    duration_s: float
    tokens_in: int
    tokens_out: int
    model_id: str
    quality_score: float
    quality_label: str
    plan_phase: int | None = None
    started_at: datetime
    completed_at: datetime | None

    model_config = {"from_attributes": True}
