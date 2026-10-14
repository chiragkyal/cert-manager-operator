from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field

from src.models.run import RunStatus


class RunCreate(BaseModel):
    change_name: str
    jira_key: str
    branch: str = ""


class RunUpdate(BaseModel):
    status: RunStatus | None = None
    branch: str | None = None
    total_tokens_in: int | None = None
    total_tokens_out: int | None = None
    total_cost_usd: float | None = None
    completed_at: datetime | None = None


class RunOut(BaseModel):
    id: str
    change_name: str
    jira_key: str
    branch: str
    status: RunStatus
    total_tokens_in: int
    total_tokens_out: int
    total_cost_usd: float
    started_at: datetime
    completed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class RunListOut(BaseModel):
    runs: list[RunOut]
    total: int
