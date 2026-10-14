from __future__ import annotations

from pydantic import BaseModel


class GlobalHealthMetrics(BaseModel):
    total_tokens_consumed: int
    total_run_cost_usd: float
    cumulative_wall_time_s: float
    compliance_index: float
    gate_passing_rate: float
    human_rejection_rate: float
    total_refinement_iterations: int
    agent_success_rate: float
    tasks_passed: int
    tasks_total: int


class TokenBurnEntry(BaseModel):
    agent_id: str
    tokens: int
    cost_usd: float


class TokenBurnOut(BaseModel):
    entries: list[TokenBurnEntry]
    total_tokens: int
    total_cost_usd: float


class ArtifactEditEntry(BaseModel):
    artifact_id: str
    phase_name: str
    eval_refinements: int
    feedback_rounds: int
    total_edits: int


class ArtifactEditsOut(BaseModel):
    artifacts: list[ArtifactEditEntry]
    total_edits: int


class EvaluateRequest(BaseModel):
    type: str  # "compliance" | "artifact" | "harness"
    content: str
    rubric: str | None = None


class EvaluateResponse(BaseModel):
    score: float
    passed: bool
    failures: list[str]
    model_id: str
    vertex_ai_enabled: bool
