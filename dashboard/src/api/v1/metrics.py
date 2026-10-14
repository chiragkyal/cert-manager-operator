from __future__ import annotations

from fastapi import APIRouter

from src.core.dependencies import DBSession, Settings
from src.schemas.metrics import ArtifactEditsOut, GlobalHealthMetrics, TokenBurnOut
from src.services.metrics_service import compute_artifact_edits, compute_global_health, compute_token_burn

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("/global/{run_id}", response_model=GlobalHealthMetrics)
async def global_health(run_id: str, db: DBSession, cfg: Settings):
    return await compute_global_health(db, run_id, cfg)


@router.get("/token-burn/{run_id}", response_model=TokenBurnOut)
async def token_burn(run_id: str, db: DBSession, cfg: Settings):
    return await compute_token_burn(db, run_id, cfg)


@router.get("/artifact-edits/{run_id}", response_model=ArtifactEditsOut)
async def artifact_edits(run_id: str, db: DBSession, cfg: Settings):
    return await compute_artifact_edits(db, run_id, cfg)
