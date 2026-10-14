from __future__ import annotations

from fastapi import APIRouter

from src.schemas.metrics import EvaluateRequest, EvaluateResponse
from src.services.vertex_ai_service import get_vertex_ai_service

router = APIRouter(prefix="/evaluate", tags=["vertex_ai"])


@router.post("", response_model=EvaluateResponse)
async def evaluate(payload: EvaluateRequest):
    svc = get_vertex_ai_service()
    return await svc.evaluate(
        eval_type=payload.type,
        content=payload.content,
        rubric=payload.rubric,
    )
