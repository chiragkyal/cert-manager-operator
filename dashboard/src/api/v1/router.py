from fastapi import APIRouter

from src.api.v1.runs import router as runs_router
from src.api.v1.phases import router as phases_router
from src.api.v1.tasks import router as tasks_router
from src.api.v1.metrics import router as metrics_router
from src.api.v1.events import router as events_router
from src.api.v1.vertex_ai import router as vertex_ai_router

v1_router = APIRouter()
v1_router.include_router(runs_router)
v1_router.include_router(phases_router)
v1_router.include_router(tasks_router)
v1_router.include_router(metrics_router)
v1_router.include_router(events_router)
v1_router.include_router(vertex_ai_router)
