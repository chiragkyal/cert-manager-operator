from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.config import get_settings
from src.core.paths import get_changes_dir
from src.core.sse import sse_broker
from src.db.engine import get_session_factory, init_db
from src.api.v1.router import v1_router
from src.services.file_event_poller import FileEventPoller
from src.services.pipeline_scanner import scan_changes

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    cfg = get_settings()
    await init_db()
    await sse_broker.start()

    factory = get_session_factory()
    async with factory() as db:
        imported = await scan_changes(db, cfg)
        if imported:
            logger.info("Auto-scan discovered new changes: %s", imported)

    poller = FileEventPoller(
        changes_dir=str(get_changes_dir(cfg)),
        poll_interval_s=cfg.telemetry.poll_interval_s,
    )
    poller_task = asyncio.create_task(poller.run())

    yield

    poller_task.cancel()
    try:
        await poller_task
    except asyncio.CancelledError:
        pass
    await sse_broker.stop()


def create_app() -> FastAPI:
    cfg = get_settings()
    logging.basicConfig(level=cfg.server.log_level.upper())

    application = FastAPI(
        title="Agentic AI Observability Dashboard",
        description="SDLC Observability for the Spec-Driven Development pipeline",
        version="0.1.0",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.server.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(v1_router, prefix="/api/v1")
    return application


app = create_app()
