from __future__ import annotations

import logging
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.config import get_settings
from src.db.base import Base

logger = logging.getLogger(__name__)

_engine = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _ensure_data_dir(url: str) -> None:
    """Create the parent directory for SQLite file URLs with proper permissions."""
    if url.startswith("sqlite"):
        db_path = url.split("///")[-1]
        parent = Path(db_path).parent
        parent.mkdir(parents=True, exist_ok=True)
        try:
            parent.chmod(0o777)
        except OSError:
            pass


def get_engine():
    global _engine
    if _engine is None:
        cfg = get_settings().database
        _ensure_data_dir(cfg.url)
        _engine = create_async_engine(cfg.url, echo=cfg.echo)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            get_engine(), class_=AsyncSession, expire_on_commit=False
        )
    return _session_factory


_COLUMN_MIGRATIONS: list[tuple[str, str, str]] = [
    ("task_executions", "metadata_json", "TEXT"),
]


async def _apply_column_migrations(conn) -> None:
    """Add missing columns to existing tables (safe for SQLite)."""
    for table, column, col_type in _COLUMN_MIGRATIONS:
        try:
            await conn.execute(text(
                f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"
            ))
            logger.info("Migration: added column %s.%s", table, column)
        except Exception:
            pass


async def init_db() -> None:
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _apply_column_migrations(conn)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    factory = get_session_factory()
    async with factory() as session:
        yield session
