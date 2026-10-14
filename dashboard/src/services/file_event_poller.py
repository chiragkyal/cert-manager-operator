"""Background poller that ingests NDJSON telemetry events from disk into the dashboard DB.

The agent/wrapper writes events to ``openspec/changes/<name>/telemetry/events.jsonl``.
This poller scans those files every N seconds, reads new lines since the last offset,
and calls existing DB/SSE logic to persist and broadcast them.

This decouples telemetry emission (file write — works in any sandbox) from
telemetry ingestion (DB + SSE — runs inside the backend process).
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select

from src.core.sse import sse_broker
from src.db.engine import get_session_factory
from src.models.event import AgentEvent
from src.models.phase import PhaseExecution, PhaseName, PhaseStatus
from src.models.run import PipelineRun, RunStatus
from src.models.task import TaskExecution, TaskStatus

logger = logging.getLogger(__name__)


class FileEventPoller:
    def __init__(self, changes_dir: str = "openspec/changes", poll_interval_s: float = 3.0):
        self._changes_dir = Path(changes_dir)
        self._poll_interval = poll_interval_s
        self._offsets: dict[str, int] = {}
        self._change_run_ids: dict[str, str] = {}
        self._seen_event_ids: set[str] = set()
        self._state_file = Path("data/.poller-state.json")
        self._load_state()

    def _load_state(self) -> None:
        if self._state_file.exists():
            try:
                state = json.loads(self._state_file.read_text())
                self._offsets = state.get("offsets", {})
                self._seen_event_ids = set(state.get("seen_event_ids", []))
            except Exception:
                pass

    def _save_state(self) -> None:
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            state = {
                "offsets": self._offsets,
                "seen_event_ids": list(self._seen_event_ids)[-5000:],
            }
            self._state_file.write_text(json.dumps(state))
        except Exception:
            logger.debug("Failed to persist poller state")

    async def run(self) -> None:
        logger.info("FileEventPoller started — watching %s every %.1fs", self._changes_dir, self._poll_interval)
        while True:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("FileEventPoller poll error")
            await asyncio.sleep(self._poll_interval)

    async def _publish_metrics_update(self, run_id: str) -> None:
        """Recompute and publish global health metrics via SSE."""
        try:
            from src.core.config import get_settings
            from src.services.metrics_service import compute_global_health

            cfg = get_settings()
            factory = get_session_factory()
            async with factory() as db:
                metrics = await compute_global_health(db, run_id, cfg)
            await sse_broker.publish("metrics_update", metrics.model_dump(), run_id=run_id)
        except Exception:
            logger.debug("Failed to publish metrics_update for run %s", run_id, exc_info=True)

    async def _poll_once(self) -> None:
        if not self._changes_dir.is_dir():
            return
        for change_dir in sorted(self._changes_dir.iterdir()):
            if not change_dir.is_dir():
                continue
            events_file = change_dir / "telemetry" / "events.jsonl"
            if not events_file.exists():
                continue
            await self._process_file(change_dir.name, events_file)

    async def _process_file(self, change: str, events_file: Path) -> None:
        file_key = str(events_file)
        last_offset = self._offsets.get(file_key, 0)
        file_size = events_file.stat().st_size
        if file_size < last_offset:
            logger.info(
                "FileEventPoller: %s shrank (%d -> %d bytes), resetting offset",
                events_file,
                last_offset,
                file_size,
            )
            last_offset = 0
            self._offsets[file_key] = 0
        if file_size <= last_offset:
            return

        with open(events_file, "r") as f:
            f.seek(last_offset)
            new_lines = f.readlines()
            new_offset = f.tell()

        if not new_lines:
            return

        ingested = 0
        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed NDJSON line in %s", events_file)
                continue
            await self._ingest_event(change, event)
            ingested += 1

        self._offsets[file_key] = new_offset
        if ingested:
            logger.info("FileEventPoller: ingested %d events from %s", ingested, change)
            self._save_state()

    async def _ingest_event(self, change: str, event: dict[str, Any]) -> None:
        event_type = event.get("type", "")
        handler = {
            "run_create": self._handle_run_create,
            "run_end": self._handle_run_end,
            "phase_start": self._handle_phase_start,
            "phase_progress": self._handle_phase_progress,
            "phase_end": self._handle_phase_end,
            "task_start": self._handle_task_start,
            "task_end": self._handle_task_end,
            "log_event": self._handle_log_event,
        }.get(event_type)
        if handler:
            try:
                await handler(change, event)
            except Exception:
                logger.exception("Failed to ingest %s event for %s", event_type, change)

    async def _get_run_id(self, change: str) -> str | None:
        if change in self._change_run_ids:
            return self._change_run_ids[change]
        state_file = self._changes_dir / change / ".dashboard.json"
        if state_file.exists():
            try:
                state = json.loads(state_file.read_text())
                run_id = state.get("run_id")
                if run_id:
                    self._change_run_ids[change] = run_id
                    return run_id
            except Exception:
                pass
        return None

    async def _handle_run_create(self, change: str, event: dict[str, Any]) -> None:
        run_id = event.get("id", "")
        if not run_id:
            return

        factory = get_session_factory()
        async with factory() as db:
            existing = await db.get(PipelineRun, run_id)
            if existing:
                self._change_run_ids[change] = run_id
                return
            run = PipelineRun(
                id=run_id,
                change_name=event.get("change_name", f"{change}"),
                jira_key=event.get("jira_key", ""),
                branch=event.get("branch", f"feature/{change}"),
            )
            db.add(run)
            await db.commit()
            self._change_run_ids[change] = run_id
            logger.info("Poller created run %s for change %s", run_id, change)

    async def _handle_run_end(self, change: str, event: dict[str, Any]) -> None:
        run_id = event.get("run_id") or await self._get_run_id(change)
        if not run_id:
            return
        factory = get_session_factory()
        async with factory() as db:
            run = await db.get(PipelineRun, run_id)
            if not run:
                return
            run.status = RunStatus(event.get("status", "completed"))
            run.completed_at = datetime.now(timezone.utc)
            await db.commit()

        await sse_broker.publish(
            "pipeline_status",
            {"run_id": run_id, "status": event.get("status", "completed")},
            run_id=run_id,
        )

    async def _handle_phase_start(self, change: str, event: dict[str, Any]) -> None:
        run_id = event.get("run_id") or await self._get_run_id(change)
        if not run_id:
            return
        phase_id = event.get("id", "")
        phase_name_str = event.get("phase_name", "")

        factory = get_session_factory()
        async with factory() as db:
            existing_run = await db.get(PipelineRun, run_id)
            if not existing_run:
                return
            if phase_id:
                existing_phase = await db.get(PhaseExecution, phase_id)
                if existing_phase:
                    return
            try:
                phase_name = PhaseName(phase_name_str)
            except ValueError:
                return
            phase = PhaseExecution(
                id=phase_id or None,
                run_id=run_id,
                phase_number=event.get("phase_number", 0),
                phase_name=phase_name,
                model_id=event.get("model_id", ""),
                plan_phase=event.get("plan_phase"),
            )
            db.add(phase)
            await db.commit()

            new_phase_number = event.get("phase_number", 0)
            if new_phase_number > 1 and event.get("plan_phase") is None:
                stale = await db.execute(
                    select(PhaseExecution).where(
                        PhaseExecution.run_id == run_id,
                        PhaseExecution.phase_number < new_phase_number,
                        PhaseExecution.status == PhaseStatus.running,
                        PhaseExecution.plan_phase.is_(None),
                    )
                )
                repaired = []
                for orphan in stale.scalars().all():
                    orphan.status = PhaseStatus.passed
                    orphan.completed_at = datetime.now(timezone.utc)
                    if not orphan.quality_label:
                        orphan.quality_label = "auto-closed (later phase started)"
                    repaired.append(orphan)
                    logger.info(
                        "Orphan repair: closed phase %s (%s) as passed for run %s",
                        orphan.phase_number, orphan.phase_name.value, run_id,
                    )
                await db.commit()
                for orphan in repaired:
                    await sse_broker.publish(
                        "phase_update",
                        {
                            "phase_name": orphan.phase_name.value,
                            "status": orphan.status.value,
                            "iteration_count": orphan.iteration_count,
                            "tokens_in": orphan.tokens_in,
                            "tokens_out": orphan.tokens_out,
                            "quality_score": orphan.quality_score,
                            "quality_label": orphan.quality_label,
                            "plan_phase": orphan.plan_phase,
                        },
                        run_id=run_id,
                    )

            await sse_broker.publish(
                "phase_update",
                {
                    "phase_name": phase.phase_name.value,
                    "status": phase.status.value,
                    "iteration_count": phase.iteration_count,
                    "tokens_in": phase.tokens_in,
                    "tokens_out": phase.tokens_out,
                    "quality_score": phase.quality_score,
                    "quality_label": phase.quality_label,
                    "plan_phase": phase.plan_phase,
                },
                run_id=run_id,
            )

    async def _handle_phase_progress(self, change: str, event: dict[str, Any]) -> None:
        phase_id = event.get("phase_id", "")
        if not phase_id:
            return
        factory = get_session_factory()
        async with factory() as db:
            phase = await db.get(PhaseExecution, phase_id)
            if not phase:
                return
            phase.tokens_in = event.get("tokens_in", phase.tokens_in)
            phase.tokens_out = event.get("tokens_out", phase.tokens_out)
            if event.get("quality_score"):
                phase.quality_score = event["quality_score"]
            if event.get("quality_label"):
                phase.quality_label = event["quality_label"]
            if event.get("iteration_count"):
                phase.iteration_count = event["iteration_count"]
            if "duration_s" in event:
                phase.duration_s = event["duration_s"]
            await db.commit()

            await sse_broker.publish(
                "phase_update",
                {
                    "phase_name": phase.phase_name.value,
                    "status": phase.status.value,
                    "iteration_count": phase.iteration_count,
                    "tokens_in": phase.tokens_in,
                    "tokens_out": phase.tokens_out,
                    "quality_score": phase.quality_score,
                    "quality_label": phase.quality_label,
                    "plan_phase": phase.plan_phase,
                },
                run_id=phase.run_id,
            )

            await self._publish_metrics_update(phase.run_id)

    async def _handle_phase_end(self, change: str, event: dict[str, Any]) -> None:
        phase_id = event.get("phase_id", "")
        if not phase_id:
            return
        factory = get_session_factory()
        async with factory() as db:
            phase = await db.get(PhaseExecution, phase_id)
            if not phase:
                return
            phase.status = PhaseStatus(event.get("status", "passed"))
            phase.tokens_in = event.get("tokens_in", 0)
            phase.tokens_out = event.get("tokens_out", 0)
            phase.quality_score = event.get("quality_score", 0)
            phase.quality_label = event.get("quality_label", "")
            phase.iteration_count = event.get("iteration_count", 1)
            if "duration_s" in event:
                phase.duration_s = event["duration_s"]
            phase.completed_at = datetime.now(timezone.utc)
            await db.commit()

            await sse_broker.publish(
                "phase_update",
                {
                    "phase_name": phase.phase_name.value,
                    "status": phase.status.value,
                    "iteration_count": phase.iteration_count,
                    "tokens_in": phase.tokens_in,
                    "tokens_out": phase.tokens_out,
                    "quality_score": phase.quality_score,
                    "quality_label": phase.quality_label,
                    "plan_phase": phase.plan_phase,
                },
                run_id=phase.run_id,
            )

            await self._publish_metrics_update(phase.run_id)

    async def _handle_task_start(self, change: str, event: dict[str, Any]) -> None:
        run_id = event.get("run_id") or await self._get_run_id(change)
        if not run_id:
            return
        task_pk = event.get("id", "")

        factory = get_session_factory()
        async with factory() as db:
            if task_pk:
                existing = await db.get(TaskExecution, task_pk)
                if existing:
                    return
            task = TaskExecution(
                id=task_pk or None,
                run_id=run_id,
                phase_id=event.get("phase_id", ""),
                task_id=event.get("task_id", ""),
                task_title=event.get("task_title", ""),
                agent_id=event.get("agent_id", ""),
            )
            db.add(task)
            await db.commit()

            await sse_broker.publish(
                "task_update",
                {
                    "task_id": task.task_id,
                    "status": task.status.value,
                    "phase_id": task.phase_id,
                    "metadata_json": None,
                },
                run_id=run_id,
            )

    async def _handle_task_end(self, change: str, event: dict[str, Any]) -> None:
        task_pk = event.get("task_pk", "")
        if not task_pk:
            return
        factory = get_session_factory()
        async with factory() as db:
            task = await db.get(TaskExecution, task_pk)
            if not task:
                return
            task.status = TaskStatus(event.get("status", "passed"))
            task.tokens_in = event.get("tokens_in", 0)
            task.tokens_out = event.get("tokens_out", 0)
            task.cost_usd = event.get("cost_usd", 0)
            task.self_correction_loops = event.get("self_correction_loops", 0)
            task.token_attribution = event.get("attribution")
            if event.get("metadata"):
                task.metadata_json = event["metadata"]
            task.completed_at = datetime.now(timezone.utc)

            if task.token_attribution != "phase_aggregate" and task.cost_usd == 0 and (task.tokens_in + task.tokens_out) > 0:
                from src.core.config import get_settings
                cfg = get_settings()
                default_cost = cfg.metrics.cost_for_model("default")
                task.cost_usd = round(
                    (task.tokens_in * default_cost.input + task.tokens_out * default_cost.output) / 1_000_000, 4
                )

            run_id = task.run_id
            await db.commit()

            await sse_broker.publish(
                "task_update",
                {
                    "task_id": task.task_id,
                    "status": task.status.value,
                    "phase_id": task.phase_id,
                    "metadata_json": task.metadata_json,
                },
                run_id=run_id,
            )

        await self._publish_metrics_update(run_id)

    async def _handle_log_event(self, change: str, event: dict[str, Any]) -> None:
        run_id = event.get("run_id") or await self._get_run_id(change)
        if not run_id:
            return

        event_id = event.get("id", "")
        if event_id and event_id in self._seen_event_ids:
            return

        factory = get_session_factory()
        async with factory() as db:
            existing_run = await db.get(PipelineRun, run_id)
            if not existing_run:
                return

            from sqlalchemy import and_
            msg = event.get("message", "")
            agent = event.get("agent_id", "Pipeline")
            dup_check = await db.execute(
                select(AgentEvent.id).where(
                    and_(
                        AgentEvent.run_id == run_id,
                        AgentEvent.message == msg,
                        AgentEvent.agent_id == agent,
                    )
                ).limit(1)
            )
            if dup_check.scalar_one_or_none():
                if event_id:
                    self._seen_event_ids.add(event_id)
                return

            from src.models.event import EventType
            try:
                et = EventType(event.get("event_type", "state_machine"))
            except ValueError:
                et = EventType.state_machine

            if event_id:
                self._seen_event_ids.add(event_id)

            agent_event = AgentEvent(
                run_id=run_id,
                task_id=event.get("task_id"),
                timestamp=datetime.now(timezone.utc),
                agent_id=event.get("agent_id", "Pipeline"),
                event_type=et,
                message=event.get("message", ""),
                metadata_json=event.get("metadata_json"),
            )
            db.add(agent_event)
            await db.commit()
            await db.refresh(agent_event)

            sse_data = {
                "id": agent_event.id,
                "run_id": agent_event.run_id,
                "task_id": agent_event.task_id,
                "timestamp": agent_event.timestamp.isoformat(),
                "agent_id": agent_event.agent_id,
                "event_type": agent_event.event_type.value,
                "message": agent_event.message,
            }
            await sse_broker.publish("agent_log", sse_data, run_id=run_id)
