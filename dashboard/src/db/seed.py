"""Seed the database with the CM-830 demo data from the design document."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta

from src.db.engine import init_db, get_session_factory
from src.models.run import PipelineRun, RunStatus
from src.models.phase import PhaseExecution, PhaseName, PhaseStatus
from src.models.task import TaskExecution, TaskStatus
from src.models.event import AgentEvent, EventType

_BASE_TIME = datetime(2026, 6, 23, 14, 0, 0, tzinfo=timezone.utc)


async def seed() -> None:
    await init_db()
    factory = get_session_factory()

    async with factory() as db:
        run = PipelineRun(
            change_name="Secure JWT Authentication Framework Additions",
            jira_key="CM-830",
            branch="feature/auth-v2",
            status=RunStatus.waiting_for_human,
            total_tokens_in=1_020_500,
            total_tokens_out=400_000,
            total_cost_usd=4.82,
            started_at=_BASE_TIME,
        )
        db.add(run)
        await db.flush()

        phases_data = [
            (1, PhaseName.spec_understanding, PhaseStatus.passed, 1, 42, 45_000, 12_000, 94.0, "AC Completeness: 94/100"),
            (2, PhaseName.repo_assessment, PhaseStatus.passed, 2, 75, 180_000, 35_000, 100.0, "Coverage: 100% No Gaps"),
            (3, PhaseName.arch_planning, PhaseStatus.passed, 1, 62, 95_000, 55_000, 91.0, "Fidelity Score: 91/100"),
            (4, PhaseName.subtask_creation, PhaseStatus.passed, 1, 55, 60_000, 40_000, 0.0, "7 Tasks Generated (2 [P])"),
            (5, PhaseName.code_generation, PhaseStatus.waiting, 4, 531, 620_000, 278_000, 0.0, "Unit Test Pass: 5/6 ❌ Linter Fail"),
        ]

        phase_ids: dict[int, str] = {}
        for num, name, status, iters, dur, t_in, t_out, score, label in phases_data:
            started = _BASE_TIME + timedelta(seconds=(num - 1) * 120)
            completed = started + timedelta(seconds=dur) if status == PhaseStatus.passed else None
            p = PhaseExecution(
                run_id=run.id,
                phase_number=num,
                phase_name=name,
                status=status,
                iteration_count=iters,
                duration_s=float(dur),
                tokens_in=t_in,
                tokens_out=t_out,
                model_id="gemini-2.5-pro",
                quality_score=score,
                quality_label=label,
                started_at=started,
                completed_at=completed,
            )
            db.add(p)
            await db.flush()
            phase_ids[num] = p.id

        tasks_data = [
            ("T1.1", "Scaffold JWT middleware", "Backend_Agent", TaskStatus.passed, 0, 180_000, 80_000, 0.90),
            ("T1.2", "Add token validation", "Backend_Agent", TaskStatus.passed, 1, 200_000, 90_000, 1.00),
            ("T1.3", "Implement refresh token logic", "Backend_Agent", TaskStatus.passed, 0, 150_000, 60_000, 0.72),
            ("T1.4", "Create user model migration", "DB_Agent", TaskStatus.passed, 0, 120_000, 50_000, 0.58),
            ("T1.5", "Add auth routes to API gateway", "Backend_Agent", TaskStatus.passed, 2, 200_000, 80_000, 0.96),
            ("T2.1", "Build token storage service", "DB_Agent", TaskStatus.passed, 0, 100_000, 50_000, 0.40),
            ("T2.2", "Implement CRUD logic in userController.ts", "Backend_Agent", TaskStatus.waiting, 4, 168_000, 110_000, 0.54),
        ]

        task_pks: dict[str, str] = {}
        for tid, title, agent, status, loops, t_in, t_out, cost in tasks_data:
            t = TaskExecution(
                run_id=run.id,
                phase_id=phase_ids[5],
                task_id=tid,
                task_title=title,
                agent_id=agent,
                status=status,
                self_correction_loops=loops,
                tokens_in=t_in,
                tokens_out=t_out,
                cost_usd=cost,
                started_at=_BASE_TIME + timedelta(minutes=4),
                completed_at=(_BASE_TIME + timedelta(minutes=12)) if status == TaskStatus.passed else None,
            )
            db.add(t)
            await db.flush()
            task_pks[tid] = t.id

        events_data = [
            (_BASE_TIME + timedelta(minutes=14, seconds=10), "API_Agent", EventType.tool_call, task_pks.get("T2.2"),
             'Consumed Task T2.2 ("Implement CRUD logic in userController.ts").'),
            (_BASE_TIME + timedelta(minutes=14, seconds=22), "API_Agent", EventType.tool_call, task_pks.get("T2.2"),
             "Generated file modification for `src/controllers/userController.ts` via edit_file."),
            (_BASE_TIME + timedelta(minutes=14, seconds=25), "API_Agent", EventType.tool_call, task_pks.get("T2.2"),
             "Running local compiler and unit test suite..."),
            (_BASE_TIME + timedelta(minutes=14, seconds=31), "API_Agent", EventType.harness_alert, task_pks.get("T2.2"),
             "❌ Compilation Error: Type 'string | undefined' is not assignable to type 'string'."),
            (_BASE_TIME + timedelta(minutes=14, seconds=32), "API_Agent", EventType.self_correction, task_pks.get("T2.2"),
             "Loop 4/5 Triggered. Prompting agent with error logs and matching Constitution.md rules."),
            (_BASE_TIME + timedelta(minutes=14, seconds=45), "API_Agent", EventType.state_machine, task_pks.get("T2.2"),
             "Max self-correction limit approached or exception hit. Pausing... Escalating to user."),
        ]

        for ts, agent, etype, task_id, msg in events_data:
            ev = AgentEvent(
                run_id=run.id,
                task_id=task_id,
                timestamp=ts,
                agent_id=agent,
                event_type=etype,
                message=msg,
            )
            db.add(ev)

        await db.commit()
        print(f"Seeded run {run.id} with {len(phases_data)} phases, {len(tasks_data)} tasks, {len(events_data)} events")


def main() -> None:
    asyncio.run(seed())


if __name__ == "__main__":
    main()
