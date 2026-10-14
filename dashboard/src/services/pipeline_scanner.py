from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import AppConfig
from src.core.paths import get_changes_dir
from src.models.phase import PhaseExecution, PhaseName, PhaseStatus
from src.models.run import PipelineRun, RunStatus
from openspec.telemetry.change_metrics import (
    ARTIFACT_PHASE_MAP,
    phase_duration_s,
    phase_iteration_count,
)

logger = logging.getLogger(__name__)

_STAGE_TO_PHASE: dict[str, PhaseName] = {
    "validation": PhaseName.spec_understanding,
    "specs": PhaseName.spec_understanding,
    "repo-assessment": PhaseName.repo_assessment,
    "constitution": PhaseName.repo_assessment,
    "plan": PhaseName.arch_planning,
    "tasks": PhaseName.subtask_creation,
    "implementation": PhaseName.code_generation,
    "code-generation": PhaseName.code_generation,
}

_PHASE_NUMBERS: dict[PhaseName, int] = {
    PhaseName.spec_understanding: 1,
    PhaseName.repo_assessment: 2,
    PhaseName.arch_planning: 3,
    PhaseName.subtask_creation: 4,
    PhaseName.code_generation: 5,
}


def _load_yaml(path: Path) -> dict[str, Any] | None:
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except Exception:
        logger.debug("Could not parse YAML at %s", path)
        return None


async def scan_changes(db: AsyncSession, cfg: AppConfig) -> list[str]:
    """Scan openspec/changes/ directories and upsert pipeline runs."""
    base_dir = get_changes_dir(cfg)
    if not base_dir.exists():
        logger.info("Changes directory %s does not exist, skipping scan", base_dir)
        return []

    imported: list[str] = []

    for change_dir in sorted(base_dir.iterdir()):
        if not change_dir.is_dir():
            continue

        change_name = change_dir.name
        existing = await db.execute(
            select(PipelineRun).where(PipelineRun.change_name == change_name)
        )
        if existing.scalar_one_or_none() is not None:
            continue

        jira_yaml = change_dir / "inputs" / "jira.yaml"
        jira_data = _load_yaml(jira_yaml) or {}

        run = PipelineRun(
            change_name=change_name,
            jira_key=str(jira_data.get("jira_key", change_name)),
            branch=str(jira_data.get("branch", "")),
            status=RunStatus.completed,
        )
        db.add(run)
        await db.flush()

        eval_dir = change_dir / "eval-results"
        if eval_dir.exists():
            seen_phases: set[PhaseName] = set()
            for eval_file in sorted(eval_dir.glob("*.yaml")):
                eval_data = _load_yaml(eval_file) or {}
                stage = eval_data.get("stage", eval_file.stem.split("-")[0] if "-" in eval_file.stem else eval_file.stem)
                phase_name = _STAGE_TO_PHASE.get(stage)
                if phase_name is None or phase_name in seen_phases:
                    continue
                seen_phases.add(phase_name)

                score = eval_data.get("overall_score", 0)
                passed = eval_data.get("overall_pass", False)
                artifact_id = eval_file.stem.split("-")[0] if "-" in eval_file.stem else eval_file.stem
                if artifact_id in ARTIFACT_PHASE_MAP:
                    phase_num = ARTIFACT_PHASE_MAP[artifact_id][0]
                    iteration_count = phase_iteration_count(change_dir, phase_num)
                    duration_s = phase_duration_s(change_dir, phase_num)
                else:
                    iteration_count = 1
                    duration_s = 0.0

                phase = PhaseExecution(
                    run_id=run.id,
                    phase_number=_PHASE_NUMBERS[phase_name],
                    phase_name=phase_name,
                    status=PhaseStatus.passed if passed else PhaseStatus.failed,
                    quality_score=float(score),
                    quality_label=f"Score: {score}/100",
                    iteration_count=iteration_count,
                    duration_s=duration_s,
                )
                db.add(phase)

        await db.commit()
        imported.append(change_name)
        logger.info("Imported change: %s", change_name)

    return imported
