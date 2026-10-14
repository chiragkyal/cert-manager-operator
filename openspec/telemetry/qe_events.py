"""QE/E2E telemetry event helpers for the OpenSpec E2E workflow.

Emits NDJSON events to ``openspec/changes/<change>/telemetry/e2e-events.jsonl``.
Follows the same disk-only pattern as the dev workflow telemetry client.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CHANGES_DIR = Path("openspec/changes")


class QETelemetryClient:
    """Writes E2E/QE telemetry events to a dedicated events file."""

    def __init__(self, change: str) -> None:
        self._change = change

    def _events_path(self) -> Path:
        return CHANGES_DIR / self._change / "telemetry" / "e2e-events.jsonl"

    def _write_event(self, event: dict[str, Any]) -> None:
        try:
            path = self._events_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(event, default=str) + "\n"
            with open(path, "a") as f:
                f.write(line)
        except OSError as exc:
            logger.debug("Failed to write QE telemetry event: %s", exc)

    # ------------------------------------------------------------------
    # E2E run lifecycle
    # ------------------------------------------------------------------

    def start_e2e_run(
        self,
        pr_url: str,
        phase: int | None = None,
        mode: str = "phase-iterative",
    ) -> str:
        run_id = str(uuid.uuid4())
        self._write_event({
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "e2e_run_start",
            "change": self._change,
            "id": run_id,
            "pr_url": pr_url,
            "phase": phase,
            "mode": mode,
        })
        return run_id

    def end_e2e_run(self, run_id: str, status: str = "completed") -> None:
        self._write_event({
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "e2e_run_end",
            "change": self._change,
            "run_id": run_id,
            "status": status,
        })

    # ------------------------------------------------------------------
    # Stage lifecycle (pre_analysis, test_plan, consolidation, code_gen, execution)
    # ------------------------------------------------------------------

    def start_stage(self, run_id: str, stage: int, stage_name: str) -> str:
        stage_id = str(uuid.uuid4())
        self._write_event({
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "e2e_stage_start",
            "change": self._change,
            "id": stage_id,
            "run_id": run_id,
            "stage": stage,
            "stage_name": stage_name,
        })
        return stage_id

    def end_stage(
        self,
        stage_id: str,
        status: str = "approved",
        *,
        tokens_in: int = 0,
        tokens_out: int = 0,
        duration_s: float = 0.0,
        refinement_rounds: int = 0,
    ) -> None:
        self._write_event({
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "e2e_stage_end",
            "change": self._change,
            "stage_id": stage_id,
            "status": status,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "duration_s": duration_s,
            "refinement_rounds": refinement_rounds,
        })

    # ------------------------------------------------------------------
    # Execution events (Stage 5)
    # ------------------------------------------------------------------

    def record_execution(
        self,
        run_id: str,
        *,
        attempt: int = 1,
        tests_run: int = 0,
        tests_passed: int = 0,
        tests_failed: int = 0,
        exit_code: int = 0,
        file_hash: str = "",
        source: str = "local",
    ) -> None:
        """Record a single test execution attempt."""
        self._write_event({
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "e2e_execution",
            "change": self._change,
            "run_id": run_id,
            "attempt": attempt,
            "tests_run": tests_run,
            "tests_passed": tests_passed,
            "tests_failed": tests_failed,
            "exit_code": exit_code,
            "file_hash": file_hash,
            "source": source,
        })

    def record_bug_found(
        self,
        run_id: str,
        test_name: str,
        failure_message: str = "",
        rca: str = "",
    ) -> None:
        self._write_event({
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "e2e_bug_found",
            "change": self._change,
            "run_id": run_id,
            "test_name": test_name,
            "failure_message": failure_message,
            "rca": rca,
        })

    def record_bug_verified(self, run_id: str, test_name: str) -> None:
        self._write_event({
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "e2e_bug_verified",
            "change": self._change,
            "run_id": run_id,
            "test_name": test_name,
        })

    def record_triage(
        self,
        run_id: str,
        test_name: str,
        rca: str,
        user_confirmed: bool | None = None,
    ) -> None:
        self._write_event({
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "e2e_triage",
            "change": self._change,
            "run_id": run_id,
            "test_name": test_name,
            "rca": rca,
            "user_confirmed": user_confirmed,
        })

    def record_archive_feedback(
        self,
        *,
        run_id: str = "",
        story_points_delivered: float | None = None,
        estimated_manual_effort: str = "",
        satisfaction_rating: int | None = None,
        user_feedback: str = "",
    ) -> None:
        """Record QE feedback collected by ``/opsx-archive`` — NOT during
        ``/opsx-e2e`` itself. ``/opsx-archive`` calls this only when it
        detects this change had at least one E2E run (i.e. this events file
        exists). ``run_id`` is best-effort — the most recent ``e2e_run_start``
        id, for traceability — since a phase-iterative change may have had
        multiple E2E runs (one per phase) by the time archive collects this.

        The fields mirror the dev workflow's ``archive_feedback`` event so
        that both reports produce a uniform ``productivity_metrics`` block:
        story_points_delivered, estimated_manual_effort (bucket),
        satisfaction_rating (1-5), user_feedback.
        """
        self._write_event({
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "qe_archive_feedback",
            "change": self._change,
            "run_id": run_id,
            "story_points_delivered": story_points_delivered,
            "estimated_manual_effort": estimated_manual_effort,
            "satisfaction_rating": satisfaction_rating,
            "user_feedback": user_feedback,
        })


def compute_file_hash(directory: Path) -> str:
    """Compute a stable hash of all *_test.go files in a directory."""
    hasher = hashlib.sha256()
    test_files = sorted(directory.glob("*_test.go"))
    for f in test_files:
        try:
            hasher.update(f.read_bytes())
        except OSError:
            continue
    return hasher.hexdigest()[:12] if test_files else ""
