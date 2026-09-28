"""In-memory ``Storage`` implementation (Phase-13 "serve" seam).

Implements the exact abstract ``Storage`` contract byte-pinned in
``core/orchestrator.py`` (``class Storage``) by round-tripping the committed
``Run``/``Task``/``ToolRun``/``Hypothesis`` dataclasses **by value** through
``dataclasses.replace`` - the same preservation contract the committed
``FakeStorage`` in ``tests/test_orchestrator.py`` pins. No field is added,
renamed or reinterpreted; the orchestrator keeps its own run/task/tool-run
semantics, this class only persists them.

This is the runtime persistence backend for the serve seam, and it mirrors the
repository-backed storage semantics exactly: it is not special-cased anywhere in
production code, and every orchestrator/Storage behaviour is identical whether
this or a real repository-backed ``Storage`` is injected.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Iterable, Optional
from uuid import UUID

from core.orchestrator import (
    Storage,
    _RUN_TERMINAL,
    _TASK_STARTED,
    _TASK_TERMINAL,
)
from database.models.entities import Hypothesis, Run, Task, ToolRun


def _now() -> datetime:
    """Same clock the entities and PostgreSQL's ``now()`` agree on (UTC)."""
    return datetime.now(timezone.utc)


def _copy(entity):
    """Value-preserving copy (``dataclasses.replace``) of a persisted entity."""
    return replace(entity)


@dataclass
class MemoryStorage(Storage):
    """Deterministic in-memory storage honoring the full Storage contract."""

    _runs: dict[UUID, Run] = field(default_factory=dict)
    _tasks: dict[UUID, Task] = field(default_factory=dict)
    _tool_runs: dict[UUID, ToolRun] = field(default_factory=dict)
    _hypotheses: dict[UUID, Hypothesis] = field(default_factory=dict)

    # -- runs ----------------------------------------------------------------

    def create_run(self, run: Run) -> Run:
        stored = replace(run)
        self._runs[stored.id] = stored
        return stored

    def get_run(self, run_id: UUID) -> Optional[Run]:
        run = self._runs.get(run_id)
        if run is None:
            return None
        return replace(run)

    def list_runs(self) -> list[Run]:
        return [replace(run) for run in self._runs.values()]

    def set_run_status(self, run_id: UUID, status: str) -> None:
        run = self._runs.get(run_id)
        if run is None:
            return
        # Mirrors RunRepository.update_status, which stamps completed_at when the
        # run reaches a terminal status.
        updates: dict = {"status": status}
        if status in _RUN_TERMINAL and run.completed_at is None:
            updates["completed_at"] = _now()
        self._runs[run_id] = replace(run, **updates)

    def set_run_progress(
        self, run_id: UUID, loop_pass: int, pass_new_tasks: bool
    ) -> None:
        # Mirrors RunRepository.update_loop_progress. Implemented for real (not
        # left as the inherited no-op) so the in-memory backend has the same
        # restart-durable loop semantics as PostgreSQL.
        run = self._runs.get(run_id)
        if run is None:
            return
        self._runs[run_id] = replace(
            run, loop_pass=loop_pass, pass_new_tasks=pass_new_tasks, updated_at=_now()
        )

    # -- tasks ---------------------------------------------------------------

    def insert_tasks(self, tasks: Iterable[Task]) -> None:
        for task in tasks:
            self._tasks[task.id] = replace(task)

    def list_tasks(self, run_id: UUID) -> list[Task]:
        return [replace(t) for t in self._tasks.values() if t.run_id == run_id]

    def list_tasks_by_status(self, run_id: UUID, status: str) -> list[Task]:
        return [
            replace(t)
            for t in self._tasks.values()
            if t.run_id == run_id and t.status == status
        ]

    def set_task_status(self, task_id: UUID, status: str) -> None:
        task = self._tasks.get(task_id)
        if task is None:
            return
        # Mirrors TaskRepository.update_status, which stamps
        # ``started_at = COALESCE(started_at, now())`` on entry to a started
        # status, ``completed_at = now()`` on a terminal status, and clears
        # ``completed_at`` when a task is re-queued for retry. Without this the
        # in-memory double recorded no lifecycle timestamps at all and silently
        # diverged from PostgreSQL.
        updates: dict = {"status": status}
        if status in _TASK_STARTED and task.started_at is None:
            updates["started_at"] = _now()
        if status in _TASK_TERMINAL and task.completed_at is None:
            updates["completed_at"] = _now()
        elif status == "pending":
            updates["completed_at"] = None
        self._tasks[task_id] = replace(task, **updates)

    # -- tool runs -----------------------------------------------------------

    def insert_tool_run(self, tr: ToolRun) -> ToolRun:
        stored = replace(tr)
        self._tool_runs[stored.id] = stored
        return replace(stored)

    def finalize_tool_run(
        self, tool_run_id: UUID, exit_code: int, raw_output_ref: Optional[str]
    ) -> None:
        if tool_run_id in self._tool_runs:
            self._tool_runs[tool_run_id] = replace(
                self._tool_runs[tool_run_id],
                exit_code=exit_code,
                raw_output_ref=raw_output_ref,
            )

    # -- hypotheses ----------------------------------------------------------

    def insert_hypothesis(self, hypothesis: Hypothesis) -> Hypothesis:
        stored = replace(hypothesis)
        self._hypotheses[stored.id] = stored
        return replace(stored)

    def get_hypothesis(
        self, run_id: UUID, hypothesis_id: UUID
    ) -> Optional[Hypothesis]:
        hypothesis = self._hypotheses.get(hypothesis_id)
        if hypothesis is None or hypothesis.run_id != run_id:
            return None
        return replace(hypothesis)

    def list_hypotheses(self, run_id: UUID) -> list[Hypothesis]:
        return [replace(h) for h in self._hypotheses.values() if h.run_id == run_id]

    def set_hypothesis_review(
        self,
        run_id: UUID,
        hypothesis_id: UUID,
        review_status: str,
        review_reason: Optional[str],
        truth_label: str,
        status: str,
    ) -> Optional[Hypothesis]:
        current = self.get_hypothesis(run_id, hypothesis_id)
        if current is None:
            return None
        updated = replace(
            current,
            review_status=review_status,
            review_reason=review_reason,
            truth_label=truth_label,
            status=status,
        )
        self._hypotheses[hypothesis_id] = updated
        return replace(updated)
