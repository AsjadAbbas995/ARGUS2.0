"""Phase 34A: execution-outcome fidelity across the served seam.

These tests are offline and deterministic. They drive the real ``Orchestrator``
over the in-memory test storage and the real ``ServedExecution`` with fake
adapters, so no subprocess, network, or PostgreSQL path is exercised.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ai import run_context
from api import serve as serve_module
from core.orchestrator import Orchestrator, ToolRunOutcome
from database.models.entities import Task, ToolRun
from recon.base import ToolExecution
from tests.test_ingest_orchestration import (
    FakeStorage,
    RecordingHook,
    _drive,
    _run,
    _scope,
    _served_hook,
    _task,
    _tool_run,
)


def _outcome(task, *, timed_out=False, error=None, artifacts=()):
    return ToolRunOutcome(
        tool_run=_tool_run(task),
        artifacts=artifacts,
        timed_out=timed_out,
        error=error,
    )


def _drive_typed(storage, hook, type_: str, seam):
    orch = Orchestrator(storage=storage, run_tool=seam, ingest=hook)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id, type_=type_)])
    status = orch.run_to_completion(run.id)
    return orch, run, status


def _drive_parent_child(storage, seam):
    orch = Orchestrator(storage=storage, run_tool=seam, ingest=RecordingHook())
    run = orch.create_run(_run())
    parent = _task(run.id, type_="tech_detect")
    child = _task(run.id, type_="dns_resolve")
    child.parent_task_id = parent.id
    orch.plan(run, [child, parent])
    status = orch.run_to_completion(run.id)
    by_type = {task.type: task for task in storage.list_tasks(run.id)}
    return run, by_type, status


def test_timeout_without_artifacts_fails_the_task():
    storage = FakeStorage()
    _, run, _ = _drive(
        storage,
        RecordingHook(),
        run_tool=lambda task: _outcome(task, timed_out=True, error="timed out"),
    )

    [task] = storage.list_tasks(run.id)
    assert task.status == "failed"


def test_explicit_adapter_error_fails_task_and_leaves_stage_uncovered():
    storage = FakeStorage()
    _, run, _ = _drive_typed(
        storage,
        RecordingHook(),
        "tech_detect",
        lambda task: _outcome(task, error="connection refused"),
    )

    [task] = storage.list_tasks(run.id)
    assert task.status == "failed"
    assert "tech_detect" not in run_context.covered_stages([task])
    assert "tech_detect" in run_context.coverage_gaps([task], ["tech_detect"])


def test_timed_out_parent_blocks_its_dependent_child():
    storage = FakeStorage()
    executed = []

    def seam(task):
        executed.append(task.type)
        if task.type == "tech_detect":
            return _outcome(task, timed_out=True)
        return _tool_run(task)

    _, by_type, _ = _drive_parent_child(storage, seam)

    assert executed == ["tech_detect"]
    assert by_type["tech_detect"].status == "failed"
    assert by_type["dns_resolve"].status == "pending"


def test_erroring_parent_blocks_its_dependent_child():
    storage = FakeStorage()
    executed = []

    def seam(task):
        executed.append(task.type)
        if task.type == "tech_detect":
            return _outcome(task, error="connection refused")
        return _tool_run(task)

    _, by_type, _ = _drive_parent_child(storage, seam)

    assert executed == ["tech_detect"]
    assert by_type["tech_detect"].status == "failed"
    assert by_type["dns_resolve"].status == "pending"


def test_successful_parent_still_unlocks_its_dependent_child():
    storage = FakeStorage()
    executed = []

    def seam(task):
        executed.append(task.type)
        return _outcome(task)

    _, by_type, _ = _drive_parent_child(storage, seam)

    assert executed == ["tech_detect", "dns_resolve"]
    assert by_type["tech_detect"].status == "completed"
    assert by_type["dns_resolve"].status == "completed"


def test_timeout_with_partial_artifacts_preserves_tool_run_and_ingestion():
    storage = FakeStorage()
    _, run, _ = _drive(
        storage,
        _served_hook(storage),
        run_tool=lambda task: _outcome(
            task,
            timed_out=True,
            error="timed out",
            artifacts=("api.example.com",),
        ),
    )

    [task] = storage.list_tasks(run.id)
    assert task.status == "failed"
    assert len(storage._tool_runs) == 1
    tool_run = next(iter(storage._tool_runs.values()))
    assert tool_run.task_id == task.id

    plan, tool_run_id, _, _ = storage.ingested[0]
    assert tool_run_id == tool_run.id
    assert [asset.hostname for asset in plan.assets] == ["api.example.com"]


def test_bare_nonzero_exit_without_failure_metadata_still_completes():
    storage = FakeStorage()
    hook = RecordingHook()

    def seam(task):
        return ToolRun(
            task_id=task.id,
            tool_name="subfinder",
            command=["subfinder", "-d", "example.com"],
            exit_code=2,
            raw_output_ref=None,
        )

    _, run, _ = _drive(storage, hook, run_tool=seam)

    [task] = storage.list_tasks(run.id)
    assert task.status == "completed"


def test_coverage_excludes_failed_tasks_and_keeps_the_gap_visible():
    tasks = [
        Task(type="tech_detect", status="failed"),
        Task(type="dns_resolve", status="completed"),
    ]

    covered = run_context.covered_stages(tasks)
    assert "tech_detect" not in covered
    assert "dns_resolve" in covered
    assert "tech_detect" in run_context.coverage_gaps(
        tasks, ["tech_detect", "dns_resolve"]
    )


def test_failed_fingerprint_is_requeued_in_place_without_a_duplicate():
    storage = FakeStorage()
    orch = Orchestrator(
        storage=storage,
        run_tool=lambda task: _outcome(task, error="boom"),
        ingest=RecordingHook(),
    )
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id, type_="tech_detect")])
    orch.run_to_completion(run.id)

    [failed] = storage.list_tasks(run.id)
    assert failed.status == "failed"

    orch.plan(run, [_task(run.id, type_="tech_detect")])
    tasks = storage.list_tasks(run.id)
    assert len(tasks) == 1
    assert tasks[0].id == failed.id
    assert tasks[0].status == "pending"


class _ScopeSpy:
    def __init__(self) -> None:
        self.checked: list[str] = []

    def check(self, target: str):
        self.checked.append(target)
        return SimpleNamespace(in_scope=True, reason="")


class _LimiterSpy:
    def __init__(self) -> None:
        self.events: list[tuple] = []

    def acquire(self, host=None, tool=None) -> None:
        self.events.append(("acquire", host, tool))

    def release(self, host=None, tool=None) -> None:
        self.events.append(("release", host, tool))


def test_failure_path_preserves_scope_and_rate_limiter_calls():
    storage = FakeStorage()
    scope = _ScopeSpy()
    limiter = _LimiterSpy()
    orch = Orchestrator(
        storage=storage,
        run_tool=lambda task: _outcome(task, timed_out=True, error="timed out"),
        ingest=RecordingHook(),
        scope=scope,
        rate_limiter=limiter,
    )
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id)])
    orch.run_to_completion(run.id)

    [task] = storage.list_tasks(run.id)
    assert task.status == "failed"
    assert scope.checked == ["example.com"]
    assert limiter.events == [
        ("acquire", "example.com", "subdomain_enum"),
        ("release", "example.com", "subdomain_enum"),
    ]


@pytest.mark.parametrize(
    ("timed_out", "error", "exit_code"),
    [
        (True, None, None),
        (False, "adapter failed", 1),
    ],
)
def test_served_execution_propagates_explicit_failure_metadata(
    timed_out, error, exit_code
):
    result = ToolExecution(
        tool="fake",
        command=["fake"],
        exit_code=exit_code,
        raw_output_ref=None,
        artifacts=(),
        timed_out=timed_out,
        error=error,
    )

    class _Adapter:
        def execute(self, task, runner, config, scope):
            return result

    execution = serve_module.ServedExecution(
        adapters={"fake": _Adapter},
        runner=object(),
    )
    outcome = execution.run(Task(type="fake", target="example.com"), scope=_scope())

    assert outcome.timed_out is timed_out
    assert outcome.error == error
