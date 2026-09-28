"""Stage-2 execution semantics: safety, failure handling, dependencies, resumability.

Each test here pins one behaviour that ``core/orchestrator.py`` previously
documented but did not implement, or implemented incorrectly:

* out-of-scope targets are refused before a tool ever runs (the production seam
  used to deny *everything*, because the adapter fell back to an empty scope);
* a tool that raises fails its task instead of wedging the run forever;
* the ``tool`` filter and ``parent_task_id`` dependencies are actually honoured;
* ``resume`` re-queues a crashed task without redundant transitions;
* task/run lifecycle timestamps are recorded identically by both storages;
* adaptive-loop progress is persisted, so a restart does not restart the budget.

Storage-level assertions use the in-memory ``MemoryStorage`` (no database
required). The PostgreSQL-backed equivalents live in ``tests/test_database_live.py``
and are skipped without a live database -- nothing here substitutes for them.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from core.config import ScopeConfig
from core.memory_storage import MemoryStorage
from core.orchestrator import Orchestrator, Storage
from core.scope_guard import ScopeGuard
from core.task_planner import task_fingerprint
from database.models.entities import Run, Task, ToolRun


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


def _run(**overrides) -> Run:
    payload = {
        "program_id": uuid4(),
        "status": "CREATED",
        "target": "example.com",
        "configuration_snapshot": {},
    }
    payload.update(overrides)
    return Run(**payload)


def _task(
    run_id,
    type_: str = "subdomain_enum",
    target: str = "example.com",
    parent: Task | None = None,
    priority: float = 0.0,
) -> Task:
    return Task(
        id=uuid4(),
        run_id=run_id,
        type=type_,
        target=target,
        parent_task_id=parent.id if parent else None,
        priority=priority,
        status="pending",
        fingerprint=task_fingerprint(type_, target),
        reason="planned",
    )


def _tool_run(task: Task) -> ToolRun:
    return ToolRun(
        id=uuid4(),
        task_id=task.id,
        tool_name=task.type,
        command=["argus", task.type, task.target],
        exit_code=0,
        raw_output_ref=f"storage/raw/{task.type}/out.txt",
    )


class RecordingLimiter:
    """Minimal ``RateLimiter`` stand-in that records acquire/release traffic."""

    def __init__(self) -> None:
        self.acquired: list[tuple] = []
        self.released: list[tuple] = []

    def acquire(self, host=None, tool=None) -> None:
        self.acquired.append((host, tool))

    def release(self, host=None, tool=None) -> None:
        self.released.append((host, tool))


@pytest.fixture
def storage() -> MemoryStorage:
    return MemoryStorage()


def orch_durable(storage) -> bool:
    """Whether the orchestrator would treat ``storage`` as persisting loop progress."""
    return Orchestrator(storage=storage, run_tool=_tool_run)._has_durable_loop_progress()


# ---------------------------------------------------------------------------
# item 1: scope enforcement
# ---------------------------------------------------------------------------


def test_out_of_scope_target_is_skipped_and_never_reaches_the_tool(storage) -> None:
    """A denied target must not be executed; it is recorded as ``skipped``.

    ``skipped`` rather than ``failed``: the task was never attempted, so a
    failure would be a false statement about what happened.
    """
    executed: list[Task] = []
    orch = Orchestrator(
        storage=storage,
        run_tool=lambda task: (executed.append(task), _tool_run(task))[1],
        scope=ScopeGuard.from_config(ScopeConfig(allowed_domains=("example.com",))),
    )
    run = orch.create_run(_run())
    denied = _task(run.id, target="evil.com")
    allowed = _task(run.id, target="www.example.com")
    orch.plan(run, [denied, allowed])
    status = orch.run_to_completion(run.id)

    assert status == "COMPLETED"
    by_target = {t.target: t for t in storage.list_tasks(run.id)}
    assert by_target["evil.com"].status == "skipped"
    assert by_target["www.example.com"].status == "completed"
    assert [t.target for t in executed] == ["www.example.com"]


def test_scope_is_derived_from_the_runs_own_configuration_snapshot(storage) -> None:
    """A run is confined to the scope it was created with, not the process default.

    The snapshot is what travels with the run, so this survives a restart and
    applies identically in another process -- which is the whole point of
    persisting it.
    """
    executed: list[Task] = []
    orch = Orchestrator(
        storage=storage,
        run_tool=lambda task: (executed.append(task), _tool_run(task))[1],
    )
    run = orch.create_run(
        _run(configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}})
    )
    orch.plan(run, [_task(run.id, target="evil.com")])
    assert orch.run_to_completion(run.id) == "COMPLETED"

    assert [t.target for t in executed] == []
    assert storage.list_tasks(run.id)[0].status == "skipped"


def test_run_with_no_scope_key_is_unenforced_but_an_empty_scope_denies_everything(
    storage,
) -> None:
    """The two cases are deliberately different, and neither is the default.

    A run that says nothing about scope is unscoped (Phase-5 behaviour, preserved
    for every existing caller). A run that declares an *empty* scope is confined
    to nothing and must be refused -- treating both as "no rules" would silently
    widen a deliberately restrictive configuration.
    """
    unscoped = Orchestrator(storage=storage, run_tool=_tool_run)
    run = unscoped.create_run(_run())
    unscoped.plan(run, [_task(run.id, target="example.com")])
    assert unscoped.run_to_completion(run.id) == "COMPLETED"
    assert storage.list_tasks(run.id)[0].status == "completed"

    empty = Orchestrator(storage=storage, run_tool=_tool_run)
    run2 = empty.create_run(_run(configuration_snapshot={"scope": {}}))
    empty.plan(run2, [_task(run2.id, target="example.com")])
    assert empty.run_to_completion(run2.id) == "COMPLETED"
    assert storage.list_tasks(run2.id)[0].status == "skipped"


def test_excluded_subdomain_is_refused_even_inside_an_allowed_domain(storage) -> None:
    orch = Orchestrator(
        storage=storage,
        run_tool=_tool_run,
        scope=ScopeGuard.from_config(
            ScopeConfig(allowed_domains=("example.com",), excluded=("admin.example.com",))
        ),
    )
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id, target="admin.example.com")])
    orch.run_to_completion(run.id)
    assert storage.list_tasks(run.id)[0].status == "skipped"


def test_run_tool_that_accepts_scope_receives_the_real_guard(storage) -> None:
    """The production seam: an adapter accepting ``scope=`` gets the run's guard.

    This is what makes ``api/serve.py`` work -- its adapter used to fall back to
    its own empty ``ScopeConfig()``, which denies every target, so production
    execution failed closed for a reason nothing could explain.
    """
    seen: list[ScopeGuard] = []

    def run_tool(task, scope=None):
        seen.append(scope)
        return _tool_run(task)

    orch = Orchestrator(
        storage=storage,
        run_tool=run_tool,
        scope=ScopeGuard.from_config(ScopeConfig(allowed_domains=("example.com",))),
    )
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id)])
    orch.run_to_completion(run.id)

    assert len(seen) == 1
    assert seen[0] is not None
    assert bool(seen[0].check("evil.com")) is False
    assert bool(seen[0].check("www.example.com")) is True


def test_single_argument_run_tool_still_supported(storage) -> None:
    """The one-argument ``run_tool`` seam is unchanged (Phase-5/8 compatibility)."""

    def run_tool(task):
        return _tool_run(task)

    orch = Orchestrator(storage=storage, run_tool=run_tool)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id)])
    assert orch.run_to_completion(run.id) == "COMPLETED"
    assert storage.list_tasks(run.id)[0].status == "completed"


# ---------------------------------------------------------------------------
# item 4: tool failures must not wedge the run
# ---------------------------------------------------------------------------


def test_raising_tool_fails_only_its_task_and_the_run_still_completes(storage) -> None:
    def run_tool(task):
        if task.target == "boom.example.com":
            raise RuntimeError("tool exploded")
        return _tool_run(task)

    orch = Orchestrator(storage=storage, run_tool=run_tool)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id, target="boom.example.com"), _task(run.id, target="ok.example.com")])
    status = orch.run_to_completion(run.id)

    assert status == "COMPLETED"
    by_target = {t.target: t for t in storage.list_tasks(run.id)}
    assert by_target["boom.example.com"].status == "failed"
    assert by_target["ok.example.com"].status == "completed"
    # A failed task must not leave a tool_run behind: nothing executed.
    assert [tr.task_id for tr in storage._tool_runs.values()] == [
        by_target["ok.example.com"].id
    ]


def test_run_terminates_when_every_task_fails(storage) -> None:
    """Worst case: all tools raise. The run still reaches a terminal state."""

    def run_tool(task):
        raise RuntimeError("nope")

    orch = Orchestrator(storage=storage, run_tool=run_tool)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id, target="a.example.com"), _task(run.id, target="b.example.com")])
    assert orch.run_to_completion(run.id) == "COMPLETED"
    assert all(t.status == "failed" for t in storage.list_tasks(run.id))


def test_replanning_a_failed_task_requeues_it_instead_of_inserting_a_duplicate(
    storage,
) -> None:
    """Re-issuing a failed fingerprint must reuse the row, not create a second one.

    This is the ``tasks_run_fingerprint_uq`` guarantee from migration 0003. Before,
    re-proposing a failed task produced a second row with the same fingerprint,
    which PostgreSQL rejects with ``UniqueViolation`` -- so the documented "no
    lost work" retry path could not actually run against the real database.
    """
    attempts = {"n": 0}

    def run_tool(task):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("transient")
        return _tool_run(task)

    orch = Orchestrator(storage=storage, run_tool=run_tool)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id, target="retry.example.com")])
    while orch.get_run(run.id).status != "EXECUTING":
        orch.advance(run.id)
    orch._execute_pending(orch.get_run(run.id), None)
    assert storage.list_tasks(run.id)[0].status == "failed"

    # The planner re-proposes the same work (as a retry would).
    orch.plan(run, [_task(run.id, target="retry.example.com")])

    tasks = storage.list_tasks(run.id)
    assert len(tasks) == 1, "a retry must not insert a second row for one fingerprint"
    assert tasks[0].status == "pending"
    # And a stale completed_at from the failed attempt must not survive.
    assert tasks[0].completed_at is None

    orch._execute_pending(orch.get_run(run.id), None)
    assert storage.list_tasks(run.id)[0].status == "completed"
    assert attempts["n"] == 2


# ---------------------------------------------------------------------------
# item 3: tool filter and parent dependencies
# ---------------------------------------------------------------------------


def test_tool_filter_executes_only_matching_task_types(storage) -> None:
    executed: list[str] = []
    orch = Orchestrator(
        storage=storage,
        run_tool=lambda task: (executed.append(task.type), _tool_run(task))[1],
    )
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id, type_="dns_resolve"), _task(run.id, type_="http_probe")])
    orch.run_to_completion(run.id, tool="dns_resolve")

    assert executed == ["dns_resolve"]
    by_type = {t.type: t for t in storage.list_tasks(run.id)}
    assert by_type["dns_resolve"].status == "completed"
    assert by_type["http_probe"].status == "pending"


def test_run_to_completion_terminates_when_the_tool_filter_matches_nothing(storage) -> None:
    """Regression: a filter that excludes everything must not spin forever."""
    orch = Orchestrator(storage=storage, run_tool=_tool_run)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id, type_="http_probe")])
    assert orch.run_to_completion(run.id, tool="dns_resolve") == "COMPLETED"
    assert storage.list_tasks(run.id)[0].status == "pending"


def test_child_waits_for_its_parent_and_runs_in_the_same_pass(storage) -> None:
    executed: list[str] = []
    orch = Orchestrator(
        storage=storage,
        run_tool=lambda task: (executed.append(task.type), _tool_run(task))[1],
    )
    run = orch.create_run(_run())
    parent = _task(run.id, type_="subdomain_enum", target="example.com")
    child = _task(run.id, type_="http_probe", target="www.example.com", parent=parent)
    orch.plan(run, [child, parent])  # child proposed first on purpose
    assert orch.run_to_completion(run.id) == "COMPLETED"

    assert executed == ["subdomain_enum", "http_probe"]
    assert all(t.status == "completed" for t in storage.list_tasks(run.id))


def test_child_of_a_failed_parent_is_never_executed(storage) -> None:
    """Executing a child against input that never arrived is worse than deferring it."""
    executed: list[str] = []

    def run_tool(task):
        executed.append(task.type)
        if task.type == "subdomain_enum":
            raise RuntimeError("parent failed")
        return _tool_run(task)

    orch = Orchestrator(storage=storage, run_tool=run_tool)
    run = orch.create_run(_run())
    parent = _task(run.id, type_="subdomain_enum")
    child = _task(run.id, type_="http_probe", parent=parent)
    orch.plan(run, [parent, child])
    assert orch.run_to_completion(run.id) == "COMPLETED"

    assert executed == ["subdomain_enum"]
    by_type = {t.type: t for t in storage.list_tasks(run.id)}
    assert by_type["subdomain_enum"].status == "failed"
    assert by_type["http_probe"].status == "pending"


def test_task_with_a_dangling_parent_reference_is_not_awaited_forever(storage) -> None:
    orch = Orchestrator(storage=storage, run_tool=_tool_run)
    run = orch.create_run(_run())
    orphan = _task(run.id, type_="http_probe")
    orphan.parent_task_id = uuid4()  # parent that was never planned
    orch.plan(run, [orphan])
    assert orch.run_to_completion(run.id) == "COMPLETED"
    assert storage.list_tasks(run.id)[0].status == "completed"


# ---------------------------------------------------------------------------
# item 2: rate limiting
# ---------------------------------------------------------------------------


def test_rate_limiter_wraps_every_tool_call_with_the_task_host_and_type(storage) -> None:
    limiter = RecordingLimiter()
    orch = Orchestrator(storage=storage, run_tool=_tool_run, rate_limiter=limiter)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id, type_="dns_resolve", target="www.example.com")])
    orch.run_to_completion(run.id)

    assert limiter.acquired == [("www.example.com", "dns_resolve")]
    assert limiter.released == [("www.example.com", "dns_resolve")]


def test_rate_limit_slot_is_released_even_when_the_tool_raises(storage) -> None:
    """A leaked slot would throttle every later task on that host forever."""

    def run_tool(task):
        raise RuntimeError("boom")

    limiter = RecordingLimiter()
    orch = Orchestrator(storage=storage, run_tool=run_tool, rate_limiter=limiter)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id, target="www.example.com")])
    orch.run_to_completion(run.id)

    assert limiter.acquired == [("www.example.com", "subdomain_enum")]
    assert limiter.released == [("www.example.com", "subdomain_enum")]


def test_out_of_scope_task_does_not_consume_a_rate_limit_slot(storage) -> None:
    limiter = RecordingLimiter()
    orch = Orchestrator(
        storage=storage,
        run_tool=_tool_run,
        rate_limiter=limiter,
        scope=ScopeGuard.from_config(ScopeConfig(allowed_domains=("example.com",))),
    )
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id, target="evil.com")])
    orch.run_to_completion(run.id)
    assert limiter.acquired == []


# ---------------------------------------------------------------------------
# item 5: resume
# ---------------------------------------------------------------------------


def test_resume_requeues_a_crashed_task_exactly_once(storage) -> None:
    """Two meaningful transitions, no redundant third write.

    The old code wrote ``failed`` then ``pending`` then ``pending`` again. The
    duplicate was pure noise, but pinning the exact call sequence is what stops
    it (or any equivalent redundancy) creeping back.
    """
    calls: list[tuple] = []

    class TrackingStorage(MemoryStorage):
        def set_task_status(self, task_id, status):  # type: ignore[override]
            calls.append((task_id, status))
            super().set_task_status(task_id, status)

    tracking = TrackingStorage()
    orch = Orchestrator(storage=tracking, run_tool=_tool_run)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id)])
    while orch.get_run(run.id).status != "EXECUTING":
        orch.advance(run.id)
    task = tracking.list_tasks(run.id)[0]
    tracking.set_task_status(task.id, "running")
    calls.clear()

    assert orch.resume(run.id) == "COMPLETED"
    assert calls.count((task.id, "failed")) == 1
    assert calls.count((task.id, "pending")) == 1
    # ... and the task really did finish, not merely get re-queued.
    assert [t.status for t in tracking.list_tasks(run.id)] == ["completed"]


def test_resume_does_not_touch_completed_tasks(storage) -> None:
    orch = Orchestrator(storage=storage, run_tool=_tool_run)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id)])
    assert orch.run_to_completion(run.id) == "COMPLETED"
    assert orch.resume(run.id) == "COMPLETED"
    assert [t.status for t in storage.list_tasks(run.id)] == ["completed"]


def test_resume_of_an_unknown_run_raises(storage) -> None:
    orch = Orchestrator(storage=storage, run_tool=_tool_run)
    with pytest.raises(Exception):
        orch.resume(uuid4())


# ---------------------------------------------------------------------------
# item 7: lifecycle timestamp parity
# ---------------------------------------------------------------------------


def test_completed_task_records_started_and_completed_timestamps(storage) -> None:
    orch = Orchestrator(storage=storage, run_tool=_tool_run)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id)])
    orch.run_to_completion(run.id)

    task = storage.list_tasks(run.id)[0]
    assert task.status == "completed"
    assert task.started_at is not None
    assert task.completed_at is not None
    assert task.started_at <= task.completed_at


def test_skipped_task_is_not_stamped_as_started_but_is_stamped_completed(storage) -> None:
    """A refused task never ran, so ``started_at`` would be a lie."""
    orch = Orchestrator(
        storage=storage,
        run_tool=_tool_run,
        scope=ScopeGuard.from_config(ScopeConfig(allowed_domains=("example.com",))),
    )
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id, target="evil.com")])
    orch.run_to_completion(run.id)

    task = storage.list_tasks(run.id)[0]
    assert task.status == "skipped"
    assert task.started_at is None
    assert task.completed_at is not None


def test_requeued_task_clears_a_stale_completed_at(storage) -> None:
    task = _task(uuid4())
    storage.insert_tasks([task])
    storage.set_task_status(task.id, "failed")
    assert storage.list_tasks(task.run_id)[0].completed_at is not None

    storage.set_task_status(task.id, "pending")
    retried = storage.list_tasks(task.run_id)[0]
    assert retried.status == "pending"
    assert retried.completed_at is None, "a re-queued task is not finished"


def test_failed_task_records_both_timestamps(storage) -> None:
    def run_tool(task):
        raise RuntimeError("boom")

    orch = Orchestrator(storage=storage, run_tool=run_tool)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id)])
    orch.run_to_completion(run.id)

    task = storage.list_tasks(run.id)[0]
    assert task.status == "failed"
    assert task.started_at is not None
    assert task.completed_at is not None


def test_completed_run_records_completed_at(storage) -> None:
    orch = Orchestrator(storage=storage, run_tool=_tool_run)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id)])
    assert orch.run_to_completion(run.id) == "COMPLETED"
    assert storage.get_run(run.id).completed_at is not None


def test_non_terminal_run_status_does_not_stamp_completed_at(storage) -> None:
    run = orch_create(storage)
    storage.set_run_status(run.id, "EXECUTING")
    assert storage.get_run(run.id).completed_at is None


def orch_create(storage) -> Run:
    orch = Orchestrator(storage=storage, run_tool=_tool_run)
    return orch.create_run(_run())


# ---------------------------------------------------------------------------
# item 6: persisted adaptive-loop progress
# ---------------------------------------------------------------------------


def test_loop_progress_is_persisted_on_the_run(storage) -> None:
    def analysis(run, current):
        return [] if current else [_task(run.id, target="www.example.com")]

    orch = Orchestrator(storage=storage, run_tool=_tool_run, analysis=analysis)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id)])

    orch.run_to_completion(run.id)
    stored = storage.get_run(run.id)
    assert stored.loop_pass >= 1
    assert stored.pass_new_tasks is False  # the final pass added nothing


def test_a_fresh_orchestrator_resumes_the_loop_from_persisted_progress(storage) -> None:
    """The point of persisting progress: a new process picks up where the last stopped.

    Before, ``_loop_pass`` lived on the orchestrator instance, so a restarted
    process began at pass 0 and the ``max_loop_passes`` budget was effectively
    unlimited across restarts.
    """
    def analysis(run, current):
        return [_task(run.id, target=f"fragment-{len(current)}.example.com")]

    first = Orchestrator(storage=storage, run_tool=_tool_run, analysis=analysis)
    first.max_loop_passes = 3
    run = first.create_run(_run())
    first.plan(run, [_task(run.id)])

    # One pass by hand, leaving the run parked at ANALYZING.
    while first.get_run(run.id).status != "ANALYZING":
        first.advance(run.id)
    first._advance_step(run.id)  # runs the analysis pass, -> PLANNING
    mid = storage.get_run(run.id)
    assert mid.loop_pass == 1
    assert mid.pass_new_tasks is True

    # A brand-new orchestrator over the same storage must not reset the budget.
    second = Orchestrator(storage=storage, run_tool=_tool_run, analysis=analysis)
    second.max_loop_passes = 3
    assert second.get_run(run.id).loop_pass == 1
    assert second.run_to_completion(run.id) == "CANCELLED"
    assert storage.get_run(run.id).loop_pass >= 3


def test_storage_without_the_optional_write_still_works() -> None:
    """A storage predating Phase 8 keeps working -- process-local, not broken."""

    class LegacyStorage(MemoryStorage):
        """Simulates a storage predating Phase 8: the contract stub, unimplemented."""

        set_run_progress = Storage.set_run_progress

    storage = LegacyStorage()
    # Same check the orchestrator uses to decide durability.
    assert type(storage).set_run_progress is Storage.set_run_progress
    assert not orch_durable(LegacyStorage())

    def analysis(run, current):
        return [_task(run.id, target=f"fragment-{len(current)}.example.com")]

    orch = Orchestrator(storage=storage, run_tool=_tool_run, analysis=analysis)
    orch.max_loop_passes = 3
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id)])
    assert orch.run_to_completion(run.id) == "CANCELLED"
    # Progress was never written, exactly as the contract permits.
    assert storage.get_run(run.id).loop_pass == 0
