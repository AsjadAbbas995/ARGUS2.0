"""Initial Orchestrator (``08_ORCHESTRATOR.md`` §run state machine / task lifecycle / resumability).

Phase-5 scope: a deterministic run/task lifecycle **without AI**. The orchestrator owns:

* the run state machine (``CREATED → VALIDATING → INITIALIZING → RECONNING → ANALYZING →
  PLANNING → EXECUTING → CORRELATING → PRIORITIZING → WAITING_FOR_NEXT_TASK → COMPLETED``,
  plus ``FAILED``/``CANCELLED``);
* task scheduling: it hands the *planner* the same deterministic inputs and executes the
  returned order, so planning twice yields the same plan;
* **resumability** — on restart it re-evaluates tasks found ``running`` instead of treating
  them as complete, and the run re-enters the state machine at the checkpoint status recorded
  in ``runs.status``. The planner's completed-fingerprint suppression guarantees no duplicate
  work; re-issued in-flight/failed fingerprints guarantee no lost work.

The orchestrator is deliberately decoupled from the database: it takes a *storage* object
exposing ``runs``/``tasks``/``tool_runs`` (the ``Repositories`` facade implements it; tests
inject an in-memory fake), and a ``ToolRunner``-like ``run_tool`` callable.

Phase-8 scope ("10_IMPLEMENTATION_PLAN.md" §Phase 8 — Adaptive Recon Loop): an optional
``analysis`` hook turns the walk into the adaptive loop from ``08_ORCHESTRATOR.md`` / "03_RECON_PIPELINE.md"
§27 — at every ``ANALYZING`` step the hook proposes new tasks, the planner fingerprint-dedupes
them, and ``WAITING_FOR_NEXT_TASK`` re-enters ``RECONNING`` while passes keep generating new
work, reaching ``COMPLETED`` only when re-analysis adds nothing. Task-level fingerprinting
prevents infinite loops (08_ORCHESTRATOR.md §Task Deduplication) and ``max_loop_passes`` is the
graceful instability/safety limit. Without a hook the phase-5 linear walk is unchanged.
"""

from __future__ import annotations

import inspect
import logging
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional
from uuid import UUID

from core.config import ScopeConfig
from core.rate_limiter import RateLimiter
from core.scope_guard import ScopeGuard, extract_host
from core.task_planner import order_tasks, plan_tasks
from database.models.entities import Hypothesis, Run, Task, ToolRun

log = logging.getLogger(__name__)

# Run-level state machine, in legal forward order (08_ORCHESTRATOR.md).
_RUN_STEPS = [
    "CREATED",
    "VALIDATING",
    "INITIALIZING",
    "RECONNING",
    "ANALYZING",
    "PLANNING",
    "EXECUTING",
    "CORRELATING",
    "PRIORITIZING",
    "WAITING_FOR_NEXT_TASK",
]
_RUN_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}
_TASK_RUNNABLE = {"pending"}
#: A task counts as "done" for dependency gating only once it genuinely succeeded.
#: Mirrors ``task_planner._FINISHED``; a failed or skipped parent does not unblock
#: its children, because doing so would execute work whose input never arrived.
_TASK_COMPLETED = {"completed"}
#: Statuses that mean the task actually began doing work, so ``started_at`` is
#: stamped on entry. ``skipped`` is deliberately absent: a task refused by the
#: scope guard never ran, and must not look as though it did.
_TASK_STARTED = {"running", "completed", "failed"}
#: Statuses that end a task's lifecycle, so ``completed_at`` is stamped. Mirrors
#: the ``tasks.status`` CHECK in migration 0001. The storage implementations import
#: this so PostgreSQL and the in-memory double record identical lifecycle
#: timestamps -- if they drift, their task histories stop being comparable.
_TASK_TERMINAL = {"completed", "failed", "skipped", "cancelled"}
#: Statuses that must never be re-queued by a planning pass: either the work is
#: finished, deliberately abandoned, or still legitimately in flight.
_TASK_SETTLED = {"completed", "skipped", "cancelled", "running"}

# A Phase-8 adaptive-loop analysis hook: given the run and its current task list, it proposes
# new reconnaissance tasks (the planner re-fingerprints and dedupes them). ``None`` disables
# the loop entirely, preserving Phase-5 behaviour.
AnalysisHook = Callable[["Run", list["Task"]], list["Task"]]


@dataclass(frozen=True)
class ToolRunOutcome:
    """A seam result carrying the execution's normalized artifacts alongside its ToolRun.

    Phase 14: seams that own the adapter (``api.serve.ServedExecution``) already hold
    ``ToolExecution.artifacts``, which used to be discarded on the way out. Returning
    this wrapper surfaces them **without** changing the pinned ``(task) -> ToolRun``
    seam contract: the orchestrator still accepts a bare :class:`ToolRun` from every
    existing seam and test double, and simply ingests nothing for it.
    """

    tool_run: ToolRun
    artifacts: tuple = ()
    timed_out: bool = False
    error: Optional[str] = None


def _execution_failed(outcome: Any) -> bool:
    """Whether a seam outcome explicitly reports an execution failure.

    Only :class:`ToolRunOutcome` can carry this metadata. A bare ``ToolRun`` keeps
    the legacy contract, including the rule that a non-zero exit code alone is
    recorded but does not fail the task.
    """
    return isinstance(outcome, ToolRunOutcome) and bool(
        outcome.timed_out or outcome.error
    )


#: An ingestion callback supplied by the served wiring: it maps artifacts to
#: canonical records and persists them with their evidence. It runs *inside* the
#: orchestrator's transaction, so the ToolRun, the evidence, the graph rows and the
#: task's terminal state commit or roll back together.
IngestHook = Callable[["Task", ToolRun, tuple, "Run", Optional[ScopeGuard]], None]


def _split_outcome(value: Any) -> tuple[ToolRun, tuple]:
    """Accept either a bare ``ToolRun`` (every pre-Phase-14 seam) or a ``ToolRunOutcome``.

    Backwards compatibility is the point: the Phase-5/8 seam contract is
    ``(task) -> ToolRun`` and is pinned by existing tests, so Phase 14 reads the
    artifacts only when a seam chooses to return them.
    """
    if isinstance(value, ToolRunOutcome):
        return value.tool_run, tuple(value.artifacts)
    return value, ()


def _transaction_for(storage: Any):
    """The storage's transaction context, or a no-op when it has none.

    ``transaction()`` is optional on the ``Storage`` contract, exactly like
    ``set_run_progress`` (Phase 8): a Storage predating Phase 14 -- including every
    in-test double -- keeps the original non-atomic three-write sequence.
    """
    factory = getattr(storage, "transaction", None)
    return factory() if callable(factory) else nullcontext()


class OrchestratorError(Exception):
    """Base error for orchestration failures."""


class RunNotFoundError(OrchestratorError):
    """No such run in storage."""


class BadRunTransition(OrchestratorError):
    """A run tried to leave its legal state machine / terminal state."""


class Storage:
    """Minimal storage contract the orchestrator depends on (implemented by Repositories)."""

    def __init__(self) -> None:
        raise NotImplementedError

    def create_run(self, run: Run) -> Run: ...
    def get_run(self, run_id: UUID) -> Optional[Run]: ...
    def list_runs(self) -> list[Run]: ...
    def set_run_status(self, run_id: UUID, status: str) -> None: ...
    def set_run_progress(
        self, run_id: UUID, loop_pass: int, pass_new_tasks: bool
    ) -> None:
        """Persist adaptive-loop progress (Phase 8) so it survives a restart.

        Optional: a ``Storage`` predating Phase 8 need not implement it, and the
        orchestrator falls back to process-local state when it is absent, which
        keeps existing third-party/in-test doubles valid.
        """
        ...

    def insert_tasks(self, tasks: Iterable[Task]) -> None: ...
    def list_tasks(self, run_id: UUID) -> list[Task]: ...
    def list_tasks_by_status(self, run_id: UUID, status: str) -> list[Task]: ...
    def set_task_status(self, task_id: UUID, status: str) -> None: ...

    def insert_tool_run(self, tr: ToolRun) -> ToolRun: ...
    def finalize_tool_run(
        self, tool_run_id: UUID, exit_code: int, raw_output_ref: Optional[str]
    ) -> None: ...

    def insert_hypothesis(self, hypothesis: Hypothesis) -> Hypothesis: ...
    def get_hypothesis(
        self, run_id: UUID, hypothesis_id: UUID
    ) -> Optional[Hypothesis]: ...
    def list_hypotheses(self, run_id: UUID) -> list[Hypothesis]: ...
    def set_hypothesis_review(
        self,
        run_id: UUID,
        hypothesis_id: UUID,
        review_status: str,
        review_reason: Optional[str],
        truth_label: str,
        status: str,
    ) -> Optional[Hypothesis]: ...


@dataclass
class Orchestrator:
    storage: Storage
    run_tool: Callable[[Task], ToolRun]  # (task) -> ToolRun; Phase-5 deterministic demos
    analysis: Optional[AnalysisHook] = None  # Phase-8 adaptive loop; None keeps Phase-5 behaviour
    max_loop_passes: int = 32  # instability/safety limit (01_PRODUCT_SPEC.md §10)
    scope: Optional[ScopeGuard] = None
    """Safety guard enforced *before* any tool runs.

    ``None`` means "no scope enforcement", preserving the Phase-5/8 behaviour the
    existing tests pin. When set, a task whose ``target`` is denied is marked
    ``skipped`` and never handed to ``run_tool``. ``api/serve.py`` builds this per
    run from the run's own ``configuration_snapshot["scope"]`` so the run cannot
    execute outside the scope it was created with.
    """
    rate_limiter: Optional[RateLimiter] = None
    """Optional per-host/per-tool limiter applied around every ``run_tool`` call."""
    ingest: Optional[IngestHook] = None
    """Optional Phase-14 evidence ingestion, applied inside the task transaction.

    ``None`` preserves the pre-Phase-14 behaviour exactly: a ``ToolRun`` is
    recorded and the task completes with no graph facts, which is what every
    Phase-5/8 seam and test double relies on. When supplied, it is called with
    ``(task, tool_run, artifacts, run, scope)`` and is expected to persist the
    canonical records and their evidence through the *same* storage/transaction
    that records the ``ToolRun``, so a failure can never leave a task marked
    completed while its facts are missing.
    """
    _loop_pass: int = field(default=0, init=False, repr=False, compare=False)
    _pass_new_tasks: bool = field(default=False, init=False, repr=False, compare=False)
    _run_tool_accepts_scope: bool = field(default=False, init=False, repr=False, compare=False)
    _run_tool_accepts_config: bool = field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        # ``run_tool`` is a one-argument seam (``task -> ToolRun``) pinned by the
        # Phase-5/8 tests. Adapters that validate scope themselves (the ``recon``
        # tools) can also accept a ``scope=`` keyword, so probe the signature once
        # and hand the run's real guard to those adapters. A seam may equally accept
        # ``config=``, which receives the run's own persisted configuration so the
        # adapter executes with the configuration the run was created with rather
        # than one the process happens to hold. Single-argument ``run_tool``
        # callables keep working unchanged.
        try:
            params = inspect.signature(self.run_tool).parameters
        except (TypeError, ValueError):  # builtins / C callables
            self._run_tool_accepts_scope = False
            self._run_tool_accepts_config = False
            return
        takes_kwargs = any(
            p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()
        )
        self._run_tool_accepts_scope = "scope" in params or takes_kwargs
        self._run_tool_accepts_config = "config" in params or takes_kwargs

    # -- run lifecycle ------------------------------------------------------

    def create_run(self, run: Run, planned: Iterable[Task] = ()) -> Run:
        """Persist a new run (CREATED) and, if given, seed its first planned tasks."""
        stored = self.storage.create_run(run)
        self.storage.set_run_status(stored.id, "CREATED")
        if planned:
            self.plan(stored, planned)
        return stored

    def start(self, run_id: UUID) -> None:
        """Begin the run: the first deterministic state transition (CREATED → VALIDATING)."""
        self._advance_step(run_id)

    # -- planning / scheduling ----------------------------------------------

    def plan(self, run: Run, planned: Iterable[Task]) -> list[Task]:
        """Fingerprint/dedupe/order ``planned`` for ``run`` and persist them (if not already done).

        Returns the ordered task list. Tasks whose fingerprint already completed are dropped by
        the planner (``plan_tasks``); the orchestrator just persists whatever the planner emits.

        A re-issued *non-completed* fingerprint is a **retry** ("no lost work"), not a new task.
        ``plan_tasks`` re-emits it, but persisting that would collide with the
        ``tasks_run_fingerprint_uq`` partial unique index (0003), so the existing row is
        re-queued in place instead of inserting a duplicate.
        """
        existing = self.storage.list_tasks(run.id)
        ordered = plan_tasks(
            run.id,
            planned,
            existing,
            config=run.configuration_snapshot or {},
        )
        by_fingerprint = {t.fingerprint: t for t in existing if t.fingerprint}
        fresh: list[Task] = []
        for task in ordered:
            prior = by_fingerprint.get(task.fingerprint) if task.fingerprint else None
            if prior is not None:
                if prior.status not in _TASK_SETTLED:
                    self.storage.set_task_status(prior.id, "pending")
                continue
            fresh.append(task)
        if fresh:
            self.storage.insert_tasks(fresh)
        return ordered

    # -- deterministic walk ------------------------------------------------

    def _advance_step(self, run_id: UUID) -> str:
        run = self._require_run(run_id)
        if run.status in _RUN_TERMINAL:
            raise BadRunTransition(f"run {run_id} is terminal ({run.status})")
        if run.status == "ANALYZING" and self.analysis is not None:
            self._run_analysis_pass(run_id)
        if run.status == "WAITING_FOR_NEXT_TASK":
            return self._next_pass(run_id)
        idx = _RUN_STEPS.index(run.status) if run.status in _RUN_STEPS else -1
        next_step = _RUN_STEPS[idx + 1] if idx >= 0 and idx + 1 < len(_RUN_STEPS) else None
        if next_step is None:
            raise BadRunTransition(f"no step after {run.status}")
        self.storage.set_run_status(run_id, next_step)
        return next_step

    def _run_analysis_pass(self, run_id: UUID) -> bool:
        """Run the analysis hook and enqueue its proposed (fingerprint-deduped) tasks.

        Returns whether the pass generated any *new* (never-seen-in-this-run) fingerprint — the
        adaptive-loop progress signal ("COMPLETED only when re-analysis adds nothing new",
        08_ORCHESTRATOR.md). ``plan`` deliberately re-issues pending/in-flight/failed
        fingerprints ("no lost work", Phase 5), so the signal is the set of fingerprints the
        pass introduced that were not present in *any* status before it.

        Both the pass counter and the signal are written back to the run so a restart resumes
        the loop where it stopped instead of replaying the full pass budget.
        """
        run = self._require_run(run_id)
        loop_pass, _prior_signal = self._loop_progress(run)
        before = {t.fingerprint for t in self.storage.list_tasks(run.id) if t.fingerprint}
        proposed = self.analysis(run, self.storage.list_tasks(run.id))
        self.plan(run, proposed)
        after = {t.fingerprint for t in self.storage.list_tasks(run.id) if t.fingerprint}
        produced_new = bool(after - before)
        self._save_loop_progress(run.id, loop_pass + 1, produced_new)
        return produced_new

    def _save_loop_progress(self, run_id: UUID, loop_pass: int, new_tasks: bool) -> None:
        """Write loop progress to storage, falling back to process-local state.

        ``set_run_progress`` is an optional part of the storage contract, so a
        ``Storage`` that does not override it still works -- it just remains as
        restart-fragile as it always was, instead of raising.
        """
        if not self._has_durable_loop_progress():
            self._loop_pass = loop_pass
            self._pass_new_tasks = new_tasks
            return
        self.storage.set_run_progress(run_id, loop_pass, new_tasks)

    def _has_durable_loop_progress(self) -> bool:
        """Whether this storage actually persists loop progress.

        Checks for a real *override* rather than mere presence: ``Storage`` itself
        declares ``set_run_progress`` as an optional no-op, so a storage that
        inherits the stub without implementing it must not be treated as durable
        (its progress would be silently discarded).
        """
        return getattr(type(self.storage), "set_run_progress", None) is not Storage.set_run_progress

    def _loop_progress(self, run: Run) -> tuple[int, bool]:
        """Loop progress for ``run``: from the persisted run when it is durable."""
        if not self._has_durable_loop_progress():
            return self._loop_pass, self._pass_new_tasks
        return run.loop_pass, run.pass_new_tasks

    def _next_pass(self, run_id: UUID) -> str:
        """Adaptive-loop stop decision at ``WAITING_FOR_NEXT_TASK`` (08_ORCHESTRATOR.md).

        Re-enter ``RECONNING`` while a pass generated new (non-duplicate) tasks; reach
        ``COMPLETED`` once re-analysis produces nothing new. ``max_loop_passes`` is the
        instability/safety limit — exceeding it ends the run gracefully as ``CANCELLED``
        (01_PRODUCT_SPEC.md §10). Without an ``analysis`` hook the run always completes,
        preserving Phase-5 behaviour.
        """
        run = self._require_run(run_id)
        loop_pass, pass_new_tasks = self._loop_progress(run)
        if self.analysis is not None and pass_new_tasks:
            if loop_pass >= self.max_loop_passes:
                self.storage.set_run_status(run_id, "CANCELLED")
                return "CANCELLED"
            self.storage.set_run_status(run_id, "RECONNING")
            return "RECONNING"
        self.storage.set_run_status(run_id, "COMPLETED")
        return "COMPLETED"

    def advance(self, run_id: UUID, tool: Optional[str] = None) -> str:
        """Advance the run one deterministic step.

        At ``EXECUTING`` this runs the next pending tool task (when one exists and ``tool`` is
        supplied); otherwise it only transitions the run state, so state-machine transitions are
        observable and testable without executing any tool.
        """
        run = self._require_run(run_id)
        if run.status in _RUN_TERMINAL:
            return run.status
        if run.status == "EXECUTING":
            self._execute_pending(run, tool)
            return self._require_run(run_id)
        self._advance_step(run_id)
        return self._require_run(run_id)

    def run_to_completion(self, run_id: UUID, tool: Optional[str] = None) -> str:
        """Walk the whole state machine to COMPLETED, executing tasks at the EXECUTING step."""
        while True:
            run = self._require_run(run_id)
            if run.status in _RUN_TERMINAL:
                return run.status
            if run.status == "EXECUTING":
                if self._execute_pending(run, tool):
                    continue
                # Nothing ran, so nothing more can run in this pass: the remaining
                # pending tasks are either excluded by the ``tool`` filter or still
                # blocked on an unfinished parent. Walking the state machine forward
                # is the only way out -- waiting for them here would spin forever.
                self._advance_step(run_id)
                continue
            self._advance_step(run_id)

    # -- resumability -------------------------------------------------------

    def resume(self, run_id: UUID) -> str:
        """Re-enter a run after a crash/interruption without losing or duplicating work.

        Tasks still ``running`` from an in-flight crash are **re-evaluated as failed** (never
        blindly assumed complete); the run returns to ``EXECUTING``/``CORRELATING`` so the next
        deterministic pass retries them. Completed fingerprints stay suppressed, so no task is
        regenerated; everything else is re-issued, so nothing is lost.
        """
        for task in self.storage.list_tasks_by_status(run_id, "running"):
            # Two distinct, non-redundant transitions. First record that the task
            # did not survive the interruption (an in-flight task must never be
            # assumed complete), then re-queue it so the next EXECUTING pass
            # retries it. The third, duplicated ``pending`` write this used to
            # perform was a pure no-op that also re-stamped nothing.
            self.storage.set_task_status(task.id, "failed")
            self.storage.set_task_status(task.id, "pending")
        run = self._require_run(run_id)
        if run.status in _RUN_TERMINAL:
            return run.status
        self.storage.set_run_status(run_id, "EXECUTING")
        return self.run_to_completion(run_id)

    # -- read/control surface (API + operator dashboard) --------------------

    def get_run(self, run_id: UUID) -> Optional[Run]:
        """Read a run through the authoritative storage layer."""
        return self.storage.get_run(run_id)

    def list_runs(self) -> list[Run]:
        """Enumerate every persisted run (never an orchestrator-local registry)."""
        return self.storage.list_runs()

    def list_tasks(self, run_id: UUID) -> list[Task]:
        return self.storage.list_tasks(run_id)

    def record_hypothesis(self, hypothesis: Hypothesis) -> Hypothesis:
        """Persist an AI-generated hypothesis as a run-scoped review item."""
        return self.storage.insert_hypothesis(hypothesis)

    def list_hypotheses(self, run_id: UUID) -> list[Hypothesis]:
        return self.storage.list_hypotheses(run_id)

    def approve_hypothesis(
        self, run_id: UUID, hypothesis_id: UUID
    ) -> Optional[Hypothesis]:
        """Record operator approval: the documented human/safe-validation boundary.

        Per ``05_DATA_MODEL.md`` a hypothesis reaches ``VALIDATED_FINDING`` only through
        human/safe validation, so approval performs that explicit transition. Returns
        ``None`` when the hypothesis does not exist in this run or is no longer pending.
        """
        current = self.storage.get_hypothesis(run_id, hypothesis_id)
        if current is None or current.review_status != "pending":
            return None
        return self.storage.set_hypothesis_review(
            run_id,
            hypothesis_id,
            review_status="approved",
            review_reason=current.review_reason,
            truth_label="VALIDATED_FINDING",
            status="validated",
        )

    def reject_hypothesis(
        self, run_id: UUID, hypothesis_id: UUID, reason: str = ""
    ) -> Optional[Hypothesis]:
        """Record operator rejection with its reason. Analytical state is unchanged."""
        current = self.storage.get_hypothesis(run_id, hypothesis_id)
        if current is None or current.review_status != "pending":
            return None
        return self.storage.set_hypothesis_review(
            run_id,
            hypothesis_id,
            review_status="rejected",
            review_reason=str(reason),
            truth_label=current.truth_label,
            status=current.status,
        )

    # -- internals ----------------------------------------------------------

    def _require_run(self, run_id: UUID) -> Run:
        run = self.storage.get_run(run_id)
        if run is None:
            raise RunNotFoundError(f"unknown run {run_id}")
        return run

    def _runnable_tasks(self, run: Run, tool: Optional[str]) -> list[Task]:
        """Pending tasks that may run *now*, in deterministic order.

        Two filters, both long-overdue:

        * ``tool`` -- the caller-supplied tool filter that ``advance``/
          ``run_to_completion`` document but used to ignore entirely; a mismatched
          task must not execute.
        * ``parent_task_id`` -- ``order_tasks`` only *sorts* parents before
          children, it never gates execution, so a child of an unfinished parent
          used to run anyway. Gating happens in ``_execute_pending`` against a live
          ``done`` set, because a parent earlier in the same batch satisfies its
          own children without costing an extra pass.
        """
        pending = [t for t in self.storage.list_tasks(run.id) if t.status in _TASK_RUNNABLE]
        if tool is not None:
            pending = [t for t in pending if t.type == tool]
        if not pending:
            return []
        return order_tasks(pending)

    def _scope_for(self, run: Run) -> Optional[ScopeGuard]:
        """The safety guard in force for ``run``, or ``None`` if it is unscoped.

        An explicitly injected ``scope`` always wins. Otherwise the run's own
        ``configuration_snapshot["scope"]`` is authoritative, so a run is confined
        to the scope it was created with even after a restart or in a different
        process -- the snapshot is what travels with the run.

        A run whose snapshot declares no ``scope`` key is left unenforced: the
        Phase-5/8 behaviour the existing tests pin. Note that this is *not* the
        same as an empty scope, which denies everything -- a run that asks for an
        empty scope is a configuration mistake, and silently allowing it would be
        the unsafe reading of the same word.
        """
        if self.scope is not None:
            return self.scope
        snapshot = run.configuration_snapshot or {}
        if "scope" not in snapshot:
            return None
        return ScopeGuard.from_config(ScopeConfig.from_dict(snapshot.get("scope")))

    def _execute_pending(self, run: Run, tool: Optional[str]) -> bool:
        ordered = self._runnable_tasks(run, tool)
        if not ordered:
            return False
        scope = self._scope_for(run)
        all_tasks = self.storage.list_tasks(run.id)
        known = {t.id for t in all_tasks}
        done = {t.id for t in all_tasks if t.status in _TASK_COMPLETED}
        executed = False
        for task in ordered:
            # Dependency gate: a parent that is still in flight (or failed) leaves
            # this child for a later pass rather than running it against input that
            # does not exist yet. A dangling parent id is not waited on forever.
            if (
                task.parent_task_id is not None
                and task.parent_task_id in known
                and task.parent_task_id not in done
            ):
                continue
            # Safety first: a denied target is never handed to a tool. Marked
            # ``skipped`` (not ``failed``) because it was never attempted; the
            # planner re-proposes it, but an existing fingerprint is not "new
            # work", so the adaptive loop still terminates.
            if scope is not None:
                decision = scope.check(task.target)
                if not decision:
                    log.info("skipping out-of-scope task %s: %s", task.id, decision.reason)
                    self.storage.set_task_status(task.id, "skipped")
                    executed = True
                    continue
            self.storage.set_task_status(task.id, "running")
            try:
                outcome = self._call_tool(
                    task, scope, getattr(run, "configuration_snapshot", None)
                )
            except Exception as exc:  # noqa: BLE001 - a failing tool must not wedge the run
                # Previously an exception escaped here leaving the task stuck in
                # ``running`` forever: nothing was pending afterwards, so the run
                # sat in EXECUTING and could never complete or resume. Record the
                # failure and keep the run moving.
                log.warning("task %s (%s) failed: %s", task.id, task.type, exc)
                self.storage.set_task_status(task.id, "failed")
                executed = True
                continue
            tool_run, artifacts = _split_outcome(outcome)
            failed = _execution_failed(outcome)
            try:
                # Phase 14: the ToolRun, the ingested evidence/graph facts and the
                # task's terminal state are one atomic unit. A storage that
                # provides ``transaction()`` gets it; one that predates Phase 14
                # (and every in-test double) keeps the original three writes.
                with _transaction_for(self.storage):
                    self.storage.insert_tool_run(tool_run)
                    if self.ingest is not None:
                        self.ingest(task, tool_run, artifacts, run, scope)
                    self.storage.set_task_status(
                        task.id, "failed" if failed else "completed"
                    )
            except Exception as exc:  # noqa: BLE001 - ingestion must not wedge the run
                # The transaction rolled back, so no ToolRun, no evidence and no
                # partial graph were committed, and the task is still ``running``.
                # Marking it failed keeps the failure visible and retryable
                # ("no lost work") rather than silently completing it without facts.
                log.warning(
                    "task %s (%s) ingestion failed: %s", task.id, task.type, exc
                )
                self.storage.set_task_status(task.id, "failed")
                executed = True
                continue
            if not failed:
                done.add(task.id)
            executed = True
        return executed

    def _call_tool(
        self, task: Task, scope: Optional[ScopeGuard], config: Optional[dict] = None
    ) -> ToolRun:
        """Invoke ``run_tool`` under the rate limiter, passing scope/config when supported.

        ``config`` is the run's own ``configuration_snapshot``. The orchestrator does
        not interpret it -- the seam does, because only the seam knows the typed
        configuration shape. It is handed over so the adapter executes with the
        configuration the run was created with, not a process-local default.
        """
        host = extract_host(task.target) if self.rate_limiter is not None else None
        if self.rate_limiter is not None:
            self.rate_limiter.acquire(host=host, tool=task.type)
        try:
            kwargs = {}
            if self._run_tool_accepts_scope and scope is not None:
                kwargs["scope"] = scope
            if self._run_tool_accepts_config and config is not None:
                kwargs["config"] = config
            if kwargs:
                return self.run_tool(task, **kwargs)  # type: ignore[call-arg]
            return self.run_tool(task)
        finally:
            if self.rate_limiter is not None:
                self.rate_limiter.release(host=host, tool=task.type)
