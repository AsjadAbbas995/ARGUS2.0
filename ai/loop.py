"""Phase-16 production ``AnalysisHook``: run the intelligence layer and run the adaptive loop
("01_PRODUCT_SPEC.md" §10, "08_ORCHESTRATOR.md" §Adaptive loop, "PHASE_16_PROPOSAL.md" §3).

``Orchestrator._run_analysis_pass`` already calls ``analysis(run, tasks) -> list[Task]``,
dedupes by fingerprint, and persists pass progress. The machinery was never the gap. What was
missing is a *production* hook: ``api/serve.py`` passed no ``analysis=``, so every run walked
straight to ``COMPLETED`` and the loop described in the product spec never executed.

This module supplies that hook and nothing else. It composes three existing pieces:

* :mod:`ai.run_context` -- builds agent context from the Phase 15 read projection;
* the existing Phase-7 agents -- called unmodified, through their existing signatures;
* the Phase 16 repositories -- one ``ai_analysis`` row per invocation, plus a ``hypotheses``
  row per hypothesis-class proposal.

Safety boundary
---------------
The hook has **no** tool execution, network, or scope logic of its own. It returns ``Task``
objects that the orchestrator then runs through the existing
``Scope Guard -> Rate Limiter -> Tool Adapter`` chain exactly like any operator-created task, so
an AI proposal is authorized on precisely the same terms as a human one. Every proposal is
re-validated by ``ai/validator.py`` before anything is persisted, and
:data:`PERSISTABLE_TRUTH_LABELS` deliberately omits ``VALIDATED_FINDING``: promotion to a
finding belongs to ``Orchestrator.approve_hypothesis`` after operator review, and nothing here
is that path.

Fail-closed
-----------
An agent that raises, a context that cannot be built, a proposal that fails re-validation, a
proposal whose stage cannot be confirmed, or a storage that lacks the Phase 16 writes all
result in **no tasks and no partial writes**. The pass then adds nothing, the orchestrator's
existing logic completes the run, and the intelligence layer degrades to exactly the Phase 15
behaviour. A broken AI layer must never be able to fail, hang, or corrupt a run.

Determinism
-----------
The agents are rule-based, so the same persisted run and task list always produce the same
proposals, the same rows, and the same tasks. Row ids remain server-generated (``uuid4``) and so
are not part of that guarantee -- Phase 14 already established that ``entity_id`` is never
trusted from tool output, and the same rule applies to what an agent proposes. See
``PHASE_16_PROPOSAL.md`` §2.2 for why real model backends are deferred.

Phase 18
--------
Phase 18 persists what Phase 15 computes and Phase 16 deferred: the reconnaissance
stages a run structurally could not attempt, because no registered adapter can run them
(:func:`ai.run_context.uncovered_without_capability`). Those gaps now go to
``ai_coverage_gaps`` (migration ``0006``) via the same duck-typed optional seam
``insert_ai_analysis`` uses, so the Phase 15 distinction survives process exit and is
readable per run.

Three properties matter here:

* **Reported, never proposed.** A gap is not a task and not a hypothesis. Nothing in
  this phase enqueues one, and ``validate``/``_task_from`` are untouched.
* **Never silently dropped.** A storage without the Phase 18 write, or a failing
  write, logs and records :data:`ANALYSIS_COVERAGE_UNAVAILABLE` rather than passing
  quietly -- a silently dropped coverage gap would be the exact failure this phase
  exists to prevent, which is why "fail closed" here means "loudly and without
  partial writes", not "quietly".
* **It cannot lose proposals.** Gap recording happens after the proposal loop and in
  its own transaction, so a gap-write failure leaves every ``ai_analysis`` row and
  hypothesis already committed exactly as they were.

Phase 17
--------
Phase 17 changes persistence attribution and observability only; the agents, the contract,
the validation rules and the truth labels are untouched.

* **Attribution.** ``ai_analysis.run_id`` (migration ``0005``) is a real foreign key. Every row
  written here carries the run's id, so run-scoped retrieval is an indexed ``WHERE run_id = %s``
  instead of a text-prefix match on ``input_context_ref``. ``input_context_ref`` is still
  written: it is the context label the ``0005`` backfill attributes legacy rows from, and it
  names the context an agent was given.
* **Observability.** A pass that could previously fail silently now records why on
  :attr:`AnalysisResult.status` and logs it. The set of outcomes, the returned tasks, the
  fail-closed guarantees and the "proposal-only" persistence semantics are unchanged:
  ``None`` still writes no row, and a failing agent still rolls back only its own transaction.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Sequence
from uuid import UUID

from database.models.entities import AiAnalysis, Hypothesis, Task

from . import hypothesis_agent, recon_agent
from .recon_agent import AI_SCHEDULABLE_STAGES, STAGE_PRIORITY
from .router import RouteConfig
from .run_context import (
    expansion_owned_gaps,
    hypothesis_context,
    recon_context,
    uncovered_without_capability,
)
from .validator import validate_structured_output

log = logging.getLogger(__name__)

#: Truth labels the hook may persist. ``VALIDATED_FINDING`` is absent by design and
#: :func:`_hypothesis_from` refuses it -- only ``Orchestrator.approve_hypothesis`` may write it,
#: after operator review.
PERSISTABLE_TRUTH_LABELS = frozenset(
    {"FACT", "OBSERVATION", "INFERENCE", "HYPOTHESIS", "UNVERIFIED_CLAIM"}
)

#: Why a pass produced what it produced. Phase 17 adds these because the hook could
#: previously only fail *silently*: a storage with no ``attack_surface`` and a pass that
#: legitimately found nothing were indistinguishable from outside the hook, so "the AI
#: layer is broken" and "the AI layer had nothing to say" looked identical to an operator.
#:
#: These are coarse, non-sensitive states. They never carry an exception message, so
#: surfacing one over the API cannot leak internals; the detail stays in the log.
#:
#: ``ANALYSIS_DISABLED`` and ``ANALYSIS_UNWIRED`` are *not* here, because a hook does not
#: exist in either case and therefore cannot report on itself. They are reported by
#: ``api.serve`` through ``app.state``.
ANALYSIS_CAPABILITY_UNAVAILABLE = "capability_unavailable"
ANALYSIS_CONTEXT_FAILED = "context_failed"
ANALYSIS_NO_PROPOSALS = "no_proposals"
ANALYSIS_PROPOSED = "proposed"
ANALYSIS_PASS_FAILED = "pass_failed"

#: Phase 18. The pass ran and reached its conclusion, but the coverage gaps it observed
#: could not be persisted -- either the storage has no Phase 18 write, or the write raised.
#:
#: This is deliberately a *distinct* state rather than a silent success. A coverage gap that
#: vanishes without a trace is the precise failure Phase 18 exists to prevent: the run would
#: look complete while the record of what it could not attempt disappeared. It is not
#: :data:`ANALYSIS_CAPABILITY_UNAVAILABLE`, because that one means the pass never reached the
#: agents at all -- here the pass genuinely ran and produced its analysis.
#:
#: It never carries the exception detail, for the same reason the other statuses do not: the
#: message stays in the log and the API client sees a coarse state.
ANALYSIS_COVERAGE_UNAVAILABLE = "coverage_unavailable"

#: Every state :attr:`AnalysisResult.status` can hold. Bounded so a caller cannot be
#: handed an unexpected string, and so the diagnostic vocabulary stays greppable.
ANALYSIS_STATUSES = frozenset(
    {
        ANALYSIS_CAPABILITY_UNAVAILABLE,
        ANALYSIS_CONTEXT_FAILED,
        ANALYSIS_NO_PROPOSALS,
        ANALYSIS_PROPOSED,
        ANALYSIS_PASS_FAILED,
        ANALYSIS_COVERAGE_UNAVAILABLE,
    }
)

_PRIORITIES = frozenset({"low", "medium", "high"})

#: Proposal ``type`` values that become a persisted ``hypotheses`` row. Anything else is still
#: recorded in ``ai_analysis`` -- the audit trail is unconditional -- but creates no hypothesis.
_HYPOTHESIS_TYPES = frozenset({"hypothesis", "unverified_claim"})

#: AI-schedulable recon stage -> the task type that executes it. The served adapter registry is
#: keyed by task type, and stage names and task types are not the same vocabulary, so the
#: translation is stated here rather than assumed.
#:
#: Expansion-owned stages are deliberately absent. ``web_crawl``, ``content_discover`` and
#: ``js_analysis`` need an evidence-backed URL seed from a completed parent task, while the AI
#: planner only proposes the scope-root hostname. Deterministic discovery expansion schedules
#: them instead.
TASK_TYPE_FOR_STAGE: Mapping[str, str] = {
    "subdomain_enum": "subfinder",
    "dns_resolve": "dns_resolve",
    "port_scan": "port_scan",
    "http_probe": "http_probe",
    "tech_detect": "tech_detect",
    # Phase 24: passive historical URL discovery. The canonical task type registered in
    # the served adapter registry (gated on ``web.historical_urls``).
    "historical_recon": "historical_recon",
}

#: ``input_context_ref`` prefix. The ``ai_analysis`` table has no ``run_id`` column, so run
#: attribution lives in this field in a documented, prefix-matchable form.
_CONTEXT_REF_PREFIX = "run:"


def context_ref(run_id: Optional[UUID]) -> Optional[str]:
    """The ``input_context_ref`` written for a run's analysis rows."""
    return f"{_CONTEXT_REF_PREFIX}{run_id}" if run_id is not None else None


@dataclass(frozen=True)
class AgentOutcome:
    """What one agent returned this pass: its name, model, proposal, and any failure."""

    agent_name: str
    model_used: str
    proposal: Optional[Mapping[str, Any]] = None
    error: Optional[str] = None


@dataclass
class AnalysisResult:
    """Everything one analysis pass produced. Exposed for tests and audit.

    ``status`` is the Phase 17 diagnostic: one of :data:`ANALYSIS_STATUSES`, naming why
    the pass ended the way it did. It exists so a silent no-op is distinguishable from a
    pass that legitimately produced nothing. ``error`` carries the *detail* for logs and
    tests; it is never surfaced to an API client.
    """

    outcomes: tuple[AgentOutcome, ...] = field(default_factory=tuple)
    tasks: tuple[Task, ...] = field(default_factory=tuple)
    uncovered_without_capability: tuple[str, ...] = field(default_factory=tuple)
    expansion_owned_gaps: tuple[str, ...] = field(default_factory=tuple)
    status: str = ANALYSIS_NO_PROPOSALS
    error: Optional[str] = None

    @property
    def proposals(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(o.proposal for o in self.outcomes if o.proposal is not None)

    @property
    def ran(self) -> bool:
        """Whether this pass actually reached the agents.

        ``False`` for a pass that bailed before invoking anything -- a storage with no
        ``attack_surface``, or a context that could not be built. Both used to be
        indistinguishable from "ran, found nothing".
        """
        return self.status not in (
            ANALYSIS_CAPABILITY_UNAVAILABLE,
            ANALYSIS_CONTEXT_FAILED,
            ANALYSIS_PASS_FAILED,
        )


class AnalysisHook:
    """The production ``AnalysisHook`` passed to ``Orchestrator(analysis=...)``.

    Callable, and holds :attr:`last_result` so a caller (or a test) can inspect what the most
    recent pass actually did instead of inferring it from side effects.
    """

    def __init__(
        self,
        storage: Any,
        executable: Sequence[str],
        *,
        route_config: Optional[RouteConfig] = None,
        max_hypotheses_per_pass: int = 1,
    ) -> None:
        # ``executable`` is the task types the served adapter registry can dispatch, supplied by
        # the caller from the live registry so the gate cannot drift from what the server runs.
        self.storage = storage
        self.runnable = frozenset(str(t) for t in executable)
        self.route_config = route_config
        self.max_hypotheses_per_pass = max(0, int(max_hypotheses_per_pass))
        self.last_result = AnalysisResult()

    # -- Orchestrator.AnalysisHook protocol ------------------------------------

    def __call__(self, run: Any, tasks: list[Task]) -> list[Task]:
        """One analysis pass. Never raises, whatever the storage, the run, or the agents do.

        Everything after the projection read is inside the guard on purpose. Building agent
        context reads a caller-supplied snapshot dict and a serialized graph, so it can raise on
        malformed input just as an agent can raise on a surprising fact. A hook that let that
        escape would fail the run it was only ever supposed to advise -- which is the exact
        failure mode this module promises it will not have.

        Phase 17 adds no behaviour here: the guard, the fail-closed result and the returned
        tasks are byte-identical to Phase 16. What changed is that every early return now
        records *why* it happened on :attr:`last_result`, so a storage that cannot feed the
        agents is visible instead of silent.
        """
        surface = self._surface(run)
        if surface is None:
            # Not a failure: a storage with no canonical fact store has nothing to analyse.
            # Logged at warning because in production it means the composition is mis-wired,
            # and recorded on ``last_result`` so an operator can tell it from a clean pass.
            log.warning(
                "analysis pass skipped: storage %s cannot provide the attack-surface "
                "projection the agents read; no analysis was performed",
                type(self.storage).__name__,
            )
            self.last_result = AnalysisResult(status=ANALYSIS_CAPABILITY_UNAVAILABLE)
            return []

        try:
            run_id = run.id
            snapshot = getattr(run, "configuration_snapshot", None)
            try:
                recon_ctx = recon_context(surface, snapshot, tasks, sorted(self.runnable))
                hypothesis_ctx = hypothesis_context(surface, snapshot)
            except Exception as exc:
                # Context construction is separated from the outer guard purely so the
                # diagnostic can say *which* stage failed. The result is the same either way:
                # no context, so no agent runs, so no tasks and no writes.
                log.warning(
                    "analysis pass skipped: could not build agent context from the "
                    "projection for run %s: %s: %s",
                    run_id,
                    type(exc).__name__,
                    exc,
                )
                self.last_result = AnalysisResult(
                    status=ANALYSIS_CONTEXT_FAILED,
                    error=f"{type(exc).__name__}: {exc}",
                )
                return []
            gaps = recon_ctx.gaps

            outcomes = [
                self._invoke("recon_agent", recon_agent.run, recon_ctx),
                self._invoke("hypothesis_agent", hypothesis_agent.run, hypothesis_ctx),
            ]

            proposed: list[Task] = []
            hypotheses_written = 0
            for outcome in outcomes:
                if outcome.proposal is None:
                    continue
                kind = str(outcome.proposal.get("type", ""))
                if kind in _HYPOTHESIS_TYPES:
                    if hypotheses_written >= self.max_hypotheses_per_pass:
                        continue
                    persisted = self._persist(outcome, run_id)
                    if persisted and _hypothesis_from(run_id, outcome.proposal) is not None:
                        hypotheses_written += 1
                elif kind == "task":
                    task = self._task_from(run, outcome.proposal, gaps)
                    # The audit row is written first and unconditionally; only the *task* is
                    # withheld when persistence fails. Losing the task is recoverable, losing the
                    # record that the agent proposed it is not.
                    if task is not None and self._persist(outcome, run_id):
                        proposed.append(task)

            # Phase 18. Computed once and recorded before the result is built, so the
            # persisted rows and the value reported on ``last_result`` cannot disagree.
            gaps = uncovered_without_capability(tasks, sorted(self.runnable))
            coverage_ok = self._record_coverage_gaps(run_id, gaps)
            expansion_owned = expansion_owned_gaps(tasks)

            self.last_result = AnalysisResult(
                outcomes=tuple(o for o in outcomes if o.proposal is not None or o.error),
                tasks=tuple(proposed),
                uncovered_without_capability=gaps,
                expansion_owned_gaps=expansion_owned,
                # "ran and proposed" is measured by what was actually persisted, not by
                # whether an agent returned something: a proposal that failed validation or
                # could not be persisted proposed no new work.
                #
                # Phase 18: a coverage-gap write failure outranks that distinction. The
                # pass really did produce its analysis, but the record of what it could not
                # attempt is missing, and an operator reading only this field must be able
                # to tell that from a clean pass -- hence ANALYSIS_COVERAGE_UNAVAILABLE
                # rather than a silent NO_PROPOSALS.
                status=(
                    ANALYSIS_COVERAGE_UNAVAILABLE
                    if not coverage_ok
                    else (
                        ANALYSIS_PROPOSED
                        if proposed or hypotheses_written
                        else ANALYSIS_NO_PROPOSALS
                    )
                ),
            )
            return proposed
        except Exception as exc:
            log.warning(
                "analysis pass failed for run %s: %s: %s",
                getattr(run, "id", "<unknown>"),
                type(exc).__name__,
                exc,
            )
            self.last_result = AnalysisResult(
                outcomes=(
                    AgentOutcome(
                        "analysis_hook",
                        _model_used("analysis_hook", self.route_config),
                        None,
                        error=f"{type(exc).__name__}: {exc}",
                    ),
                ),
                status=ANALYSIS_PASS_FAILED,
                error=f"{type(exc).__name__}: {exc}",
            )
            return []

    def _record_coverage_gaps(self, run_id: UUID, gaps: Sequence[str]) -> bool:
        """Persist the coverage gaps observed this pass.

        Phase 18. One row per stage, deduplicated per ``(run_id, stage)``; the storage's
        ``observe_coverage_gaps`` advances ``last_seen_at`` and ``observation_count`` on
        conflict. The caller passes the tuple returned by
        :func:`ai.run_context.uncovered_without_capability` verbatim, so no change to how gaps
        are computed is made here.

        The return value is ``False`` only when a gap was supposed to be recorded but could
        not. That is a deliberate signal: the pass must not silently drop the gap. In that
        case the method logs the condition, and the caller promotes the result status to
        :data:`ANALYSIS_COVERAGE_UNAVAILABLE` rather than returning ``ANALYSIS_NO_PROPOSALS``.
        """
        if not gaps:
            return True
        recorder = getattr(self.storage, "observe_coverage_gaps", None)
        if not callable(recorder):
            log.warning(
                "coverage gaps were observed for run %s but storage %s has no "
                "observe_coverage_gaps method; gaps are NOT persisted",
                run_id,
                type(self.storage).__name__,
            )
            return False
        try:
            recorder(run_id, tuple(gaps))
        except Exception as exc:
            log.warning(
                "coverage gap persistence failed for run %s: %s: %s",
                run_id,
                type(exc).__name__,
                exc,
            )
            return False
        return True

    # -- internals -------------------------------------------------------------

    def _surface(self, run: Any) -> Optional[Mapping[str, Any]]:
        """The run's Phase 15 projection, or ``None`` when it cannot be read."""
        reader = getattr(self.storage, "attack_surface", None)
        if not callable(reader):
            return None
        try:
            surface = reader(run.id)
        except Exception:
            return None
        return surface if isinstance(surface, Mapping) else None

    def _invoke(self, agent_name: str, agent: Callable[..., Any], ctx: Any) -> AgentOutcome:
        """Run one agent and re-validate its output; never let it raise past here."""
        model = _model_used(agent_name, self.route_config)
        try:
            proposal = agent(ctx, self.route_config)
        except Exception as exc:
            return AgentOutcome(agent_name, model, None, error=f"{type(exc).__name__}: {exc}")
        if proposal is None:
            return AgentOutcome(agent_name, model, None)
        verdict = validate_structured_output(proposal)
        if not verdict.valid:
            return AgentOutcome(agent_name, model, None, error=f"rejected: {verdict.reason()}")
        return AgentOutcome(agent_name, model, dict(proposal))

    def _task_from(
        self, run: Any, proposal: Mapping[str, Any], gaps: Sequence[str]
    ) -> Optional[Task]:
        """Translate one ``type="task"`` proposal into a runnable :class:`Task`, or ``None``.

        ``ai.recon_agent`` does not carry the stage as a proposal field: it writes the scope
        root to ``target`` and names the stage only inside ``observation``. Rather than parse it
        out of prose, the stage is recomputed from the same ordered ``gaps`` tuple the agent was
        given -- the AI-schedulable gaps from :func:`recon_context`, in ``STAGE_PRIORITY``
        order -- and then *confirmed* against the observation text. If the two disagree the
        proposal is refused.

        That yields two independent refusals rather than one guess: the capability gate rejects
        a stage with no registered adapter, and the confirmation rejects a proposal whose stage
        cannot be tied back to the gap list. ``api/serve.py`` raises ``NoAdapterError`` before
        constructing an adapter for an unknown type, so an ungated proposal would not degrade
        gracefully -- it would fail the task it just created.
        """
        if not gaps:
            return None
        stage = str(gaps[0])
        if stage not in AI_SCHEDULABLE_STAGES:
            return None
        if stage not in str(proposal.get("observation", "")):
            return None
        task_type = TASK_TYPE_FOR_STAGE.get(stage)
        if task_type is None or task_type not in self.runnable:
            return None
        target = str(proposal.get("target", ""))
        if not target:
            return None
        return Task(run_id=run.id, type=task_type, target=target, status="pending")

    def _persist(self, outcome: AgentOutcome, run_id: UUID) -> bool:
        """Record one invocation, and any hypothesis it implies, in a single transaction.

        Returns whether the ``ai_analysis`` row was written. A storage without the Phase 16
        methods, or a failing transaction, writes nothing at all -- the caller treats that as
        "this agent produced no new work" rather than raising.
        """
        insert_analysis = getattr(self.storage, "insert_ai_analysis", None)
        if not callable(insert_analysis) or outcome.proposal is None:
            return False

        record = AiAnalysis(
            # Phase 17: the real run id, so ``list_ai_analysis(run_id)`` is an indexed
            # ``WHERE run_id = %s`` rather than a text-prefix match on
            # ``input_context_ref``. ``input_context_ref`` is still written below -- it
            # records the context the agent was given, which a run id does not carry.
            run_id=run_id,
            agent_name=outcome.agent_name,
            model_used=outcome.model_used,
            input_context_ref=context_ref(run_id),
            output=dict(outcome.proposal),
        )
        hypothesis = (
            _hypothesis_from(run_id, outcome.proposal)
            if str(outcome.proposal.get("type", "")) in _HYPOTHESIS_TYPES
            else None
        )

        transaction = getattr(self.storage, "transaction", None)
        try:
            if callable(transaction):
                with transaction():
                    insert_analysis(record)
                    if hypothesis is not None:
                        self._insert_hypothesis(hypothesis)
            else:
                insert_analysis(record)
                if hypothesis is not None:
                    self._insert_hypothesis(hypothesis)
        except Exception as exc:
            # Phase 16 already failed closed here (return False, write nothing). Phase 17
            # adds only a log line, so a rejected analysis row is visible to an operator
            # through the process log instead of vanishing.
            log.warning(
                "analysis persistence failed for agent %r on run %s: %s: %s",
                outcome.agent_name,
                run_id,
                type(exc).__name__,
                exc,
            )
            return False
        return True

    def _insert_hypothesis(self, hypothesis: Hypothesis) -> None:
        """Write a hypothesis row through whichever documented surface the storage offers.

        ``Repositories`` exposes both the ``insert_hypothesis`` facade and a ``.hypotheses``
        repository; the facade is preferred because it is the public contract, and the attribute
        is the documented fallback. Anything else is a storage that cannot persist Phase 16, and
        the caller's ``except`` turns that into "this agent produced no new work".
        """
        facade = getattr(self.storage, "insert_hypothesis", None)
        if callable(facade):
            facade(hypothesis)
            return
        repository = getattr(self.storage, "hypotheses", None)
        insert = getattr(repository, "insert", None)
        if not callable(insert):
            raise AttributeError("storage cannot insert hypotheses")
        insert(hypothesis)


def _model_used(agent_name: str, cfg: Optional[RouteConfig]) -> str:
    """The model id recorded for an agent's invocation.

    Phase 16 makes no model call, so there is no live model id to record. What *is* recorded is
    the routing configuration the agent consulted (``ai.route.route``), which is a true and
    useful fact about the invocation: which way the Phase-6 ballot would have sent this task
    type. Phase 17 replaces this with the real provider model id at the same seam.
    """
    if cfg is None:
        return "argus-rule-based"
    return f"argus-rule-based (route mode={cfg.mode})"


def _severity_for(priority: str) -> str:
    """Map a proposal's ``priority`` onto the ``hypotheses.severity`` vocabulary.

    The Common Output Contract has ``priority`` but no ``severity``, while ``hypotheses`` has a
    ``NOT NULL`` severity column constrained to ``low|medium|high``. This maps the contract's
    urgency onto the stored triage vocabulary rather than inventing an independent severity
    judgement. It is a documented lossy projection: a reader comparing the two columns deserves
    to know they are not the same field.
    """
    return priority if priority in _PRIORITIES else "low"


def _hypothesis_from(run_id: UUID, proposal: Mapping[str, Any]) -> Optional[Hypothesis]:
    """Build an un-reviewed :class:`Hypothesis` from a validated proposal, or ``None``.

    Always ``status='open'`` and ``review_status='pending'``: the hook runs before any operator
    has seen the proposal, so it has no authority to mark anything reviewed, rejected, or
    validated.
    """
    if str(proposal.get("truth_label", "")) not in PERSISTABLE_TRUTH_LABELS:
        return None
    statement = str(proposal.get("potential_issue", "")) or str(
        proposal.get("observation", "")
    )
    if not statement.strip():
        return None
    priority = str(proposal.get("priority", "low"))
    priority = priority if priority in _PRIORITIES else "low"
    return Hypothesis(
        run_id=run_id,
        statement=statement,
        truth_label=str(proposal["truth_label"]),
        confidence=float(proposal.get("confidence", 0.0)),
        severity=_severity_for(priority),
        priority=priority,
        status="open",
        target=str(proposal.get("target", "")),
        validation_step=str(proposal.get("validation_step", "")),
        review_status="pending",
    )


def build_analysis_hook(
    storage: Any,
    executable: Sequence[str],
    *,
    route_config: Optional[RouteConfig] = None,
    max_hypotheses_per_pass: int = 1,
) -> AnalysisHook:
    """Build the production ``AnalysisHook`` for ``Orchestrator(analysis=...)``."""
    return AnalysisHook(
        storage,
        executable,
        route_config=route_config,
        max_hypotheses_per_pass=max_hypotheses_per_pass,
    )
