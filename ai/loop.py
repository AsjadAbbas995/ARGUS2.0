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
``PHASE_16_PROPOSAL.md`` §2.2 for why real model backends are deferred to Phase 17.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Sequence
from uuid import UUID

from database.models.entities import AiAnalysis, Hypothesis, Task

from . import hypothesis_agent, recon_agent
from .recon_agent import STAGE_PRIORITY
from .router import RouteConfig
from .run_context import hypothesis_context, recon_context, uncovered_without_capability
from .validator import validate_structured_output

#: Truth labels the hook may persist. ``VALIDATED_FINDING`` is absent by design and
#: :func:`_hypothesis_from` refuses it -- only ``Orchestrator.approve_hypothesis`` may write it,
#: after operator review.
PERSISTABLE_TRUTH_LABELS = frozenset(
    {"FACT", "OBSERVATION", "INFERENCE", "HYPOTHESIS", "UNVERIFIED_CLAIM"}
)

_PRIORITIES = frozenset({"low", "medium", "high"})

#: Proposal ``type`` values that become a persisted ``hypotheses`` row. Anything else is still
#: recorded in ``ai_analysis`` -- the audit trail is unconditional -- but creates no hypothesis.
_HYPOTHESIS_TYPES = frozenset({"hypothesis", "unverified_claim"})

#: Documented recon stage -> the task type that executes it. The served adapter registry is keyed
#: by task type, and stage names and task types are not the same vocabulary, so the translation
#: is stated here rather than assumed.
TASK_TYPE_FOR_STAGE: Mapping[str, str] = {
    "subdomain_enum": "subfinder",
    "dns_resolve": "dns_resolve",
    "port_scan": "port_scan",
    "http_probe": "http_probe",
    "tech_detect": "tech_detect",
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
    """Everything one analysis pass produced. Exposed for tests and audit."""

    outcomes: tuple[AgentOutcome, ...] = field(default_factory=tuple)
    tasks: tuple[Task, ...] = field(default_factory=tuple)
    uncovered_without_capability: tuple[str, ...] = field(default_factory=tuple)

    @property
    def proposals(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(o.proposal for o in self.outcomes if o.proposal is not None)


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
        """
        surface = self._surface(run)
        if surface is None:
            self.last_result = AnalysisResult()
            return []

        try:
            run_id = run.id
            snapshot = getattr(run, "configuration_snapshot", None)
            recon_ctx = recon_context(surface, snapshot, tasks, sorted(self.runnable))
            hypothesis_ctx = hypothesis_context(surface, snapshot)
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

            self.last_result = AnalysisResult(
                outcomes=tuple(o for o in outcomes if o.proposal is not None or o.error),
                tasks=tuple(proposed),
                uncovered_without_capability=uncovered_without_capability(
                    tasks, sorted(self.runnable)
                ),
            )
            return proposed
        except Exception as exc:
            self.last_result = AnalysisResult(
                outcomes=(
                    AgentOutcome(
                        "analysis_hook",
                        _model_used("analysis_hook", self.route_config),
                        None,
                        error=f"{type(exc).__name__}: {exc}",
                    ),
                )
            )
            return []

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
        given -- ``recon_agent`` proposes the first gap in ``STAGE_PRIORITY`` order -- and then
        *confirmed* against the observation text. If the two disagree the proposal is refused.

        That yields two independent refusals rather than one guess: the capability gate rejects
        a stage with no registered adapter, and the confirmation rejects a proposal whose stage
        cannot be tied back to the gap list. ``api/serve.py`` raises ``NoAdapterError`` before
        constructing an adapter for an unknown type, so an ungated proposal would not degrade
        gracefully -- it would fail the task it just created.
        """
        if not gaps:
            return None
        stage = str(gaps[0])
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
        except Exception:
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
