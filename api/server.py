"""FastAPI application factory for the ARGUS read/control surface (Phase 10, Phase 11).

Composition contract (``10_IMPLEMENTATION_PLAN.md`` Phase 10): the app receives the
committed ``Orchestrator`` (or an injected double exposing the same read seam) and exposes
run creation, run status, task inspection, report retrieval and the run-scoped operator
hypothesis review workflow over HTTP. Every handler funnels through the injected
orchestrator, which delegates to the authoritative ``Storage`` layer; there is no route that
executes a tool, adapter or subprocess directly, and no route reaches storage directly, so
the Phase-10 objective "no endpoint may bypass the safety architecture" holds by
construction.

The orchestrator seam the app depends on is exactly: ``create_run(run: Run)``, ``get_run``,
``list_runs``, ``list_tasks``, ``list_hypotheses``, ``approve_hypothesis`` and
``reject_hypothesis``.
The liveness probe is deliberately unauthenticated; every other route requires a Bearer API
key compared in constant time against ``app.state.argus_api_key``.

Phase 15 adds ``GET /api/v1/runs/{run_id}/attack-surface`` and feeds the served report from
real persisted facts. Both read through the orchestrator's ``storage`` attribute -- the same
seam every other route already uses -- so no route instantiates a repository, executes a tool,
adapter or subprocess, or opens its own database connection. The attack surface is rebuilt from
the run's evidence on each request rather than cached, so it cannot go stale relative to the
database it describes. Every storage read here is optional and duck-typed, so a backend that
predates Phase 15 degrades to an honest empty section instead of raising.

Phase 17 adds ``GET /api/v1/runs/{run_id}/ai-analysis`` and an ``ai_analysis`` report section.
Both read the run's persisted analysis through the same optional, duck-typed storage seam, run
scoped by the ``ai_analysis.run_id`` foreign key rather than by a text prefix. Before this the
intelligence layer was a write-only audit trail: rows were committed but no operator-reachable
surface could read them, so "the AI ran" could not be established from the API or a report. The
route also reports a coarse ``diagnostics`` block, because "no analysis" previously had three
indistinguishable causes (disabled, unwired, or genuinely nothing to propose) and only the last
is a statement about the target. No diagnostic carries exception text or any credential.
"""

from __future__ import annotations

from typing import Mapping, Optional
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path as _ArgusRoot

from core.config import ConfigError, ScopeConfig, run_snapshot_from_dict
from core.orchestrator import BadRunTransition, Orchestrator, RunNotFoundError
from core.scope_guard import ScopeGuard, ScopeRuleType
from database import projection
from database.models.entities import Run, Task
from reports import html_report, json_report, markdown_report

#: ``scope_rules.rule_type`` values that can grant access, mapped onto the fields
#: of ``core.config.ScopeConfig`` that ``ScopeGuard.from_config`` consumes. These
#: are the only rule types that may contribute an *allow* to a run's effective
#: scope. Everything else -- ``exclusion``, and any of the above carrying
#: ``allowed = false`` -- contributes only an exclusion, which can never widen
#: access. ``port`` has no ``ScopeConfig`` counterpart and is ignored, which is
#: the same posture as today (``ScopeGuard.from_config`` never emits PORT rules).
_SCOPE_ALLOW_DOMAINS = (ScopeRuleType.DOMAIN, ScopeRuleType.SUBDOMAIN)
_SCOPE_ALLOW_IPS = (ScopeRuleType.IP, ScopeRuleType.CIDR)

_LIVENESS = "/_healthz"
_BEARER_PREFIX = "bearer "

#: The only ``truth_label`` that may appear in a report's ``validated_findings``
#: section. ``core.orchestrator.Orchestrator.approve_hypothesis`` is the single
#: writer that sets it, and it only does so through explicit operator approval, so
#: reading this one field is what keeps the facts/hypotheses/findings separation
#: truthful in the served report instead of decorative.
_VALIDATED_TRUTH_LABEL = "VALIDATED_FINDING"


def _read_from_storage(orchestrator: Orchestrator, name: str, *args) -> list:
    """Call an optional read on the orchestrator's storage, or return ``[]``.

    Duck-typed on purpose and in the same spirit as ``_has_program_scope_rules``: a
    storage backend that predates Phase 15 (the in-memory development double, a
    recording double) simply does not have the read, and an absent read must degrade to
    an honest empty section rather than raise. Production ``Repositories`` provides every
    name probed here.
    """
    storage = getattr(orchestrator, "storage", None)
    reader = getattr(storage, name, None)
    if not callable(reader):
        return []
    return list(reader(*args))


def _attack_surface(orchestrator: Orchestrator, run_id: UUID) -> dict:
    """The run's Phase 15 attack surface, read-only.

    Delegates to ``Repositories.attack_surface``, which owns the run-scoped SQL and the
    projection. A storage backend with no canonical fact store returns
    ``available: false`` instead of an empty-but-present graph, so a consumer can tell
    "nothing was projected because there is nothing to project from" apart from "this run
    observed nothing".
    """
    storage = getattr(orchestrator, "storage", None)
    provider = getattr(storage, "attack_surface", None)
    if not callable(provider):
        return projection.unavailable(run_id)
    surface = provider(run_id)
    # ``None`` means the run id is unknown. Callers resolve the run first and 404, so
    # this is only a guard against a storage that disagrees with ``get_run``.
    return projection.unavailable(run_id) if surface is None else surface


def _asset_counts(surface: Mapping[str, object]) -> dict[str, int]:
    """Canonical entity counts for the report's ``assets`` section.

    Only the canonical entity types are counted. The attack surface also counts the
    observation-only evidence tags (out-of-scope hosts/IPs, the artifact cap); those are
    not assets, and folding them into an "assets" count would overstate what was found.
    Denied observations stay visible in the ``evidence`` section, which is where they
    belong.
    """
    counts = surface.get("evidence_counts")
    if not isinstance(counts, Mapping):
        return {}
    return {
        entity_type: int(counts[entity_type])
        for entity_type in projection.CANONICAL_ENTITY_TYPES
        if counts.get(entity_type)
    }


def _run_payload(run) -> Mapping[str, str]:
    return {
        "id": str(run.id),
        "program_id": str(run.program_id),
        "target": str(run.target),
        "status": str(run.status),
    }


def _task_payload(task) -> Mapping[str, str]:
    return {
        "id": str(task.id),
        "run_id": str(task.run_id),
        "type": str(task.type),
        "target": str(task.target),
        "status": str(task.status),
    }



def _hypothesis_payload(hypothesis) -> Mapping[str, object]:
    """Project a persisted ``Hypothesis`` onto the API/dashboard wire contract.

    Analytical state (``truth_label`` / ``status``) and operator review state
    (``review_status`` / ``review_reason``) are reported as separate fields so the two
    lifecycles are never conflated.
    """
    return {
        "id": str(hypothesis.id),
        "run_id": str(hypothesis.run_id),
        "endpoint_id": str(hypothesis.endpoint_id) if hypothesis.endpoint_id else None,
        "statement": str(hypothesis.statement),
        "truth_label": str(hypothesis.truth_label),
        "confidence": float(hypothesis.confidence),
        "priority": str(hypothesis.priority),
        "severity": str(hypothesis.severity),
        "target": str(hypothesis.target),
        "validation_step": str(hypothesis.validation_step),
        "status": str(hypothesis.status),
        "review_status": str(hypothesis.review_status),
        "review_reason": hypothesis.review_reason,
    }


def _hypotheses_payload(run_id, hyps) -> dict:
    return {
        "count": len(hyps),
        "run_id": str(run_id),
        "hypotheses": [_hypothesis_payload(h) for h in hyps],
    }


#: Proposal fields lifted out of a persisted ``ai_analysis.output`` for the wire contract.
#:
#: These are **not** new columns and nothing is invented: each is read straight out of the
#: stored Common Output Contract object, so the full payload (``output``) remains the record of
#: truth and these are a convenience projection of it. They exist because ``proposal_type``,
#: ``truth_label`` and ``evidence`` are the three things an operator triaging a run actually
#: looks for, and reaching two levels into a jsonb for each one is not a reasonable API.
#:
#: An absent contract key yields ``None`` rather than a default: a proposal that genuinely
#: carries no truth label must not be rendered as if it were, say, ``HYPOTHESIS``.
_PROPOSAL_EVIDENCE_KEY = "evidence"
_PROPOSAL_TYPE_KEY = "type"
_PROPOSAL_TRUTH_LABEL_KEY = "truth_label"


def _proposal_field(output: object, key: str):
    """Read one key from a persisted proposal object, or ``None`` if absent/not a mapping."""
    if not isinstance(output, Mapping):
        return None
    return output.get(key)


def _ai_analysis_payload(analysis) -> Mapping[str, object]:
    """Project a persisted ``AiAnalysis`` row onto the operator wire contract.

    Every field here is a real column of ``ai_analysis`` (``run_id`` since migration ``0005``)
    or a key of its persisted ``output`` jsonb. Nothing is derived from a target, nothing is
    inferred, and no agent output is re-validated or re-labelled here.

    ``model_used`` is reported exactly as persisted. Phase 17 makes no model call, so that
    value names the rule-based router, not a language model -- the field is named honestly and
    this docstring exists so a future reader does not mistake it for evidence of an LLM.
    """
    output = getattr(analysis, "output", None)
    evidence = _proposal_field(output, _PROPOSAL_EVIDENCE_KEY)
    return {
        "id": str(analysis.id),
        # A legacy row migration 0005 could not attribute reports ``None`` rather than a
        # fabricated run. Such a row is never returned by the run-scoped query in the first
        # place; the field is nullable so the shape matches the stored row.
        "run_id": str(analysis.run_id) if getattr(analysis, "run_id", None) else None,
        "agent_name": str(analysis.agent_name),
        "model_used": str(analysis.model_used),
        "input_context_ref": analysis.input_context_ref,
        # The complete persisted Common Output Contract object, verbatim.
        "output": output if isinstance(output, Mapping) else {},
        # Projections of three keys of that object, for triage. See _PROPOSAL_TYPE_KEY et al.
        "proposal_type": _proposal_field(output, _PROPOSAL_TYPE_KEY),
        "truth_label": _proposal_field(output, _PROPOSAL_TRUTH_LABEL_KEY),
        "evidence": list(evidence) if isinstance(evidence, list) else [],
        "created_at": analysis.created_at.isoformat()
        if getattr(analysis, "created_at", None) is not None
        else None,
    }


def _analysis_diagnostics(app, orchestrator: Orchestrator) -> Mapping[str, object]:
    """Coarse, non-sensitive description of the intelligence layer's state.

    Phase 17 exists because "the AI produced nothing" had three indistinguishable causes: the
    layer was disabled, it was enabled but the composition never wired it, or it ran and
    genuinely had nothing to propose. Only the third is a statement about the target.

    What is reported here is deliberately coarse and deliberately free of internals:
    ``status`` is drawn from the bounded vocabulary in ``ai.loop.ANALYSIS_STATUSES`` plus the
    two states a hook cannot report about itself, and no exception text, path, DSN or key ever
    reaches an API client -- those stay in the process log. A diagnostic read that fails is
    reported as such and never breaks the run or the response.
    """
    from ai.loop import ANALYSIS_STATUSES

    hook = getattr(app.state, "argus_analysis_hook", None)
    if hook is None:
        # An unwired hook is reported as "disabled" rather than "unwired" when the served
        # policy also has it off, because that is the single switch an operator controls; the
        # two are only distinguishable when the policy says enabled but no hook exists.
        enabled = bool(getattr(getattr(app.state, "argus_config", None), "ai", None) and
                       app.state.argus_config.ai.enabled)
        return {
            "enabled": enabled,
            "wired": False,
            "status": "unwired" if enabled else "disabled",
        }

    last = getattr(hook, "last_result", None)
    status = getattr(last, "status", None)
    if status not in ANALYSIS_STATUSES:
        # No pass has run for this process yet, or the hook predates the diagnostic.
        status = "no_pass_yet"
    return {
        "enabled": True,
        "wired": True,
        "status": status,
        # The last pass's uncovered stages, i.e. recon work the AI wanted and the served
        # adapter registry could not execute. Diagnostic, not a task list.
        "uncovered_without_capability": sorted(
            str(s) for s in (getattr(last, "uncovered_without_capability", None) or ())
        ),
        "max_loop_passes": int(getattr(orchestrator, "max_loop_passes", 0)),
    }


def _ai_coverage_gap_payload(gap) -> Mapping[str, object]:
    """Project a persisted ``AiCoverageGap`` row onto the operator wire contract.

    The fields returned are the real columns of the ``ai_coverage_gaps`` table, never
    inferred values, and never sanitized beyond converting non-string values to their
    string forms for ids. ``run_id`` is required on every persisted gap, so it is always
    returned as a string here. Timestamps are passed through as-is (``created_at`` etc.)
    the same way other dataclass fields are serialized.
    """
    return {
        "id": str(getattr(gap, "id", "")),
        "run_id": str(getattr(gap, "run_id", "")),
        "stage": str(getattr(gap, "stage", "")),
        "first_seen_at": getattr(gap, "first_seen_at", None).isoformat()
        if getattr(getattr(gap, "first_seen_at", None), "isoformat", None)
        else getattr(gap, "first_seen_at", None),
        "last_seen_at": getattr(gap, "last_seen_at", None).isoformat()
        if getattr(getattr(gap, "last_seen_at", None), "isoformat", None)
        else getattr(gap, "last_seen_at", None),
        "observation_count": int(getattr(gap, "observation_count", 1) or 1),
        "created_at": getattr(gap, "created_at", None).isoformat()
        if getattr(getattr(gap, "created_at", None), "isoformat", None)
        else getattr(gap, "created_at", None),
    }


def _has_program_scope_rules(orchestrator: Orchestrator) -> bool:
    """Whether the orchestrator's storage exposes the authoritative ``scope_rules``.

    Mirrors the ``_resolve_program`` probe: a storage with no ``programs`` table
    has no program to own an authorization boundary, so there is nothing to
    resolve and the caller's scope stands. The production ``Repositories``
    exposes both, so production always takes the program-scope path.
    """
    storage = getattr(orchestrator, "storage", None)
    return getattr(storage, "scope_rules", None) is not None


def _program_scope(orchestrator: Orchestrator, program_id: UUID) -> dict:
    """The authoritative scope for ``program_id``, from its persisted rules.

    This is the flow ``04_SCOPE_SAFETY.md`` describes and that
    ``core.scope_guard.ScopeGuard`` already documents as its contract: scope is
    defined per ``programs`` and stored in ``scope_rules``, and the guard
    "evaluates fixed ``scope_rules`` ... AI agents, parsers, and adapters cannot
    override it". A program with no rules authorizes nothing, which is the
    fail-closed reading: the run is created with an empty scope and every target
    is denied.

    ``allowed`` rules grant; ``exclusion`` rules and ``allowed = false`` rows deny.
    """
    storage = getattr(orchestrator, "storage", None)
    rows = storage.scope_rules.list_for_program(program_id) or []
    allowed_domains: list[str] = []
    allowed_ips: list[str] = []
    excluded: list[str] = []
    for row in rows:
        rule_type = str(row.get("rule_type", "")).strip().lower()
        value = str(row.get("value", "")).strip()
        if not value:
            continue
        allowed = bool(row.get("allowed", True))
        if rule_type in _SCOPE_ALLOW_DOMAINS:
            (allowed_domains if allowed else excluded).append(value.lower().rstrip("."))
        elif rule_type in _SCOPE_ALLOW_IPS:
            (allowed_ips if allowed else excluded).append(value)
        elif rule_type == ScopeRuleType.EXCLUSION:
            excluded.append(value)
        # A 'port' rule has no ScopeConfig counterpart; ignoring it cannot widen
        # access, and inventing a port boundary here is out of scope for this pass.
    return {
        "allowed_domains": sorted(set(allowed_domains)),
        "allowed_ips": sorted(set(allowed_ips)),
        "excluded": sorted(set(excluded)),
    }


def _reject_scope_broadening(requested: dict, program_scope: dict) -> None:
    """Refuse a caller-supplied scope that reaches outside the program's.

    The request may *select* a program and a target inside it; it may not
    redefine what the program authorizes. Each requested allow entry is therefore
    evaluated against a guard built from the program's own scope, and anything the
    program does not already permit is a 422.

    Entries the program does permit are accepted: a request for a strict subset
    ("www.example.com" where the program allows "example.com") passes, because
    the effective scope is the program's regardless -- narrowing a request here
    does not silently grant it anything extra.
    """
    guard = ScopeGuard.from_config(ScopeConfig.from_dict(program_scope))
    for field in ("allowed_domains", "allowed_ips"):
        for entry in requested.get(field) or ():
            if not guard.check(str(entry)):
                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"scope {field} entry {entry!r} is outside the program's "
                        f"authorized scope; a run may narrow but never widen the "
                        f"scope its program defines"
                    ),
                )


def _effective_scope(
    orchestrator: Orchestrator, program_id: UUID, requested: object
) -> dict:
    """The scope a new run will actually execute under.

    The program's persisted rules are the boundary. A caller's scope object is
    validated against that boundary and may contribute only *exclusions* -- and
    because ``ScopeGuard`` already makes exclusions win over allows
    (``core/scope_guard.py``), folding them in can only ever remove access. An
    absent or empty caller scope therefore cannot erase program authorization,
    and the two are never unioned into a wider set.
    """
    program_scope = _program_scope(orchestrator, program_id)
    if not isinstance(requested, dict):
        return program_scope
    _reject_scope_broadening(requested, program_scope)
    extra_excluded = [
        str(value).strip() for value in (requested.get("excluded") or ()) if str(value).strip()
    ]
    if not extra_excluded:
        return program_scope
    return {
        **program_scope,
        "excluded": sorted(set(program_scope["excluded"]) | set(extra_excluded)),
    }


def _configuration_snapshot(
    app, payload: Mapping[str, object], effective_scope: Optional[dict] = None
) -> dict:
    """Build the ``configuration_snapshot`` stored on a new run.

    The snapshot must describe the configuration the run will *actually* execute
    with, so it is derived from the served policy and the request is applied as an
    overlay on top of it. Three rules follow from what is enforced at runtime:

    * Sections the request mentions (``web``, ``network``, ...) override the
      served policy for that run, so an operator can tune a run without
      restarting the process. ``scope`` is not among them: it comes from the
      program's persisted ``scope_rules`` (see :func:`_effective_scope`) and is
      written verbatim, because it is the authorization boundary rather than a
      tuning knob. An authorization boundary must be stated in full, never
      inherited field by field from a broader policy -- and never assembled out
      of a request. An effective empty scope therefore denies everything (fail
      closed).
    * ``limits`` always comes from the served policy, because the rate limiter is a
      process-level component built once at start-up. Recording a per-run limit that
      nothing enforces would make the persisted row describe a throttle that is not
      in force -- the snapshot would look right while execution ignored it.
    * ``web.historical_urls`` also comes from the served policy: the GAU adapter is
      registered once at start-up, so a per-run override can only make the snapshot
      disagree with the capability the process actually has.

    The payload is validated by ``core.config.run_snapshot_from_dict`` and carries no
    ``database`` section, so a DSN (and any password inside it) can never be persisted
    on a run row.

    When the app carries no policy (a caller that built ``create_app`` directly) the
    request's own configuration is used as-is.
    """
    raw = payload.get("configuration")
    served = getattr(app.state, "argus_config", None)
    if raw is not None and not isinstance(raw, dict):
        raise ConfigError("configuration must be a mapping")
    if raw is not None and "web" in raw and not isinstance(raw["web"], dict):
        raise ConfigError("web must be a mapping")
    if served is None:
        merged: dict = run_snapshot_from_dict(raw)
        if effective_scope is not None:
            merged["scope"] = dict(effective_scope)
        return run_snapshot_from_dict(merged)

    merged = served.to_dict()
    for section, value in (raw or {}).items():
        if section == "limits":
            continue  # enforced process-wide; see the docstring
        if section == "scope":
            continue  # replaced below from the program's scope_rules
        if section == "web" and isinstance(value, dict):
            # Historical recon is registered process-wide at start-up.
            value = {
                key: item
                for key, item in value.items()
                if key != "historical_urls"
            }
        if isinstance(value, dict) and isinstance(merged.get(section), dict):
            merged[section] = {**merged[section], **value}
        else:
            merged[section] = value
    if effective_scope is not None:
        # The boundary, written in full and last so nothing above can override it.
        merged["scope"] = dict(effective_scope)
    return run_snapshot_from_dict(merged)


def _resolve_program(orchestrator: Orchestrator, raw: str) -> UUID:
    """Resolve the program a new run belongs to.

    ``runs.program_id`` is a foreign key to ``programs`` (``05_DATA_MODEL.md``), so
    a run cannot be stored without a program that exists. This route used to invent
    a ``uuid4()`` program id when the caller omitted one, which only ever worked
    against an in-memory double: against real PostgreSQL it was a guaranteed
    foreign-key violation, and every served run creation failed.

    So where the constraint exists, it is enforced and the caller is told exactly
    what is wrong (422) instead of the database raising an opaque 500. A run is never
    attributed to a program nobody created -- inventing an engagement is not the
    API's call to make.

    Storage that has no ``programs`` table (the in-memory development double, or a
    recording test double) has no such constraint to enforce, so the generated id
    stands there.
    """
    storage = getattr(orchestrator, "storage", None)
    programs = getattr(storage, "programs", None)
    if not raw:
        if programs is not None:
            raise HTTPException(
                status_code=422,
                detail="program_id is required: a run must belong to an existing program",
            )
        return uuid4()
    try:
        program_uuid = UUID(raw)
    except ValueError:
        raise HTTPException(status_code=422, detail="program_id must be a UUID")
    if programs is not None and programs.get(program_uuid) is None:
        raise HTTPException(
            status_code=422, detail="program_id must reference an existing program"
        )
    return program_uuid


def _require_run(orchestrator: Orchestrator, run_id: UUID):
    run = orchestrator.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    return run


def _run_state_payload(orchestrator: Orchestrator, run_id: UUID) -> JSONResponse:
    """Project the run plus its task rollup after an execution step.

    Execution results are observable from the API, so a caller never has to reach
    into storage to learn whether the work actually ran.
    """
    run = _require_run(orchestrator, run_id)
    tasks = orchestrator.list_tasks(run_id)
    by_status: dict[str, int] = {}
    for task in tasks:
        by_status[str(task.status)] = by_status.get(str(task.status), 0) + 1
    payload = dict(_run_payload(run))
    payload["tasks"] = {"count": len(tasks), "by_status": by_status}
    return JSONResponse(payload)


def _parse_tasks(run_id: UUID, payload: Mapping[str, object]) -> list[Task]:
    """Validate a task list from the wire into ``Task`` entities.

    Validation is deliberately strict: an enqueued task is queued for a real tool
    invocation, so a task without a type or a target is rejected at intake rather
    than at execution time, where the failure would be attributed to the tool.
    """
    specs = payload.get("tasks")
    if not isinstance(specs, list) or not specs:
        raise HTTPException(status_code=422, detail="tasks must be a non-empty list")
    tasks: list[Task] = []
    for spec in specs:
        if not isinstance(spec, dict):
            raise HTTPException(status_code=422, detail="each task must be an object")
        kind = str(spec.get("type", "")).strip()
        target = str(spec.get("target", "")).strip()
        if not kind:
            raise HTTPException(status_code=422, detail="task type is required")
        if not target:
            raise HTTPException(status_code=422, detail="task target is required")
        raw_parent = spec.get("parent_task_id")
        try:
            parent = UUID(str(raw_parent)) if raw_parent else None
        except ValueError:
            raise HTTPException(status_code=422, detail="parent_task_id must be a UUID")
        tasks.append(
            Task(
                run_id=run_id,
                type=kind,
                target=target,
                parent_task_id=parent,
            )
        )
    return tasks


def create_app(orchestrator: Orchestrator, api_key: str) -> FastAPI:
    """Build the FastAPI control/read surface around ``orchestrator``.

    ``api_key`` is **required** and has no default. There is deliberately no
    committed fallback credential: a value published in the repository is not a
    secret, and one that silently becomes the production key would let anyone
    holding the source drive ``POST /runs/{id}/run`` -- i.e. the whole
    ``Scope Guard -> Rate Limiter -> Adapter -> Tool Runner -> Target`` chain --
    against a host of their choosing. Callers that want one supply it explicitly
    (``api.serve.create_serve_app`` requires ``ARGUS_API_KEY`` in production).

    A blank key is not a way to disable authentication: :func:`_authed` compares
    against ``app.state.argus_api_key`` with ``secrets.compare_digest`` and
    rejects when the expected value is empty, so a misconfigured key fails
    closed on every protected route rather than opening them.
    """
    app = FastAPI(title="ARGUS API", version="0.3.0")
    app.state.argus_api_key = str(api_key).strip() if api_key else ""

    import secrets

    def _authed(request: Request) -> None:
        header = request.headers.get("authorization")
        if not header or not header.lower().startswith(_BEARER_PREFIX):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing API key")
        token = header[len(_BEARER_PREFIX):].strip()
        expected = app.state.argus_api_key
        if not expected or not secrets.compare_digest(str(token), str(expected)):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid API key")

    @app.get(_LIVENESS, include_in_schema=False)
    def liveness() -> PlainTextResponse:
        return PlainTextResponse("ok")

    @app.post("/api/v1/runs", dependencies=[Depends(_authed)], status_code=status.HTTP_201_CREATED)
    def create_run(payload: dict) -> JSONResponse:
        target = str(payload.get("target", "")).strip()
        program_id = str(payload.get("program_id", "")).strip()
        if not target:
            raise HTTPException(status_code=422, detail="target is required")
        program_uuid = _resolve_program(orchestrator, program_id)
        # The snapshot is validated before the run is stored: an invalid scope, port
        # range or limit is a 422 at intake, never a run that fails mid-execution.
        # Everything that can raise ConfigError happens inside this try, so a
        # malformed configuration is a 422 on every path rather than a 500.
        try:
            # The scope is resolved from the program's persisted `scope_rules` before
            # the snapshot is built, so the row records the boundary that will
            # actually be enforced. A caller's scope object is validated against it
            # and can never widen it; with a storage that has no scope_rules there is
            # no program-owned boundary, so the caller's scope stands (in-memory
            # double path).
            effective_scope = None
            if _has_program_scope_rules(orchestrator):
                configuration = payload.get("configuration")
                if configuration is not None and not isinstance(configuration, dict):
                    raise ConfigError("configuration must be a mapping")
                requested_scope = (configuration or {}).get("scope")
                if requested_scope is not None and not isinstance(requested_scope, dict):
                    raise ConfigError("scope must be a mapping")
                effective_scope = _effective_scope(orchestrator, program_uuid, requested_scope)
            snapshot = _configuration_snapshot(app, payload, effective_scope)
        except ConfigError as exc:
            raise HTTPException(status_code=422, detail=f"invalid configuration: {exc}")
        run = Run(
            program_id=program_uuid,
            target=target,
            configuration_snapshot=snapshot,
        )
        created = orchestrator.create_run(run)
        return JSONResponse(_run_payload(created), status_code=status.HTTP_201_CREATED)

    @app.get("/api/v1/runs/{run_id}", dependencies=[Depends(_authed)])
    def get_run(run_id: UUID) -> JSONResponse:
        run = orchestrator.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        return JSONResponse(_run_payload(run))

    @app.get("/api/v1/runs/{run_id}/tasks", dependencies=[Depends(_authed)])
    def list_tasks(run_id: UUID) -> JSONResponse:
        if orchestrator.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="run not found")
        tasks = orchestrator.list_tasks(run_id)
        return JSONResponse({"run_id": str(run_id), "count": len(tasks), "tasks": [_task_payload(t) for t in tasks]})

    @app.get("/api/v1/runs/{run_id}/configuration", dependencies=[Depends(_authed)])
    def get_run_configuration(run_id: UUID) -> JSONResponse:
        """Read back the configuration a run is executing with.

        Exposed so an operator (and the Stage-3 end-to-end test) can confirm the
        policy persisted with the run is the policy being applied, instead of having
        to trust the process. It is credential-free by construction.
        """
        run = _require_run(orchestrator, run_id)
        return JSONResponse(
            {
                "run_id": str(run_id),
                "configuration_snapshot": dict(run.configuration_snapshot or {}),
            }
        )

    # -- execution seams ---------------------------------------------------
    # Thin delegations to the orchestrator. Orchestration stays in the orchestrator
    # (``02_ARCHITECTURE.md``): these routes validate the wire shape, call one
    # orchestrator method, and project the result. No lifecycle, scope, rate-limit or
    # tool logic belongs here.

    @app.post("/api/v1/runs/{run_id}/tasks", dependencies=[Depends(_authed)], status_code=status.HTTP_201_CREATED)
    def enqueue_tasks(run_id: UUID, payload: dict) -> JSONResponse:
        run = _require_run(orchestrator, run_id)
        planned = orchestrator.plan(run, _parse_tasks(run_id, payload))
        return JSONResponse(
            {
                "run_id": str(run_id),
                "count": len(planned),
                "tasks": [_task_payload(t) for t in planned],
            },
            status_code=status.HTTP_201_CREATED,
        )

    @app.post("/api/v1/runs/{run_id}/advance", dependencies=[Depends(_authed)])
    def advance_run(run_id: UUID, payload: Optional[dict] = None) -> JSONResponse:
        """Advance the run by exactly one orchestrator step."""
        _require_run(orchestrator, run_id)
        tool = str((payload or {}).get("tool") or "").strip() or None
        try:
            orchestrator.advance(run_id, tool=tool)
        except RunNotFoundError:
            raise HTTPException(status_code=404, detail="run not found")
        except BadRunTransition as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return _run_state_payload(orchestrator, run_id)

    @app.post("/api/v1/runs/{run_id}/run", dependencies=[Depends(_authed)])
    def run_to_completion(run_id: UUID, payload: Optional[dict] = None) -> JSONResponse:
        """Drive the run to a terminal state through the orchestrator."""
        _require_run(orchestrator, run_id)
        tool = str((payload or {}).get("tool") or "").strip() or None
        try:
            orchestrator.run_to_completion(run_id, tool=tool)
        except RunNotFoundError:
            raise HTTPException(status_code=404, detail="run not found")
        except BadRunTransition as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return _run_state_payload(orchestrator, run_id)

    @app.post("/api/v1/runs/{run_id}/resume", dependencies=[Depends(_authed)])
    def resume_run(run_id: UUID) -> JSONResponse:
        """Re-enter a run after an interruption (process restart, failed run)."""
        _require_run(orchestrator, run_id)
        try:
            orchestrator.resume(run_id)
        except RunNotFoundError:
            raise HTTPException(status_code=404, detail="run not found")
        except BadRunTransition as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return _run_state_payload(orchestrator, run_id)

    @app.get("/api/v1/runs/{run_id}/attack-surface", dependencies=[Depends(_authed)])
    def get_attack_surface(run_id: UUID) -> JSONResponse:
        """The run's projected attack surface: records, graph, and inferences.

        Read-only. This handler performs no writes, creates no task, runs no tool, makes
        no network call and evaluates no scope: it delegates to the orchestrator's storage
        read, which resolves the run's persisted evidence and runs the committed
        correlation graph and inference engine over it. Every node and edge carries the
        evidence id that justifies it, and inferences are returned with their own
        ``truth_label`` -- this route asserts nothing on the target's behalf.
        """
        _require_run(orchestrator, run_id)
        return JSONResponse(_attack_surface(orchestrator, run_id))

    @app.get("/api/v1/runs/{run_id}/reports/{fmt}", dependencies=[Depends(_authed)])
    def get_report(run_id: UUID, fmt: str):
        run = orchestrator.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        # Phase 15: the report is built from the run's *actual* persisted facts.
        # Previously only ``run`` and ``tasks`` were supplied, so every tool run,
        # asset count, evidence row and hypothesis section rendered empty even though
        # Phase 14 had persisted all of them, and the report read as a run that had
        # observed nothing.
        surface = _attack_surface(orchestrator, run_id)
        tool_runs = _read_from_storage(orchestrator, "list_tool_runs", run_id)
        evidence = _read_from_storage(orchestrator, "list_evidence", run_id)
        # Phase 17: the run's own analysis rows. Read run-scoped (migration 0005 gives
        # ``ai_analysis`` a real ``run_id``), so a report can only ever contain this run's
        # analysis -- and a storage without the read degrades to an empty section.
        ai_analysis = _read_from_storage(orchestrator, "list_ai_analysis", run_id)
        reviewed = [
            _hypothesis_payload(h)
            for h in (orchestrator.list_hypotheses(run_id) or [])
        ]
        report = json_report.build_report(
            run=run,
            tasks=orchestrator.list_tasks(run_id),
            tool_runs=tool_runs,
            asset_counts=_asset_counts(surface),
            evidence_count=len(evidence),
            # Split on the stored truth label: only operator approval sets
            # VALIDATED_FINDING, so nothing is promoted by being merely derived.
            hypotheses=[
                h for h in reviewed if str(h.get("truth_label", "")) != _VALIDATED_TRUTH_LABEL
            ],
            validated_findings=[
                h for h in reviewed if str(h.get("truth_label", "")) == _VALIDATED_TRUTH_LABEL
            ],
            evidence=evidence,
            attack_surface=surface,
            ai_analysis=[_ai_analysis_payload(row) for row in ai_analysis],
            ai_coverage_gaps=[_ai_coverage_gap_payload(g) for g in _read_from_storage(orchestrator, "list_coverage_gaps", run_id)],
        )
        if fmt == "json":
            return PlainTextResponse(json_report.render(report), media_type="application/json")
        if fmt == "markdown":
            return PlainTextResponse(markdown_report.render(report), media_type="text/markdown")
        if fmt == "html":
            return HTMLResponse(html_report.render(report))
        raise HTTPException(status_code=404, detail="unsupported report format")


    @app.get("/api/v1/runs", dependencies=[Depends(_authed)])
    def list_runs() -> JSONResponse:
        runs = orchestrator.list_runs()
        return JSONResponse({"count": len(runs), "runs": [_run_payload(r) for r in runs]})

    # Phase 11: serve the dependency-free operator dashboard from disk.
    _dash = _ArgusRoot() / "dashboard"
    if _dash.is_dir():
        app.mount("/dashboard", StaticFiles(directory=str(_dash), html=True), name="dashboard")

    @app.get("/api/v1/runs/{run_id}/hypotheses", dependencies=[Depends(_authed)])
    def list_hypotheses(run_id: UUID) -> JSONResponse:
        if orchestrator.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="run not found")
        hyps = orchestrator.list_hypotheses(run_id)
        return JSONResponse(_hypotheses_payload(run_id, hyps))

    @app.get("/api/v1/runs/{run_id}/ai-analysis", dependencies=[Depends(_authed)])
    def list_ai_analysis(run_id: UUID) -> JSONResponse:
        """The run's persisted AI analysis: one row per agent invocation that proposed.

        Phase 17. Before this route the intelligence layer was a write-only audit trail: rows
        were persisted but nothing an operator could reach could read them, so "the AI ran"
        was only ever inferable from a side effect.

        Read-only and run-scoped, on exactly the same terms as every other route here:

        * Bearer-authenticated by the single existing ``_authed`` dependency -- no second
          authentication mechanism is introduced.
        * 404 for an unknown run, resolved through ``_require_run`` before any read, so this
          route cannot be used to distinguish "run does not exist" from "run has no analysis".
        * Scoped by the ``ai_analysis.run_id`` foreign key (``WHERE run_id = %s``, migration
          ``0005``), never by a text prefix, so one run can never observe another run's rows and
          a row that could not be attributed stays invisible. It does not expose the
          unfiltered ``list_ai_analysis()``.
        * Performs no write, creates no task, runs no tool, evaluates no scope and makes no
          network call. It is a projection of rows already committed.
        * Returns only fields that exist in the persisted model, plus three keys projected out
          of the stored proposal object (see ``_ai_analysis_payload``).
        """
        _require_run(orchestrator, run_id)
        rows = _read_from_storage(orchestrator, "list_ai_analysis", run_id)
        # A storage with no run-scoped analysis read (the in-memory development double)
        # degrades to an honest empty list rather than raising, matching every other optional
        # read in this module.
        return JSONResponse(
            {
                "run_id": str(run_id),
                "count": len(rows),
                "ai_analysis": [_ai_analysis_payload(row) for row in rows],
                "diagnostics": _analysis_diagnostics(app, orchestrator),
            }
        )

    @app.get("/api/v1/runs/{run_id}/ai-coverage-gaps", dependencies=[Depends(_authed)])
    def list_ai_coverage_gaps(run_id: UUID) -> JSONResponse:
        """The run's persisted coverage gaps: stages that no registered adapter can run.

        Phase 18. Read-only, run-scoped, and authenticated by the same ``_authed``
        dependency as every other route. ``_require_run`` raises 404 for unknown runs
        before any read, so the route cannot be used to distinguish "run does not exist"
        from "run has no gaps". The storage read is optional (duck-typed): a storage with
        no Phase 18 support degrades to an honest empty list rather than raising.

        These are reported-only: a gap is a statement about capability, never a task and
        never a hypothesis, and nothing here enqueues work.
        """
        _require_run(orchestrator, run_id)
        gaps = _read_from_storage(orchestrator, "list_coverage_gaps", run_id)
        return JSONResponse(
            {
                "run_id": str(run_id),
                "count": len(gaps),
                "ai_coverage_gaps": [_ai_coverage_gap_payload(g) for g in gaps],
            }
        )

    @app.post("/api/v1/runs/{run_id}/hypotheses/{hypothesis_id}/approve", dependencies=[Depends(_authed)])
    def approve_hypothesis(run_id: UUID, hypothesis_id: UUID) -> JSONResponse:
        if orchestrator.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="run not found")
        h = orchestrator.approve_hypothesis(run_id, hypothesis_id)
        if h is None:
            raise HTTPException(status_code=404, detail="hypothesis not found")
        return JSONResponse(_hypothesis_payload(h))

    @app.post("/api/v1/runs/{run_id}/hypotheses/{hypothesis_id}/reject", dependencies=[Depends(_authed)])
    def reject_hypothesis(run_id: UUID, hypothesis_id: UUID, payload: dict) -> JSONResponse:
        if orchestrator.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="run not found")
        h = orchestrator.reject_hypothesis(
            run_id, hypothesis_id, reason=str(payload.get("reason", ""))
        )
        if h is None:
            raise HTTPException(status_code=404, detail="hypothesis not found")
        return JSONResponse(_hypothesis_payload(h))
    return app
