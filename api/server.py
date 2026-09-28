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
"""

from __future__ import annotations

from typing import Mapping, Optional
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path as _ArgusRoot

from core.config import ConfigError, run_snapshot_from_dict
from core.orchestrator import BadRunTransition, Orchestrator, RunNotFoundError
from database.models.entities import Run, Task
from reports import html_report, json_report, markdown_report

_LIVENESS = "/_healthz"
_BEARER_PREFIX = "bearer "
_API_KEY = "phase-10"


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


def _configuration_snapshot(app, payload: Mapping[str, object]) -> dict:
    """Build the ``configuration_snapshot`` stored on a new run.

    The snapshot must describe the configuration the run will *actually* execute
    with, so it is derived from the served policy and the request is applied as an
    overlay on top of it. Two rules follow from what is enforced at runtime:

    * Sections the request mentions (``scope``, ``web``, ``network``, ...) override
      the served policy for that run, so an operator can scope a run without
      restarting the process. ``scope`` is *replaced* rather than merged: an
      authorization boundary must be stated in full, never inherited field by field
      from a broader policy. An explicit empty scope therefore denies everything
      (fail closed) instead of silently keeping the served allowances.
    * ``limits`` always comes from the served policy, because the rate limiter is a
      process-level component built once at start-up. Recording a per-run limit that
      nothing enforces would make the persisted row describe a throttle that is not
      in force -- the snapshot would look right while execution ignored it.

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
    if served is None:
        return run_snapshot_from_dict(raw)

    merged = served.to_dict()
    for section, value in (raw or {}).items():
        if section == "limits":
            continue  # enforced process-wide; see the docstring
        if section == "scope":
            merged[section] = value  # an authorization boundary is stated in full
        elif isinstance(value, dict) and isinstance(merged.get(section), dict):
            merged[section] = {**merged[section], **value}
        else:
            merged[section] = value
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


def create_app(orchestrator: Orchestrator, api_key: str = _API_KEY) -> FastAPI:
    app = FastAPI(title="ARGUS API", version="0.3.0")
    app.state.argus_api_key = api_key

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
        try:
            snapshot = _configuration_snapshot(app, payload)
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

    @app.get("/api/v1/runs/{run_id}/reports/{fmt}", dependencies=[Depends(_authed)])
    def get_report(run_id: UUID, fmt: str):
        run = orchestrator.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        tasks = orchestrator.list_tasks(run_id)
        report = json_report.build_report(run=run, tasks=tasks)
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
