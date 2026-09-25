"""Real-Orchestrator API integration gates (``api/server.py`` + ``api/serve.py``).

Every gate here drives the served API against the **real** ``Orchestrator`` over the real
``MemoryStorage`` implementation of the ``Storage`` contract. The Phase-11 review surface
escaped review precisely because every committed API test injected
``_RecordingOrchestrator``; these gates exercise the real collaborator, so a route calling
a method the orchestrator does not own fails here instead of hiding behind a double.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from api.server import create_app
from core.memory_storage import MemoryStorage
from core.orchestrator import Orchestrator
from database.models.entities import Hypothesis, Run, Task, ToolRun

_API_KEY = "phase-13"
_AUTH = {"Authorization": "Bearer " + _API_KEY}

_APPROVE_PATH = "/api/v1/runs/{run_id}/hypotheses/{hypothesis_id}/approve"
_REJECT_PATH = "/api/v1/runs/{run_id}/hypotheses/{hypothesis_id}/reject"
_HYPOTHESES_PATH = "/api/v1/runs/{run_id}/hypotheses"


def _tool_run(task: Task) -> ToolRun:
    return ToolRun(
        task_id=task.id,
        tool_name=task.type,
        command=["argus", task.type, task.target],
        exit_code=0,
        raw_output_ref="storage/raw/out.txt",
    )


@pytest.fixture
def wired():
    storage = MemoryStorage()
    orch = Orchestrator(storage=storage, run_tool=_tool_run)
    return create_app(orch, api_key=_API_KEY), storage, orch


@pytest.fixture
def client(wired):
    app, _storage, _orch = wired
    with TestClient(app) as c:
        yield c


def _create_run(c, target: str = "example.com") -> dict:
    r = c.post("/api/v1/runs", json={"target": target}, headers=_AUTH)
    assert r.status_code == 201, r.text
    return r.json()


def _run_for(orch, target: str) -> Run:
    matches = [run for run in orch.list_runs() if run.target == target]
    assert matches, "run %r was not persisted" % target
    return matches[0]


def _hypothesis(orch, run: Run, **overrides) -> Hypothesis:
    fields = dict(
        run_id=run.id,
        statement="Potential object-level authorization weakness on /api/users/{id}",
        truth_label="HYPOTHESIS",
        confidence=0.4,
        severity="high",
        priority="high",
        target="example.com",
        validation_step="safe, non-invasive observation confirmation before any action",
    )
    fields.update(overrides)
    return orch.record_hypothesis(Hypothesis(**fields))


# -- run surface ------------------------------------------------------------


def test_post_runs_creates_canonical_run_persisted_in_storage(client, wired) -> None:
    _app, storage, _orch = wired
    body = _create_run(client)

    assert body["target"] == "example.com"
    assert body["status"] == "CREATED"

    runs = storage.list_runs()
    assert len(runs) == 1
    assert str(runs[0].id) == body["id"]
    assert runs[0].target == "example.com"


def test_post_runs_rejects_empty_target(client) -> None:
    for payload in ({}, {"target": ""}, {"target": "   "}):
        assert (
            client.post("/api/v1/runs", json=payload, headers=_AUTH).status_code == 422
        )


def test_post_runs_rejects_malformed_program_id(client) -> None:
    r = client.post(
        "/api/v1/runs",
        json={"target": "example.com", "program_id": "not-a-uuid"},
        headers=_AUTH,
    )
    assert r.status_code == 422


def test_get_runs_lists_persisted_runs_with_real_orchestrator(client, wired) -> None:
    _app, _storage, orch = wired
    first = _create_run(client, "example.com")
    second = _create_run(client, "example.net")

    r = client.get("/api/v1/runs", headers=_AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    assert {run["id"] for run in body["runs"]} == {first["id"], second["id"]}
    assert len(orch.list_runs()) == 2


def test_get_run_by_id_uses_real_storage(client, wired) -> None:
    _app, _storage, _orch = wired
    created = _create_run(client)

    r = client.get("/api/v1/runs/{0}".format(created["id"]), headers=_AUTH)
    assert r.status_code == 200
    assert r.json()["id"] == created["id"]
    assert r.json()["target"] == "example.com"


def test_get_run_unknown_id_is_404(client) -> None:
    missing = "00000000-0000-0000-0000-000000000099"
    r = client.get("/api/v1/runs/{0}".format(missing), headers=_AUTH)
    assert r.status_code == 404


def test_get_run_tasks_reads_persisted_tasks(client, wired) -> None:
    _app, _storage, orch = wired
    created = _create_run(client)
    run = _run_for(orch, "example.com")
    orch.plan(
        run,
        [
            Task(run_id=run.id, type="subdomain_enum", target="example.com"),
            Task(run_id=run.id, type="http_probe", target="example.com"),
        ],
    )

    r = client.get("/api/v1/runs/{0}/tasks".format(created["id"]), headers=_AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    assert {t["type"] for t in body["tasks"]} == {"subdomain_enum", "http_probe"}


def test_get_run_tasks_unknown_run_is_404(client) -> None:
    missing = "00000000-0000-0000-0000-000000000099"
    r = client.get("/api/v1/runs/{0}/tasks".format(missing), headers=_AUTH)
    assert r.status_code == 404


@pytest.mark.parametrize("fmt", ["json", "markdown", "html"])
def test_get_run_reports_deterministic_with_real_state(client, wired, fmt: str) -> None:
    _app, _storage, orch = wired
    created = _create_run(client)
    run = _run_for(orch, "example.com")
    orch.plan(run, [Task(run_id=run.id, type="http_probe", target="example.com")])

    first = client.get(
        "/api/v1/runs/{0}/reports/{1}".format(created["id"], fmt), headers=_AUTH
    )
    second = client.get(
        "/api/v1/runs/{0}/reports/{1}".format(created["id"], fmt), headers=_AUTH
    )
    assert first.status_code == 200
    assert first.content == second.content
    assert len(first.content) > 0


# -- hypothesis review surface ---------------------------------------------


def test_get_hypotheses_empty_for_new_run(client) -> None:
    created = _create_run(client)
    r = client.get(_HYPOTHESES_PATH.format(run_id=created["id"]), headers=_AUTH)
    assert r.status_code == 200
    assert r.json() == {"count": 0, "run_id": created["id"], "hypotheses": []}


def test_get_hypotheses_returns_persisted_run_scoped_hypotheses(client, wired) -> None:
    _app, _storage, orch = wired
    created = _create_run(client)
    run = _run_for(orch, "example.com")
    _hypothesis(orch, run)

    r = client.get(_HYPOTHESES_PATH.format(run_id=created["id"]), headers=_AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 1
    payload = body["hypotheses"][0]
    assert payload["run_id"] == created["id"]
    assert payload["truth_label"] == "HYPOTHESIS"
    assert payload["status"] == "open"
    assert payload["review_status"] == "pending"
    assert payload["review_reason"] is None
    assert payload["target"] == "example.com"
    assert payload["validation_step"]


def test_approve_hypothesis_performs_validated_finding_transition(client, wired) -> None:
    _app, _storage, orch = wired
    created = _create_run(client)
    run = _run_for(orch, "example.com")
    hypothesis = _hypothesis(orch, run)

    r = client.post(_APPROVE_PATH.format(run_id=created["id"], hypothesis_id=hypothesis.id), headers=_AUTH)
    assert r.status_code == 200
    payload = r.json()
    assert payload["review_status"] == "approved"
    assert payload["truth_label"] == "VALIDATED_FINDING"
    assert payload["status"] == "validated"

    persisted = orch.storage.get_hypothesis(run.id, hypothesis.id)
    assert persisted.review_status == "approved"
    assert persisted.truth_label == "VALIDATED_FINDING"
    assert persisted.status == "validated"


def test_reject_hypothesis_records_reason(client, wired) -> None:
    _app, _storage, orch = wired
    created = _create_run(client)
    run = _run_for(orch, "example.com")
    hypothesis = _hypothesis(orch, run)

    r = client.post(
        _REJECT_PATH.format(run_id=created["id"], hypothesis_id=hypothesis.id),
        json={"reason": "operator review: confidence insufficient"},
        headers=_AUTH,
    )
    assert r.status_code == 200
    payload = r.json()
    assert payload["review_status"] == "rejected"
    assert payload["review_reason"] == "operator review: confidence insufficient"
    assert payload["truth_label"] == "HYPOTHESIS"
    assert payload["status"] == "open"


def test_review_actions_are_not_repeatable(client, wired) -> None:
    _app, _storage, orch = wired
    created = _create_run(client)
    run = _run_for(orch, "example.com")
    hypothesis = _hypothesis(orch, run)

    first = client.post(_APPROVE_PATH.format(run_id=created["id"], hypothesis_id=hypothesis.id), headers=_AUTH)
    assert first.status_code == 200
    second = client.post(_APPROVE_PATH.format(run_id=created["id"], hypothesis_id=hypothesis.id), headers=_AUTH)
    assert second.status_code == 404


def test_unknown_hypothesis_is_404(client) -> None:
    created = _create_run(client)
    missing = uuid4()
    assert (
        client.post(_APPROVE_PATH.format(run_id=created["id"], hypothesis_id=missing), headers=_AUTH).status_code
        == 404
    )
    assert (
        client.post(
            _REJECT_PATH.format(run_id=created["id"], hypothesis_id=missing), json={"reason": "x"}, headers=_AUTH
        ).status_code
        == 404
    )


def test_hypotheses_for_unknown_run_is_404(client) -> None:
    missing = "00000000-0000-0000-0000-000000000099"
    r = client.get(_HYPOTHESES_PATH.format(run_id=missing), headers=_AUTH)
    assert r.status_code == 404


# -- run_id isolation -------------------------------------------------------


def test_hypotheses_are_isolated_per_run(client, wired) -> None:
    _app, _storage, orch = wired
    first = _create_run(client, "example.com")
    _create_run(client, "example.net")
    hypothesis_a = _hypothesis(orch, _run_for(orch, "example.com"))
    _hypothesis(orch, _run_for(orch, "example.net"), statement="second run hypothesis")

    listed = client.get(_HYPOTHESES_PATH.format(run_id=first["id"]), headers=_AUTH).json()
    assert listed["count"] == 1
    assert listed["hypotheses"][0]["id"] == str(hypothesis_a.id)


def test_hypothesis_of_other_run_cannot_be_reviewed_through_this_run(client, wired) -> None:
    _app, _storage, orch = wired
    first = _create_run(client, "example.com")
    _create_run(client, "example.net")
    hypothesis_b = _hypothesis(orch, _run_for(orch, "example.net"))
    other_run = _run_for(orch, "example.net")

    r = client.post(_APPROVE_PATH.format(run_id=first["id"], hypothesis_id=hypothesis_b.id), headers=_AUTH)
    assert r.status_code == 404
    persisted = orch.storage.get_hypothesis(other_run.id, hypothesis_b.id)
    assert persisted.review_status == "pending"
    assert persisted.truth_label == "HYPOTHESIS"


# -- duplicate route detection ---------------------------------------------


def test_exactly_one_approve_and_one_reject_route(wired) -> None:
    app, _storage, _orch = wired
    approve = [r for r in app.routes if getattr(r, "path", "") == _APPROVE_PATH]
    reject = [r for r in app.routes if getattr(r, "path", "") == _REJECT_PATH]
    assert len(approve) == 1
    assert len(reject) == 1


def test_reject_route_takes_reason_from_json_body(client, wired) -> None:
    _app, _storage, orch = wired
    created = _create_run(client)
    run = _run_for(orch, "example.com")
    hypothesis = _hypothesis(orch, run)

    r = client.post(
        _REJECT_PATH.format(run_id=created["id"], hypothesis_id=hypothesis.id), json={}, headers=_AUTH
    )
    assert r.status_code == 200
    assert r.json()["review_reason"] == ""


# -- authentication ---------------------------------------------------------


def test_protected_routes_require_bearer(client, wired) -> None:
    _app, _storage, orch = wired
    created = _create_run(client)
    run = _run_for(orch, "example.com")
    hypothesis = _hypothesis(orch, run)

    for method, path, kwargs in [
        ("get", "/api/v1/runs", {}),
        ("post", "/api/v1/runs", {"json": {"target": "example.com"}}),
        ("get", "/api/v1/runs/{0}".format(created["id"]), {}),
        ("get", "/api/v1/runs/{0}/tasks".format(created["id"]), {}),
        ("get", "/api/v1/runs/{0}/reports/json".format(created["id"]), {}),
        ("get", _HYPOTHESES_PATH.format(run_id=created["id"]), {}),
        ("post", _APPROVE_PATH.format(run_id=created["id"], hypothesis_id=hypothesis.id), {}),
    ]:
        assert getattr(client, method)(path, **kwargs).status_code == 401
        assert (
            getattr(client, method)(
                path, headers={"Authorization": "Bearer wrong"}, **kwargs
            ).status_code
            == 401
        )


def test_liveness_open_unauthenticated(client) -> None:
    assert client.get("/_healthz").status_code == 200


# -- persistence semantics --------------------------------------------------


def test_storage_hands_out_value_copies_not_live_state(client, wired) -> None:
    _app, storage, _orch = wired
    _create_run(client)

    fetched = storage.list_runs()[0]
    fetched.status = "MUTATED"
    assert storage.list_runs()[0].status == "CREATED"
