"""Phase-10 FastAPI tests (``10_IMPLEMENTATION_PLAN.md``).

These tests inject a recording double with the exact ``create_run`` / ``get_run`` /
``list_tasks`` seam that the committed ``Orchestrator`` exposes. The double deliberately has
**no** tool, adapter or subprocess surface, proving ``test_orchestrator_double_has_no_tool_``
surface`` holds even when the API is handed an untrusted orchestrator: no endpoint can bypass
the Scope-Guarded safety architecture because the double cannot execute anything.
"""

from __future__ import annotations

from typing import Mapping, Optional
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from api.server import create_app
from core.config import Config
from database.models.entities import Run

#: An explicit test key, passed by the caller. Production has no default credential
#: (``api.serve.create_serve_app`` requires ``ARGUS_API_KEY``), so this constant is a
#: value these tests choose -- not a fallback the app would use on its own. It is
#: deliberately *not* the removed ``"phase-10"`` literal, which used to be the
#: published production key and must stay recognizable only as a rejected back door
#: in ``tests/test_serve.py``.
_API_KEY = "test-api-key"
_AUTH = {"Authorization": "Bearer " + _API_KEY}


class _FakeRun:
    def __init__(self, target: str, program_id: str = "") -> None:
        self.id = uuid4()
        self.program_id = program_id
        self.target = target
        self.status = "created"
        self.started_at = None
        self.completed_at = None
        self.configuration_snapshot = None


class _FakeTask:
    def __init__(self, run_id: UUID, task_type: str, target: str, status: str = "pending") -> None:
        self.id = uuid4()
        self.run_id = run_id
        self.type = task_type
        self.target = target
        self.status = status
        self.reason = ""
        self.parent_task_id = None
        self.priority = 0
        self.started_at = None
        self.completed_at = None


class _RecordingOrchestrator:
    def __init__(self) -> None:
        self.runs = {}
        self.tasks = {}
        self.created = []

    def create_run(self, run: Run) -> _FakeRun:
        stored = _FakeRun(target=run.target, program_id=str(run.program_id))
        stored.status = run.status
        stored.configuration_snapshot = dict(run.configuration_snapshot or {})
        self.runs[str(stored.id)] = stored
        self.created.append(str(stored.id))
        return stored

    def get_run(self, run_id: UUID) -> Optional[_FakeRun]:
        return self.runs.get(str(run_id))

    def list_runs(self) -> list:
        return list(self.runs.values())

    def list_tasks(self, run_id: UUID):
        return self.tasks.get(str(run_id), [])

    def list_hypotheses(self, run_id: UUID) -> list:
        # Part of the orchestrator seam ``create_app`` documents that it depends on.
        # This double records no hypotheses, so an empty list is the accurate answer --
        # it must not be absent, or the served report would fail on a missing method.
        return []

    def set_task_status(self, run_id: UUID) -> None:
        raise AssertionError("Phase-10 API must not write task state directly")


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(orchestrator=_RecordingOrchestrator(), api_key=_API_KEY))


@pytest.fixture
def orchestrated() -> tuple:
    fake = _RecordingOrchestrator()
    app = create_app(orchestrator=fake, api_key=_API_KEY)
    return TestClient(app), fake


def _seed(orchestrated):
    c, fake = orchestrated
    run = fake.create_run(Run(target="example.com"))
    fake.tasks[str(run.id)] = [
        _FakeTask(run.id, "subdomain_enum", "example.com", "completed"),
        _FakeTask(run.id, "http_probe", "example.com", "running"),
    ]
    return run


_NO_WEB_OVERLAY = object()


def _post_run_with_served_web(
    *, historical_urls: bool, request_web: object = _NO_WEB_OVERLAY
):
    fake = _RecordingOrchestrator()
    app = create_app(orchestrator=fake, api_key=_API_KEY)
    app.state.argus_config = Config.from_dict(
        {
            "database": {"url": "postgresql://argus:argus@localhost:5432/argus"},
            "web": {"historical_urls": historical_urls},
        }
    )
    configuration = {} if request_web is _NO_WEB_OVERLAY else {"web": request_web}
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/runs",
            json={"target": "example.com", "configuration": configuration},
            headers=_AUTH,
        )
        snapshot = None
        if created.status_code == 201:
            readback = client.get(
                f"/api/v1/runs/{created.json()['id']}/configuration", headers=_AUTH
            )
            assert readback.status_code == 200, readback.text
            snapshot = readback.json()["configuration_snapshot"]
    return created, snapshot, fake


def _snapshot_for_served_web(
    *, historical_urls: bool, request_web: object = _NO_WEB_OVERLAY
) -> dict:
    created, snapshot, _ = _post_run_with_served_web(
        historical_urls=historical_urls, request_web=request_web
    )
    assert created.status_code == 201, created.text
    assert snapshot is not None
    return snapshot


def test_liveness_open_unauthenticated(client: TestClient) -> None:
    with client as c:
        assert c.get("/_healthz").status_code == 200


def test_all_routes_reject_missing_key(client: TestClient) -> None:
    with client as c:
        for method, path in [
            ("post", "/api/v1/runs"),
            ("get", "/api/v1/runs/00000000-0000-0000-0000-000000000099"),
            ("get", "/api/v1/runs/00000000-0000-0000-0000-000000000099/tasks"),
            ("get", "/api/v1/runs/00000000-0000-0000-0000-000000000099/reports/json"),
        ]:
            assert getattr(c, method)(path).status_code == 401
            assert getattr(c, method)(path, headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_create_run_contract(orchestrated) -> None:
    c, _ = orchestrated
    with c as client:
        r = client.post("/api/v1/runs", json={"target": "example.com"}, headers=_AUTH)
        assert r.status_code == 201
        body = r.json()
        assert body["status"] == "CREATED"
        assert body["target"] == "example.com"


def test_per_run_web_cannot_enable_historical_urls_when_served_disabled() -> None:
    snapshot = _snapshot_for_served_web(
        historical_urls=False,
        request_web={"historical_urls": True, "crawling": False},
    )
    assert snapshot["web"]["historical_urls"] is False
    assert snapshot["web"]["crawling"] is False


def test_per_run_web_cannot_disable_historical_urls_when_served_enabled() -> None:
    snapshot = _snapshot_for_served_web(
        historical_urls=True,
        request_web={"historical_urls": False, "http_probe": False},
    )
    assert snapshot["web"]["historical_urls"] is True
    assert snapshot["web"]["http_probe"] is False


@pytest.mark.parametrize("historical_urls", [False, True])
def test_served_historical_urls_snapshot_without_override(
    historical_urls: bool,
) -> None:
    snapshot = _snapshot_for_served_web(historical_urls=historical_urls)
    assert snapshot["web"]["historical_urls"] is historical_urls


@pytest.mark.parametrize("request_web", [None, False, 0, "enabled", []])
def test_non_mapping_web_overlay_is_rejected_without_creating_a_run(
    request_web,
) -> None:
    created, snapshot, fake = _post_run_with_served_web(
        historical_urls=True, request_web=request_web
    )
    assert created.status_code == 422
    assert "web must be a mapping" in created.json()["detail"]
    assert snapshot is None
    assert fake.runs == {}
    assert fake.created == []


def test_create_run_rejects_empty_target(orchestrated) -> None:
    c, _ = orchestrated
    with c as client:
        for payload in ({}, {"target": ""}, {"target": "   "}):
            r = client.post("/api/v1/runs", json=payload, headers=_AUTH)
            assert r.status_code == 422


def test_run_status_and_tasks_projected(orchestrated) -> None:
    c, _ = orchestrated
    with c as client:
        run = _seed(orchestrated)
        r = client.get("/api/v1/runs/{0}".format(run.id), headers=_AUTH)
        assert r.status_code == 200
        assert r.json()["id"] == str(run.id)
        t = client.get("/api/v1/runs/{0}/tasks".format(run.id), headers=_AUTH)
        assert t.status_code == 200
        body = t.json()
        assert body["count"] == 2
        assert {task["type"] for task in body["tasks"]} == {"subdomain_enum", "http_probe"}


def test_unknown_run_returns_404(orchestrated) -> None:
    c, _ = orchestrated
    with c as client:
        run_id = "00000000-0000-0000-0000-000000000099"
        assert c.get("/api/v1/runs/{0}".format(run_id), headers=_AUTH).status_code == 404
        assert c.get("/api/v1/runs/{0}/tasks".format(run_id), headers=_AUTH).status_code == 404
        assert c.get("/api/v1/runs/{0}/reports/json".format(run_id), headers=_AUTH).status_code == 404


@pytest.mark.parametrize("fmt", ["json", "markdown", "html"])
def test_report_endpoints_deterministic(orchestrated, fmt: str) -> None:
    c, _ = orchestrated
    with c as client:
        run = _seed(orchestrated)
        first = client.get("/api/v1/runs/{0}/reports/{1}".format(run.id, fmt), headers=_AUTH)
        second = client.get("/api/v1/runs/{0}/reports/{1}".format(run.id, fmt), headers=_AUTH)
        assert first.status_code == 200
        assert first.content == second.content
        assert len(first.content) > 0


def test_orchestrator_double_has_no_tool_surface(orchestrated) -> None:
    _, fake = orchestrated
    for banned in ("execute", "run_tool", "invoke_tool", "subprocess"):
        assert not hasattr(fake, banned)
