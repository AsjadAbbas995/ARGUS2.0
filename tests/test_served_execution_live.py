"""Stage 3: end-to-end proof of the *served* execution path against real PostgreSQL.

Skipped automatically when ``ARGUS_TEST_DATABASE_URL`` is unset/unreachable (see
``conftest.py``), like the rest of the live suite. With the DSN set, every test in
this module runs -- none of them stand down.

What is proven here is the whole chain documented in ``02_ARCHITECTURE.md``::

    HTTP API -> PostgreSQL -> Orchestrator -> persisted configuration -> ScopeGuard
             -> RateLimiter -> ToolAdapter -> ToolRunner -> subprocess -> target
             -> PostgreSQL -> HTTP API readback (and the same after a restart)

Every component is the production one. There is no ``MemoryStorage``, no fake
orchestrator, no stub adapter and no fabricated success:

* the app is built by ``api.serve.create_serve_app`` against the live database;
* the only substitution is the *target*, which is a deterministic loopback HTTP
  server started by the test on ``127.0.0.1`` with an ephemeral port, so nothing
  leaves the machine and no third party is contacted;
* the tool is a real ``ToolAdapter`` that shells out through the real
  ``core.tool_runner.ToolRunner`` (argv array, ``shell=False``, timeout, captured
  output, raw preservation). Its executable is the interpreter running the tests,
  which makes it available on any machine regardless of which recon binaries are
  installed -- the subprocess boundary is what matters, and it is the real one.
  The default production adapters (``httpx``/``subfinder``) are separately gated by
  ``test_served_dispatch_routes_each_task_type_to_its_own_adapter``.

The adapter is injected through ``create_serve_app(adapters=...)``, the documented
injection point. The production default table is untouched, and no new
reconnaissance capability is added to the product.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg.rows import dict_row
from starlette.testclient import TestClient

from api.serve import ServedExecution, UnknownTaskType, create_serve_app
from core.config import Config, ScopeConfig
from core.scope_guard import ScopeGuard, extract_host
from core.tool_runner import CommandResult, ToolRunner
from recon.base import ScopeViolation, ToolAdapter
from recon.dns.resolver import DnsResolverAdapter
from recon.subdomains.subfinder import SubfinderAdapter
from recon.web.httpx_probe import HttpxProbeAdapter

# Loopback only. Anything non-loopback in this module is a bug, not a test case.
LOOPBACK = "127.0.0.1"

#: The controlled tool. A real subprocess performing a real HTTP request against the
#: loopback target, using only the standard library so the test has no dependency on
#: which reconnaissance binaries happen to be installed.
_PROBE_SCRIPT = (
    "import json, sys, urllib.request\n"
    "url = sys.argv[1]\n"
    "with urllib.request.urlopen(url, timeout=10) as response:\n"
    "    body = response.read().decode('utf-8', 'replace')\n"
    "    print(json.dumps({'status': response.status, 'body': body}))\n"
)


class ControlledTarget:
    """A deterministic loopback HTTP server plus a record of what it was asked for."""

    def __init__(self) -> None:
        self.hits: list[str] = []
        self._lock = threading.Lock()
        control = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                with control._lock:
                    control.hits.append(self.path)
                payload = json.dumps(
                    {"served_by": "argus-stage3-controlled-target", "path": self.path}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args) -> None:  # silence stderr noise
                return

        self._server = ThreadingHTTPServer((LOOPBACK, 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def url(self) -> str:
        return f"http://{LOOPBACK}:{self.port}/probe"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def target() -> Iterator[ControlledTarget]:
    server = ControlledTarget()
    try:
        yield server
    finally:
        server.close()


class LocalHttpProbeAdapter(ToolAdapter):
    """A genuine ``ToolAdapter`` that reaches a target through the real Tool Runner.

    It implements the ``06_TOOL_CONTRACTS.md`` order faithfully: availability,
    scope validation, argument-array construction, execution through the Tool Runner,
    raw preservation (the runner's job) and parsing.
    """

    name = "local_http_probe"
    executables = ()

    def __init__(self) -> None:
        #: Every command this adapter actually built and ran. Proves whether the
        #: target was reached -- and, for the negative tests, that it was not.
        self.invocations: list[list[str]] = []

    def is_available(self) -> bool:
        # The "binary" is the interpreter running this test; it is present by
        # definition, which is exactly why the subprocess boundary can be exercised
        # on any machine.
        return Path(sys.executable).is_file()

    def validate(self, task, scope: ScopeGuard) -> None:
        self._require_in_scope(task.target, scope)

    def build_command(self, task, config) -> list[str]:
        host = extract_host(task.target)
        assert host == LOOPBACK, f"controlled target must be loopback, got {host!r}"
        command = [sys.executable, "-I", "-c", _PROBE_SCRIPT, task.target]
        self.invocations.append(command)
        return command

    def parse(self, result: CommandResult) -> list[object]:
        for line in reversed(result.stdout.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                return [json.loads(line)]
            except ValueError:
                continue
        return []


def _probe_factory(probes: list[LocalHttpProbeAdapter]):
    def factory() -> LocalHttpProbeAdapter:
        probe = LocalHttpProbeAdapter()
        probes.append(probe)
        return probe

    return factory


def _config(
    database_url: str,
    *,
    allowed_ips: tuple[str, ...] = (LOOPBACK,),
    rps: float = 50.0,
    concurrency: int = 4,
    raw_dir: Path | None = None,
) -> Config:
    """The served policy under test, built the way a deployment builds it."""
    return Config.from_dict(
        {
            "database": {"url": database_url},
            "scope": {"allowed_ips": list(allowed_ips)},
            "limits": {"requests_per_second": rps, "concurrency": concurrency},
            "storage": {"raw_dir": str(raw_dir) if raw_dir else "storage/raw"},
        }
    )


@pytest.fixture
def program_id(database_url: str) -> Iterator[str]:
    """A real organization + program, created through the production repositories.

    ``runs.program_id`` is a foreign key, so a served run cannot exist without one.
    The fix under test is that the API refuses to invent a program rather than
    letting the database reject the row.
    """
    from database.repositories.all import Repositories
    from database.repositories.base import DatabaseConnection

    connection = DatabaseConnection(database_url)
    repositories = Repositories(connection.connect())
    try:
        organization = repositories.organizations.upsert(
            f"argus-stage3-org-{uuid4().hex}"
        )
        program = repositories.programs.upsert(
            organization["id"], f"argus-stage3-program-{uuid4().hex}"
        )
        yield str(program["id"])
    finally:
        connection.close()


@pytest.fixture
def client(database_url: str, target: ControlledTarget, tmp_path: Path):
    """A served app wired to the live database, the controlled target and a real runner.

    Yields ``(client, probes, app)``. The raw-output root is a per-test temporary
    directory so preservation is proven without writing into the working tree.
    """
    probes: list[LocalHttpProbeAdapter] = []
    app = create_serve_app(
        api_key="stage3-key",
        database_url=database_url,
        config=_config(database_url, raw_dir=tmp_path / "raw"),
        runner=ToolRunner(raw_dir=tmp_path / "raw"),
        adapters={"http_probe": _probe_factory(probes)},
    )
    with TestClient(app) as test_client:
        yield test_client, probes, app


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer stage3-key"}


def _create_run(client, program_id: str, **payload) -> dict:
    body = {
        "target": f"http://{LOOPBACK}/",
        "program_id": program_id,
        "configuration": {"scope": {"allowed_ips": [LOOPBACK]}},
    }
    body.update(payload)
    response = client.post("/api/v1/runs", json=body, headers=_auth())
    assert response.status_code == 201, response.text
    return response.json()


def _enqueue(client, run_id: str, task_type: str, target: str) -> dict:
    response = client.post(
        f"/api/v1/runs/{run_id}/tasks",
        json={"tasks": [{"type": task_type, "target": target}]},
        headers=_auth(),
    )
    assert response.status_code == 201, response.text
    return response.json()


class _task:
    """A minimal task stand-in for exercising the seam/adapters directly."""

    def __init__(self, type_: str, target: str = "") -> None:
        self.type = type_
        self.target = target


# ---------------------------------------------------------------------------
# The end-to-end proof
# ---------------------------------------------------------------------------


def test_served_run_reaches_controlled_target_and_persists_everything(
    client, target, database_url, tmp_path, program_id
):
    """API -> PostgreSQL -> ... -> subprocess -> target -> PostgreSQL -> API readback."""
    test_client, probes, app = client

    # A real rate limiter is wired into the served orchestrator.
    assert app.state.argus_rate_limiter is not None
    assert app.state.argus_orchestrator.rate_limiter is app.state.argus_rate_limiter

    run = _create_run(test_client, program_id)
    run_id = run["id"]

    # The configuration the run will execute with is readable before anything runs.
    configuration = test_client.get(
        f"/api/v1/runs/{run_id}/configuration", headers=_auth()
    ).json()["configuration_snapshot"]
    assert configuration["scope"]["allowed_ips"] == [LOOPBACK]
    assert configuration["limits"]["requests_per_second"] == 50.0

    _enqueue(test_client, run_id, "http_probe", target.url)
    result = test_client.post(f"/api/v1/runs/{run_id}/run", json={}, headers=_auth())
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "COMPLETED"
    assert result.json()["tasks"]["by_status"] == {"completed": 1}

    # The tool really ran, and really reached the controlled target.
    assert len(probes) == 1
    assert probes[0].invocations, "the adapter never built a command"
    assert target.hits == ["/probe"], f"target was not reached as expected: {target.hits}"

    # Everything is durable in PostgreSQL, read back with an independent connection.
    with psycopg.connect(database_url, row_factory=dict_row) as connection:
        task_row = connection.execute(
            "SELECT status FROM tasks WHERE run_id = %s", (run_id,)
        ).fetchone()
        assert task_row["status"] == "completed"

        tool_runs = connection.execute(
            "SELECT tool_name, command, exit_code, raw_output_ref FROM tool_runs "
            "WHERE task_id = (SELECT id FROM tasks WHERE run_id = %s)",
            (run_id,),
        ).fetchall()

    assert len(tool_runs) == 1
    tool_run = tool_runs[0]
    assert tool_run["tool_name"] == "local_http_probe"
    assert tool_run["exit_code"] == 0
    assert tool_run["command"][0] == sys.executable

    # Raw output was preserved on disk and contains what the target actually served.
    raw_ref = Path(tool_run["raw_output_ref"])
    assert raw_ref.is_file(), f"raw output not preserved at {raw_ref}"
    preserved = json.loads(raw_ref.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert preserved["status"] == 200
    assert "argus-stage3-controlled-target" in preserved["body"]

    # And the API reads the same persisted state back.
    tasks = test_client.get(f"/api/v1/runs/{run_id}/tasks", headers=_auth()).json()
    assert tasks["tasks"][0]["status"] == "completed"
    report = test_client.get(
        f"/api/v1/runs/{run_id}/reports/json", headers=_auth()
    )
    assert report.status_code == 200


# ---------------------------------------------------------------------------
# Safety: the guard runs before the target
# ---------------------------------------------------------------------------


def test_out_of_scope_target_never_reaches_a_subprocess(client, target, program_id):
    """A denied target is never handed to a tool (198.51.100.0/24 is TEST-NET-2)."""
    test_client, probes, _ = client
    run = _create_run(test_client, program_id)
    run_id = run["id"]
    _enqueue(test_client, run_id, "http_probe", "http://198.51.100.7/probe")

    result = test_client.post(f"/api/v1/runs/{run_id}/run", json={}, headers=_auth())
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "COMPLETED"
    # Marked ``skipped``, not ``failed``: it was never attempted.
    assert result.json()["tasks"]["by_status"] == {"skipped": 1}
    assert probes == [], "an out-of-scope target reached the tool adapter"
    assert target.hits == [], "an out-of-scope target reached the network"


def test_empty_scope_fails_closed(client, target, program_id):
    """An empty scope denies everything; it is not read as "unscoped"."""
    test_client, probes, _ = client
    run = _create_run(test_client, program_id, configuration={"scope": {}})
    run_id = run["id"]
    _enqueue(test_client, run_id, "http_probe", target.url)

    result = test_client.post(f"/api/v1/runs/{run_id}/run", json={}, headers=_auth())
    assert result.json()["tasks"]["by_status"] == {"skipped": 1}
    assert probes == []
    assert target.hits == []


def test_invalid_configuration_is_rejected_at_intake(client, program_id):
    """A bad limit is a 422, never a run that fails mid-execution."""
    test_client, _, _ = client
    before = {r["id"] for r in test_client.get("/api/v1/runs", headers=_auth()).json()["runs"]}
    response = test_client.post(
        "/api/v1/runs",
        json={
            "target": f"http://{LOOPBACK}/",
            "configuration": {"limits": {"requests_per_second": 0}},
        },
        headers=_auth(),
    )
    assert response.status_code == 422, response.text
    after = {r["id"] for r in test_client.get("/api/v1/runs", headers=_auth()).json()["runs"]}
    assert after == before, "a run was stored despite invalid configuration"


# ---------------------------------------------------------------------------
# A run must belong to a program that exists (the foreign key the API used to miss)
# ---------------------------------------------------------------------------


def test_run_creation_refuses_an_invented_program(client, database_url):
    """``runs.program_id`` is a foreign key: no program means no run, not a 500.

    Pre-Stage-3 the API generated a random ``program_id`` when the caller omitted
    one. Against real PostgreSQL that was an unavoidable foreign-key violation, so
    every served run creation failed while the in-memory tests stayed green.
    """
    test_client, _, _ = client
    before = test_client.get("/api/v1/runs", headers=_auth()).json()["count"]

    response = test_client.post(
        "/api/v1/runs", json={"target": f"http://{LOOPBACK}/"}, headers=_auth()
    )
    assert response.status_code == 422, response.text
    assert "program_id" in response.json()["detail"]

    after = test_client.get("/api/v1/runs", headers=_auth()).json()["count"]
    assert after == before


def test_run_creation_refuses_a_program_that_does_not_exist(client):
    """A supplied program id must resolve, so the failure is a clear 422."""
    test_client, _, _ = client
    response = test_client.post(
        "/api/v1/runs",
        json={"target": f"http://{LOOPBACK}/", "program_id": str(uuid4())},
        headers=_auth(),
    )
    assert response.status_code == 422, response.text
    assert "existing program" in response.json()["detail"]


def test_run_creation_rejects_a_malformed_program_id(client):
    test_client, _, _ = client
    response = test_client.post(
        "/api/v1/runs",
        json={"target": f"http://{LOOPBACK}/", "program_id": "not-a-uuid"},
        headers=_auth(),
    )
    assert response.status_code == 422, response.text


def test_task_payload_is_validated(client, program_id):
    """A task with no target is rejected before it can be queued for a real tool."""
    test_client, _, _ = client
    run = _create_run(test_client, program_id)
    run_id = run["id"]
    for tasks in ([], [{"type": "http_probe"}], [{"target": "127.0.0.1"}]):
        response = test_client.post(
            f"/api/v1/runs/{run_id}/tasks", json={"tasks": tasks}, headers=_auth()
        )
        assert response.status_code == 422, response.text


# ---------------------------------------------------------------------------
# The limiter is real, not just present
# ---------------------------------------------------------------------------


def test_served_execution_goes_through_the_rate_limiter(client, target, program_id):
    """Every real task takes and returns a permit from the served limiter."""
    test_client, probes, app = client
    limiter = app.state.argus_rate_limiter

    # Instrument the real limiter (same object the orchestrator holds) so the calls
    # the served path actually makes are observable. The throttling logic is not
    # replaced -- only recorded.
    calls: list[tuple[str, object, object]] = []
    real_acquire, real_release = limiter.acquire, limiter.release

    def acquire(host=None, tool=None):
        calls.append(("acquire", host, tool))
        return real_acquire(host=host, tool=tool)

    def release(host=None, tool=None):
        calls.append(("release", host, tool))
        return real_release(host=host, tool=tool)

    limiter.acquire, limiter.release = acquire, release

    run = _create_run(test_client, program_id)
    run_id = run["id"]
    _enqueue(test_client, run_id, "http_probe", target.url)
    result = test_client.post(f"/api/v1/runs/{run_id}/run", json={}, headers=_auth())

    assert result.json()["tasks"]["by_status"] == {"completed": 1}
    assert target.hits == ["/probe"]
    # One permit taken for the task's own host and tool, and handed back afterwards.
    assert calls == [
        ("acquire", LOOPBACK, "http_probe"),
        ("release", LOOPBACK, "http_probe"),
    ], f"task did not pass through the served limiter: {calls}"


def test_served_rate_limiter_actually_throttles(database_url, tmp_path):
    """The served limiter is a working throttle, not a permissive no-op.

    The orchestrator executes tasks serially and a permit is returned on release, so
    a serial run never has to wait for a refill; the rate limit is what bounds a
    *concurrent* burst. That is exercised here directly through the limiter the
    served app hands to its orchestrator.
    """
    app = create_serve_app(
        api_key="stage3-key",
        database_url=database_url,
        config=_config(database_url, rps=2.0, concurrency=4, raw_dir=tmp_path / "raw"),
    )
    limiter = app.state.argus_rate_limiter
    assert limiter is app.state.argus_orchestrator.rate_limiter

    started = time.monotonic()
    for _ in range(5):  # capacity 4, so the fifth permit must wait for a refill
        limiter.acquire(host=LOOPBACK, tool="http_probe")
    elapsed = time.monotonic() - started
    for _ in range(5):
        limiter.release(host=LOOPBACK, tool="http_probe")

    assert elapsed >= 0.5, f"served limiter did not throttle a burst (took {elapsed:.3f}s)"


# ---------------------------------------------------------------------------
# Credentials must not be persisted on a run row
# ---------------------------------------------------------------------------


def test_run_snapshot_never_persists_the_database_url(database_url, program_id):
    """A DSN reaching a run row would be a credential leak in durable, readable data."""
    sentinel_url = database_url.replace("argus_test", "argus_test")  # keep the live DSN
    password = ""
    if "@" in sentinel_url and ":" in sentinel_url.split("@", 1)[0].split("//", 1)[-1]:
        userinfo = sentinel_url.split("//", 1)[-1].split("@", 1)[0]
        password = userinfo.split(":", 1)[1]

    app = create_serve_app(api_key="stage3-key", database_url=database_url)
    with TestClient(app) as test_client:
        run = _create_run(test_client, program_id)  # configuration comes from the served policy
        run_id = run["id"]

    with psycopg.connect(database_url, row_factory=dict_row) as connection:
        snapshot = connection.execute(
            "SELECT configuration_snapshot FROM runs WHERE id = %s", (run_id,)
        ).fetchone()["configuration_snapshot"]

    serialized = json.dumps(snapshot)
    assert "database" not in snapshot
    assert database_url not in serialized
    assert "postgresql" not in serialized.lower()
    if password:
        assert password not in serialized


# ---------------------------------------------------------------------------
# Restart: the same database serves the same run
# ---------------------------------------------------------------------------


def test_served_run_is_resumable_after_a_restart(client, target, database_url, tmp_path, program_id):
    """A second process finds the run, resumes it, and finishes the real work."""
    test_client, _, app = client
    run = _create_run(test_client, program_id)
    run_id = run["id"]
    _enqueue(test_client, run_id, "http_probe", target.url)

    # Simulate a process that died mid-flight: exactly the residue a crash leaves,
    # a task marked ``running`` with the run parked in EXECUTING.
    storage = app.state.argus_storage
    run_uuid = UUID(run_id)
    task = storage.list_tasks(run_uuid)[0]
    storage.set_task_status(task.id, "running")
    storage.set_run_status(run_uuid, "EXECUTING")
    assert storage.list_tasks(run_uuid)[0].status == "running"

    # A brand-new app instance against the same database: a restart.
    probes: list[LocalHttpProbeAdapter] = []
    restarted = create_serve_app(
        api_key="stage3-key",
        database_url=database_url,
        config=_config(database_url, raw_dir=tmp_path / "raw-restart"),
        runner=ToolRunner(raw_dir=tmp_path / "raw-restart"),
        adapters={"http_probe": _probe_factory(probes)},
    )
    with TestClient(restarted) as second:
        # The run and its persisted policy are there without any in-process state.
        assert second.get(f"/api/v1/runs/{run_id}", headers=_auth()).json()["status"] == "EXECUTING"
        assert second.get(
            f"/api/v1/runs/{run_id}/configuration", headers=_auth()
        ).json()["configuration_snapshot"]["scope"]["allowed_ips"] == [LOOPBACK]

        resumed = second.post(f"/api/v1/runs/{run_id}/resume", headers=_auth())
        assert resumed.status_code == 200, resumed.text
        # The in-flight task was not assumed complete: it was re-queued and actually
        # retried, so the run finishes and the target is reached exactly once.
        assert resumed.json()["status"] == "COMPLETED"
        assert resumed.json()["tasks"]["by_status"] == {"completed": 1}

    # Exactly one execution: the retry ran the task, it was not skipped, and it was
    # not run twice.
    assert target.hits == ["/probe"], "the resumed task did not reach the target once"


# ---------------------------------------------------------------------------
# Dispatch: each task type gets the tool that implements it
# ---------------------------------------------------------------------------


def test_served_app_uses_the_production_dispatch_table(database_url):
    """The default served composition maps task types to the committed adapters."""
    app = create_serve_app(api_key="stage3-key", database_url=database_url)
    execution: ServedExecution = app.state.argus_execution

    class _Task:
        def __init__(self, type_: str) -> None:
            self.type = type_

    assert isinstance(execution.adapter_for(_Task("http_probe")), HttpxProbeAdapter)
    assert isinstance(execution.adapter_for(_Task("httpx")), HttpxProbeAdapter)
    assert isinstance(execution.adapter_for(_Task("dns_resolve")), DnsResolverAdapter)
    assert isinstance(execution.adapter_for(_Task("dns")), DnsResolverAdapter)
    assert isinstance(execution.adapter_for(_Task("resolve")), DnsResolverAdapter)
    # The shared runner is reused and rooted at the configured raw directory.
    assert isinstance(execution._runner, ToolRunner)
    assert Path(execution._runner.raw_dir) == Path(app.state.argus_config.storage.raw_dir)


# ---------------------------------------------------------------------------
# Unknown task types must fail closed, never fall back to another tool
# ---------------------------------------------------------------------------


def test_adapter_for_refuses_an_unknown_task_type():
    """No silent substitute: an unknown type has no adapter, and says which it knows."""
    execution = ServedExecution(
        adapters={"dns_resolve": DnsResolverAdapter},
        runner=ToolRunner(),
    )

    class _Task:
        def __init__(self, type_: str) -> None:
            self.type = type_

    for unknown in ("http_probe", "", "totally_made_up", "HTTP_PROBE", None):
        with pytest.raises(UnknownTaskType) as caught:
            execution.adapter_for(_Task(unknown))
        # The error names the offending type and what is actually available, so the
        # fault is diagnosable rather than mysterious.
        assert "no adapter is registered" in str(caught.value)
        assert "dns_resolve" in str(caught.value)

    # A registered type still resolves normally.
    assert isinstance(execution.adapter_for(_Task("dns_resolve")), DnsResolverAdapter)


def test_unknown_task_type_cannot_accidentally_execute_the_dns_adapter(
    database_url, program_id, tmp_path
):
    """Regression: an unknown type must not be run by the DNS resolver.

    The served composition used to fall back to the DNS adapter for any type it did
    not recognise -- a typo, or a type from a newer planner -- so the task produced a
    DNS answer recorded as a successful execution. The resolver here is a spy, so this
    test fails if that fallback is ever reintroduced.
    """
    resolver_calls: list[str] = []

    def spy_resolver(host, *_args, **_kwargs):  # pragma: no cover - must never run
        resolver_calls.append(host)
        return "127.0.0.1"

    app = create_serve_app(
        api_key="stage3-key",
        database_url=database_url,
        config=_config(database_url, raw_dir=tmp_path / "raw"),
        runner=ToolRunner(raw_dir=tmp_path / "raw"),
        resolver_fn=spy_resolver,
    )
    with TestClient(app) as test_client:
        run = _create_run(test_client, program_id)
        run_id = run["id"]
        # The target is deliberately *in* scope. Scope is enforced first, so an
        # out-of-scope target would be skipped before dispatch was ever consulted and
        # this test would prove nothing about unknown task types. In scope means the
        # request actually reaches the seam, where the type must be refused.
        _enqueue(test_client, run_id, "definitely_not_a_real_tool", LOOPBACK)

        result = test_client.post(f"/api/v1/runs/{run_id}/run", json={}, headers=_auth())

    # Documented failure state: the task failed and the run kept moving.
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "COMPLETED"
    assert result.json()["tasks"]["by_status"] == {"failed": 1}

    # Nothing was executed by any adapter, above all not the DNS resolver.
    assert resolver_calls == [], "an unknown task type was executed by the DNS adapter"

    # No execution was recorded either, so nothing claims this task produced a result.
    with psycopg.connect(database_url, row_factory=dict_row) as connection:
        tool_runs = connection.execute(
            "SELECT count(*) AS n FROM tool_runs WHERE task_id IN "
            "(SELECT id FROM tasks WHERE run_id = %s)",
            (run_id,),
        ).fetchone()["n"]
    assert tool_runs == 0


def test_served_execution_requires_live_postgres_by_default():
    """A served process without PostgreSQL refuses to start; it never falls back."""
    from api.serve import ServeConfigurationError

    previous = os.environ.pop("ARGUS_DATABASE_URL", None)
    try:
        with pytest.raises(ServeConfigurationError):
            create_serve_app(api_key="stage3-key")
    finally:
        if previous is not None:
            os.environ["ARGUS_DATABASE_URL"] = previous


# ===========================================================================
# The real, committed production adapters
#
# The tests above drive a purpose-built adapter so the *subprocess boundary* can be
# proven on any machine. The tests below use the adapters ARGUS actually ships --
# no subclass, no injection, no stand-in -- so the committed dispatch, validation,
# command construction and Tool Runner boundary are what get exercised.
#
# Tool availability is a *precondition* asserted explicitly, never a skip: if these
# binaries are absent the test fails and says so rather than quietly proving less.
# ===========================================================================


@pytest.fixture
def real_tools_on_path() -> Iterator[None]:
    """Make the venv's tool directory visible so ``shutil.which`` finds the binaries.

    The ProjectDiscovery binaries are installed next to the interpreter
    (``.venv\\Scripts``), which is not on PATH by default. Prepending it for the
    duration of the test lets the committed adapters discover their executables the
    same way they would on a machine where they are installed system-wide.
    """
    tool_dir = str(Path(sys.executable).parent)
    previous = os.environ.get("PATH", "")
    if tool_dir.lower() not in previous.lower().split(os.pathsep):
        os.environ["PATH"] = tool_dir + os.pathsep + previous
    try:
        yield
    finally:
        os.environ["PATH"] = previous


def _require_tool(executable: str) -> str:
    """Assert a real tool is installed, returning its resolved path.

    Deliberately an assertion rather than a skip: "the tool is not installed here"
    is a result to report, not a reason to pass quietly.
    """
    from core.tool_runner import is_executable_on_path

    assert is_executable_on_path(executable), (
        f"the committed adapter requires the {executable!r} executable on PATH; "
        f"expected it beside the interpreter at {Path(sys.executable).parent}"
    )
    import shutil

    return shutil.which(executable)


def test_served_path_executes_the_real_httpx_adapter(
    real_tools_on_path, database_url, program_id, target, tmp_path
):
    """End-to-end through the shipped ``HttpxProbeAdapter`` -- nothing injected.

    This is the real dispatch table, the real ``httpx`` binary, the real Tool Runner
    and real PostgreSQL: the argv the adapter committed is the argv that ran, and its
    outcome is persisted.
    """
    executable = _require_tool("httpx")
    app = create_serve_app(
        api_key="stage3-key",
        database_url=database_url,
        config=_config(database_url, raw_dir=tmp_path / "raw"),
        runner=ToolRunner(raw_dir=tmp_path / "raw"),
    )
    # No ``adapters=`` injection: http_probe must resolve to the committed adapter.
    assert isinstance(
        app.state.argus_execution.adapter_for(_task("http_probe")), HttpxProbeAdapter
    )

    with TestClient(app) as test_client:
        run = _create_run(test_client, program_id)
        run_id = run["id"]
        probe_target = f"{LOOPBACK}:{target.port}"
        _enqueue(test_client, run_id, "http_probe", probe_target)
        result = test_client.post(
            f"/api/v1/runs/{run_id}/run", json={}, headers=_auth()
        )

    assert result.status_code == 200, result.text
    assert result.json()["status"] == "COMPLETED"
    assert result.json()["tasks"]["by_status"] == {"completed": 1}

    with psycopg.connect(database_url, row_factory=dict_row) as connection:
        tool_runs = connection.execute(
            "SELECT tool_name, command, exit_code, raw_output_ref FROM tool_runs "
            "WHERE task_id IN (SELECT id FROM tasks WHERE run_id = %s)",
            (run_id,),
        ).fetchall()

    assert len(tool_runs) == 1
    tool_run = tool_runs[0]
    # The committed adapter's name and its committed argument array are what ran.
    assert tool_run["tool_name"] == "httpx"
    assert tool_run["command"] == [
        "httpx", "-json", "-tech-detect", "-title", "-status-code", probe_target
    ]
    # argv[0] is the bare executable name, resolved through PATH when the process is
    # created -- so compare it against the real installed binary, not a fixed path.
    assert Path(tool_run["command"][0]).stem == Path(executable).stem == "httpx"
    # The real binary ran to completion (exit 0, no timeout/launch failure).
    assert tool_run["exit_code"] == 0
    # Raw output was preserved by the real Tool Runner.
    raw_ref = Path(tool_run["raw_output_ref"])
    assert raw_ref.is_file()


def test_real_httpx_adapter_refuses_an_out_of_scope_target(real_tools_on_path):
    """The committed adapter validates scope itself, before building a command."""
    _require_tool("httpx")
    adapter = HttpxProbeAdapter()

    class _Task:
        type = "http_probe"
        target = "198.51.100.7:8080"

    in_scope = ScopeGuard.from_config(ScopeConfig(allowed_ips=[LOOPBACK]))
    with pytest.raises(ScopeViolation):
        adapter.validate(_Task(), in_scope)

    # The same target is accepted when the scope covers it, so the guard is the
    # thing that decided -- not the adapter refusing everything.
    adapter.validate(_Task(), ScopeGuard.from_config(ScopeConfig(allowed_ips=["198.51.100.7"])))


def test_httpx_does_not_probe_loopback_targets(real_tools_on_path, target):
    """Documents a hard limitation of the pinned httpx build.

    httpx v1.12.0 excludes private/loopback addresses from its input filter and
    offers no flag to override it: ``-allow``, ``-p``, ``-probe-all-ips`` and an
    explicit ``http://`` scheme all leave it silently skipping the host, exiting 0
    with no output and never opening a connection. The controlled server below
    therefore records zero requests.

    Consequence for Stage 3: the *positive* "the committed httpx adapter fetched the
    controlled target" claim is ENVIRONMENT-UNVERIFIED here, and cannot be made
    without either a non-loopback target (out of bounds: no external or public
    targets) or patching the shipped adapter's command construction. Everything up to
    the connection -- dispatch, scope validation, argv construction, Tool Runner
    execution, exit code and PostgreSQL persistence -- is proven by the test above.
    """
    executable = _require_tool("httpx")
    adapter = HttpxProbeAdapter()
    probe_target = f"{LOOPBACK}:{target.port}"

    class _Task:
        type = "http_probe"
        target = probe_target

    scope = ScopeGuard.from_config(ScopeConfig(allowed_ips=[LOOPBACK]))
    adapter.validate(_Task(), scope)  # in scope: the guard permits it
    command = adapter.build_command(_Task(), None)
    result = ToolRunner().run_command(command, tool="httpx")

    assert result.exit_code == 0, "the pinned httpx build no longer runs"
    # The tool started, understood the input, and declined to connect to loopback.
    assert target.hits == [], (
        "httpx unexpectedly probed a loopback target; if this build now supports it, "
        "the positive localhost proof can replace the ENVIRONMENT-UNVERIFIED item"
    )


def test_subfinder_dispatch_validation_and_command_are_proven_without_executing(
    real_tools_on_path,
):
    """Subfinder is proven as far as it can be here, and not one step further.

    ``SubfinderAdapter`` performs *passive* subdomain enumeration: its input is a
    registrable root domain and it answers by querying internet-wide passive
    sources. It has no localhost mode -- there is nothing to enumerate beneath
    ``127.0.0.1`` -- and running it for real would mean pointing it at a public
    domain and letting it contact third-party services, which is out of bounds.

    So it is deliberately not executed. What is proven instead is the part that is
    meaningful without network egress: that dispatch selects it, that it validates
    scope before doing anything, and that it builds the argument array the contract
    requires. Executing it is ENVIRONMENT-UNVERIFIED by design, not by omission.
    """
    _require_tool("subfinder")
    execution = ServedExecution(
        adapters={"subdomain_discovery": SubfinderAdapter},
        runner=ToolRunner(),
    )
    adapter = execution.adapter_for(_task("subdomain_discovery"))
    assert isinstance(adapter, SubfinderAdapter)

    class _Task:
        type = "subdomain_discovery"
        target = "198.51.100.7"

    # Scope is enforced by the adapter itself, before any command is built.
    with pytest.raises(ScopeViolation):
        adapter.validate(_Task(), ScopeGuard.from_config(ScopeConfig(allowed_ips=[LOOPBACK])))

    # An in-scope root domain builds a proper argument array (never a shell string).
    in_scope = ScopeGuard.from_config(ScopeConfig(allowed_ips=["198.51.100.7"]))
    adapter.validate(_Task(), in_scope)
    command = adapter.build_command(_Task(), None)
    assert command[:3] == ["subfinder", "-d", "198.51.100.7"]
    assert isinstance(command, list) and all(isinstance(part, str) for part in command)

    # An empty target is rejected outright rather than producing a bare invocation.
    class _Empty:
        type = "subdomain_discovery"
        target = "   "

    with pytest.raises(ValueError):
        adapter.build_command(_Empty(), None)
