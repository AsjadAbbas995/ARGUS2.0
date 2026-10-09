"""Phase 22 LIVE tests: deterministic web crawling end-to-end against real PostgreSQL.

Skipped automatically when ``ARGUS_TEST_DATABASE_URL`` is unset/unreachable
(``tests/conftest.py``). Executes real SQL through the production ``Repositories``
facade and drives the real served composition -- two concerns nothing offline proves:

1. **The expansion chain enqueues ``web_crawl`` and the crawl facts persist + project.**
   The discovery expansion maps the completing ``http_probe``'s web-app artifact to a
   ``web_crawl`` child (``subfinder -> dns_resolve -> port_scan -> http_probe ->
   web_crawl``) seeded with the app's own recorded URL; the real ``KatanaAdapter``
   parses a recorded JSONL capture into canonical observations that are rooted through
   ``asset -> ip -> port -> web_app`` and persisted as ``urls`` / ``endpoints`` /
   ``parameters`` / ``javascript_files`` rows, then surface in ``attack_surface`` as
   ``url`` / ``endpoint`` / ``parameter`` / ``javascript`` records and graph edges.
2. **The served HTTP app dispatches ``web_crawl``.** A real ``create_serve_app`` run
   accepts a ``web_crawl`` task and executes the real adapter through a controlled
   runner that replays a recorded crawl capture, persisting the same canonical rows.

No public or third-party host is contacted: the loopback HTTP server exists only so the
URLs the crawl replays resolve to a real socket; the crawl itself replays recorded JSONL
(``katana`` is a deterministic parser, so the tool is exercised without the binary).
The harness doubles override ``execute``/``run_command`` only -- the orchestrator, scope
guard, rate limiter, ingestion, expansion, persistence and projection are the real ones
(same approach as ``test_phase21_live.py``).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

import psycopg
import pytest
from psycopg.rows import dict_row
from starlette.testclient import TestClient

from ai.run_context import coverage_gaps, uncovered_without_capability
from api.serve import ServedExecution, _build_ingestor, create_serve_app
from core.config import Config
from core.orchestrator import Orchestrator
from core.rate_limiter import RateLimiter
from core.scope_guard import extract_host
from core.tool_runner import CommandResult, ToolRunner
from database.migrate import apply, revert
from database.models.entities import Asset, Ip, Port, Run, ScopeRule, Task, WebApp
from database.repositories.all import Repositories
from database.repositories.base import DatabaseConnection
from recon.base import ToolExecution
from recon.dns.resolver import DnsResolverAdapter
from recon.expansion import (
    CHILD_TYPE_DNS,
    CHILD_TYPE_HTTP_PROBE,
    CHILD_TYPE_PORT_SCAN,
    CHILD_TYPE_WEB_CRAWL,
)
from recon.ports.nmap import NmapAdapter, PortObservation
from recon.subdomains.subfinder import SubfinderAdapter
from recon.web.httpx_probe import HttpxProbeAdapter, WebAppObservation
from recon.web.katana import KatanaAdapter

LOOPBACK = "127.0.0.1"
HOSTNAME = "www.example.com"
WEB_IP = "203.0.113.42"
API_KEY = "phase22-key"

FIXTURES = __import__("pathlib").Path(__file__).parent / "fixtures" / "katana"


def _normal() -> str:
    return (FIXTURES / "normal.ndjson").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# the loopback target (only so replayed URLs name a real socket)
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        body = b"<html><body>phase22</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


class ControlledTarget:
    def __init__(self) -> None:
        self._server = ThreadingHTTPServer((LOOPBACK, 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def target() -> ControlledTarget:
    server = ControlledTarget()
    try:
        yield server
    finally:
        server.close()


def _scope_dict() -> dict:
    return {
        "allowed_domains": ["example.com", "localhost"],
        "allowed_ips": ["203.0.113.0/24", "127.0.0.0/8"],
        "excluded": [],
    }


def _snapshot() -> dict:
    config = Config.from_dict(
        {
            "database": {"url": "unconfigured"},
            "scope": _scope_dict(),
            "network": {"tcp_ports": {"start": 1, "end": 1000}},
        }
    )
    snapshot = config.to_dict()
    snapshot.pop("database", None)
    return snapshot


@pytest.fixture
def schema(database_url: str):
    c = psycopg.connect(database_url, row_factory=dict_row)
    revert(c, 0)
    apply(c)
    yield c
    c.rollback()
    tables = c.execute(
        "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()"
    ).fetchall()
    if tables:
        names = ", ".join(f'"{t["tablename"]}"' for t in tables)
        c.execute(f"TRUNCATE {names} RESTART IDENTITY CASCADE")
    c.close()


@pytest.fixture
def store(schema):
    return Repositories(schema)


def _program(store) -> str:
    org = store.organizations.upsert("Phase 22 Org")
    return store.programs.upsert(org["id"], "Phase 22 Program")["id"]


def _make_program(database_url: str) -> str:
    connection = DatabaseConnection(database_url)
    repositories = Repositories(connection.connect())
    try:
        org = repositories.organizations.upsert(f"argus-phase22-org-{uuid4().hex}")
        program = repositories.programs.upsert(
            org["id"], f"argus-phase22-program-{uuid4().hex}"
        )
        for rule_type, value in (("domain", HOSTNAME), ("ip", LOOPBACK)):
            repositories.scope_rules.upsert(
                ScopeRule(
                    program_id=program["id"],
                    rule_type=rule_type,
                    value=value,
                    allowed=True,
                )
            )
        return str(program["id"])
    finally:
        connection.close()


def _seed_web_app(database_url: str, program: str, hostname: str, port: int) -> None:
    """Persist the canonical asset -> ip -> port -> web_app tree the crawl roots to."""
    connection = DatabaseConnection(database_url)
    repositories = Repositories(connection.connect())
    try:
        asset = repositories.assets.upsert(
            Asset(program_id=program, hostname=hostname, source="phase22-seed")
        )
        ip = repositories.ips.upsert(LOOPBACK)
        repositories.asset_ips.upsert(asset["id"], ip["id"])
        port_row = repositories.ports.upsert(
            Port(ip_id=ip["id"], port_number=port, protocol="tcp", state="open")
        )
        repositories.web_apps.upsert(
            WebApp(
                asset_id=asset["id"],
                port_id=port_row["id"],
                status_code=200,
                title="Seed",
                server_header="nginx",
            )
        )
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# harness doubles
# ---------------------------------------------------------------------------


class _FakeSubfinder(SubfinderAdapter):
    def is_available(self) -> bool:
        return True

    def execute(self, task, runner, config, scope):
        self.validate(task, scope)
        return ToolExecution(
            tool="subfinder",
            command=["subfinder", "-d", extract_host(task.target), "-json"],
            exit_code=0,
            raw_output_ref=None,
            artifacts=("www.example.com",),
        )


class _FakeNmap(NmapAdapter):
    def is_available(self) -> bool:
        return True

    def execute(self, task, runner, config, scope):
        self.validate(task, scope)
        return ToolExecution(
            tool="nmap",
            command=["nmap", "-sT", "-Pn", str(extract_host(task.target))],
            exit_code=0,
            raw_output_ref=None,
            artifacts=(
                PortObservation(
                    address=WEB_IP,
                    port=8080,
                    protocol="tcp",
                    state="open",
                    service="http",
                    host="www.example.com",
                ),
            ),
        )


class _FakeHttpx(HttpxProbeAdapter):
    def is_available(self) -> bool:
        return True

    def execute(self, task, runner, config, scope):
        self.validate(task, scope)
        from recon.web.httpx_probe import extract_host_from_value

        host = extract_host_from_value(getattr(task, "target", ""))
        return ToolExecution(
            tool="httpx",
            command=["httpx", "-json", str(getattr(task, "target", ""))],
            exit_code=0,
            raw_output_ref=None,
            artifacts=(
                WebAppObservation(
                    host=host,
                    url=f"http://{host}:8080/",
                    scheme="http",
                    port=8080,
                    status_code=200,
                    webserver="nginx",
                    title="Example",
                    content_type="text/html",
                ),
            ),
        )


class _FakeKatana(KatanaAdapter):
    """The real adapter's validate/command/parse, with the subprocess replayed."""

    def is_available(self) -> bool:
        return True

    def execute(self, task, runner, config, scope):
        self.validate(task, scope)
        command = self.build_command(task, config)
        result = runner.run_command(
            command, tool="katana", timeout=self.overall_timeout
        )
        return ToolExecution(
            tool="katana",
            command=command,
            exit_code=result.exit_code,
            raw_output_ref=result.raw_output_ref,
            artifacts=tuple(self.parse(result)),
        )


class _CannedRunner(ToolRunner):
    """A controlled runner that replays a recorded JSONL capture.

    Only ``run_command`` is overridden so the real Katana adapter's command, scope,
    and parse logic run exactly as in production; raw output is still preserved
    through the real :meth:`ToolRunner.save_raw`.
    """

    def __init__(self, stdout: str, *, raw_dir):
        super().__init__(raw_dir=raw_dir)
        self._stdout = stdout

    def run_command(self, command, *, tool, timeout=None, env=None, cwd=None):
        raw_ref = self.save_raw(tool, self._stdout, extension="jsonl", tag="crawl")
        return CommandResult(
            tool=tool,
            command=list(command),
            exit_code=0,
            stdout=self._stdout,
            stderr="",
            raw_output_ref=raw_ref,
        )


def _dns_factory() -> DnsResolverAdapter:
    def resolve(hostname, record_type):
        if hostname == "www.example.com" and record_type == "A":
            return (WEB_IP,), None
        return (), "NXDOMAIN"

    return DnsResolverAdapter(resolver_fn=resolve, timeout=1.0)


def _served_pipeline(store, tmp_path):
    adapters = {
        "dns_resolve": _dns_factory,
        "dns": _dns_factory,
        "resolve": _dns_factory,
        "subfinder": _FakeSubfinder,
        "subdomain_enum": _FakeSubfinder,
        "port_scan": _FakeNmap,
        "nmap": _FakeNmap,
        "http_probe": _FakeHttpx,
        "httpx": _FakeHttpx,
        "web_probe": _FakeHttpx,
        # Phase 22: both spellings route to the same crawl adapter.
        "web_crawl": _FakeKatana,
        "katana": _FakeKatana,
    }
    config = Config.from_dict({"database": {"url": "unconfigured"}, "scope": _scope_dict()})
    execution = ServedExecution(
        adapters=adapters,
        runner=_CannedRunner(_normal(), raw_dir=tmp_path / "storage" / "raw"),
    )
    orchestrator = Orchestrator(
        storage=store,
        run_tool=execution.run,
        rate_limiter=RateLimiter.from_config(config.limits),
        ingest=_build_ingestor(store, config, execution.known_task_types()),
    )
    return orchestrator, execution


# ---------------------------------------------------------------------------
# 1. served pipeline: expansion deepens http_probe -> web_crawl, facts project
# ---------------------------------------------------------------------------


def test_full_served_pipeline_expands_into_web_crawl_and_projects_facts(
    store, tmp_path
) -> None:
    orchestrator, execution = _served_pipeline(store, tmp_path)
    program = _program(store)
    run = orchestrator.create_run(
        Run(
            program_id=program,
            status="CREATED",
            target="example.com",
            configuration_snapshot=_snapshot(),
        ),
        planned=[Task(run_id=None, type="subfinder", target="example.com")],
    )

    assert orchestrator.run_to_completion(run.id) == "COMPLETED"

    tasks = orchestrator.list_tasks(run.id)
    by_type: dict[str, list[Task]] = {}
    for task in tasks:
        by_type.setdefault(task.type, []).append(task)
    assert set(by_type) == {
        "subfinder",
        CHILD_TYPE_DNS,
        CHILD_TYPE_PORT_SCAN,
        CHILD_TYPE_HTTP_PROBE,
        CHILD_TYPE_WEB_CRAWL,
    }
    assert {t.status for ts in by_type.values() for t in ts} == {"completed"}

    crawl = by_type[CHILD_TYPE_WEB_CRAWL]
    assert len(crawl) == 1
    # seeded with the app URL http_probe recorded; the seed doubles as the reuse payload
    assert crawl[0].target == "http://www.example.com:8080/"
    assert crawl[0].parent_task_id == by_type[CHILD_TYPE_HTTP_PROBE][0].id
    assert json.loads(crawl[0].reason) == {"url": "http://www.example.com:8080/"}

    # canonical crawl rows per normal.ndjson: 5 urls, 5 GET endpoints, 3 params, 1 js
    app = schema_row_for(store, HOSTNAME, 8080)
    url_rows = store.urls.list_by_ids(
        [r["id"] for r in store.conn.execute(
            "SELECT id FROM urls WHERE web_app_id = %s ORDER BY path", (app["id"],)
        ).fetchall()]
    )
    assert {r["path"] for r in url_rows} == {
        "/",
        "/about",
        "/search",
        "/static/app.js",
        "/login",
    }
    endpoint_rows = store.conn.execute(
        "SELECT method, pattern FROM endpoints e JOIN urls u ON u.id = e.url_id "
        "WHERE u.web_app_id = %s ORDER BY pattern, method",
        (app["id"],),
    ).fetchall()
    assert {(r["method"], r["pattern"]) for r in endpoint_rows} == {
        ("GET", "/"),
        ("GET", "/about"),
        ("GET", "/search"),
        ("GET", "/static/app.js"),
        ("GET", "/login"),
    }
    param_rows = store.conn.execute(
        "SELECT p.name FROM parameters p "
        "JOIN endpoints e ON e.id = p.endpoint_id "
        "JOIN urls u ON u.id = e.url_id WHERE u.web_app_id = %s",
        (app["id"],),
    ).fetchall()
    assert {r["name"] for r in param_rows} == {"q", "page", "next"}
    js_rows = store.conn.execute(
        "SELECT url FROM javascript_files WHERE web_app_id = %s", (app["id"],)
    ).fetchall()
    assert {r["url"] for r in js_rows} == {
        "http://www.example.com:8080/static/app.js"
    }

    kinds = {row["entity_type"] for row in store.evidence.list_for_run(run.id)}
    assert {"url", "endpoint", "parameter", "javascript"} <= kinds

    # The completed crawl closes the ``web_crawl`` stage: it is neither a runnable gap
    # nor an uncovered-without-capability gap once the served composition registers it.
    runnable = execution.known_task_types()
    assert "web_crawl" not in coverage_gaps(tasks, runnable)
    assert "web_crawl" not in uncovered_without_capability(tasks, runnable)

    surface = store.attack_surface(run.id)
    by_kind = surface["records"]["by_kind"]
    assert by_kind.get("url") == 5
    assert by_kind.get("endpoint") == 5
    assert by_kind.get("parameter") == 3
    assert by_kind.get("javascript") == 1

    url_nodes = {n["key"] for n in surface["graph"]["nodes"] if n["kind"] == "url"}
    assert "www.example.com:8080/about" in url_nodes
    serves = [
        e
        for e in surface["graph"]["edges"]
        if e["kind"] == "serves_url" and e["target"] == "www.example.com:8080/about"
    ]
    assert serves, "a crawled URL must be linked to its web app"


def schema_row_for(store, hostname: str, port: int) -> dict:
    return store.conn.execute(
        "SELECT w.* FROM web_apps w "
        "JOIN assets a ON a.id = w.asset_id "
        "JOIN ports p ON p.id = w.port_id "
        "WHERE a.hostname = %s AND p.port_number = %s",
        (hostname, port),
    ).fetchone()


# ---------------------------------------------------------------------------
# 2. served HTTP app: dispatches web_crawl and persists canonical crawl rows
# ---------------------------------------------------------------------------


def test_served_app_dispatches_web_crawl_and_persists_facts(
    database_url, target: ControlledTarget, store, schema, tmp_path
) -> None:
    program = _make_program(database_url)
    port = target.port
    _seed_web_app(database_url, program, HOSTNAME, port)

    crawl = "\n".join(
        [
            json.dumps({"request": {"method": "GET", "endpoint": f"http://{HOSTNAME}:{port}/"}}),
            json.dumps({"request": {"method": "GET", "endpoint": f"http://{HOSTNAME}:{port}/about"}}),
            json.dumps(
                {
                    "request": {
                        "method": "GET",
                        "endpoint": f"http://{HOSTNAME}:{port}/search?q=argus&page=2",
                    }
                }
            ),
            json.dumps(
                {
                    "request": {
                        "method": "GET",
                        "endpoint": f"http://{HOSTNAME}:{port}/static/app.js",
                    }
                }
            ),
        ]
    )

    app = create_serve_app(
        api_key=API_KEY,
        database_url=database_url,
        config=Config.from_dict(
            {
                "database": {"url": database_url},
                "scope": _scope_dict(),
                "storage": {"raw_dir": str(tmp_path / "raw")},
            }
        ),
        runner=_CannedRunner(crawl, raw_dir=tmp_path / "raw"),
        adapters={"web_crawl": _FakeKatana, "katana": _FakeKatana},
    )
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/runs",
            json={
                "target": HOSTNAME,
                "program_id": program,
                "configuration": {
                    "scope": {
                        "allowed_domains": [HOSTNAME],
                        "allowed_ips": [LOOPBACK],
                    }
                },
            },
            headers={"Authorization": f"Bearer {API_KEY}"},
        )
        assert created.status_code == 201, created.text
        run_id = created.json()["id"]

        enqueued = client.post(
            f"/api/v1/runs/{run_id}/tasks",
            json={"tasks": [{"type": "web_crawl", "target": f"http://{HOSTNAME}:{port}/"}]},
            headers={"Authorization": f"Bearer {API_KEY}"},
        )
        assert enqueued.status_code == 201, enqueued.text

        result = client.post(
            f"/api/v1/runs/{run_id}/run",
            json={},
            headers={"Authorization": f"Bearer {API_KEY}"},
        )
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["status"] == "COMPLETED", body
    assert body["tasks"]["by_status"] == {"completed": 1}, body["tasks"]

    # raw crawl capture preserved through the controlled runner
    raw = list((tmp_path / "raw" / "katana").glob("*.jsonl"))
    assert raw, "raw crawl capture must be preserved under storage/raw/katana"

    app_row = schema_row_for(store, HOSTNAME, port)
    assert app_row is not None
    url_rows = store.conn.execute(
        "SELECT path FROM urls WHERE web_app_id = %s ORDER BY path", (app_row["id"],)
    ).fetchall()
    assert {r["path"] for r in url_rows} == {"/", "/about", "/search", "/static/app.js"}
    js_rows = store.conn.execute(
        "SELECT url FROM javascript_files WHERE web_app_id = %s", (app_row["id"],)
    ).fetchall()
    assert {r["url"] for r in js_rows} == {
        f"http://{HOSTNAME}:{port}/static/app.js"
    }

    endpoint_rows = store.conn.execute(
        "SELECT method, pattern FROM endpoints e JOIN urls u ON u.id = e.url_id "
        "WHERE u.web_app_id = %s ORDER BY pattern, method",
        (app_row["id"],),
    ).fetchall()
    assert {(r["method"], r["pattern"]) for r in endpoint_rows} == {
        ("GET", "/"),
        ("GET", "/about"),
        ("GET", "/search"),
        ("GET", "/static/app.js"),
    }
    param_rows = store.conn.execute(
        "SELECT p.name FROM parameters p "
        "JOIN endpoints e ON e.id = p.endpoint_id "
        "JOIN urls u ON u.id = e.url_id WHERE u.web_app_id = %s",
        (app_row["id"],),
    ).fetchall()
    assert {r["name"] for r in param_rows} == {"q", "page"}

    # The served run evidences every crawl fact it observed, with the entity id it was
    # rooted to, so the facts are attributed to *this* run. The projection of
    # url/endpoint/parameter/javascript records is exercised end-to-end in test 1,
    # where the discovering ``http_probe`` also run-evidences the parent web app; this
    # direct-seed path has no web-app evidence, and ``build_records`` withholds a crawl
    # fact whose parent web app is not itself run-evidenced rather than stitch a record
    # to a stand-in (``database/projection.py``).
    evidenced = {
        r["entity_type"]
        for r in store.evidence.list_fact_refs_for_run(run_id)
        if r["entity_id"] is not None
    }
    assert {"url", "endpoint", "parameter", "javascript"} <= evidenced
