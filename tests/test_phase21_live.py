"""Phase 21A LIVE tests: served `tech_detect` end-to-end against real PostgreSQL.

Skipped automatically when ``ARGUS_TEST_DATABASE_URL`` is unset/unreachable
(``tests/conftest.py``). Executes real SQL through the production
``Repositories`` facade, then drives the real served composition through the
real repository-backed app (test 1) and the real orchestrator (test 2) -- no
in-memory substitutes.

Two concerns nothing offline proves:

1. **Real bounded fetch + fingerprint + persistence.** A real
   ``TechDetectAdapter`` (in-process, stdlib HTTP) performs a genuine GET to a
   ``ThreadingHTTPServer`` the test starts on ``127.0.0.1`` (an ephemeral port,
   resolved through ``localhost``). No public or third-party host is contacted.
   The fingerprint function runs over the real response and its canonical
   categories are persisted into real ``technologies``/``asset_technologies``
   rows with provenance, surfacing in ``attack_surface`` as ``technology``
   records. The adapter preserves the raw capture under ``storage/raw/tech_detect/``
   through the controlled Tool Runner.
2. **The expansion chain enqueues ``tech_detect``.** The discovery expansion
   maps the completing ``http_probe``'s web-app artifact to a ``tech_detect``
   child (``subfinder -> dns_resolve -> port_scan -> http_probe -> tech_detect``)
   with the captured signals embedded as the reuse payload; the real adapter
   fingerprints from those signals with no second request and the technology is
   persisted.

The web-app artifacts for the first four stages come from harness doubles that
override ``execute`` only -- the orchestrator, scope guard, rate limiter,
ingestion, expansion, persistence and projection layers they run through are the
real ones (same approach as ``test_phase20_live.py``).
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

from api.serve import ServedExecution, _build_ingestor, create_serve_app
from core.config import Config
from core.orchestrator import Orchestrator
from core.rate_limiter import RateLimiter
from core.scope_guard import extract_host
from core.tool_runner import ToolRunner
from database.migrate import apply, revert
from database.models.entities import Run, ScopeRule, Task
from database.repositories.all import Repositories
from database.repositories.base import DatabaseConnection
from recon.base import ToolExecution
from recon.dns.resolver import DnsResolverAdapter
from recon.expansion import CHILD_TYPE_DNS, CHILD_TYPE_HTTP_PROBE, CHILD_TYPE_PORT_SCAN, CHILD_TYPE_TECH_DETECT
from recon.ports.nmap import NmapAdapter, PortObservation
from recon.subdomains.subfinder import SubfinderAdapter
from recon.web.httpx_probe import HttpxProbeAdapter, WebAppObservation
from recon.web.tech_detect import TechDetectAdapter

LOOPBACK = "127.0.0.1"
HOSTNAME = "localhost"
WEB_IP = "203.0.113.42"
API_KEY = "phase21-key"


# ---------------------------------------------------------------------------
# the controlled loopback target (a genuinely served HTTP response)
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    """A real HTTP server answering a real GET with explicit fingerprint signals.

    ``server_version`` is "cloudflare" so the canonical ``Server`` header is
    deterministic, plus a ``Cf-Ray`` header, ``X-Powered-By`` runtime and a CMS
    generator tag in the body -- every first-class category exercised: cdn, other,
    cms.
    """

    server_version = "cloudflare"
    sys_version = ""
    hits: list[int] = []

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        type(self).hits.append(1)
        body = (
            b"<html><head><title>Controlled</title>"
            b'<meta name="generator" content="WordPress 6.4" /></head>'
            b"<body>controlled</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cf-Ray", "abc123-EWR")
        self.send_header("X-Powered-By", "PHP/8.2")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass  # keep test output quiet


class ControlledTarget:
    def __init__(self) -> None:
        _Handler.hits = []
        self._server = ThreadingHTTPServer((LOOPBACK, 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def url(self) -> str:
        return f"http://{HOSTNAME}:{self.port}/"

    @property
    def hits(self) -> int:
        return len(_Handler.hits)

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
    """Migrate a clean schema, yield an open connection, then tear rows down."""
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
    org = store.organizations.upsert("Phase 21A Org")
    return store.programs.upsert(org["id"], "Phase 21A Program")["id"]


def _make_program(database_url: str) -> str:
    """A real program whose persisted ``scope_rules`` authorize the loopback target.

    ``api/server`` resolves a run's scope from the program's rules (fail-closed for
    a rule-less program) and refuses a request scope that reaches outside them, so
    both the domain ``localhost`` and the IP ``127.0.0.1`` are persisted. The
    insert runs on an autocommit connection so the serve-app storage (a separate,
    later connection) can read it.
    """
    connection = DatabaseConnection(database_url)
    repositories = Repositories(connection.connect())
    try:
        org = repositories.organizations.upsert(f"argus-phase21-org-{uuid4().hex}")
        program = repositories.programs.upsert(
            org["id"], f"argus-phase21-program-{uuid4().hex}"
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


# ---------------------------------------------------------------------------
# 1. Served app: real in-process fetch -> fingerprint -> persistence
# ---------------------------------------------------------------------------


def test_served_tech_detect_really_fetches_and_persists_technologies(
    database_url, target: ControlledTarget, store, schema, tmp_path
) -> None:
    program = _make_program(database_url)
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
        runner=ToolRunner(raw_dir=tmp_path / "raw"),
    )
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/runs",
            json={
                "target": HOSTNAME,
                "program_id": program,
                # A request scope is only ever a subset of the program's rules.
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
            json={"tasks": [{"type": "tech_detect", "target": target.url}]},
            headers={"Authorization": f"Bearer {API_KEY}"},
        )
        assert enqueued.status_code == 201, enqueued.text

        result = client.post(
            f"/api/v1/runs/{run_id}/run", json={}, headers={"Authorization": f"Bearer {API_KEY}"}
        )
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["status"] == "COMPLETED", body
    assert body["tasks"]["by_status"] == {"completed": 1}, body["tasks"]

    # the real adapter really performed the bounded in-process request
    assert target.hits == 1, "the controlled target was reached once"

    # the raw capture was preserved through the controlled runner
    raw = list((tmp_path / "raw" / "tech_detect").glob("*.json"))
    assert raw, "raw fingerprint capture must be preserved under storage/raw/tech_detect"
    capture = json.loads(raw[0].read_text(encoding="utf-8"))
    assert capture["source"] == "fetch"
    assert capture["host"] == "localhost"

    # canonical categories persisted with provenance
    assets = schema.execute(
        "SELECT id FROM assets WHERE hostname = %s", (HOSTNAME,)
    ).fetchone()
    assert assets is not None
    technology_rows = schema.execute(
        "SELECT t.name, t.category FROM technologies t "
        "JOIN asset_technologies at ON at.technology_id = t.id "
        "WHERE at.asset_id = %s ORDER BY t.name",
        (assets["id"],),
    ).fetchall()
    assert {(r["name"], r["category"]) for r in technology_rows} == {
        ("cloudflare", "cdn"),
        ("php", "other"),
        ("wordpress", "cms"),
    }

    kinds = {row["entity_type"] for row in store.evidence.list_for_run(run_id)}
    assert {"asset", "technology", "asset_technology"} <= kinds

    surface = store.attack_surface(run_id)
    assert surface["records"]["by_kind"].get("technology") == 3
    tech_nodes = {n["key"] for n in surface["graph"]["nodes"] if n["kind"] == "technology"}
    assert {"cloudflare@localhost", "php@localhost", "wordpress@localhost"} <= tech_nodes


# ---------------------------------------------------------------------------
# 2. Served pipeline: expansion deepens http_probe -> tech_detect (reuse)
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
        # Phase 21A: the REAL in-process tech_detect adapter (reuse path).
        "tech_detect": TechDetectAdapter,
        "whatweb": TechDetectAdapter,
    }
    config = Config.from_dict({"database": {"url": "unconfigured"}, "scope": _scope_dict()})
    execution = ServedExecution(
        adapters=adapters,
        runner=ToolRunner(raw_dir=tmp_path / "storage" / "raw"),
    )
    orchestrator = Orchestrator(
        storage=store,
        run_tool=execution.run,
        rate_limiter=RateLimiter.from_config(config.limits),
        ingest=_build_ingestor(store, config, execution.known_task_types()),
    )
    return orchestrator, execution


def test_full_served_pipeline_expands_into_tech_detect_and_reuses_signals(
    store, tmp_path
) -> None:
    orchestrator, _ = _served_pipeline(store, tmp_path)
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

    final = orchestrator.run_to_completion(run.id)
    assert final == "COMPLETED"

    tasks = orchestrator.list_tasks(run.id)
    by_type: dict[str, list[Task]] = {}
    for task in tasks:
        by_type.setdefault(task.type, []).append(task)
    assert set(by_type) == {
        "subfinder",
        CHILD_TYPE_DNS,
        CHILD_TYPE_PORT_SCAN,
        CHILD_TYPE_HTTP_PROBE,
        CHILD_TYPE_TECH_DETECT,
    }
    assert {s for s in (t.status for ts in by_type.values() for t in ts)} == {"completed"}

    detect = by_type[CHILD_TYPE_TECH_DETECT]
    assert len(detect) == 1
    assert detect[0].target == "www.example.com:8080"
    # the tech_detect child hangs directly off the completing http_probe task
    assert detect[0].parent_task_id == by_type[CHILD_TYPE_HTTP_PROBE][0].id
    # the probe's captured signals travelled with the task as the reuse payload
    assert json.loads(detect[0].reason) == {
        "server_header": "nginx",
        "title": "Example",
        "content_type": "text/html",
    }

    surface = store.attack_surface(run.id)
    assert surface["records"]["by_kind"].get("technology") == 1
    tech_nodes = [n["key"] for n in surface["graph"]["nodes"] if n["kind"] == "technology"]
    assert tech_nodes == ["nginx@www.example.com"]
    kinds = {row["entity_type"] for row in store.evidence.list_for_run(run.id)}
    assert {"technology", "asset_technology"} <= kinds