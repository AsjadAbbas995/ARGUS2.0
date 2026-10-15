"""Phase 24 LIVE tests: historical (GAU) recon against real PostgreSQL.

Skipped automatically when ``ARGUS_TEST_DATABASE_URL`` is unset/unreachable
(``tests/conftest.py``). This module exercises the parts that only a real database can
prove: the corrected ``urls`` upsert truth table (proposal §10/§13.7, acceptance §14.3
and §14.4) over the production ``Repositories`` facade. The end-to-end
ingest->persist->project path and the no-expansion guard live in the same module.

No external host is contacted: every value is synthesized.
"""

from __future__ import annotations

from uuid import uuid4

import psycopg
import pytest
from psycopg.rows import dict_row

from core.config import Config, ScopeConfig
from core.scope_guard import ScopeGuard, extract_host
from database.migrate import apply, revert
from database.models.entities import (
    Asset,
    Ip,
    Port,
    Run,
    ScopeRule,
    Task,
    ToolRun,
    WebApp,
)
from database.repositories.all import Repositories
from api.serve import ServedExecution, _build_ingestor
from core.orchestrator import Orchestrator
from core.rate_limiter import RateLimiter
from core.tool_runner import ToolRunner
from recon.base import ToolExecution
from recon.historical import HistoricalUrlObservation
from recon.historical.gau import GauAdapter
from recon.ingest import plan_ingestion
from recon.dns.resolver import IpObservation
from recon.web.httpx_probe import WebAppObservation

HOSTNAME = "www.example.com"
WEB_IP = "203.0.113.44"
TARGET = "example.com"
RESOLVED = "93.184.216.34"


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


def _web_app(store) -> str:
    """Persist the canonical asset -> ip -> port -> web_app tree the URLs root to."""
    org = store.organizations.upsert("Phase 24 Org")
    program = store.programs.upsert(org["id"], "Phase 24 Program")["id"]
    asset = store.assets.upsert(
        Asset(program_id=program, hostname=HOSTNAME, source="phase24-seed")
    )
    ip = store.ips.upsert(WEB_IP)
    store.asset_ips.upsert(asset["id"], ip["id"])
    port_row = store.ports.upsert(
        Port(ip_id=ip["id"], port_number=8080, protocol="tcp", state="open")
    )
    app = store.web_apps.upsert(
        WebApp(
            asset_id=asset["id"],
            port_id=port_row["id"],
            status_code=200,
            title="Seed",
            server_header="nginx",
        )
    )
    return app["id"]


def _row(store, app_id, path):
    return store.conn.execute(
        "SELECT historical, source FROM urls WHERE web_app_id = %s AND path = %s",
        (app_id, path),
    ).fetchone()


# -- §13.7 / §14.3: the initial historical insert --------------------------------


def test_historical_insert_sets_true_and_gau(store) -> None:
    app = _web_app(store)
    row = store.urls.upsert(app, "/old/api", "gau", True)
    assert row["historical"] is True
    assert row["source"] == "gau"
    assert _row(store, app, "/old/api") == {"historical": True, "source": "gau"}


# -- §13.7 / §14.4: the four-row source-promotion truth table --------------------


def test_live_then_live_keeps_last_writer_wins(store) -> None:
    app = _web_app(store)
    store.urls.upsert(app, "/live-live", "katana", False)
    row = store.urls.upsert(app, "/live-live", "ffuf", False)
    assert row["historical"] is False
    assert row["source"] == "ffuf"


def test_live_then_historical_preserves_live_source(store) -> None:
    app = _web_app(store)
    store.urls.upsert(app, "/live-hist", "katana", False)
    row = store.urls.upsert(app, "/live-hist", "gau", True)
    assert row["historical"] is False
    assert row["source"] == "katana"


def test_historical_then_live_promotes_to_the_live_tool(store) -> None:
    app = _web_app(store)
    store.urls.upsert(app, "/hist-live", "gau", True)
    row = store.urls.upsert(app, "/hist-live", "katana", False)
    assert row["historical"] is False
    assert row["source"] == "katana"


def test_historical_then_historical_stays_historical(store) -> None:
    app = _web_app(store)
    store.urls.upsert(app, "/hist-hist", "gau", True)
    row = store.urls.upsert(app, "/hist-hist", "wayback", True)
    assert row["historical"] is True
    assert row["source"] == "wayback"


# -- §13.8 / §14.5: projection carries the flag onto the UrlRecord ---------------


def _scope() -> ScopeGuard:
    return ScopeGuard.from_config(
        ScopeConfig(allowed_domains=(TARGET,), allowed_ips=(f"{RESOLVED}/32",))
    )


def _program(store):
    org = store.organizations.upsert("Phase 24 Projection Org")
    program = store.programs.upsert(org["id"], "Phase 24 Projection Program")["id"]
    for rule_type, value in (("domain", TARGET), ("ip", RESOLVED)):
        store.scope_rules.upsert(
            ScopeRule(program_id=program, rule_type=rule_type, value=value, allowed=True)
        )
    return program


def _run(store, program):
    return store.create_run(
        Run(
            program_id=program,
            status="CREATED",
            target=TARGET,
            configuration_snapshot={"scope": {"allowed_domains": [TARGET]}},
        )
    )


def _ingest(store, run, artifacts, *, source) -> None:
    task = Task(
        id=uuid4(), run_id=run.id, type=source, target=TARGET, status="running"
    )
    store.insert_tasks([task])
    tool_run = store.insert_tool_run(
        ToolRun(
            task_id=task.id,
            tool_name=source,
            command=[source, "-d", TARGET],
            exit_code=0,
            raw_output_ref=f"raw/phase24-{source}.out",
        )
    )
    plan = plan_ingestion(
        artifacts,
        scope=_scope(),
        source=source,
        target_host=TARGET,
        max_artifacts=1000,
    )
    with store.transaction():
        store.ingest_observations(
            plan,
            tool_run_id=tool_run.id,
            raw_output_ref=tool_run.raw_output_ref,
            program_id=run.program_id,
        )


def test_projection_marks_a_historical_url_record(store) -> None:
    program = _program(store)
    run = _run(store, program)

    # A live web app so the URL has a run-evidenced web_app to root through.
    _ingest(
        store,
        run,
        [
            IpObservation(address=RESOLVED, record_type="A"),
            WebAppObservation(
                host=TARGET,
                url="https://example.com/",
                scheme="https",
                port=443,
                status_code=200,
                title="Example",
                webserver="nginx",
            ),
        ],
        source="httpx",
    )
    # A passive historical URL on the same host:port.
    _ingest(
        store,
        run,
        [
            HistoricalUrlObservation(
                host=TARGET,
                port=443,
                path="/old/admin",
                url="https://example.com/old/admin",
                source="gau",
            )
        ],
        source="gau",
    )

    payload = store.attack_surface(run.id)
    assert payload["available"] is True
    assert payload["records"]["by_kind"]["url"] == 1

    url_node = next(
        n for n in payload["graph"]["nodes"] if n["kind"] == "url"
    )
    # ``record_node`` mirrors the UrlRecord attributes onto the node; the value proves
    # the projected UrlRecord carried historical=True.
    assert url_node["attributes"]["historical"] == "True"
    assert url_node["attributes"]["path"] == "/old/admin"


# -- §13.4 / §14.6: a historical discovery creates no child task ------------------


class _FakeGau(GauAdapter):
    """The real adapter's validate, with a canned artifact set -- no subprocess."""

    def is_available(self) -> bool:
        return True

    def execute(self, task, runner, config, scope):
        self.validate(task, scope)
        return ToolExecution(
            tool="gau",
            command=["gau", "--json", extract_host(task.target) or ""],
            exit_code=0,
            raw_output_ref=None,
            artifacts=(
                HistoricalUrlObservation(
                    host="www.example.com",
                    port=443,
                    path="/old/admin",
                    url="https://www.example.com/old/admin",
                    source="gau",
                ),
            ),
        )


def test_a_historical_task_produces_no_child_task(store, tmp_path) -> None:
    def gau_factory():
        return _FakeGau()

    adapters = {"historical_recon": gau_factory, "gau": gau_factory}
    config = Config.from_dict(
        {
            "database": {"url": "unconfigured"},
            "scope": {"allowed_domains": [TARGET]},
            "web": {"historical_urls": True},
        }
    )
    execution = ServedExecution(
        adapters=adapters, runner=ToolRunner(raw_dir=tmp_path / "raw")
    )
    orchestrator = Orchestrator(
        storage=store,
        run_tool=execution.run,
        rate_limiter=RateLimiter.from_config(config.limits),
        ingest=_build_ingestor(store, config, execution.known_task_types()),
    )
    program = _program(store)
    run = orchestrator.create_run(
        Run(
            program_id=program,
            status="CREATED",
            target=TARGET,
            configuration_snapshot={"scope": {"allowed_domains": [TARGET]}},
        ),
        planned=[Task(run_id=None, type="historical_recon", target=TARGET)],
    )

    assert orchestrator.run_to_completion(run.id) == "COMPLETED"

    types = {t.type for t in orchestrator.list_tasks(run.id)}
    assert types == {"historical_recon"}
    assert "http_probe" not in types
