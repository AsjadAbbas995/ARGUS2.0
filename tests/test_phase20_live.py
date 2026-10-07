"""Phase 20A LIVE tests: port discovery end-to-end against real PostgreSQL.

Skipped automatically when ``ARGUS_TEST_DATABASE_URL`` is unset/unreachable
(``tests/conftest.py``). Executes real SQL through the production
``Repositories`` facade, then drives the full served composition
(``api/serve.ServedExecution`` + ``_build_ingestor`` + ``Orchestrator``) through
``run_to_completion`` against the same database -- no in-memory substitutes.

Two concerns no fake-storage test can prove:

1. A directly observed port persists as a real ``ports`` row (``ip_id`` FK,
   protocol/state CHECKs), is linked to its asset, and its ``ENTITY_PORT``
   evidence reaches the Phase 15 projection so ``attack_surface`` reports it.
2. The discovery-to-task expansion runs inside the orchestrator's transaction:
   ``subfinder -> dns_resolve -> port_scan -> http_probe`` children are
   enqueued from a real ingest callback and executed to ``COMPLETED``.

External binaries (``subfinder``/``nmap``/``httpx``) are not installed in this
environment, so the tool adapters are driven by harness doubles that override
``execute`` only -- the orchestrator, scope guard, rate limiter, ingestion,
expansion, persistence and projection layers they run through are the real ones.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest
from psycopg.rows import dict_row

from api.serve import ServedExecution, _build_ingestor
from core.config import Config
from core.orchestrator import Orchestrator
from core.rate_limiter import RateLimiter
from core.scope_guard import extract_host
from core.tool_runner import ToolRunner
from database.migrate import apply, revert
from database.models.entities import Run, Task
from database.repositories.all import Repositories
from recon.base import ToolExecution
from recon.dns.resolver import DnsResolverAdapter, IpObservation
from recon.expansion import CHILD_TYPE_DNS, CHILD_TYPE_HTTP_PROBE, CHILD_TYPE_PORT_SCAN
from recon.ingest import plan_ingestion
from recon.ports.nmap import NmapAdapter, PortObservation
from recon.subdomains.subfinder import SubfinderAdapter
from recon.web.httpx_probe import HttpxProbeAdapter, WebAppObservation

WEB_IP = "203.0.113.42"


def _scope_dict() -> dict:
    return {
        "allowed_domains": ["example.com"],
        "allowed_ips": ["203.0.113.0/24"],
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
    org = store.organizations.upsert("Phase 20A Org")
    return store.programs.upsert(org["id"], "Phase 20A Program")["id"]


# ---------------------------------------------------------------------------
# 1. Standalone port persistence + projection
# ---------------------------------------------------------------------------


def test_port_plan_persists_ip_asset_link_port_and_evidence(store, schema) -> None:
    program = _program(store)
    run = store.create_run(
        Run(program_id=program, status="CREATED", target="example.com", configuration_snapshot=_snapshot())
    )
    task = Task(id=uuid4(), run_id=run.id, type="subdomain_enum", target="example.com", status="pending")
    store.insert_tasks([task])
    tool_run = store.insert_tool_run(
        _tool_run(task.id, "subfinder", ["subfinder", "-d", "example.com"])
    )

    plan = plan_ingestion(
        [
            PortObservation(
                address=WEB_IP,
                port=443,
                protocol="tcp",
                state="open",
                service="https",
                version="nginx 1.25.1",
                host="www.example.com",
            )
        ],
        scope=SimpleNamespace(check_ip=lambda a: SimpleNamespace(in_scope=True), check_host=lambda h: SimpleNamespace(in_scope=True)),
        source="nmap",
        target_host="www.example.com",
    )
    store.ingest_observations(
        plan, tool_run_id=tool_run.id, raw_output_ref="raw/nmap/scan.xml", program_id=program
    )

    asset = schema.execute(
        "SELECT * FROM assets WHERE hostname = %s", ("www.example.com",)
    ).fetchone()
    assert asset is not None
    ip = schema.execute("SELECT * FROM ips WHERE address = %s", (WEB_IP,)).fetchone()
    assert ip is not None
    link = schema.execute(
        "SELECT * FROM asset_ips WHERE asset_id = %s AND ip_id = %s",
        (asset["id"], ip["id"]),
    ).fetchone()
    assert link is not None
    port = schema.execute(
        "SELECT * FROM ports WHERE ip_id = %s AND port_number = %s AND protocol = %s",
        (ip["id"], 443, "tcp"),
    ).fetchone()
    assert port is not None
    assert (port["state"], port["service"], port["version"]) == (
        "open",
        "https",
        "nginx 1.25.1",
    )

    kinds = {row["entity_type"] for row in store.evidence.list_for_run(run.id)}
    assert {"port", "ip", "asset_ip", "asset"} <= kinds

    surface = store.attack_surface(run.id)
    assert surface["records"]["by_kind"].get("port") == 1
    port_nodes = [n for n in surface["graph"]["nodes"] if n["kind"] == "port"]
    assert any(f"{WEB_IP}:443" == n["key"] for n in port_nodes)


def test_standalone_port_is_a_fact_not_a_finding(store, schema) -> None:
    program = _program(store)
    run = store.create_run(
        Run(program_id=program, status="CREATED", target="example.com", configuration_snapshot=_snapshot())
    )
    task = Task(id=uuid4(), run_id=run.id, type="subdomain_enum", target="example.com", status="pending")
    store.insert_tasks([task])
    tool_run = store.insert_tool_run(_tool_run(task.id, "subfinder", ["subfinder"]))
    store.ingest_observations(
        plan_ingestion(
            [PortObservation(address=WEB_IP, port=22, state="open")],
            scope=SimpleNamespace(check_ip=lambda a: SimpleNamespace(in_scope=True), check_host=lambda h: SimpleNamespace(in_scope=True)),
            source="nmap",
        ),
        tool_run_id=tool_run.id,
        raw_output_ref="raw/nmap/facts.xml",
        program_id=program,
    )
    surface = store.attack_surface(run.id)
    assert surface["records"]["by_kind"].get("port") == 1
    # Port discovery records evidence; it never fabricates a finding.
    assert surface["inferences"]["count"] == 0


# ---------------------------------------------------------------------------
# 2. Full served pipeline: subfinder -> dns_resolve -> port_scan -> http_probe
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
        target = extract_host(task.target)
        host = "" if target is None else target.lower().rstrip(".")
        return ToolExecution(
            tool="nmap",
            command=["nmap", "-sT", "-Pn", str(target)],
            exit_code=0,
            raw_output_ref=None,
            artifacts=(
                PortObservation(
                    address=WEB_IP,
                    port=443,
                    protocol="tcp",
                    state="open",
                    service="https",
                    host=host,
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
                    url=f"https://{host}:443/",
                    scheme="https",
                    port=443,
                    status_code=200,
                    webserver="nginx",
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
    }
    config = Config.from_dict(
        {"database": {"url": "unconfigured"}, "scope": _scope_dict()}
    )
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


def test_full_served_pipeline_expands_and_executes(store, tmp_path) -> None:
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
    by_type = {}
    for task in tasks:
        by_type.setdefault(task.type, []).append(task)
    assert set(by_type) == {"subfinder", CHILD_TYPE_DNS, CHILD_TYPE_PORT_SCAN, CHILD_TYPE_HTTP_PROBE}
    # Every task must have actually run, not been skipped or failed.
    assert {s for s in (t.status for tasks in by_type.values() for t in tasks)} == {"completed"}

    dns_children = by_type[CHILD_TYPE_DNS]
    assert [t.target for t in dns_children] == ["www.example.com"]
    root = by_type["subfinder"][0]
    assert all(t.parent_task_id == root.id for t in dns_children)
    # The resolved host discovered the port, so port_scan hangs off the dns_resolve child.
    assert {t.parent_task_id for t in by_type[CHILD_TYPE_PORT_SCAN]} == {dns_children[0].id}
    # The open web port discovered the web app, so http_probe hangs off port_scan.
    probe = by_type[CHILD_TYPE_HTTP_PROBE][0]
    assert probe.target == "www.example.com:443"
    assert probe.parent_task_id == by_type[CHILD_TYPE_PORT_SCAN][0].id

    surface = store.attack_surface(run.id)
    assert surface["records"]["by_kind"].get("port") == 1
    assert surface["records"]["by_kind"].get("webapp") == 1
    assert surface["records"]["by_kind"].get("ip") >= 1


def _tool_run(task_id, tool_name, command):
    from database.models.entities import ToolRun

    return ToolRun(
        task_id=task_id,
        tool_name=tool_name,
        command=list(command),
        exit_code=0,
        raw_output_ref="raw/phase20.out",
    )