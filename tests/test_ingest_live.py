"""Phase 14.2 LIVE integration + security-negative tests against a real PostgreSQL.

Skipped automatically when ``ARGUS_TEST_DATABASE_URL`` is unset/unreachable
(see ``tests/conftest.py``). Unlike ``tests/test_ingest_orchestration.py`` -- which
uses an in-memory fake and therefore proves *nothing* about SQL -- every test here
executes real statements against the migrated schema through the production
``Repositories`` facade. No fakes, no in-memory substitutes.

This module is what the 14.2 verification gate required. It covers exactly the
areas the fake-storage tests could not: SQL column names and CHECK/FK constraints,
psycopg UUID adaptation, ``inet`` handling for ``ips.address``, the
``ON CONFLICT`` upsert paths, ``evidence``/``tool_run``/``raw_reference``
provenance, real database idempotency, and a real ``conn.transaction()`` rollback.

Security-negative cases (out-of-scope destinations, SQL metacharacters, malformed
artifacts, the cardinality cap) are asserted *against the database*, so a mapping
layer that looked safe but still wrote a graph row would fail here.

Note on provenance: ``evidence.tool_run_id`` is a real foreign key to
``tool_runs(id)``. That is deliberate and load-bearing -- it is why every test here
inserts a genuine ``ToolRun`` row first, and why a passing suite is itself evidence
that the tool-run linkage is enforced by the database rather than merely asserted.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg.rows import dict_row

from api.serve import _build_ingestor
from core.config import ScopeConfig
from core.orchestrator import Orchestrator, ToolRunOutcome
from core.rate_limiter import RateLimiter, RateLimits
from core.scope_guard import ScopeGuard
from database.migrate import apply, revert
from database.models.entities import Asset, Run, Task, ToolRun
from database.repositories.all import Repositories
from recon.dns.resolver import DnsRecordObservation, IpObservation
from recon.ingest import plan_ingestion
from recon.web.httpx_probe import AssetTechnologyObservation, WebAppObservation


SCOPE_DICT = {"scope": {"allowed_domains": ["example.com"]}}


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def schema(database_url: str):
    """Migrate a clean schema, yield an open connection, then tear the rows down."""
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


@pytest.fixture
def program(store) -> UUID:
    org = store.organizations.upsert("Phase 14 Org")
    return store.programs.upsert(org["id"], "Phase 14 Program")["id"]


@pytest.fixture
def run_row(store, program) -> Run:
    return store.create_run(
        Run(
            program_id=program,
            status="CREATED",
            target="example.com",
            configuration_snapshot=dict(SCOPE_DICT),
        )
    )


@pytest.fixture
def task(store, run_row) -> Task:
    t = Task(
        id=uuid4(),
        run_id=run_row.id,
        type="subdomain_enum",
        target="example.com",
        status="pending",
    )
    store.insert_tasks([t])
    return t


@pytest.fixture
def tool_run(store, task) -> ToolRun:
    """A real ``tool_runs`` row, so evidence's FK to it is satisfiable."""
    return store.insert_tool_run(
        ToolRun(
            task_id=task.id,
            tool_name="subfinder",
            command=["subfinder", "-d", "example.com"],
            exit_code=0,
            raw_output_ref="raw/subfinder/phase14.out",
        )
    )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _scope() -> ScopeGuard:
    """A scope that authorizes both a domain *and* the specific IPs it may resolve to.

    Deliberately explicit about IPs: ``ScopeGuard.check_ip`` denies by default, so a
    domain-only scope would drop every resolved address (and therefore every port
    and web app). See ``test_domain_only_scope_drops_ips_but_keeps_the_observation``.
    """
    return ScopeGuard.from_config(
        ScopeConfig(
            allowed_domains=("example.com",),
            allowed_ips=("93.184.216.34/32", "2606:2800:220:1::/64"),
        )
    )


def _plan(artifacts, *, source="subfinder", target="example.com", max_artifacts=10000):
    return plan_ingestion(
        artifacts,
        scope=_scope(),
        source=source,
        target_host=target,
        max_artifacts=max_artifacts,
    )


def _ingest(store, plan, program_id, tool_run, *, raw="raw/subfinder/phase14.out"):
    store.ingest_observations(
        plan,
        tool_run_id=tool_run.id,
        raw_output_ref=raw,
        program_id=program_id,
    )


def _counts(conn, *tables) -> dict:
    return {
        t: conn.execute(f"SELECT count(*) AS n FROM {t}").fetchone()["n"] for t in tables
    }


# ---------------------------------------------------------------------------
# 14.2.1  SQL columns, UUID adaptation, inet handling
# ---------------------------------------------------------------------------


def test_basic_ingest_writes_real_rows_with_correct_columns(store, program, tool_run, schema) -> None:
    _ingest(store, _plan(["api.example.com"]), program, tool_run)

    row = schema.execute(
        "SELECT id, program_id, hostname, source FROM assets WHERE hostname = %s",
        ("api.example.com",),
    ).fetchone()
    assert row is not None
    assert isinstance(row["id"], UUID), "psycopg must adapt a uuid column to UUID"
    assert row["program_id"] == program
    assert row["source"] == "subfinder"


def test_ip_ingest_stores_a_real_inet_and_links_it_to_the_asset(store, program, tool_run, schema) -> None:
    _ingest(
        store,
        _plan([IpObservation(address="93.184.216.34", record_type="A")], source="dns"),
        program,
        tool_run,
    )

    ip = schema.execute("SELECT id, address FROM ips").fetchone()
    assert ip is not None
    assert str(ip["address"]) == "93.184.216.34", "inet must round-trip verbatim"
    assert ip["id"].version == 4

    link = schema.execute("SELECT asset_id, ip_id FROM asset_ips").fetchone()
    assert link is not None
    assert link["ip_id"] == ip["id"]
    asset = schema.execute("SELECT id, hostname FROM assets").fetchone()
    assert link["asset_id"] == asset["id"]
    assert asset["hostname"] == "example.com", "the IP is attributed to the task target"


def test_ipv6_is_stored_and_linked_without_truncation(store, program, tool_run, schema) -> None:
    v6 = "2606:2800:220:1:248:1893:25c8:1946"
    _ingest(
        store,
        _plan([IpObservation(address=v6, record_type="AAAA")], source="dns"),
        program,
        tool_run,
    )
    ip = schema.execute("SELECT id, address, family(address) AS fam FROM ips").fetchone()
    assert str(ip["address"]) == v6
    assert ip["fam"] == 6
    assert schema.execute("SELECT count(*) AS n FROM asset_ips").fetchone()["n"] == 1


def test_dns_record_ingest_writes_the_real_triple(store, program, tool_run, schema) -> None:
    _ingest(
        store,
        _plan(
            [DnsRecordObservation(hostname="example.com", record_type="A", value="93.184.216.34")],
            source="dns",
        ),
        program,
        tool_run,
    )
    row = schema.execute("SELECT record_type, value, asset_id FROM dns_records").fetchone()
    assert row["record_type"] == "A"
    assert row["value"] == "93.184.216.34"
    assert schema.execute("SELECT id FROM assets WHERE hostname='example.com'").fetchone()


def test_web_app_is_rooted_through_the_port_and_ip_chain(store, program, tool_run, schema) -> None:
    """A web app needs a known IP (port_id is NOT NULL), so DNS must land first."""
    _ingest(
        store,
        _plan(
            [
                IpObservation(address="93.184.216.34", record_type="A"),
                WebAppObservation(
                    host="example.com",
                    url="https://example.com",
                    scheme="https",
                    port=443,
                    status_code=200,
                    title="Example",
                    webserver="nginx",
                ),
            ],
            source="httpx",
        ),
        program,
        tool_run,
    )
    row = schema.execute(
        "SELECT w.id, w.status_code, w.title, w.server_header, p.port_number, "
        "       p.protocol, p.state, i.address "
        "FROM web_apps w "
        "JOIN ports p ON p.id = w.port_id "
        "JOIN ips i ON i.id = p.ip_id"
    ).fetchone()
    assert row is not None
    assert row["status_code"] == 200
    assert row["title"] == "Example"
    assert row["server_header"] == "nginx"
    assert row["port_number"] == 443
    assert row["protocol"] == "tcp"
    assert row["state"] == "open", "the ports.state CHECK must accept the value we write"
    assert str(row["address"]) == "93.184.216.34"


def test_unrootable_web_app_becomes_evidence_and_never_a_fabricated_web_app_row(
    store, program, tool_run, schema
) -> None:
    """No IP was resolved, so port_id cannot be satisfied: preserve it as evidence."""
    _ingest(
        store,
        _plan(
            [WebAppObservation(host="example.com", url="https://example.com", scheme="https", port=443, status_code=200)],
            source="httpx",
        ),
        program,
        tool_run,
    )
    c = _counts(schema, "web_apps", "ports")
    assert c["web_apps"] == 0
    assert c["ports"] == 0
    ev = schema.execute(
        "SELECT entity_type, entity_id, raw_reference FROM evidence "
        "WHERE entity_type = 'observed_web_app'"
    ).fetchone()
    assert ev is not None
    assert ev["entity_id"] is None, "an unrooted observation has no canonical row"
    assert ev["raw_reference"] == "raw/subfinder/phase14.out"


# ---------------------------------------------------------------------------
# 14.2.2  technologies + evidence_id linkage
# ---------------------------------------------------------------------------


def test_technology_ingest_populates_both_tables_and_links_evidence_id(
    store, program, tool_run, schema
) -> None:
    _ingest(
        store,
        _plan(
            [AssetTechnologyObservation(host="example.com", technology="nginx")],
            source="httpx",
        ),
        program,
        tool_run,
    )
    tech = schema.execute("SELECT id, name, category FROM technologies").fetchone()
    assert tech["name"] == "nginx"
    assert tech["category"] == "other", "category is not guessable from the name"

    link = schema.execute(
        "SELECT asset_id, technology_id, confidence, evidence_id FROM asset_technologies"
    ).fetchone()
    assert link["technology_id"] == tech["id"]
    assert float(link["confidence"]) == 1.0, "a directly observed technology is a fact"
    assert link["evidence_id"] is not None, "the link must carry its provenance"

    ev = schema.execute(
        "SELECT id, tool_run_id, entity_type FROM evidence WHERE id = %s",
        (link["evidence_id"],),
    ).fetchone()
    assert ev is not None
    assert ev["entity_type"] == "asset_technology"
    assert ev["tool_run_id"] == tool_run.id, "the inline FK must point at the real tool run"


# ---------------------------------------------------------------------------
# 14.2.3  evidence provenance: tool_run + raw_reference
# ---------------------------------------------------------------------------


def test_every_ingested_entity_gets_evidence_tied_to_the_tool_run_and_raw_ref(
    store, program, tool_run, schema
) -> None:
    _ingest(
        store,
        _plan(
            [
                "api.example.com",
                DnsRecordObservation(hostname="example.com", record_type="A", value="1.1.1.1"),
                IpObservation(address="93.184.216.34", record_type="A"),
                AssetTechnologyObservation(host="example.com", technology="nginx"),
            ],
            source="subfinder",
        ),
        program,
        tool_run,
        raw="raw/subfinder/provenance.out",
    )
    rows = schema.execute(
        "SELECT entity_type, entity_id, tool_run_id, raw_reference FROM evidence "
        "ORDER BY entity_type"
    ).fetchall()
    assert rows, "ingestion must produce evidence"
    for r in rows:
        assert r["tool_run_id"] == tool_run.id, f"{r['entity_type']} lost its tool run"
        assert r["raw_reference"] == "raw/subfinder/provenance.out"

    kinds = {r["entity_type"] for r in rows}
    assert {"asset", "dns_record", "ip", "technology", "asset_technology", "asset_ip"} <= kinds

    # every evidence row that names a canonical entity must name a row that exists
    for r in rows:
        if r["entity_id"] is None:
            continue
        table = {
            "asset": "assets",
            "dns_record": "dns_records",
            "ip": "ips",
            "asset_ip": "asset_ips",
            "technology": "technologies",
        }.get(r["entity_type"])
        if table is None:
            continue
        exists = schema.execute(
            f"SELECT 1 AS ok FROM {table} WHERE id = %s", (r["entity_id"],)
        ).fetchone()
        assert exists is not None, f"{r['entity_type']} evidence points at a missing row"


def test_evidence_tool_run_fk_is_really_enforced(store, program, tool_run, schema) -> None:
    """Provenance is enforced by the database, not merely asserted by the code."""
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _ingest(store, _plan(["api.example.com"]), program, tool_run=_FakeToolRun())
    schema.rollback()


# ---------------------------------------------------------------------------
# 14.2.4  real database idempotency
# ---------------------------------------------------------------------------


def test_repeated_ingest_does_not_duplicate_canonical_entities(store, program, tool_run, schema) -> None:
    artifacts = [
        "api.example.com",
        "api.example.com",
        DnsRecordObservation(hostname="example.com", record_type="A", value="1.1.1.1"),
        IpObservation(address="93.184.216.34", record_type="A"),
        AssetTechnologyObservation(host="example.com", technology="nginx"),
    ]
    for _ in range(3):
        _ingest(store, _plan(artifacts, source="subfinder"), program, tool_run)

    c = _counts(schema, "assets", "ips", "asset_ips", "technologies", "asset_technologies", "dns_records")
    # two distinct assets are expected: the discovered "api.example.com" and
    # "example.com", which owns the resolved IP
    assert c["assets"] == 2
    hosts = {
        r["hostname"] for r in schema.execute("SELECT hostname FROM assets").fetchall()
    }
    assert hosts == {"api.example.com", "example.com"}
    assert c["ips"] == 1
    assert c["asset_ips"] == 1
    assert c["technologies"] == 1
    assert c["asset_technologies"] == 1
    # dns_records has no unique index, so the plan's in-run dedup is the only guard
    assert c["dns_records"] == 1
    # three executions, but the canonical graph is not fanned out
    assert c["assets"] == 2, "re-running ingestion must not duplicate assets"


def test_asset_ip_upsert_is_idempotent_and_repeatable(store, program, tool_run, schema) -> None:
    """asset_ips is a link table: repeated resolution must not fan out rows."""
    plan = _plan([IpObservation(address="93.184.216.34", record_type="A")], source="dns")
    for _ in range(4):
        _ingest(store, plan, program, tool_run)
    c = _counts(schema, "ips", "asset_ips")
    assert c["ips"] == 1
    assert c["asset_ips"] == 1


def test_two_assets_sharing_one_ip_do_not_duplicate_the_ip(store, program, tool_run, schema) -> None:
    for host in ("a.example.com", "b.example.com"):
        _ingest(
            store,
            _plan([IpObservation(address="93.184.216.34", record_type="A")], source="dns", target=host),
            program,
            tool_run,
        )
    c = _counts(schema, "ips", "asset_ips", "assets")
    assert c["ips"] == 1, "one inet, two links"
    assert c["asset_ips"] == 2
    assert c["assets"] == 2


def test_repeated_execution_creates_a_second_tool_run_but_no_second_entity(
    store, program, task, schema
) -> None:
    """A real second execution: provenance history grows, canonical facts do not."""
    first = store.insert_tool_run(
        ToolRun(task_id=task.id, tool_name="subfinder", command=["subfinder"], exit_code=0,
                raw_output_ref="raw/a.out")
    )
    second = store.insert_tool_run(
        ToolRun(task_id=task.id, tool_name="subfinder", command=["subfinder"], exit_code=0,
                raw_output_ref="raw/b.out")
    )
    artifacts = ["api.example.com", IpObservation(address="93.184.216.34", record_type="A")]
    for tr, ref in ((first, "raw/a.out"), (second, "raw/b.out")):
        _ingest(store, _plan(artifacts, source="subfinder"), program, tr, raw=ref)

    c = _counts(schema, "assets", "ips", "asset_ips", "tool_runs", "evidence")
    assert c["tool_runs"] == 2, "each execution is its own provenance record"
    # "api.example.com" plus "example.com" (which owns the IP): two assets, once
    assert c["assets"] == 2 and c["ips"] == 1 and c["asset_ips"] == 1, (
        "canonical entities must not duplicate across executions"
    )
    # evidence is per-execution provenance and therefore grows with each run:
    # 2 assets + 1 ip + 1 asset_ip = 4 rows per execution, x2 executions = 8
    assert c["evidence"] == 8, "evidence history grows even though canonical rows do not"
    refs = {
        r["raw_reference"]
        for r in schema.execute("SELECT DISTINCT raw_reference FROM evidence").fetchall()
    }
    assert refs == {"raw/a.out", "raw/b.out"}


# ---------------------------------------------------------------------------
# 14.2.5  real transaction rollback
# ---------------------------------------------------------------------------


def test_transaction_rollback_discards_every_ingested_row(store, program, tool_run, schema) -> None:
    """The real psycopg transaction must undo real writes, not just record events."""
    plan = _plan(
        [
            "api.example.com",
            IpObservation(address="93.184.216.34", record_type="A"),
            AssetTechnologyObservation(host="example.com", technology="nginx"),
        ]
    )

    with pytest.raises(RuntimeError):
        with store.transaction():
            store.ingest_observations(
                plan,
                tool_run_id=tool_run.id,
                raw_output_ref="raw/subfinder/rollback.out",
                program_id=program,
            )
            # prove the rows were visible *inside* the transaction...
            inside = _counts(schema, "assets", "ips", "evidence", "technologies")
            assert inside["assets"] == 2  # "api.example.com" and "example.com"
            assert inside["evidence"] > 0
            raise RuntimeError("simulated failure mid-ingest")

    # ...and that none of them survived it
    after = _counts(schema, "assets", "ips", "asset_ips", "technologies", "asset_technologies", "evidence")
    assert all(v == 0 for v in after.values()), f"rows survived a rolled-back transaction: {after}"


def test_orchestrator_rolls_back_tool_run_and_ingest_together(store, program, run_row, schema) -> None:
    """A failure anywhere in the atomic unit leaves neither the ToolRun nor the facts."""
    task = Task(
        id=uuid4(),
        run_id=run_row.id,
        type="subdomain_enum",
        target="example.com",
        status="pending",
    )
    store.insert_tasks([task])

    def seam(t):
        return ToolRunOutcome(
            tool_run=ToolRun(
                task_id=t.id,
                tool_name="subfinder",
                command=["subfinder"],
                exit_code=0,
                raw_output_ref="raw/subfinder/orch.out",
            ),
            artifacts=("api.example.com",),
        )

    def failing_hook(task_, tool_run, artifacts, run_, scope_):
        # do the real ingestion, then fail: the rollback must undo the facts too
        hook = _build_ingestor(
            store, SimpleNamespace(limits=SimpleNamespace(max_artifacts_per_run=100))
        )
        hook(task_, tool_run, artifacts, run_, scope_)
        raise RuntimeError("ingest then fail")

    orch = Orchestrator(
        storage=store, run_tool=seam, ingest=failing_hook, rate_limiter=RateLimiter(RateLimits())
    )
    orch.run_to_completion(run_row.id)

    c = _counts(schema, "tool_runs", "assets", "evidence", "ips")
    assert c["tool_runs"] == 0, "the ToolRun must roll back with the facts it introduced"
    assert c["assets"] == 0
    assert c["evidence"] == 0
    assert schema.execute(
        "SELECT status FROM tasks WHERE id = %s", (task.id,)
    ).fetchone()["status"] == "failed"


def test_orchestrator_commits_tool_run_and_ingest_together_on_success(
    store, program, run_row, schema
) -> None:
    """The happy path of the same atomic unit, through the real served ingestor."""
    task = Task(
        id=uuid4(), run_id=run_row.id, type="subdomain_enum", target="example.com", status="pending"
    )
    store.insert_tasks([task])

    def seam(t):
        return ToolRunOutcome(
            tool_run=ToolRun(
                task_id=t.id, tool_name="subfinder", command=["subfinder"],
                exit_code=0, raw_output_ref="raw/subfinder/ok.out",
            ),
            artifacts=("api.example.com",),
        )

    hook = _build_ingestor(
        store, SimpleNamespace(limits=SimpleNamespace(max_artifacts_per_run=100))
    )
    orch = Orchestrator(
        storage=store, run_tool=seam, ingest=hook, rate_limiter=RateLimiter(RateLimits())
    )
    orch.run_to_completion(run_row.id)

    c = _counts(schema, "tool_runs", "assets", "evidence")
    assert c["tool_runs"] == 1
    assert c["assets"] == 1
    assert c["evidence"] >= 1
    assert schema.execute(
        "SELECT status FROM tasks WHERE id = %s", (task.id,)
    ).fetchone()["status"] == "completed"

    # provenance is consistent across the committed unit
    row = schema.execute(
        "SELECT tr.raw_output_ref, e.raw_reference, e.tool_run_id "
        "FROM evidence e JOIN tool_runs tr ON tr.id = e.tool_run_id"
    ).fetchone()
    assert row["raw_output_ref"] == row["raw_reference"] == "raw/subfinder/ok.out"
    assert row["tool_run_id"] is not None


# ---------------------------------------------------------------------------
# 14.2.6  SECURITY / NEGATIVE cases, asserted against the database
# ---------------------------------------------------------------------------


def test_domain_only_scope_drops_ips_but_keeps_the_observation(
    store, program, tool_run, schema
) -> None:
    """A domain-only scope authorizes the host but not the address it resolves to.

    Pinned because it is a security posture, not an accident: ``check_ip`` denies by
    default, so nothing is promoted without an explicit IP/CIDR allow rule. The IP
    survives as evidence, and no ``ips``/``ports``/``web_apps`` row is fabricated.
    """
    plan = plan_ingestion(
        [IpObservation(address="93.184.216.34", record_type="A")],
        scope=ScopeGuard.from_config(ScopeConfig(allowed_domains=("example.com",))),
        source="dns",
        target_host="example.com",
    )
    _ingest(store, plan, program, tool_run)

    assert schema.execute(
        "SELECT count(*) AS n FROM assets WHERE hostname='example.com'"
    ).fetchone()["n"] == 1
    c = _counts(schema, "ips", "asset_ips", "ports", "web_apps")
    assert c["ips"] == 0 and c["asset_ips"] == 0 and c["ports"] == 0 and c["web_apps"] == 0
    ev = schema.execute(
        "SELECT entity_id FROM evidence WHERE entity_type = 'observed_ip'"
    ).fetchone()
    assert ev is not None and ev["entity_id"] is None


def test_out_of_scope_host_writes_evidence_and_no_asset(store, program, tool_run, schema) -> None:
    _ingest(store, _plan(["evil.com", "api.example.com"]), program, tool_run)

    assert schema.execute(
        "SELECT count(*) AS n FROM assets WHERE hostname = 'evil.com'"
    ).fetchone()["n"] == 0
    assert schema.execute(
        "SELECT count(*) AS n FROM assets WHERE hostname = 'api.example.com'"
    ).fetchone()["n"] == 1
    ev = schema.execute(
        "SELECT entity_type, entity_id FROM evidence WHERE entity_type = 'observed_host'"
    ).fetchone()
    assert ev is not None
    assert ev["entity_id"] is None, "a denied destination has no canonical row to point at"


def test_out_of_scope_ip_writes_evidence_and_no_ip_row(store, program, tool_run, schema) -> None:
    _ingest(
        store,
        _plan([IpObservation(address="10.0.0.5", record_type="A")], source="dns"),
        program,
        tool_run,
    )
    c = _counts(schema, "ips", "asset_ips")
    assert c["ips"] == 0
    assert c["asset_ips"] == 0
    ev = schema.execute(
        "SELECT entity_id FROM evidence WHERE entity_type = 'observed_ip'"
    ).fetchone()
    assert ev is not None and ev["entity_id"] is None


def test_out_of_scope_dns_value_is_not_persisted_as_a_record(store, program, tool_run, schema) -> None:
    """An in-scope host whose *answer* is out of scope keeps the host, drops the IP."""
    _ingest(
        store,
        _plan(
            [IpObservation(address="10.0.0.5", record_type="A")],
            source="dns",
            target="example.com",
        ),
        program,
        tool_run,
    )
    assert schema.execute(
        "SELECT count(*) AS n FROM assets WHERE hostname='example.com'"
    ).fetchone()["n"] == 1
    assert _counts(schema, "ips")["ips"] == 0


def test_sql_metacharacters_are_inert_in_the_database(store, program, tool_run, schema) -> None:
    """A hostile hostname can neither drop tables nor reach the asset graph.

    Two independent defences are proven here, because they fail differently:

    1. the scope guard rejects a string that no resolver could answer for, so it
       is never promoted to an ``assets`` row at all; and
    2. the persistence layer is parameterized, proven by writing a
       metacharacter-bearing value *directly* through the repository -- bypassing
       the scope guard entirely -- and observing that it round-trips as a single
       inert value with the schema intact.
    """
    hostile = "evil'; DROP TABLE assets; --.example.com"

    # 1. denied at the scope boundary, so nothing is promoted
    _ingest(store, _plan([hostile]), program, tool_run)
    assert schema.execute("SELECT count(*) AS n FROM assets").fetchone()["n"] == 0, (
        "a malformed hostname must not reach the asset graph"
    )
    assert schema.execute("SELECT count(*) AS n FROM evidence").fetchone()["n"] >= 1, (
        "it is still recorded as evidence rather than dropped"
    )

    # 2. parameterized SQL, proven independently of the scope guard
    store.assets.upsert(
        Asset(
            program_id=program,
            hostname=hostile.lower(),
            source="subfinder",
        )
    )
    assert schema.execute("SELECT count(*) AS n FROM assets").fetchone()["n"] == 1
    row = schema.execute("SELECT hostname FROM assets").fetchone()
    assert row["hostname"] == hostile.lower(), "stored verbatim, as a single inert value"
    # the whole schema is still queryable
    assert schema.execute("SELECT count(*) AS n FROM information_schema.tables WHERE table_schema='public'").fetchone()["n"] > 10


def test_malformed_artifacts_fabricate_nothing(store, program, tool_run, schema) -> None:
    plan = plan_ingestion(
        [object(), None, 42, {"host": "x.example.com"}, b"bytes"],
        scope=ScopeGuard.from_config(ScopeConfig(allowed_domains=("example.com",))),
        source="subfinder",
        target_host="example.com",
    )
    assert plan.unrecognized == 5
    _ingest(store, plan, program, tool_run)
    c = _counts(schema, "assets", "ips", "dns_records", "web_apps", "technologies", "evidence")
    assert all(v == 0 for v in c.values()), f"malformed input fabricated rows: {c}"


def test_cardinality_cap_is_enforced_before_any_write(store, program, tool_run, schema) -> None:
    many = [f"h{i}.example.com" for i in range(500)]
    plan = _plan(many, max_artifacts=10)
    assert plan.truncated == 490
    assert len(plan.assets) == 10
    _ingest(store, plan, program, tool_run)
    assert schema.execute("SELECT count(*) AS n FROM assets").fetchone()["n"] == 10
    ev = schema.execute(
        "SELECT entity_type FROM evidence WHERE entity_type = 'artifact_cap'"
    ).fetchone()
    assert ev is not None, "the cap must leave a trace in the evidence trail"


# ---------------------------------------------------------------------------
# helper
# ---------------------------------------------------------------------------


class _FakeToolRun:
    """A tool-run id that does not exist, to prove the evidence FK is enforced."""

    id = uuid4()
