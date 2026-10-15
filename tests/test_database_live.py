"""Live integration tests against a real PostgreSQL.

Skipped automatically when ``ARGUS_TEST_DATABASE_URL`` is unset/unreachable
(see conftest.py). These verify migrations apply/revert cleanly and that the
repository layer honors ``05_DATA_MODEL.md`` constraints.

Stage 1 adds the gates that were missing: the real repository implementation is
driven through the real ``core.orchestrator.Storage`` contract (not through
per-table repository calls alone), the orchestrator itself is run on top of
PostgreSQL, and the migration runner's bookkeeping is checked for consistency
with the actual schema state. Every test here constructs the production
``Repositories`` facade -- there are no fakes and no in-memory substitutes.
"""

from __future__ import annotations

import contextlib
import shutil
from uuid import uuid4

import psycopg
import pytest
from psycopg.rows import dict_row

from core.config import ScopeConfig
from core.memory_storage import MemoryStorage
from core.orchestrator import Orchestrator, Storage
from core.rate_limiter import RateLimiter, RateLimits
from core.scope_guard import ScopeGuard
from database.migrate import MIGRATIONS_DIR, apply, migration_files, revert, version_of
from database.repositories.all import Repositories
from database.repositories.base import DatabaseConnection

from database.models.entities import (
    Asset,
    DnsRecord,
    Hypothesis,
    Ip,
    Organization,
    Port,
    Program,
    Run,
    ScopeRule,
    Task,
    ToolRun,
    WebApp,
)


@pytest.fixture
def conn(database_url: str):
    c = psycopg.connect(database_url)
    yield c
    c.close()


@pytest.fixture
def schema(database_url: str):
    """Fully migrate a fresh test database, yield it, then revert."""
    c = psycopg.connect(database_url, row_factory=dict_row)
    revert(c, 0)
    applied = apply(c)
    assert applied == sorted(version_of(p) for p in migration_files())
    yield c
    # A failed test leaves the transaction aborted, which would make every
    # subsequent statement (including the revert below) fail. Roll back first so
    # teardown reports only the real failure. Reverting to version 0 drops every
    # table anyway, so discarding rows here changes nothing -- it only keeps
    # 0003's down migration, which restores the strict (run_id, fingerprint)
    # unique index, from tripping over duplicate un-fingerprinted test tasks.
    c.rollback()
    tables = c.execute(
        "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()"
    ).fetchall()
    if tables:
        names = ", ".join(f'"{t["tablename"]}"' for t in tables)
        c.execute(f"TRUNCATE {names} RESTART IDENTITY CASCADE")
    revert(c, 0)
    c.close()


def test_migrations_apply_and_revert(schema) -> None:
    cur = schema.execute(
        "SELECT version, name FROM schema_migrations ORDER BY version"
    )
    rows = cur.fetchall()
    assert len(rows) == len(migration_files())
    assert rows[0]["version"] == 1
    assert schema.execute(
        "SELECT to_regclass('organizations') AS t"
    ).fetchone()["t"]


def test_apply_is_idempotent(schema) -> None:
    before = schema.execute(
        "SELECT count(*) AS n FROM schema_migrations"
    ).fetchone()["n"]
    assert apply(schema) == []
    after = schema.execute("SELECT count(*) AS n FROM schema_migrations").fetchone()["n"]
    assert after == before


def _seed_org_program(schema) -> tuple[dict, dict]:
    repos = Repositories(schema)
    org = repos.organizations.upsert("Acme Corp")
    prog = repos.programs.upsert(org["id"], "Q4 Pentest")
    return org, prog


def test_run_insert_and_lifecycle(schema) -> None:
    repos = Repositories(schema)
    org, prog = _seed_org_program(schema)
    run = Run(
        program_id=prog["id"],
        target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    created = repos.runs.insert(run)
    assert created["id"] == run.id
    assert created["status"] == "CREATED"
    assert created["configuration_snapshot"]["scope"]["allowed_domains"] == [
        "example.com"
    ]

    started = repos.runs.mark_started(run.id)
    assert started["status"] == "RECONNING"
    assert started["started_at"] is not None

    done = repos.runs.mark_completed(run.id)
    assert done["status"] == "COMPLETED"
    assert done["completed_at"] is not None


def test_task_and_tool_run_chain(schema) -> None:
    repos = Repositories(schema)
    org, prog = _seed_org_program(schema)
    run = Run(program_id=prog["id"], target="example.com")
    repos.runs.insert(run)

    task = Task(
        run_id=run.id,
        type="subdomain_discovery",
        target="example.com",
        fingerprint="sub:example.com",
    )
    task_row = repos.tasks.insert(task)
    assert task_row["run_id"] == run.id
    assert task_row["status"] == "pending"

    tool = ToolRun(
        task_id=task.id,
        tool_name="subfinder",
        command=["subfinder", "-d", "example.com"],
    )
    tool_row = repos.tool_runs.insert(tool)
    assert tool_row["task_id"] == task.id

    finalized = repos.tool_runs.finalize(tool.id, 0, "storage/raw/subfinder/x")
    assert finalized["exit_code"] == 0

    persisted = repos.tasks.get_by_fingerprint(run.id, "sub:example.com")
    assert persisted["id"] == task.id


def test_task_fingerprint_unique_per_run(schema) -> None:
    repos = Repositories(schema)
    org, prog = _seed_org_program(schema)
    run = Run(program_id=prog["id"], target="example.com")
    repos.runs.insert(run)

    repos.tasks.insert(
        Task(
            run_id=run.id,
            type="x",
            target="example.com",
            fingerprint="dup",
        )
    )
    with pytest.raises(psycopg.errors.UniqueViolation):
        repos.tasks.insert(
            Task(run_id=run.id, type="x", target="example.com", fingerprint="dup")
        )


def test_asset_dedup_and_dns(schema) -> None:
    repos = Repositories(schema)
    org, prog = _seed_org_program(schema)
    run = Run(program_id=prog["id"], target="example.com")
    repos.runs.insert(run)

    a1 = repos.assets.upsert(
        Asset(
            program_id=prog["id"],
            hostname="www.example.com",
            source="subfinder",
        )
    )
    a2 = repos.assets.upsert(
        Asset(
            program_id=prog["id"],
            hostname="www.example.com",
            source="amass",
        )
    )
    assert a1["id"] == a2["id"], "asset dedup violated unique constraint"

    ip = repos.ips.upsert("203.0.113.10")
    # ``ips.address`` is ``inet`` and the repository returns ``address::text``,
    # whose canonical PostgreSQL form always carries the prefix length. A bare
    # host address is a /32, so that -- not the bare string -- is the correct
    # round-trip value.
    assert ip["address"] == "203.0.113.10/32"
    # The value is still the same address, and dedup is still by value.
    same_ip = repos.ips.upsert("203.0.113.10")
    assert same_ip["id"] == ip["id"], "inet dedup must match on value, not text"

    repos.dns_records.insert(
        DnsRecord(asset_id=a1["id"], record_type="A", value="203.0.113.10")
    )
    records = repos.dns_records.list_for_asset(a1["id"])
    assert len(records) == 1
    assert records[0]["record_type"] == "A"


def test_scope_rules_upsert(schema) -> None:
    repos = Repositories(schema)
    org, prog = _seed_org_program(schema)
    repos.scope_rules.upsert(
        ScopeRule(
            program_id=prog["id"],
            rule_type="domain",
            value="example.com",
            allowed=True,
        )
    )
    repos.scope_rules.upsert(
        ScopeRule(
            program_id=prog["id"],
            rule_type="domain",
            value="example.com",
            allowed=True,
        )
    )
    rules = repos.scope_rules.list_for_program(prog["id"])
    assert len(rules) == 1


def test_ip_and_port_and_webapp(schema) -> None:
    repos = Repositories(schema)
    org, prog = _seed_org_program(schema)
    asset = repos.assets.upsert(
        Asset(program_id=prog["id"], hostname="app.example.com", source="manual")
    )
    ip = repos.ips.upsert("198.51.100.7")
    port = repos.ports.upsert(
        Port(ip_id=ip["id"], port_number=443, protocol="tcp", state="open",
             service="https")
    )
    web = repos.web_apps.upsert(
        WebApp(
            asset_id=asset["id"],
            port_id=port["id"],
            status_code=200,
            title="Acme App",
            server_header="nginx",
        )
    )
    assert web["status_code"] == 200

    refreshed = repos.web_apps.upsert(
        WebApp(
            asset_id=asset["id"],
            port_id=port["id"],
            status_code=503,
            title="Acme App",
            server_header="nginx",
        )
    )
    assert refreshed["status_code"] == 503


# -- Stage 1: serve composition against real PostgreSQL ----------------------


def _seed_program(conn) -> dict:
    org = conn.execute(
        "INSERT INTO organizations (name) VALUES ('Serve Org') RETURNING id"
    ).fetchone()
    program = conn.execute(
        "INSERT INTO programs (organization_id, name, status) "
        "VALUES (%s, 'Serve Program', 'active') RETURNING id",
        (org["id"],),
    ).fetchone()
    conn.commit()
    return program


def _post_run(app, api_key: str, program_id) -> str:
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.post(
            "/api/v1/runs",
            json={"target": "example.com", "program_id": str(program_id)},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert r.status_code == 201, r.text
        return r.json()["id"]


def test_production_serve_persists_to_postgresql(database_url: str) -> None:
    """Production composition must reach PostgreSQL -- no MemoryStorage fallback."""
    from api.serve import create_serve_app

    c = psycopg.connect(database_url, row_factory=dict_row)
    try:
        revert(c, 0)
        apply(c)
        program = _seed_program(c)
        api_key = "live-verify-key"

        run_id = _post_run(
            create_serve_app(api_key=api_key, database_url=database_url),
            api_key,
            program["id"],
        )

        # Read the row back over a brand-new connection, after the app (and its
        # own connection) is gone. A MemoryStorage fallback could not produce it.
        verify = psycopg.connect(database_url, row_factory=dict_row)
        try:
            row = verify.execute(
                "SELECT program_id, target, status FROM runs WHERE id = %s", (run_id,)
            ).fetchone()
        finally:
            verify.close()
        assert row is not None, "production serve must persist to PostgreSQL"
        assert row["program_id"] == program["id"]
        assert row["target"] == "example.com"
        assert row["status"] == "CREATED"
    finally:
        c.rollback()
        revert(c, 0)
        c.close()


def test_in_memory_serve_never_touches_postgresql(database_url: str) -> None:
    """``in_memory=True`` is the only path to MemoryStorage, and it writes nowhere."""
    from api.serve import create_serve_app

    c = psycopg.connect(database_url, row_factory=dict_row)
    try:
        revert(c, 0)
        apply(c)
        program = _seed_program(c)
        api_key = "live-verify-key"

        run_id = _post_run(
            create_serve_app(api_key=api_key, database_url=database_url, in_memory=True),
            api_key,
            program["id"],
        )

        assert c.execute(
            "SELECT count(*) AS n FROM runs WHERE id = %s", (run_id,)
        ).fetchone()["n"] == 0, "explicit in-memory mode must not write to PostgreSQL"
    finally:
        c.rollback()
        revert(c, 0)
        c.close()


def test_serve_reads_back_through_a_second_connection(database_url: str) -> None:
    """GET after POST must be served from PostgreSQL, not process memory."""
    from fastapi.testclient import TestClient

    from api.serve import create_serve_app

    c = psycopg.connect(database_url, row_factory=dict_row)
    try:
        revert(c, 0)
        apply(c)
        program = _seed_program(c)
        api_key = "live-verify-key"
        app = create_serve_app(api_key=api_key, database_url=database_url)
        auth = {"Authorization": f"Bearer {api_key}"}

        with TestClient(app) as client:
            created = client.post(
                "/api/v1/runs",
                json={"target": "example.com", "program_id": str(program["id"])},
                headers=auth,
            )
            assert created.status_code == 201, created.text
            run_id = created.json()["id"]

        # A second app instance, over its own connection, must observe the run.
        other = create_serve_app(api_key=api_key, database_url=database_url)
        with TestClient(other) as client:
            fetched = client.get(f"/api/v1/runs/{run_id}", headers=auth)
            assert fetched.status_code == 200, fetched.text
            assert fetched.json()["id"] == run_id
            assert fetched.json()["target"] == "example.com"
    finally:
        c.rollback()
        revert(c, 0)
        c.close()


# -- Stage 1: Storage contract against the real repository implementation ------


def _contract_storage(conn) -> tuple[Repositories, dict]:
    """A real ``Repositories`` facade plus the program its FK chain requires."""
    repos = Repositories(conn)
    org = repos.organizations.upsert("Contract Org")
    program = repos.programs.upsert(org["id"], "Contract Program")
    return repos, program


@contextlib.contextmanager
def _clean_database(database_url: str):
    """Fully migrated, empty database, torn down afterwards.

    Used by tests that must drive the real production ``DatabaseConnection``
    rather than the ``schema`` fixture's raw connection, and therefore have to
    manage their own isolation (test order is randomised, so leftover rows would
    otherwise leak into unrelated tests).
    """
    c = psycopg.connect(database_url, row_factory=dict_row)
    try:
        revert(c, 0)
        apply(c)
        yield c
    finally:
        c.rollback()
        revert(c, 0)
        c.close()


def test_database_connection_connects_with_dict_rows(database_url: str) -> None:
    """``DatabaseConnection`` is the production connection wrapper."""
    with DatabaseConnection(database_url) as db:
        raw = db.connect()
        assert not raw.closed
        assert raw.info.dbname
        row = raw.execute("SELECT 1 AS one").fetchone()
        assert row["one"] == 1, "connection must use the dict_row factory"
    assert raw.closed, "context manager exit must close the connection"


def test_migrations_apply_to_a_never_migrated_database(database_url: str) -> None:
    c = psycopg.connect(database_url)
    try:
        # Establish the precondition deterministically rather than assuming no
        # other test left the schema behind (test order is randomised).
        revert(c, 0)
        assert revert(c, 0) == [], "a never-migrated database has nothing to revert"
        assert apply(c) == sorted(version_of(p) for p in migration_files())
    finally:
        revert(c, 0)
        c.close()


def test_storage_contract_run_lifecycle(schema) -> None:
    repos, program = _contract_storage(schema)
    run = Run(
        program_id=program["id"],
        target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    created = repos.create_run(run)
    assert created.id == run.id, "the entity id must survive the round trip"
    assert created.status == "CREATED"
    assert created.configuration_snapshot["scope"]["allowed_domains"] == ["example.com"]

    repos.set_run_status(run.id, "RECONNING")
    fetched = repos.get_run(run.id)
    assert fetched.status == "RECONNING"
    assert fetched.target == "example.com"

    assert [r.id for r in repos.list_runs()] == [run.id]
    assert repos.get_run(uuid4()) is None


def test_storage_contract_task_persistence(schema) -> None:
    repos, program = _contract_storage(schema)
    run = Run(program_id=program["id"], target="example.com")
    repos.create_run(run)
    tasks = [
        Task(run_id=run.id, type="dns_resolve", target="example.com", priority=10),
        Task(run_id=run.id, type="http_probe", target="www.example.com"),
    ]
    repos.insert_tasks(tasks)

    listed = repos.list_tasks(run.id)
    assert sorted(t.id for t in listed) == sorted(t.id for t in tasks)
    by_id = {t.id: t for t in listed}
    assert by_id[tasks[0].id].type == "dns_resolve"
    assert by_id[tasks[0].id].priority == 10.0, "numeric must be narrowed to float"
    assert by_id[tasks[1].id].priority is None

    assert sorted(t.id for t in repos.list_tasks_by_status(run.id, "pending")) == sorted(
        t.id for t in tasks
    )
    repos.set_task_status(tasks[0].id, "running")
    assert [t.id for t in repos.list_tasks_by_status(run.id, "running")] == [tasks[0].id]
    assert [t.id for t in repos.list_tasks_by_status(run.id, "pending")] == [tasks[1].id]


def test_storage_contract_tool_run_persistence(schema) -> None:
    repos, program = _contract_storage(schema)
    run = Run(program_id=program["id"], target="example.com")
    repos.create_run(run)
    task = Task(run_id=run.id, type="dns_resolve", target="example.com", fingerprint="dns:example.com")
    repos.insert_tasks([task])

    tool = ToolRun(
        task_id=task.id, tool_name="dns", command=["dns-resolve", "example.com"]
    )
    stored = repos.insert_tool_run(tool)
    assert stored.id == tool.id
    assert stored.command == ["dns-resolve", "example.com"]
    assert stored.exit_code is None

    repos.finalize_tool_run(tool.id, 0, "storage/raw/dns/x.json")
    row = schema.execute(
        "SELECT exit_code, raw_output_ref, completed_at FROM tool_runs WHERE id = %s",
        (tool.id,),
    ).fetchone()
    assert row["exit_code"] == 0
    assert row["raw_output_ref"] == "storage/raw/dns/x.json"
    assert row["completed_at"] is not None


def test_storage_contract_hypothesis_persistence_and_review(schema) -> None:
    repos, program = _contract_storage(schema)
    run = Run(program_id=program["id"], target="example.com")
    repos.create_run(run)

    hypothesis = Hypothesis(
        run_id=run.id,
        statement="Potential object-level authorization weakness",
        truth_label="HYPOTHESIS",
        confidence=0.4,
        severity="high",
        priority="high",
        target="example.com",
        validation_step="non-invasive observation only",
    )
    stored = repos.insert_hypothesis(hypothesis)
    assert stored.id == hypothesis.id
    assert stored.run_id == run.id
    assert stored.confidence == 0.4, "numeric must be narrowed to float"
    assert stored.review_status == "pending"
    assert stored.review_reason is None

    assert [h.id for h in repos.list_hypotheses(run.id)] == [hypothesis.id]
    assert repos.get_hypothesis(run.id, hypothesis.id).statement == hypothesis.statement
    assert repos.get_hypothesis(uuid4(), hypothesis.id) is None, "hypotheses are run-scoped"
    assert repos.list_hypotheses(uuid4()) == []

    approved = repos.set_hypothesis_review(
        run.id, hypothesis.id, "approved", "operator ok",
        "VALIDATED_FINDING", "validated",
    )
    assert approved.review_status == "approved"
    assert approved.review_reason == "operator ok"
    assert approved.truth_label == "VALIDATED_FINDING"
    assert approved.status == "validated"

    # analytical state and review state stay independently writable
    rejected = repos.set_hypothesis_review(
        run.id, hypothesis.id, "rejected", "second look",
        approved.truth_label, approved.status,
    )
    assert rejected.review_status == "rejected"
    assert rejected.truth_label == "VALIDATED_FINDING"


def _contract_script(storage, program_id) -> list:
    """Drive one Storage implementation through the contract, recording state.

    Deliberately excludes ``started_at``/``completed_at``: the database stamps
    those server-side in ``TaskRepository.update_status`` while the in-memory
    double does not, and reconciling lifecycle timestamps is Stage 2's job.
    Every contract-visible value is compared.

    Generated UUIDs are replaced by stable role labels, because two independent
    executions can never agree on random ids; the *relationships* between ids
    are still compared exactly.
    """
    run = Run(program_id=program_id, target="example.com")
    created = storage.create_run(run)
    storage.set_run_status(run.id, "RECONNING")
    tasks = [
        Task(run_id=run.id, type="dns_resolve", target="example.com"),
        Task(run_id=run.id, type="http_probe", target="www.example.com"),
    ]
    storage.insert_tasks(tasks)
    storage.set_task_status(tasks[0].id, "running")

    tool = ToolRun(
        task_id=tasks[0].id, tool_name="dns", command=["dns-resolve", "example.com"]
    )
    storage.insert_tool_run(tool)
    storage.finalize_tool_run(tool.id, 0, "storage/raw/dns/x.json")

    hypothesis = Hypothesis(
        run_id=run.id, statement="s", confidence=0.4, severity="high",
        priority="high", target="example.com", validation_step="observe only",
    )
    storage.insert_hypothesis(hypothesis)
    storage.set_hypothesis_review(
        run.id, hypothesis.id, "approved", "ok", "VALIDATED_FINDING", "validated"
    )

    label = {run.id: "RUN", tasks[0].id: "TASK0", tasks[1].id: "TASK1",
             hypothesis.id: "HYP"}
    fetched = storage.get_hypothesis(run.id, hypothesis.id)
    return [
        (label[run.id], created.status, created.target, created.configuration_snapshot),
        (label[run.id], storage.get_run(run.id).status, storage.get_run(run.id).target),
        storage.get_run(uuid4()),
        sorted(
            (label[t.id], t.type, t.target, t.status) for t in storage.list_tasks(run.id)
        ),
        sorted(
            (label[t.id], t.status)
            for t in storage.list_tasks_by_status(run.id, "running")
        ),
        sorted(
            (label[t.id],) for t in storage.list_tasks_by_status(run.id, "completed")
        ),
        sorted(
            (label[h.id], label[h.run_id], h.statement, h.confidence, h.truth_label,
             h.status)
            for h in storage.list_hypotheses(run.id)
        ),
        (label[hypothesis.id], fetched.review_status, fetched.review_reason,
         fetched.validation_step),
        storage.list_hypotheses(uuid4()),
        storage.get_hypothesis(uuid4(), hypothesis.id),
    ]


def test_postgres_storage_matches_memory_storage_semantics(schema) -> None:
    """The real implementation and the test double are interchangeable."""
    repos, program = _contract_storage(schema)
    assert _contract_script(repos, program["id"]) == _contract_script(
        MemoryStorage(), uuid4()
    )


def test_orchestrator_runs_on_postgres_storage(database_url: str) -> None:
    """The Stage 1 acceptance chain: Orchestrator -> Storage -> PostgreSQL.

    Uses ``DatabaseConnection`` -- the production connection wrapper -- and
    deliberately never commits by hand, so this also proves the repository layer
    makes writes durable on its own.
    """
    with _clean_database(database_url):
        with DatabaseConnection(database_url) as db:
            repos = Repositories(db.connect())
            org = repos.organizations.upsert("Orchestrator Org")
            program = repos.programs.upsert(org["id"], "Orchestrator Program")

            def run_tool(task: Task) -> ToolRun:
                return ToolRun(
                    task_id=task.id,
                    tool_name=task.type,
                    command=["argus", task.type, task.target],
                    exit_code=0,
                    raw_output_ref="storage/raw/out.txt",
                )

            orch = Orchestrator(storage=repos, run_tool=run_tool)
            run = Run(program_id=program["id"], target="example.com")
            orch.create_run(
                run,
                planned=[Task(run_id=run.id, type="dns_resolve", target="example.com")],
            )
            assert orch.get_run(run.id).status == "CREATED"

            assert orch.run_to_completion(run.id) == "COMPLETED"

            task = repos.list_tasks(run.id)[0]
            assert task.status == "completed"
            assert [r.status for r in repos.list_runs()] == ["COMPLETED"]

        # The orchestrator's connection is now closed. A second, fully
        # independent connection must observe everything: that is durability,
        # not in-process state.
        other = Repositories(psycopg.connect(database_url, row_factory=dict_row))
        try:
            assert [r.status for r in other.list_runs()] == ["COMPLETED"]
            assert [r.target for r in other.list_runs()] == ["example.com"]
            assert [t.status for t in other.list_tasks(run.id)] == ["completed"]
            assert other.list_hypotheses(run.id) == []
            tool_rows = other.conn.execute(
                "SELECT exit_code, raw_output_ref FROM tool_runs WHERE task_id = %s",
                (task.id,),
            ).fetchall()
            assert len(tool_rows) == 1
            assert tool_rows[0]["exit_code"] == 0
            assert tool_rows[0]["raw_output_ref"] == "storage/raw/out.txt"
        finally:
            other.conn.close()


def test_repository_writes_are_durable_without_a_manual_commit(
    database_url: str,
) -> None:
    """A second connection must see committed writes; the writer must not hold locks."""
    with _clean_database(database_url), DatabaseConnection(database_url) as db:
        repos = Repositories(db.connect())
        org = repos.organizations.upsert("Durability Org")
        program = repos.programs.upsert(org["id"], "Durability Program")
        run = Run(program_id=program["id"], target="example.com")
        repos.create_run(run)
        task = Task(run_id=run.id, type="dns_resolve", target="example.com")
        repos.insert_tasks([task])
        repos.set_task_status(task.id, "running")
        tool = ToolRun(task_id=task.id, tool_name="dns", command=["dns"])
        repos.insert_tool_run(tool)
        repos.finalize_tool_run(tool.id, 0, "storage/raw/d.json")
        hyp = Hypothesis(run_id=run.id, statement="durable", confidence=0.5,
                         severity="low", priority="low", target="example.com",
                         validation_step="observe")
        repos.insert_hypothesis(hyp)
        repos.set_hypothesis_review(run.id, hyp.id, "approved", "ok",
                                    "VALIDATED_FINDING", "validated")

        # No open transaction may be held: an uncommitted writer would block DDL
        # and every other writer, which is the defect this test exists to catch.
        assert (
            db.connect().info.transaction_status
            == psycopg.pq.TransactionStatus.IDLE
        ), "production connection must not sit in an open transaction"

        reader = Repositories(psycopg.connect(database_url, row_factory=dict_row))
        try:
            assert reader.get_run(run.id).target == "example.com"
            assert reader.list_tasks(run.id)[0].status == "running"
            assert reader.get_hypothesis(run.id, hyp.id).review_status == "approved"
            finalized = reader.conn.execute(
                "SELECT exit_code FROM tool_runs WHERE id = %s", (tool.id,)
            ).fetchone()
            assert finalized["exit_code"] == 0
        finally:
            reader.conn.close()


# -- Stage 1: migration bookkeeping -----------------------------------------


def _applied(schema) -> list[int]:
    return sorted(
        r["version"]
        for r in schema.execute("SELECT version FROM schema_migrations").fetchall()
    )


def _fingerprint_index_def(schema) -> str:
    row = schema.execute(
        "SELECT indexdef AS d FROM pg_indexes "
        "WHERE schemaname = current_schema() AND indexname = 'tasks_run_fingerprint_uq'"
    ).fetchone()
    return row["d"] if row else ""


def _foreign_key_names(schema) -> set[str]:
    return {
        r["conname"]
        for r in schema.execute(
            "SELECT conname FROM pg_constraint WHERE contype = 'f'"
        ).fetchall()
    }


def test_revert_updates_schema_migrations_bookkeeping(schema) -> None:
    """``schema_migrations`` must never claim a version whose schema was reverted."""
    assert _applied(schema) == [1, 2, 3, 4, 5, 6]
    assert "WHERE" in _fingerprint_index_def(schema), "0003 must scope the unique index"

    assert revert(schema, 1) == [6, 5, 4, 3, 2]
    assert _applied(schema) == [1], "reverted versions must not stay recorded as applied"
    assert schema.execute(
        "SELECT to_regclass('hypotheses_run_id_idx') AS t"
    ).fetchone()["t"] is None, "0002's index must be gone"
    assert "WHERE" not in _fingerprint_index_def(schema), (
        "reverting 0003 must restore 0001's unconditional unique index"
    )

    # 0002-0006's objects are gone, so apply must re-run them rather than
    # skipping them because bookkeeping still claimed they were applied.
    assert apply(schema) == [2, 3, 4, 5, 6]
    assert _applied(schema) == [1, 2, 3, 4, 5, 6]
    assert schema.execute(
        "SELECT to_regclass('hypotheses_run_id_idx') AS t"
    ).fetchone()["t"]
    assert "WHERE" in _fingerprint_index_def(schema)


def test_0002_on_fresh_database_validates_run_id_requirement(database_url: str) -> None:
    c = psycopg.connect(database_url)
    try:
        revert(c, 0)
        assert apply(c) == [1, 2, 3, 4, 5, 6]
        assert c.execute(
            "SELECT convalidated FROM pg_constraint "
            "WHERE conname = 'hypotheses_run_id_required_check'"
        ).fetchone()[0] is True
    finally:
        revert(c, 0)
        c.close()


def test_0002_upgrades_populated_hypotheses_without_inventing_ownership(
    database_url: str, tmp_path
) -> None:
    """A pre-0002 database with hypotheses must upgrade, not fail and not lie."""
    v1_dir = tmp_path / "v1"
    v1_dir.mkdir()
    for path in MIGRATIONS_DIR.glob("0001_*.sql"):
        shutil.copy(path, v1_dir / path.name)

    c = psycopg.connect(database_url)
    try:
        revert(c, 0)
        assert apply(c, directory=v1_dir) == [1]

        org = c.execute(
            "INSERT INTO organizations (name) VALUES ('Legacy Org') RETURNING id"
        ).fetchone()
        program = c.execute(
            "INSERT INTO programs (organization_id, name, status) "
            "VALUES (%s, 'Legacy Program', 'active') RETURNING id",
            (org[0],),
        ).fetchone()
        run = c.execute(
            "INSERT INTO runs (program_id, status, target) "
            "VALUES (%s, 'CREATED', 'example.com') RETURNING id",
            (program[0],),
        ).fetchone()
        c.execute(
            "INSERT INTO hypotheses (endpoint_id, statement, truth_label, confidence, "
            "severity, priority, status) "
            "VALUES (NULL, 'legacy unowned hypothesis', 'HYPOTHESIS', 0.4, "
            "'high', 'high', 'open')"
        )
        assert c.execute("SELECT count(*) FROM hypotheses").fetchone()[0] == 1

        assert apply(c) == [2, 3, 4, 5, 6], (
            "0002-0006 must apply to a populated database"
        )

        run_id, target, review_status = c.execute(
            "SELECT run_id, target, review_status FROM hypotheses"
        ).fetchone()
        assert run_id is None, "ownership must not be invented for a legacy row"
        assert target == ""
        assert review_status == "pending"
        assert c.execute(
            "SELECT count(*) FROM hypotheses WHERE run_id = %s", (run[0],)
        ).fetchone()[0] == 0, "an un-attributed row is invisible to run-scoped reads"
        assert c.execute(
            "SELECT convalidated FROM pg_constraint "
            "WHERE conname = 'hypotheses_run_id_required_check'"
        ).fetchone()[0] is False

        # New rows are required to be run-scoped, so provenance cannot rot again.
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute(
                "INSERT INTO hypotheses (statement, truth_label, confidence, severity, "
                "priority, status) VALUES ('unowned', 'HYPOTHESIS', 0.1, 'low', 'low', 'open')"
            )
        # The caught violation aborted the transaction; clear it so the revert in
        # the finally block can still run.
        c.rollback()
    finally:
        revert(c, 0)
        c.close()


def test_0002_downgrade_restores_the_0001_shape(database_url: str) -> None:
    c = psycopg.connect(database_url)
    try:
        revert(c, 0)
        assert apply(c) == [1, 2, 3, 4, 5, 6]
        assert revert(c, 1) == [6, 5, 4, 3, 2]

        columns = {
            r[0]
            for r in c.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'hypotheses'"
            ).fetchall()
        }
        assert columns == {
            "id", "endpoint_id", "statement", "truth_label", "confidence",
            "severity", "priority", "status",
        }
        # The 0001 shape is genuinely restored: the pre-0002 insert works again.
        c.execute(
            "INSERT INTO hypotheses (statement, truth_label, confidence, severity, "
            "priority, status) VALUES ('back to 0001', 'HYPOTHESIS', 0.1, 'low', "
            "'low', 'open')"
        )
    finally:
        revert(c, 0)
        c.close()


# -- Stage 2: execution semantics against the real database -------------------


def test_0004_adds_and_reverts_adaptive_loop_columns(database_url: str) -> None:
    """0004 is additive, defaults existing runs to "pass 0, no new tasks", reverts."""
    c = psycopg.connect(database_url, row_factory=dict_row)
    try:
        revert(c, 0)
        assert apply(c) == [1, 2, 3, 4, 5, 6]

        def columns() -> set[str]:
            return {
                r["column_name"]
                for r in c.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'runs'"
                ).fetchall()
            }

        assert {"loop_pass", "pass_new_tasks"} <= columns()

        # A run created by the pre-0002 path (raw INSERT) must read back sane
        # defaults rather than NULL, or the loop's first comparison would fail.
        org = c.execute(
            "INSERT INTO organizations (name) VALUES ('Loop Org') RETURNING id"
        ).fetchone()["id"]
        program = c.execute(
            "INSERT INTO programs (organization_id, name, status) "
            "VALUES (%s, 'Loop Program', 'active') RETURNING id",
            (org,),
        ).fetchone()["id"]
        run_id = c.execute(
            "INSERT INTO runs (program_id, status, target) "
            "VALUES (%s, 'CREATED', 'example.com') RETURNING id",
            (program,),
        ).fetchone()["id"]
        row = c.execute(
            "SELECT loop_pass, pass_new_tasks FROM runs WHERE id = %s", (run_id,)
        ).fetchone()
        assert row["loop_pass"] == 0
        assert row["pass_new_tasks"] is False

        assert revert(c, 3) == [6, 5, 4]
        assert not {"loop_pass", "pass_new_tasks"} & columns()
    finally:
        revert(c, 0)
        c.close()


def test_storage_contract_persists_run_progress(schema) -> None:
    repos, program = _contract_storage(schema)
    run = Run(program_id=program["id"], target="example.com")
    repos.create_run(run)

    repos.set_run_progress(run.id, 7, True)
    stored = repos.get_run(run.id)
    assert stored.loop_pass == 7
    assert stored.pass_new_tasks is True

    repos.set_run_progress(run.id, 8, False)
    stored = repos.get_run(run.id)
    assert stored.loop_pass == 8
    assert stored.pass_new_tasks is False


def test_task_lifecycle_timestamps_are_stamped_in_postgres(schema) -> None:
    """The Stage-1 gap: ``completed_at`` was never written for any task."""
    repos, program = _contract_storage(schema)
    run = Run(program_id=program["id"], target="example.com")
    repos.create_run(run)
    task = Task(run_id=run.id, type="dns_resolve", target="example.com")
    repos.insert_tasks([task])

    repos.set_task_status(task.id, "running")
    running = repos.list_tasks(run.id)[0]
    assert running.started_at is not None
    assert running.completed_at is None, "still in flight"

    repos.set_task_status(task.id, "completed")
    done = repos.list_tasks(run.id)[0]
    assert done.completed_at is not None
    assert done.started_at == running.started_at, "start time must not move"

    # Re-queued for retry: a stale completed_at must not survive.
    repos.set_task_status(task.id, "pending")
    requeued = repos.list_tasks(run.id)[0]
    assert requeued.completed_at is None
    assert requeued.started_at is not None, "the earlier attempt already started"


def test_skipped_task_is_not_stamped_as_started_in_postgres(schema) -> None:
    repos, program = _contract_storage(schema)
    run = Run(program_id=program["id"], target="example.com")
    repos.create_run(run)
    task = Task(run_id=run.id, type="dns_resolve", target="evil.com")
    repos.insert_tasks([task])

    repos.set_task_status(task.id, "skipped")
    skipped = repos.list_tasks(run.id)[0]
    assert skipped.started_at is None, "a refused task never ran"
    assert skipped.completed_at is not None


def test_terminal_run_status_stamps_completed_at_in_postgres(schema) -> None:
    repos, program = _contract_storage(schema)
    run = Run(program_id=program["id"], target="example.com")
    repos.create_run(run)

    repos.set_run_status(run.id, "EXECUTING")
    assert repos.get_run(run.id).completed_at is None
    repos.set_run_status(run.id, "COMPLETED")
    assert repos.get_run(run.id).completed_at is not None


def test_postgres_and_memory_agree_on_task_lifecycle_timestamps(schema) -> None:
    """Same transitions must produce the same timestamp *presence* in both backends.

    Exact instants cannot match (two clocks, and PostgreSQL stamps server-side),
    so parity is asserted on which timestamps exist -- that is the property the
    orchestrator and the dashboard actually depend on.
    """

    def lifecycle(store, program_id) -> dict:
        run = Run(program_id=program_id, target="example.com")
        store.create_run(run)
        task = Task(run_id=run.id, type="dns_resolve", target="example.com")
        store.insert_tasks([task])
        store.set_task_status(task.id, "running")
        store.set_task_status(task.id, "completed")
        store.set_task_status(task.id, "pending")  # re-queued
        store.set_task_status(task.id, "skipped")
        store.set_run_status(run.id, "COMPLETED")
        stored = store.list_tasks(run.id)[0]
        done = store.get_run(run.id)
        return {
            "task_started": stored.started_at is not None,
            "task_completed": stored.completed_at is not None,
            "run_completed": done.completed_at is not None,
        }

    repos, program = _contract_storage(schema)
    assert lifecycle(repos, program["id"]) == lifecycle(MemoryStorage(), uuid4())


def test_retrying_a_failed_task_does_not_violate_the_fingerprint_index(
    schema,
) -> None:
    """Live proof for the "no lost work" retry path under migration 0003's index.

    Re-proposing a failed fingerprint must re-queue the existing row. Inserting a
    second row for the same fingerprint raises ``UniqueViolation``, which used to
    make every retry fail against the real database.
    """
    repos, program = _contract_storage(schema)
    orch = Orchestrator(
        storage=repos,
        run_tool=lambda task: ToolRun(
            task_id=task.id, tool_name=task.type, command=["argus"], exit_code=0,
            raw_output_ref="storage/raw/out.txt",
        ),
    )
    run = Run(
        program_id=program["id"],
        target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    orch.create_run(run)
    task = Task(run_id=run.id, type="dns_resolve", target="example.com")
    orch.plan(run, [task])

    repos.set_task_status(task.id, "failed")
    orch.plan(run, [Task(run_id=run.id, type="dns_resolve", target="example.com")])

    stored = repos.list_tasks(run.id)
    assert len(stored) == 1, "retry must reuse the row, not insert a duplicate"
    assert stored[0].status == "pending"


def test_out_of_scope_task_is_skipped_in_postgres(database_url: str) -> None:
    """The production safety guarantee, enforced against the real database."""
    with _clean_database(database_url), DatabaseConnection(database_url) as db:
        repos = Repositories(db.connect())
        org = repos.organizations.upsert("Scope Org")
        program = repos.programs.upsert(org["id"], "Scope Program")
        executed: list[str] = []

        def run_tool(task: Task) -> ToolRun:
            executed.append(task.target)
            return ToolRun(
                task_id=task.id, tool_name=task.type, command=["argus"],
                exit_code=0, raw_output_ref="storage/raw/out.txt",
            )

        orch = Orchestrator(storage=repos, run_tool=run_tool)
        run = Run(
            program_id=program["id"],
            target="example.com",
            configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
        )
        orch.create_run(run)
        orch.plan(
            run,
            [
                Task(run_id=run.id, type="dns_resolve", target="evil.com"),
                Task(run_id=run.id, type="dns_resolve", target="www.example.com"),
            ],
        )
        assert orch.run_to_completion(run.id) == "COMPLETED"

        assert executed == ["www.example.com"]
        by_target = {t.target: t for t in repos.list_tasks(run.id)}
        assert by_target["evil.com"].status == "skipped"
        assert by_target["www.example.com"].status == "completed"
        assert by_target["evil.com"].started_at is None


def test_failing_tool_does_not_wedge_the_run_in_postgres(database_url: str) -> None:
    """A raising tool must fail its task and let the run finish in the database."""
    with _clean_database(database_url), DatabaseConnection(database_url) as db:
        repos = Repositories(db.connect())
        org = repos.organizations.upsert("Failure Org")
        program = repos.programs.upsert(org["id"], "Failure Program")

        def run_tool(task: Task) -> ToolRun:
            if task.target == "boom.example.com":
                raise RuntimeError("tool exploded")
            return ToolRun(
                task_id=task.id, tool_name=task.type, command=["argus"],
                exit_code=0, raw_output_ref="storage/raw/out.txt",
            )

        orch = Orchestrator(storage=repos, run_tool=run_tool)
        run = Run(
            program_id=program["id"],
            target="example.com",
            configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
        )
        orch.create_run(run)
        orch.plan(
            run,
            [
                Task(run_id=run.id, type="dns_resolve", target="boom.example.com"),
                Task(run_id=run.id, type="dns_resolve", target="ok.example.com"),
            ],
        )
        assert orch.run_to_completion(run.id) == "COMPLETED"

        by_target = {t.target: t for t in repos.list_tasks(run.id)}
        assert by_target["boom.example.com"].status == "failed"
        assert by_target["boom.example.com"].completed_at is not None
        assert by_target["ok.example.com"].status == "completed"
        assert repos.get_run(run.id).completed_at is not None


def test_adaptive_loop_progress_survives_a_new_orchestrator(database_url: str) -> None:
    """A restarted process resumes the pass budget from the database, not from zero.

    Before, ``_loop_pass`` was process-local, so each restart handed the run a
    fresh budget and ``max_loop_passes`` was not really a limit.
    """
    with _clean_database(database_url), DatabaseConnection(database_url) as db:
        repos = Repositories(db.connect())
        org = repos.organizations.upsert("Loop Org")
        program = repos.programs.upsert(org["id"], "Loop Program")

        def run_tool(task: Task) -> ToolRun:
            return ToolRun(
                task_id=task.id, tool_name=task.type, command=["argus"],
                exit_code=0, raw_output_ref="storage/raw/out.txt",
            )

        def analysis(run: Run, current: list[Task]) -> list[Task]:
            # Always a fresh fingerprint, so the loop can only stop at the limit.
            return [
                Task(
                    run_id=run.id,
                    type="reprobe",
                    target=f"fragment-{len(current)}.example.com",
                )
            ]

        first = Orchestrator(storage=repos, run_tool=run_tool, analysis=analysis)
        first.max_loop_passes = 3
        run = Run(
            program_id=program["id"],
            target="example.com",
            configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
        )
        first.create_run(run)
        first.plan(run, [Task(run_id=run.id, type="dns_resolve", target="example.com")])

        while first.get_run(run.id).status != "ANALYZING":
            first.advance(run.id)
        first._advance_step(run.id)  # performs one analysis pass

        mid = repos.get_run(run.id)
        assert mid.loop_pass == 1
        assert mid.pass_new_tasks is True

        # A brand-new orchestrator over the same storage: the budget must continue
        # from the persisted value, so the run cancels instead of looping forever.
        second = Orchestrator(storage=repos, run_tool=run_tool, analysis=analysis)
        second.max_loop_passes = 3
        assert second.get_run(run.id).loop_pass == 1
        assert second.run_to_completion(run.id) == "CANCELLED"
        assert repos.get_run(run.id).loop_pass >= 3


# -- Stage 2: live coverage for the areas the orchestrator gates must prove ----


def _pg_orchestrator(storage, program_id, *, snapshot=None, analysis=None, tool=None, **kw):
    """Orchestrator over a real PostgreSQL-backed Storage, with recording tool."""
    calls: list[str] = []

    def run_tool(task: Task, scope=None) -> ToolRun:
        calls.append(task.target)
        if tool is not None:
            return tool(task)
        return ToolRun(
            task_id=task.id, tool_name=task.type, command=["argus", task.target],
            exit_code=0, raw_output_ref="storage/raw/out.txt",
        )

    orch = Orchestrator(
        storage=storage,
        run_tool=run_tool,
        analysis=analysis,
        **kw,
    )
    return orch, calls


def _leak_detector(concurrency: int = 1, rps: float = 1000.0):
    """A real ``RateLimiter`` that *records* any wait instead of raising.

    A permit that is never released leaves the next ``acquire()`` without a token, so it has
    to wait -- and any wait is a leak. Recording (rather than raising) matters: an exception
    raised inside ``acquire()`` happens before the orchestrator's ``try``, so it would be
    swallowed into a task failure and hide the real cause. The clock advances by a hair per
    call, so a leaked permit is refilled slowly enough to register as a wait but quickly
    enough that a genuine leak fails the test instead of hanging the suite.
    """
    waits: list[float] = []
    now = [0.0]

    def clock() -> float:
        now[0] += 1e-6
        return now[0]

    limiter = RateLimiter(
        RateLimits(requests_per_second=rps, concurrency=concurrency),
        clock=clock,
        sleeper=waits.append,
    )
    return limiter, waits


def test_scope_variants_against_postgres(schema) -> None:
    """Three distinct configurations, three distinct outcomes, all durable in PG.

    * no ``scope`` key        -> unscoped, the task executes (Phase-5 behaviour)
    * ``scope: {}``           -> deny-all, the task is refused
    * a real allowlist        -> enforced
    """
    repos, program = _contract_storage(schema)

    # 1. Unscoped run: the snapshot says nothing about scope.
    unscoped, calls = _pg_orchestrator(repos, program["id"])
    run_a = Run(program_id=program["id"], target="example.com")
    unscoped.create_run(run_a)
    unscoped.plan(run_a, [Task(run_id=run_a.id, type="dns_resolve", target="anything.test")])
    assert unscoped.run_to_completion(run_a.id) == "COMPLETED"
    assert calls == ["anything.test"], "a run with no scope key must not be restricted"
    assert repos.list_tasks(run_a.id)[0].status == "completed"

    # 2. Empty scope: declared, and it permits nothing. This must not be read as
    #    "no rules", which would silently widen a deliberately restrictive config.
    empty, empty_calls = _pg_orchestrator(repos, program["id"])
    run_b = Run(
        program_id=program["id"], target="example.com",
        configuration_snapshot={"scope": {}},
    )
    empty.create_run(run_b)
    empty.plan(run_b, [Task(run_id=run_b.id, type="dns_resolve", target="example.com")])
    assert empty.run_to_completion(run_b.id) == "COMPLETED"
    assert empty_calls == []
    assert repos.list_tasks(run_b.id)[0].status == "skipped"

    # 3. A real allowlist, enforced on the way in.
    scoped, scoped_calls = _pg_orchestrator(repos, program["id"])
    run_c = Run(
        program_id=program["id"], target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    scoped.create_run(run_c)
    scoped.plan(
        run_c,
        [
            Task(run_id=run_c.id, type="dns_resolve", target="evil.com"),
            Task(run_id=run_c.id, type="dns_resolve", target="www.example.com"),
        ],
    )
    assert scoped.run_to_completion(run_c.id) == "COMPLETED"
    assert scoped_calls == ["www.example.com"]
    assert {t.target: t.status for t in repos.list_tasks(run_c.id)} == {
        "evil.com": "skipped",
        "www.example.com": "completed",
    }


def test_scope_is_read_from_the_persisted_snapshot_by_a_new_orchestrator(schema) -> None:
    """Scope must survive a restart: a new instance re-reads it from PostgreSQL."""
    repos, program = _contract_storage(schema)
    run = Run(
        program_id=program["id"], target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    first = Orchestrator(storage=repos, run_tool=lambda t: ToolRun(
        task_id=t.id, tool_name=t.type, command=["argus"], exit_code=0,
        raw_output_ref="storage/raw/out.txt",
    ))
    first.create_run(run)
    first.plan(run, [Task(run_id=run.id, type="dns_resolve", target="evil.com")])

    # A brand-new orchestrator, with no scope injected at all: the only place the
    # rules can come from is the run row that was persisted in step one.
    second, calls = _pg_orchestrator(repos, program["id"])
    assert second.scope is None, "no guard is injected; the snapshot must supply it"
    assert second.run_to_completion(run.id) == "COMPLETED"

    assert calls == [], "the restarted orchestrator must still refuse evil.com"
    assert repos.list_tasks(run.id)[0].status == "skipped"


def test_rate_limiter_permits_are_held_during_execution_in_postgres(schema) -> None:
    """Acquire happens before the tool runs, and the permit is returned after.

    A real ``RateLimiter`` with ``concurrency=1`` is used: a leaked permit would force the
    second task to wait, and any wait is recorded and asserted against.
    """
    repos, program = _contract_storage(schema)
    held_during_execution: list[float] = []
    limiter, waits = _leak_detector(concurrency=1)

    def tool(task: Task) -> ToolRun:
        # A permit is held while the tool executes, so the global bucket is drained.
        held_during_execution.append(limiter._buckets["global"].tokens)
        return ToolRun(
            task_id=task.id, tool_name=task.type, command=["argus"],
            exit_code=0, raw_output_ref="storage/raw/out.txt",
        )

    orch, calls = _pg_orchestrator(repos, program["id"], tool=tool)
    orch.rate_limiter = limiter
    run = Run(
        program_id=program["id"], target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    orch.create_run(run)
    orch.plan(run, [
        Task(run_id=run.id, type="dns_resolve", target="a.example.com"),
        Task(run_id=run.id, type="dns_resolve", target="b.example.com"),
    ])
    assert orch.run_to_completion(run.id) == "COMPLETED"

    assert calls == ["a.example.com", "b.example.com"], "both tasks must execute"
    assert waits == [], f"acquire() had to wait, so a permit leaked: {waits}"
    assert held_during_execution == [0.0, 0.0], (
        "the permit must already be consumed while the tool runs"
    )
    # Both permits were returned, so the bucket is back to full capacity.
    assert limiter._buckets["global"].tokens == float(limiter._buckets["global"].capacity)


def test_rate_limit_permit_is_released_when_the_tool_raises_in_postgres(schema) -> None:
    """A raising tool must not leak its permit and throttle the rest of the run.

    The other task can only proceed if the failing call's permit was returned by the
    ``finally`` in ``_call_tool``; with ``concurrency=1`` a leak makes it wait, and the wait
    is recorded.
    """
    repos, program = _contract_storage(schema)
    limiter, waits = _leak_detector(concurrency=1)

    def tool(task: Task) -> ToolRun:
        if "boom" in task.target:
            raise RuntimeError("tool exploded")
        return ToolRun(
            task_id=task.id, tool_name=task.type, command=["argus"],
            exit_code=0, raw_output_ref="storage/raw/out.txt",
        )

    orch, calls = _pg_orchestrator(repos, program["id"], tool=tool)
    orch.rate_limiter = limiter
    run = Run(
        program_id=program["id"], target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    orch.create_run(run)
    orch.plan(run, [
        Task(run_id=run.id, type="dns_resolve", target="boom.example.com"),
        Task(run_id=run.id, type="dns_resolve", target="after.example.com"),
    ])
    assert orch.run_to_completion(run.id) == "COMPLETED"

    assert waits == [], f"the error path leaked a permit: {waits}"
    # Both tasks were attempted, so the second one needed the released permit.
    assert sorted(calls) == ["after.example.com", "boom.example.com"]
    assert {t.target: t.status for t in repos.list_tasks(run.id)} == {
        "boom.example.com": "failed",
        "after.example.com": "completed",
    }
    assert limiter._buckets["global"].tokens == float(limiter._buckets["global"].capacity)


def test_out_of_scope_task_consumes_no_rate_limit_permit_in_postgres(schema) -> None:
    """Refusing work must not cost capacity; the in-scope task still gets its permit.

    With a single permit available, two refused tasks plus one permitted task can only all
    behave correctly if the refused tasks never touched the limiter.
    """
    repos, program = _contract_storage(schema)
    limiter, waits = _leak_detector(concurrency=1)
    orch, calls = _pg_orchestrator(repos, program["id"])
    orch.rate_limiter = limiter
    orch.scope = ScopeGuard.from_config(ScopeConfig(allowed_domains=("example.com",)))
    run = Run(
        program_id=program["id"], target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    orch.create_run(run)
    orch.plan(run, [
        Task(run_id=run.id, type="dns_resolve", target="evil-1.com"),
        Task(run_id=run.id, type="dns_resolve", target="evil-2.com"),
        Task(run_id=run.id, type="dns_resolve", target="www.example.com"),
    ])
    assert orch.run_to_completion(run.id) == "COMPLETED"

    assert waits == [], f"a refused task consumed a permit: {waits}"
    assert calls == ["www.example.com"]
    statuses = {t.target: t.status for t in repos.list_tasks(run.id)}
    assert statuses["evil-1.com"] == "skipped"
    assert statuses["evil-2.com"] == "skipped"
    assert statuses["www.example.com"] == "completed"
    # A single permit existed, the one task took it, and it came back.
    assert limiter._buckets["global"].tokens == float(limiter._buckets["global"].capacity)


def test_nonzero_tool_exit_is_recorded_and_the_task_completes_in_postgres(schema) -> None:
    """The execution contract records the exit code; it does not fail the task.

    ``run_tool`` returning a ``ToolRun`` means the tool ran and reported, so the
    orchestrator marks the task complete and persists the non-zero exit for the
    evidence pipeline. Only a raised exception means the task failed.
    """
    repos, program = _contract_storage(schema)

    def tool(task: Task) -> ToolRun:
        return ToolRun(
            task_id=task.id, tool_name=task.type, command=["argus", task.target],
            exit_code=2, raw_output_ref="storage/raw/fail.txt",
        )

    orch, calls = _pg_orchestrator(repos, program["id"], tool=tool)
    run = Run(
        program_id=program["id"], target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    orch.create_run(run)
    orch.plan(run, [Task(run_id=run.id, type="dns_resolve", target="example.com")])
    assert orch.run_to_completion(run.id) == "COMPLETED"

    assert calls == ["example.com"]
    assert repos.list_tasks(run.id)[0].status == "completed"
    row = repos.conn.execute(
        "SELECT exit_code, raw_output_ref FROM tool_runs WHERE task_id = %s",
        (repos.list_tasks(run.id)[0].id,),
    ).fetchone()
    assert row["exit_code"] == 2, "a non-zero exit must be persisted, not swallowed"
    assert row["raw_output_ref"] == "storage/raw/fail.txt"


def test_retry_of_a_failed_task_actually_executes_in_postgres(schema) -> None:
    """The full retry path: fail -> replan -> requeue -> execute, with no duplicate row."""
    repos, program = _contract_storage(schema)
    attempts = {"n": 0}

    def tool(task: Task) -> ToolRun:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("transient failure")
        return ToolRun(
            task_id=task.id, tool_name=task.type, command=["argus"],
            exit_code=0, raw_output_ref="storage/raw/out.txt",
        )

    orch, calls = _pg_orchestrator(repos, program["id"], tool=tool)
    run = Run(
        program_id=program["id"], target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    orch.create_run(run)
    orch.plan(run, [Task(run_id=run.id, type="dns_resolve", target="example.com")])
    while orch.get_run(run.id).status != "EXECUTING":
        orch.advance(run.id)
    orch.advance(run.id)  # executes the batch; the tool raises
    assert repos.list_tasks(run.id)[0].status == "failed"

    # The planner re-proposes the same work, as a retry would. Against real
    # PostgreSQL this used to raise UniqueViolation on tasks_run_fingerprint_uq.
    orch.plan(run, [Task(run_id=run.id, type="dns_resolve", target="example.com")])
    assert len(repos.list_tasks(run.id)) == 1, "the retry reused the existing row"
    assert repos.list_tasks(run.id)[0].status == "pending"

    orch.advance(run.id)  # the requeued task now executes and succeeds
    assert repos.list_tasks(run.id)[0].status == "completed"
    assert attempts["n"] == 2
    assert len(repos.list_tasks(run.id)) == 1


def test_migration_0003_index_is_still_partial_and_enforced_in_postgres(schema) -> None:
    """0003 must still scope uniqueness to real fingerprints, and still bite."""
    assert "WHERE" in _fingerprint_index_def(schema)
    assert "<>" in _fingerprint_index_def(schema)

    repos, program = _contract_storage(schema)
    run = Run(program_id=program["id"], target="example.com")
    repos.create_run(run)

    # Empty fingerprints are exempt: many un-fingerprinted tasks in one run is legal.
    repos.insert_tasks([
        Task(run_id=run.id, type="dns_resolve", target="a", fingerprint=""),
        Task(run_id=run.id, type="http_probe", target="b", fingerprint=""),
    ])
    assert len(repos.list_tasks(run.id)) == 2

    # A real fingerprint may appear once per run, and only once.
    repos.insert_tasks([Task(run_id=run.id, type="dns_resolve", target="c", fingerprint="fp-1")])
    with pytest.raises(psycopg.errors.UniqueViolation):
        repos.insert_tasks([Task(run_id=run.id, type="dns_resolve", target="d", fingerprint="fp-1")])
    repos.conn.rollback()  # the caught violation aborted the transaction


def test_resume_requeues_and_finishes_interrupted_work_in_postgres(schema) -> None:
    """A crashed in-flight task is re-queued and completed, with no duplicate writes."""
    repos, program = _contract_storage(schema)
    orch, calls = _pg_orchestrator(repos, program["id"])
    run = Run(
        program_id=program["id"], target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    orch.create_run(run)
    orch.plan(run, [
        Task(run_id=run.id, type="dns_resolve", target="a.example.com"),
        Task(run_id=run.id, type="dns_resolve", target="b.example.com"),
    ])
    while orch.get_run(run.id).status != "EXECUTING":
        orch.advance(run.id)

    # Crash: one task left in flight.
    in_flight = repos.list_tasks(run.id)[0]
    repos.set_task_status(in_flight.id, "running")
    assert calls == []

    assert orch.resume(run.id) == "COMPLETED"

    statuses = sorted(t.status for t in repos.list_tasks(run.id))
    assert statuses == ["completed", "completed"]
    assert len(repos.list_tasks(run.id)) == 2, "resume must not duplicate task rows"
    # Each target ran exactly once: no repeated work after the crash.
    assert sorted(calls) == ["a.example.com", "b.example.com"]
    assert repos.get_run(run.id).completed_at is not None
    assert repos.get_run(run.id).status == "COMPLETED"


def test_resume_of_a_terminal_run_never_moves_it_backwards_in_postgres(schema) -> None:
    repos, program = _contract_storage(schema)
    orch, calls = _pg_orchestrator(repos, program["id"])
    run = Run(
        program_id=program["id"], target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    orch.create_run(run)
    orch.plan(run, [Task(run_id=run.id, type="dns_resolve", target="example.com")])
    assert orch.run_to_completion(run.id) == "COMPLETED"
    completed_at = repos.get_run(run.id).completed_at
    calls.clear()

    assert orch.resume(run.id) == "COMPLETED"
    assert repos.get_run(run.id).status == "COMPLETED", "a terminal run must stay terminal"
    assert repos.get_run(run.id).completed_at == completed_at
    assert calls == [], "a terminal run must not re-execute anything"


def test_dependencies_are_honoured_against_postgres(schema) -> None:
    """A child waits for a *finished* parent, and only for a finished parent."""
    repos, program = _contract_storage(schema)
    orch, calls = _pg_orchestrator(repos, program["id"])
    run = Run(
        program_id=program["id"], target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    orch.create_run(run)
    parent = Task(run_id=run.id, type="subdomain_enum", target="example.com")
    child = Task(
        run_id=run.id, type="http_probe", target="www.example.com",
        parent_task_id=parent.id,
    )
    orch.plan(run, [child, parent])  # child proposed first, on purpose
    while orch.get_run(run.id).status != "EXECUTING":
        orch.advance(run.id)

    # The parent is in flight: the child must not run against input it lacks.
    repos.set_task_status(parent.id, "running")
    orch.advance(run.id)
    assert calls == []
    assert {t.type: t.status for t in repos.list_tasks(run.id)} == {
        "subdomain_enum": "running",
        "http_probe": "pending",
    }

    # Once the parent genuinely completes, the child is unblocked.
    repos.set_task_status(parent.id, "completed")
    orch.advance(run.id)
    assert calls == ["www.example.com"]
    assert {t.type: t.status for t in repos.list_tasks(run.id)}["http_probe"] == "completed"


def test_child_of_a_failed_parent_never_runs_in_postgres(schema) -> None:
    repos, program = _contract_storage(schema)
    orch, calls = _pg_orchestrator(repos, program["id"])
    run = Run(
        program_id=program["id"], target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    orch.create_run(run)
    parent = Task(run_id=run.id, type="subdomain_enum", target="example.com")
    child = Task(
        run_id=run.id, type="http_probe", target="www.example.com",
        parent_task_id=parent.id,
    )
    orch.plan(run, [parent, child])
    while orch.get_run(run.id).status != "EXECUTING":
        orch.advance(run.id)

    repos.set_task_status(parent.id, "failed")  # the parent will never succeed
    orch.advance(run.id)
    assert calls == [], "a failed parent must not let its child execute"
    assert {t.type: t.status for t in repos.list_tasks(run.id)}["http_probe"] == "pending"


def test_dangling_parent_reference_is_impossible_in_postgres(schema) -> None:
    """``tasks.parent_task_id -> tasks.id`` is a documented FK, so it is enforced.

    A task can never point at a parent that does not exist, which means the
    orchestrator's dependency wait only ever has to handle "parent exists but has
    not finished" (covered above). This test pins the guarantee that makes that
    reasoning sound, and that the real database refuses the impossible state.
    """
    assert "tasks_parent_task_id_fkey" in _foreign_key_names(schema)

    repos, program = _contract_storage(schema)
    run = Run(program_id=program["id"], target="example.com")
    repos.create_run(run)
    orphan = Task(run_id=run.id, type="http_probe", target="www.example.com")
    orphan.parent_task_id = uuid4()  # a parent that was never planned

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        repos.insert_tasks([orphan])
    repos.conn.rollback()  # the caught violation aborted the transaction


def test_loop_state_is_run_scoped_not_shared_between_orchestrators(schema) -> None:
    """Two runs driven by two instances must keep independent counters.

    If the pass counter were shared mutable state on the orchestrator (as it was
    before it was persisted), these interleaved passes would contaminate each
    other and ``max_loop_passes`` would fire against the wrong run.
    """
    repos, program = _contract_storage(schema)

    def analysis_for(marker: str):
        """Propose a genuinely new target for the first two passes, then a repeat.

        Fingerprints are derived from task type + target + config + parent, so a *new
        target* is new work (the loop continues) while a *repeat* of an already-planned
        target dedupes to the same fingerprint (the loop stops). Without this bound the
        loop would keep finding new work forever, which is the point of
        ``max_loop_passes`` rather than something to assert here.
        """
        state = {"n": 0}

        def analysis(run: Run, current: list[Task]) -> list[Task]:
            state["n"] += 1
            n = state["n"] if state["n"] <= 2 else 1
            return [Task(run_id=run.id, type="probe", target=f"{marker}-{n}.example.com")]
        return analysis

    orch_a, _ = _pg_orchestrator(repos, program["id"], analysis=analysis_for("a"))
    orch_b, _ = _pg_orchestrator(repos, program["id"], analysis=analysis_for("b"))
    run_a = Run(
        program_id=program["id"], target="a.example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    run_b = Run(
        program_id=program["id"], target="b.example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    orch_a.create_run(run_a)
    orch_b.create_run(run_b)
    orch_a.plan(run_a, [Task(run_id=run_a.id, type="probe", target="seed-a.example.com")])
    orch_b.plan(run_b, [Task(run_id=run_b.id, type="probe", target="seed-b.example.com")])

    def one_pass(orch: Orchestrator, run_id) -> int:
        """Walk to the next ANALYZING step and run exactly one analysis pass.

        This reproduces the walk ``run_to_completion`` performs because ``advance()``
        deliberately does not step a run forward at EXECUTING when nothing ran.
        """
        for _ in range(200):
            run = orch.get_run(run_id)
            if run.status == "ANALYZING":
                orch._advance_step(run_id)  # runs the hook, increments loop_pass
                return orch.get_run(run_id).loop_pass
            if run.status in ("COMPLETED", "CANCELLED", "FAILED"):
                raise AssertionError(f"run reached {run.status} before an analysis pass")
            if run.status == "EXECUTING":
                if not orch._execute_pending(run, "probe"):
                    orch._advance_step(run_id)
                continue
            orch._advance_step(run_id)
        raise AssertionError("run never reached ANALYZING")

    # Interleave the two runs: neither instance may advance the other's counter.
    assert one_pass(orch_a, run_a.id) == 1
    assert one_pass(orch_b, run_b.id) == 1
    assert repos.get_run(run_a.id).loop_pass == 1
    assert repos.get_run(run_b.id).loop_pass == 1

    assert one_pass(orch_a, run_a.id) == 2
    assert repos.get_run(run_a.id).loop_pass == 2
    assert repos.get_run(run_b.id).loop_pass == 1, (
        "run B's progress must not be advanced by run A's pass"
    )

    # The counters are columns on the run, so a third instance agrees with the database.
    observer = Orchestrator(storage=repos, run_tool=lambda t: ToolRun(
        task_id=t.id, tool_name=t.type, command=["argus"], exit_code=0,
        raw_output_ref="storage/raw/out.txt",
    ))
    assert observer.get_run(run_a.id).loop_pass == 2
    assert observer.get_run(run_b.id).loop_pass == 1
    assert one_pass(orch_b, run_b.id) == 2
    assert repos.get_run(run_a.id).loop_pass == 2, (
        "run A must be unaffected by run B catching up"
    )


def test_loop_completes_when_reanalysis_adds_no_new_fingerprint_in_postgres(schema) -> None:
    """The documented stop condition: COMPLETED only when re-analysis adds nothing new.

    The progress signal is fingerprint-based, so a pass that re-proposes work the run has
    already planned adds no *new* fingerprint and the loop must terminate instead of
    grinding through its whole ``max_loop_passes`` budget.
    """
    repos, program = _contract_storage(schema)
    calls: list[str] = []

    def analysis(run: Run, current: list[Task]) -> list[Task]:
        # The very same type + target the run already planned, so the derived
        # fingerprint is identical and nothing new is learned.
        return [Task(run_id=run.id, type="probe", target="example.com")]

    orch, _ = _pg_orchestrator(repos, program["id"], analysis=analysis)
    run = Run(
        program_id=program["id"], target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    orch.create_run(run)
    orch.plan(run, [Task(run_id=run.id, type="probe", target="example.com")])

    assert orch.run_to_completion(run.id, tool="probe") == "COMPLETED"
    assert repos.get_run(run.id).loop_pass == 1, "one analysis pass, then a stop"
    # The re-proposed task deduped onto the existing row rather than duplicating it.
    assert len(repos.list_tasks(run.id)) == 1
    assert repos.get_run(run.id).completed_at is not None


def test_production_storage_is_durable_so_the_optional_stub_cannot_hide(schema) -> None:
    """The real storage must genuinely implement the optional progress write.

    ``Storage`` declares ``set_run_progress`` as a no-op so a pre-Phase-8 double
    still conforms. If the shipped PostgreSQL storage inherited that stub, real
    runs would silently restart their pass budget -- so pin the override here.
    """
    assert Repositories.__dict__.get("set_run_progress") is not None, (
        "the production storage must define the write itself, not inherit a stub"
    )
    assert Repositories.set_run_progress is not Storage.set_run_progress
    assert MemoryStorage.set_run_progress is not Storage.set_run_progress


def test_tool_filter_against_postgres(schema) -> None:
    """Only matching task types execute, and the run still reaches a terminal state."""
    repos, program = _contract_storage(schema)
    orch, calls = _pg_orchestrator(repos, program["id"])
    run = Run(
        program_id=program["id"], target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    orch.create_run(run)
    orch.plan(run, [
        Task(run_id=run.id, type="dns_resolve", target="example.com"),
        Task(run_id=run.id, type="http_probe", target="www.example.com"),
    ])

    assert orch.run_to_completion(run.id, tool="dns_resolve") == "COMPLETED"
    assert calls == ["example.com"], "the http_probe task must not have run"
    assert {t.type: t.status for t in repos.list_tasks(run.id)} == {
        "dns_resolve": "completed",
        "http_probe": "pending",
    }


def test_tool_filter_matching_nothing_terminates_in_postgres(schema) -> None:
    """Regression guard: a filter that excludes everything must not spin forever."""
    repos, program = _contract_storage(schema)
    orch, calls = _pg_orchestrator(repos, program["id"])
    run = Run(
        program_id=program["id"], target="example.com",
        configuration_snapshot={"scope": {"allowed_domains": ["example.com"]}},
    )
    orch.create_run(run)
    orch.plan(run, [Task(run_id=run.id, type="http_probe", target="www.example.com")])

    assert orch.run_to_completion(run.id, tool="dns_resolve") == "COMPLETED"
    assert calls == []
    assert repos.get_run(run.id).status == "COMPLETED"
