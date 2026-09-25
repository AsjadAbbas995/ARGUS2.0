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

from core.memory_storage import MemoryStorage
from core.orchestrator import Orchestrator
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


def test_revert_updates_schema_migrations_bookkeeping(schema) -> None:
    """``schema_migrations`` must never claim a version whose schema was reverted."""
    assert _applied(schema) == [1, 2, 3]
    assert "WHERE" in _fingerprint_index_def(schema), "0003 must scope the unique index"

    assert revert(schema, 1) == [3, 2]
    assert _applied(schema) == [1], "reverted versions must not stay recorded as applied"
    assert schema.execute(
        "SELECT to_regclass('hypotheses_run_id_idx') AS t"
    ).fetchone()["t"] is None, "0002's index must be gone"
    assert "WHERE" not in _fingerprint_index_def(schema), (
        "reverting 0003 must restore 0001's unconditional unique index"
    )

    # 0002 and 0003's objects are gone, so apply must re-run both rather than
    # skipping them because bookkeeping still claimed they were applied.
    assert apply(schema) == [2, 3]
    assert _applied(schema) == [1, 2, 3]
    assert schema.execute(
        "SELECT to_regclass('hypotheses_run_id_idx') AS t"
    ).fetchone()["t"]
    assert "WHERE" in _fingerprint_index_def(schema)


def test_0002_on_fresh_database_validates_run_id_requirement(database_url: str) -> None:
    c = psycopg.connect(database_url)
    try:
        revert(c, 0)
        assert apply(c) == [1, 2, 3]
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

        assert apply(c) == [2, 3], "0002/0003 must apply to a populated hypotheses table"

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
        assert apply(c) == [1, 2, 3]
        assert revert(c, 1) == [3, 2]

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
