"""Phase 15.1 LIVE: persisted PostgreSQL facts -> projection -> served API and report.

Gated on ``ARGUS_TEST_DATABASE_URL`` (see ``tests/conftest.py``). Every statement here runs
against real PostgreSQL through the production ``Repositories`` facade -- no fakes, no
in-memory substitutes -- because the things this phase can get wrong are exactly the things
an in-memory double cannot see: the run-scoping JOIN, ``inet`` -> text adaptation, the
``WHERE id = ANY(...)`` batching, and whether the served app really reaches the projection.

The acceptance chain:

    real Phase 14 ingestion -> evidence -> assets/ips/asset_ips/ports/web_apps
                            -> Repositories.attack_surface
                            -> correlation graph + relationship engine
                            -> GET /api/v1/runs/{id}/attack-surface
                            -> GET /api/v1/runs/{id}/reports/{json,markdown,html}

Cross-run isolation is asserted against the database, not against a hand-built fixture: two
runs share one program, so they share the very same ``assets``/``ips`` rows. Only the run
that actually observed a fact holds its ``evidence`` row, so only that run may project it.
An implementation that scoped by program membership or by ``discovered_at`` -- both of which
look correct and both of which leak -- fails here.

Isolated by construction
    The schema is reverted and re-applied per test and every table is truncated on
    teardown, so a shared test database cannot influence any assertion here.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg.rows import dict_row

from api.serve import create_serve_app
from core.config import Config
from core.scope_guard import ScopeGuard
from core.tool_runner import ToolRunner
from database.migrate import apply
from database.models.entities import Run, ScopeRule as ScopeRuleEntity, Task, ToolRun
from database.repositories.all import Repositories
from database.repositories.base import DatabaseConnection
from recon.dns.resolver import IpObservation
from recon.ingest import plan_ingestion
from recon.web.httpx_probe import AssetTechnologyObservation, WebAppObservation
from starlette.testclient import TestClient

from core.config import ScopeConfig

TARGET = "example.com"
RESOLVED = "93.184.216.34"
API_KEY = "phase15-key"
SCOPE_DICT = {"scope": {"allowed_domains": [TARGET], "allowed_ips": [RESOLVED]}}


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {API_KEY}"}


def _scope() -> ScopeGuard:
    """Authorize the domain *and* the address, since ``check_ip`` denies by default."""
    return ScopeGuard.from_config(
        ScopeConfig(allowed_domains=(TARGET,), allowed_ips=(f"{RESOLVED}/32",))
    )


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def schema(database_url: str):
    """A committed, migrated schema that other connections can actually see.

    ``autocommit=True`` is load-bearing here and must not be "simplified" away. psycopg
    opens an implicit transaction that is never committed by default, which is ideal for
    tests that only ever read back through the same connection -- and completely wrong for
    this module. The served app under test opens its *own* connection through
    ``create_serve_app``, so the seeded program, run, tool runs and evidence would be
    invisible to it and every served assertion would 404 against a run the test had just
    created.

    Rollback semantics are unaffected: ``Repositories.transaction()`` issues an explicit
    BEGIN/COMMIT regardless of autocommit, which is what ``ingest_observations`` relies on.

    The schema is rebuilt by dropping and recreating ``public`` rather than by
    ``revert(conn, 0)``. ``revert`` can only undo versions recorded in
    ``schema_migrations``, so a database whose bookkeeping has drifted (a table left behind
    by an autocommit writer while the recording transaction rolled back -- exactly what a
    shared test database accumulates) leaves a stale table that ``apply`` then trips over
    with "column ... already exists". A hard reset is immune to that and cannot inherit
    another test's rows.
    """
    c = psycopg.connect(database_url, row_factory=dict_row, autocommit=True)
    c.execute("DROP SCHEMA public CASCADE")
    c.execute("CREATE SCHEMA public")
    apply(c)
    yield c
    c.execute("DROP SCHEMA IF EXISTS public CASCADE")
    c.execute("CREATE SCHEMA public")
    c.close()


@pytest.fixture
def store(schema):
    return Repositories(schema)


@pytest.fixture
def program(store) -> UUID:
    org = store.organizations.upsert("Phase 15 Org")
    program_id = store.programs.upsert(org["id"], "Phase 15 Program")["id"]
    for rule_type, value in (("domain", TARGET), ("ip", RESOLVED)):
        store.scope_rules.upsert(
            ScopeRuleEntity(
                program_id=program_id, rule_type=rule_type, value=value, allowed=True
            )
        )
    return program_id


def _new_run(store, program: UUID, name: str = "run") -> Run:
    return store.create_run(
        Run(
            program_id=program,
            status="CREATED",
            target=TARGET,
            configuration_snapshot=dict(SCOPE_DICT),
        )
    )


def _execute(
    store,
    run: Run,
    artifacts,
    *,
    source="dns",
    raw="raw/phase15.out",
    scope=None,
) -> ToolRun:
    """A real ToolRun plus a real, transaction-wrapped Phase 14 ingestion."""
    task = Task(
        id=uuid4(),
        run_id=run.id,
        type=source,
        target=TARGET,
        status="running",
    )
    store.insert_tasks([task])
    tool_run = store.insert_tool_run(
        ToolRun(
            task_id=task.id,
            tool_name=source,
            command=[source, "-d", TARGET],
            exit_code=0,
            raw_output_ref=raw,
        )
    )
    plan = plan_ingestion(
        artifacts,
        scope=scope or _scope(),
        source=source,
        target_host=TARGET,
        max_artifacts=1000,
    )
    with store.transaction():
        store.ingest_observations(
            plan, tool_run_id=tool_run.id, raw_output_ref=raw, program_id=run.program_id
        )
    return tool_run


def _full_observations():
    """The complete Phase 14 fact set: host, IP, web app and technology."""
    return [
        IpObservation(address=RESOLVED, record_type="A"),
        WebAppObservation(
            host=TARGET,
            url="https://example.com",
            scheme="https",
            port=443,
            status_code=200,
            title="Example Domain",
            webserver="nginx",
        ),
        AssetTechnologyObservation(host=TARGET, technology="nginx"),
    ]


# ---------------------------------------------------------------------------
# the projection over real persisted rows
# ---------------------------------------------------------------------------


def test_persisted_phase_14_facts_project_into_a_connected_graph(store, program):
    """The whole read path, over rows written by the real Phase 14 writer."""
    run = _new_run(store, program)
    tool_run = _execute(store, run, _full_observations())

    payload = store.attack_surface(run.id)
    assert payload is not None
    assert payload["run_id"] == str(run.id)
    assert payload["available"] is True

    kinds = payload["records"]["by_kind"]
    assert kinds["domain"] == 1
    assert kinds["ip"] == 1
    assert kinds["port"] == 1
    assert kinds["webapp"] == 1
    assert kinds["technology"] == 1

    graph = payload["graph"]
    assert graph["node_count"] == 5
    assert graph["orphan_count"] == 0, (
        "a fully evidenced Phase 14 fact set must produce a connected graph"
    )
    edge_kinds = {e["kind"] for e in graph["edges"]}
    assert "resolves_to" in edge_kinds
    assert "hosts" in edge_kinds or "serves" in edge_kinds or "runs" in edge_kinds

    keys = {n["key"] for n in graph["nodes"]}
    assert TARGET in keys
    assert RESOLVED in keys
    assert f"{RESOLVED}:443" in keys
    assert f"{TARGET}:443" in keys
    assert "nginx@example.com" in keys

    # the real inet came back as a usable string, not a psycopg object
    ip_node = next(n for n in graph["nodes"] if n["kind"] == "ip")
    assert ip_node["attributes"]["address"] == RESOLVED
    assert isinstance(ip_node["attributes"]["address"], str)

    # the real observed values survived projection
    app_node = next(n for n in graph["nodes"] if n["kind"] == "webapp")
    assert app_node["attributes"]["status_code"] == "200"
    assert app_node["attributes"]["title"] == "Example Domain"

    # every node cites evidence that belongs to THIS run
    run_evidence = {str(e.id) for e in store.list_evidence(run.id)}
    assert run_evidence
    for node in graph["nodes"]:
        assert node["evidence_id"] in run_evidence, (
            f"node {node['key']} cites evidence outside this run"
        )
    for edge in graph["edges"]:
        assert edge["evidence_id"] in run_evidence

    # and the tool run that produced them really is this run's
    tool_runs = store.list_tool_runs(run.id)
    assert [t.id for t in tool_runs] == [tool_run.id]
    assert all(t.tool_run_id == tool_run.id for t in store.list_evidence(run.id))


def test_inet_addresses_are_cast_to_text_so_nodes_key_correctly(store, program):
    """``ips.address`` is ``inet``, so the graph key must not carry a netmask.

    ``address::text`` would yield ``2001:db8::1/128`` -- PostgreSQL always stores the
    prefix length -- which would key this node differently from every other projection of
    the same observed address.
    """
    run = _new_run(store, program)
    _execute(
        store,
        run,
        [IpObservation(address="2001:db8::1", record_type="AAAA")],
        scope=ScopeGuard.from_config(
            ScopeConfig(allowed_domains=(TARGET,), allowed_ips=("2001:db8::1/128",))
        ),
    )
    keys = {n["key"] for n in store.attack_surface(run.id)["graph"]["nodes"]}
    assert "2001:db8::1" in keys
    assert not any("/" in key for key in keys), f"a netmask leaked into a node key: {keys}"


def test_ipv4_keys_also_carry_no_netmask(store, program):
    """The same for IPv4, where PostgreSQL renders ``93.184.216.34/32``."""
    run = _new_run(store, program)
    _execute(store, run, [IpObservation(address=RESOLVED, record_type="A")])
    keys = {n["key"] for n in store.attack_surface(run.id)["graph"]["nodes"]}
    assert RESOLVED in keys
    assert not any("/" in key for key in keys), f"a netmask leaked into a node key: {keys}"


def test_repeated_reads_return_an_identical_payload(store, program):
    run = _new_run(store, program)
    _execute(store, run, _full_observations())
    assert store.attack_surface(run.id) == store.attack_surface(run.id)


def test_attack_surface_for_an_unknown_run_is_none(store):
    assert store.attack_surface(uuid4()) is None


def test_a_run_that_observed_nothing_is_available_and_empty(store, program):
    run = _new_run(store, program)
    payload = store.attack_surface(run.id)
    assert payload["available"] is True, "an observed-nothing run is not an unavailable store"
    assert payload["records"]["count"] == 0
    assert payload["graph"]["node_count"] == 0
    assert payload["evidence_counts"] == {}


def test_evidence_counts_include_denied_observations(store, program):
    """Out-of-scope findings are counted as recorded, and still project no node."""
    run = _new_run(store, program)
    _execute(
        store,
        run,
        [IpObservation(address=RESOLVED, record_type="A"), "evil.com"],
        source="subfinder",
    )
    payload = store.attack_surface(run.id)
    assert payload["evidence_counts"]["observed_host"] == 1
    assert "evil.com" not in {n["key"] for n in payload["graph"]["nodes"]}


# ---------------------------------------------------------------------------
# cross-run isolation -- the property that distinguishes provenance from heuristics
# ---------------------------------------------------------------------------


def test_a_run_only_projects_the_facts_its_own_evidence_names(store, program):
    """Two runs, one program, one shared ``assets``/``ips`` row.

    The asset and IP rows are program-scoped and therefore visible to both runs. Only the
    observing run holds the ``evidence`` rows, so only it may project them. Scoping by
    program membership, or by ``discovered_at``/``first_seen`` ordering, would wrongly
    attribute the fact to the second run.
    """
    observing = _new_run(store, program, "observing")
    observing_tool_run = _execute(store, observing, _full_observations())

    silent = _new_run(store, program, "silent")

    # the rows really are shared: one asset, one ip, in the same program
    schema_counts = {
        "assets": store.conn.execute("SELECT count(*) AS n FROM assets").fetchone()["n"],
        "ips": store.conn.execute("SELECT count(*) AS n FROM ips").fetchone()["n"],
    }
    assert schema_counts == {"assets": 1, "ips": 1}

    silent_payload = store.attack_surface(silent.id)
    assert silent_payload["available"] is True
    assert silent_payload["records"]["count"] == 0
    assert silent_payload["graph"]["node_count"] == 0
    assert silent_payload["graph"]["edges"] == []

    # ...while the observing run sees the whole graph
    observing_payload = store.attack_surface(observing.id)
    assert observing_payload["graph"]["node_count"] == 5
    observing_evidence = {str(e.id) for e in store.list_evidence(observing.id)}
    assert observing_tool_run.id in {
        t.id for t in store.list_tool_runs(observing.id)
    }
    for node in observing_payload["graph"]["nodes"]:
        assert node["evidence_id"] in observing_evidence


def test_two_runs_that_both_observe_the_same_fact_both_project_it(store, program):
    """Shared entities are not withheld: provenance is per evidence row, not per entity."""
    first = _new_run(store, program, "first")
    _execute(store, first, _full_observations(), raw="raw/first.out")
    second = _new_run(store, program, "second")
    _execute(store, second, _full_observations(), raw="raw/second.out")

    one = store.attack_surface(first.id)
    two = store.attack_surface(second.id)
    assert one["records"]["count"] == two["records"]["count"] == 5
    assert {n["key"] for n in one["graph"]["nodes"]} == {
        n["key"] for n in two["graph"]["nodes"]
    }
    # each run cites its own evidence
    one_ids = {n["evidence_id"] for n in one["graph"]["nodes"]}
    two_ids = {n["evidence_id"] for n in two["graph"]["nodes"]}
    assert one_ids.isdisjoint(two_ids), "each run must cite its own evidence"
    assert one_ids <= {str(e.id) for e in store.list_evidence(first.id)}
    assert two_ids <= {str(e.id) for e in store.list_evidence(second.id)}


def test_a_second_run_seeing_only_a_subset_projects_only_that_subset(store, program):
    """Partial observation yields a partial graph, never the whole store."""
    first = _new_run(store, program, "full")
    _execute(store, first, _full_observations())

    second = _new_run(store, program, "dns-only")
    _execute(
        store,
        second,
        [IpObservation(address=RESOLVED, record_type="A")],
        raw="raw/dns-only.out",
    )

    payload = store.attack_surface(second.id)
    kinds = payload["records"]["by_kind"]
    assert kinds.get("domain") == 1
    assert kinds.get("ip") == 1
    assert "webapp" not in kinds, "no web app was observed by this run"
    assert "port" not in kinds
    assert payload["graph"]["edges"], "the host -> IP binding this run observed is present"
    keys = {n["key"] for n in payload["graph"]["nodes"]}
    assert f"{RESOLVED}:443" not in keys


def test_evidence_outside_the_run_chain_is_never_projected(store, program, schema):
    """An evidence row whose tool run belongs to another run cannot leak in."""
    run = _new_run(store, program, "target")
    _execute(store, run, [IpObservation(address=RESOLVED, record_type="A")])
    other = _new_run(store, program, "other")

    # a genuine observation, persisted for a *different* run
    other_task = Task(id=uuid4(), run_id=other.id, type="dns", target=TARGET, status="running")
    store.insert_tasks([other_task])
    other_tool_run = store.insert_tool_run(
        ToolRun(
            task_id=other_task.id, tool_name="dns", command=["dns"], exit_code=0,
            raw_output_ref="raw/other.out",
        )
    )
    secret_ip = "198.51.100.9"
    with store.transaction():
        store.ingest_observations(
            plan_ingestion(
                [IpObservation(address=secret_ip, record_type="A")],
                scope=ScopeGuard.from_config(
                    ScopeConfig(
                        allowed_domains=(TARGET,),
                        allowed_ips=(f"{secret_ip}/32",),
                    )
                ),
                source="dns",
                target_host=TARGET,
            ),
            tool_run_id=other_tool_run.id,
            raw_output_ref="raw/other.out",
            program_id=program,
        )

    assert secret_ip not in {n["key"] for n in store.attack_surface(run.id)["graph"]["nodes"]}
    assert secret_ip in {
        n["key"] for n in store.attack_surface(other.id)["graph"]["nodes"]
    }


def test_evidence_with_no_tool_run_is_not_attributable_to_any_run(store, program):
    """A NULL ``tool_run_id`` is excluded rather than assumed to belong somewhere."""
    run = _new_run(store, program)
    _execute(store, run, [IpObservation(address=RESOLVED, record_type="A")])
    store.conn.execute(
        "INSERT INTO evidence (tool_run_id, entity_type, entity_id, raw_reference) "
        "VALUES (NULL, 'ip', (SELECT id FROM ips LIMIT 1), 'orphan.out')"
    )
    payload = store.attack_surface(run.id)
    assert payload["available"] is True
    # the orphan row is scoped out, and the legitimately evidenced IP still projects
    assert payload["records"]["by_kind"]["ip"] == 1


# ---------------------------------------------------------------------------
# the served API and report, against the real repositories
# ---------------------------------------------------------------------------


@pytest.fixture
def served(database_url: str, schema, tmp_path: Path):
    def factory():
        config = Config.from_dict(
            {
                "database": {"url": database_url},
                "scope": {"allowed_domains": [TARGET], "allowed_ips": [RESOLVED]},
                "storage": {"raw_dir": str(tmp_path / "raw")},
            }
        )
        app = create_serve_app(
            api_key=API_KEY,
            database_url=database_url,
            config=config,
            runner=ToolRunner(raw_dir=tmp_path / "raw"),
        )
        return TestClient(app)

    return factory


def _create_run(client, program_id: UUID) -> str:
    response = client.post(
        "/api/v1/runs",
        json={"target": TARGET, "program_id": str(program_id)},
        headers=_auth(),
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_served_attack_surface_route_returns_the_projected_graph(served, store, program):
    run = _new_run(store, program)
    _execute(store, run, _full_observations())

    with served() as client:
        response = client.get(f"/api/v1/runs/{run.id}/attack-surface", headers=_auth())
        assert response.status_code == 200, response.text
        payload = response.json()

    assert payload["available"] is True
    assert payload["run_id"] == str(run.id)
    assert payload["records"]["count"] == 5
    assert payload["graph"]["node_count"] == 5
    assert payload["endpoint_subgraph"]["empty"] is True
    # identical to the storage read: the route adds no view of its own
    assert payload == store.attack_surface(run.id)


def test_served_attack_surface_route_is_read_only(served, store, program):
    """Hitting the route must not create, mutate or delete anything."""
    run = _new_run(store, program)
    _execute(store, run, _full_observations())
    before = _row_counts(store)

    with served() as client:
        for _ in range(3):
            assert client.get(
                f"/api/v1/runs/{run.id}/attack-surface", headers=_auth()
            ).status_code == 200

    assert _row_counts(store) == before, "a read route wrote to the database"


def test_served_attack_surface_route_requires_auth_and_404s(served, store, program):
    run = _new_run(store, program)
    with served() as client:
        assert client.get(f"/api/v1/runs/{run.id}/attack-surface").status_code == 401
        bad = client.get(
            f"/api/v1/runs/{run.id}/attack-surface",
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert bad.status_code == 401
        assert client.get(
            f"/api/v1/runs/{uuid4()}/attack-surface", headers=_auth()
        ).status_code == 404


def test_served_report_is_fed_from_real_persisted_facts(served, store, program):
    """The false-green this closes: the report previously rendered empty sections."""
    run = _new_run(store, program)
    tool_run = _execute(store, run, _full_observations())

    with served() as client:
        body = client.get(f"/api/v1/runs/{run.id}/reports/json", headers=_auth())
        assert body.status_code == 200, body.text
        report = body.json()
        markdown = client.get(f"/api/v1/runs/{run.id}/reports/markdown", headers=_auth()).text
        html = client.get(f"/api/v1/runs/{run.id}/reports/html", headers=_auth()).text

    # tool runs: real, previously always empty
    assert report["tool_runs"]["total"] == 1
    assert report["tool_runs"]["by_tool"] == {"dns": 1}
    assert report["tool_runs"]["items"][0]["id"] == str(tool_run.id)

    # evidence: real rows with real provenance
    assert report["evidence_count"] == len(store.list_evidence(run.id)) > 0
    assert all(
        item["tool_run_id"] == str(tool_run.id) for item in report["evidence"]
    )

    # asset counts: canonical entities only
    assert report["assets"] == {
        "asset": 1,
        "ip": 1,
        "port": 1,
        "technology": 1,
        "web_app": 1,
    }
    assert "observed_host" not in report["assets"]

    # the projected graph is in all three formats
    surface = report["attack_surface"]
    assert surface["available"] is True
    assert surface["graph"]["node_count"] == 5
    assert "## Attack Surface" in markdown
    assert surface["run_id"] in markdown
    assert "Attack Surface" in html

    # ...and the truth-label sections are still separate and correctly labelled
    assert report["hypotheses"] == []
    assert report["validated_findings"] == []
    assert surface["inferences"]["count"] == 0


def test_served_report_keeps_the_review_promotion_boundary(served, store, program):
    """Only operator approval may put an item in ``validated_findings``."""
    from database.models.entities import Hypothesis

    run = _new_run(store, program)
    _execute(store, run, _full_observations())
    store.insert_hypothesis(
        Hypothesis(
            run_id=run.id,
            statement="possible exposure on /admin",
            truth_label="HYPOTHESIS",
            confidence=0.4,
            severity="high",
            priority="high",
            target=TARGET,
            validation_step="observe only",
        )
    )

    with served() as client:
        before = client.get(f"/api/v1/runs/{run.id}/reports/json", headers=_auth()).json()
        assert len(before["hypotheses"]) == 1
        assert before["hypotheses"][0]["truth_label"] == "HYPOTHESIS"
        assert before["validated_findings"] == []

        hypothesis_id = before["hypotheses"][0]["id"]
        approved = client.post(
            f"/api/v1/runs/{run.id}/hypotheses/{hypothesis_id}/approve", headers=_auth()
        )
        assert approved.status_code == 200, approved.text
        after = client.get(f"/api/v1/runs/{run.id}/reports/json", headers=_auth()).json()

    assert after["hypotheses"] == []
    assert len(after["validated_findings"]) == 1
    assert after["validated_findings"][0]["truth_label"] == "VALIDATED_FINDING"


def test_served_report_for_an_empty_run_is_honest(served, store, program):
    run = _new_run(store, program)
    with served() as client:
        report = client.get(f"/api/v1/runs/{run.id}/reports/json", headers=_auth()).json()
    assert report["assets"] == {}
    assert report["evidence_count"] == 0
    assert report["attack_surface"]["available"] is True
    assert report["attack_surface"]["records"]["count"] == 0


def test_served_report_never_leaks_the_database_url(served, store, program, database_url):
    run = _new_run(store, program)
    _execute(store, run, _full_observations())
    with served() as client:
        for fmt in ("json", "markdown", "html"):
            text = client.get(f"/api/v1/runs/{run.id}/reports/{fmt}", headers=_auth()).text
            assert database_url not in text
            assert "postgresql://" not in text


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _row_counts(store) -> dict[str, int]:
    names = [
        "assets", "ips", "asset_ips", "ports", "web_apps", "technologies",
        "asset_technologies", "dns_records", "evidence", "tool_runs", "tasks",
        "runs", "hypotheses",
    ]
    return {
        name: store.conn.execute(f"SELECT count(*) AS n FROM {name}").fetchone()["n"]
        for name in names
    }
