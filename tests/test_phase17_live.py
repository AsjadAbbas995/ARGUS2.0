"""Phase 17 LIVE: run-scoped AI analysis over real PostgreSQL, and the production composition.

Gated on ``ARGUS_TEST_DATABASE_URL`` (see ``tests/conftest.py``). Follows the
``tests/test_phase16_live.py`` / ``tests/test_projection_live.py`` conventions: hard-reset of
``public`` per test, a committed migrated schema, and independent read-only connections for the
verifications.

``tests/test_phase17.py`` proves the contract without a database. It cannot see the things most
likely to be wrong in practice, which is what this module covers:

* whether migration ``0005`` really is upgrade-safe on a **populated** legacy table -- legacy rows
  surviving, attributable rows attributed, and an unattributable row left honestly NULL rather
  than guessed at;
* whether ``run_id`` is a real foreign key and a real index, not just a matching value;
* whether ``list_ai_analysis(run_id)`` isolates two runs over real rows;
* whether the served route and the three report renderers carry a real run's rows and no other
  run's;
* and the acceptance proof Phase 17 exists for -- that ``create_serve_app`` really wires a
  functional ``AnalysisHook`` over real PostgreSQL, so ``analysis=...`` being dropped from the
  composition fails a test rather than silently disabling the intelligence layer.

CONTROLLED TARGET ONLY
    The composition test's target is a ``ThreadingHTTPServer`` the test itself starts on
    ``127.0.0.1`` with an ephemeral port, resolved through the loopback names. No public or
    third-party host is contacted at any point.

ENVIRONMENT-UNVERIFIED (stated, not hidden)
    * The ``httpx`` binary is not installed on this machine, so the default
      ``HttpxProbeAdapter`` cannot run. The web-app artifact comes from a real ``ToolAdapter``
      that performs a genuine HTTP request through the real ``ToolRunner`` subprocess boundary.
      The ``httpx`` *binary* path remains unverified, exactly as in Phase 14.
    * dnspython cannot resolve ``localhost`` (it never consults the hosts file), so DNS goes
      through the adapter's documented ``resolver_fn`` seam backed by ``socket.getaddrinfo`` --
      a real local resolver call, not a fixture.
"""

from __future__ import annotations

import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from starlette.testclient import TestClient

from ai.loop import ANALYSIS_PROPOSED, AnalysisHook, build_analysis_hook, context_ref
from api.serve import create_serve_app
from core.config import Config
from core.scope_guard import ScopeGuard, extract_host
from core.tool_runner import CommandResult, ToolRunner
from database.migrate import apply, revert
from database.models.entities import AiAnalysis, Run, ScopeRule as ScopeRuleEntity, Task, ToolRun
from database.repositories.all import Repositories
from recon.base import ToolAdapter
from recon.dns.resolver import IpObservation
from recon.ingest import plan_ingestion
from recon.web.httpx_probe import WebAppObservation

TARGET = "example.com"
RESOLVED = "93.184.216.34"
SCOPE_DICT = {"scope": {"allowed_domains": [TARGET], "allowed_ips": [RESOLVED]}}
REGISTRY = ("dns", "resolve", "dns_resolve", "httpx", "web_probe", "http_probe")

LOOPBACK = "127.0.0.1"
HOSTNAME = "localhost"
API_KEY = "phase17-key"


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def schema(database_url: str):
    """A committed, migrated schema other connections can see."""
    with psycopg.connect(database_url, row_factory=dict_row, autocommit=True) as conn:
        conn.execute("DROP SCHEMA public CASCADE")
        conn.execute("CREATE SCHEMA public")
        apply(conn)
        yield conn
        conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
        conn.execute("CREATE SCHEMA public")


@pytest.fixture
def store(schema):
    return Repositories(schema)


@pytest.fixture
def program(store) -> UUID:
    org = store.organizations.upsert("Phase 17 Org")
    program_id = store.programs.upsert(org["id"], "Phase 17 Program")["id"]
    for rule_type, value in (("domain", TARGET), ("ip", RESOLVED)):
        store.scope_rules.upsert(
            ScopeRuleEntity(
                program_id=program_id, rule_type=rule_type, value=value, allowed=True
            )
        )
    return program_id


def _scope() -> ScopeGuard:
    from core.config import ScopeConfig

    return ScopeGuard.from_config(
        ScopeConfig(allowed_domains=(TARGET,), allowed_ips=(f"{RESOLVED}/32",))
    )


def _new_run(store, program: UUID) -> Run:
    return store.create_run(
        Run(
            program_id=program,
            status="ANALYZING",
            target=TARGET,
            configuration_snapshot=dict(SCOPE_DICT),
        )
    )


def _facts(store, run: Run) -> ToolRun:
    """The Phase 14 fact set that produces real evidence rows for the projection to read."""
    task = Task(id=uuid4(), run_id=run.id, type="dns", target=TARGET, status="completed")
    store.insert_tasks([task])
    tool_run = store.insert_tool_run(
        ToolRun(
            task_id=task.id,
            tool_name="dns",
            command=["dns", "-d", TARGET],
            exit_code=0,
            raw_output_ref=f"raw/{uuid4().hex[:8]}.out",
        )
    )
    plan = plan_ingestion(
        [
            IpObservation(address=RESOLVED, record_type="A"),
            WebAppObservation(
                host=TARGET, url="https://example.com", scheme="https", port=443,
                status_code=200, title="Example Domain", webserver="nginx",
            ),
        ],
        scope=_scope(),
        source="dns",
        target_host=TARGET,
        max_artifacts=1000,
    )
    with store.transaction():
        store.ingest_observations(
            plan, tool_run_id=tool_run.id, raw_output_ref=tool_run.raw_output_ref,
            program_id=run.program_id,
        )
    return tool_run


# ---------------------------------------------------------------------------
# migration 0005: the shape it produces
# ---------------------------------------------------------------------------


def _columns(conn) -> set[str]:
    rows = conn.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = 'ai_analysis'"
    ).fetchall()
    return {r["column_name"] for r in rows}


def test_0005_gives_ai_analysis_a_run_id(schema):
    assert "run_id" in _columns(schema)


def test_run_id_is_a_real_foreign_key_to_runs(schema):
    fks = schema.execute(
        "SELECT tc.constraint_name, ccu.table_name AS target "
        "FROM information_schema.table_constraints tc "
        "JOIN information_schema.constraint_column_usage ccu "
        "  ON ccu.constraint_name = tc.constraint_name "
        "WHERE tc.table_name = 'ai_analysis' AND tc.constraint_type = 'FOREIGN KEY'"
    ).fetchall()
    assert any(fk["target"] == "runs" for fk in fks), fks


def test_a_real_index_covers_run_scoped_reads(schema):
    indexes = schema.execute(
        "SELECT indexdef FROM pg_indexes WHERE tablename = 'ai_analysis'"
    ).fetchall()
    assert any("(run_id)" in str(i["indexdef"]) for i in indexes), indexes


def test_a_fresh_install_fully_enforces_the_required_constraint(schema):
    """An empty table has nothing to exempt, so the constraint validates immediately."""
    row = schema.execute(
        "SELECT convalidated FROM pg_constraint WHERE conname = "
        "'ai_analysis_run_id_required_check'"
    ).fetchone()
    assert row is not None
    assert row["convalidated"] is True


# ---------------------------------------------------------------------------
# migration 0005: upgrade safety on a populated legacy table
# ---------------------------------------------------------------------------


def _insert_legacy_row(conn, agent: str, ref: str | None) -> None:
    """Insert an ``ai_analysis`` row using only the *pre-0005* column set.

    The Phase 17 repository always writes ``run_id``, so it cannot populate a table that ``revert``
    has just rolled back to the Phase 16 shape -- attempting to raises ``UndefinedColumn``. Raw SQL
    over exactly the Phase 16 columns keeps this faithful to the real legacy table, and stays valid
    once 0005 is re-applied.
    """
    conn.execute(
        "INSERT INTO ai_analysis (agent_name, model_used, input_context_ref, output) "
        "VALUES (%s, %s, %s, %s)",
        (
            agent,
            "argus-rule-based (route mode=hybrid)",
            ref,
            Jsonb({"type": "legacy", "statement": agent}),
        ),
    )


@pytest.fixture
def legacy(store, program):
    """A populated ``ai_analysis`` table in its *pre-0005* shape, via the real revert.

    Reverting to version 4 runs ``0005_ai_analysis_run_scope.down.sql`` for real, so the rows
    inserted here are inserted into the genuine Phase 16 schema -- with no ``run_id`` column and
    therefore none of the Phase 17 constraint -- rather than into a hand-built imitation.
    """
    conn = store.conn
    revert(conn, target_version=4)
    assert "run_id" not in _columns(conn)
    run = _new_run(store, program)
    missing_run = uuid4()
    rows = {
        "attributable": f"run:{run.id}",
        "non_canonical": "run:not-a-uuid",
        "missing_run": f"run:{missing_run}",
        "no_ref": None,
        "other_shape": f"ctx:{run.id}",
    }
    for agent, ref in rows.items():
        _insert_legacy_row(conn, agent, ref)
    return run


def test_legacy_rows_survive_the_upgrade_and_are_attributed(schema, store, legacy):
    apply(schema)
    assert "run_id" in _columns(schema)
    agents = {a.agent_name for a in store.list_ai_analysis()}
    assert agents == {
        "attributable", "non_canonical", "missing_run", "no_ref", "other_shape",
    }


def test_only_a_canonical_reference_to_a_real_run_is_attributed(schema, store, legacy):
    apply(schema)
    by_agent = {a.agent_name: a for a in store.list_ai_analysis()}
    assert by_agent["attributable"].run_id == legacy.id
    # Everything else stays honestly un-attributed rather than being guessed at.
    for agent in ("non_canonical", "missing_run", "no_ref", "other_shape"):
        assert by_agent[agent].run_id is None, agent


def test_an_upgraded_table_with_unattributable_rows_keeps_the_constraint_unvalidated(
    schema, store, legacy
):
    apply(schema)
    row = schema.execute(
        "SELECT convalidated FROM pg_constraint WHERE conname = "
        "'ai_analysis_run_id_required_check'"
    ).fetchone()
    # NOT VALID is the honest state: the legacy row cannot be validated away, and pretending
    # otherwise would be a false claim about the data.
    assert row["convalidated"] is False


def test_the_constraint_still_rejects_a_new_write_without_a_run(schema, store, legacy):
    apply(schema)
    with pytest.raises(psycopg.Error):
        store.ai_analysis.insert(
            AiAnalysis(agent_name="new", output={"type": "x"}, input_context_ref="run:none")
        )


def test_a_new_write_with_a_run_succeeds_on_an_upgraded_table(schema, store, legacy):
    apply(schema)
    row = store.ai_analysis.insert(
        AiAnalysis(
            run_id=legacy.id,
            agent_name="new",
            model_used="argus-rule-based",
            input_context_ref=context_ref(legacy.id),
            output={"type": "x", "statement": "s"},
        )
    )
    assert row["run_id"] == legacy.id


def test_a_run_id_that_is_not_a_run_is_rejected_by_the_foreign_key(schema, store, program):
    """The relationship is enforced by the database, not by a convention in Python."""
    with pytest.raises(psycopg.Error):
        store.ai_analysis.insert(
            AiAnalysis(
                run_id=uuid4(),
                agent_name="orphan",
                model_used="m",
                input_context_ref="run:x",
                output={"type": "x"},
            )
        )


def test_0005_reverts_and_can_be_reapplied(schema, store, legacy):
    revert(schema, target_version=4)
    assert "run_id" not in _columns(schema)
    assert {a.agent_name for a in store.list_ai_analysis()} == {
        "attributable", "non_canonical", "missing_run", "no_ref", "other_shape",
    }
    assert apply(schema) == [5]
    assert "run_id" in _columns(schema)


# ---------------------------------------------------------------------------
# run scoping over real rows
# ---------------------------------------------------------------------------


def _insert(store, run, agent: str) -> AiAnalysis:
    return store.insert_ai_analysis(
        AiAnalysis(
            run_id=run.id,
            agent_name=agent,
            model_used="argus-rule-based (route mode=hybrid)",
            input_context_ref=context_ref(run.id),
            output={"type": "recon_stage_proposal", "statement": agent, "truth_label": "INFERENCE"},
        )
    )


def test_the_repository_returns_only_the_requested_runs_rows(store, program):
    first = _new_run(store, program)
    second = _new_run(store, program)
    _insert(store, first, "recon_agent")
    _insert(store, first, "hypothesis_agent")
    _insert(store, second, "recon_agent")

    assert {a.agent_name for a in store.list_ai_analysis(first.id)} == {
        "recon_agent", "hypothesis_agent",
    }
    assert [a.agent_name for a in store.list_ai_analysis(second.id)] == ["recon_agent"]


def test_a_run_with_no_analysis_returns_nothing_rather_than_everything(store, program):
    first = _new_run(store, program)
    second = _new_run(store, program)
    _insert(store, first, "recon_agent")
    assert store.list_ai_analysis(second.id) == []


def test_the_unattributed_audit_read_still_sees_everything(store, program, schema):
    """The migration/backfill path needs the unfiltered view, including unattributed rows."""
    revert(store.conn, target_version=4)
    run = _new_run(store, program)
    _insert_legacy_row(store.conn, "legacy", None)
    apply(schema)
    assert {a.agent_name for a in store.list_ai_analysis()} == {"legacy"}
    assert store.list_ai_analysis(run.id) == []


def test_the_repository_read_is_ordered_deterministically(store, program):
    run = _new_run(store, program)
    for agent in ("c_agent", "a_agent", "b_agent"):
        _insert(store, run, agent)
    reads = [
        [a.agent_name for a in store.list_ai_analysis(run.id)] for _ in range(3)
    ]
    assert reads[0] == reads[1] == reads[2]
    assert len(reads[0]) == 3


# ---------------------------------------------------------------------------
# the hook writes the real run id
# ---------------------------------------------------------------------------


def test_the_hook_persists_the_real_run_id(store, program):
    run = _new_run(store, program)
    _facts(store, run)
    hook = build_analysis_hook(store, REGISTRY)
    hook(run, [])
    assert hook.last_result.status == ANALYSIS_PROPOSED, hook.last_result
    rows = store.list_ai_analysis(run.id)
    assert rows, "the hook produced no analysis to attribute"
    assert all(a.run_id == run.id for a in rows)
    # input_context_ref is still written: it is the context label, not the run filter.
    assert {a.input_context_ref for a in rows} == {context_ref(run.id)}


def test_two_runs_analysis_stays_isolated(store, program):
    first = _new_run(store, program)
    second = _new_run(store, program)
    hook = build_analysis_hook(store, REGISTRY)
    _facts(store, first)
    hook(first, [])
    # The second run has no facts, so it proposes nothing and must not inherit the first's rows.
    hook(second, [])
    assert {a.run_id for a in store.list_ai_analysis(second.id)} <= {None}
    assert store.list_ai_analysis(second.id) == []
    assert store.list_ai_analysis(first.id)


def test_an_analysis_row_survives_a_json_round_trip_intact(store, program):
    run = _new_run(store, program)
    row = _insert(store, run, "recon_agent")
    reloaded = next(a for a in store.list_ai_analysis(run.id) if a.id == row.id)
    assert reloaded.run_id == run.id
    assert reloaded.output["type"] == "recon_stage_proposal"
    assert reloaded.output["statement"] == "recon_agent"
    assert reloaded.model_used == "argus-rule-based (route mode=hybrid)"


# ---------------------------------------------------------------------------
# the served route over real rows
# ---------------------------------------------------------------------------


def _app(store, **kw):
    from api.server import create_app
    from core.orchestrator import Orchestrator

    def _run_tool(task):
        return ToolRun(
            task_id=task.id, tool_name=task.type,
            command=["argus", task.type, task.target],
            exit_code=0, raw_output_ref="raw/out.txt",
        )

    return create_app(Orchestrator(storage=store, run_tool=_run_tool), api_key=API_KEY, **kw)


def _auth():
    return {"Authorization": f"Bearer {API_KEY}"}


def test_the_served_route_requires_authentication(store, program):
    run = _new_run(store, program)
    with TestClient(_app(store)) as client:
        assert client.get(f"/api/v1/runs/{run.id}/ai-analysis").status_code == 401


def test_the_served_route_404s_an_unknown_run(store):
    with TestClient(_app(store)) as client:
        assert client.get(f"/api/v1/runs/{uuid4()}/ai-analysis", headers=_auth()).status_code == 404


def test_the_served_route_returns_only_this_runs_real_rows(store, program):
    first = _new_run(store, program)
    second = _new_run(store, program)
    _insert(store, first, "recon_agent")
    _insert(store, second, "hypothesis_agent")
    with TestClient(_app(store)) as client:
        body = client.get(f"/api/v1/runs/{first.id}/ai-analysis", headers=_auth()).json()
    assert body["count"] == 1
    assert body["ai_analysis"][0]["agent_name"] == "recon_agent"
    assert body["ai_analysis"][0]["run_id"] == str(first.id)


@pytest.mark.parametrize("fmt", ["json", "markdown", "html"])
def test_the_served_report_carries_only_this_runs_analysis(store, program, fmt):
    first = _new_run(store, program)
    second = _new_run(store, program)
    _insert(store, first, "recon_agent")
    _insert(store, second, "hypothesis_agent")
    with TestClient(_app(store)) as client:
        response = client.get(f"/api/v1/runs/{first.id}/reports/{fmt}", headers=_auth())
    assert response.status_code == 200, response.text
    assert "recon_agent" in response.text
    assert "hypothesis_agent" not in response.text


# ---------------------------------------------------------------------------
# production composition: create_serve_app over real PostgreSQL
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        type(self).hits.append(self.path)
        body = b"<html><head><title>argus-phase17</title></head><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def version_string(self) -> str:
        return "argus-phase17-controlled"

    def log_message(self, *args) -> None:
        return


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
        return f"http://{HOSTNAME}:{self.port}/probe"

    @property
    def hits(self) -> list[str]:
        return list(_Handler.hits)

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


def _local_resolver(hostname: str, record_type: str):
    if record_type not in ("A", "AAAA"):
        return (), "NOANSWER"
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return (), "NXDOMAIN"
    want = socket.AF_INET if record_type == "A" else socket.AF_INET6
    values = [info[4][0] for info in infos if info[0] == want]
    return tuple(dict.fromkeys(values)), (None if values else "NOANSWER")


_PROBE_SCRIPT = r"""
import json, sys, urllib.request
url = sys.argv[1]
with urllib.request.urlopen(url, timeout=10) as r:
    body = r.read().decode("utf-8", "replace")
    title = ""
    low = body.lower()
    if "<title>" in low:
        start = low.index("<title>") + 7
        end = low.index("</title>", start)
        title = body[start:end].strip()
    print(json.dumps({
        "status_code": r.status,
        "title": title,
        "server_header": r.headers.get("Server", ""),
        "url": url,
    }))
"""


class ControlledHttpProbeAdapter(ToolAdapter):
    name = "controlled_http_probe"
    executables = ()

    def __init__(self) -> None:
        self.invocations: list[list[str]] = []

    def is_available(self) -> bool:
        return Path(sys.executable).is_file()

    def validate(self, task, scope: ScopeGuard) -> None:
        self._require_in_scope(task.target, scope)

    def build_command(self, task, config) -> list[str]:
        command = [sys.executable, "-I", "-c", _PROBE_SCRIPT, task.target]
        self.invocations.append(command)
        return command

    def parse(self, result: CommandResult) -> list[object]:
        import json as _json

        for line in reversed(result.stdout.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                data = _json.loads(line)
            except ValueError:
                continue
            url = data.get("url", "")
            port = int(url.rsplit(":", 1)[-1].split("/")[0]) if ":" in url else 0
            return [
                WebAppObservation(
                    host=extract_host(url),
                    url=url,
                    scheme=url.split(":", 1)[0] if ":" in url else "http",
                    port=port,
                    status_code=int(data.get("status_code") or 0),
                    title=data.get("title", ""),
                    webserver=data.get("server_header", ""),
                )
            ]
        return []


def _make_program(database_url: str) -> str:
    from database.repositories.base import DatabaseConnection

    connection = DatabaseConnection(database_url)
    repositories = Repositories(connection.connect())
    try:
        org = repositories.organizations.upsert(f"argus-phase17-org-{uuid4().hex}")
        program = repositories.programs.upsert(
            org["id"], f"argus-phase17-program-{uuid4().hex}"
        )
        for rule_type, value in (("domain", HOSTNAME), ("ip", LOOPBACK)):
            repositories.scope_rules.upsert(
                ScopeRuleEntity(
                    program_id=program["id"], rule_type=rule_type, value=value, allowed=True
                )
            )
        return str(program["id"])
    finally:
        connection.close()


def _config(database_url: str, raw_dir: Path, **ai) -> Config:
    return Config.from_dict(
        {
            "database": {"url": database_url},
            "scope": {"allowed_domains": [HOSTNAME], "allowed_ips": [LOOPBACK]},
            "storage": {"raw_dir": str(raw_dir)},
            "ai": {"enabled": True, **ai},
        }
    )


@pytest.fixture
def program_id(database_url: str) -> str:
    return _make_program(database_url)


@pytest.fixture
def probes() -> list[ControlledHttpProbeAdapter]:
    return []


@pytest.fixture
def served(database_url: str, target, probes, tmp_path: Path):
    def factory() -> ControlledHttpProbeAdapter:
        adapter = ControlledHttpProbeAdapter()
        probes.append(adapter)
        return adapter

    app = create_serve_app(
        api_key=API_KEY,
        database_url=database_url,
        config=_config(database_url, tmp_path / "raw"),
        runner=ToolRunner(raw_dir=tmp_path / "raw"),
        resolver_fn=_local_resolver,
        adapters={"http_probe": factory},
    )
    with TestClient(app) as test_client:
        yield test_client


def _create_run(client, program_id: str) -> dict:
    response = client.post(
        "/api/v1/runs",
        json={
            "target": HOSTNAME,
            "program_id": program_id,
            "configuration": {
                "scope": {"allowed_domains": [HOSTNAME], "allowed_ips": [LOOPBACK]}
            },
        },
        headers=_auth(),
    )
    assert response.status_code == 201, response.text
    return response.json()


def _enqueue(client, run_id: str, task_type: str, target_value: str) -> None:
    response = client.post(
        f"/api/v1/runs/{run_id}/tasks",
        json={"tasks": [{"type": task_type, "target": target_value}]},
        headers=_auth(),
    )
    assert response.status_code == 201, response.text


def test_the_served_composition_wires_a_functional_analysis_hook(served):
    """The Phase 17 acceptance proof for composition.

    Asserted on the live orchestrator the app really uses, so dropping ``analysis=...`` from
    ``create_serve_app`` makes this fail rather than silently disabling the intelligence layer.
    """
    orch = served.app.state.argus_orchestrator
    assert isinstance(orch.analysis, AnalysisHook)
    assert served.app.state.argus_analysis_wired is True


def test_the_served_composition_wires_the_configured_loop_budget(served):
    assert served.app.state.argus_orchestrator.max_loop_passes == 32


def test_the_served_composition_wires_a_custom_loop_budget(database_url, target, probes, tmp_path):
    app = create_serve_app(
        api_key=API_KEY,
        database_url=database_url,
        config=_config(database_url, tmp_path / "raw", max_loop_passes=5),
        runner=ToolRunner(raw_dir=tmp_path / "raw"),
        resolver_fn=_local_resolver,
        adapters={"http_probe": lambda: ControlledHttpProbeAdapter()},
    )
    with TestClient(app) as client:
        assert client.app.state.argus_orchestrator.max_loop_passes == 5


def _drive_analysis(served, run_id: str) -> None:
    """Run the analysis pass that the served loop defers to its next iteration.

    A ``/run`` whose only task *creates* the run's first data analyses a projection that is still
    empty from the hook's point of view, so it honestly reports ``ANALYSIS_NO_PROPOSALS``: the
    probe's ingestion has not committed yet. The proposal appears on the following pass, once it
    has. Driving that pass here, through the very hook object the server holds, is what the
    scheduler does on the next run -- and it is the pass that has something to attribute.
    """
    hook = served.app.state.argus_analysis_hook
    store = hook.storage
    hook(store.get_run(UUID(run_id)), store.list_tasks(UUID(run_id)))


def test_a_served_run_persists_analysis_attributed_to_that_run(
    served, target, probes, program_id, database_url
):
    """Served run -> real HTTP probe -> ingestion -> projection -> hook -> real rows.

    Only ``http_probe`` is enqueued, so ``dns_resolve`` stays an uncovered executable stage for the
    agent to propose. Completing every executable stage would leave ``coverage_gaps`` empty and the
    hook would correctly return ``ANALYSIS_NO_PROPOSALS``.
    """
    run = _create_run(served, program_id)
    run_id = run["id"]
    _enqueue(served, run_id, "http_probe", target.url)
    result = served.post(f"/api/v1/runs/{run_id}/run", json={}, headers=_auth())
    assert result.status_code == 200, result.text

    assert probes and probes[0].invocations, "the controlled adapter never ran"
    assert target.hits == ["/probe"], f"the controlled target was not reached: {target.hits}"

    _drive_analysis(served, run_id)
    hook = served.app.state.argus_analysis_hook
    assert hook.last_result.status == ANALYSIS_PROPOSED, hook.last_result

    body = served.get(f"/api/v1/runs/{run_id}/ai-analysis", headers=_auth()).json()
    assert body["count"] >= 1, "the served composition persisted no AI analysis"
    assert all(a["run_id"] == run_id for a in body["ai_analysis"])
    assert body["diagnostics"]["status"] == ANALYSIS_PROPOSED
    assert body["diagnostics"]["wired"] is True

    # ---- verified with an INDEPENDENT read-only connection -----------------
    with psycopg.connect(database_url, row_factory=dict_row) as conn:
        conn.execute("SET TRANSACTION READ ONLY")
        rows = conn.execute(
            "SELECT id, run_id, agent_name, model_used, input_context_ref, output "
            "FROM ai_analysis WHERE run_id = %s ORDER BY created_at, id",
            (run_id,),
        ).fetchall()
        assert rows, "no ai_analysis row for this run in PostgreSQL"
        assert {str(r["run_id"]) for r in rows} == {run_id}
        assert {r["input_context_ref"] for r in rows} == {f"run:{run_id}"}
        # Every run_id really joins back to a real run.
        assert conn.execute(
            "SELECT count(*) AS n FROM ai_analysis a "
            "LEFT JOIN runs r ON r.id = a.run_id "
            "WHERE a.run_id IS NOT NULL AND r.id IS NULL"
        ).fetchone()["n"] == 0


def test_the_served_report_carries_the_served_runs_analysis(
    served, target, probes, program_id
):
    run = _create_run(served, program_id)
    run_id = run["id"]
    # Only http_probe, so dns_resolve stays an uncovered executable stage for the agent to
    # propose and there is analysis to report on.
    _enqueue(served, run_id, "http_probe", target.url)
    served.post(f"/api/v1/runs/{run_id}/run", json={}, headers=_auth())
    _drive_analysis(served, run_id)

    md = served.get(f"/api/v1/runs/{run_id}/reports/markdown", headers=_auth())
    assert md.status_code == 200, md.text
    assert "# AI Analysis" in md.text

    body = served.get(f"/api/v1/runs/{run_id}/reports/json", headers=_auth()).json()
    assert body["ai_analysis"], "the served JSON report has no analysis section"
    assert all(a["run_id"] == run_id for a in body["ai_analysis"])


def test_a_second_served_run_does_not_see_the_first_runs_analysis(
    served, target, probes, program_id
):
    first = _create_run(served, program_id)
    _enqueue(served, first["id"], "http_probe", target.url)
    served.post(f"/api/v1/runs/{first['id']}/run", json={}, headers=_auth())
    _drive_analysis(served, first["id"])
    # Guard the premise: an isolation test over an empty first run would pass for the wrong reason.
    assert served.get(
        f"/api/v1/runs/{first['id']}/ai-analysis", headers=_auth()
    ).json()["count"] >= 1

    second = _create_run(served, program_id)
    body = served.get(f"/api/v1/runs/{second['id']}/ai-analysis", headers=_auth()).json()
    assert body["count"] == 0
    assert body["ai_analysis"] == []
