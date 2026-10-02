"""Phase 16 LIVE: the analysis hook over real persisted PostgreSQL facts.

The fake-storage suite (``tests/test_phase16.py``) proves the hook's logic without a database.
It cannot see the things most likely to be wrong in practice:

* whether the ``ai_analysis`` JSONB round-trips the Common Output Contract intact;
* whether ``ai_analysis`` and ``hypotheses`` really do commit or roll back *together*;
* whether ``_severity_for`` produces values the ``hypotheses.severity`` CHECK accepts;
* whether every cited ``evidence_id`` resolves to a row in *this* database;
* whether the Phase 15 projection really feeds the agents end to end.

So this module drives the production chain -- real Phase 14 ingestion -> real
``Repositories.attack_surface`` -> real ``AnalysisHook`` -> real rows -- with no substitutes.

Follows ``tests/test_projection_live.py`` conventions: hard-reset ``public`` per test and a
committed, migrated schema, because the served path opens its own connection.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg.rows import dict_row

from ai.loop import AnalysisHook, build_analysis_hook, context_ref
from core.config import Config
from core.scope_guard import ScopeGuard
from database.migrate import apply
from database.models.entities import Run, ScopeRule as ScopeRuleEntity, Task, ToolRun
from database.repositories.all import Repositories
from recon.dns.resolver import IpObservation
from recon.ingest import plan_ingestion
from recon.web.httpx_probe import AssetTechnologyObservation, WebAppObservation

TARGET = "example.com"
RESOLVED = "93.184.216.34"
SCOPE_DICT = {"scope": {"allowed_domains": [TARGET], "allowed_ips": [RESOLVED]}}
REGISTRY = ("dns", "resolve", "dns_resolve", "httpx", "web_probe", "http_probe")


def _scope() -> ScopeGuard:
    from core.config import ScopeConfig

    return ScopeGuard.from_config(
        ScopeConfig(allowed_domains=(TARGET,), allowed_ips=(f"{RESOLVED}/32",))
    )


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def schema(database_url: str):
    """A committed, migrated schema other connections can see. See test_projection_live."""
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
    org = store.organizations.upsert("Phase 16 Org")
    program_id = store.programs.upsert(org["id"], "Phase 16 Program")["id"]
    for rule_type, value in (("domain", TARGET), ("ip", RESOLVED)):
        store.scope_rules.upsert(
            ScopeRuleEntity(
                program_id=program_id, rule_type=rule_type, value=value, allowed=True
            )
        )
    return program_id


def _new_run(store, program: UUID) -> Run:
    return store.create_run(
        Run(
            program_id=program,
            status="ANALYZING",
            target=TARGET,
            configuration_snapshot=dict(SCOPE_DICT),
        )
    )


def _execute(store, run: Run, artifacts, *, source="dns") -> ToolRun:
    task = Task(id=uuid4(), run_id=run.id, type=source, target=TARGET, status="completed")
    store.insert_tasks([task])
    tool_run = store.insert_tool_run(
        ToolRun(
            task_id=task.id,
            tool_name=source,
            command=[source, "-d", TARGET],
            exit_code=0,
            raw_output_ref=f"raw/{uuid4().hex[:8]}.out",
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
            plan, tool_run_id=tool_run.id, raw_output_ref=tool_run.raw_output_ref,
            program_id=run.program_id,
        )
    return tool_run


def _facts(store, run: Run) -> ToolRun:
    """The Phase 14 fact set that produces real evidence rows for the projection to read."""
    return _execute(
        store,
        run,
        [
            IpObservation(address=RESOLVED, record_type="A"),
            WebAppObservation(
                host=TARGET, url="https://example.com", scheme="https", port=443,
                status_code=200, title="Example Domain", webserver="nginx",
            ),
            AssetTechnologyObservation(host=TARGET, technology="nginx"),
        ],
    )


def _hook(store, registry=REGISTRY, **kw) -> AnalysisHook:
    return build_analysis_hook(store, registry, **kw)


def _norm(rows):
    return sorted((a.agent_name, json.dumps(a.output, sort_keys=True, default=str)) for a in rows)


# ---------------------------------------------------------------------------
# the ai_analysis row is really persisted
# ---------------------------------------------------------------------------


def test_a_run_with_real_facts_produces_an_ai_analysis_row(store, program):
    run = _new_run(store, program)
    _facts(store, run)

    _hook(store)(run, [])

    assert {a.agent_name for a in store.list_ai_analysis()} == {
        "recon_agent",
        "hypothesis_agent",
    }


def test_the_contract_output_survives_the_jsonb_round_trip(store, program):
    run = _new_run(store, program)
    _facts(store, run)

    _hook(store)(run, [])

    recon = next(a for a in store.list_ai_analysis() if a.agent_name == "recon_agent")
    for field in (
        "type", "target", "observation", "reasoning", "potential_issue",
        "evidence", "confidence", "priority", "truth_label", "validation_step",
    ):
        assert field in recon.output, field
    assert recon.output["evidence"], "the contract requires cited evidence"


def test_the_analysis_row_is_attributable_to_its_run(store, program):
    run = _new_run(store, program)
    _facts(store, run)

    _hook(store)(run, [])

    assert {a.input_context_ref for a in store.list_ai_analysis()} == {context_ref(run.id)}


def test_two_runs_do_not_share_analysis_rows(store, program):
    first, second = _new_run(store, program), _new_run(store, program)
    _facts(store, first)
    _facts(store, second)

    hook = _hook(store)
    hook(first, [])
    hook(second, [])

    refs = {a.input_context_ref for a in store.list_ai_analysis()}
    assert refs == {context_ref(first.id), context_ref(second.id)}


def test_every_cited_evidence_id_resolves_to_a_real_row(store, program):
    """The provenance claim is only true if the cited ids point at this database's evidence.

    The Common Output Contract names the citation field ``source``; the hook fills it with the
    Phase 15 projection's ``evidence_id``, so this asserts the UUIDs really resolve.
    """
    run = _new_run(store, program)
    _facts(store, run)

    _hook(store)(run, [])

    # The cited ids survive the JSONB round-trip as strings; normalise both sides.
    known = {str(e.id) for e in store.list_evidence(run.id)}
    assert known, "the fixture must have produced real evidence"

    cited = [
        item["source"]
        for a in store.list_ai_analysis()
        for item in a.output["evidence"]
        if item.get("source")
    ]
    assert cited, "the agents must have cited evidence"
    for evidence_id in cited:
        assert evidence_id in known, evidence_id


# ---------------------------------------------------------------------------
# hypotheses
# ---------------------------------------------------------------------------


def test_a_hypothesis_proposal_becomes_an_unreviewed_hypothesis_row(store, program):
    run = _new_run(store, program)
    _facts(store, run)

    _hook(store)(run, [])

    rows = store.list_hypotheses(run.id)
    assert len(rows) == 1
    assert rows[0].status == "open"
    assert rows[0].review_status == "pending"


def test_the_severity_mapping_satisfies_the_database_constraint(store, program):
    """If _severity_for emitted anything outside low|medium|high, this INSERT would fail."""
    run = _new_run(store, program)
    _facts(store, run)

    _hook(store)(run, [])

    assert {h.severity for h in store.list_hypotheses(run.id)} <= {"low", "medium", "high"}


def test_the_hook_never_claims_a_validated_finding(store, program):
    """Promotion to a finding is ``Orchestrator.approve_hypothesis``, after operator review.

    Nothing the hook writes may assert that on its own authority.
    """
    run = _new_run(store, program)
    _facts(store, run)

    _hook(store)(run, [])

    for row in store.list_ai_analysis():
        assert row.output["truth_label"] != "VALIDATED_FINDING"
    for hypothesis in store.list_hypotheses(run.id):
        assert hypothesis.truth_label != "VALIDATED_FINDING"
        assert hypothesis.review_status == "pending"


def test_a_run_with_no_facts_creates_no_hypothesis(store, program):
    run = _new_run(store, program)

    _hook(store)(run, [])

    assert store.list_hypotheses(run.id) == []


# ---------------------------------------------------------------------------
# atomicity -- the property a fake storage can only pretend to have
# ---------------------------------------------------------------------------


def test_a_hypothesis_failure_rolls_back_its_own_analysis_row(store, program, monkeypatch):
    """Atomicity is per invocation: an agent's audit row and its hypothesis commit together.

    The ``hypothesis_agent`` row must vanish with the hypothesis it describes. The
    ``recon_agent`` row is a *different* proposal with no hypothesis to write, so it commits on
    its own -- two independent transactions, each internally atomic. Asserting the whole table
    was empty would be asserting a stronger property than the design claims.
    """
    run = _new_run(store, program)
    _facts(store, run)

    def boom(hypothesis):
        raise RuntimeError("simulated hypothesis write failure")

    monkeypatch.setattr(type(store.hypotheses), "insert", boom)
    _hook(store)(run, [])

    assert store.list_hypotheses(run.id) == []
    assert [a.agent_name for a in store.list_ai_analysis()] == ["recon_agent"]


def test_a_connection_error_is_swallowed_and_the_run_still_works(store, program, monkeypatch):
    """A broken intelligence layer must never be able to fail a run."""
    run = _new_run(store, program)
    _facts(store, run)

    def boom(*args, **kw):
        raise psycopg.OperationalError("connection lost")

    monkeypatch.setattr(type(store), "insert_ai_analysis", boom)
    tasks = _hook(store)(run, [])

    assert isinstance(tasks, list)
    assert store.list_ai_analysis() == []


# ---------------------------------------------------------------------------
# the capability gate, against a real projection
# ---------------------------------------------------------------------------


def test_an_empty_registry_proposes_nothing(store, program):
    run = _new_run(store, program)
    _facts(store, run)

    assert _hook(store, registry=())(run, []) == []


def test_only_registry_backed_task_types_are_proposed(store, program):
    run = _new_run(store, program)
    _facts(store, run)

    tasks = _hook(store)(run, [])

    assert tasks
    assert all(t.type in REGISTRY for t in tasks)


def test_the_proposed_task_is_dispatchable_and_in_scope(store, program):
    """What the hook proposes must survive the same guards any operator task would."""
    from api.serve import ServedExecution
    from core.tool_runner import ToolRunner

    run = _new_run(store, program)
    _facts(store, run)

    tasks = _hook(store)(run, [])
    assert len(tasks) == 1

    task = tasks[0]
    assert task.run_id == run.id
    assert task.type == "dns_resolve"
    assert task.target == TARGET
    assert task.status == "pending"

    execution = ServedExecution(adapters={t.type: None for t in tasks}, runner=ToolRunner())
    assert execution.adapter_for is not None
    assert task.type in execution.known_task_types()


def test_a_covered_run_proposes_no_task(store, program):
    run = _new_run(store, program)
    _facts(store, run)

    done = [
        Task(id=uuid4(), run_id=run.id, type=t, target=TARGET, status="completed")
        for t in ("dns", "resolve", "dns_resolve", "httpx", "web_probe", "http_probe")
    ]

    assert _hook(store)(run, done) == []


# ---------------------------------------------------------------------------
# the Phase 15 -> Phase 16 bridge
# ---------------------------------------------------------------------------


def test_the_hook_really_reads_the_phase15_projection(store, program):
    run = _new_run(store, program)
    _facts(store, run)

    surface = store.attack_surface(run.id)
    assert surface["available"] is True
    assert surface["graph"]["node_count"] >= 4

    hook = _hook(store)
    hook(run, [])
    assert {o.agent_name for o in hook.last_result.outcomes} == {
        "recon_agent",
        "hypothesis_agent",
    }


def test_two_identical_passes_produce_identical_content(store, program):
    """Same persisted facts, same agent pass -> byte-identical contract output.

    Row ids and ``created_at`` are server-generated and excluded, as documented: Phase 14
    already established that ids are never trusted from tool output, and the same applies to
    agent proposals. What must be reproducible is the *content*.
    """
    run = _new_run(store, program)
    _facts(store, run)

    hook = _hook(store)
    hook(run, [])
    first = _norm(store.list_ai_analysis())
    seen = {a.id for a in store.list_ai_analysis()}

    hook(run, [])
    second = _norm([a for a in store.list_ai_analysis() if a.id not in seen])

    assert first == second


# ---------------------------------------------------------------------------
# the served composition, with the flag on, over real data
# ---------------------------------------------------------------------------


@pytest.fixture
def served(database_url: str, schema, tmp_path: Path):
    def factory(enabled: bool):
        from api.serve import create_serve_app

        config = Config.from_dict(
            {
                "database": {"url": database_url},
                "storage": {"raw_root": str(tmp_path / "raw")},
                "ai": {"enabled": enabled, "mode": "local"},
            }
        )
        return create_serve_app(
            api_key="phase16-key", database_url=database_url, config=config
        )

    return factory


def test_the_served_app_wires_the_hook_only_when_enabled(served):
    assert served(False).state.argus_orchestrator.analysis is None
    assert isinstance(served(True).state.argus_orchestrator.analysis, AnalysisHook)


def test_the_served_hook_is_gated_on_its_own_adapter_registry(served):
    app = served(True)
    assert app.state.argus_orchestrator.analysis.runnable == frozenset(
        app.state.argus_execution.known_task_types()
    )


def test_the_served_app_persists_analysis_for_a_real_run(database_url, store, program, served):
    """The full chain, through the served composition rather than a hand-wired hook."""
    run = _new_run(store, program)
    _facts(store, run)

    app = served(True)
    hook = app.state.argus_orchestrator.analysis
    tasks = hook(run, [])

    assert tasks
    assert {a.input_context_ref for a in store.list_ai_analysis()} == {context_ref(run.id)}
    assert len(store.list_hypotheses(run.id)) == 1
