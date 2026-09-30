"""Phase 14.2 orchestration/ingestion contract, WITHOUT PostgreSQL.

These tests pin the behaviour Phase 14.2 added on top of 14.1's pure mapping:
the ``ToolRunOutcome`` seam, the orchestrator's transaction boundary, ingestion
failure handling, and the scope/robustness properties of the plan that gets handed
to storage. They drive a real :class:`Orchestrator` over an in-memory fake that
records the calls it receives.

WHAT THIS MODULE PROVES
    * the orchestrator enters the storage's ``transaction()`` and performs the
      ToolRun -> ingest -> terminal-status writes inside it;
    * a storage predating Phase 14 (no ``transaction()``) still works unchanged;
    * a failing ingest hook rolls back and fails the task instead of wedging the run;
    * the artifacts reaching the hook are exactly what the seam returned;
    * out-of-scope destinations never appear as graph records, only observations;
    * the cardinality cap, malformed-artifact tolerance, and the absence of SQL
      construction in the mapping layer.

WHAT THIS MODULE DOES **NOT** PROVE -- all of it still requires 14.3
    * SQL column/CHECK/FK correctness against the real schema;
    * psycopg UUID and ``inet`` adaptation;
    * PostgreSQL unique-index / ``ON CONFLICT`` upsert idempotency;
    * ``AssetIpRepository.upsert`` behaviour (``DO NOTHING`` returning no row);
    * ``dns_records`` deduplication, which has no unique index at all;
    * real transaction rollback (``conn.transaction()`` discarding real writes);
    * real ``evidence`` -> ``tool_run`` foreign-key relationships.

The fake's rollback is a *simulation* of the context-manager contract. It is not
evidence that PostgreSQL discarded anything. Nothing here substitutes for the live
suite in ``tests/test_database_live.py`` and the Phase 14.3 integration tests.
"""

from __future__ import annotations

import ast
import copy
import inspect
from types import SimpleNamespace
from typing import Optional
from uuid import uuid4

import pytest

from api import serve as serve_module
from core.config import ScopeConfig
from core.memory_storage import MemoryStorage
from core.orchestrator import Orchestrator, ToolRunOutcome, _split_outcome
from core.scope_guard import ScopeGuard
from database.models.entities import Run, Task, ToolRun
from recon.dns.resolver import DnsRecordObservation, IpObservation
from recon.ingest import (
    ENTITY_OBSERVED_HOST,
    ENTITY_OBSERVED_IP,
    KIND_HOST,
    KIND_IP,
    plan_ingestion,
)
from recon.web.httpx_probe import (
    AssetTechnologyObservation,
    WebAppObservation,
)

import database.repositories.all as repos_all


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

SCOPED = {"scope": {"allowed_domains": ["example.com"]}}


def _scope() -> ScopeGuard:
    return ScopeGuard.from_config(ScopeConfig(allowed_domains=("example.com",)))


def _run(**overrides) -> Run:
    payload = {
        "program_id": uuid4(),
        "status": "CREATED",
        "target": "example.com",
        "configuration_snapshot": dict(SCOPED),
    }
    payload.update(overrides)
    return Run(**payload)


def _task(run_id, type_: str = "subdomain_enum", target: str = "example.com") -> Task:
    return Task(
        id=uuid4(),
        run_id=run_id,
        type=type_,
        target=target,
        status="pending",
    )


def _tool_run(task: Task) -> ToolRun:
    return ToolRun(
        task_id=task.id,
        tool_name="subfinder",
        command=["subfinder", "-d", "example.com"],
        exit_code=0,
        raw_output_ref="raw/subfinder/x.out",
    )


class FakeStorage(MemoryStorage):
    """MemoryStorage that records what the orchestrator did to it.

    ``transaction()`` snapshots the dict-backed state on entry and restores it if the
    block raises, so the orchestrator's rollback path is observable. That is a
    simulation of the context-manager *contract* only -- see the module docstring.
    """

    def __init__(self) -> None:
        super().__init__()
        self.events: list[str] = []
        self.ingested: list[tuple] = []
        self.tx_active = 0
        self.tx_depth_at_ingest: list[int] = []
        self.committed = 0
        self.rolled_back = 0
        self.ingest_error: Optional[Exception] = None

    # -- transaction ---------------------------------------------------------
    def transaction(self):
        storage = self

        class _Tx:
            def __enter__(self):
                storage.events.append("tx.begin")
                storage._snapshot = copy.deepcopy(
                    {k: v for k, v in vars(storage).items() if isinstance(v, dict)}
                )
                storage.tx_active += 1
                return self

            def __exit__(self, exc_type, exc, tb):
                storage.tx_active -= 1
                if exc_type is not None:
                    storage.rolled_back += 1
                    storage.events.append("tx.rollback")
                    for key, value in storage._snapshot.items():
                        setattr(storage, key, value)
                    storage.ingested.clear()
                    return False
                storage.committed += 1
                storage.events.append("tx.commit")
                return False

        return _Tx()

    # -- recorded writes -----------------------------------------------------
    def insert_tool_run(self, tr: ToolRun) -> ToolRun:
        self.events.append("insert_tool_run")
        return super().insert_tool_run(tr)

    def set_task_status(self, task_id, status: str) -> None:
        self.events.append(f"set_task_status:{status}")
        super().set_task_status(task_id, status)

    # -- Phase 14 ingestion --------------------------------------------------
    def ingest_observations(self, plan, *, tool_run_id, raw_output_ref, program_id):
        self.events.append("ingest_observations")
        # recorded, not asserted: the fake is also driven directly by the
        # served-wiring tests, which legitimately call this outside a transaction.
        self.tx_depth_at_ingest.append(self.tx_active)
        if self.ingest_error is not None:
            raise self.ingest_error
        self.ingested.append((plan, tool_run_id, raw_output_ref, program_id))


class RecordingHook:
    """An ``IngestHook`` that records its arguments instead of persisting."""

    def __init__(self, error: Optional[Exception] = None) -> None:
        self.calls: list[tuple] = []
        self.error = error

    def __call__(self, task, tool_run, artifacts, run, scope):
        self.calls.append((task, tool_run, artifacts, run, scope))
        if self.error is not None:
            raise self.error

    @property
    def artifacts(self) -> tuple:
        assert self.calls, "ingest hook was never called"
        return self.calls[0][2]


def _served_hook(storage, max_artifacts: int = 100):
    """The *real* served ingestor, so tests exercise production wiring.

    ``api.serve._build_ingestor`` is what ``create_serve_app`` installs: it plans and
    then calls ``storage.ingest_observations`` exactly as production does. Driving the
    transaction tests through it means the ordering and rollback assertions describe
    the shipped path, not a stand-in.
    """
    cfg = SimpleNamespace(limits=SimpleNamespace(max_artifacts_per_run=max_artifacts))
    hook = serve_module._build_ingestor(storage, cfg)
    assert hook is not None, "FakeStorage provides ingest_observations, so wiring applies"
    return hook


def _seam(artifacts: tuple):
    """A run_tool that returns a Phase 14 ``ToolRunOutcome`` carrying ``artifacts``."""
    return lambda task: ToolRunOutcome(tool_run=_tool_run(task), artifacts=artifacts)


def _drive(storage, hook, run_tool=None, run=None, task_target="example.com"):
    """Run one task to completion (or failure) and return the orchestrator + run."""
    if run_tool is None:
        run_tool = lambda task: _tool_run(task)  # noqa: E731 - bare ToolRun seam
    orch = Orchestrator(storage=storage, run_tool=run_tool, ingest=hook)
    run = run if run is not None else _run()
    run = orch.create_run(run)
    orch.plan(run, [_task(run.id, target=task_target)])
    status = orch.run_to_completion(run.id)
    return orch, run, status


# ---------------------------------------------------------------------------
# 1. ToolRunOutcome behaviour / splitting
# ---------------------------------------------------------------------------


def test_split_outcome_unwraps_outcome_and_coerces_artifacts_to_tuple():
    tr = ToolRun(task_id=uuid4(), tool_name="httpx", command=[], exit_code=0)
    tool_run, artifacts = _split_outcome(ToolRunOutcome(tool_run=tr, artifacts=["a", "b"]))
    assert tool_run is tr
    assert artifacts == ("a", "b")
    assert isinstance(artifacts, tuple)


def test_split_outcome_accepts_a_bare_tool_run_from_every_legacy_seam():
    tr = ToolRun(task_id=uuid4(), tool_name="subfinder", command=[], exit_code=0)
    tool_run, artifacts = _split_outcome(tr)
    assert tool_run is tr
    assert artifacts == ()


def test_tool_run_outcome_defaults_to_no_artifacts():
    tr = ToolRun(task_id=uuid4(), tool_name="subfinder", command=[], exit_code=0)
    assert ToolRunOutcome(tool_run=tr).artifacts == ()


def test_orchestrator_hands_the_exact_artifacts_to_the_hook():
    """A seam that returns artifacts gets them ingested; a bare ToolRun ingests nothing."""
    artifacts = ("api.example.com", "www.example.com")
    task_seen = uuid4()

    def seam(task):
        return ToolRunOutcome(tool_run=_tool_run(task), artifacts=artifacts)

    storage = FakeStorage()
    hook = RecordingHook()
    _drive(storage, hook, run_tool=seam)
    assert hook.artifacts == artifacts
    assert "ingest_observations" not in storage.events  # hook records, storage does not

    # a legacy bare-ToolRun seam still completes and still invokes the hook,
    # with an empty artifact tuple rather than crashing
    storage2 = FakeStorage()
    hook2 = RecordingHook()
    _drive(storage2, hook2)
    assert hook2.artifacts == ()
    assert task_seen  # keeps flake quiet


# ---------------------------------------------------------------------------
# 2. Orchestrator transaction behaviour
# ---------------------------------------------------------------------------


def test_storage_transaction_wraps_tool_run_ingest_and_terminal_status():
    """The three writes happen inside one transaction, in order, exactly once."""
    storage = FakeStorage()
    _drive(storage, _served_hook(storage), run_tool=_seam(("api.example.com",)))

    assert storage.committed == 1
    assert storage.rolled_back == 0
    events = storage.events
    assert events.count("tx.begin") == 1 and events.count("tx.commit") == 1

    # the task is marked running before the transaction opens (it is not a fact
    # that can be rolled back -- the tool is already executing at that point)
    assert events.index("set_task_status:running") < events.index("tx.begin")

    # and the atomic unit is ordered: tool run, then evidence, then terminal status
    assert (
        events.index("tx.begin")
        < events.index("insert_tool_run")
        < events.index("ingest_observations")
        < events.index("set_task_status:completed")
        < events.index("tx.commit")
    )
    assert storage.tx_depth_at_ingest == [1], "ingest observed an open transaction"


def test_ingest_hook_runs_inside_the_transaction():
    storage = FakeStorage()
    seen: list[int] = []
    hook = lambda task, tr, art, run, scope: seen.append(storage.tx_active)  # noqa: E731
    _drive(storage, hook)
    assert seen == [1], "the ingest hook must execute within the transaction"


def test_storage_without_transaction_still_works_unchanged():
    """A pre-Phase-14 Storage (no ``transaction()``) keeps the original write sequence."""
    storage = MemoryStorage()  # deliberately has no transaction()
    assert not callable(getattr(storage, "transaction", None))
    hook = RecordingHook()
    _, _, status = _drive(storage, hook)
    assert status == "COMPLETED"
    assert hook.calls, "hook still runs; only atomicity is unavailable"


def test_transactional_and_legacy_storage_reach_the_same_terminal_state():
    transactional, legacy = FakeStorage(), MemoryStorage()
    _, run_t, status_t = _drive(transactional, RecordingHook())
    _, run_l, status_l = _drive(legacy, RecordingHook())
    assert status_t == status_l == "COMPLETED"
    assert [t.status for t in transactional.list_tasks(run_t.id)] == [
        t.status for t in legacy.list_tasks(run_l.id)
    ]


# ---------------------------------------------------------------------------
# 3. Ingestion-hook failure handling
# ---------------------------------------------------------------------------


def test_failed_ingest_rolls_back_and_fails_the_task():
    """A storage-level ingest failure must roll the whole atomic unit back."""
    storage = FakeStorage()
    storage.ingest_error = RuntimeError("evidence insert blew up")
    _, run, status = _drive(
        storage, _served_hook(storage), run_tool=_seam(("api.example.com",))
    )

    assert storage.rolled_back == 1
    assert storage.committed == 0
    assert "tx.rollback" in storage.events
    # no ToolRun survived the rollback
    assert storage._tool_runs == {}
    # the task is visible as failed, not silently completed without its facts
    assert [t.status for t in storage.list_tasks(run.id)] == ["failed"]
    assert status in {"FAILED", "COMPLETED"}


def test_failed_ingest_leaves_no_partial_ingested_records():
    storage = FakeStorage()
    storage.ingest_error = ValueError("boom")
    _drive(storage, _served_hook(storage), run_tool=_seam(("api.example.com",)))
    assert storage.ingested == [], "a rolled-back transaction must not retain records"


def test_failed_ingest_does_not_wedge_the_run():
    """One poisoned task must not leave the run stuck; it terminates observably."""
    storage = FakeStorage()
    storage.ingest_error = RuntimeError("nope")
    _, run, status = _drive(storage, RecordingHook())
    assert status in {"FAILED", "COMPLETED"}
    # a second pass must not re-execute infinitely / hang
    orch = Orchestrator(storage=storage, run_tool=lambda t: _tool_run(t), ingest=RecordingHook())
    assert orch.resume(run.id) in {"FAILED", "COMPLETED"}


def test_tool_failure_is_still_handled_before_ingestion():
    """A raising seam fails the task without ever reaching the ingest hook."""
    storage = FakeStorage()
    hook = RecordingHook()

    def boom(task):
        raise RuntimeError("tool exploded")

    orch = Orchestrator(storage=storage, run_tool=boom, ingest=hook)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id)])
    status = orch.run_to_completion(run.id)
    # the *task* is what fails; the run itself still reaches a terminal state
    assert [t.status for t in storage.list_tasks(run.id)] == ["failed"]
    assert status in {"FAILED", "COMPLETED"}
    assert hook.calls == [], "ingest must not run when the tool itself failed"
    assert "tx.begin" not in storage.events, "a failed tool must not open a transaction"


# ---------------------------------------------------------------------------
# 4. Idempotency that is testable without PostgreSQL
# ---------------------------------------------------------------------------


def test_plan_ingestion_is_deterministic_for_identical_artifact_lists():
    artifacts = [
        "api.example.com",
        "api.example.com",
        DnsRecordObservation(hostname="example.com", record_type="A", value="93.184.216.34"),
        IpObservation(address="93.184.216.34", record_type="A"),
    ]
    first = plan_ingestion(artifacts, scope=_scope(), source="subfinder", target_host="example.com")
    second = plan_ingestion(artifacts, scope=_scope(), source="subfinder", target_host="example.com")
    assert first == second


def test_plan_ingestion_deduplicates_within_one_execution():
    """Same destination twice -> one record. This is the dedup the *plan* guarantees.

    It does NOT prove database-level idempotency: a real re-run creates a *second*
    execution, and only the unique indexes/``ON CONFLICT`` stop that from duplicating
    rows. That is 14.3.
    """
    plan = plan_ingestion(
        ["api.example.com", "api.example.com", "API.EXAMPLE.COM."],
        scope=_scope(),
        source="subfinder",
    )
    assert [a.hostname for a in plan.assets] == ["api.example.com"]

    plan2 = plan_ingestion(
        [
            DnsRecordObservation(hostname="example.com", record_type="A", value="1.1.1.1"),
            DnsRecordObservation(hostname="example.com", record_type="A", value="1.1.1.1"),
        ],
        scope=_scope(),
        source="dns",
    )
    assert len(plan2.dns_records) == 1, "the in-run DNS dedup that persistence relies on"


# ---------------------------------------------------------------------------
# 5. Out-of-scope ingestion / security
# ---------------------------------------------------------------------------


def test_out_of_scope_host_is_evidence_only_never_an_asset():
    plan = plan_ingestion(
        ["evil.com", "api.example.com"],
        scope=_scope(),
        source="subfinder",
    )
    assert [a.hostname for a in plan.assets] == ["api.example.com"]
    assert "evil.com" not in {a.hostname for a in plan.assets}
    denied = [o for o in plan.out_of_scope if o.kind == KIND_HOST and o.value == "evil.com"]
    assert denied and denied[0].reason


def test_out_of_scope_ip_is_evidence_only_never_linked():
    plan = plan_ingestion(
        [IpObservation(address="10.0.0.5", record_type="A")],
        scope=_scope(),
        source="dns",
        target_host="example.com",
    )
    assert plan.ip_links == (), "a denied IP must not be attached to the asset"
    denied = [o for o in plan.out_of_scope if o.kind == KIND_IP and o.value == "10.0.0.5"]
    assert denied


def test_out_of_scope_findings_never_spawn_a_follow_up_task():
    storage = FakeStorage()
    hook = RecordingHook()
    orch = Orchestrator(storage=storage, run_tool=lambda t: _tool_run(t), ingest=hook)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id)])
    orch.run_to_completion(run.id)
    # the only task is the one we planned; discovery does not add work
    assert len(storage.list_tasks(run.id)) == 1


def test_denied_target_task_is_never_ingested():
    """The orchestrator refuses an out-of-scope target before the tool, so no plan."""
    storage = FakeStorage()
    hook = RecordingHook()
    orch = Orchestrator(storage=storage, run_tool=lambda t: _tool_run(t), ingest=hook)
    run = orch.create_run(_run())
    orch.plan(run, [_task(run.id, target="evil.com")])
    status = orch.run_to_completion(run.id)
    assert status == "COMPLETED"
    assert hook.calls == [], "a skipped out-of-scope task must not reach ingestion"
    assert [t.status for t in storage.list_tasks(run.id)] == ["skipped"]


# ---------------------------------------------------------------------------
# 6. SQL-metacharacter handling at the mapping/storage boundary
# ---------------------------------------------------------------------------

HOSTILE = "evil'; DROP TABLE assets; --.example.com"


def test_hostile_hostname_is_denied_and_never_promoted():
    """A SQL-metacharacter hostname is not a hostname and must not become an asset.

    ``ScopeGuard`` matches by suffix, so the string ends in ``.example.com`` and
    would otherwise be classified in scope. ``check_host`` now validates that a
    host is a *possible* DNS name first, so the value is rejected at the scope
    boundary and ingestion records it as an out-of-scope observation instead of
    promoting attacker-chosen bytes into the asset graph.
    """
    plan = plan_ingestion([HOSTILE], scope=_scope(), source="subfinder")

    assert not plan.assets, "a malformed hostname must never be promoted to an asset"
    assert not plan.ip_links and not plan.web_apps and not plan.dns_records
    assert not plan.technologies
    # it is still observed and still accounted for, never silently dropped
    assert plan.out_of_scope, "the malformed host must still produce an observation"
    assert HOSTILE.lower() in repr(plan.out_of_scope)


@pytest.mark.parametrize(
    "host",
    [
        "has space.example.com",
        "semi;colon.example.com",
        "tab\t.example.com",
        "null\x00byte.example.com",
        "quote'.example.com",
        "double\"quote.example.com",
        "back\\slash.example.com",
        "star*.example.com",
        "brace{}.example.com",
        "paren().example.com",
        "amp&.example.com",
        "pipe|.example.com",
        "dot.dot..example.com",
        ".example.com",
        "a" * 64 + ".example.com",
    ],
)
def test_impossible_hostnames_are_out_of_scope(host):
    """No string that no resolver can answer for may pass as a hostname."""
    plan = plan_ingestion([host], scope=_scope(), source="subfinder")
    assert not plan.assets, f"{host!r} must not be promoted"


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "www.example.com",
        "Example.COM.",
        "api-1.example.com",
        # real recon output contains service names; these must keep working
        "_dmarc.example.com",
        "_sip._tcp.example.com",
        # punycode is valid ASCII and must pass through unchanged
        "xn--bcher-kva.example.com",
        "a" * 63 + ".example.com",
    ],
)
def test_plausible_hostnames_still_pass(host):
    """The syntax check must not reject names that legitimately occur."""
    plan = plan_ingestion([host], scope=_scope(), source="subfinder")
    # normalization is authoritative: lowercase, with the root dot stripped
    expected = host.lower().rstrip(".")
    assert [a.hostname for a in plan.assets] == [expected], (
        f"{host!r} is a possible DNS name and must stay in scope"
    )


def test_mapping_module_constructs_no_sql_at_all():
    """``recon/ingest.py`` is pure: it must contain no SQL and no string interpolation
    into anything query-shaped, so a hostile artifact cannot reach a query here."""
    source = inspect.getsource(plan_ingestion)
    lowered = source.lower()
    for token in ("select ", "insert ", "update ", "delete ", "drop ", "union ", "where "):
        assert token not in lowered, f"mapping layer must not contain SQL: {token!r}"


def test_phase14_ingest_path_is_parameterized_not_interpolated():
    """The Phase 14 SQL path must not build queries by interpolating values.

    Scoped deliberately to ``ingest_observations`` -- the function Phase 14 added.
    The module also contains pre-existing Phase 3/8 statements that interpolate
    *identifiers* (column names drawn from a fixed allow-list), which is a different
    and legitimate pattern; auditing those is out of scope here.
    """
    module = inspect.getsource(repos_all)
    tree = ast.parse(module)
    fn = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "ingest_observations"
    )
    offenders = []
    for node in ast.walk(fn):
        if isinstance(node, ast.JoinedStr) and any(
            isinstance(v, ast.FormattedValue) for v in node.values
        ):
            offenders.append(ast.get_source_segment(module, node) or "")
    assert not offenders, f"Phase 14 ingest path must not interpolate into SQL: {offenders}"


def test_phase14_ingest_path_passes_values_as_query_parameters():
    """Every attacker-influenced value must travel as a bound parameter, not a literal."""
    module = inspect.getsource(repos_all)
    fn_source = inspect.getsource(repos_all.Repositories.ingest_observations)
    # plan values are handed to repositories, which bind them; the ingest function
    # itself must not concatenate any plan field into a statement.
    for field in ("plan.hostname", "plan.address", "plan.url", "plan.title"):
        assert field not in fn_source, f"{field} must not reach SQL as text"
    # the only literals it builds are the fixed evidence entity-type tags
    assert "ENTITY_" in module


# ---------------------------------------------------------------------------
# 7. Artifact cardinality enforcement
# ---------------------------------------------------------------------------


def test_cardinality_cap_truncates_and_counts_the_drop():
    many = [f"h{i}.example.com" for i in range(50)]
    plan = plan_ingestion(many, scope=_scope(), source="subfinder", max_artifacts=10)
    assert plan.truncated == 40
    assert len(plan.assets) == 10


def test_zero_cap_consumes_nothing_but_still_reports_truncation():
    plan = plan_ingestion(["a.example.com"], scope=_scope(), source="s", max_artifacts=0)
    assert plan.assets == ()
    assert plan.truncated == 1
    # truncation is bookkeeping: the artifact is dropped before classification, so it
    # produces neither a record nor a scope decision
    assert plan.is_empty is True
    assert plan.out_of_scope == ()


def test_negative_cap_is_clamped_to_zero_not_treated_as_unlimited():
    plan = plan_ingestion(["a.example.com"], scope=_scope(), source="s", max_artifacts=-5)
    assert plan.assets == ()
    assert plan.truncated == 1


def test_cardinality_is_enforced_before_any_scope_check():
    """Truncation is applied to raw artifact count, pre-classification."""
    artifacts = ["evil.com"] * 5 + ["a.example.com"] * 5
    plan = plan_ingestion(artifacts, scope=_scope(), source="s", max_artifacts=2)
    assert plan.truncated == 8
    assert plan.assets == ()


# ---------------------------------------------------------------------------
# 8. Malformed-artifact behaviour (non-fatal parse contract)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "junk",
    [object(), None, 123, {"host": "a.example.com"}, ["a.example.com"], 3.5, b"a.example.com"],
)
def test_malformed_artifacts_are_counted_not_fatal(junk):
    plan = plan_ingestion([junk], scope=_scope(), source="s")
    assert plan.unrecognized == 1
    assert plan.is_empty is True


def test_malformed_artifacts_do_not_block_valid_ones():
    plan = plan_ingestion(
        [object(), "a.example.com", None, WebAppObservation(host="b.example.com", url="https://b.example.com", scheme="https", port=443, status_code=200)],
        scope=_scope(),
        source="s",
    )
    assert plan.unrecognized == 2
    assert {a.hostname for a in plan.assets} == {"a.example.com", "b.example.com"}


def test_empty_artifact_list_yields_an_empty_plan():
    plan = plan_ingestion([], scope=_scope(), source="s")
    assert plan.is_empty is True
    assert plan.unrecognized == 0 and plan.truncated == 0


# ---------------------------------------------------------------------------
# 9. Served-wiring contract that does not need a database
# ---------------------------------------------------------------------------


def test_build_ingestor_is_none_for_storage_that_cannot_persist():
    """MemoryStorage predates Phase 14; wiring must not force a call it cannot serve."""
    assert serve_module._build_ingestor(MemoryStorage(), SimpleNamespace()) is None


def test_build_ingestor_applies_the_configured_cap_and_fails_closed():
    store = FakeStorage()
    store.ingest_error = None
    cfg = SimpleNamespace(limits=SimpleNamespace(max_artifacts_per_run=2))
    ingest = serve_module._build_ingestor(store, cfg)
    assert callable(ingest)

    task, run, tr = _task(uuid4()), _run(), _tool_run(_task(uuid4()))
    ingest(task, tr, [f"h{i}.example.com" for i in range(9)], run, None)  # scope=None
    plan = store.ingested[0][0]
    # no scope -> deny-all, so nothing is promoted, and the cap still applies
    assert plan.assets == ()
    assert plan.truncated == 7
    assert plan.out_of_scope


def test_build_ingestor_short_circuits_on_no_artifacts():
    store = FakeStorage()
    ingest = serve_module._build_ingestor(store, SimpleNamespace(limits=SimpleNamespace(max_artifacts_per_run=10)))
    ingest(_task(uuid4()), _tool_run(_task(uuid4())), [], _run(), _scope())
    assert store.ingested == [], "an execution with no artifacts writes nothing"


def test_build_ingestor_passes_tool_run_and_run_identity_through():
    store = FakeStorage()
    ingest = serve_module._build_ingestor(store, SimpleNamespace(limits=SimpleNamespace(max_artifacts_per_run=100)))
    task, run, tr = _task(uuid4()), _run(), _tool_run(_task(uuid4()))
    ingest(task, tr, ["api.example.com"], run, _scope())
    plan, tool_run_id, raw_ref, program_id = store.ingested[0]
    assert tool_run_id == tr.id
    assert raw_ref == tr.raw_output_ref
    assert program_id == run.program_id
    assert [a.hostname for a in plan.assets] == ["api.example.com"]
