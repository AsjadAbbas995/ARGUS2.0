"""Phase 16 unit + integration gates: context building, the analysis hook, and the wiring.

No database required. The hook is exercised against a fake storage that records what it was
asked to write, so the fail-closed paths and the capability gate are testable without
PostgreSQL; ``tests/test_phase16_live.py`` proves the same behaviour against the real thing.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from ai import loop as ai_loop
from ai import run_context
from ai.loop import AnalysisHook, build_analysis_hook, context_ref
from ai.router import RouteConfig
from core.config import AiConfig, Config, ConfigError
from database.models.entities import AiAnalysis, Run, Task

TARGET = "example.com"


# -- fixtures -----------------------------------------------------------------


def _node(kind: str, key: str, evidence_id: str, **attributes: str) -> dict:
    return {
        "key": key,
        "kind": kind,
        "evidence_id": evidence_id,
        "attributes": {k: str(v) for k, v in attributes.items()},
    }


def _surface(nodes: list[dict] | None = None) -> dict:
    return {
        "run_id": str(uuid4()),
        "available": True,
        "evidence_counts": {"asset": len(nodes or [])},
        "records": {"count": len(nodes or []), "by_kind": {}},
        "graph": {
            "node_count": len(nodes or []),
            "edge_count": 0,
            "orphan_count": 0,
            "nodes": sorted(nodes or [], key=lambda n: (n["kind"], n["key"])),
            "edges": [],
            "orphans": [],
        },
        "endpoint_subgraph": {"kinds": [], "node_count": 0, "edge_count": 0, "empty": True},
        "inferences": {"count": 0, "items": []},
        "unproduced_record_kinds": ["endpoint"],
    }


def _chain() -> dict:
    """A realistic domain/IP/port/web-app/technology chain, each with its own evidence."""
    return _surface(
        [
            _node("domain", TARGET, "ev-domain"),
            _node("ip", "93.184.216.34", "ev-ip", hostname=TARGET),
            _node("port", "93.184.216.34:443", "ev-port", ip="93.184.216.34", port=443),
            _node(
                "webapp",
                f"{TARGET}:443",
                "ev-webapp",
                host=TARGET,
                port=443,
                status_code=200,
                title="Example",
            ),
            _node("technology", f"nginx@{TARGET}", "ev-tech", host=TARGET, category="other"),
        ]
    )


def _run(snapshot: dict | None = None) -> Run:
    return Run(
        id=uuid4(),
        program_id=uuid4(),
        status="ANALYZING",
        configuration_snapshot=snapshot
        or {"scope": {"allowed_domains": [TARGET]}},
    )


def _task(task_type: str, status: str = "completed", target: str = TARGET) -> Task:
    return Task(
        id=uuid4(),
        run_id=uuid4(),
        type=task_type,
        target=target,
        status=status,
    )


class FakeStorage:
    """Records writes; optionally fails, to prove the hook fails closed."""

    def __init__(self, surface: dict | None = None, *, fail: bool = False) -> None:
        self._surface = _chain() if surface is None else surface
        self.fail = fail
        self.analyses: list[AiAnalysis] = []
        self.hypotheses: list[object] = []
        self.transactions = 0
        self.calls: list[str] = []

    # -- reads ----------------------------------------------------------------

    def attack_surface(self, run_id):
        self.calls.append("attack_surface")
        return self._surface

    # -- writes ---------------------------------------------------------------

    def insert_ai_analysis(self, analysis: AiAnalysis) -> AiAnalysis:
        if self.fail:
            raise RuntimeError("simulated write failure")
        self.analyses.append(analysis)
        return analysis

    # ``self.storage.insert_hypothesis(...)`` -- the documented ``Repositories`` facade.
    def insert_hypothesis(self, hypothesis):
        if self.fail:
            raise RuntimeError("simulated write failure")
        self.hypotheses.append(hypothesis)
        return hypothesis

    def transaction(self):
        """A real transaction would roll back; this fake must too, or the fail-closed tests
        would pass for the wrong reason."""
        storage = self

        class _Tx:
            def __enter__(self_inner):
                storage.transactions += 1
                self_inner.analyses = len(storage.analyses)
                self_inner.hypotheses = len(storage.hypotheses)
                return self_inner

            def __exit__(self_inner, *exc):
                if exc[0] is not None:
                    del storage.analyses[self_inner.analyses :]
                    del storage.hypotheses[self_inner.hypotheses :]
                return False

        return _Tx()


# -- run_context gates --------------------------------------------------------


class TestScopeRef:
    def test_reads_allowed_domains_from_the_snapshot(self):
        ref = run_context.scope_ref({"scope": {"allowed_domains": [TARGET]}})
        assert ref.root == TARGET
        assert ref.allowed_hosts == (TARGET,)

    def test_empty_scope_denies_rather_than_inventing_a_target(self):
        ref = run_context.scope_ref({"scope": {}})
        assert ref.root == ""
        assert ref.allowed_hosts == ()

    def test_missing_snapshot_is_treated_as_no_scope(self):
        assert run_context.scope_ref(None).allowed_hosts == ()


class TestObservations:
    def test_every_observation_carries_a_real_evidence_id(self):
        ids = {o.evidence_id for o in run_context.observations(_chain())}
        assert ids == {"ev-domain", "ev-ip", "ev-port", "ev-webapp", "ev-tech"}

    def test_a_node_without_evidence_is_never_cited(self):
        surface = _surface([_node("domain", TARGET, ""), _node("ip", "1.2.3.4", "ev-ip")])
        assert [o.evidence_id for o in run_context.observations(surface)] == ["ev-ip"]

    def test_statements_restate_the_recorded_fact(self):
        statements = {o.statement for o in run_context.observations(_chain())}
        assert f"in-scope asset `{TARGET}` recorded" in statements
        assert any("IP `93.184.216.34` resolved for example.com" in s for s in statements)

    def test_ordering_is_deterministic(self):
        first = run_context.observations(_chain())
        second = run_context.observations(_chain())
        assert first == second

    def test_an_empty_run_yields_no_observations(self):
        assert run_context.observations(_surface([])) == ()


class TestCoverageGaps:
    EXEC = ("dns_resolve", "http_probe")

    def test_uncovered_executable_stage_is_a_gap(self):
        assert run_context.coverage_gaps([], self.EXEC) == ("dns_resolve", "http_probe")

    def test_a_completed_task_covers_its_stage(self):
        assert "dns_resolve" not in run_context.coverage_gaps([_task("dns_resolve")], self.EXEC)

    def test_an_aliased_task_type_covers_the_same_stage(self):
        assert "dns_resolve" not in run_context.coverage_gaps([_task("resolve")], self.EXEC)

    def test_a_failed_task_covers_nothing(self):
        assert "dns_resolve" in run_context.coverage_gaps(
            [_task("dns_resolve", status="failed")], self.EXEC
        )

    def test_a_stage_with_no_adapter_is_a_gap_not_a_task(self):
        # Phase 22 gave ``web_crawl`` a served adapter (``katana``), so a stage that
        # is neither in ``STAGE_PRIORITY`` nor registered can never become a gap task.
        assert "certificate" not in run_context.coverage_gaps([], ("certificate",))
        assert "certificate" not in run_context.uncovered_without_capability(
            [], ("certificate",)
        )

    def test_a_crawl_task_type_covers_the_crawl_stage(self):
        # Phase 22: a completed ``katana`` task satisfies the ``web_crawl`` stage,
        # exactly like ``resolve`` did for ``dns_resolve`` before it.
        executable = self.EXEC + ("web_crawl", "katana")
        assert "web_crawl" in run_context.coverage_gaps([], executable)
        assert "web_crawl" not in run_context.coverage_gaps(
            [_task("katana")], executable
        )

    def test_a_historical_task_type_covers_the_historical_stage(self):
        # Phase 24: a completed ``gau`` (tool spelling) or ``historical_recon``
        # (canonical) task satisfies the ``historical_recon`` stage.
        executable = self.EXEC + ("historical_recon", "gau")
        assert "historical_recon" in run_context.coverage_gaps([], executable)
        assert "historical_recon" not in run_context.coverage_gaps(
            [_task("gau")], executable
        )
        assert "historical_recon" not in run_context.coverage_gaps(
            [_task("historical_recon")], executable
        )

    def test_historical_recon_without_capability_is_reported_not_proposed(self):
        # With the gate disabled (no adapter registered) the stage is named as
        # "we could not", never enqueued.
        blocked = run_context.uncovered_without_capability([], self.EXEC)
        assert "historical_recon" in blocked

    def test_the_historical_stage_resolves_to_its_canonical_task_type(self):
        assert ai_loop.TASK_TYPE_FOR_STAGE["historical_recon"] == "historical_recon"

    def test_uncovered_without_capability_reports_the_rest(self):
        blocked = run_context.uncovered_without_capability([], self.EXEC)
        assert "subdomain_enum" in blocked
        assert "dns_resolve" not in blocked

    def test_gaps_respect_documented_stage_priority(self):
        from ai.recon_agent import STAGE_PRIORITY

        gaps = run_context.coverage_gaps([], self.EXEC)
        assert list(gaps) == [s for s in STAGE_PRIORITY if s in set(self.EXEC)]


# -- the hook -----------------------------------------------------------------


class TestAnalysisHook:
    EXEC = ("dns_resolve", "http_probe")

    def _hook(self, storage, **kw) -> AnalysisHook:
        return build_analysis_hook(storage, self.EXEC, **kw)

    def test_a_run_with_facts_produces_an_ai_analysis_row(self):
        store = FakeStorage()
        self._hook(store)(_run(), [])
        assert [a.agent_name for a in store.analyses] == ["recon_agent", "hypothesis_agent"]

    def test_the_analysis_row_keeps_the_full_contract_output(self):
        store = FakeStorage()
        self._hook(store)(_run(), [])
        out = store.analyses[0].output
        for field in (
            "type", "target", "observation", "reasoning", "potential_issue",
            "evidence", "confidence", "priority", "truth_label", "validation_step",
        ):
            assert field in out, field

    def test_the_analysis_row_is_attributable_to_its_run(self):
        run = _run()
        store = FakeStorage()
        self._hook(store)(run, [])
        assert {a.input_context_ref for a in store.analyses} == {context_ref(run.id)}

    def test_a_hypothesis_proposal_becomes_an_unreviewed_hypothesis(self):
        store = FakeStorage()
        run = _run()
        self._hook(store)(run, [])
        assert len(store.hypotheses) == 1
        h = store.hypotheses[0]
        assert h.run_id == run.id
        assert h.status == "open"
        assert h.review_status == "pending"

    def test_the_hook_never_writes_validated_finding(self):
        store = FakeStorage()
        self._hook(store)(_run(), [])
        for h in store.hypotheses:
            assert h.truth_label != "VALIDATED_FINDING"
        assert "VALIDATED_FINDING" not in ai_loop.PERSISTABLE_TRUTH_LABELS

    def test_cited_evidence_survives_on_the_analysis_row(self):
        store = FakeStorage()
        self._hook(store)(_run(), [])
        cited = {e["source"] for a in store.analyses for e in a.output["evidence"]}
        assert cited <= {"ev-domain", "ev-ip", "ev-port", "ev-webapp", "ev-tech"}

    def test_the_only_proposed_task_is_one_the_registry_can_run(self):
        store = FakeStorage()
        tasks = self._hook(store)(_run(), [])
        assert [t.type for t in tasks] == ["dns_resolve"]
        assert all(t.type in self.EXEC for t in tasks)

    def test_a_proposed_task_targets_the_run_scope_root(self):
        store = FakeStorage()
        tasks = self._hook(store)(_run(), [])
        assert [t.target for t in tasks] == [TARGET]

    def test_no_capable_stage_means_no_task(self):
        # An empty registry: every stage is uncoverable, so nothing may be proposed.
        store = FakeStorage()
        assert build_analysis_hook(store, ())(_run(), []) == []

    def test_fully_covered_run_proposes_no_task(self):
        store = FakeStorage()
        done = [_task("dns_resolve"), _task("http_probe")]
        assert self._hook(store)(_run(), done) == []

    def test_the_pass_runs_in_a_transaction(self):
        store = FakeStorage()
        self._hook(store)(_run(), [])
        assert store.transactions >= 1

    def test_hypotheses_are_bounded_per_pass(self):
        store = FakeStorage()
        self._hook(store, max_hypotheses_per_pass=0)(_run(), [])
        assert store.hypotheses == []
        assert store.analyses  # the audit trail is unconditional

    def test_determinism_identical_passes(self):
        first, second = FakeStorage(), FakeStorage()
        self._hook(first)(_run(), [])
        self._hook(second)(_run(), [])
        strip = lambda s: [  # noqa: E731
            (a.agent_name, a.model_used, a.input_context_ref is not None, a.output)
            for a in s.analyses
        ]
        assert strip(first) == strip(second)

    def test_uncovered_without_capability_is_reported(self):
        store = FakeStorage()
        hook = self._hook(store)
        hook(_run(), [])
        assert "web_crawl" in hook.last_result.uncovered_without_capability


class TestFailClosed:
    EXEC = ("dns_resolve",)

    def test_a_write_failure_produces_no_tasks_and_no_hypothesis(self):
        store = FakeStorage(fail=True)
        assert build_analysis_hook(store, self.EXEC)(_run(), []) == []
        assert store.analyses == []
        assert store.hypotheses == []

    def test_a_storage_without_the_projection_yields_nothing(self):
        class Bare:
            pass

        assert build_analysis_hook(Bare(), self.EXEC)(_run(), []) == []

    def test_a_projection_read_failure_yields_nothing(self):
        class Exploding(FakeStorage):
            def attack_surface(self, run_id):
                raise RuntimeError("db down")

        store = Exploding()
        assert build_analysis_hook(store, self.EXEC)(_run(), []) == []

    def test_an_unavailable_surface_yields_nothing(self):
        store = FakeStorage({"available": False})
        assert build_analysis_hook(store, self.EXEC)(_run(), []) == []

    def test_a_context_build_failure_yields_nothing_rather_than_failing_the_run(self):
        """Context building reads caller-supplied data, so it can raise just like an agent can.

        If this escaped, the hook would fail the very run it exists to advise.
        """
        store = FakeStorage()
        run = _run()
        run.configuration_snapshot = {"scope": {"allowed_domains": object()}}  # unhashable junk

        def explode(*args, **kw):
            raise RuntimeError("context builder failed")

        original = ai_loop.recon_context
        ai_loop.recon_context = explode
        try:
            assert build_analysis_hook(store, self.EXEC)(run, []) == []
            assert store.analyses == []
        finally:
            ai_loop.recon_context = original

    def test_a_malformed_projection_does_not_fail_the_run(self):
        """A graph the context builder cannot read must degrade, not raise."""
        store = FakeStorage({"available": True, "graph": {"nodes": "not-a-list"}})
        assert build_analysis_hook(store, self.EXEC)(_run(), []) == []

    def test_a_storage_missing_the_write_method_still_proposes_nothing(self):
        class NoAnalysisWrite(FakeStorage):
            insert_ai_analysis = None  # not callable, like a storage predating Phase 16

        store = NoAnalysisWrite()
        assert build_analysis_hook(store, self.EXEC)(_run(), []) == []
        assert store.hypotheses == []

    def test_a_raising_agent_is_captured_not_propagated(self):
        class Boom(AnalysisHook):
            def _invoke(self, agent_name, agent, ctx):
                return ai_loop.AgentOutcome(agent_name, "m", None, error="boom")

        store = FakeStorage()
        hook = Boom(store, self.EXEC)
        assert hook(_run(), []) == []
        assert store.analyses == []

    def test_an_off_contract_proposal_is_rejected_before_any_write(self, monkeypatch):
        store = FakeStorage()

        def bad(ctx, cfg=None):
            return {"type": "hypothesis", "target": TARGET}  # missing required fields

        monkeypatch.setattr(ai_loop.hypothesis_agent, "run", bad)
        hook = build_analysis_hook(store, self.EXEC)
        hook(_run(), [])
        outcome = next(o for o in hook.last_result.outcomes if o.agent_name == "hypothesis_agent")
        assert outcome.proposal is None
        assert outcome.error is not None
        assert store.hypotheses == []


# -- config gate --------------------------------------------------------------


class TestAiConfigEnabled:
    def test_defaults_to_disabled(self):
        assert AiConfig().enabled is False
        assert AiConfig.from_dict(None).enabled is False
        assert AiConfig.from_dict({}).enabled is False

    def test_explicitly_enabled(self):
        assert AiConfig.from_dict({"enabled": True}).enabled is True

    def test_round_trips_through_the_snapshot(self, monkeypatch):
        monkeypatch.setenv("ARGUS_DATABASE_URL", "postgresql://u:p@localhost/argus")
        cfg = Config.from_dict({"ai": {"enabled": True, "mode": "local"}})
        assert cfg.to_dict()["ai"]["enabled"] is True

    def test_snapshot_default_leaves_it_disabled(self, monkeypatch):
        monkeypatch.setenv("ARGUS_DATABASE_URL", "postgresql://u:p@localhost/argus")
        assert Config.from_dict({}).to_dict()["ai"]["enabled"] is False

    def test_an_invalid_mode_is_still_rejected(self):
        with pytest.raises(ConfigError):
            AiConfig.from_dict({"mode": "telepathy"})


# -- served composition -------------------------------------------------------


def _served_orchestrator(ai_enabled: bool):
    """Build the real served composition and hand back its orchestrator."""
    from api.serve import create_serve_app

    app = create_serve_app(api_key="k", in_memory=True, config=_served_config(ai_enabled))
    return app.state.argus_orchestrator


def _served_execution(ai_enabled: bool):
    from api.serve import create_serve_app

    app = create_serve_app(api_key="k", in_memory=True, config=_served_config(ai_enabled))
    return app.state.argus_execution


def _served_config(ai_enabled: bool) -> Config:
    import dataclasses

    from core.config import AiMode

    cfg = Config.from_dict({"database": {"url": "postgresql://u:p@localhost/argus"}})
    return dataclasses.replace(cfg, ai=AiConfig(mode=AiMode.LOCAL, enabled=ai_enabled))


class TestServedComposition:
    """The gate that actually matters: is the loop wired into the served app at all?"""

    def test_disabled_by_default_leaves_no_analysis_hook(self):
        assert _served_orchestrator(False).analysis is None

    def test_enabled_wires_the_production_hook(self):
        orch = _served_orchestrator(True)
        assert isinstance(orch.analysis, AnalysisHook)

    def test_the_hook_is_gated_on_the_live_adapter_registry(self):
        orch = _served_orchestrator(True)
        registry = _served_execution(True).known_task_types()
        # Whatever the registry can dispatch, the hook may run -- and nothing else.
        assert orch.analysis.runnable == frozenset(registry)

    def test_the_gate_excludes_every_stage_without_an_adapter(self):
        orch = _served_orchestrator(True)
        # Phase 20A registered Subfinder and Nmap adapters; Phase 21A registered
        # the served ``tech_detect`` and Phase 23 ``content_discover`` adapters, so
        # every stage with a served adapter is translatable into a runnable task
        # type. Only stages that still lack an adapter must not be runnable.
        covered = frozenset(
            {
                "dns_resolve",
                "http_probe",
                "subdomain_enum",
                "port_scan",
                "tech_detect",
                "content_discover",
            }
        )
        for stage, task_type in ai_loop.TASK_TYPE_FOR_STAGE.items():
            if stage in covered:
                continue
            assert task_type not in orch.analysis.runnable, stage

    def test_the_configured_route_mode_reaches_the_hook(self):
        assert _served_orchestrator(True).analysis.route_config.mode == "local"

    def test_no_ai_config_leaves_the_default_app_unwired(self):
        assert _served_orchestrator(False).analysis is None


class TestRecordedModelId:
    def test_route_config_records_the_configured_mode_on_each_row(self):
        store = FakeStorage()
        hook = build_analysis_hook(
            store, ("dns_resolve",), route_config=RouteConfig(mode="local")
        )
        hook(_run(), [])
        assert all("mode=local" in a.model_used for a in store.analyses)

    def test_the_model_id_is_honest_about_making_no_call(self):
        store = FakeStorage()
        build_analysis_hook(store, ("dns_resolve",))(_run(), [])
        assert all(a.model_used.startswith("argus-rule-based") for a in store.analyses)


class TestContextRef:
    def test_is_prefix_matchable(self):
        run = uuid4()
        assert context_ref(run) == f"run:{run}"

    def test_none_for_no_run(self):
        assert context_ref(None) is None

    def test_is_a_valid_uuid_suffix(self):
        assert UUID(str(context_ref(uuid4())).removeprefix("run:"))
