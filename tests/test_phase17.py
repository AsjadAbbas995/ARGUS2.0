"""Phase 17 unit/integration gates: run-scoped AI observability, no DSN.

Phase 16 made the intelligence layer *durable*: rows were committed, but nothing an operator
could reach could read them, and attributing a row to a run meant matching a text prefix inside
``input_context_ref``. This module covers the Phase 17 contract that has no database in it:

* the wire contract of ``GET /api/v1/runs/{run_id}/ai-analysis`` -- auth, 404, run scoping, and
  the honest diagnostics that separate "AI disabled" from "AI unwired" from "AI found nothing";
* the three report renderers, each of which must carry the section without merging it into
  findings;
* ``ai.max_loop_passes`` config: default, custom value, and rejection of a bad one;
* ``AnalysisHook`` diagnostics and the fail-closed / proposal-only semantics Phase 16 promised,
  re-asserted because Phase 17 changed how a pass reports what it did.

The PostgreSQL half -- migration 0005, the foreign key, run isolation across real rows, and the
production ``create_serve_app`` composition -- is in ``tests/test_phase17_live.py``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from starlette.testclient import TestClient

from ai.loop import (
    ANALYSIS_CAPABILITY_UNAVAILABLE,
    ANALYSIS_CONTEXT_FAILED,
    ANALYSIS_NO_PROPOSALS,
    ANALYSIS_PASS_FAILED,
    ANALYSIS_PROPOSED,
    ANALYSIS_STATUSES,
)
from api.server import create_app
from core.config import AiConfig, Config, ConfigError, run_snapshot_from_dict
from core.orchestrator import Orchestrator
from database.models.entities import AiAnalysis, Run, ToolRun
from reports import html_report, json_report, markdown_report

API_KEY = "phase17-key"
RUN_ID = uuid4()

#: A loopback DSN with no credentials. ``Config.from_dict`` requires a database url, and the
#: loop-budget tests below never connect -- only ``to_dict``/``run_snapshot_from_dict`` are
#: exercised. No secret is committed: there is no user, password or host here.
_CONFIG_DSN = "postgresql:///argus_test"


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {API_KEY}"}


def _run_tool(task) -> ToolRun:
    return ToolRun(
        task_id=task.id,
        tool_name=task.type,
        command=["argus", task.type, task.target],
        exit_code=0,
        raw_output_ref="raw/out.txt",
    )


def _analysis(run_id=RUN_ID, **kw) -> AiAnalysis:
    defaults = dict(
        run_id=run_id,
        agent_name="recon_agent",
        model_used="argus-rule-based (route mode=hybrid)",
        input_context_ref=f"run:{run_id}",
        output={
            "type": "recon_stage_proposal",
            "statement": "DNS A record observed; no subdomain coverage in scope.",
            "truth_label": "INFERENCE",
            "confidence": 0.4,
            "evidence": [str(uuid4())],
            "target": "example.com",
        },
        created_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )
    defaults.update(kw)
    return AiAnalysis(**defaults)


class _Storage:
    """Minimal run-scoped storage double.

    Records the ``run_id`` every read was called with so a test can assert the scoping happens
    in the query rather than being filtered client-side afterwards.
    """

    def __init__(self, run: Run, analysis=()) -> None:
        self.run = run
        self.analysis = list(analysis)
        self.analysis_calls: list[object] = []

    def get_run(self, run_id):
        return self.run if run_id == self.run.id else None

    def list_tasks(self, run_id):
        return []

    def list_tool_runs(self, run_id):
        return []

    def list_evidence(self, run_id):
        return []

    def list_hypotheses(self, run_id):
        return []

    def list_ai_analysis(self, run_id=None):
        self.analysis_calls.append(run_id)
        if run_id is None:
            return list(self.analysis)
        return [a for a in self.analysis if a.run_id == run_id]


def _client(run: Run, analysis=(), hook: str = "default", **kw) -> TestClient:
    orch = Orchestrator(storage=_Storage(run, analysis), run_tool=_run_tool, **kw)
    app = create_app(orch, api_key=API_KEY)
    if hook is not None:
        app.state.argus_analysis_hook = hook
    return TestClient(app)


def _run() -> Run:
    return Run(id=RUN_ID, program_id=uuid4(), status="COMPLETED", target="example.com",
               configuration_snapshot={})


# ---------------------------------------------------------------------------
# the route: authentication and existence
# ---------------------------------------------------------------------------


def test_the_route_requires_authentication():
    with _client(_run()) as client:
        assert client.get(f"/api/v1/runs/{RUN_ID}/ai-analysis").status_code == 401


def test_a_wrong_key_is_rejected():
    with _client(_run()) as client:
        response = client.get(
            f"/api/v1/runs/{RUN_ID}/ai-analysis",
            headers={"Authorization": "Bearer not-the-key"},
        )
        assert response.status_code == 401


def test_an_unknown_run_is_a_404():
    with _client(_run()) as client:
        response = client.get(f"/api/v1/runs/{uuid4()}/ai-analysis", headers=_auth())
        assert response.status_code == 404


def test_a_non_uuid_run_id_is_a_422_not_a_500():
    with _client(_run()) as client:
        assert client.get("/api/v1/runs/not-a-uuid/ai-analysis", headers=_auth()).status_code == 422


# ---------------------------------------------------------------------------
# the route: run scoping
# ---------------------------------------------------------------------------


def test_the_route_returns_this_runs_rows():
    rows = [_analysis(), _analysis(agent_name="hypothesis_agent")]
    with _client(_run(), rows) as client:
        body = client.get(f"/api/v1/runs/{RUN_ID}/ai-analysis", headers=_auth()).json()
    assert body["run_id"] == str(RUN_ID)
    assert body["count"] == 2
    assert {a["agent_name"] for a in body["ai_analysis"]} == {"recon_agent", "hypothesis_agent"}
    assert all(a["run_id"] == str(RUN_ID) for a in body["ai_analysis"])


def test_the_route_never_sees_another_runs_rows():
    other = uuid4()
    with _client(_run(), [_analysis(run_id=RUN_ID), _analysis(run_id=other)]) as client:
        body = client.get(f"/api/v1/runs/{RUN_ID}/ai-analysis", headers=_auth()).json()
    assert [a["run_id"] for a in body["ai_analysis"]] == [str(RUN_ID)]


def test_a_row_with_no_run_is_never_attributed_to_a_run():
    """An unattributable legacy row stays invisible rather than being shown as some run's."""
    with _client(_run(), [_analysis(run_id=None, input_context_ref="run:not-a-uuid")]) as client:
        body = client.get(f"/api/v1/runs/{RUN_ID}/ai-analysis", headers=_auth()).json()
    assert body["count"] == 0
    assert body["ai_analysis"] == []


def test_the_route_scopes_in_the_query_not_by_filtering_the_unfiltered_read():
    """The run id must reach the storage, not be applied to an already-unscoped result.

    An ``AiAnalysisRepository.list_all()`` behind this route would still return only the right
    rows for a single-run test, which is exactly why the scoping has to be asserted at the seam.
    """
    storage = _Storage(_run(), [_analysis()])
    orch = Orchestrator(storage=storage, run_tool=_run_tool)
    with TestClient(create_app(orch, api_key=API_KEY)) as client:
        client.get(f"/api/v1/runs/{RUN_ID}/ai-analysis", headers=_auth())
    assert storage.analysis_calls == [RUN_ID], (
        "the route must ask the storage for this run's rows, not fetch every row and filter"
    )


def test_the_projection_is_honest_about_the_model():
    """``model_used`` is reported verbatim -- Phase 17 makes no provider call."""
    with _client(_run(), [_analysis()]) as client:
        body = client.get(f"/api/v1/runs/{RUN_ID}/ai-analysis", headers=_auth()).json()
    assert body["ai_analysis"][0]["model_used"] == "argus-rule-based (route mode=hybrid)"


def test_the_output_is_returned_verbatim_alongside_the_projections():
    with _client(_run(), [_analysis()]) as client:
        row = client.get(f"/api/v1/runs/{RUN_ID}/ai-analysis", headers=_auth()).json()[
            "ai_analysis"
        ][0]
    # The full Common Output Contract object is the record of truth...
    assert row["output"]["statement"].startswith("DNS A record")
    assert row["output"]["confidence"] == 0.4
    # ...and the three triage keys are projections of it, not new claims.
    assert row["proposal_type"] == "recon_stage_proposal"
    assert row["truth_label"] == "INFERENCE"
    assert row["evidence"] == row["output"]["evidence"]


def test_a_proposal_without_a_truth_label_reports_none_not_a_default():
    with _client(_run(), [_analysis(output={"type": "x", "statement": "s"})]) as client:
        row = client.get(f"/api/v1/runs/{RUN_ID}/ai-analysis", headers=_auth()).json()[
            "ai_analysis"
        ][0]
    assert row["truth_label"] is None
    assert row["evidence"] == []


# ---------------------------------------------------------------------------
# the route: diagnostics distinguish why there is nothing to show
# ---------------------------------------------------------------------------


def test_diagnostics_say_disabled_when_ai_is_off():
    """No hook exists, so the hook cannot report on itself -- app state answers instead."""
    app = create_app(Orchestrator(storage=_Storage(_run()), run_tool=_run_tool), api_key=API_KEY)
    app.state.argus_config = Config.from_dict({"database": {"url": _CONFIG_DSN}, "ai": {"enabled": False}})
    with TestClient(app) as client:
        diagnostics = client.get(
            f"/api/v1/runs/{RUN_ID}/ai-analysis", headers=_auth()
        ).json()["diagnostics"]
    assert diagnostics == {"enabled": False, "wired": False, "status": "disabled"}


def test_diagnostics_say_unwired_when_policy_is_on_but_no_hook_exists():
    """The two are only distinguishable when the policy says enabled -- and then it matters."""
    app = create_app(Orchestrator(storage=_Storage(_run()), run_tool=_run_tool), api_key=API_KEY)
    app.state.argus_config = Config.from_dict({"database": {"url": _CONFIG_DSN}, "ai": {"enabled": True}})
    with TestClient(app) as client:
        diagnostics = client.get(
            f"/api/v1/runs/{RUN_ID}/ai-analysis", headers=_auth()
        ).json()["diagnostics"]
    assert diagnostics == {"enabled": True, "wired": False, "status": "unwired"}


def test_diagnostics_say_no_pass_yet_before_the_first_pass():
    with _client(_run(), hook=SimpleNamespace(last_result=None)) as client:
        diagnostics = client.get(
            f"/api/v1/runs/{RUN_ID}/ai-analysis", headers=_auth()
        ).json()["diagnostics"]
    assert diagnostics["status"] == "no_pass_yet"
    assert diagnostics["wired"] is True


def test_diagnostics_report_the_hook_status_verbatim():
    app = create_app(Orchestrator(storage=_Storage(_run()), run_tool=_run_tool), api_key=API_KEY)
    app.state.argus_analysis_hook = SimpleNamespace(
        last_result=SimpleNamespace(
            status=ANALYSIS_NO_PROPOSALS, uncovered_without_capability=["subdomains", "asn"]
        )
    )
    with TestClient(app) as client:
        diagnostics = client.get(
            f"/api/v1/runs/{RUN_ID}/ai-analysis", headers=_auth()
        ).json()["diagnostics"]
    assert diagnostics["status"] == ANALYSIS_NO_PROPOSALS
    assert diagnostics["uncovered_without_capability"] == ["asn", "subdomains"]


def test_diagnostics_report_the_configured_loop_budget():
    with _client(_run(), max_loop_passes=7) as client:
        diagnostics = client.get(
            f"/api/v1/runs/{RUN_ID}/ai-analysis", headers=_auth()
        ).json()["diagnostics"]
    assert diagnostics["max_loop_passes"] == 7


def test_diagnostics_never_carry_exception_text():
    """A failure is reported as a bounded state; the detail stays in the log."""
    app = create_app(Orchestrator(storage=_Storage(_run()), run_tool=_run_tool), api_key=API_KEY)
    app.state.argus_analysis_hook = SimpleNamespace(
        last_result=SimpleNamespace(
            status=ANALYSIS_PASS_FAILED,
            error="RuntimeError: password=hunter2 host=db.internal",
            uncovered_without_capability=(),
        )
    )
    with TestClient(app) as client:
        raw = client.get(f"/api/v1/runs/{RUN_ID}/ai-analysis", headers=_auth()).text
    assert "hunter2" not in raw
    assert "db.internal" not in raw
    assert json.loads(raw)["diagnostics"]["status"] == ANALYSIS_PASS_FAILED


def test_every_reported_status_is_from_the_bounded_vocabulary():
    assert ANALYSIS_STATUSES == {
        ANALYSIS_CAPABILITY_UNAVAILABLE,
        ANALYSIS_CONTEXT_FAILED,
        ANALYSIS_NO_PROPOSALS,
        ANALYSIS_PROPOSED,
        ANALYSIS_PASS_FAILED,
        "coverage_unavailable",
    }


def test_the_status_vocabulary_and_the_hook_statuses_are_the_same_set():
    """A hook cannot invent a diagnostic the API would then have to trust."""
    from ai.loop import AnalysisResult

    default = AnalysisResult()
    assert default.status in ANALYSIS_STATUSES
    assert default.ran is True
    for status in (ANALYSIS_CAPABILITY_UNAVAILABLE, ANALYSIS_CONTEXT_FAILED, ANALYSIS_PASS_FAILED):
        assert AnalysisResult(status=status).ran is False


# ---------------------------------------------------------------------------
# a storage with no analysis read degrades honestly
# ---------------------------------------------------------------------------


def test_a_storage_with_no_analysis_read_returns_an_empty_list_not_an_error():
    class _Bare(_Storage):
        list_ai_analysis = None  # not callable, like a storage predating Phase 16

    orch = Orchestrator(storage=_Bare(_run()), run_tool=_run_tool)
    with TestClient(create_app(orch, api_key=API_KEY)) as client:
        body = client.get(f"/api/v1/runs/{RUN_ID}/ai-analysis", headers=_auth()).json()
    assert body == {
        "run_id": str(RUN_ID),
        "count": 0,
        "ai_analysis": [],
        "diagnostics": body["diagnostics"],
    }


# ---------------------------------------------------------------------------
# the reports
# ---------------------------------------------------------------------------


def _report(**kw):
    return json_report.build_report(run=_run(), **kw)


def test_the_json_report_carries_the_analysis_section():
    report = _report(ai_analysis=[{"id": str(uuid4()), "created_at": "2026-01-01T00:00:00"}])
    assert isinstance(report["ai_analysis"], list)
    assert len(report["ai_analysis"]) == 1


def test_an_absent_analysis_read_omits_the_section_entirely():
    """A caller with no analysis store must not be reported as a run that found nothing."""
    assert "ai_analysis" not in _report()


def test_an_empty_analysis_list_is_reported_as_an_explicit_empty_section():
    """Different claim from "no store": analysed, proposed nothing."""
    assert _report(ai_analysis=[])["ai_analysis"] == []


def test_the_analysis_section_is_never_merged_into_findings():
    report = _report(
        ai_analysis=[{"id": str(uuid4()), "truth_label": "VALIDATED_FINDING", "created_at": "x"}]
    )
    assert report["validated_findings"] == []
    assert report["hypotheses"] == []
    assert report["ai_analysis"][0]["truth_label"] == "VALIDATED_FINDING"


def test_the_analysis_section_is_ordered_deterministically():
    rows = [{"id": str(i), "created_at": f"2026-01-0{i}"} for i in (3, 1, 2)]
    first = _report(ai_analysis=list(rows))["ai_analysis"]
    second = _report(ai_analysis=list(reversed(rows)))["ai_analysis"]
    assert [r["id"] for r in first] == ["1", "2", "3"] == [r["id"] for r in second]


def test_the_markdown_report_renders_the_analysis_section():
    text = markdown_report.render(
        _report(ai_analysis=[{"id": "a1", "created_at": "x", "proposal_type": "recon_stage_proposal",
                              "truth_label": "INFERENCE", "agent_name": "recon_agent",
                              "model_used": "rule-based", "target": "example.com",
                              "evidence": ["e1", "e2"]}])
    )
    assert "# AI Analysis" in text
    assert "a1" in text and "recon_stage_proposal" in text and "INFERENCE" in text
    assert "evidence=[e1, e2]" in text


def test_the_markdown_report_says_so_when_the_analysis_found_nothing():
    text = markdown_report.render(_report(ai_analysis=[]))
    assert "# AI Analysis" in text
    assert "No AI analysis recorded" in text


def test_the_markdown_report_omits_the_section_when_there_is_no_store():
    assert "# AI Analysis" not in markdown_report.render(_report())


def test_a_multiline_proposal_cannot_break_the_markdown_list_structure():
    text = markdown_report.render(
        _report(ai_analysis=[{"id": "a1", "created_at": "x", "agent_name": "a\n- injected",
                              "model_used": "m"}])
    )
    assert "\n- injected" not in text
    assert "a - injected" in text


def test_the_html_report_renders_the_analysis_section():
    html = html_report.render(
        _report(ai_analysis=[{"id": "a1", "created_at": "x", "proposal_type": "recon",
                              "truth_label": "INFERENCE", "agent_name": "recon_agent",
                              "model_used": "rule-based"}])
    )
    assert '<section id="ai_analysis">' in html
    assert "a1" in html and "INFERENCE" in html


def test_the_html_report_escapes_proposal_content():
    html = html_report.render(
        _report(ai_analysis=[{"id": "<script>alert(1)</script>", "created_at": "x"}])
    )
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_all_three_renderers_project_the_same_section():
    report = _report(ai_analysis=[{"id": "a1", "created_at": "x", "agent_name": "recon_agent"}])
    assert len(report["ai_analysis"]) == 1
    assert "a1" in markdown_report.render(report)
    assert "a1" in html_report.render(report)
    assert json.loads(json_report.render(report))["ai_analysis"] == report["ai_analysis"]


# ---------------------------------------------------------------------------
# the served report carries the section
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["json", "markdown", "html"])
def test_the_served_report_includes_the_analysis_section(fmt):
    with _client(_run(), [_analysis()]) as client:
        response = client.get(
            f"/api/v1/runs/{RUN_ID}/reports/{fmt}", headers=_auth()
        )
    assert response.status_code == 200, response.text
    body = response.text
    if fmt == "json":
        assert len(json.loads(body)["ai_analysis"]) == 1
    elif fmt == "markdown":
        assert "# AI Analysis" in body
    else:
        assert '<section id="ai_analysis">' in body


# ---------------------------------------------------------------------------
# ai.max_loop_passes
# ---------------------------------------------------------------------------


def test_the_loop_budget_defaults_to_the_pre_existing_value():
    assert AiConfig().max_loop_passes == 32
    assert AiConfig.from_dict({}).max_loop_passes == 32
    assert AiConfig.from_dict({"enabled": True}).max_loop_passes == 32


def test_the_loop_budget_is_configurable():
    assert AiConfig.from_dict({"max_loop_passes": 5}).max_loop_passes == 5


@pytest.mark.parametrize("value", [0, -1])
def test_a_non_positive_loop_budget_is_rejected(value):
    with pytest.raises(ConfigError):
        AiConfig.from_dict({"max_loop_passes": value})


@pytest.mark.parametrize("value", [2.5, "8"])
def test_a_loop_budget_that_is_not_a_whole_number_is_rejected(value):
    """``int(3.5)`` would silently become 3 -- a budget the operator did not mean."""
    with pytest.raises(ConfigError):
        AiConfig.from_dict({"max_loop_passes": value})


def test_the_loop_budget_is_reported_in_the_configuration():
    assert Config.from_dict({"database": {"url": _CONFIG_DSN}, "ai": {"max_loop_passes": 9}}).to_dict()["ai"][
        "max_loop_passes"
    ] == 9


def test_the_loop_budget_is_not_recorded_per_run():
    """Process-level policy: the budget is fixed at composition, so a snapshot value that the
    run does not enforce would be a lie."""
    snapshot = run_snapshot_from_dict(
        {"database": {"url": _CONFIG_DSN}, "ai": {"max_loop_passes": 9}}
    )
    assert "max_loop_passes" not in snapshot.get("ai", {})


# ---------------------------------------------------------------------------
# compatibility
# ---------------------------------------------------------------------------


def test_every_pre_existing_build_report_caller_is_unaffected():
    """An ``attack_surface``-less, ``ai_analysis``-less report keeps its exact previous shape."""
    report = json_report.build_report(run=_run())
    assert "ai_analysis" not in report
    assert "attack_surface" not in report
    assert set(report) == {
        "run", "assets", "tasks", "tool_runs", "dedup", "schema_version",
        "evidence_count", "generator",
        "hypotheses", "validated_findings", "evidence",
    }


def test_the_analysis_entity_defaults_to_unattributed():
    """Legacy rows must stay honestly un-attributed rather than defaulting to a fabricated run."""
    assert AiAnalysis().run_id is None
    assert AiAnalysis(run_id=RUN_ID).run_id is RUN_ID
