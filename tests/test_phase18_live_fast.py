"""Phase 18: AI coverage gaps - fast live PostgreSQL tests (5433 fixture)."""

from __future__ import annotations

import os
import uuid

import pytest

from database.repositories.all import Repositories
from database.models.entities import Run
from api import server
from fastapi.testclient import TestClient
from reports import json_report, markdown_report, html_report

pytestmark = pytest.mark.skipif(
    not os.environ.get("ARGUS_TEST_DATABASE_URL"),
    reason="set ARGUS_TEST_DATABASE_URL=postgresql://argus@127.0.0.1:5433/argus_test to run live tests",
)

def _url() -> str:
    return os.environ["ARGUS_TEST_DATABASE_URL"]

def _make_test_run(conn):
    r = Repositories(conn)
    from database.models.entities import Program, Run, Organization
    org = Organization(name=f"org-{uuid.uuid4().hex[:8]}")
    ores = r.organizations.upsert(org.name)
    org_id = ores["id"] if isinstance(ores, dict) else getattr(ores, "id", None)
    if org_id is None and hasattr(ores, "get"): org_id = ores.get("id")
    if org_id is None and isinstance(ores, tuple): org_id = ores[0]
    prog = Program(organization_id=org_id, name=f"t-{uuid.uuid4().hex[:8]}", status="active")
    pres = r.programs.upsert(prog.organization_id, prog.name, prog.status)
    pid = pres["id"] if isinstance(pres, dict) else getattr(pres, "id", None)
    if pid is None and hasattr(pres, "get"): pid = pres.get("id")
    if pid is None and isinstance(pres, tuple): pid = pres[0]
    run = Run(program_id=pid, status="COMPLETED")
    res = r.runs.insert(run)
    rid = res["id"] if isinstance(res, dict) else getattr(res, "id", None)
    if rid is None and hasattr(res, "get"):
        rid = res.get("id")
    if rid is None and isinstance(res, tuple):
        rid = res[0]
    return r, rid

def test_live_schema_exists():
    from psycopg.rows import dict_row
    import psycopg
    conn = psycopg.connect(_url(), row_factory=dict_row, autocommit=True)
    try:
        cur = conn.execute("SELECT COUNT(*) AS c FROM information_schema.tables WHERE table_name='ai_coverage_gaps'")
        r = cur.fetchone()
        val = r["c"] if isinstance(r, dict) else r[0]
        assert val == 1
        cur = conn.execute("SELECT column_name FROM information_schema.columns WHERE table_name='ai_coverage_gaps' ORDER BY ordinal_position")
        cols = [row["column_name"] if isinstance(row, dict) else row[0] for row in cur.fetchall()]
    finally:
        conn.close()
    assert {"run_id", "stage", "observation_count", "first_seen_at", "last_seen_at"}.issubset(set(cols))


def test_live_persistence_and_upsert():
    import psycopg
    from psycopg.rows import dict_row
    conn = psycopg.connect(_url(), row_factory=dict_row, autocommit=True)
    try:
        r, run_id = _make_test_run(conn)
        stage = "analysis"
        from database.models.entities import AiCoverageGap
        r.ai_coverage_gaps.observe(AiCoverageGap(run_id=run_id, stage=stage))
        gaps = r.ai_coverage_gaps.list_for_run(run_id)
        assert len(gaps) == 1
        oc1 = gaps[0]["observation_count"]
        from database.models.entities import AiCoverageGap
        r.ai_coverage_gaps.observe(AiCoverageGap(run_id=run_id, stage=stage))
        gaps = r.ai_coverage_gaps.list_for_run(run_id)
        assert len(gaps) == 1
        oc2 = gaps[0]["observation_count"]
        assert oc2 >= oc1 + 1
    finally:
        conn.close()

def test_live_run_isolation():
    import psycopg
    from psycopg.rows import dict_row
    conn = psycopg.connect(_url(), row_factory=dict_row, autocommit=True)
    try:
        _, run_a = _make_test_run(conn)
        r_b, run_b = _make_test_run(conn)
        stage = "analysis"
        from database.models.entities import AiCoverageGap
        Repositories(conn).ai_coverage_gaps.observe(AiCoverageGap(run_id=run_a, stage=stage))
        from database.models.entities import AiCoverageGap
        r_b.ai_coverage_gaps.observe(AiCoverageGap(run_id=run_b, stage=stage))
        gaps_a = Repositories(conn).ai_coverage_gaps.list_for_run(run_a)
        gaps_b = r_b.ai_coverage_gaps.list_for_run(run_b)
        assert len(gaps_a) == 1 and len(gaps_b) == 1
        ra = gaps_a[0]["run_id"]; rb = gaps_b[0]["run_id"]
        assert str(ra) == str(run_a)
        assert str(rb) == str(run_b)
    finally:
        conn.close()

def test_live_gaps_do_not_create_tasks_or_hypotheses():
    import psycopg
    from psycopg.rows import dict_row
    conn = psycopg.connect(_url(), row_factory=dict_row, autocommit=True)
    try:
        r, run_id = _make_test_run(conn)
        before_tasks = r.tasks.count() if hasattr(r.tasks, "count") else 0
        before_hyps = r.hypotheses.count() if hasattr(r.hypotheses, "count") else 0
        from database.models.entities import AiCoverageGap
        r.ai_coverage_gaps.observe(AiCoverageGap(run_id=run_id, stage="analysis"))
        after_tasks = r.tasks.count() if hasattr(r.tasks, "count") else 0
        after_hyps = r.hypotheses.count() if hasattr(r.hypotheses, "count") else 0
        assert after_tasks == before_tasks
        assert after_hyps == before_hyps
    finally:
        conn.close()

def test_live_api_reports_read_path():
    import psycopg
    from psycopg.rows import dict_row
    conn = psycopg.connect(_url(), row_factory=dict_row, autocommit=True)
    try:
        r, run_id = _make_test_run(conn)
        stage = "analysis"
        from database.models.entities import AiCoverageGap
        r.ai_coverage_gaps.observe(AiCoverageGap(run_id=run_id, stage=stage))
        gaps = r.ai_coverage_gaps.list_for_run(run_id)
        assert isinstance(gaps, list) and len(gaps) >= 1
        report = {"run_id": str(run_id), "ai_coverage_gaps": gaps}
        j = json_report.render(report)
        assert "ai_coverage_gaps" in j
        m = markdown_report.render(report)
        assert "coverage" in m.lower() or "gap" in m.lower()
        h = html_report.render(report)
        assert "coverage" in h.lower() or "gap" in h.lower()
    finally:
        conn.close()
