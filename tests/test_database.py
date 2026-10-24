"""Step 3 tests.

The conformance tests below require no live database: they statically verify
that the migration SQL (``0001_initial_schema.sql`` plus any table created by a
later migration) and the entity models match the authoritative
``docs/05_DATA_MODEL.md`` table-for-table and column-for-column. Live-DB tests
are conditional and skip when no PostgreSQL is reachable (see conftest.py).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from database.models.entities import (
    Asset,
    AssetIp,
    DnsRecord,
    Evidence,
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
from database.migrate import migration_files, version_of

DOC_PATH = Path(__file__).resolve().parents[1] / "docs" / "05_DATA_MODEL.md"
SQL_PATH = (
    Path(__file__).resolve().parents[1]
    / "database"
    / "migrations"
    / "0001_initial_schema.sql"
)

DOC_TABLES = [
    "organizations",
    "programs",
    "runs",
    "scope_rules",
    "assets",
    "dns_records",
    "ips",
    "asset_ips",
    "ports",
    "technologies",
    "asset_technologies",
    "web_apps",
    "urls",
    "endpoints",
    "parameters",
    "javascript_files",
    "apis",
    "graphql_operations",
    "websocket_endpoints",
    "auth_mechanisms",
    "hypotheses",
    "evidence",
    "tasks",
    "tool_runs",
    "ai_analysis",
    "ai_coverage_gaps",
]

DOC_COLUMNS: dict[str, list[str]] = {
    "organizations": ["id", "name", "created_at"],
    "programs": ["id", "organization_id", "name", "status"],
    "runs": [
        "id",
        "program_id",
        "status",
        "target",
        "configuration_snapshot",
        "started_at",
        "completed_at",
        "created_at",
        "updated_at",
        "loop_pass",
        "pass_new_tasks",
    ],
    "scope_rules": ["id", "program_id", "rule_type", "value", "allowed"],
    "assets": ["id", "program_id", "hostname", "source", "discovered_at"],
    "dns_records": ["id", "asset_id", "record_type", "value", "resolved_at"],
    "ips": ["id", "address", "first_seen"],
    "asset_ips": ["asset_id", "ip_id", "observed_at"],
    "ports": ["id", "ip_id", "port_number", "protocol", "state", "service", "version"],
    "technologies": ["id", "name", "category"],
    "asset_technologies": [
        "asset_id",
        "technology_id",
        "confidence",
        "evidence_id",
    ],
    "web_apps": ["id", "asset_id", "port_id", "status_code", "title", "server_header"],
    "urls": ["id", "web_app_id", "path", "source", "historical"],
    "endpoints": ["id", "url_id", "method", "pattern"],
    "parameters": ["id", "endpoint_id", "name", "location", "significance"],
    "javascript_files": ["id", "web_app_id", "url", "has_source_map"],
    "apis": ["id", "web_app_id", "api_type", "documented"],
    "graphql_operations": ["id", "api_id", "operation_type", "name"],
    "websocket_endpoints": ["id", "web_app_id", "url", "auth_mechanism_id"],
    "auth_mechanisms": ["id", "web_app_id", "mechanism_type", "details"],
    "hypotheses": [
        "id",
        "endpoint_id",
        "statement",
        "truth_label",
        "confidence",
        "severity",
        "priority",
        "status",
        "run_id",
        "target",
        "validation_step",
        "review_status",
        "review_reason",
    ],
    "evidence": ["id", "tool_run_id", "entity_type", "entity_id", "raw_reference"],
    "tasks": [
        "id",
        "run_id",
        "type",
        "target",
        "parent_task_id",
        "priority",
        "status",
        "fingerprint",
        "reason",
        "created_at",
        "started_at",
        "completed_at",
    ],
    "tool_runs": [
        "id",
        "task_id",
        "tool_name",
        "command",
        "exit_code",
        "started_at",
        "completed_at",
        "raw_output_ref",
    ],
    "ai_analysis": [
        "id",
        # Phase 17, migration 0005: the run that owns this analysis. Nullable in the
        # column so a populated legacy table upgrades without rewriting history, and
        # enforced NOT NULL on new writes by ``ai_analysis_run_id_required_check``;
        # a row migration 0005 could not attribute keeps NULL and stays invisible to
        # every run-scoped read. Discovered automatically from the migration by
        # ``_columns_added_by_later_migrations`` -- listed here because the documented
        # schema is the post-migration schema.
        "run_id",
        "agent_name",
        "model_used",
        "input_context_ref",
        "output",
        "created_at",
    ],
    "ai_coverage_gaps": [
        "id",
        "run_id",
        "stage",
        "first_seen_at",
        "last_seen_at",
        "observation_count",
    ],
}

MODEL_CLASSES = {
    "organizations": Organization,
    "programs": Program,
    "runs": Run,
    "scope_rules": ScopeRule,
    "assets": Asset,
    "dns_records": DnsRecord,
    "ips": Ip,
    "asset_ips": AssetIp,
    "ports": Port,
    "web_apps": WebApp,
    "tasks": Task,
    "tool_runs": ToolRun,
    "evidence": Evidence,
    # ``hypotheses`` belongs here: migration 0002 widened it, and while it was
    # missing from this map the entity<->doc check could not catch the
    # documentation drift that followed.
    "hypotheses": Hypothesis,
}


def _table_sql(table: str) -> str:
    """Body of the ``CREATE TABLE`` for ``table``, from whichever migration defines it.

    Most tables come from the initial schema, but tables added by later migrations
    (e.g. ``ai_coverage_gaps``) are also found.
    """
    for path in migration_files():
        match = re.search(
            rf"CREATE TABLE IF NOT EXISTS {table} \((.*?)\)\s*;",
            path.read_text(encoding="utf-8"),
            re.S,
        )
        if match is not None:
            return match.group(1)
    raise AssertionError(f"CREATE TABLE {table} not found in any migration")


def _columns_added_by_later_migrations(table: str) -> set[str]:
    """Columns later migrations add to ``table`` (``ALTER TABLE ... ADD COLUMN``).

    The documented schema is the schema *after every migration*, not the 0001
    shape, so these must be folded into the SQL comparison below. Migrations that
    drop or rename columns are not handled here and would need this extended.
    """
    added: set[str] = set()
    for path in migration_files():
        if path.name.startswith("0001_"):
            continue
        sql = path.read_text(encoding="utf-8")
        for statement in re.findall(
            rf"ALTER TABLE\s+{table}\s+(.*?);", sql, re.S | re.I
        ):
            for match in re.finditer(
                r"ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)", statement, re.I
            ):
                added.add(match.group(1))
    return added


@pytest.mark.parametrize("table", DOC_TABLES)
def test_every_documented_table_exists_in_sql(table: str) -> None:
    for path in migration_files():
        if f"CREATE TABLE IF NOT EXISTS {table} (" in path.read_text(encoding="utf-8"):
            return
    pytest.fail(f"{table} is documented but no migration creates it")


@pytest.mark.parametrize("table", DOC_TABLES)
def test_sql_has_exactly_documented_columns(table: str) -> None:
    fragment = _table_sql(table)
    expected = DOC_COLUMNS[table]
    defined = {
        name
        for name in re.findall(r"(?m)^\s*(\w+)\s+\w", fragment)
        if name not in {"PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"}
    }
    defined |= _columns_added_by_later_migrations(table)
    assert defined == set(expected), (
        f"{table}: SQL columns {defined ^ set(expected)} differ from doc"
    )


@pytest.mark.parametrize("table", list(MODEL_CLASSES))
def test_model_fields_match_doc_columns(table: str) -> None:
    model = MODEL_CLASSES[table]
    fields = set(model.__dataclass_fields__)
    doc_cols = set(DOC_COLUMNS[table])
    assert fields == doc_cols, f"{model.__name__}: {fields ^ doc_cols}"


def test_migration_files_are_sorted_and_versioned() -> None:
    files = migration_files()
    assert files, "no migration files found"
    versions = [version_of(p) for p in files]
    assert versions == sorted(versions)
    assert len(versions) == len(set(versions)), "duplicate migration versions"
    assert files[0].name.startswith("0001_")


def test_every_up_migration_has_down_pair() -> None:
    up = migration_files()
    for path in up:
        assert path.with_name(path.stem + ".down.sql").exists(), (
            f"{path.name} has no .down.sql revert"
        )
    assert version_of(up[0]) == 1


def test_no_stray_tables_in_sql() -> None:
    sql = SQL_PATH.read_text(encoding="utf-8")
    defined = re.findall(r"CREATE TABLE IF NOT EXISTS (\w+) \(", sql)
    documented = set(DOC_TABLES)
    extras = set(defined) - documented
    assert extras == {"schema_migrations"}, f"unexpected SQL tables: {extras}"
    assert "schema_migrations" in defined