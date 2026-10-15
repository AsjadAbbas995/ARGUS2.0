"""Phase 18: AI coverage gaps - live PostgreSQL tests (5433 fixture).

Gated on ``ARGUS_TEST_DATABASE_URL``; the module skips when it is unset. Follows
the established live-test conventions (``tests/test_phase17_live.py``,
``tests/test_phase21_live.py``): reset to the fully migrated schema through the
migration runner, then read back through a direct ``psycopg`` connection using
the ``dict_row`` factory -- never through ``DatabaseConnection``, which is a
connection *wrapper* rather than a DBAPI connection and exposes no ``cursor``,
``execute`` or ``commit``.
"""

from __future__ import annotations

import os

import psycopg
import pytest
from psycopg.rows import dict_row

from database import migrate

pytestmark = pytest.mark.skipif(
    not os.environ.get("ARGUS_TEST_DATABASE_URL"),
    reason="set ARGUS_TEST_DATABASE_URL=postgresql://argus@127.0.0.1:5433/argus_test to run live tests",
)


def _url() -> str:
    return os.environ["ARGUS_TEST_DATABASE_URL"]


def _ensure_schema() -> None:
    """Reset the schema to the fully migrated state through the migration runner.

    ``revert(..., 0)`` drops every applied object via its down migration, and
    ``apply`` then brings the schema up to the current head -- including ``0006``,
    which creates ``ai_coverage_gaps``. The connection is closed before the
    verification opens its own, so the two never share a session.
    """
    conn = psycopg.connect(_url(), row_factory=dict_row)
    try:
        migrate.revert(conn, 0)
        migrate.apply(conn)
    finally:
        conn.close()


def test_migration_up_creates_ai_coverage_gaps() -> None:
    _ensure_schema()
    conn = psycopg.connect(_url(), row_factory=dict_row)
    try:
        columns = [
            row["column_name"]
            for row in conn.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'ai_coverage_gaps'
                ORDER BY ordinal_position
                """
            ).fetchall()
        ]
    finally:
        conn.close()
    assert "run_id" in columns
    assert "stage" in columns
    assert "observation_count" in columns
