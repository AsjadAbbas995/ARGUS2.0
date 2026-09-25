"""Deterministic SQL migration runner.

Applies ``database/migrations/*.sql`` in lexical (version) order, recording each
applied version in ``schema_migrations``. Revert files are named
``<version>_<name>.down.sql`` and drop objects in reverse dependency order.

Gate: a migration either fully applies or fully reverts; each file runs inside
its own transaction.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import psycopg
from psycopg.rows import dict_row

from core.config import Config

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


class MigrationError(RuntimeError):
    """Raised when a migration cannot be applied cleanly."""


def migration_files(directory: Path = MIGRATIONS_DIR) -> list[Path]:
    up = sorted(
        p for p in directory.glob("*.sql") if not p.name.endswith(".down.sql")
    )
    return up


def version_of(path: Path) -> int:
    return int(path.name.split("_", 1)[0])


def _row_value(row, key: str, index: int = 0):
    """Read one column from a result row under either psycopg row factory.

    ``apply``/``revert`` are called both with a plain tuple-row connection (the
    test fixtures) and with the dict-row connection ``DatabaseConnection`` hands
    to ``Repositories``, so bookkeeping must not assume one of them.
    """
    if row is None:
        return None
    if isinstance(row, dict):
        return row.get(key)
    return row[index]


def _schema_migrations_exists(conn: psycopg.Connection) -> bool:
    # Unqualified, exactly like every other bookkeeping query here, so the guard
    # follows the connection's search_path instead of assuming ``public``.
    row = conn.execute("SELECT to_regclass('schema_migrations')").fetchone()
    return bool(_row_value(row, "to_regclass"))


def _applied_versions(conn: psycopg.Connection) -> set[int]:
    cur = conn.execute(
        "SELECT version FROM schema_migrations ORDER BY version"
    )
    return {_row_value(row, "version") for row in cur.fetchall()}


def _flush(conn: psycopg.Connection) -> None:
    """Commit any implicit transaction opened by a bookkeeping statement.

    This is load-bearing, not tidiness. On a non-autocommit connection every
    statement implicitly opens a transaction, and psycopg3 silently downgrades
    ``conn.transaction()`` to a SAVEPOINT when one is already open. Exiting that
    block then only RELEASEs the savepoint: the migration DDL is never committed,
    its locks stay held, and a connection that closes afterwards (the CLI's
    ``with connect(...)``) rolls the whole migration back. Committing first
    guarantees the following ``conn.transaction()`` is a real transaction.
    """
    if not conn.autocommit:
        conn.commit()


def apply(conn: psycopg.Connection, directory: Path = MIGRATIONS_DIR) -> list[int]:
    """Apply all pending migrations, returning the versions applied."""
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " version integer PRIMARY KEY,"
            " name text NOT NULL,"
            " applied_at timestamptz NOT NULL DEFAULT now())"
        )
    except psycopg.Error as exc:
        raise MigrationError(f"cannot create schema_migrations: {exc}") from exc
    _flush(conn)

    applied = _applied_versions(conn)
    versions = []
    for path in migration_files(directory):
        version = version_of(path)
        if version in applied:
            continue
        try:
            _flush(conn)
            with conn.transaction():
                conn.execute(path.read_text(encoding="utf-8"))
                conn.execute(
                    "INSERT INTO schema_migrations (version, name) VALUES (%s, %s)",
                    (version, path.name),
                )
        except psycopg.Error as exc:
            raise MigrationError(f"migration {path.name} failed: {exc}") from exc
        versions.append(version)
    return versions


def revert(
    conn: psycopg.Connection,
    target_version: int = 0,
    directory: Path = MIGRATIONS_DIR,
) -> list[int]:
    """Revert applied migrations back to ``target_version`` (default: none).

    Returns the list of versions reverted, in reverse version order.

    ``schema_migrations`` is kept consistent with the schema it describes: a
    reverted version's bookkeeping row is removed in the same transaction as
    its down file, so a later ``apply`` re-runs that migration instead of
    reporting a version whose columns no longer exist. A database that has never
    been migrated has nothing to revert and yields ``[]``.
    """
    if not _schema_migrations_exists(conn):
        return []
    applied = sorted(_applied_versions(conn))
    to_revert = [v for v in applied if v > target_version]
    reverted: list[int] = []
    for version in reversed(to_revert):
        candidates = [
            p
            for p in directory.glob(f"{version:04d}_*.down.sql")
        ]
        if not candidates:
            raise MigrationError(
                f"no down migration found for version {version}"
            )
        down = candidates[0]
        try:
            _flush(conn)
            with conn.transaction():
                # Delete the bookkeeping row *before* running the down file:
                # 0001's down migration drops schema_migrations itself, and a
                # reverted version must never be left recorded as applied.
                conn.execute(
                    "DELETE FROM schema_migrations WHERE version = %s", (version,)
                )
                conn.execute(down.read_text(encoding="utf-8"))
        except psycopg.Error as exc:
            raise MigrationError(f"revert {down.name} failed: {exc}") from exc
        reverted.append(version)
    return reverted


def ensure_migrated(conn: psycopg.Connection) -> list[int]:
    """Apply pending migrations; idempotent."""
    return apply(conn)


def connect(url: str) -> psycopg.Connection:
    """Open a psycopg connection (row factory: dict)."""
    return psycopg.connect(url, row_factory=dict_row)


def migrate_from_config(config: Config) -> list[int]:
    """Convenience: connect from parsed config and apply pending migrations."""
    with connect(config.database.url) as conn:
        return apply(conn)