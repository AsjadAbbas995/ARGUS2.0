"""Serve seam for ARGUS (Phase 13).

Wires the committed ``Orchestrator`` + the committed PostgreSQL-backed
``Repositories`` implementation of the ``Storage`` contract + the committed
``DnsResolverAdapter`` into the committed ``create_app`` factory, so the API can
be served against the authoritative store from ``05_DATA_MODEL.md``.

API key precedence:
  1. ``ARGUS_API_KEY`` environment variable
  2. the ``api_key`` argument (used by ``create_serve_app``)
  3. the committed default ``_API_KEY = "phase-10"`` from ``api.server``

Storage precedence:
  1. an explicitly injected ``storage`` (tests / embedding)
  2. PostgreSQL via ``ARGUS_DATABASE_URL`` (or ``database_url=``) -- production
  3. ``in_memory=True`` -- an explicit, opt-in development mode only

There is deliberately **no** silent fallback to ``MemoryStorage``: if
``ARGUS_DATABASE_URL`` is unset, production startup fails loudly instead of
serving an unauditable, non-durable store. ``MemoryStorage`` remains a test
double implementing the same ``Storage`` contract.

The factory is uvicorn-``--factory`` compatible (zero-argument callable
returning a ``FastAPI`` instance); it constructs the whole injection graph so
``api/server.py`` never needs to know how storage/adapters are built.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from api.server import _API_KEY, create_app
from core.config import ScopeConfig
from core.memory_storage import MemoryStorage
from core.orchestrator import Orchestrator
from core.scope_guard import ScopeGuard, ScopeRule, ScopeRuleType
from core.tool_runner import ToolRunner, ToolRunnerError
from database.models.entities import ToolRun
from recon.dns.resolver import DnsResolverAdapter, make_resolver

#: Environment variable holding the PostgreSQL URL for the served runtime. Same
#: variable name ``core.config.DatabaseConfig`` already reads.
DATABASE_URL_ENV = "ARGUS_DATABASE_URL"


class ServeConfigurationError(RuntimeError):
    """Raised when the serve seam cannot build a production storage backend."""


#: Inject the DNS resolution outcome into an ``Orchestrator.run_tool`` seam.
def _dns_run_tool(
    task,
    resolver_fn=None,
    timeout: float = 3.0,
    *,
    runner: Optional[ToolRunner] = None,
    config=None,
    scope: Optional[ScopeGuard] = None,
) -> ToolRun:
    adapter = DnsResolverAdapter(
        resolver_fn=resolver_fn or make_resolver(timeout=timeout),
        timeout=timeout,
    )
    execution = adapter.execute(
        task,
        runner=runner if runner is not None else ToolRunner(),
        config=config,
        scope=scope if scope is not None else ScopeGuard.from_config(ScopeConfig()),
    )
    return ToolRun(
        task_id=task.id,
        tool_name=execution.tool,
        command=list(execution.command),
        exit_code=execution.exit_code,
        raw_output_ref=execution.raw_output_ref,
    )


def _postgres_storage(database_url: Optional[str]):
    """Build the production ``Storage``: a migrated PostgreSQL repository facade.

    Migrations are applied here because the committed CLI is still a no-op, so
    this is the only entry point that can bring a fresh database up to the
    committed schema. ``ensure_migrated`` is idempotent.
    """
    if not database_url:
        raise ServeConfigurationError(
            f"production serve requires PostgreSQL: set {DATABASE_URL_ENV} (or pass "
            f"database_url=). In-memory storage is available only via the explicit "
            f"in_memory=True development flag; it is never selected implicitly."
        )

    from database.migrate import ensure_migrated
    from database.repositories.all import Repositories
    from database.repositories.base import DatabaseConnection

    connection = DatabaseConnection(database_url)
    raw = connection.connect()
    try:
        ensure_migrated(raw)
    except Exception:
        connection.close()
        raise
    return Repositories(raw)


def create_serve_app(
    *,
    api_key: Optional[str] = None,
    storage=None,
    resolver_fn=None,
    database_url: Optional[str] = None,
    in_memory: bool = False,
) -> "object":
    """Build the fully-wired FastAPI app for serving ARGUS.

    ``api_key`` is used when ``ARGUS_API_KEY`` is unset, otherwise the committed
    server default is used. ``storage``/``resolver_fn`` are optional injection
    points for tests. With neither ``storage`` nor ``in_memory``, the app is
    backed by PostgreSQL (``database_url`` or ``ARGUS_DATABASE_URL``) and refuses
    to start if no database is configured.
    """
    effective_key = os.environ.get("ARGUS_API_KEY") or api_key or _API_KEY
    if storage is not None:
        store = storage
    elif in_memory:
        store = MemoryStorage()
    else:
        store = _postgres_storage(database_url or os.environ.get(DATABASE_URL_ENV))
    orch = Orchestrator(
        storage=store,
        run_tool=lambda task: _dns_run_tool(task, resolver_fn=resolver_fn),
    )
    return create_app(orch, api_key=effective_key)


def serve_factory() -> "object":
    """uvicorn ``--factory`` entrypoint: zero-arg callable -> FastAPI app."""
    return create_serve_app()
