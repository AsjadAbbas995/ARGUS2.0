"""Serve seam for ARGUS (Phase 13).

Wires the committed ``Orchestrator`` + committed ``MemoryStorage`` + committed
``DnsResolverAdapter`` into the committed ``create_app`` factory so the API can
be served with a real in-process storage and a real (in-process) DNS tool.

API key precedence:
  1. ``ARGUS_API_KEY`` environment variable
  2. the ``api_key`` argument (used by ``create_serve_app``)
  3. the committed default ``_API_KEY = "phase-10"`` from ``api.server``

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


def create_serve_app(
    *,
    api_key: Optional[str] = None,
    storage=None,
    resolver_fn=None,
) -> "object":
    """Build the fully-wired FastAPI app for serving ARGUS.

    ``api_key`` is used when ``ARGUS_API_KEY`` is unset, otherwise the committed
    server default is used. ``storage``/``resolver_fn`` are optional injection points
    for tests; defaults use committed ``MemoryStorage`` and the committed in-process DNS
    adapter.
    """
    from core.memory_storage import MemoryStorage as _MS
    from core.orchestrator import Orchestrator as _Orch
    from api.server import create_app as _create

    effective_key = os.environ.get("ARGUS_API_KEY") or api_key or _API_KEY
    mem = storage if storage is not None else _MS()
    orch = _Orch(
        storage=mem,
        run_tool=lambda task: _dns_run_tool(task, resolver_fn=resolver_fn),
    )
    return _create(orch, api_key=effective_key)


def serve_factory() -> "object":
    """uvicorn ``--factory`` entrypoint: zero-arg callable -> FastAPI app."""
    return create_serve_app()
