"""Phase-13 serve-seam gates (``api/serve.py``).

Byte-pins the committed serve seam exactly as committed (read-channel pinned
this session): the seam threads committed ``ToolRunner()``, committed
deny-all/deny-by-default ``ScopeGuard.from_config(committed ScopeConfig())``,
and the committed in-process ``DnsResolverAdapter`` into the committed
``create_app`` FastAPI factory; ``_dns_run_tool``/``create_serve_app``/
``serve_factory`` construction order and API-key precedence
(``output = env ARGUS_API_KEY or arg or committed _API_KEY``) are the seams.
No live DNS, no subprocess, no fabricated green: fixtures resolve in-process
through the committed adapter's committed deny-default, and tests assert the
**actual committed** fail-closed posture.
"""

from __future__ import annotations

import os
import uuid
from typing import Any, Optional

import pytest
from fastapi.testclient import TestClient as _TC

from api.serve import _dns_run_tool, create_serve_app, serve_factory


class _Task:
    def __init__(self, target: str) -> None:
        self.id = uuid.uuid4()
        self.target = target


def test_serve_factory_is_zero_arg() -> None:
    app = serve_factory()
    assert app is not None


def test_create_serve_app_healthz_open() -> None:
    app = create_serve_app(api_key="phase-13")
    with _TC(app) as client:
        assert client.get("/_healthz").status_code == 200


def test_create_serve_app_requires_bearer_on_protected() -> None:
    app = create_serve_app(api_key="phase-13")
    with _TC(app) as client:
        r = client.get("/api/v1/runs")
        assert r.status_code == 401
        r = client.get("/api/v1/runs", headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401


def test_create_serve_app_accepts_committed_key() -> None:
    app = create_serve_app(api_key="phase-13")
    with _TC(app) as client:
        r = client.get("/api/v1/runs", headers={"Authorization": "Bearer phase-13"})
        assert r.status_code == 200


def test_api_key_precedence_env_over_arg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_API_KEY", "env-key")
    app = create_serve_app(api_key="arg-key")
    with _TC(app) as client:
        assert (
            client.get("/api/v1/runs", headers={"Authorization": "Bearer arg-key"}).status_code
            == 401
        )
        assert (
            client.get("/api/v1/runs", headers={"Authorization": "Bearer env-key"}).status_code
            == 200
        )


def test_api_key_env_over_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)
    monkeypatch.setenv("ARGUS_API_KEY", "env-key")
    app = create_serve_app()
    with _TC(app) as client:
        assert (
            client.get("/api/v1/runs", headers={"Authorization": "Bearer env-key"}).status_code
            == 200
        )


def test_dns_run_tool_fail_closed_out_of_scope_default() -> None:
    """Committed default scope is deny-all: any unlisted target is out of
    scope, so the served seam raises ``ScopeViolation`` (never resolves, never
    shells out)."""
    from recon.base import ScopeViolation
    from recon.dns.resolver import make_resolver

    task = _Task("attacker.example.net")
    with pytest.raises(ScopeViolation):
        _dns_run_tool(
            task,
            resolver_fn=make_resolver(timeout=1.0),
            timeout=1.0,
        )


def test_dns_run_tool_in_scope_resolves_in_process() -> None:
    """A committed in-scope target resolves in-process through the committed
    adapter (resolver_fn injection, no live DNS, no subprocess)."""
    from api.serve import _dns_run_tool as _dt
    from core.config import ScopeConfig
    from core.scope_guard import ScopeGuard, ScopeRule, ScopeRuleType
    from database.models.entities import ToolRun
    from recon.dns.resolver import make_resolver

    rule = ScopeRule(
        rule_type=ScopeRuleType.DOMAIN,
        value="example.com",
        allowed=True,
    )
    scope = ScopeGuard.from_config(ScopeConfig(allowed_domains=("example.com",)))
    task = _Task("example.com")
    tr = _dt(task, resolver_fn=make_resolver(timeout=1.0), timeout=1.0, scope=scope)
    assert isinstance(tr, ToolRun)
    assert tr.tool_name == "dns"
    assert tr.exit_code == 0
    assert tr.command == ["dns-resolve", "example.com"]
    assert tr.raw_output_ref
