"""Phase-13 serve-seam gates (``api/serve.py``).

Byte-pins the committed serve seam: the seam threads committed ``ToolRunner()``,
committed deny-all/deny-by-default ``ScopeGuard.from_config(committed ScopeConfig())``,
and the committed in-process ``DnsResolverAdapter`` into the committed
``create_app`` FastAPI factory; ``_dns_run_tool``/``create_serve_app``/
``serve_factory`` construction order and API-key precedence
(``env ARGUS_API_KEY`` else explicit ``api_key``, **no fallback**) are the seams.
No live DNS, no subprocess, no fabricated green: fixtures resolve in-process
through the committed adapter's committed deny-default, and tests assert the
**actual committed** fail-closed posture.

Security posture (Phase 13.1): the served runtime has no committed default
credential. ``test_production_serve_refuses_without_api_key`` and its blank-key
sibling pin that startup fails rather than authenticating on a published
literal.

Storage posture (Stage 1): production ``create_serve_app`` is backed by
PostgreSQL and raises ``ServeConfigurationError`` when no database is
configured. These gates drive the app through the explicit ``in_memory=True``
development flag, and ``test_production_serve_refuses_without_database`` pins
that MemoryStorage is never selected implicitly.
"""

from __future__ import annotations

import inspect
import os
import uuid
from typing import Any, Optional

import pytest
from fastapi.testclient import TestClient as _TC

from api.serve import (
    ServeConfigurationError,
    _dns_run_tool,
    create_serve_app,
    serve_factory,
)


class _Task:
    def __init__(self, target: str) -> None:
        self.id = uuid.uuid4()
        self.target = target


def test_serve_factory_is_zero_arg() -> None:
    assert not inspect.signature(serve_factory).parameters


def test_production_serve_refuses_without_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production storage is PostgreSQL; there is no implicit MemoryStorage."""
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)
    monkeypatch.delenv("ARGUS_DATABASE_URL", raising=False)
    with pytest.raises(ServeConfigurationError) as exc:
        create_serve_app(api_key="phase-13")
    assert "ARGUS_DATABASE_URL" in str(exc.value)
    assert "in_memory=True" in str(exc.value)


def test_create_serve_app_healthz_open() -> None:
    app = create_serve_app(api_key="phase-13", in_memory=True)
    with _TC(app) as client:
        assert client.get("/_healthz").status_code == 200


def test_create_serve_app_requires_bearer_on_protected() -> None:
    app = create_serve_app(api_key="phase-13", in_memory=True)
    with _TC(app) as client:
        r = client.get("/api/v1/runs")
        assert r.status_code == 401
        r = client.get("/api/v1/runs", headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401


def test_create_serve_app_accepts_committed_key() -> None:
    app = create_serve_app(api_key="phase-13", in_memory=True)
    with _TC(app) as client:
        r = client.get("/api/v1/runs", headers={"Authorization": "Bearer phase-13"})
        assert r.status_code == 200


def test_api_key_env_over_explicit_arg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_API_KEY", "env-key")
    app = create_serve_app(api_key="arg-key", in_memory=True)
    with _TC(app) as client:
        assert (
            client.get("/api/v1/runs", headers={"Authorization": "Bearer arg-key"}).status_code
            == 401
        )
        assert (
            client.get("/api/v1/runs", headers={"Authorization": "Bearer env-key"}).status_code
            == 200
        )


def test_production_serve_refuses_without_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 13.1 / F-01: no committed default credential exists.

    ``serve_factory()`` takes no arguments, so the environment is the only place a
    production key can come from. With it unset the served runtime must refuse to
    start rather than fall back to a literal that is published in this repository.
    """
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)
    with pytest.raises(ServeConfigurationError) as exc:
        create_serve_app(in_memory=True)
    assert "ARGUS_API_KEY" in str(exc.value)
    assert "no default credential" in str(exc.value)


def test_blank_api_key_is_treated_as_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty or whitespace-only key is not a way to serve a working API."""
    monkeypatch.setenv("ARGUS_API_KEY", "   ")
    with pytest.raises(ServeConfigurationError):
        create_serve_app(in_memory=True)
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)
    with pytest.raises(ServeConfigurationError):
        create_serve_app(api_key="   ", in_memory=True)


def test_serve_factory_requires_the_environment_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The zero-arg production entrypoint requires ``ARGUS_API_KEY``."""
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)
    with pytest.raises(ServeConfigurationError) as exc:
        serve_factory()
    assert "ARGUS_API_KEY" in str(exc.value)
    # With a key present it gets past authentication and on to storage, so a
    # different (storage) failure is what surfaces -- never the key again.
    monkeypatch.setenv("ARGUS_API_KEY", "env-key")
    monkeypatch.setenv(
        "ARGUS_DATABASE_URL", "postgresql://x:x@127.0.0.1:1/none?connect_timeout=2"
    )
    with pytest.raises(Exception) as exc:
        serve_factory()
    assert "ARGUS_API_KEY" not in str(exc.value)


def test_api_key_env_alone_starts_successfully(monkeypatch: pytest.MonkeyPatch) -> None:
    """Phase 13.1 / F-01: a valid explicit environment key starts and authenticates."""
    monkeypatch.setenv("ARGUS_API_KEY", "env-key")
    app = create_serve_app(in_memory=True)
    assert app.state.argus_api_key == "env-key"
    with _TC(app) as client:
        assert (
            client.get("/api/v1/runs", headers={"Authorization": "Bearer env-key"}).status_code
            == 200
        )
        assert client.get("/api/v1/runs").status_code == 401
        assert (
            client.get(
                "/api/v1/runs", headers={"Authorization": "Bearer wrong-key"}
            ).status_code
            == 401
        )


def test_published_phase10_literal_cannot_authenticate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 13.1 / F-01: the removed ``"phase-10"`` default is not a back door.

    It is a literal anyone with the source can read, and it used to be the
    production key whenever nothing was configured.
    """
    monkeypatch.delenv("ARGUS_API_KEY", raising=False)
    app = create_serve_app(api_key="a-real-key", in_memory=True)
    with _TC(app) as client:
        assert (
            client.get(
                "/api/v1/runs", headers={"Authorization": "Bearer phase-10"}
            ).status_code
            == 401
        )
        assert (
            client.get(
                "/api/v1/runs", headers={"Authorization": "Bearer a-real-key"}
            ).status_code
            == 200
        )


def test_blank_key_app_fails_closed_on_every_protected_route() -> None:
    """Defense in depth: a blank key authenticates nothing, not everything.

    ``create_serve_app`` refuses a blank key outright, so this drives the lower
    level ``create_app`` directly: if an embedder ever constructs one with an
    empty key, every protected route must still reject rather than open.
    """
    from api.server import create_app
    from core.memory_storage import MemoryStorage
    from core.orchestrator import Orchestrator

    def _never_runs(task, scope=None, config=None):  # pragma: no cover - never reached
        raise AssertionError("no task may execute on an unauthenticated app")

    app = create_app(
        Orchestrator(storage=MemoryStorage(), run_tool=_never_runs), api_key=""
    )
    assert app.state.argus_api_key == ""
    with _TC(app) as client:
        for headers in (
            {},
            {"Authorization": "Bearer "},
            {"Authorization": "Bearer anything"},
        ):
            assert client.get("/api/v1/runs", headers=headers).status_code == 401


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
