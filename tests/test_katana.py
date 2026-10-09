"""katana web-crawl adapter fixture tests (``06_TOOL_CONTRACTS.md`` §Katana;
``13_TESTING_STRATEGY.md`` §Adapter Fixture Tests; ``docs/PHASE_22_PROPOSAL.md`` §11).

All parse/scope/command/execution tests drive ``recon.web.katana.KatanaAdapter``
against the recorded JSONL streams under ``tests/fixtures/katana/`` — no live
external target and no Katana binary are ever touched, so CI stays deterministic
and offline.

Covered cases:

- `normal.ndjson` -> four observation kinds (URLs, endpoints, query parameters,
  linked JavaScript) with query-stripped paths and honest ``GET``/``unknown``
  conventions.
- `empty.ndjson` -> no artifacts; `malformed.ndjson` -> valid lines survive,
  malformed/foreign lines skipped non-fatally; `duplicates.ndjson` -> deduplicated
  per kind.
- Normalization: path extraction, query-stripping, default ports for http/https,
  ``.js`` vs ``.js.map``, non-http(s) URLs skipped.
- Scope: out-of-scope host or port -> ``ScopeViolation`` before anything runs.
- Command: ``-u`` seed (from the ``{"url": ...}`` reuse payload or the target),
  ``-jsonl``, ``-js-crawl``, ``-depth``, ``-timeout``, and a ``-cs`` scope regex
  pinned to the seed host.
- Execution: missing binary -> ``ToolUnavailable`` (never a crash); non-zero exit
  preserves partial results; runner timeout is recorded non-fatally.
- Registration: the served composition dispatches ``web_crawl`` and ``katana`` and
  refuses anything else with ``UnknownTaskType``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import pytest

from core.scope_guard import ScopeGuard, ScopeRule, ScopeRuleType
from core.tool_runner import CommandResult, ToolRunner, ToolTimeoutError
from recon.base import ScopeViolation, ToolUnavailable
from recon.web.katana import (
    DEFAULT_DEPTH,
    DEFAULT_OVERALL_TIMEOUT,
    DEFAULT_PER_REQUEST_TIMEOUT,
    EndpointObservation,
    JavascriptFileObservation,
    KatanaAdapter,
    ParameterObservation,
    UrlObservation,
    parse_jsonl,
)

FIXTURES = Path(__file__).parent / "fixtures" / "katana"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _result(stdout: str, exit_code: int = 0) -> CommandResult:
    return CommandResult(
        tool="katana",
        command=["katana", "-u", "http://www.example.com:8080/", "-jsonl"],
        stdout=stdout,
        stderr="",
        exit_code=exit_code,
        timed_out=False,
        raw_output_ref="storage/raw/katana/fixture.out",
    )


class _Task:
    def __init__(
        self,
        target: str = "http://www.example.com:8080/",
        reason: Optional[str] = None,
        task_type: str = "web_crawl",
    ):
        self.target = target
        self.reason = reason
        self.type = task_type


class _Available(KatanaAdapter):
    def is_available(self) -> bool:
        return True


class _FakeRunner:
    """Execution double: returns a canned result, records what the adapter built."""

    def __init__(self, result: CommandResult):
        self.result = result
        self.calls: list[tuple[list[str], Optional[float]]] = []

    def run_command(self, command, *, tool, timeout=None, env=None, cwd=None):
        self.calls.append((command, timeout))
        return self.result

    def save_raw(self, tool, content, *, extension="out", tag="tool") -> str:
        return f"storage/raw/{tool}/fixture.{extension}"


@pytest.fixture
def adapter() -> KatanaAdapter:
    return KatanaAdapter()


@pytest.fixture
def scope() -> ScopeGuard:
    return ScopeGuard(
        [ScopeRule(rule_type=ScopeRuleType.DOMAIN, value="example.com", allowed=True)]
    )


# -- parse: fixture coverage -----------------------------------------------------


def test_parse_normal_fixture_surfaces_all_four_kinds(adapter: KatanaAdapter) -> None:
    out = adapter.parse(_result(_read("normal.ndjson")))
    urls = [o for o in out if isinstance(o, UrlObservation)]
    endpoints = [o for o in out if isinstance(o, EndpointObservation)]
    params = [o for o in out if isinstance(o, ParameterObservation)]
    scripts = [o for o in out if isinstance(o, JavascriptFileObservation)]
    assert len(urls) == 5
    assert len(endpoints) == 5
    assert len(params) == 3
    assert len(scripts) == 1


def test_parse_normal_fixture_paths_and_parameters(adapter: KatanaAdapter) -> None:
    out = adapter.parse(_result(_read("normal.ndjson")))
    urls = {o.path for o in out if isinstance(o, UrlObservation)}
    assert urls == {"/", "/about", "/search", "/static/app.js", "/login"}
    params = {(o.path, o.name) for o in out if isinstance(o, ParameterObservation)}
    assert params == {("/search", "q"), ("/search", "page"), ("/login", "next")}
    for p in [o for o in out if isinstance(o, ParameterObservation)]:
        assert p.location == "query"
        assert p.significance == "unknown"


def test_parse_normal_fixture_methods_are_verbatim(adapter: KatanaAdapter) -> None:
    out = adapter.parse(_result(_read("normal.ndjson")))
    endpoints = [o for o in out if isinstance(o, EndpointObservation)]
    assert {(o.path, o.method) for o in endpoints} == {
        ("/", "GET"),
        ("/about", "GET"),
        ("/search", "GET"),
        ("/static/app.js", "GET"),
        ("/login", "GET"),
    }


def test_parse_normal_fixture_javascript_url_is_canonical(adapter: KatanaAdapter) -> None:
    out = adapter.parse(_result(_read("normal.ndjson")))
    scripts = [o for o in out if isinstance(o, JavascriptFileObservation)]
    assert scripts[0].url == "http://www.example.com:8080/static/app.js"
    assert scripts[0].host == "www.example.com"
    assert scripts[0].port == 8080


def test_parse_empty_fixture_yields_no_artifacts(adapter: KatanaAdapter) -> None:
    out = adapter.parse(_result(_read("empty.ndjson")))
    assert out == []


def test_parse_malformed_fixture_keeps_valid_lines(adapter: KatanaAdapter) -> None:
    out = adapter.parse(_result(_read("malformed.ndjson")))
    urls = [o for o in out if isinstance(o, UrlObservation)]
    assert {o.path for o in urls} == {"/valid", "/also-valid"}


def test_parse_duplicates_fixture_deduplicates_per_kind(adapter: KatanaAdapter) -> None:
    out = adapter.parse(_result(_read("duplicates.ndjson")))
    urls = [o for o in out if isinstance(o, UrlObservation)]
    endpoints = [o for o in out if isinstance(o, EndpointObservation)]
    params = [o for o in out if isinstance(o, ParameterObservation)]
    scripts = [o for o in out if isinstance(o, JavascriptFileObservation)]
    assert len(urls) == 1
    assert len(endpoints) == 1
    assert {(p.name) for p in params} == {"x", "y"}
    assert scripts == []


def test_parse_is_deterministic_when_line_order_changes(adapter: KatanaAdapter) -> None:
    lines = _read("normal.ndjson").splitlines()
    a = adapter.parse(_result("\n".join(lines)))
    b = adapter.parse(_result("\n".join(reversed(lines))))
    assert [(type(o).__name__, o.key) for o in a] == [
        (type(o).__name__, o.key) for o in b
    ]


# -- parse: normalization ---------------------------------------------------------


def test_parse_defaults_ports_by_scheme(adapter: KatanaAdapter) -> None:
    out = adapter.parse(
        _result(
            '{"request":{"method":"GET","endpoint":"https://shop.example.com/path"}}\n'
        )
    )
    urls = [o for o in out if isinstance(o, UrlObservation)]
    assert urls and urls[0].port == 443


def test_parse_skips_non_http_schemes(adapter: KatanaAdapter) -> None:
    out = adapter.parse(
        _result(
            '{"request":{"method":"GET","endpoint":"ftp://www.example.com/file"}}\n'
            '{"request":{"method":"GET","endpoint":"javascript:void(0)"}}\n'
        )
    )
    assert out == []


def test_parse_excludes_source_maps(adapter: KatanaAdapter) -> None:
    out = adapter.parse(
        _result(
            '{"request":{"method":"GET","endpoint":"http://www.example.com:8080/x.js.map"}}\n'
            '{"request":{"method":"GET","endpoint":"http://www.example.com:8080/x.js"}}\n'
        )
    )
    urls = [o for o in out if isinstance(o, UrlObservation)]
    scripts = [o for o in out if isinstance(o, JavascriptFileObservation)]
    assert {o.path for o in urls} == {"/x.js.map", "/x.js"}
    assert [s.url for s in scripts] == ["http://www.example.com:8080/x.js"]


def test_parse_keeps_method_verbatim_else_get(adapter: KatanaAdapter) -> None:
    out = adapter.parse(
        _result(
            '{"request":{"method":"POST","endpoint":"http://www.example.com:8080/api"}}\n'
            '{"request":{"endpoint":"http://www.example.com:8080/"}}\n'
        )
    )
    endpoints = {o.path: o.method for o in out if isinstance(o, EndpointObservation)}
    assert endpoints == {"/api": "POST", "/": "GET"}


def test_parse_jsonl_public_function_accepts_partial_output() -> None:
    out = parse_jsonl('{"endpoint":"http://www.example.com:8080/kept"}\nbroken\n')
    assert [o.path for o in out if isinstance(o, UrlObservation)] == ["/kept"]


# -- scope -------------------------------------------------------------------


def test_validate_refuses_out_of_scope_host(adapter: KatanaAdapter, scope: ScopeGuard) -> None:
    with pytest.raises(ScopeViolation):
        adapter.validate(_Task(target="http://evil.example.net:8080/"), scope)


def test_validate_refuses_out_of_scope_port(adapter: KatanaAdapter) -> None:
    port_scoped = ScopeGuard(
        [
            ScopeRule(rule_type=ScopeRuleType.DOMAIN, value="example.com", allowed=True),
            ScopeRule(rule_type=ScopeRuleType.PORT, value="8080", allowed=True),
        ]
    )
    with pytest.raises(ScopeViolation):
        adapter.validate(_Task(target="http://www.example.com:9999/"), port_scoped)


def test_validate_accepts_in_scope_host_and_port(
    adapter: KatanaAdapter, scope: ScopeGuard
) -> None:
    adapter.validate(_Task(target="http://www.example.com:8080/"), scope)


# -- command construction --------------------------------------------------------


def test_build_command_seeds_from_reuse_payload(adapter: KatanaAdapter) -> None:
    task = _Task(
        target="http://www.example.com:8080/",
        reason='{"url": "http://www.example.com:8080/"}',
    )
    command = adapter.build_command(task, None)
    assert command[0] == "katana"
    assert command[command.index("-u") + 1] == "http://www.example.com:8080/"


def test_build_command_falls_back_to_target(adapter: KatanaAdapter) -> None:
    command = adapter.build_command(_Task(target="http://www.example.com:8080/"), None)
    assert command[command.index("-u") + 1] == "http://www.example.com:8080/"


def test_build_command_always_uses_safe_flags_and_bounds(adapter: KatanaAdapter) -> None:
    command = adapter.build_command(
        _Task(reason='{"url": "http://www.example.com:8080/"}'), None
    )
    assert "-jsonl" in command
    assert "-js-crawl" in command
    assert command[command.index("-depth") + 1] == str(DEFAULT_DEPTH)
    assert command[command.index("-timeout") + 1] == str(int(DEFAULT_PER_REQUEST_TIMEOUT))
    assert command[command.index("-cs") + 1] == re.escape("www.example.com")


def test_build_command_refuses_without_a_seed(adapter: KatanaAdapter) -> None:
    with pytest.raises(ValueError):
        adapter.build_command(_Task(target=""), None)


# -- execution -------------------------------------------------------------------


def test_execute_missing_binary_raises_unavailable(scope: ScopeGuard) -> None:
    class _Missing(KatanaAdapter):
        def is_available(self) -> bool:
            return False

    with pytest.raises(ToolUnavailable):
        _Missing().execute(_Task(), _FakeRunner(_result("")), None, scope)


def test_execute_parses_artifacts_and_passes_overall_timeout(scope: ScopeGuard) -> None:
    runner = _FakeRunner(_result(_read("normal.ndjson")))
    execution = _Available().execute(_Task(), runner, None, scope)
    assert execution.tool == "katana"
    assert execution.exit_code == 0
    assert execution.raw_output_ref == "storage/raw/katana/fixture.out"
    assert len(execution.artifacts) == 14  # 5 urls + 5 endpoints + 3 params + 1 js
    assert runner.calls[0][1] == DEFAULT_OVERALL_TIMEOUT


def test_execute_preserves_partial_results_on_nonzero_exit(scope: ScopeGuard) -> None:
    runner = _FakeRunner(_result(_read("malformed.ndjson"), exit_code=1))
    execution = _Available().execute(_Task(), runner, None, scope)
    assert execution.exit_code == 1
    urls = [o for o in execution.artifacts if isinstance(o, UrlObservation)]
    assert {o.path for o in urls} == {"/valid", "/also-valid"}


def test_execute_records_runner_timeout_non_fatally(scope: ScopeGuard) -> None:
    class _TimingOut(_FakeRunner):
        def run_command(self, command, *, tool, timeout=None, env=None, cwd=None):
            self.calls.append((command, timeout))
            raise ToolTimeoutError(f"{tool}: timed out after {timeout}s")

    execution = _Available().execute(_Task(), _TimingOut(_result("")), None, scope)
    assert execution.timed_out is True
    assert execution.artifacts == ()
    assert execution.exit_code is None


# -- served registration ---------------------------------------------------------


def _served_execution():
    from api.serve import UnknownTaskType, create_serve_app

    app = create_serve_app(api_key="k", in_memory=True)
    return app.state.argus_execution, UnknownTaskType


def test_served_registry_contains_both_spellings() -> None:
    execution, _ = _served_execution()
    known = execution.known_task_types()
    assert "web_crawl" in known
    assert "katana" in known


def test_served_dispatch_routes_both_spellings_to_katana() -> None:
    execution, _ = _served_execution()
    assert isinstance(execution.adapter_for(_Task(task_type="web_crawl")), KatanaAdapter)
    assert isinstance(execution.adapter_for(_Task(task_type="katana")), KatanaAdapter)


def test_served_dispatch_still_refuses_unregistered_types() -> None:
    execution, UnknownTaskType = _served_execution()
    with pytest.raises(UnknownTaskType):
        execution.adapter_for(_Task(task_type="graphql_enum"))