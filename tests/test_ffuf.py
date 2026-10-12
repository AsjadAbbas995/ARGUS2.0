"""ffuf content-discovery adapter fixture tests (``06_TOOL_CONTRACTS.md`` §FFUF;
``13_TESTING_STRATEGY.md`` §Adapter Fixture Tests; ``docs/PHASE_23_PROPOSAL.md`` §8).

All parse/scope/command/execution tests drive ``recon.web.ffuf.FfufAdapter``
against the recorded JSON documents under ``tests/fixtures/ffuf/`` -- no live
external target and no FFUF binary are ever touched, so CI stays deterministic
and offline. The approved wordlist is a real scratch file created per-test, since
the adapter is deliberately fail-closed without one.

Covered cases:

- `normal.json` -> URL + endpoint observations with the FFUF status preserved as
  metadata; `empty.json` -> no artifacts; `malformed.json` (NDJSON with broken
  lines) -> valid lines survive non-fatally; `duplicates.json` -> deduplicated per
  kind, first-seen status kept; `partial.json` (mixed doc/NDJSON fragments) ->
  valid records parse.
- Normalization: default ports by scheme, non-http(s) URLs skipped, deterministic
  output independent of input order.
- Scope: out-of-scope host or port -> ``ScopeViolation`` before anything runs.
- Command: ``-u <seed>/FUZZ`` (from the ``{"url": ...}`` reuse payload or the
  target), ``-w`` (the *approved* wordlist only), ``-json``, ``-o`` outfile,
  ``-t`` bounded by ``limits.concurrency``, ``-rate`` only when configured, and
  an injected ``-timeout`` flag; refusing to run without an approved wordlist.
- Execution: missing binary -> ``ToolUnavailable`` (never a crash); the `-o`
  document is re-persisted through the runner; non-zero exit preserves partial
  results; runner timeout records partial output non-fatally.
- Registration: the served composition dispatches ``content_discover`` and
  ``ffuf`` and refuses anything else with ``UnknownTaskType``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import pytest

from core.scope_guard import ScopeGuard, ScopeRule, ScopeRuleType
from core.tool_runner import CommandResult, ToolTimeoutError
from recon.base import ScopeViolation, ToolUnavailable
from recon.web.ffuf import (
    DEFAULT_MAX_CONCURRENCY,
    DEFAULT_OVERALL_TIMEOUT,
    DEFAULT_PER_REQUEST_TIMEOUT,
    EndpointObservation,
    FfufAdapter,
    UrlObservation,
    parse_discovery,
)

FIXTURES = Path(__file__).parent / "fixtures" / "ffuf"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _result(stdout: str, exit_code: int = 0) -> CommandResult:
    return CommandResult(
        tool="ffuf",
        command=["ffuf", "-u", "http://www.example.com:8080/FUZZ", "-json"],
        stdout=stdout,
        stderr="",
        exit_code=exit_code,
        timed_out=False,
        raw_output_ref="storage/raw/ffuf/fixture.out",
    )


class _Task:
    def __init__(
        self,
        target: str = "http://www.example.com:8080/",
        reason: Optional[str] = None,
        task_type: str = "content_discover",
    ):
        self.target = target
        self.reason = reason
        self.type = task_type


class _Available(FfufAdapter):
    def is_available(self) -> bool:
        return True


class _OutfileRunner:
    """Execution double: writes the canned output to the ``-o`` path the adapter
    gave FFUF, then returns a bare ``CommandResult``. Documents what the adapter
    built and which raw documents it re-persisted."""

    def __init__(self, content: str, exit_code: int = 0):
        self.content = content
        self.exit_code = exit_code
        self.calls: list[tuple[list[str], Optional[float]]] = []
        self.saved: list[tuple[str, str]] = []

    def run_command(self, command, *, tool, timeout=None, env=None, cwd=None):
        self.calls.append((command, timeout))
        outfile = Path(command[command.index("-o") + 1])
        outfile.parent.mkdir(parents=True, exist_ok=True)
        outfile.write_text(self.content, encoding="utf-8")
        return CommandResult(
            tool=tool,
            command=command,
            stdout="",
            stderr="",
            exit_code=self.exit_code,
            timed_out=False,
            raw_output_ref=None,
        )

    def save_raw(self, tool, content, *, extension="out", tag="tool") -> str:
        self.saved.append((tool, content))
        return f"storage/raw/{tool}/fixture.{extension}"


def _approved_snapshot(
    tmp_path,
    *,
    wordlist: str = "wordlist.txt",
    enabled: bool = True,
    rate: Optional[int] = None,
    concurrency: Optional[int] = None,
) -> dict:
    """A run snapshot carrying an approved ``web.content_discovery`` wordlist."""
    wordlist_path = Path(tmp_path) / wordlist
    if not wordlist_path.exists():
        wordlist_path.write_text("FUZZ\nlogin\nadmin\nrobots.txt\napi\n", encoding="utf-8")
    snapshot: dict = {
        "web": {"content_discovery": {"enabled": enabled, "wordlist": str(wordlist_path)}},
        "limits": {},
    }
    if rate is not None:
        snapshot["limits"]["requests_per_second"] = rate
    if concurrency is not None:
        snapshot["limits"]["concurrency"] = concurrency
    return snapshot


@pytest.fixture
def adapter() -> FfufAdapter:
    return FfufAdapter()


@pytest.fixture
def scope() -> ScopeGuard:
    return ScopeGuard(
        [ScopeRule(rule_type=ScopeRuleType.DOMAIN, value="example.com", allowed=True)]
    )


# -- parse: fixture coverage -----------------------------------------------------


def test_parse_normal_fixture_surfaces_urls_and_endpoints(adapter: FfufAdapter) -> None:
    out = adapter.parse(_result(_read("normal.json")))
    urls = [o for o in out if isinstance(o, UrlObservation)]
    endpoints = [o for o in out if isinstance(o, EndpointObservation)]
    assert len(urls) == 4
    assert len(endpoints) == 4
    assert {o.path for o in urls} == {"/login", "/admin", "/robots.txt", "/api"}


def test_parse_normal_fixture_keeps_status_as_metadata(adapter: FfufAdapter) -> None:
    out = adapter.parse(_result(_read("normal.json")))
    urls = {o.path: dict(o.metadata) for o in out if isinstance(o, UrlObservation)}
    assert urls == {
        "/login": {"status": 200},
        "/admin": {"status": 403},
        "/robots.txt": {"status": 200},
        "/api": {"status": 200},
    }


def test_parse_empty_fixture_yields_no_artifacts(adapter: FfufAdapter) -> None:
    assert adapter.parse(_result(_read("empty.json"))) == []


def test_parse_malformed_fixture_keeps_valid_lines(adapter: FfufAdapter) -> None:
    out = adapter.parse(_result(_read("malformed.json")))
    urls = {o.path for o in out if isinstance(o, UrlObservation)}
    assert urls == {"/valid", "/also-valid"}


def test_parse_duplicates_fixture_deduplicates_per_kind_first_seen(
    adapter: FfufAdapter,
) -> None:
    out = adapter.parse(_result(_read("duplicates.json")))
    urls = [o for o in out if isinstance(o, UrlObservation)]
    endpoints = [o for o in out if isinstance(o, EndpointObservation)]
    assert len(urls) == 2
    assert len(endpoints) == 2
    kept = {o.path: dict(o.metadata) for o in urls}
    assert kept == {"/login": {"status": 200}, "/old": {"status": 301}}


def test_parse_partial_fixture_accepts_documents_and_ndjson_fragments(
    adapter: FfufAdapter,
) -> None:
    out = adapter.parse(_result(_read("partial.json")))
    urls = {o.path: dict(o.metadata) for o in out if isinstance(o, UrlObservation)}
    assert urls == {"/login": {"status": 200}, "/old": {"status": 301}}


def test_parse_is_deterministic_when_line_order_changes(adapter: FfufAdapter) -> None:
    lines = _read("partial.json").splitlines()
    a = adapter.parse(_result("\n".join(lines)))
    b = adapter.parse(_result("\n".join(reversed(lines))))
    assert [(type(o).__name__, o.key) for o in a] == [
        (type(o).__name__, o.key) for o in b
    ]


# -- parse: normalization ---------------------------------------------------------


def test_parse_defaults_ports_by_scheme(adapter: FfufAdapter) -> None:
    out = adapter.parse(
        _result('{"results": [{"status": 200, "url": "https://shop.example.com/path"}]}')
    )
    urls = [o for o in out if isinstance(o, UrlObservation)]
    assert urls and urls[0].port == 443


def test_parse_skips_non_http_schemes(adapter: FfufAdapter) -> None:
    out = adapter.parse(
        _result(
            '{"results": [{"url": "ftp://www.example.com/file", "status": 200},'
            ' {"url": "gopher://www.example.com/x", "status": 200}]}'
        )
    )
    assert out == []


def test_parse_status_metadata_is_absent_when_unset(adapter: FfufAdapter) -> None:
    out = adapter.parse(_result('{"results": [{"url": "http://www.example.com:8080/plain"}]}'))
    url = [o for o in out if isinstance(o, UrlObservation)][0]
    assert url.metadata == {}


def test_parse_discovery_public_function_accepts_partial_output() -> None:
    out = parse_discovery(
        '{"status": 200, "url": "http://www.example.com:8080/kept"}\n'
        "broken\n"
        '{"results": [{"status": 301, "url": "http://www.example.com:8080/old"}]}'
    )
    assert {o.path for o in out if isinstance(o, UrlObservation)} == {"/kept", "/old"}


# -- scope -------------------------------------------------------------------


def test_validate_refuses_out_of_scope_host(adapter: FfufAdapter, scope: ScopeGuard) -> None:
    with pytest.raises(ScopeViolation):
        adapter.validate(_Task(target="http://evil.example.net:8080/"), scope)


def test_validate_refuses_out_of_scope_port(adapter: FfufAdapter) -> None:
    port_scoped = ScopeGuard(
        [
            ScopeRule(rule_type=ScopeRuleType.DOMAIN, value="example.com", allowed=True),
            ScopeRule(rule_type=ScopeRuleType.PORT, value="8080", allowed=True),
        ]
    )
    with pytest.raises(ScopeViolation):
        adapter.validate(_Task(target="http://www.example.com:9999/"), port_scoped)


def test_validate_accepts_in_scope_host_and_port(
    adapter: FfufAdapter, scope: ScopeGuard
) -> None:
    adapter.validate(_Task(target="http://www.example.com:8080/"), scope)


# -- command construction ------------------------------------------------------


def test_build_command_seeds_from_reuse_payload(adapter: FfufAdapter, tmp_path) -> None:
    task = _Task(
        target="http://www.example.com:8080/",
        reason='{"url": "http://www.example.com:8080/"}',
    )
    command = adapter.build_command(task, _approved_snapshot(tmp_path))
    assert command[0] == "ffuf"
    assert command[command.index("-u") + 1] == "http://www.example.com:8080/FUZZ"
    assert command[command.index("-w") + 1] == str(Path(tmp_path) / "wordlist.txt")
    assert "-json" in command
    assert "-o" in command


def test_build_command_falls_back_to_target(adapter: FfufAdapter, tmp_path) -> None:
    command = adapter.build_command(
        _Task(target="http://www.example.com:8080/"), _approved_snapshot(tmp_path)
    )
    assert command[command.index("-u") + 1] == "http://www.example.com:8080/FUZZ"


def test_build_command_bounds_concurrency_from_limits(
    adapter: FfufAdapter, tmp_path
) -> None:
    command = adapter.build_command(
        _Task(reason='{"url": "http://www.example.com:8080/"}'),
        _approved_snapshot(tmp_path, concurrency=5, rate=50),
    )
    assert command[command.index("-t") + 1] == "5"
    assert command[command.index("-rate") + 1] == "50"


def test_build_command_omits_rate_and_uses_default_concurrency(
    adapter: FfufAdapter, tmp_path
) -> None:
    command = adapter.build_command(
        _Task(reason='{"url": "http://www.example.com:8080/"}'),
        _approved_snapshot(tmp_path),
    )
    assert command[command.index("-t") + 1] == str(DEFAULT_MAX_CONCURRENCY)
    assert "-rate" not in command


def test_build_command_passes_injected_timeout_flag(adapter: FfufAdapter, tmp_path) -> None:
    injected = FfufAdapter(timeout_flag="-timeout")
    command = injected.build_command(
        _Task(reason='{"url": "http://www.example.com:8080/"}'),
        _approved_snapshot(tmp_path),
    )
    assert command[command.index("-timeout") + 1] == str(int(DEFAULT_PER_REQUEST_TIMEOUT))


def test_build_command_reads_typed_config_wordlist(tmp_path) -> None:
    from core.config import Config

    wordlist = Path(tmp_path) / "wl.txt"
    wordlist.write_text("FUZZ\n", encoding="utf-8")
    cfg = Config.from_dict(
        {
            "database": {"url": "postgresql://argus@127.0.0.1:5434/argus_test"},
            "web": {
                "content_discovery": {"enabled": True, "wordlist": str(wordlist)}
            },
        }
    )
    command = FfufAdapter().build_command(
        _Task(reason='{"url": "http://www.example.com:8080/"}'), cfg
    )
    assert command[command.index("-w") + 1] == str(wordlist)


def test_build_command_refuses_without_approved_wordlist(
    adapter: FfufAdapter, tmp_path
) -> None:
    task = _Task(reason='{"url": "http://www.example.com:8080/"}')
    with pytest.raises(ValueError):
        adapter.build_command(task, None)
    with pytest.raises(ValueError):
        adapter.build_command(task, {"web": {"content_discovery": True}})
    with pytest.raises(ValueError):
        adapter.build_command(
            task,
            {"web": {"content_discovery": {"enabled": True, "wordlist": ""}}},
        )


def test_build_command_refuses_unreadable_approved_wordlist(
    adapter: FfufAdapter, tmp_path
) -> None:
    snapshot = _approved_snapshot(tmp_path)
    snapshot["web"]["content_discovery"]["wordlist"] = str(
        Path(tmp_path) / "does-not-exist.txt"
    )
    with pytest.raises(ValueError):
        adapter.build_command(
            _Task(reason='{"url": "http://www.example.com:8080/"}'), snapshot
        )


def test_build_command_refuses_without_a_seed(adapter: FfufAdapter, tmp_path) -> None:
    with pytest.raises(ValueError):
        adapter.build_command(_Task(target=""), _approved_snapshot(tmp_path))


# -- execution -----------------------------------------------------------------


def test_execute_missing_binary_raises_unavailable(scope: ScopeGuard, tmp_path) -> None:
    class _Missing(FfufAdapter):
        def is_available(self) -> bool:
            return False

    with pytest.raises(ToolUnavailable):
        _Missing(output_dir=Path(tmp_path)).execute(
            _Task(), _OutfileRunner(""), _approved_snapshot(tmp_path), scope
        )


def test_execute_parses_artifacts_and_passes_overall_timeout(
    scope: ScopeGuard, tmp_path
) -> None:
    runner = _OutfileRunner(_read("normal.json"))
    execution = _Available(output_dir=Path(tmp_path)).execute(
        _Task(), runner, _approved_snapshot(tmp_path), scope
    )
    assert execution.tool == "ffuf"
    assert execution.exit_code == 0
    assert len(execution.artifacts) == 8  # 4 urls + 4 endpoints
    assert runner.calls[0][1] == DEFAULT_OVERALL_TIMEOUT
    assert runner.saved and runner.saved[0][0] == "ffuf"
    assert execution.raw_output_ref == "storage/raw/ffuf/fixture.json"


def test_execute_preserves_partial_results_on_nonzero_exit(
    scope: ScopeGuard, tmp_path
) -> None:
    runner = _OutfileRunner(_read("malformed.json"), exit_code=1)
    execution = _Available(output_dir=Path(tmp_path)).execute(
        _Task(), runner, _approved_snapshot(tmp_path), scope
    )
    assert execution.exit_code == 1
    urls = [o for o in execution.artifacts if isinstance(o, UrlObservation)]
    assert {o.path for o in urls} == {"/valid", "/also-valid"}


def test_execute_records_runner_timeout_non_fatally_with_partial_outfile(
    scope: ScopeGuard, tmp_path
) -> None:
    class _TimingOut(_OutfileRunner):
        def run_command(self, command, *, tool, timeout=None, env=None, cwd=None):
            self.calls.append((command, timeout))
            outfile = Path(command[command.index("-o") + 1])
            outfile.parent.mkdir(parents=True, exist_ok=True)
            outfile.write_text(self.content, encoding="utf-8")
            raise ToolTimeoutError(f"{tool}: timed out after {timeout}s")

    execution = _Available(output_dir=Path(tmp_path)).execute(
        _Task(), _TimingOut(_read("normal.json")), _approved_snapshot(tmp_path), scope
    )
    assert execution.timed_out is True
    assert execution.exit_code is None
    assert len(execution.artifacts) == 8  # partial document was preserved and read


# -- served registration -------------------------------------------------------


def _served_execution():
    from api.serve import UnknownTaskType, create_serve_app

    app = create_serve_app(api_key="k", in_memory=True)
    return app.state.argus_execution, UnknownTaskType


def test_served_registry_contains_both_spellings() -> None:
    execution, _ = _served_execution()
    known = execution.known_task_types()
    assert "content_discover" in known
    assert "ffuf" in known


def test_served_dispatch_routes_both_spellings_to_ffuf() -> None:
    execution, _ = _served_execution()
    assert isinstance(
        execution.adapter_for(_Task(task_type="content_discover")), FfufAdapter
    )
    assert isinstance(execution.adapter_for(_Task(task_type="ffuf")), FfufAdapter)


def test_served_dispatch_still_refuses_unregistered_types() -> None:
    execution, UnknownTaskType = _served_execution()
    with pytest.raises(UnknownTaskType):
        execution.adapter_for(_Task(task_type="graphql_enum"))