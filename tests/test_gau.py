"""GAU historical-URL adapter fixture tests (``06_TOOL_CONTRACTS.md`` §GAU;
``13_TESTING_STRATEGY.md`` §Adapter Fixture Tests; ``docs/PHASE_24_PROPOSAL.md`` §13).

Offline: every test drives the parser against the recorded streams under
``tests/fixtures/gau/`` and the adapter through a canned runner -- no live tool, no
network, no subprocess.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import pytest

from core.scope_guard import ScopeGuard, ScopeRule, ScopeRuleType
from core.tool_runner import CommandResult, ToolTimeoutError
from recon.base import ScopeViolation, ToolUnavailable
from recon.historical import SOURCE_GAU, HistoricalUrlObservation
from recon.historical.gau import GauAdapter, parse_gau

FIXTURES = Path(__file__).parent / "fixtures" / "gau"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _result(stdout: str, exit_code: int = 0) -> CommandResult:
    return CommandResult(
        tool="gau",
        command=["gau", "--json", "example.com"],
        stdout=stdout,
        stderr="",
        exit_code=exit_code,
        timed_out=False,
        raw_output_ref="storage/raw/gau/fixture.out",
    )


class _Task:
    def __init__(self, target: str = "example.com", task_type: str = "historical_recon"):
        self.target = target
        self.type = task_type


class _Available(GauAdapter):
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


class _TimeoutRunner:
    def run_command(self, command, *, tool, timeout=None, env=None, cwd=None):
        raise ToolTimeoutError("gau: timed out")

    def save_raw(self, tool, content, *, extension="out", tag="tool") -> str:
        return f"storage/raw/{tool}/fixture.{extension}"


@pytest.fixture
def adapter() -> GauAdapter:
    return GauAdapter()


@pytest.fixture
def scope() -> ScopeGuard:
    return ScopeGuard(
        [ScopeRule(rule_type=ScopeRuleType.DOMAIN, value="example.com", allowed=True)]
    )


# -- parse: fixture coverage -----------------------------------------------------


def test_parse_normal_fixture_normalizes_and_strips_query() -> None:
    out = parse_gau(_read("normal.ndjson"))
    assert all(isinstance(o, HistoricalUrlObservation) for o in out)
    assert {o.host for o in out} == {"example.com", "www.example.com"}
    assert {o.path for o in out} == {"/", "/old/api/v1/users", "/legacy/panel"}
    assert all("?" not in o.path for o in out)
    # ftp:// is not admitted and the record with no ``url`` yields nothing.
    assert len(out) == 3


def test_parse_normal_fixture_scheme_and_port_defaults() -> None:
    out = {(o.host, o.port, o.path): o for o in parse_gau(_read("normal.ndjson"))}
    assert out[("example.com", 443, "/")].url == "https://example.com:443/"
    assert out[("www.example.com", 443, "/old/api/v1/users")].source == SOURCE_GAU
    assert out[("www.example.com", 8080, "/legacy/panel")].port == 8080


def test_parse_empty_fixture_yields_nothing() -> None:
    assert parse_gau(_read("empty.ndjson")) == []
    assert parse_gau("") == []


def test_parse_malformed_fixture_keeps_valid_lines() -> None:
    out = parse_gau(_read("malformed.ndjson"))
    assert {o.path for o in out} == {"/good", "/plain-line", "/also-good"}
    assert any(o.port == 8080 for o in out)


def test_parse_duplicates_fixture_deduplicates() -> None:
    out = parse_gau(_read("duplicates.ndjson"))
    assert len(out) == 3
    assert len({o.key for o in out}) == 3


def test_parse_partial_fixture_keeps_what_was_seen() -> None:
    out = parse_gau(_read("partial.ndjson"))
    assert {(o.host, o.port, o.path) for o in out} == {
        ("www.example.com", 443, "/first"),
        ("www.example.com", 8080, "/third"),
    }


def test_parse_accepts_a_whole_json_array() -> None:
    out = parse_gau(_read("array.ndjson"))
    assert {(o.host, o.port, o.path) for o in out} == {
        ("www.example.com", 443, "/array-one"),
        ("www.example.com", 8080, "/array-two"),
    }


def test_parse_is_deterministic_and_sorted() -> None:
    first = parse_gau(_read("normal.ndjson"))
    second = parse_gau(_read("normal.ndjson"))
    assert [o.key for o in first] == [o.key for o in second]
    assert [o.key for o in first] == sorted(o.key for o in first)


# -- adapter contract ------------------------------------------------------------


def test_is_available_false_when_binary_absent(monkeypatch) -> None:
    monkeypatch.setattr(
        "core.tool_runner.is_executable_on_path", lambda name: False
    )
    assert GauAdapter().is_available() is False


def test_is_available_true_when_binary_present(monkeypatch) -> None:
    monkeypatch.setattr("core.tool_runner.is_executable_on_path", lambda name: True)
    assert GauAdapter().is_available() is True


def test_execute_missing_binary_raises_unavailable(scope: ScopeGuard) -> None:
    class _Missing(GauAdapter):
        def is_available(self) -> bool:
            return False

    with pytest.raises(ToolUnavailable):
        _Missing().execute(_Task(), _FakeRunner(_result("")), {"web": {"historical_urls": True}}, scope)


def test_validate_refuses_out_of_scope_target(adapter: GauAdapter, scope: ScopeGuard) -> None:
    with pytest.raises(ScopeViolation):
        adapter.validate(_Task(target="evil.example.net"), scope)


def test_validate_accepts_in_scope_target(adapter: GauAdapter, scope: ScopeGuard) -> None:
    adapter.validate(_Task(target="example.com"), scope)


def test_build_command_is_the_documented_argument_array(adapter: GauAdapter) -> None:
    command = adapter.build_command(_Task(target="example.com"), {"web": {"historical_urls": True}})
    assert command == ["gau", "--json", "example.com"]


def test_build_command_refuses_when_gate_disabled(adapter: GauAdapter) -> None:
    with pytest.raises(ValueError):
        adapter.build_command(_Task(target="example.com"), {"web": {"historical_urls": False}})
    with pytest.raises(ValueError):
        adapter.build_command(_Task(target="example.com"), None)


def test_parse_method_delegates_to_parse_gau(adapter: GauAdapter) -> None:
    out = adapter.parse(_result(_read("normal.ndjson")))
    assert len(out) == 3


# -- execution -------------------------------------------------------------------


def test_execute_parses_artifacts_and_passes_overall_timeout(scope: ScopeGuard) -> None:
    runner = _FakeRunner(_result(_read("normal.ndjson")))
    execution = _Available().execute(
        _Task(), runner, {"web": {"historical_urls": True}}, scope
    )
    assert execution.tool == "gau"
    assert execution.exit_code == 0
    assert len(execution.artifacts) == 3
    assert execution.raw_output_ref == "storage/raw/gau/fixture.out"
    # The adapter passes its own overall timeout to the runner.
    assert runner.calls[0][1] == GauAdapter().overall_timeout


def test_execute_timeout_is_non_fatal(scope: ScopeGuard) -> None:
    execution = _Available().execute(
        _Task(), _TimeoutRunner(), {"web": {"historical_urls": True}}, scope
    )
    assert execution.timed_out is True
    assert execution.artifacts == ()
    assert execution.exit_code is None


# -- served registration (Phase 24 §13.6) ----------------------------------------


def _served_execution(historical: bool):
    from api.serve import UnknownTaskType, create_serve_app
    from core.config import Config

    cfg = Config.from_dict(
        {
            "database": {"url": "postgresql://u:p@localhost/argus"},
            "web": {"historical_urls": historical},
        }
    )
    app = create_serve_app(api_key="k", in_memory=True, config=cfg)
    return app.state.argus_execution, UnknownTaskType


def test_served_registry_omits_historical_types_by_default() -> None:
    execution, UnknownTaskType = _served_execution(False)
    known = execution.known_task_types()
    assert "historical_recon" not in known
    assert "gau" not in known
    with pytest.raises(UnknownTaskType):
        execution.adapter_for(_Task(task_type="historical_recon"))


def test_served_registry_includes_historical_types_when_enabled() -> None:
    execution, _ = _served_execution(True)
    known = execution.known_task_types()
    assert "historical_recon" in known
    assert "gau" in known
    assert isinstance(
        execution.adapter_for(_Task(task_type="historical_recon")), GauAdapter
    )
    assert isinstance(execution.adapter_for(_Task(task_type="gau")), GauAdapter)
