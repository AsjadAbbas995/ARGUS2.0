"""tech_detect adapter fixture tests (``06_TOOL_CONTRACTS.md`` §tech_detect;
``13_TESTING_STRATEGY.md`` §Adapter Fixture Tests).

All parse/scope/execution tests drive the **in-process** technology
fingerprinting adapter (``recon.web.tech_detect``) against deterministic,
bounded signals -- a fake in-process fetcher, or explicit reuse payloads. No
live HTTP probing, no shelled binary, no subprocess is ever touched, so CI
stays deterministic and offline.

Covered cases per ``06_TOOL_CONTRACTS.md`` §tech_detect:

- **Fingerprint table A**: explicit CDN/WAF signals (Cloudflare ``cf-ray`` /
  ``cf-cache-status`` / ``Server``; Sucuri ``x-sucuri-*``; Akamai
  ``x-akamai-transformed``), conventional web servers -> honest ``other``,
  ``X-Powered-By`` -> ``framework``, CMS generator/structural markers ->
  ``cms``. Case-insensitive header names and values; deduplicated by name;
  every emitted category belongs to the schema's allowed set.
- **Reuse**: a task whose ``reason`` carries the documented
  ``{"server_header": ..., "title": ..., "content_type": ...}`` payload is
  fingerprinted from those already-captured signals with **no request**.
- **Bounded fetch**: otherwise exactly one in-process bounded request through
  the injected fetcher; a fetch failure is recorded non-fatally with no
  artifacts rather than a guess.
- Raw output is preserved through the controlled runner
  (``storage/raw/tech_detect/``).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from core.scope_guard import ScopeGuard, ScopeRule, ScopeRuleType
from core.tool_runner import CommandResult
from recon.base import ScopeViolation
from recon.web.httpx_probe import AssetTechnologyObservation
from recon.web.tech_detect import (
    ALLOWED_CATEGORIES,
    DEFAULT_MAX_BYTES,
    DEFAULT_TIMEOUT,
    DEFAULT_TECHNOLOGY_CATEGORY,
    FetchOutcome,
    FingerprintSignals,
    TechDetectAdapter,
    extract_port,
    extract_title,
    fingerprint,
)

BODY_WORDPRESS = (
    "<html><head><meta name=\"generator\" content=\"WordPress 6.4\" /></head>"
    "<body>Welcome to my /wp-content/uploads page</body></html>"
)


def _signals(headers: dict[str, str] | None = None, *, title: str = "", body: str = "") -> FingerprintSignals:
    return FingerprintSignals(headers=headers or {}, title=title, body=body)


def _matches(signals: FingerprintSignals) -> dict[str, str]:
    return {m.name: m.category for m in fingerprint(signals)}


def _result(stdout: str) -> CommandResult:
    return CommandResult(
        tool="tech_detect",
        command=["tech-detect", "app.example.com:8080"],
        stdout=stdout,
        stderr="",
        exit_code=0,
        timed_out=False,
    )


def _task(target: str = "app.example.com:8080", reason: str | None = None) -> Any:
    class _Task:
        def __init__(self, target: str, reason: str | None) -> None:
            self.target = target
            self.reason = reason

    return _Task(target, reason)


def _runner() -> Any:
    class _FakeRunner:
        def __init__(self) -> None:
            self.saved: list[tuple[str, str]] = []

        def save_raw(
            self, tool: str, content: str, *, extension: str = "out", tag: str = "tool"
        ) -> str:
            self.saved.append((tool, content, extension, tag))
            return f"storage/raw/{tool}/{tag}.{extension}"

    return _FakeRunner()


@pytest.fixture
def adapter() -> TechDetectAdapter:
    return TechDetectAdapter()


@pytest.fixture
def scope() -> ScopeGuard:
    return ScopeGuard(
        [ScopeRule(rule_type=ScopeRuleType.DOMAIN, value="example.com", allowed=True)]
    )


@pytest.fixture
def config() -> Any:
    class _Config:
        tech_detect = object()

    return _Config()


# ---------------------------------------------------------------------------
# Fingerprint table A
# ---------------------------------------------------------------------------


def test_no_signals_yield_no_technologies() -> None:
    assert fingerprint(_signals()) == ()


def test_cloudflare_explicit_headers_are_cdn() -> None:
    assert _matches(_signals({"cf-ray": "abc123-EWR"})) == {"cloudflare": "cdn"}
    assert _matches(_signals({"cf-cache-status": "HIT"})) == {"cloudflare": "cdn"}


def test_cloudflare_server_header_is_cdn() -> None:
    assert _matches(_signals({"server": "cloudflare"})) == {"cloudflare": "cdn"}


def test_sucuri_explicit_signals_are_waf() -> None:
    assert _matches(_signals({"x-sucuri-id": "42"})) == {"sucuri": "waf"}
    assert _matches(_signals({"x-sucuri-cache": "MISS"})) == {"sucuri": "waf"}


def test_akamai_explicit_signals_are_cdn() -> None:
    assert _matches(_signals({"x-akamai-transformed": "9 - 0 mb=2"})) == {"akamai": "cdn"}


def test_conventional_web_servers_are_other() -> None:
    for server, name in (
        ("nginx/1.25", "nginx"),
        ("Apache/2.4.57", "apache"),
        ("Microsoft-IIS/10.0", "microsoft-iis"),
        ("Microsoft IIS/8.5", "microsoft-iis"),
        ("openresty/1.21.4", "openresty"),
        ("LiteSpeed", "litespeed"),
    ):
        assert _matches(_signals({"server": server})) == {name: "other"}


def test_x_powered_by_runtimes() -> None:
    assert _matches(_signals({"x-powered-by": "Express"})) == {"express": "framework"}
    assert _matches(_signals({"x-powered-by": "ASP.NET"})) == {"asp.net": "framework"}
    assert _matches(_signals({"x-powered-by": "Django"})) == {"django": "framework"}
    assert _matches(_signals({"x-powered-by": "PHP/8.2"})) == {"php": "other"}


def test_cms_structural_markers() -> None:
    assert _matches(_signals(body=BODY_WORDPRESS)) == {"wordpress": "cms"}
    assert _matches(_signals(body="<meta name=\"generator\" content=\"Joomla 5\">")) == {
        "joomla": "cms"
    }
    assert _matches(_signals(body="<meta name=\"generator\" content=\"Drupal 10\">")) == {
        "drupal": "cms"
    }


def test_header_names_and_values_match_case_insensitively() -> None:
    assert _matches(_signals({"Cf-Ray": "abc-ORD"})) == {"cloudflare": "cdn"}
    assert _matches(_signals({"Server": "Nginx/1.25"})) == {"nginx": "other"}


def test_entry_is_deduplicated_by_name() -> None:
    signals = _signals({"cf-ray": "x", "cf-cache-status": "HIT", "server": "cloudflare"})
    assert len(fingerprint(signals)) == 1


def test_every_emitted_category_is_allowed() -> None:
    signals = _signals(
        {
            "cf-ray": "x",
            "x-sucuri-id": "1",
            "x-akamai-transformed": "1",
            "server": "nginx",
            "x-powered-by": "Express",
        },
        body=BODY_WORDPRESS,
    )
    for match in fingerprint(signals):
        assert match.category in ALLOWED_CATEGORIES


def test_weak_or_generic_evidence_yields_nothing() -> None:
    # A "Server" of just "1.0" or a bare presence of a common header is not an
    # explicit signal: no technology may be guessed from weak evidence.
    assert fingerprint(_signals({"server": "1.0"})) == ()
    assert fingerprint(_signals({"x-powered-by": "Unknown"})) == ()


# ---------------------------------------------------------------------------
# Signal helpers
# ---------------------------------------------------------------------------


def test_extract_title() -> None:
    assert extract_title("<html><head><title>  Hello,\n World </title></head></html>") == "Hello, World"
    assert extract_title("<title></title>") == ""
    assert extract_title("no title here") == ""


def test_extract_port() -> None:
    assert extract_port("app.example.com:8080") == 8080
    assert extract_port("app.example.com") is None
    assert extract_port("https://app.example.com:8443/path") == 8443
    assert extract_port("203.0.113.5:443") == 443
    assert extract_port("not:aport") is None
    assert extract_port("") is None


# ---------------------------------------------------------------------------
# Parse (offline)
# ---------------------------------------------------------------------------


def test_parse_capture_to_observations(adapter: TechDetectAdapter) -> None:
    capture = {
        "host": "app.example.com",
        "port": 80,
        "source": "fetch",
        "headers": {"server": "cloudflare", "x-powered-by": "PHP/8.2"},
        "title": "Example App",
    }
    observed = adapter.parse(_result(json.dumps(capture)))
    assert observed == [
        AssetTechnologyObservation(host="app.example.com", technology="cloudflare", category="cdn"),
        AssetTechnologyObservation(host="app.example.com", technology="php", category="other"),
    ]


def test_parse_capture_strips_host_when_absent(adapter: TechDetectAdapter) -> None:
    assert adapter.parse(_result("{}")) == []


def test_parse_malformed_output_is_non_fatal(adapter: TechDetectAdapter) -> None:
    assert adapter.parse(_result("not json")) == []


# ---------------------------------------------------------------------------
# Availability / command / scope
# ---------------------------------------------------------------------------


def test_is_available_and_no_external_binary(adapter: TechDetectAdapter) -> None:
    assert adapter.is_available()
    assert adapter.executables == ()


def test_build_command_is_a_diagnostic_marker(adapter: TechDetectAdapter, config: Any) -> None:
    assert adapter.build_command(_task(), config) == ["tech-detect", "app.example.com:8080"]


def test_validate_in_scope_ok(adapter: TechDetectAdapter, scope: ScopeGuard) -> None:
    adapter.validate(_task(), scope)


def test_validate_bare_host_ok(adapter: TechDetectAdapter, scope: ScopeGuard) -> None:
    adapter.validate(_task("app.example.com"), scope)


def test_validate_out_of_scope_host_raises(adapter: TechDetectAdapter, scope: ScopeGuard) -> None:
    with pytest.raises(ScopeViolation):
        adapter.validate(_task("evil.example.org:8080"), scope)


def test_validate_port_outside_allowlist_raises(adapter: TechDetectAdapter) -> None:
    narrow = ScopeGuard(
        [
            ScopeRule(rule_type=ScopeRuleType.DOMAIN, value="example.com", allowed=True),
            ScopeRule(rule_type=ScopeRuleType.PORT, value="8080", allowed=True),
        ]
    )
    adapter.validate(_task("app.example.com:8080"), narrow)
    with pytest.raises(ScopeViolation):
        adapter.validate(_task("app.example.com:443"), narrow)


# ---------------------------------------------------------------------------
# Execution: reuse path
# ---------------------------------------------------------------------------


def test_execute_reuses_signals_without_a_request(adapter: TechDetectAdapter, scope: ScopeGuard, config: Any) -> None:
    def _never_fetched(*_: Any) -> FetchOutcome:
        raise AssertionError("reuse path must never issue a request")

    runner = _runner()
    adapter = TechDetectAdapter(fetcher_fn=_never_fetched)
    reason = json.dumps(
        {"server_header": "cloudflare", "title": "Example App", "content_type": "text/html"},
        sort_keys=True,
    )
    execution = adapter.execute(_task(reason=reason), runner, config, scope)
    assert execution.exit_code == 0
    assert execution.error is None
    assert {o.technology for o in execution.artifacts} == {"cloudflare"}
    assert {o.category for o in execution.artifacts} == {"cdn"}
    assert {tool for tool, _, _, _ in runner.saved} == {"tech_detect"}
    capture = json.loads(runner.saved[0][1])
    assert capture["source"] == "reuse"
    assert capture["host"] == "app.example.com"


def test_execute_reuse_payload_with_only_title_still_fingerprints(adapter: TechDetectAdapter, scope: ScopeGuard, config: Any) -> None:
    def _never_fetched(*_: Any) -> FetchOutcome:
        raise AssertionError("reuse path must never issue a request")

    runner = _runner()
    adapter = TechDetectAdapter(fetcher_fn=_never_fetched)
    reason = json.dumps({"title": "Hello"})
    execution = adapter.execute(_task(reason=reason), runner, config, scope)
    assert execution.exit_code == 0
    assert execution.artifacts == ()


# ---------------------------------------------------------------------------
# Execution: bounded fetch path
# ---------------------------------------------------------------------------


def test_execute_fetches_once_and_preserves_raw(adapter: TechDetectAdapter, scope: ScopeGuard, config: Any) -> None:
    calls: list[tuple[str, int, float, int]] = []

    def fetcher(host: str, port: int, timeout: float, max_bytes: int) -> FetchOutcome:
        calls.append((host, port, timeout, max_bytes))
        return FetchOutcome(
            host=host,
            port=port,
            status=200,
            headers={"Server": "nginx/1.25"},
            title="App",
            body="<html>ok</html>",
            requested=True,
        )

    runner = _runner()
    adapter = TechDetectAdapter(fetcher_fn=fetcher)
    execution = adapter.execute(_task("app.example.com:8081"), runner, config, scope)
    assert calls == [("app.example.com", 8081, DEFAULT_TIMEOUT, DEFAULT_MAX_BYTES)]
    assert execution.exit_code == 0
    assert [o.technology for o in execution.artifacts] == ["nginx"]
    assert [o.category for o in execution.artifacts] == ["other"]
    assert {tool for tool, _, _, _ in runner.saved} == {"tech_detect"}
    capture = json.loads(runner.saved[0][1])
    assert capture["source"] == "fetch"
    assert capture["status"] == 200


def test_execute_fetch_failure_is_non_fatal_with_no_artifacts(adapter: TechDetectAdapter, scope: ScopeGuard, config: Any) -> None:
    def fetcher(host: str, port: int, timeout: float, max_bytes: int) -> FetchOutcome:
        return FetchOutcome(host=host, port=port, error="ConnectionRefusedError: refused", timed_out=False, requested=True)

    runner = _runner()
    adapter = TechDetectAdapter(fetcher_fn=fetcher)
    execution = adapter.execute(_task(), runner, config, scope)
    assert execution.exit_code == 1
    assert execution.artifacts == ()
    assert execution.error and "refused" in execution.error
    assert runner.saved == []  # nothing observed, nothing raw


def test_execute_fetch_timeout_is_recorded(adapter: TechDetectAdapter, scope: ScopeGuard, config: Any) -> None:
    def fetcher(host: str, port: int, timeout: float, max_bytes: int) -> FetchOutcome:
        return FetchOutcome(host=host, port=port, error="timed out", timed_out=True, requested=True)

    runner = _runner()
    adapter = TechDetectAdapter(fetcher_fn=fetcher)
    execution = adapter.execute(_task(), runner, config, scope)
    assert execution.exit_code == 1
    assert execution.timed_out is True


def test_execute_requires_a_host_target(adapter: TechDetectAdapter, scope: ScopeGuard, config: Any) -> None:
    runner = _runner()
    with pytest.raises(ValueError):
        adapter.execute(_task(":8080"), runner, config, scope)


def test_execute_out_of_scope_raises_before_any_request(adapter: TechDetectAdapter, config: Any) -> None:
    def _never_fetched(*_: Any) -> FetchOutcome:
        raise AssertionError("must not fetch an out-of-scope target")

    runner = _runner()
    adapter = TechDetectAdapter(fetcher_fn=_never_fetched)
    out_scope = ScopeGuard(
        [ScopeRule(rule_type=ScopeRuleType.DOMAIN, value="example.com", allowed=True)]
    )
    with pytest.raises(ScopeViolation):
        adapter.execute(_task("evil.example.org:8080"), runner, config, out_scope)


def test_the_default_fetch_category_is_other() -> None:
    assert DEFAULT_TECHNOLOGY_CATEGORY == "other"


# ---------------------------------------------------------------------------
# Real in-process exchange against a controlled loopback server
# ---------------------------------------------------------------------------


class _LoopbackHandler(BaseHTTPRequestHandler):
    """A real served response with explicit, deterministic fingerprint signals."""

    server_version = "cloudflare"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        body = (
            b"<html><head><title>Served</title></head>"
            b'<meta name="generator" content="WordPress 6.4" /></html>'
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cf-Ray", "abc-EWR")
        self.send_header("X-Powered-By", "PHP/8.2")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass  # keep test output quiet


@pytest.fixture
def loopback() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LoopbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_execute_real_loopback_fetch_uses_the_documented_default_fetcher(
    loopback: int, config: Any
) -> None:
    """The adapter's documented fetch path against a genuinely served response.

    ``localhost`` is the controlled host and no port rules confine it, so the
    canonical client performs one real GET through the standard library; the
    fingerprint then runs over the genuine response metadata. No fake fetcher, no
    external host.
    """
    runner = _runner()
    scope = ScopeGuard(
        [ScopeRule(rule_type=ScopeRuleType.DOMAIN, value="localhost", allowed=True)]
    )
    execution = TechDetectAdapter().execute(
        _task(f"localhost:{loopback}"), runner, config, scope
    )
    assert execution.exit_code == 0
    assert execution.error is None
    assert {(o.technology, o.category) for o in execution.artifacts} == {
        ("cloudflare", "cdn"),
        ("php", "other"),
        ("wordpress", "cms"),
    }
    # the capture reflects the real exchange
    tool, capture_text, _extension, _tag = runner.saved[0]
    assert tool == "tech_detect"
    capture = json.loads(capture_text)
    assert capture["source"] == "fetch"
    assert capture["status"] == 200
    assert capture["host"] == "localhost"