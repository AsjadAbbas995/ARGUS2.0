"""Bounded JavaScript fetcher tests (``recon.web.js_analyze``).

Every test is offline and deterministic. DNS resolution and the HTTP/TLS
connection are injected test doubles, so no public network, real socket or real
certificate is ever involved; the one test that must observe the socket layer
monkeypatches ``socket.create_connection`` itself.

Covered policy (``docs/PHASE_25_PROPOSAL.md`` §4.1):

* URL validation: scheme, credentials/userinfo, host, port;
* scope: host authorization (separate from SSRF filtering) and port policy;
* SSRF: prohibited/loopback/private answer, mixed answers, empty answers, DNS
  failure -- each fails the whole fetch (never silently retried/filtered);
* no second DNS lookup: the TCP connection targets the validated IP, and TLS
  keeps the original hostname as ``server_hostname`` (SNI + cert verification);
* redirects refused, retries never attempted, non-2xx recorded;
* timeout/TLS/HTTP failures yield no body;
* accepted content types and the ``.js`` path fallback (only for a *missing*
  ``Content-Type``; a declared HTML type is refused even at a ``.js`` URL);
* log redaction (query/credential values never appear in emitted logs) and
  bounded/sanitized exception text;
* the per-response byte cap and bounded gzip/deflate decompression;
* the shared per-run total-byte budget (exhaustion, consumption, read cap,
  eviction/release cleanup).
"""

from __future__ import annotations

import gzip
import json
import ssl

import pytest

import recon.web.js_analyze as js
from core.scope_guard import ScopeGuard, ScopeRule, ScopeRuleType
from core.tool_runner import CommandResult

DOMAIN = ScopeRuleType.DOMAIN
PORT = ScopeRuleType.PORT


def _scope(*rules: ScopeRule) -> ScopeGuard:
    return ScopeGuard(list(rules))


def _domain_scope() -> ScopeGuard:
    return _scope(ScopeRule(DOMAIN, "example.com", True))


def _resolver(*answers: str):
    captured: list[str] = []

    def resolve(host: str) -> tuple[str, ...]:
        captured.append(host)
        return tuple(answers)

    resolve.captured = captured  # type: ignore[attr-defined]
    return resolve


class _FakeResponse:
    def __init__(self, *, status=200, headers=None, body=b""):
        self.status = status
        self._headers = {k.lower(): v for k, v in (headers or {}).items()}
        self._body = body
        self.read_calls: list = []

    def getheader(self, name, default=None):
        return self._headers.get(name.lower(), default)

    def read(self, n=None):
        self.read_calls.append(n)
        if n is None:
            return self._body
        return self._body[:n]


class _FakeConnection:
    def __init__(self, record, *, response=None, exc=None):
        self._record = record
        self._response = response
        self._exc = exc

    def request(self, method, path, headers=None):
        self._record["method"] = method
        self._record["path"] = path
        self._record["headers"] = headers
        if self._exc is not None:
            raise self._exc

    def getresponse(self):
        if self._exc is not None:
            raise self._exc
        return self._response

    def close(self):
        self._record["closed"] = True


def _factory(record, *, response=None, exc=None):
    def build(scheme, host, port, validated_ip, timeout, context):
        record.update(
            scheme=scheme,
            host=host,
            port=port,
            validated_ip=validated_ip,
            timeout=timeout,
            has_context=context is not None,
        )
        return _FakeConnection(record, response=response, exc=exc)

    return build


def _fetch(url, *, scope=None, resolver=None, factory=None, budget=None,
           run_id="run-1", **kwargs):
    return js.fetch_javascript(
        url,
        scope=scope or _domain_scope(),
        run_id=run_id,
        budget=budget or js.JsFetchBudget(js.DEFAULT_TOTAL_BYTES_PER_RUN),
        resolver=resolver or _resolver("93.184.216.34"),
        connection_factory=factory or _factory({}),
        **kwargs,
    )


# -- happy path --------------------------------------------------------------


def test_fetches_js_body_and_pins_ip():
    record = {}
    response = _FakeResponse(
        status=200, headers={"Content-Type": "text/javascript"}, body=b"var a=1;"
    )
    result = _fetch(
        "https://app.example.com/app.js",
        factory=_factory(record, response=response),
    )
    assert result.ok
    assert result.body == "var a=1;"
    assert result.bytes_read == 8
    assert result.requested is True
    assert result.status == 200
    assert record["validated_ip"] == "93.184.216.34"
    assert record["host"] == "app.example.com"
    assert record["scheme"] == "https"
    assert record["has_context"] is True
    assert record["method"] == "GET"
    assert record["path"] == "/app.js"
    assert record["headers"]["Host"] == "app.example.com"


def test_http_has_no_tls_context_and_non_default_port_in_host_header():
    record = {}
    response = _FakeResponse(
        status=200, headers={"Content-Type": "application/javascript"}, body=b"x"
    )
    result = _fetch(
        "http://app.example.com:8080/app.js",
        factory=_factory(record, response=response),
    )
    assert result.ok
    assert record["has_context"] is False
    assert record["port"] == 8080
    assert record["headers"]["Host"] == "app.example.com:8080"


def test_query_string_preserved_in_request_path():
    record = {}
    response = _FakeResponse(status=200, headers={"Content-Type": "text/javascript"})
    _fetch(
        "https://app.example.com/app.js?v=2&x=1",
        factory=_factory(record, response=response),
    )
    assert record["path"] == "/app.js?v=2&x=1"


# -- TLS pinning (real socket layer, faked create_connection) -----------------


def test_pinned_https_uses_validated_ip_and_original_sni(monkeypatch):
    calls = {}

    class _DummySock:
        pass

    def fake_create_connection(address, timeout=None, source_address=None):
        calls["address"] = address
        return _DummySock()

    monkeypatch.setattr(js.socket, "create_connection", fake_create_connection)

    wrapped = {}

    class _FakeContext:
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True
        post_handshake_auth = None

        def wrap_socket(self, sock, server_hostname=None):
            wrapped["server_hostname"] = server_hostname
            return sock

    conn = js._PinnedHTTPSConnection(
        "app.example.com",
        443,
        validated_ip="93.184.216.34",
        timeout=5.0,
        context=_FakeContext(),
    )
    conn.connect()
    assert calls["address"] == ("93.184.216.34", 443)
    assert wrapped["server_hostname"] == "app.example.com"


def test_pinned_http_connects_to_validated_ip(monkeypatch):
    calls = {}

    def fake_create_connection(address, timeout=None, source_address=None):
        calls["address"] = address
        return object()

    monkeypatch.setattr(js.socket, "create_connection", fake_create_connection)
    conn = js._PinnedHTTPConnection(
        "app.example.com", 80, validated_ip="93.184.216.34", timeout=5.0
    )
    conn.connect()
    assert calls["address"] == ("93.184.216.34", 80)


# -- URL validation ----------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "ftp://app.example.com/a.js",
        "file:///etc/passwd",
        "javascript:alert(1)",
    ],
)
def test_unsupported_scheme_rejected(url):
    result = _fetch(url, resolver=_resolver("93.184.216.34"))
    assert result.error is not None
    assert "scheme" in result.error
    assert result.requested is False
    assert result.body == ""


def test_userinfo_rejected():
    result = _fetch("http://user:pass@app.example.com/a.js")
    assert result.error is not None
    assert "userinfo" in result.error
    assert result.requested is False


def test_missing_host_rejected():
    result = _fetch("http:///a.js")
    assert result.error is not None
    assert result.requested is False


def test_out_of_range_port_rejected():
    result = _fetch("http://app.example.com:99999/a.js")
    assert result.error is not None
    assert result.requested is False


# -- scope -------------------------------------------------------------------


def test_host_out_of_scope_rejected():
    result = _fetch("http://other.test/a.js")
    assert result.error is not None
    assert "out of scope" in result.error


def test_port_out_of_scope_rejected():
    scope = _scope(
        ScopeRule(DOMAIN, "example.com", True),
        ScopeRule(PORT, "443", True),
    )
    result = _fetch("http://app.example.com:8088/a.js", scope=scope)
    assert result.error is not None
    assert "port" in result.error


def test_allowed_port_is_fetched():
    scope = _scope(
        ScopeRule(DOMAIN, "example.com", True),
        ScopeRule(PORT, "443", True),
    )
    record = {}
    response = _FakeResponse(status=200, headers={"Content-Type": "text/javascript"})
    result = _fetch(
        "https://app.example.com/a.js",
        scope=scope,
        factory=_factory(record, response=response),
    )
    assert result.ok
    assert record["port"] == 443


# -- SSRF / DNS --------------------------------------------------------------


def test_prohibited_ip_fails_closed():
    result = _fetch(
        "http://app.example.com/a.js", resolver=_resolver("10.0.0.5")
    )
    assert result.error is not None
    assert "prohibited" in result.error
    assert result.body == ""


def test_loopback_ip_fails_closed():
    result = _fetch(
        "http://app.example.com/a.js", resolver=_resolver("127.0.0.1")
    )
    assert result.error is not None
    assert "prohibited" in result.error


def test_decimal_encoded_loopback_fails_closed():
    result = _fetch(
        "http://app.example.com/a.js", resolver=_resolver("2130706433")
    )
    assert result.error is not None
    assert "prohibited" in result.error


def test_mixed_answers_fail_closed():
    result = _fetch(
        "http://app.example.com/a.js",
        resolver=_resolver("93.184.216.34", "10.0.0.1"),
    )
    assert result.error is not None
    assert "prohibited" in result.error


def test_empty_answers_fail_closed():
    result = _fetch("http://app.example.com/a.js", resolver=_resolver())
    assert result.error is not None
    assert "no answers" in result.error


def test_dns_error_fails_closed():
    def boom(host):
        raise OSError("resolver down")

    result = _fetch("http://app.example.com/a.js", resolver=boom)
    assert result.error is not None
    assert "dns error" in result.error


# -- redirects / status / content type --------------------------------------


def test_redirect_refused():
    response = _FakeResponse(status=302, headers={"Location": "/elsewhere"})
    result = _fetch(
        "https://app.example.com/a.js",
        factory=_factory({}, response=response),
    )
    assert result.skipped_reason == "redirect refused"
    assert result.body == ""
    assert result.requested is True


def test_non_success_status_recorded():
    response = _FakeResponse(status=404, headers={"Content-Type": "text/javascript"})
    result = _fetch(
        "https://app.example.com/a.js",
        factory=_factory({}, response=response),
    )
    assert result.skipped_reason == "non-success status 404"
    assert result.body == ""


def test_content_type_rejected_for_non_js_path():
    response = _FakeResponse(status=200, headers={"Content-Type": "text/html"})
    result = _fetch(
        "https://app.example.com/page.txt",
        factory=_factory({}, response=response),
    )
    assert result.skipped_reason == "content-type rejected"
    assert result.body == ""


def test_js_path_accepts_missing_content_type():
    response = _FakeResponse(status=200, headers={}, body=b"body")
    result = _fetch(
        "https://app.example.com/bundle.js",
        factory=_factory({}, response=response),
    )
    assert result.ok
    assert result.body == "body"


# -- failures yield no body --------------------------------------------------


def test_tls_failure_yields_no_body():
    exc = ssl.SSLError("certificate verify failed")
    result = _fetch(
        "https://app.example.com/a.js", factory=_factory({}, exc=exc)
    )
    assert result.error is not None
    assert "SSLError" in result.error
    assert result.body == ""
    assert result.requested is True


def test_timeout_yields_no_body():
    import socket as _socket

    result = _fetch(
        "https://app.example.com/a.js", factory=_factory({}, exc=_socket.timeout())
    )
    assert result.error is not None
    assert result.body == ""


# -- resource limits ---------------------------------------------------------


def test_response_size_cap_truncates_read():
    response = _FakeResponse(
        status=200, headers={"Content-Type": "text/javascript"}, body=b"0123456789"
    )
    result = _fetch(
        "https://app.example.com/a.js",
        factory=_factory({}, response=response),
        max_bytes=5,
    )
    assert result.body == "01234"
    assert result.bytes_read == 5
    assert response.read_calls == [5]


def test_gzip_decompression_overflow_skipped():
    payload = gzip.compress(b"a" * 1000)
    response = _FakeResponse(
        status=200,
        headers={"Content-Type": "text/javascript", "Content-Encoding": "gzip"},
        body=payload,
    )
    result = _fetch(
        "https://app.example.com/a.js",
        factory=_factory({}, response=response),
        max_bytes=100,
    )
    assert result.skipped_reason == "decompression overflow"
    assert result.body == ""


def test_gzip_decompression_within_limit_succeeds():
    payload = gzip.compress(b"var x = 1;" * 3)
    response = _FakeResponse(
        status=200,
        headers={"Content-Type": "text/javascript", "Content-Encoding": "gzip"},
        body=payload,
    )
    result = _fetch(
        "https://app.example.com/a.js",
        factory=_factory({}, response=response),
    )
    assert result.ok
    assert result.body == "var x = 1;" * 3


def test_unsupported_encoding_skipped():
    response = _FakeResponse(
        status=200,
        headers={"Content-Type": "text/javascript", "Content-Encoding": "br"},
        body=b"whatever",
    )
    result = _fetch(
        "https://app.example.com/a.js",
        factory=_factory({}, response=response),
    )
    assert result.skipped_reason == "decompression overflow"
    assert result.body == ""


# -- shared budget -----------------------------------------------------------


def test_budget_exhausted_makes_no_request():
    def resolver(host):
        raise AssertionError("resolver must not be called when budget is exhausted")

    def factory(*args, **kwargs):
        raise AssertionError("no connection when budget is exhausted")

    result = _fetch(
        "https://app.example.com/a.js",
        resolver=resolver,
        factory=factory,
        budget=js.JsFetchBudget(0),
    )
    assert result.requested is False
    assert result.skipped_reason == "budget exhausted"
    assert result.body == ""


def test_budget_consumed_by_bytes_read():
    budget = js.JsFetchBudget(1000)
    response = _FakeResponse(
        status=200, headers={"Content-Type": "text/javascript"}, body=b"12345"
    )
    _fetch(
        "https://app.example.com/a.js",
        budget=budget,
        factory=_factory({}, response=response),
    )
    assert budget.remaining("run-1") == 995


def test_read_cap_respects_remaining_budget():
    budget = js.JsFetchBudget(3)
    response = _FakeResponse(
        status=200, headers={"Content-Type": "text/javascript"}, body=b"0123456789"
    )
    result = _fetch(
        "https://app.example.com/a.js",
        budget=budget,
        factory=_factory({}, response=response),
        max_bytes=10,
    )
    assert result.body == "012"
    assert result.bytes_read == 3
    assert budget.remaining("run-1") == 0


def test_budget_evicts_least_recently_used_and_releases():
    budget = js.JsFetchBudget(100, max_runs=2)
    budget.remaining("a")
    budget.remaining("b")
    budget.remaining("c")
    assert budget.tracked_runs() == 2
    assert budget.remaining("b") == 100
    budget.release("b")
    assert budget.tracked_runs() == 1
    budget.release("c")
    assert budget.tracked_runs() == 0


def test_budget_default_is_full_budget():
    budget = js.JsFetchBudget()
    assert budget.remaining("x") == js.DEFAULT_TOTAL_BYTES_PER_RUN


# -- helper units ------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("127.0.0.1", True),
        ("10.1.2.3", True),
        ("169.254.1.1", True),
        ("::1", True),
        ("fe80::1", True),
        ("93.184.216.34", False),
        ("2606:2800:220:1:248:1893:25c8:1946", False),
    ],
)
def test_is_prohibited(value, expected):
    address = js._normalize_ip(value)
    assert address is not None
    assert js._is_prohibited(address) is expected


def test_normalize_ip_handles_decimal_and_invalid():
    assert str(js._normalize_ip("2130706433")) == "127.0.0.1"
    assert js._normalize_ip("not-an-ip") is None
    assert js._normalize_ip("") is None


# ===========================================================================
# Adapter (Phase 25 §4.2)
# ===========================================================================


from recon.base import ScopeViolation  # noqa: E402
from recon.web.js_analyze import JsAnalyzeAdapter  # noqa: E402
from recon.web.katana import (  # noqa: E402
    EndpointObservation,
    ParameterObservation,
    UrlObservation,
)


class _Task:
    def __init__(self, target, *, reason=None, run_id="run-1", task_type="js_analysis"):
        self.target = target
        self.reason = reason
        self.run_id = run_id
        self.type = task_type


class _FakeRunner:
    def __init__(self):
        self.saved = []

    def save_raw(self, tool, content, *, extension="out", tag="tool"):
        self.saved.append((tool, content, extension, tag))
        return f"storage/raw/{tool}/{tag}.{extension}"


def _ok_fetcher(body=b'axios.post("/api/login?id=1");'):
    def f(url, **kwargs):
        return js.JsFetchResult(
            url=url,
            host="app.example.com",
            port=443,
            status=200,
            content_type="text/javascript",
            body=body.decode("utf-8"),
            bytes_read=len(body),
            requested=True,
        )

    return f


def test_adapter_is_in_process_with_no_binary():
    adapter = JsAnalyzeAdapter()
    assert adapter.is_available()
    assert adapter.executables == ()


def test_adapter_build_command_is_a_diagnostic_marker():
    adapter = JsAnalyzeAdapter()
    task = _Task("https://app.example.com/app.js")
    assert adapter.build_command(task, None) == [
        "js-analyze",
        "https://app.example.com/app.js",
    ]


def test_adapter_validate_in_scope_ok():
    JsAnalyzeAdapter().validate(_Task("https://app.example.com/app.js"), _domain_scope())


def test_adapter_validate_out_of_scope_raises():
    with pytest.raises(ScopeViolation):
        JsAnalyzeAdapter().validate(
            _Task("https://evil.example.org/app.js"), _domain_scope()
        )


def test_adapter_validate_port_outside_allowlist_raises():
    narrow = _scope(
        ScopeRule(DOMAIN, "example.com", True),
        ScopeRule(PORT, "8443", True),
    )
    adapter = JsAnalyzeAdapter()
    adapter.validate(_Task("https://app.example.com:8443/app.js"), narrow)
    with pytest.raises(ScopeViolation):
        adapter.validate(_Task("https://app.example.com:9443/app.js"), narrow)


def test_adapter_parse_capture_to_observations():
    adapter = JsAnalyzeAdapter()
    capture = json.dumps(
        {
            "url": "https://app.example.com/app.js",
            "body_prefix": 'axios.post("/api/login?id=1");',
        }
    )
    result = adapter.parse(CommandResult(tool="js_analysis", command=[], stdout=capture))
    kinds = {type(o) for o in result}
    assert kinds <= {UrlObservation, EndpointObservation, ParameterObservation}
    assert UrlObservation(host="app.example.com", port=443, path="/api/login") in result
    assert (
        EndpointObservation(
            host="app.example.com", port=443, path="/api/login", method="POST"
        )
        in result
    )
    param = next(o for o in result if isinstance(o, ParameterObservation))
    assert param.name == "id"


def test_adapter_parse_malformed_is_non_fatal():
    adapter = JsAnalyzeAdapter()
    assert adapter.parse(CommandResult(tool="js_analysis", command=[], stdout="not json")) == []
    assert adapter.parse(CommandResult(tool="js_analysis", command=[], stdout="{}")) == []


def test_adapter_execute_fetches_parses_and_preserves_raw():
    runner = _FakeRunner()
    adapter = JsAnalyzeAdapter(fetcher=_ok_fetcher())
    execution = adapter.execute(
        _Task("https://app.example.com/app.js"), runner, None, _domain_scope()
    )
    assert execution.exit_code == 0
    assert execution.error is None
    assert {type(o) for o in execution.artifacts} <= {
        UrlObservation,
        EndpointObservation,
        ParameterObservation,
    }
    assert [tool for tool, *_ in runner.saved] == ["js_analysis"]
    capture = json.loads(runner.saved[0][1])
    assert capture["url"] == "https://app.example.com/app.js"
    assert capture["source"] == "fetch"


def test_adapter_execute_skip_is_non_fatal_with_no_artifacts():
    def skipping(url, **kwargs):
        return js.JsFetchResult(url=url, skipped_reason="redirect refused", requested=True)

    runner = _FakeRunner()
    execution = JsAnalyzeAdapter(fetcher=skipping).execute(
        _Task("https://app.example.com/app.js"), runner, None, _domain_scope()
    )
    assert execution.exit_code == 0
    assert execution.error is None
    assert execution.artifacts == ()
    assert runner.saved == []


def test_adapter_execute_error_is_non_fatal_with_no_artifacts():
    def failing(url, **kwargs):
        return js.JsFetchResult(url=url, error="SSLError: verify failed", requested=True)

    execution = JsAnalyzeAdapter(fetcher=failing).execute(
        _Task("https://app.example.com/app.js"), _FakeRunner(), None, _domain_scope()
    )
    assert execution.exit_code == 0
    assert execution.artifacts == ()


def test_adapter_execute_with_exhausted_budget_makes_no_request():
    # The default fetcher is used with a zero budget; the resolver must never run.
    adapter = JsAnalyzeAdapter(budget=js.JsFetchBudget(0))
    execution = adapter.execute(
        _Task("https://app.example.com/app.js"), _FakeRunner(), None, _domain_scope()
    )
    assert execution.exit_code == 0
    assert execution.artifacts == ()


def test_adapter_execute_out_of_scope_raises_before_fetch():
    def _never(url, **kwargs):
        raise AssertionError("must not fetch an out-of-scope target")

    with pytest.raises(ScopeViolation):
        JsAnalyzeAdapter(fetcher=_never).execute(
            _Task("https://evil.example.org/app.js"),
            _FakeRunner(),
            None,
            _domain_scope(),
        )


# ===========================================================================
# Served registration + coverage (Phase 25 §4.3)
# ===========================================================================


def _served_execution(enabled):
    from api.serve import UnknownTaskType, create_serve_app
    from core.config import Config

    cfg = Config.from_dict(
        {
            "database": {"url": "postgresql://u:p@localhost/argus"},
            "javascript": {"enabled": enabled},
        }
    )
    app = create_serve_app(api_key="k", in_memory=True, config=cfg)
    return app.state.argus_execution, UnknownTaskType


def test_served_registry_omits_js_analysis_by_default():
    execution, UnknownTaskType = _served_execution(False)
    known = execution.known_task_types()
    assert "js_analysis" not in known
    with pytest.raises(UnknownTaskType):
        execution.adapter_for(_Task("https://app.example.com/app.js"))


def test_served_registry_includes_js_analysis_when_enabled():
    execution, _ = _served_execution(True)
    assert "js_analysis" in execution.known_task_types()
    adapter = execution.adapter_for(_Task("https://app.example.com/app.js"))
    assert isinstance(adapter, JsAnalyzeAdapter)


def test_served_js_analysis_adapters_share_one_budget():
    execution, _ = _served_execution(True)
    first = execution.adapter_for(_Task("https://app.example.com/app.js"))
    second = execution.adapter_for(_Task("https://app.example.com/other.js"))
    assert first._budget is second._budget


def test_coverage_disabled_reports_uncovered_without_capability():
    from ai import run_context

    execution, _ = _served_execution(False)
    known = execution.known_task_types()
    assert "js_analysis" in run_context.uncovered_without_capability([], known)
    assert "js_analysis" not in run_context.coverage_gaps([], known)


def test_coverage_enabled_reports_a_gap_then_closes_it():
    from ai import run_context

    execution, _ = _served_execution(True)
    known = execution.known_task_types()
    assert "js_analysis" in run_context.coverage_gaps([], known)
    assert "js_analysis" not in run_context.uncovered_without_capability([], known)

    class _Done:
        type = "js_analysis"
        status = "completed"

    assert "js_analysis" not in run_context.coverage_gaps([_Done()], known)


def test_task_type_mappings_keep_js_analysis_expansion_owned():
    from ai import run_context
    from ai import loop
    from ai.recon_agent import EXPANSION_OWNED_STAGES

    assert "js_analysis" in EXPANSION_OWNED_STAGES
    assert "js_analysis" not in loop.TASK_TYPE_FOR_STAGE
    assert run_context.TASK_TYPE_COVERS_STAGE["js_analysis"] == "js_analysis"


# ===========================================================================
# Normalization / persistence via existing repositories (Phase 25 §4.5)
# ===========================================================================


def test_analyzer_observations_ingest_into_existing_records():
    from recon.ingest import plan_ingestion

    parsed = js.JsAnalyzeAdapter().parse(
        CommandResult(
            tool="js_analysis",
            command=[],
            stdout=json.dumps(
                {
                    "url": "https://app.example.com/app.js",
                    "body_prefix": 'axios.post("/api/login?id=1");',
                }
            ),
        )
    )
    plan = plan_ingestion(
        parsed,
        scope=_domain_scope(),
        source="js_analysis",
        target_host="app.example.com",
    )
    assert plan.unrecognized == 0
    assert any(u.path == "/api/login" for u in plan.urls)
    assert any(e.path == "/api/login" and e.method == "POST" for e in plan.endpoints)
    assert any(p.name == "id" for p in plan.parameters)
    # No JavaScript-file artifact is produced, so no javascript_files row is created
    # and the analyzer cannot self-seed further js_analysis tasks.
    assert plan.javascript_files == ()


# ===========================================================================
# SSRF fail-closed global-routability policy (Phase 25 Step 4, M-1)
# ===========================================================================


@pytest.mark.parametrize(
    "value",
    [
        "100.64.0.1",          # CGNAT (RFC 6598): is_private is False
        "100.127.255.255",     # CGNAT upper bound
        "2002:7f00:1::",       # 6to4 embedding loopback (2002::/16)
        "2002:0a00:0001::",    # 6to4 embedding 10.0.0.1
        "64:ff9b::7f00:1",     # NAT64 embedding loopback
        "64:ff9b::0a00:1",     # NAT64 embedding 10.0.0.1
        "::ffff:127.0.0.1",    # IPv4-mapped loopback
        "::ffff:10.0.0.1",     # IPv4-mapped private
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
        "fe80::1",
        "fc00::1",
        "224.0.0.1",           # IPv4 multicast (CPython is_global is True here)
        "ff02::1",             # IPv6 multicast
        # Step 5 strict policy: is_global misreports these as global.
        "3fff::1",             # IPv6 documentation (RFC 9637)
        "5f00::1",             # SRv6 SIDs (RFC 9602)
        "3ffe::1",             # 6bone (RFC 2471, deprecated)
        "192.88.99.1",         # 6to4 relay anycast (RFC 7526, deprecated)
    ],
)
def test_is_prohibited_rejects_special_ranges(value):
    address = js._normalize_ip(value)
    assert address is not None
    assert js._is_prohibited(address) is True


@pytest.mark.parametrize(
    "value",
    [
        "93.184.216.34",
        "8.8.8.8",
        "2001:4860:4860::8888",
        "2606:2800:220:1:248:1893:25c8:1946",
    ],
)
def test_is_prohibited_allows_global_ranges(value):
    address = js._normalize_ip(value)
    assert address is not None
    assert js._is_prohibited(address) is False


@pytest.mark.parametrize(
    "answer",
    ["100.64.0.1", "2002:7f00:1::", "64:ff9b::7f00:1"],
)
def test_dns_answer_in_newly_covered_range_fails_closed(answer):
    result = _fetch("http://app.example.com/a.js", resolver=_resolver(answer))
    assert result.error is not None
    assert "prohibited" in result.error
    assert result.body == ""


def test_mixed_safe_and_cgnat_answers_fail_closed():
    result = _fetch(
        "http://app.example.com/a.js",
        resolver=_resolver("93.184.216.34", "100.64.0.1"),
    )
    assert result.error is not None
    assert "prohibited" in result.error


def test_no_connection_attempt_after_prohibited_dns():
    def factory(*args, **kwargs):
        raise AssertionError("a prohibited resolution must never open a connection")

    result = _fetch(
        "http://app.example.com/a.js",
        resolver=_resolver("2002:0a00:0001::"),
        factory=factory,
    )
    assert result.error is not None
    assert result.body == ""


# ===========================================================================
# Decompression accounting against the shared run budget (Phase 25 Step 4, M-2)
# ===========================================================================


def test_gzip_decompressed_bytes_consume_shared_budget():
    budget = js.JsFetchBudget(1000)
    payload = gzip.compress(b"a" * 100)
    response = _FakeResponse(
        status=200,
        headers={"Content-Type": "text/javascript", "Content-Encoding": "gzip"},
        body=payload,
    )
    result = _fetch(
        "https://app.example.com/a.js",
        budget=budget,
        factory=_factory({}, response=response),
    )
    assert result.ok
    assert result.body == "a" * 100
    # 100 decompressed bytes are charged, not the ~30 compressed bytes read.
    assert budget.remaining("run-1") == 900


def test_gzip_expansion_beyond_remaining_budget_fails_closed():
    budget = js.JsFetchBudget(50)
    payload = gzip.compress(b"a" * 1000)
    response = _FakeResponse(
        status=200,
        headers={"Content-Type": "text/javascript", "Content-Encoding": "gzip"},
        body=payload,
    )
    result = _fetch(
        "https://app.example.com/a.js",
        budget=budget,
        factory=_factory({}, response=response),
    )
    assert result.skipped_reason == "decompression overflow"
    assert result.body == ""
    # The bounded expansion is charged before failing closed, so the run cannot
    # be re-amplified by repeating the oversized payload.
    assert budget.remaining("run-1") == 0


def test_two_fetches_share_one_run_budget():
    budget = js.JsFetchBudget(10)
    first = _fetch(
        "https://app.example.com/a.js",
        budget=budget,
        factory=_factory(
            {},
            response=_FakeResponse(
                status=200,
                headers={"Content-Type": "text/javascript"},
                body=b"12345",
            ),
        ),
    )
    assert first.ok and first.body == "12345"
    assert budget.remaining("run-1") == 5

    second = _fetch(
        "https://app.example.com/b.js",
        budget=budget,
        factory=_factory(
            {},
            response=_FakeResponse(
                status=200,
                headers={"Content-Type": "text/javascript"},
                body=b"0123456789",
            ),
        ),
    )
    assert second.body == "01234"
    assert budget.remaining("run-1") == 0

    def no_dns(host):
        raise AssertionError("no resolution once the budget is exhausted")

    def no_conn(*args, **kwargs):
        raise AssertionError("no connection once the budget is exhausted")

    third = _fetch(
        "https://app.example.com/c.js",
        budget=budget,
        resolver=no_dns,
        factory=no_conn,
    )
    assert third.requested is False
    assert third.skipped_reason == "budget exhausted"


def test_budget_consume_never_goes_negative():
    budget = js.JsFetchBudget(5)
    assert budget.consume("run-1", 100) == 0
    assert budget.remaining("run-1") == 0


def test_adapter_budget_exhaustion_yields_no_observations():
    payload = gzip.compress(b"a" * 1000)
    adapter = JsAnalyzeAdapter(
        budget=js.JsFetchBudget(3),
        resolver=_resolver("93.184.216.34"),
        connection_factory=_factory(
            {},
            response=_FakeResponse(
                status=200,
                headers={
                    "Content-Type": "text/javascript",
                    "Content-Encoding": "gzip",
                },
                body=payload,
            ),
        ),
    )
    execution = adapter.execute(
        _Task("https://app.example.com/app.js"), _FakeRunner(), None, _domain_scope()
    )
    assert execution.exit_code == 0
    assert execution.artifacts == ()


def test_adapter_tasks_share_one_run_budget():
    budget = js.JsFetchBudget(5)

    def make_adapter():
        return JsAnalyzeAdapter(
            budget=budget,
            resolver=_resolver("93.184.216.34"),
            connection_factory=_factory(
                {},
                response=_FakeResponse(
                    status=200,
                    headers={"Content-Type": "text/javascript"},
                    body=b"12345",
                ),
            ),
        )

    first = make_adapter().execute(
        _Task("https://app.example.com/a.js", run_id="run-x"),
        _FakeRunner(),
        None,
        _domain_scope(),
    )
    assert first.exit_code == 0
    assert budget.remaining("run-x") == 0

    second = make_adapter().execute(
        _Task("https://app.example.com/b.js", run_id="run-x"),
        _FakeRunner(),
        None,
        _domain_scope(),
    )
    assert second.exit_code == 0
    assert second.artifacts == ()


# ===========================================================================
# L-1: budget run isolation and explicit cleanup (Phase 25 Step 5)
# ===========================================================================


def test_budget_isolates_runs_and_releases_only_the_target():
    budget = js.JsFetchBudget(100)
    assert budget.consume("run-a", 40) == 60
    assert budget.consume("run-b", 10) == 90
    # Releasing one run's entry leaves every other run untouched.
    budget.release("run-a")
    assert budget.remaining("run-a") == 100  # recreated at the full budget
    assert budget.remaining("run-b") == 90
    assert budget.tracked_runs() == 2


def test_budget_released_run_starts_fresh_without_touching_others():
    budget = js.JsFetchBudget(10)
    budget.consume("keep", 7)
    budget.consume("done", 10)
    budget.release("done")
    assert budget.remaining("done") == 10
    assert budget.remaining("keep") == 3


def test_adapter_budget_is_isolated_per_run_id():
    budget = js.JsFetchBudget(5)

    def make_adapter():
        return JsAnalyzeAdapter(
            budget=budget,
            resolver=_resolver("93.184.216.34"),
            connection_factory=_factory(
                {},
                response=_FakeResponse(
                    status=200,
                    headers={"Content-Type": "text/javascript"},
                    body=b"12345",
                ),
            ),
        )

    make_adapter().execute(
        _Task("https://app.example.com/a.js", run_id="run-a"),
        _FakeRunner(),
        None,
        _domain_scope(),
    )
    assert budget.remaining("run-a") == 0
    assert budget.remaining("run-b") == 5  # a different run is unaffected


# ===========================================================================
# L-2: logs never carry URL query/credential values (Phase 25 Step 5)
# ===========================================================================


def test_skip_log_redacts_query_values(caplog):
    response = _FakeResponse(status=200, headers={"Content-Type": "text/html"})
    secret = "SUPERSECRET-TOKEN-123"
    with caplog.at_level("INFO", logger="argus.recon.js_analyze"):
        execution = JsAnalyzeAdapter(
            resolver=_resolver("93.184.216.34"),
            connection_factory=_factory({}, response=response),
        ).execute(
            _Task(f"https://app.example.com/app.js?token={secret}&x=1"),
            _FakeRunner(),
            None,
            _domain_scope(),
        )
    assert execution.exit_code == 0
    assert secret not in caplog.text
    assert "token=" not in caplog.text
    # The origin/path needed for diagnosis is retained.
    assert "https://app.example.com/app.js" in caplog.text


def test_truncation_log_redacts_query_values(caplog):
    secret = "LEAK-ME-999"
    adapter = JsAnalyzeAdapter(max_bytes=4)
    capture = json.dumps(
        {
            "url": f"https://app.example.com/app.js?api_key={secret}",
            "body_prefix": 'axios.get("/x"); and more text to truncate',
        }
    )
    with caplog.at_level("INFO", logger="argus.recon.js_analyze"):
        adapter.parse(CommandResult(tool="js_analysis", command=[], stdout=capture))
    assert secret not in caplog.text
    assert "api_key=" not in caplog.text
    assert "/app.js" in caplog.text


def test_redact_url_helper_drops_userinfo_query_and_fragment():
    assert (
        js._redact_url("https://u:p@h.example.com/a/b.js?t=1#f")
        == "https://h.example.com/a/b.js"
    )
    assert (
        js._redact_url("http://h.example.com:8080/x.js?a=b")
        == "http://h.example.com:8080/x.js"
    )
    assert js._redact_url("https://[2001:db8::1]:443/y.js?z=1") == "https://[2001:db8::1]:443/y.js"
    assert js._redact_url("") == "<url>"


# ===========================================================================
# L-3: content-type validation (Phase 25 Step 5)
# ===========================================================================


@pytest.mark.parametrize(
    "content_type",
    [
        "text/javascript",
        "application/javascript",
        "application/x-javascript",
        "text/ecmascript",
        "application/ecmascript",
        "application/json",
        "application/ld+json",
        "text/javascript; charset=utf-8",
    ],
)
def test_valid_js_media_types_accepted_at_non_js_path(content_type):
    response = _FakeResponse(
        status=200, headers={"Content-Type": content_type}, body=b"x"
    )
    result = _fetch(
        "https://app.example.com/static/asset",
        factory=_factory({}, response=response),
    )
    assert result.ok
    assert result.body == "x"


@pytest.mark.parametrize(
    "content_type",
    ["text/html", "text/plain", "application/octet-stream", "image/png", "text/css"],
)
def test_html_and_unexpected_types_rejected_at_js_path(content_type):
    response = _FakeResponse(
        status=200, headers={"Content-Type": content_type}, body=b"<html>nope</html>"
    )
    result = _fetch(
        "https://app.example.com/app.js", factory=_factory({}, response=response)
    )
    assert result.skipped_reason == "content-type rejected"
    assert result.body == ""


def test_html_at_js_url_is_not_parsed_by_adapter():
    response = _FakeResponse(
        status=200,
        headers={"Content-Type": "text/html"},
        body=b"<html><body>hi</body></html>",
    )
    execution = JsAnalyzeAdapter(
        resolver=_resolver("93.184.216.34"),
        connection_factory=_factory({}, response=response),
    ).execute(
        _Task("https://app.example.com/app.js"), _FakeRunner(), None, _domain_scope()
    )
    assert execution.exit_code == 0
    assert execution.artifacts == ()
    assert execution.raw_output_ref is None


def test_missing_content_type_rejected_at_non_js_path():
    response = _FakeResponse(status=200, headers={}, body=b"x")
    result = _fetch(
        "https://app.example.com/static/asset",
        factory=_factory({}, response=response),
    )
    assert result.skipped_reason == "content-type rejected"


@pytest.mark.parametrize(
    "content_type,path,expected",
    [
        ("text/javascript", "/a.txt", True),
        ("application/json", "/a.js.map", True),
        ("text/html", "/a.js", False),
        ("", "/a.js", True),
        ("", "/a.txt", False),
        ("application/octet-stream", "/a.js", False),
        ("garbage", "/a.js", False),
    ],
)
def test_content_type_ok_policy(content_type, path, expected):
    assert js._content_type_ok(content_type, path) is expected


# ===========================================================================
# L-4: bounded, sanitized exception text (Phase 25 Step 5)
# ===========================================================================


def test_long_exception_message_is_bounded():
    result = _fetch(
        "https://app.example.com/a.js",
        factory=_factory({}, exc=OSError("E" * 5000)),
    )
    assert result.error is not None
    assert result.error.startswith("OSError:")
    assert len(result.error) <= js.MAX_ERROR_CHARS + len("OSError: ") + 3


def test_sensitive_exception_message_is_sanitized():
    message = (
        "connect failed https://user:hunter2@api.example.com/x?token=abc123#frag "
        "password=letmein"
    )
    result = _fetch(
        "https://app.example.com/a.js", factory=_factory({}, exc=OSError(message))
    )
    assert "hunter2" not in result.error
    assert "abc123" not in result.error
    assert "letmein" not in result.error
    assert "frag" not in result.error
    assert "https://api.example.com" in result.error


def test_control_characters_stripped_from_exception_text():
    result = _fetch(
        "https://app.example.com/a.js",
        factory=_factory({}, exc=OSError("a\n\r\tb\x00c")),
    )
    assert "\n" not in result.error
    assert "\r" not in result.error
    assert "\x00" not in result.error
    assert "a b c" in result.error


def test_dns_error_text_is_bounded_and_categorized():
    def boom(host):
        raise OSError("x" * 5000)

    result = _fetch("https://app.example.com/a.js", resolver=boom)
    assert result.error.startswith("dns error:")
    assert len(result.error) <= len("dns error: ") + len("OSError: ") + js.MAX_ERROR_CHARS + 3


def test_unparseable_address_text_is_bounded():
    result = _fetch(
        "https://app.example.com/a.js",
        resolver=_resolver("y" * 5000),
    )
    assert result.error is not None
    assert len(result.error) <= len("unparseable address ") + js.MAX_ERROR_CHARS + 5


def test_sanitize_error_text_unit():
    assert js._sanitize_error_text("a\nb") == "a b"
    assert js._sanitize_error_text("https://u:p@h/x?t=1#f") == "https://h"
    assert js._sanitize_error_text("token=SECRET rest") == "token=[redacted] rest"
    assert len(js._sanitize_error_text("z" * 1000)) == js.MAX_ERROR_CHARS + 3
