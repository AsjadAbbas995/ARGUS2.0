"""Bounded offline JavaScript parser tests (``intelligence.javascript``).

These tests exercise the Phase 25 extraction engine only. They are pure and
offline: the parser never touches the network, a subprocess or a target, so no
fixture beyond a source string is required.

Covered cases:

* normal extraction of absolute and root-relative URLs plus query parameters;
* method-annotated call sites (``axios.<method>`` / ``xhr.open`` / ``fetch``)
  producing ``EndpointObservation`` rows, and the guarantee that a method is
  never fabricated from a bare string;
* empty input, malformed/unusual source (no uncaught exception);
* oversized input (bounded + ``truncated``);
* duplicate literals (deduplicated);
* the ``max_observations`` output cap;
* deterministic ordering;
* the output-kind restriction: only ``Url``/``Endpoint``/``Parameter`` -- never
  ``JavascriptFileObservation``, ``WebAppObservation`` or a bare ``str``.
"""

from __future__ import annotations

from recon.web.katana import (
    EndpointObservation,
    JavascriptFileObservation,
    ParameterObservation,
    UrlObservation,
)
from recon.web.httpx_probe import WebAppObservation

from intelligence.javascript import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_OBSERVATIONS,
    JsParseResult,
    parse_javascript,
)

BASE = "https://app.example.com:8443/index.html"


def test_absolute_url_yields_url_and_parameters() -> None:
    result = parse_javascript(
        'var x = "https://api.example.com/v2/users?id=1&role=admin";',
        base_url=BASE,
    )
    assert result.truncated is False
    assert result.candidates_seen == 1
    urls = [o for o in result.observations if isinstance(o, UrlObservation)]
    assert urls == [UrlObservation(host="api.example.com", port=443, path="/v2/users")]
    params = {
        o.name for o in result.observations if isinstance(o, ParameterObservation)
    }
    assert params == {"id", "role"}
    for param in result.observations:
        if isinstance(param, ParameterObservation):
            assert param.location == "query"
            assert param.significance == "unknown"


def test_relative_path_anchored_on_base_url() -> None:
    result = parse_javascript('let p = "/static/app.js";', base_url=BASE)
    assert result.observations == (
        UrlObservation(host="app.example.com", port=8443, path="/static/app.js"),
    )


def test_relative_path_without_base_is_skipped() -> None:
    result = parse_javascript('let p = "/static/app.js";')
    assert result.observations == ()
    assert result.skipped == 1


def test_method_call_sites_emit_endpoints() -> None:
    source = """
    axios.post("/api/login?debug=1");
    xhr.open("PUT", "/api/item/1");
    fetch("/api/data", {method: "DELETE"});
    """
    result = parse_javascript(source, base_url=BASE)
    endpoints = {
        (o.path, o.method)
        for o in result.observations
        if isinstance(o, EndpointObservation)
    }
    assert endpoints == {
        ("/api/login", "POST"),
        ("/api/item/1", "PUT"),
        ("/api/data", "DELETE"),
    }


def test_bare_string_never_fabricates_a_method() -> None:
    result = parse_javascript('let p = "/api/thing";', base_url=BASE)
    assert not any(isinstance(o, EndpointObservation) for o in result.observations)
    assert result.observations == (
        UrlObservation(host="app.example.com", port=8443, path="/api/thing"),
    )


def test_protocol_relative_is_not_guessed() -> None:
    result = parse_javascript('let p = "//cdn.example.com/lib.js";', base_url=BASE)
    assert result.observations == ()


def test_empty_and_non_string_input() -> None:
    for value in ("", None, 123, b"bytes"):
        result = parse_javascript(value)
        assert isinstance(result, JsParseResult)
        assert result.observations == ()
        assert result.truncated is False


def test_malformed_source_does_not_raise() -> None:
    source = (
        "function( { ) => }} ;\n"
        "var t = `template ${x} text`;\n"
        "const weird = \"a\\q b\";\n"
        "fetch('/ok/endpoint');\n"
        "/* /not/a/url */ \x00\n"
    )
    result = parse_javascript(source, base_url=BASE)
    assert isinstance(result, JsParseResult)
    assert UrlObservation(host="app.example.com", port=8443, path="/ok/endpoint") in (
        result.observations
    )


def test_oversized_input_is_truncated() -> None:
    source = 'var a = "aaaa";' + ("x" * 1000) + 'var b = "/late/path";'
    result = parse_javascript(source, base_url=BASE, max_bytes=20)
    assert result.truncated is True
    assert result.source_bytes == len(source)
    assert all(
        not (isinstance(o, UrlObservation) and o.path == "/late/path")
        for o in result.observations
    )


def test_duplicate_literals_are_deduplicated() -> None:
    source = 'a = "/api/dup"; b = "/api/dup"; axios.get("/api/dup");'
    result = parse_javascript(source, base_url=BASE)
    urls = [o for o in result.observations if isinstance(o, UrlObservation)]
    assert len(urls) == 1
    endpoints = [o for o in result.observations if isinstance(o, EndpointObservation)]
    assert len(endpoints) == 1


def test_output_limit_caps_and_flags_truncation() -> None:
    source = "".join(f'var u{i} = "/path/{i}?p={i}";' for i in range(50))
    result = parse_javascript(source, base_url=BASE, max_observations=3)
    assert len(result.observations) == 3
    assert result.truncated is True


def test_ordering_is_deterministic() -> None:
    source = (
        'b = "/zeta"; a = "/alpha"; c = "https://api.example.com/beta?q=1";'
    )
    first = parse_javascript(source, base_url=BASE)
    second = parse_javascript(source, base_url=BASE)
    assert first.observations == second.observations
    keys = [o.key for o in first.observations]
    assert keys == sorted(keys)


def test_only_url_endpoint_parameter_kinds_are_emitted() -> None:
    source = """
    axios.post("/api/one?x=1");
    fetch("/api/two", {method: "GET"});
    const u = "https://api.example.com/three";
    """
    result = parse_javascript(source, base_url=BASE)
    assert result.observations
    for observation in result.observations:
        assert isinstance(
            observation, (UrlObservation, EndpointObservation, ParameterObservation)
        )
        assert not isinstance(observation, JavascriptFileObservation)
        assert not isinstance(observation, WebAppObservation)
        assert isinstance(observation, object) and not isinstance(observation, str)


def test_defaults_are_sane() -> None:
    assert DEFAULT_MAX_BYTES > 0
    assert DEFAULT_MAX_OBSERVATIONS > 0
