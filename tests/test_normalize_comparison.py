"""Read-only comparison keys (Phase 26 Step 3) — persistence identity untouched.

These keys are for comparison/grouping only. They must never mutate
observations, change ingestion identity keys, or trigger DB deduplication.
"""

from __future__ import annotations

import pytest

from recon import normalize


def test_url_comparison_key_deterministic_and_idempotent():
    u = "https://Example.COM:443/a/b?x=1&y=2#frag"
    k1 = normalize.url_comparison_key(u)
    k2 = normalize.url_comparison_key(u)
    assert k1 == k2
    assert k1.key == ("https", "example.com", 443, "/a/b", "x=1&y=2")
    # original unchanged
    assert u == "https://Example.COM:443/a/b?x=1&y=2#frag"


def test_url_comparison_key_hostname_case_and_trailing_dot():
    k = normalize.url_comparison_key("http://Example.COM./x")
    assert k is not None
    assert k.key[0] == "http"
    assert k.key[1] == "example.com"


def test_url_comparison_key_fragment_dropped_only_unambiguous():
    k = normalize.url_comparison_key("https://example.com/a#section")
    assert k is not None
    # Fragment is dropped for unambiguous absolute URL (not part of HTTP request)
    assert k.key == ("https", "example.com", None, "/a", "")


def test_url_comparison_key_preserves_path_case_trailing_slash():
    k = normalize.url_comparison_key("https://example.com/Api/Users/")
    assert k.key[3] == "/Api/Users/"
    k2 = normalize.url_comparison_key("https://example.com/Api/Users")
    assert k2.key[3] == "/Api/Users"


def test_url_comparison_key_preserves_scheme_and_port_distinction():
    k1 = normalize.url_comparison_key("http://example.com/")
    k2 = normalize.url_comparison_key("https://example.com/")
    k3 = normalize.url_comparison_key("http://example.com:8080/")
    k4 = normalize.url_comparison_key("http://example.com:80/")
    assert k1.key != k2.key
    assert k1.key != k3.key
    assert k1.key != k4.key  # scheme/port distinction preserved


def test_url_comparison_key_preserves_query_order_and_repeats():
    k = normalize.url_comparison_key("https://example.com/a?b=2&a=1&b=3")
    assert k.key[4] == "b=2&a=1&b=3"


def test_url_comparison_key_preserves_encoding_and_separators():
    k = normalize.url_comparison_key("https://example.com/a%2Fb%20c?x=%2F&y=%20")
    assert k.key[3] == "/a%2Fb%20c"
    assert k.key[4] == "x=%2F&y=%20"


def test_url_comparison_key_rejects_non_absolute():
    assert normalize.url_comparison_key("/path?q=1") is None
    assert normalize.url_comparison_key("//example.com/x") is None
    assert normalize.url_comparison_key("?q=1") is None
    assert normalize.url_comparison_key("#frag") is None
    assert normalize.url_comparison_key("mailto:a@b.com") is None
    assert normalize.url_comparison_key("javascript:void(0)") is None


def test_url_comparison_key_rejects_malformed():
    assert normalize.url_comparison_key("") is None
    assert normalize.url_comparison_key("   ") is None


def test_url_comparison_key_ipv6_preserved_in_form():
    k = normalize.url_comparison_key("http://[2001:db8::1]:8080/path")
    assert k is not None
    assert k.key[1] in ("[2001:db8::1]", "2001:db8::1")
    assert k.key[2] == 8080
    assert k.key[3] == "/path"


def test_endpoint_comparison_key_preserves_method_casing():
    k = normalize.endpoint_comparison_key("https", "Example.COM", 443, "/Users", "get")
    assert k.key == ("https", "example.com", 443, "/Users", "get")
    k2 = normalize.endpoint_comparison_key("https", "example.com", 443, "/Users", "POST")
    assert k2.key == ("https", "example.com", 443, "/Users", "POST")
    assert k.key != k2.key


def test_endpoint_comparison_key_preserves_path_casing_and_slashes():
    k = normalize.endpoint_comparison_key("http", "example.com", None, "/Api//v1/", "GET")
    assert k.key[3] == "/Api//v1/"


def test_parameter_comparison_key_preserves_name_casing():
    k = normalize.parameter_comparison_key(
        "http", "Example.COM", None, "/search", "get", "UserId", "query"
    )
    assert k.key == ("http", "example.com", None, "/search", "get", "UserId", "query")
    k2 = normalize.parameter_comparison_key(
        "http", "example.com", None, "/search", "GET", "userid", "query"
    )
    assert k.key != k2.key


def test_comparison_keys_do_not_mutate_observations():
    from recon.web.katana import EndpointObservation, ParameterObservation, UrlObservation

    uo = UrlObservation(host="Example.COM", port=443, path="/A")
    po = ParameterObservation(host="Example.COM", port=443, path="/A", name="Id", method="get")
    eo = EndpointObservation(host="Example.COM", port=443, path="/A", method="get")
    # call comparison helpers - must not change observations
    _ = normalize.url_comparison_key("https://Example.COM/A")
    _ = normalize.endpoint_comparison_key("https", eo.host, eo.port, eo.path, eo.method)
    _ = normalize.parameter_comparison_key("https", po.host, po.port, po.path, po.method, po.name)
    assert uo.host == "Example.COM"
    assert po.name == "Id"
    assert eo.method == "get"


def test_comparison_key_equality_not_proof_of_semantic_equivalence():
    # same key structure doesn't imply equivalence by policy; just that keys are deterministic
    k1 = normalize.url_comparison_key("https://example.com/a?x=1")
    k2 = normalize.url_comparison_key("https://example.com/a?x=1")
    assert k1.key == k2.key
    assert k1 is not k2  # different instances
