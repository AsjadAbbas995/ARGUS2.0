"""Stage 2A.2 typed graph index and safe relationship resolution tests."""

from __future__ import annotations

import pytest

from correlation.asset_graph import GraphIndexInvariantError, _build_typed_indexes, build
from correlation.records import (
    ApiRecord,
    AuthRecord,
    CertificateRecord,
    DomainRecord,
    EndpointRecord,
    IpRecord,
    JavaScriptRecord,
    Node,
    NodeIdentityConflict,
    ParameterRecord,
    PortRecord,
    TechnologyRecord,
    UrlRecord,
    WebAppRecord,
    canonical_node_id,
    endpoint_key,
    record_node,
)


def _assert_canonical_edges(graph) -> None:
    assert graph.unresolved_legacy_edges == ()
    for edge in graph.edges:
        assert edge.is_resolved
        assert edge.source_id
        assert edge.target_id


def _edge(graph, kind: str, source_id: str, target_id: str):
    matches = [
        e
        for e in graph.edges
        if e.kind == kind and e.source_id == source_id and e.target_id == target_id
    ]
    assert len(matches) == 1
    return matches[0]


def test_unique_typed_hostname_resolution() -> None:
    domain = DomainRecord(hostname="example.com", evidence_id="ev-domain")
    ip = IpRecord(address="1.2.3.4", hostname="example.com", evidence_id="ev-ip")
    graph = build([domain, ip])
    domain_node = record_node(domain)
    ip_node = record_node(ip)
    edge = _edge(graph, "resolves_to", domain_node.id, ip_node.id)
    assert edge.evidence_id == "ev-ip"
    _assert_canonical_edges(graph)


def test_domain_first_hostname_resolution() -> None:
    domain = DomainRecord(hostname="127.0.0.1", evidence_id="ev-domain")
    ip = IpRecord(address="10.0.0.1", hostname="127.0.0.1", evidence_id="ev-ip")
    webapp = WebAppRecord(host="127.0.0.1", port=8080, status_code=200, title="t", ip="10.0.0.1", evidence_id="ev-webapp")
    graph = build([domain, ip, webapp])
    domain_node = record_node(domain)
    ip_node = record_node(ip)
    webapp_node = record_node(webapp)
    edge = _edge(graph, "resolves_to", domain_node.id, ip_node.id)
    assert edge.evidence_id == "ev-ip"
    assert not any(e.kind == "resolves_to" and e.source_id == webapp_node.id for e in graph.edges)
    _assert_canonical_edges(graph)


def test_unique_webapp_host_resolution() -> None:
    webapp = WebAppRecord(host="app.example.com", port=8080, status_code=200, title="t", ip="10.0.0.1", evidence_id="ev-webapp")
    endpoint = EndpointRecord(method="GET", pattern="/health", host="app.example.com", evidence_id="ev-endpoint")
    graph = build([webapp, endpoint])
    webapp_node = record_node(webapp)
    endpoint_node = record_node(endpoint)
    edge = _edge(graph, "serves_url", webapp_node.id, endpoint_node.id)
    assert edge.evidence_id == "ev-endpoint"
    _assert_canonical_edges(graph)


def test_ambiguous_webapp_host_resolution_produces_no_relationship() -> None:
    webapp_a = WebAppRecord(host="app.example.com", port=8080, status_code=200, title="a", ip="10.0.0.1", evidence_id="ev-a")
    webapp_b = WebAppRecord(host="app.example.com", port=8081, status_code=200, title="b", ip="10.0.0.1", evidence_id="ev-b")
    endpoint = EndpointRecord(method="GET", pattern="/health", host="app.example.com", evidence_id="ev-endpoint")
    graph = build([webapp_a, webapp_b, endpoint])
    endpoint_node = record_node(endpoint)
    assert not any(e.target_id == endpoint_node.id and e.kind == "serves_url" for e in graph.edges)
    assert endpoint_node.id in graph.orphan_ids
    _assert_canonical_edges(graph)


def test_empty_host_produces_no_relationship() -> None:
    endpoint = EndpointRecord(method="GET", pattern="/health", host="", evidence_id="ev-endpoint")
    cert = CertificateRecord(subject="CN=empty", host="", evidence_id="ev-cert")
    tech = TechnologyRecord(name="nginx", category="server", host="", evidence_id="ev-tech")
    graph = build([endpoint, cert, tech])
    assert graph.edges == ()
    assert set(graph.orphan_ids) == {record_node(endpoint).id, record_node(cert).id, record_node(tech).id}


def test_unique_url_to_webapp_match() -> None:
    webapp = WebAppRecord(host="app.example.com", port=443, status_code=200, title="t", ip="10.0.0.1", evidence_id="ev-webapp")
    url = UrlRecord(host="app.example.com", port=443, path="/admin", source="crawl", evidence_id="ev-url")
    graph = build([webapp, url])
    edge = _edge(graph, "serves_url", record_node(webapp).id, record_node(url).id)
    assert edge.evidence_id == "ev-url"
    _assert_canonical_edges(graph)


def test_zero_url_to_webapp_match_uses_typed_host_fallback() -> None:
    domain = DomainRecord(hostname="app.example.com", evidence_id="ev-domain")
    url = UrlRecord(host="app.example.com", port=443, path="/admin", source="crawl", evidence_id="ev-url")
    graph = build([domain, url])
    edge = _edge(graph, "serves_url", record_node(domain).id, record_node(url).id)
    assert edge.evidence_id == "ev-url"
    _assert_canonical_edges(graph)


def test_ambiguous_url_to_webapp_match_does_not_fall_back() -> None:
    # Under accepted Stage 1 identity, same (host,port) webapps with different IPs
    # conflict in the real build path. This proves ambiguous URL->webapp selection is
    # unreachable in normal production build and cannot be masked by host fallback.
    webapp_a = WebAppRecord(host="app.example.com", port=443, status_code=200, title="a", ip="10.0.0.1", evidence_id="ev-a")
    webapp_b = WebAppRecord(host="app.example.com", port=443, status_code=200, title="b", ip="10.0.0.2", evidence_id="ev-b")
    domain = DomainRecord(hostname="app.example.com", evidence_id="ev-domain")
    url = UrlRecord(host="app.example.com", port=443, path="/admin", source="crawl", evidence_id="ev-url")
    with pytest.raises(NodeIdentityConflict):
        build([webapp_a, webapp_b, domain, url])

    # Defensive invariant: if an unexpected duplicate typed key were encountered in a
    # unique index, construction fails closed rather than selecting/falling back.
    node_a = record_node(webapp_a)
    node_b = Node(
        key=node_a.key,
        kind=node_a.kind,
        evidence_id="ev-b",
        attributes={**node_a.attributes, "ip": "10.0.0.2", "status_code": "201", "title": "b"},
        id=canonical_node_id("webapp-anomaly", ("app.example.com", 443)),
    )
    with pytest.raises(GraphIndexInvariantError):
        _build_typed_indexes((node_a, node_b))


def test_port_to_webapp_resolution_uses_ip_and_port() -> None:
    port = PortRecord(ip="10.0.0.5", number=8443, service="https", evidence_id="ev-port")
    webapp = WebAppRecord(host="api.example.com", port=8443, status_code=200, title="api", ip="10.0.0.5", evidence_id="ev-webapp")
    graph = build([port, webapp])
    edge = _edge(graph, "serves", record_node(port).id, record_node(webapp).id)
    assert edge.evidence_id == "ev-webapp"
    _assert_canonical_edges(graph)


def test_missing_webapp_ip_produces_no_port_relationship() -> None:
    port = PortRecord(ip="127.0.0.1", number=8080, service="http", evidence_id="ev-port")
    webapp = WebAppRecord(host="127.0.0.1", port=8080, status_code=200, title="t", ip="", evidence_id="ev-webapp")
    graph = build([port, webapp])
    webapp_node = record_node(webapp)
    assert not any(e.target_id == webapp_node.id and e.kind == "serves" for e in graph.edges)
    _assert_canonical_edges(graph)


def test_missing_matching_port_produces_no_relationship() -> None:
    webapp = WebAppRecord(host="app.example.com", port=8443, status_code=200, title="t", ip="10.0.0.5", evidence_id="ev-webapp")
    graph = build([webapp])
    webapp_node = record_node(webapp)
    assert not any(e.kind == "serves" and e.target_id == webapp_node.id for e in graph.edges)
    assert webapp_node.id in graph.orphan_ids
    _assert_canonical_edges(graph)


def test_endpoint_resolution_uses_logical_endpoint_key() -> None:
    key = endpoint_key("POST", "/api/orders/{id}", "api.example.com")
    endpoint = EndpointRecord(method="POST", pattern="/api/orders/{id}", host="api.example.com", evidence_id="ev-endpoint")
    param = ParameterRecord(endpoint_key=key, name="id", location="path", significance="object_id", evidence_id="ev-param")
    auth = AuthRecord(mechanism_type="bearer", endpoint_key=key, evidence_id="ev-auth")
    js = JavaScriptRecord(js_url="https://api.example.com/app.js", host="api.example.com", evidence_id="ev-js", endpoint_keys=(key,))
    graph = build([endpoint, param, auth, js])
    endpoint_node = record_node(endpoint)
    _edge(graph, "has_parameter", endpoint_node.id, record_node(param).id)
    _edge(graph, "requires_auth", endpoint_node.id, record_node(auth).id)
    _edge(graph, "references", record_node(js).id, endpoint_node.id)
    _assert_canonical_edges(graph)


def test_one_to_many_ip_api_javascript_relationships_remain_intact() -> None:
    domain = DomainRecord(hostname="lab.example.com", evidence_id="ev-domain")
    ip1 = IpRecord(address="10.0.0.1", hostname="lab.example.com", evidence_id="ev-ip1")
    ip2 = IpRecord(address="10.0.0.2", hostname="lab.example.com", evidence_id="ev-ip2")
    key1 = endpoint_key("GET", "/v1/orders", "api.example.com")
    key2 = endpoint_key("POST", "/v1/orders", "api.example.com")
    ep1 = EndpointRecord(method="GET", pattern="/v1/orders", host="api.example.com", evidence_id="ev-ep1")
    ep2 = EndpointRecord(method="POST", pattern="/v1/orders", host="api.example.com", evidence_id="ev-ep2")
    api = ApiRecord(name="orders", api_type="rest", host="api.example.com", documented=True, evidence_id="ev-api")
    js = JavaScriptRecord(js_url="https://api.example.com/app.js", host="api.example.com", evidence_id="ev-js", endpoint_keys=(key1, key2))
    graph = build([domain, ip1, ip2, ep1, ep2, api, js])
    domain_node = record_node(domain)
    assert len([e for e in graph.edges if e.kind == "resolves_to" and e.source_id == domain_node.id]) == 2
    api_node = record_node(api)
    docs = [e for e in graph.edges if e.kind == "documents" and e.source_id == api_node.id]
    assert {e.target_id for e in docs} == {record_node(ep1).id, record_node(ep2).id}
    refs = [e for e in graph.edges if e.kind == "references" and e.source_id == record_node(js).id]
    assert {e.target_id for e in refs} == {record_node(ep1).id, record_node(ep2).id}
    _assert_canonical_edges(graph)


def test_evidence_provenance_remains_correct_for_relevant_edge_types() -> None:
    parent = DomainRecord(hostname="example.com", evidence_id="ev-parent")
    domain = DomainRecord(hostname="lab.example.com", evidence_id="ev-domain")
    ip = IpRecord(address="10.0.0.5", hostname="lab.example.com", evidence_id="ev-ip")
    port = PortRecord(ip="10.0.0.5", number=443, service="https", evidence_id="ev-port")
    webapp = WebAppRecord(host="lab.example.com", port=443, status_code=200, title="t", ip="10.0.0.5", evidence_id="ev-webapp")
    url = UrlRecord(host="lab.example.com", port=443, path="/", source="crawl", evidence_id="ev-url")
    key = endpoint_key("GET", "/v1/orders", "lab.example.com")
    endpoint = EndpointRecord(method="GET", pattern="/v1/orders", host="lab.example.com", evidence_id="ev-endpoint")
    param = ParameterRecord(endpoint_key=key, name="id", location="query", significance="generic", evidence_id="ev-param")
    auth = AuthRecord(mechanism_type="bearer", endpoint_key=key, evidence_id="ev-auth")
    api = ApiRecord(name="orders", api_type="rest", host="lab.example.com", documented=True, evidence_id="ev-api")
    js = JavaScriptRecord(js_url="https://lab.example.com/app.js", host="lab.example.com", evidence_id="ev-js", endpoint_keys=(key,))
    cert = CertificateRecord(subject="CN=lab", host="lab.example.com", evidence_id="ev-cert")
    tech = TechnologyRecord(name="nginx", category="server", host="lab.example.com", evidence_id="ev-tech")
    records = [parent, domain, ip, port, webapp, url, endpoint, param, auth, api, js, cert, tech]
    graph = build(records)

    n_parent = record_node(parent)
    n_domain = record_node(domain)
    n_ip = record_node(ip)
    n_port = record_node(port)
    n_webapp = record_node(webapp)
    n_url = record_node(url)
    n_endpoint = record_node(endpoint)
    n_param = record_node(param)
    n_auth = record_node(auth)
    n_api = record_node(api)
    n_js = record_node(js)
    n_cert = record_node(cert)
    n_tech = record_node(tech)

    assert _edge(graph, "parent_of", n_parent.id, n_domain.id).evidence_id == "ev-domain"
    assert _edge(graph, "resolves_to", n_domain.id, n_ip.id).evidence_id == "ev-ip"
    assert _edge(graph, "hosts", n_ip.id, n_port.id).evidence_id == "ev-port"
    assert _edge(graph, "serves", n_port.id, n_webapp.id).evidence_id == "ev-webapp"
    assert _edge(graph, "serves_url", n_webapp.id, n_url.id).evidence_id == "ev-url"
    assert _edge(graph, "serves_url", n_domain.id, n_endpoint.id).evidence_id == "ev-endpoint"
    assert _edge(graph, "has_parameter", n_endpoint.id, n_param.id).evidence_id == "ev-param"
    assert _edge(graph, "requires_auth", n_endpoint.id, n_auth.id).evidence_id == "ev-auth"
    assert _edge(graph, "hosts_api", n_domain.id, n_api.id).evidence_id == "ev-api"
    assert _edge(graph, "documents", n_api.id, n_endpoint.id).evidence_id == "ev-api"
    assert _edge(graph, "references", n_js.id, n_endpoint.id).evidence_id == "ev-js"
    assert _edge(graph, "identity_of", n_cert.id, n_domain.id).evidence_id == "ev-cert"
    assert _edge(graph, "runs", n_domain.id, n_tech.id).evidence_id == "ev-tech"
    _assert_canonical_edges(graph)


def test_unique_typed_indexes_reject_duplicate_keys() -> None:
    # Distinct canonical nodes sharing a typed unique key must fail closed.
    domain_a = Node(key="a.example.com", kind="domain", evidence_id="ev-a", attributes={"hostname": "example.com"}, id=canonical_node_id("domain", ("a.example.com",)))
    domain_b = Node(key="b.example.com", kind="domain", evidence_id="ev-b", attributes={"hostname": "example.com"}, id=canonical_node_id("domain", ("b.example.com",)))
    with pytest.raises(GraphIndexInvariantError):
        _build_typed_indexes((domain_a, domain_b))

    ip_a = Node(key="1.1.1.1", kind="ip", evidence_id="ev-a", attributes={"address": "1.1.1.1", "hostname": "a"}, id=canonical_node_id("ip", ("1.1.1.1",)))
    ip_b = Node(key="1.1.1.1b", kind="ip", evidence_id="ev-b", attributes={"address": "1.1.1.1", "hostname": "b"}, id=canonical_node_id("ip", ("1.1.1.1b",)))
    with pytest.raises(GraphIndexInvariantError):
        _build_typed_indexes((ip_a, ip_b))

    port_a = Node(key="1.1.1.1:80", kind="port", evidence_id="ev-a", attributes={"ip": "1.1.1.1", "number": "80"}, id=canonical_node_id("port", ("1.1.1.1", 80)))
    port_b = Node(key="1.1.1.1:80alt", kind="port", evidence_id="ev-b", attributes={"ip": "1.1.1.1", "number": "80"}, id=canonical_node_id("port-alt", ("1.1.1.1", 80)))
    with pytest.raises(GraphIndexInvariantError):
        _build_typed_indexes((port_a, port_b))

    web_a = Node(key="example.com:80", kind="webapp", evidence_id="ev-a", attributes={"host": "example.com", "port": "80", "ip": "1.1.1.1"}, id=canonical_node_id("webapp", ("example.com", 80)))
    web_b = Node(key="example.com:80b", kind="webapp", evidence_id="ev-b", attributes={"host": "example.com", "port": "80", "ip": "2.2.2.2"}, id=canonical_node_id("webapp-alt", ("example.com", 80)))
    with pytest.raises(GraphIndexInvariantError):
        _build_typed_indexes((web_a, web_b))

    ep_a = Node(key="GET /a host", kind="endpoint", evidence_id="ev-a", attributes={"method": "GET", "pattern": "/a", "host": "host"}, id=canonical_node_id("endpoint", ("GET", "/a", "host")))
    ep_b = Node(key="GET /a host", kind="endpoint", evidence_id="ev-b", attributes={"method": "GET", "pattern": "/a", "host": "host"}, id=canonical_node_id("endpoint-alt", ("GET", "/a", "host")))
    with pytest.raises(GraphIndexInvariantError):
        _build_typed_indexes((ep_a, ep_b))


def test_same_canonical_webapp_evidence_only_differences_compatible() -> None:
    first = WebAppRecord(host="app.example.com", port=443, status_code=200, title="t", ip="10.0.0.1", evidence_id="ev-1")
    second = WebAppRecord(host="app.example.com", port=443, status_code=200, title="t", ip="10.0.0.1", evidence_id="ev-2")
    graph = build([first, second])
    nodes = [n for n in graph.nodes if n.kind == "webapp"]
    assert len(nodes) == 1
    assert nodes[0].evidence_id == "ev-1"
    _assert_canonical_edges(graph)


def test_same_host_port_conflicting_non_evidence_attributes_raises_through_build() -> None:
    first = WebAppRecord(host="app.example.com", port=443, status_code=200, title="t", ip="10.0.0.1", evidence_id="ev-1")
    second = WebAppRecord(host="app.example.com", port=443, status_code=200, title="t", ip="10.0.0.2", evidence_id="ev-2")
    with pytest.raises(NodeIdentityConflict):
        build([first, second])


def test_canonical_resolved_edges_and_stage2a1_legacy_behavior_compatible() -> None:
    domain = DomainRecord(hostname="example.com", evidence_id="ev-domain")
    ip = IpRecord(address="1.2.3.4", hostname="example.com", evidence_id="ev-ip")
    graph = build([domain, ip])
    assert graph.unresolved_legacy_edges == ()
    assert all(e.is_resolved for e in graph.edges)
    # Stage 2A.1 legacy unresolved behavior remains in Graph model
    legacy = Node(key="legacy.example.com", kind="domain", evidence_id="ev-legacy", attributes={"hostname": "legacy.example.com"}, id=canonical_node_id("domain", ("legacy.example.com",)))
    bad = graph.edges[0].__class__(source="missing", target="legacy.example.com", kind="legacy", evidence_id="ev-bad")
    g2 = type(graph)(nodes=(legacy,), edges=(bad,))
    assert g2.resolved_edges == ()
    assert g2.unresolved_legacy_edges == (bad,)


def test_juice_shop_regression_collision() -> None:
    domain = DomainRecord(hostname="127.0.0.1", evidence_id="ev-domain")
    ip = IpRecord(address="127.0.0.1", hostname="127.0.0.1", evidence_id="ev-ip")
    port = PortRecord(ip="127.0.0.1", number=8080, service="http", evidence_id="ev-port")
    webapp = WebAppRecord(host="127.0.0.1", port=8080, status_code=200, title="Juice Shop", ip="127.0.0.1", evidence_id="ev-webapp")
    graph = build([domain, ip, port, webapp])

    assert len(graph.nodes) == 4
    assert {n.kind for n in graph.nodes} == {"domain", "ip", "port", "webapp"}
    assert len({n.id for n in graph.nodes}) == 4

    d = record_node(domain)
    i = record_node(ip)
    p = record_node(port)
    w = record_node(webapp)
    assert _edge(graph, "resolves_to", d.id, i.id).evidence_id == "ev-ip"
    assert _edge(graph, "hosts", i.id, p.id).evidence_id == "ev-port"
    assert _edge(graph, "serves", p.id, w.id).evidence_id == "ev-webapp"
    assert not any(e.source_id == d.id and e.target_id == p.id for e in graph.edges)
    assert graph.unresolved_legacy_edges == ()
    assert graph.orphan_ids == ()
    _assert_canonical_edges(graph)
