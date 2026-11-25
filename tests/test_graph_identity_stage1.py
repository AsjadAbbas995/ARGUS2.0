"""Stage 1 graph identity/deduplication tests (focused)."""

from __future__ import annotations

import pytest

from correlation.asset_graph import build as build_asset_graph
from correlation.deduplication import dedupe_nodes
from correlation.records import (
    DomainRecord,
    Edge,
    Graph,
    IpRecord,
    Node,
    NodeIdentityConflict,
    PortRecord,
    TechnologyRecord,
    WebAppRecord,
    canonical_node_id,
    endpoint_key,
    record_node,
)


def test_domain_and_ip_same_display_key_have_distinct_ids() -> None:
    domain = record_node(DomainRecord(hostname="127.0.0.1", evidence_id="ev-domain"))
    ip = record_node(IpRecord(address="127.0.0.1", hostname="127.0.0.1", evidence_id="ev-ip"))
    assert domain.key == "127.0.0.1"
    assert ip.key == "127.0.0.1"
    assert domain.kind == "domain"
    assert ip.kind == "ip"
    assert domain.id != ip.id
    assert len(dedupe_nodes([domain, ip])) == 2


def test_port_and_webapp_same_display_key_have_distinct_ids() -> None:
    port = record_node(PortRecord(ip="127.0.0.1", number=8080, service="http", evidence_id="ev-port"))
    webapp = record_node(
        WebAppRecord(
            host="127.0.0.1",
            port=8080,
            status_code=200,
            title="Juice Shop",
            ip="127.0.0.1",
            evidence_id="ev-webapp",
        )
    )
    assert port.key == "127.0.0.1:8080"
    assert webapp.key == "127.0.0.1:8080"
    assert port.id != webapp.id
    assert len(dedupe_nodes([port, webapp])) == 2


def test_identical_canonical_inputs_produce_identical_ids() -> None:
    a = canonical_node_id("domain", ("example.com",))
    b = canonical_node_id("domain", ("example.com",))
    assert a == b


def test_different_kinds_same_display_components_have_different_ids() -> None:
    domain_id = canonical_node_id("domain", ("127.0.0.1",))
    ip_id = canonical_node_id("ip", ("127.0.0.1",))
    assert domain_id != ip_id


def test_same_kind_different_canonical_components_have_different_ids() -> None:
    a = canonical_node_id("port", ("127.0.0.1", 80))
    b = canonical_node_id("port", ("127.0.0.1", 8080))
    assert a != b


def test_equivalent_duplicates_deduplicate_deterministically() -> None:
    node = Node(key="example.com", kind="domain", evidence_id="ev-1", id=canonical_node_id("domain", ("example.com",)))
    same = Node(key="example.com", kind="domain", evidence_id="", id=node.id)
    out = dedupe_nodes([node, same, node])
    assert out == (node,)


def test_same_canonical_entity_different_evidence_ids_dedupes_domain() -> None:
    first = record_node(DomainRecord(hostname="example.com", evidence_id="ev-1"))
    second = record_node(DomainRecord(hostname="example.com", evidence_id="ev-2"))
    out = dedupe_nodes([first, second])
    assert out == (first,)
    assert out[0].evidence_id == "ev-1"


def test_same_canonical_entity_different_evidence_ids_dedupes_ip() -> None:
    first = record_node(IpRecord(address="1.2.3.4", hostname="example.com", evidence_id="ev-1"))
    second = record_node(IpRecord(address="1.2.3.4", hostname="example.com", evidence_id="ev-2"))
    out = dedupe_nodes([first, second])
    assert out == (first,)
    assert out[0].evidence_id == "ev-1"


def test_same_canonical_entity_different_evidence_ids_dedupes_port() -> None:
    first = record_node(PortRecord(ip="1.2.3.4", number=443, service="https", evidence_id="ev-1"))
    second = record_node(PortRecord(ip="1.2.3.4", number=443, service="https", evidence_id="ev-2"))
    out = dedupe_nodes([first, second])
    assert out == (first,)
    assert out[0].evidence_id == "ev-1"


def test_same_canonical_entity_different_evidence_ids_dedupes_technology() -> None:
    first = record_node(TechnologyRecord(name="nginx", category="other", host="example.com", evidence_id="ev-1"))
    second = record_node(TechnologyRecord(name="nginx", category="other", host="example.com", evidence_id="ev-2"))
    out = dedupe_nodes([first, second])
    assert out == (first,)
    assert out[0].evidence_id == "ev-1"


def test_reversed_input_changes_representative_evidence_but_not_identity() -> None:
    first = record_node(DomainRecord(hostname="example.com", evidence_id="ev-1"))
    second = record_node(DomainRecord(hostname="example.com", evidence_id="ev-2"))
    forward = dedupe_nodes([first, second])[0]
    reverse = dedupe_nodes([second, first])[0]
    assert forward.id == reverse.id == first.id
    assert forward.key == reverse.key == "example.com"
    assert forward.evidence_id == "ev-1"
    assert reverse.evidence_id == "ev-2"


def test_same_id_incompatible_attributes_remain_conflict() -> None:
    node = Node(key="example.com", kind="domain", evidence_id="ev-1", attributes={"hostname": "example.com"}, id=canonical_node_id("domain", ("example.com",)))
    conflicting = Node(key="example.com", kind="domain", evidence_id="ev-2", attributes={"hostname": "other.example.com"}, id=node.id)
    with pytest.raises(NodeIdentityConflict):
        dedupe_nodes([node, conflicting])


def test_existing_display_key_behavior_preserved() -> None:
    domain = DomainRecord(hostname="lab.example.com", evidence_id="ev-domain")
    node = record_node(domain)
    assert node.key == "lab.example.com"
    assert node.kind == "domain"
    assert node.evidence_id == "ev-domain"
    assert node.attributes.get("hostname") == "lab.example.com"
    graph = Graph(nodes=(node,), edges=())
    assert graph.find("lab.example.com") == node
    assert graph.orphan_keys == ("lab.example.com",)


def test_endpoint_logical_identity_unchanged() -> None:
    a = endpoint_key("POST", "/api/orders/{order_id}", "api.example.com")
    b = endpoint_key("POST", "/api/orders/{order_id}", "api.example.com")
    c = endpoint_key("GET", "/api/orders/{order_id}", "api.example.com")
    assert a == b == "POST /api/orders/{order_id} api.example.com"
    assert a != c


def test_existing_graph_build_still_dedupes_identical_record_nodes() -> None:
    domain = DomainRecord(hostname="lab.example.com", evidence_id="ev-domain")
    graph = build_asset_graph([domain, domain])
    assert len(graph.nodes) == 1
    assert graph.nodes[0].key == "lab.example.com"


def test_projection_shaped_duplicate_domain_different_evidence_ids_dedupes() -> None:
    # Projection-shaped: same canonical domain entity observed twice with different evidence IDs.
    # Graph build receives record nodes; dedupe must not fail on provenance difference.
    first = DomainRecord(hostname="example.com", evidence_id="ev-1")
    second = DomainRecord(hostname="example.com", evidence_id="ev-2")
    graph = build_asset_graph([first, second])
    assert len(graph.nodes) == 1
    assert graph.nodes[0].kind == "domain"
    assert graph.nodes[0].key == "example.com"
    assert graph.nodes[0].evidence_id == "ev-1"
