"""Stage 2A.1 graph model and canonical index tests."""

from __future__ import annotations

import pytest

from correlation.asset_graph import build as build_asset_graph
from correlation.deduplication import dedupe_edges
from correlation.records import (
    DomainRecord,
    Edge,
    Graph,
    IpRecord,
    Node,
    NodeLookupAmbiguity,
    canonical_node_id,
    record_node,
)


def _domain_node(host: str, evidence_id: str) -> Node:
    return record_node(DomainRecord(hostname=host, evidence_id=evidence_id))


def _ip_node(address: str, evidence_id: str, hostname: str = "127.0.0.1") -> Node:
    return record_node(IpRecord(address=address, hostname=hostname, evidence_id=evidence_id))


def test_graph_indexes_retain_distinct_nodes_with_identical_display_keys() -> None:
    domain = _domain_node("127.0.0.1", "ev-domain")
    ip = _ip_node("127.0.0.1", "ev-ip")
    graph = Graph(nodes=(domain, ip), edges=())

    assert domain.key == ip.key == "127.0.0.1"
    assert domain.id != ip.id
    assert set(graph.nodes_by_id) == {domain.id, ip.id}
    assert set(graph.node_ids_by_key["127.0.0.1"]) == {domain.id, ip.id}


def test_find_by_id_resolves_correct_typed_node() -> None:
    domain = _domain_node("127.0.0.1", "ev-domain")
    ip = _ip_node("127.0.0.1", "ev-ip")
    graph = Graph(nodes=(domain, ip), edges=())

    assert graph.find_by_id(domain.id) is domain
    assert graph.find_by_id(ip.id) is ip
    assert graph.find_by_id("missing") is None


def test_find_by_key_returns_all_matches_and_kind_filter() -> None:
    domain = _domain_node("127.0.0.1", "ev-domain")
    ip = _ip_node("127.0.0.1", "ev-ip")
    other = _domain_node("example.com", "ev-example")
    graph = Graph(nodes=(domain, ip, other), edges=())

    matches = graph.find_by_key("127.0.0.1")
    assert {n.id for n in matches} == {domain.id, ip.id}
    assert graph.find_by_key("127.0.0.1", kind="domain") == (domain,)
    assert graph.find_by_key("127.0.0.1", kind="ip") == (ip,)
    assert graph.find_by_key("missing") == ()


def test_ambiguous_legacy_find_fails_explicitly() -> None:
    domain = _domain_node("127.0.0.1", "ev-domain")
    ip = _ip_node("127.0.0.1", "ev-ip")
    graph = Graph(nodes=(domain, ip), edges=())

    with pytest.raises(NodeLookupAmbiguity):
        graph.find("127.0.0.1")


def test_unambiguous_legacy_find_remains_compatible() -> None:
    domain = _domain_node("example.com", "ev-domain")
    graph = Graph(nodes=(domain,), edges=())

    assert graph.find("example.com") is domain
    assert graph.find("missing.example.com") is None


def test_edge_source_target_ids_are_canonical_references() -> None:
    src = _domain_node("example.com", "ev-src")
    tgt = _ip_node("1.2.3.4", "ev-tgt", hostname="example.com")
    edge = Edge(
        source=src.key,
        target=tgt.key,
        kind="resolves_to",
        evidence_id="ev-edge",
        source_id=src.id,
        target_id=tgt.id,
        source_key=src.key,
        target_key=tgt.key,
    )
    graph = Graph(nodes=(src, tgt), edges=(edge,))

    assert edge.is_resolved
    assert graph.resolved_edges == (edge,)
    assert graph.unresolved_legacy_edges == ()


def test_display_metadata_does_not_influence_canonical_edge_identity() -> None:
    src = _domain_node("example.com", "ev-src")
    tgt = _ip_node("1.2.3.4", "ev-tgt", hostname="example.com")
    edge_a = Edge(
        source="display-a",
        target="display-b",
        kind="resolves_to",
        evidence_id="ev-a",
        source_id=src.id,
        target_id=tgt.id,
        source_key="display-a",
        target_key="display-b",
    )
    edge_b = Edge(
        source="different-a",
        target="different-b",
        kind="resolves_to",
        evidence_id="ev-b",
        source_id=src.id,
        target_id=tgt.id,
        source_key="different-a",
        target_key="different-b",
    )

    deduped = dedupe_edges([edge_a, edge_b])
    assert deduped == (edge_a,)


def test_id_based_edge_traversal_works() -> None:
    src = _domain_node("example.com", "ev-src")
    tgt = _ip_node("1.2.3.4", "ev-tgt", hostname="example.com")
    edge = Edge(
        source=src.key,
        target=tgt.key,
        kind="resolves_to",
        evidence_id="ev-edge",
        source_id=src.id,
        target_id=tgt.id,
        source_key=src.key,
        target_key=tgt.key,
    )
    graph = Graph(nodes=(src, tgt), edges=(edge,))

    assert graph.edges_from_id(src.id) == (edge,)
    assert graph.edges_to_id(tgt.id) == (edge,)
    assert graph.neighbors_by_id(src.id) == (tgt,)


def test_orphan_ids_use_canonical_ids_and_orphan_keys_are_display_only() -> None:
    src = _domain_node("example.com", "ev-src")
    tgt = _ip_node("1.2.3.4", "ev-tgt", hostname="example.com")
    orphan = _domain_node("orphan.example.com", "ev-orphan")
    edge = Edge(
        source=src.key,
        target=tgt.key,
        kind="resolves_to",
        evidence_id="ev-edge",
        source_id=src.id,
        target_id=tgt.id,
        source_key=src.key,
        target_key=tgt.key,
    )
    graph = Graph(nodes=(src, tgt, orphan), edges=(edge,))

    assert graph.orphan_ids == (orphan.id,)
    assert graph.orphan_keys == ("orphan.example.com",)


def test_multiple_valid_nodes_for_one_display_key_preserved() -> None:
    domain = _domain_node("127.0.0.1", "ev-domain")
    ip = _ip_node("127.0.0.1", "ev-ip")
    graph = Graph(nodes=(domain, ip), edges=())

    assert len(graph.nodes) == 2
    assert {n.kind for n in graph.nodes} == {"domain", "ip"}
    assert len(set(n.id for n in graph.nodes)) == 2


def test_invalid_edge_endpoint_references_become_unresolved_legacy_edges() -> None:
    node = _domain_node("example.com", "ev-node")
    bad = Edge(
        source="example.com",
        target="missing.example.com",
        kind="resolves_to",
        evidence_id="ev-bad",
    )
    graph = Graph(nodes=(node,), edges=(bad,))

    assert graph.resolved_edges == ()
    assert graph.unresolved_legacy_edges == (bad,)
    assert graph.orphan_ids == (node.id,)


def test_legacy_unambiguous_edges_resolve_to_canonical_ids() -> None:
    src = _domain_node("example.com", "ev-src")
    tgt = _ip_node("1.2.3.4", "ev-tgt", hostname="example.com")
    legacy = Edge(source="example.com", target="1.2.3.4", kind="resolves_to", evidence_id="ev")
    graph = Graph(nodes=(src, tgt), edges=(legacy,))

    assert len(graph.resolved_edges) == 1
    resolved = graph.resolved_edges[0]
    assert resolved.source_id == src.id
    assert resolved.target_id == tgt.id
    assert resolved.source_key == "example.com"
    assert resolved.target_key == "1.2.3.4"
    assert graph.unresolved_legacy_edges == ()


def test_legacy_ambiguous_edges_are_not_inferred_and_are_observable() -> None:
    domain = _domain_node("127.0.0.1", "ev-domain")
    ip = _ip_node("127.0.0.1", "ev-ip")
    tgt = _ip_node("10.0.0.1", "ev-tgt", hostname="x")
    ambiguous = Edge(source="127.0.0.1", target="10.0.0.1", kind="resolves_to", evidence_id="ev")

    graph = Graph(nodes=(domain, ip, tgt), edges=(ambiguous,))

    assert graph.resolved_edges == ()
    assert graph.unresolved_legacy_edges == (ambiguous,)
    assert ambiguous in graph.unresolved_legacy_edges
    # Orphan IDs are computed from canonical resolved edges only.
    assert set(graph.orphan_ids) == {domain.id, ip.id, tgt.id}


def test_legacy_key_traversal_fails_closed_on_ambiguous_keys() -> None:
    domain = _domain_node("127.0.0.1", "ev-domain")
    ip = _ip_node("127.0.0.1", "ev-ip")
    tgt = _ip_node("10.0.0.1", "ev-tgt", hostname="x")
    edge = Edge(
        source=ip.key,
        target=tgt.key,
        kind="resolves_to",
        evidence_id="ev",
        source_id=ip.id,
        target_id=tgt.id,
        source_key=ip.key,
        target_key=tgt.key,
    )
    graph = Graph(nodes=(domain, ip, tgt), edges=(edge,))

    with pytest.raises(NodeLookupAmbiguity):
        graph.edges_from("127.0.0.1")
    with pytest.raises(NodeLookupAmbiguity):
        graph.edges_to("127.0.0.1")
    with pytest.raises(NodeLookupAmbiguity):
        graph.neighbors("127.0.0.1")
    # Canonical ID traversal remains precise.
    assert graph.edges_from_id(ip.id) == (edge,)
    assert graph.neighbors_by_id(ip.id) == (tgt,)


def test_unambiguous_legacy_key_traversal_remains_compatible() -> None:
    src = _domain_node("example.com", "ev-src")
    tgt = _ip_node("1.2.3.4", "ev-tgt", hostname="example.com")
    legacy = Edge(source="example.com", target="1.2.3.4", kind="resolves_to", evidence_id="ev")
    graph = Graph(nodes=(src, tgt), edges=(legacy,))

    assert len(graph.edges_from("example.com")) == 1
    assert len(graph.edges_to("1.2.3.4")) == 1
    assert graph.neighbors("example.com") == (tgt,)


def test_existing_asset_graph_build_remains_compatible_under_bridge() -> None:
    domain = DomainRecord(hostname="lab.example.com", evidence_id="ev-domain")
    graph = build_asset_graph([domain])
    assert len(graph.nodes) == 1
    assert graph.find("lab.example.com") is not None
    assert graph.orphan_keys == ("lab.example.com",)
def test_legacy_unresolved_edges_are_preserved_not_deduped_by_display_key() -> None:
    domain = _domain_node("127.0.0.1", "ev-domain")
    ip = _ip_node("127.0.0.1", "ev-ip")
    target = _ip_node("10.0.0.1", "ev-target", hostname="x")
    e1 = Edge(source="127.0.0.1", target="10.0.0.1", kind="rel", evidence_id="ev1")
    e2 = Edge(source="127.0.0.1", target="10.0.0.1", kind="rel", evidence_id="ev2")

    deduped = dedupe_edges([e1, e2])
    assert [e.evidence_id for e in deduped] == ["ev1", "ev2"]

    graph = Graph(nodes=(domain, ip, target), edges=deduped)
    assert graph.resolved_edges == ()
    assert [e.evidence_id for e in graph.unresolved_legacy_edges] == ["ev1", "ev2"]
    assert set(graph.orphan_ids) == {domain.id, ip.id, target.id}


def test_identical_ambiguous_legacy_edges_remain_observable() -> None:
    domain = _domain_node("127.0.0.1", "ev-domain")
    ip = _ip_node("127.0.0.1", "ev-ip")
    target = _ip_node("10.0.0.1", "ev-target", hostname="x")
    e1 = Edge(source="127.0.0.1", target="10.0.0.1", kind="rel", evidence_id="ev1")
    e2 = Edge(source="127.0.0.1", target="10.0.0.1", kind="rel", evidence_id="ev1")

    graph = Graph(nodes=(domain, ip, target), edges=dedupe_edges([e1, e2]))
    assert len(graph.unresolved_legacy_edges) == 2
    assert graph.resolved_edges == ()


def test_canonical_edges_same_display_keys_different_ids_remain_distinct() -> None:
    domain = _domain_node("127.0.0.1", "ev-domain")
    ip = _ip_node("127.0.0.1", "ev-ip")
    target = _ip_node("10.0.0.1", "ev-target", hostname="x")
    e_domain = Edge(source="127.0.0.1", target="10.0.0.1", kind="rel", evidence_id="ev-domain", source_id=domain.id, target_id=target.id, source_key="127.0.0.1", target_key="10.0.0.1")
    e_ip = Edge(source="127.0.0.1", target="10.0.0.1", kind="rel", evidence_id="ev-ip", source_id=ip.id, target_id=target.id, source_key="127.0.0.1", target_key="10.0.0.1")

    graph = Graph(nodes=(domain, ip, target), edges=dedupe_edges([e_domain, e_ip]))
    assert len(graph.resolved_edges) == 2
    assert {e.source_id for e in graph.resolved_edges} == {domain.id, ip.id}


def test_canonically_equivalent_resolved_edges_deduplicate_first_seen() -> None:
    src = _domain_node("example.com", "ev-src")
    tgt = _ip_node("1.2.3.4", "ev-tgt", hostname="example.com")
    e1 = Edge(source="example.com", target="1.2.3.4", kind="resolves_to", evidence_id="ev1", source_id=src.id, target_id=tgt.id, source_key="example.com", target_key="1.2.3.4")
    e2 = Edge(source="example.com", target="1.2.3.4", kind="resolves_to", evidence_id="ev2", source_id=src.id, target_id=tgt.id, source_key="example.com", target_key="1.2.3.4")

    graph = Graph(nodes=(src, tgt), edges=dedupe_edges([e1, e2]))
    assert len(graph.resolved_edges) == 1
    assert graph.resolved_edges[0].evidence_id == "ev1"


def test_complete_asset_graph_style_path_preserves_ambiguous_legacy_edges() -> None:
    from correlation.deduplication import dedupe_nodes

    domain = _domain_node("127.0.0.1", "ev-domain")
    ip = _ip_node("127.0.0.1", "ev-ip")
    target = _ip_node("10.0.0.1", "ev-target", hostname="x")
    e1 = Edge(source="127.0.0.1", target="10.0.0.1", kind="rel", evidence_id="intent-domain")
    e2 = Edge(source="127.0.0.1", target="10.0.0.1", kind="rel", evidence_id="intent-ip")

    nodes = dedupe_nodes([domain, ip, target])
    edges = dedupe_edges([e1, e2])
    graph = Graph(nodes=nodes, edges=edges)

    assert len(edges) == 2
    assert graph.resolved_edges == ()
    assert [e.evidence_id for e in graph.unresolved_legacy_edges] == ["intent-domain", "intent-ip"]
    assert set(graph.orphan_ids) == {n.id for n in nodes}

def test_merge_graphs_preserves_unresolved_legacy_edges() -> None:
    from correlation.deduplication import merge_graphs

    domain = _domain_node("127.0.0.1", "ev-domain")
    ip = _ip_node("127.0.0.1", "ev-ip")
    target = _ip_node("10.0.0.1", "ev-target", hostname="x")
    e1 = Edge(source="127.0.0.1", target="10.0.0.1", kind="rel", evidence_id="ev1")
    e2 = Edge(source="127.0.0.1", target="10.0.0.1", kind="rel", evidence_id="ev2")
    g1 = Graph(nodes=(domain, ip, target), edges=(e1,))
    g2 = Graph(nodes=(domain, ip, target), edges=(e2,))

    merged = merge_graphs([g1, g2])
    assert merged.resolved_edges == ()
    assert [e.evidence_id for e in merged.unresolved_legacy_edges] == ["ev1", "ev2"]
    assert set(merged.orphan_ids) == {domain.id, ip.id, target.id}
