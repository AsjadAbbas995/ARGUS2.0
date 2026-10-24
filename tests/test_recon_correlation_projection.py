"""Phase 28 Step 1: parity between ``recon.correlate_endpoints`` and the committed graph.

Synthetic, in-memory records only -- no PostgreSQL, no projection I/O. The point is to
prove the helper groups and attaches exactly what ``correlation.asset_graph`` already
encodes, and to make explicit where the graph's deduplication loses observations that the
helper preserves.
"""

from __future__ import annotations

from correlation.asset_graph import build
from correlation.records import (
    DomainRecord,
    EndpointRecord,
    ParameterRecord,
    endpoint_key,
)
from recon.correlation import correlate_endpoints


def _mixed_records() -> list:
    users = endpoint_key("GET", "/users/{id}", "example.com")
    login = endpoint_key("POST", "/login", "example.com")
    return [
        DomainRecord(hostname="example.com", evidence_id="d1"),
        EndpointRecord(
            method="GET",
            pattern="/users/{id}",
            host="example.com",
            evidence_id="e1",
        ),
        EndpointRecord(
            method="GET",
            pattern="/users/{id}",
            host="example.com",
            evidence_id="e2",
        ),
        EndpointRecord(
            method="POST",
            pattern="/login",
            host="example.com",
            evidence_id="e3",
        ),
        ParameterRecord(
            endpoint_key=users,
            name="id",
            location="path",
            significance="object_id",
            evidence_id="p1",
        ),
        ParameterRecord(
            endpoint_key=users,
            name="expand",
            location="query",
            significance="low",
            evidence_id="p2",
        ),
        ParameterRecord(
            endpoint_key=login,
            name="password",
            location="body",
            significance="high",
            evidence_id="p3",
        ),
    ]


def _groups_by_key(records: list) -> dict:
    return {group.endpoint_key: group for group in correlate_endpoints(records)}


def test_grouping_matches_graph_endpoint_nodes():
    records = _mixed_records()
    graph = build(records)
    groups = _groups_by_key(records)
    endpoint_nodes = {node.key for node in graph.nodes if node.kind == "endpoint"}
    assert set(groups) == endpoint_nodes


def test_parameter_attachment_matches_has_parameter_edges():
    records = _mixed_records()
    graph = build(records)
    groups = _groups_by_key(records)
    for key, group in groups.items():
        edge_targets = {
            edge.target
            for edge in graph.edges_from(key)
            if edge.kind == "has_parameter"
        }
        group_targets = {
            f"{param.endpoint_key}#{param.name}" for param in group.parameters
        }
        assert edge_targets == group_targets


def test_graph_collapses_duplicate_endpoints_helper_preserves_them():
    users = endpoint_key("GET", "/users/{id}", "example.com")
    records = _mixed_records()
    graph = build(records)
    group = _groups_by_key(records)[users]

    assert len(group.endpoints) == 2
    assert group.evidence_ids == ("e1", "e2", "p1", "p2")
    assert len([node for node in graph.nodes if node.key == users]) == 1
    assert graph.find(users).evidence_id == "e1"


def test_graph_collapses_duplicate_parameters_helper_preserves_them():
    key = endpoint_key("GET", "/dup", "example.com")
    endpoint = EndpointRecord(
        method="GET", pattern="/dup", host="example.com", evidence_id="e1"
    )
    param_a = ParameterRecord(
        endpoint_key=key,
        name="q",
        location="query",
        significance="low",
        evidence_id="p1",
    )
    param_b = ParameterRecord(
        endpoint_key=key,
        name="q",
        location="query",
        significance="low",
        evidence_id="p1",
    )
    records = [endpoint, param_a, param_b]
    graph = build(records)
    group = correlate_endpoints(records)[0]

    assert len(group.parameters) == 2
    param_key = f"{key}#q"
    param_nodes = [node for node in graph.nodes if node.key == param_key]
    assert len(param_nodes) == 1
    assert param_nodes[0].evidence_id == "p1"


def test_reordered_input_and_repeated_calls_are_deterministic():
    records = _mixed_records()
    first = correlate_endpoints(records)
    assert correlate_endpoints(records) == first
    assert correlate_endpoints(list(reversed(records))) == first


def test_grouped_observations_are_the_original_record_objects():
    records = _mixed_records()
    for group in correlate_endpoints(records):
        for endpoint in group.endpoints:
            assert any(endpoint is original for original in records)
