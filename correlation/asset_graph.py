"""Attack-Surface Graph builder ("03_RECON_PIPELINE.md" §25 Logical Grouping).

Turns normalized correlation records into a queryable ``Graph`` spanning
``Domain → Subdomain → IP → Port → Service → Web App → URL → Endpoint → Parameter →
API/Authentication/Technology`` plus cross-links (``JavaScript → Endpoint``,
``Certificate → Domain``, ``API → Endpoint``). Every edge is evidence-referenced, and a
record with no derivable link is still stored as a node — never dropped.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

from correlation.deduplication import dedupe_edges, dedupe_nodes
from correlation.records import Edge, Graph, Node, record_node


class GraphIndexInvariantError(ValueError):
    """Raised when a unique typed graph index contains duplicate typed keys."""


@dataclass(frozen=True)
class _TypedIndexes:
    domains_by_hostname: dict[str, Node]
    ips_by_address: dict[str, Node]
    ports_by_ip_port: dict[tuple[str, int], Node]
    webapps_by_host_port: dict[tuple[str, int], Node]
    webapps_by_host: dict[str, tuple[Node, ...]]
    endpoints_by_logical_key: dict[str, Node]
    endpoints_by_host: dict[str, tuple[Node, ...]]


def build(records: Iterable[Any]) -> Graph:
    """Build the evidence-referenced attack-surface graph over ``records``.

    Deterministic: the same records always yield the same node/edge sets. Orphaned nodes
    remain stored without an edge (03 §25 failure condition).
    """
    nodes = dedupe_nodes([record_node(r) for r in records])
    indexes = _build_typed_indexes(nodes)
    edges: list[Edge] = []
    for node in nodes:
        edges.extend(_edges_for(node, indexes))
    return Graph(nodes=dedupe_nodes(nodes), edges=dedupe_edges(edges))


def _set_unique(index: dict[Any, Node], key: Any, node: Node, index_name: str) -> None:
    existing = index.get(key)
    if existing is None:
        index[key] = node
        return
    if existing.id == node.id:
        return
    raise GraphIndexInvariantError(
        f"duplicate key {key!r} in unique index {index_name!r}: "
        f"{existing.kind}:{existing.key!r} ({existing.id}) vs "
        f"{node.kind}:{node.key!r} ({node.id})"
    )


def _append_grouped(index: dict[str, list[Node]], key: str, node: Node) -> None:
    if not key:
        return
    index.setdefault(key, []).append(node)


def _build_typed_indexes(nodes: tuple[Node, ...]) -> _TypedIndexes:
    domains_by_hostname: dict[str, Node] = {}
    ips_by_address: dict[str, Node] = {}
    ports_by_ip_port: dict[tuple[str, int], Node] = {}
    webapps_by_host_port: dict[tuple[str, int], Node] = {}
    webapps_by_host_lists: dict[str, list[Node]] = {}
    endpoints_by_logical_key: dict[str, Node] = {}
    endpoints_by_host_lists: dict[str, list[Node]] = {}

    for node in nodes:
        if node.kind == "domain":
            hostname = _attr(node, "hostname") or node.key
            if hostname:
                _set_unique(domains_by_hostname, hostname, node, "domains_by_hostname")
        elif node.kind == "ip":
            address = _attr(node, "address") or node.key
            if address:
                _set_unique(ips_by_address, address, node, "ips_by_address")
        elif node.kind == "port":
            ip = _attr(node, "ip")
            number = _attr_int(node, "number")
            if ip and number is not None:
                _set_unique(ports_by_ip_port, (ip, number), node, "ports_by_ip_port")
        elif node.kind == "webapp":
            host = _attr(node, "host")
            port = _attr_int(node, "port")
            if host and port is not None:
                _set_unique(webapps_by_host_port, (host, port), node, "webapps_by_host_port")
            _append_grouped(webapps_by_host_lists, host, node)
        elif node.kind == "endpoint":
            logical_key = node.key
            if logical_key:
                _set_unique(endpoints_by_logical_key, logical_key, node, "endpoints_by_logical_key")
            _append_grouped(endpoints_by_host_lists, _attr(node, "host"), node)

    return _TypedIndexes(
        domains_by_hostname=domains_by_hostname,
        ips_by_address=ips_by_address,
        ports_by_ip_port=ports_by_ip_port,
        webapps_by_host_port=webapps_by_host_port,
        webapps_by_host={k: tuple(v) for k, v in webapps_by_host_lists.items()},
        endpoints_by_logical_key=endpoints_by_logical_key,
        endpoints_by_host={k: tuple(v) for k, v in endpoints_by_host_lists.items()},
    )


def _edge(source: Node, target: Node, kind: str, evidence_id: str) -> Edge:
    return Edge(
        source=source.key,
        target=target.key,
        kind=kind,
        evidence_id=evidence_id,
        source_id=source.id,
        target_id=target.id,
        source_key=source.key,
        target_key=target.key,
    )


def _edges_for(node: Node, indexes: _TypedIndexes) -> list[Edge]:
    if node.kind == "domain":
        return _domain_edges(node, indexes)
    if node.kind == "ip":
        return _ip_edges(node, indexes)
    if node.kind == "port":
        return _port_edges(node, indexes)
    if node.kind == "webapp":
        return _webapp_edges(node, indexes)
    if node.kind == "url":
        return _url_edges(node, indexes)
    if node.kind == "endpoint":
        return _endpoint_edges(node, indexes)
    if node.kind == "parameter":
        return _parameter_edges(node, indexes)
    if node.kind == "auth":
        return _auth_edges(node, indexes)
    if node.kind == "api":
        return _api_edges(node, indexes)
    if node.kind == "javascript":
        return _javascript_edges(node, indexes)
    if node.kind == "certificate":
        return _certificate_edges(node, indexes)
    if node.kind == "technology":
        return _technology_edges(node, indexes)
    return []


def _resolve_host(indexes: _TypedIndexes, host: str) -> Optional[Node]:
    """Resolve a host using typed domain-first, then unique-webapp fallback."""
    if not host:
        return None
    domain = indexes.domains_by_hostname.get(host)
    if domain is not None and domain.kind == "domain":
        return domain
    candidates = tuple(
        node
        for node in indexes.webapps_by_host.get(host, ())
        if node.kind == "webapp" and _attr(node, "host") == host
    )
    if len(candidates) == 1:
        return candidates[0]
    return None


def _domain_edges(node: Node, indexes: _TypedIndexes) -> list[Edge]:
    hostname = _attr(node, "hostname") or node.key
    parts = hostname.split(".")
    parent = ".".join(parts[1:]) if len(parts) > 1 else ""
    if not parent:
        return []
    target = indexes.domains_by_hostname.get(parent)
    if target is None:
        return []
    return [_edge(target, node, "parent_of", node.evidence_id)]


def _ip_edges(node: Node, indexes: _TypedIndexes) -> list[Edge]:
    host = _attr(node, "hostname")
    target = _resolve_host(indexes, host)
    if target is None:
        return []
    return [_edge(target, node, "resolves_to", node.evidence_id)]


def _port_edges(node: Node, indexes: _TypedIndexes) -> list[Edge]:
    ip = _attr(node, "ip")
    if not ip:
        return []
    target = indexes.ips_by_address.get(ip)
    if target is None:
        return []
    return [_edge(target, node, "hosts", node.evidence_id)]


def _webapp_edges(node: Node, indexes: _TypedIndexes) -> list[Edge]:
    ip = _attr(node, "ip")
    port = _attr_int(node, "port")
    if not ip or port is None:
        return []
    target = indexes.ports_by_ip_port.get((ip, port))
    if target is None:
        return []
    return [_edge(target, node, "serves", node.evidence_id)]


def _endpoint_edges(node: Node, indexes: _TypedIndexes) -> list[Edge]:
    host = _attr(node, "host")
    target = _resolve_host(indexes, host)
    if target is None:
        return []
    return [_edge(target, node, "serves_url", node.evidence_id)]


def _url_edges(node: Node, indexes: _TypedIndexes) -> list[Edge]:
    """Link a crawl URL to its webapp by typed (host,port), else typed host fallback."""
    host = _attr(node, "host")
    port = _attr_int(node, "port")
    if host and port is not None:
        webapp = indexes.webapps_by_host_port.get((host, port))
        if webapp is not None:
            return [_edge(webapp, node, "serves_url", node.evidence_id)]
    target = _resolve_host(indexes, host)
    if target is None:
        return []
    return [_edge(target, node, "serves_url", node.evidence_id)]


def _parameter_edges(node: Node, indexes: _TypedIndexes) -> list[Edge]:
    endpoint = _attr(node, "endpoint_key")
    if not endpoint:
        return []
    target = indexes.endpoints_by_logical_key.get(endpoint)
    if target is None:
        return []
    return [_edge(target, node, "has_parameter", node.evidence_id)]


def _auth_edges(node: Node, indexes: _TypedIndexes) -> list[Edge]:
    endpoint = _attr(node, "endpoint_key")
    if not endpoint:
        return []
    target = indexes.endpoints_by_logical_key.get(endpoint)
    if target is None:
        return []
    return [_edge(target, node, "requires_auth", node.evidence_id)]


def _api_edges(node: Node, indexes: _TypedIndexes) -> list[Edge]:
    host = _attr(node, "host")
    edges: list[Edge] = []
    hostnode = _resolve_host(indexes, host)
    if hostnode is not None:
        edges.append(_edge(hostnode, node, "hosts_api", node.evidence_id))
    if _attr(node, "documented") == "True":
        for other in indexes.endpoints_by_host.get(host, ()):
            if other.kind == "endpoint" and _attr(other, "host") == host:
                edges.append(_edge(node, other, "documents", node.evidence_id))
    return edges


def _javascript_edges(node: Node, indexes: _TypedIndexes) -> list[Edge]:
    edges: list[Edge] = []
    for endpoint in _attr(node, "endpoint_keys").split("|"):
        if not endpoint:
            continue
        target = indexes.endpoints_by_logical_key.get(endpoint)
        if target is not None:
            edges.append(_edge(node, target, "references", node.evidence_id))
    return edges


def _certificate_edges(node: Node, indexes: _TypedIndexes) -> list[Edge]:
    target = _resolve_host(indexes, _attr(node, "host"))
    if target is None:
        return []
    return [_edge(node, target, "identity_of", node.evidence_id)]


def _technology_edges(node: Node, indexes: _TypedIndexes) -> list[Edge]:
    target = _resolve_host(indexes, _attr(node, "host"))
    if target is None:
        return []
    return [_edge(target, node, "runs", node.evidence_id)]


def _attr(node: Node, name: str) -> str:
    return node.attributes.get(name, "")


def _attr_int(node: Node, name: str) -> Optional[int]:
    value = node.attributes.get(name, "")
    if value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
