"""Correlation-level deduplication ("03_RECON_PIPELINE.md" §26 Correlation tools).

Deduplicates graph primitives and correlation inferences so repeated re-analysis over the
same recorded evidence cannot grow the graph or generate duplicate inferences forever. The
deterministic ``fingerprint`` digest is the anti-infinite-loop key used by the adaptive loop.
"""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Iterable, Sequence, TypeVar

from correlation.records import Edge, Graph, Node, NodeIdentityConflict

_T = TypeVar("_T")


def fingerprint(value: Any) -> str:
    """Deterministic content digest (stable across processes/machines)."""
    digest = hashlib.sha256()
    digest.update(repr(_stable(value)).encode("utf-8"))
    return digest.hexdigest()


def _stable(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _stable(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_stable(item) for item in value]
    return value


def _dedupe(items: Iterable[_T], key: Callable[[_T], Any]) -> tuple[_T, ...]:
    """Drop later items sharing a key, preserving first-occurrence order."""
    seen: set = set()
    kept: list[_T] = []
    for item in items:
        k = key(item)
        if k in seen:
            continue
        seen.add(k)
        kept.append(item)
    return tuple(kept)


def _node_conflict(existing: Node, candidate: Node) -> bool:
    """Return True when same-canonical-id nodes are semantically incompatible.

    Evidence IDs are provenance, not graph identity: different evidence IDs for the
    same canonical entity are legitimate repeated observations and must not conflict.

    Attribute semantics are currently conservative: ``record_node()`` copies all
    record fields except ``evidence_id`` into attributes, but the model does not yet
    distinguish stable canonical attributes from mutable observation attributes. To
    avoid silently discarding meaningful conflicting observations, any attribute
    difference remains a conflict for now. This is an explicit design limitation;
    do not broaden to silent merge without a field-level classification.
    """
    if existing.kind != candidate.kind or existing.key != candidate.key:
        return True
    if dict(existing.attributes) != dict(candidate.attributes):
        return True
    return False


def dedupe_nodes(nodes: Iterable[Node]) -> tuple[Node, ...]:
    """Deduplicate nodes by canonical ``id``.

    First occurrence wins for equivalent duplicates, including repeated observations
    that differ only by evidence provenance. Conflicting same-id nodes with
    incompatible attributes are rejected to avoid silently discarding incompatible
    payloads.
    """
    seen: dict[str, Node] = {}
    kept: list[Node] = []
    for node in nodes:
        node_id = node.id or node.key
        existing = seen.get(node_id)
        if existing is not None:
            if _node_conflict(existing, node):
                raise NodeIdentityConflict(
                    f"conflicting node payloads share canonical id {node_id!r}: "
                    f"{existing.kind}:{existing.key!r} vs {node.kind}:{node.key!r}"
                )
            continue
        seen[node_id] = node
        kept.append(node)
    return tuple(kept)


def dedupe_edges(edges: Iterable[Edge]) -> tuple[Edge, ...]:
    """Deduplicate canonical resolved edges only.

    Canonical resolved edges dedupe by ``(source_id, target_id, kind)`` with
    first occurrence wins. Legacy edges lacking complete canonical endpoint IDs
    are preserved in their original deterministic order; display-key dedupe is
    unsafe before ambiguity detection and must not discard information.
    """
    seen: set[tuple[str, str, str]] = set()
    kept: list[Edge] = []
    for edge in edges:
        if edge.source_id and edge.target_id:
            key = (edge.source_id, edge.target_id, edge.kind)
            if key in seen:
                continue
            seen.add(key)
        kept.append(edge)
    return tuple(kept)


def dedupe_inferences(inferences: Iterable[_T]) -> tuple[_T, ...]:
    """Deduplicate inferences by their fingerprint (first occurrence wins)."""
    return _dedupe(inferences, lambda i: fingerprint(i))


def merge_graphs(graphs: Sequence[Graph]) -> Graph:
    """Union of several graphs with nodes/edges deduplicated by identity."""
    nodes = dedupe_nodes(n for graph in graphs for n in graph.nodes)
    edges = dedupe_edges(e for graph in graphs for e in graph.edges)
    return Graph(nodes=nodes, edges=edges)