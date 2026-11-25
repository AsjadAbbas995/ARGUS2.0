"""Phase-8 typed correlation records and the attack-surface graph primitives
("05_DATA_MODEL.md" entities, "03_RECON_PIPELINE.md" §25 Logical Grouping).

The graph is a *descriptive* view over normalized records: it only links what the recorded
facts support, every node/edge carries the traceable evidence that justifies it, and an
orphaned/unlinkable record is **stored without an edge rather than dropped**
(03 §25 failure condition). Building the graph never grants execution capability.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional


@dataclass(frozen=True)
class DomainRecord:
    """An in-scope domain or discovered subdomain."""

    hostname: str
    evidence_id: str

    @property
    def key(self) -> str:
        return self.hostname


@dataclass(frozen=True)
class IpRecord:
    """A resolved host -> IP binding."""

    address: str
    hostname: str
    evidence_id: str

    @property
    def key(self) -> str:
        return self.address


@dataclass(frozen=True)
class PortRecord:
    """An open port on an IP with its detected service."""

    ip: str
    number: int
    service: str
    evidence_id: str

    @property
    def key(self) -> str:
        return f"{self.ip}:{self.number}"


@dataclass(frozen=True)
class WebAppRecord:
    """A probed web application on a host:port."""

    host: str
    port: int
    status_code: int
    title: str
    ip: str
    evidence_id: str

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass(frozen=True)
class UrlRecord:
    """A recorded crawl URL (one path under a web app's host:port)."""

    host: str
    port: int
    path: str
    source: str
    evidence_id: str
    historical: bool = False

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}{self.path}"


@dataclass(frozen=True)
class EndpointRecord:
    """A recorded HTTP endpoint (method + URL pattern on a host)."""

    method: str
    pattern: str
    host: str
    evidence_id: str

    @property
    def key(self) -> str:
        return endpoint_key(self.method, self.pattern, self.host)


def endpoint_key(method: str, pattern: str, host: str) -> str:
    """Stable key for an endpoint (also used by parameter/auth records to link back)."""
    return f"{method} {pattern} {host}"


@dataclass(frozen=True)
class ParameterRecord:
    """A recorded endpoint parameter."""

    endpoint_key: str
    name: str
    location: str
    significance: str
    evidence_id: str

    @property
    def key(self) -> str:
        return f"{self.endpoint_key}#{self.name}"


@dataclass(frozen=True)
class AuthRecord:
    """One recorded authentication mechanism for an endpoint."""

    mechanism_type: str
    endpoint_key: str
    evidence_id: str

    @property
    def key(self) -> str:
        return f"{self.endpoint_key}#auth:{self.mechanism_type}"


@dataclass(frozen=True)
class ApiRecord:
    """A documented or inferred API binding on a host."""

    name: str
    api_type: str
    host: str
    documented: bool
    evidence_id: str

    @property
    def key(self) -> str:
        return f"{self.name}@{self.host}"


@dataclass(frozen=True)
class TechnologyRecord:
    """One technology observed on a host."""

    name: str
    category: str
    host: str
    evidence_id: str

    @property
    def key(self) -> str:
        return f"{self.name}@{self.host}"


@dataclass(frozen=True)
class JavaScriptRecord:
    """A JavaScript file of interest and the endpoints it surfaced (if any)."""

    js_url: str
    host: str
    evidence_id: str
    endpoint_keys: tuple[str, ...] = field(default_factory=tuple)

    @property
    def key(self) -> str:
        return self.js_url


@dataclass(frozen=True)
class CertificateRecord:
    """A TLS certificate observed for a host."""

    subject: str
    host: str
    evidence_id: str

    @property
    def key(self) -> str:
        return self.subject


# --- graph primitives ---------------------------------------------------------


class NodeIdentityConflict(ValueError):
    """Raised when two nodes share a canonical id but have incompatible payloads."""


class NodeLookupAmbiguity(LookupError):
    """Raised when a legacy/display-key lookup matches multiple canonical nodes."""


def canonical_node_id(kind: str, components: tuple[Any, ...]) -> str:
    """Deterministic, type-aware canonical node identity.

    The encoding is structured JSON so component boundaries are unambiguous and
    different kinds/components cannot collide by delimiter tricks.
    """
    return json.dumps(
        [kind, list(components)],
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _record_identity_components(record: Any) -> tuple[Any, ...]:
    if isinstance(record, DomainRecord):
        return (record.hostname,)
    if isinstance(record, IpRecord):
        return (record.address,)
    if isinstance(record, PortRecord):
        return (record.ip, record.number)
    if isinstance(record, WebAppRecord):
        return (record.host, record.port)
    if isinstance(record, UrlRecord):
        return (record.host, record.port, record.path)
    if isinstance(record, EndpointRecord):
        return (record.method, record.pattern, record.host)
    if isinstance(record, ParameterRecord):
        return (record.endpoint_key, record.location, record.name)
    if isinstance(record, AuthRecord):
        return (record.endpoint_key, record.mechanism_type)
    if isinstance(record, ApiRecord):
        return (record.host, record.name, record.api_type)
    if isinstance(record, TechnologyRecord):
        return (record.host, record.name, record.category)
    if isinstance(record, JavaScriptRecord):
        return (record.js_url,)
    if isinstance(record, CertificateRecord):
        return (record.host, record.subject)
    return (record.key,)


@dataclass(frozen=True)
class Node:
    """One graph node; ``kind`` names the record type it mirrors.

    ``key`` is the human-readable display key and is preserved for compatibility.
    ``id`` is the canonical, type-aware identity used for deduplication.
    """

    key: str
    kind: str
    evidence_id: str
    attributes: Mapping[str, str] = field(default_factory=dict)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            object.__setattr__(self, "id", canonical_node_id(self.kind, (self.key,)))


@dataclass(frozen=True)
class Edge:
    """One evidence-referenced directed edge.

    Canonical identity is ``(source_id, target_id, kind)`` when endpoint IDs are
    resolved. ``source``/``target`` are display-key compatibility aliases and must
    not be interpreted as canonical node IDs. ``source_key``/``target_key`` carry
    display metadata. Legacy unresolved edges have empty endpoint IDs and are kept
    observable until Stage 2A.2 migrates builders.
    """

    source: str
    target: str
    kind: str
    evidence_id: str
    source_id: str = ""
    target_id: str = ""
    source_key: str = ""
    target_key: str = ""

    def __post_init__(self) -> None:
        # Normalize display-key metadata. Never infer canonical IDs from keys.
        src_key = self.source_key or self.source
        tgt_key = self.target_key or self.target
        object.__setattr__(self, "source_key", src_key)
        object.__setattr__(self, "target_key", tgt_key)
        # Keep legacy display aliases populated for compatibility callers.
        if not self.source:
            object.__setattr__(self, "source", src_key)
        if not self.target:
            object.__setattr__(self, "target", tgt_key)

    @property
    def is_resolved(self) -> bool:
        return bool(self.source_id and self.target_id)


@dataclass(frozen=True)
class Graph:
    """A queryable, descriptive attack-surface graph (see module docstring)."""

    nodes: tuple[Node, ...] = field(default_factory=tuple)
    edges: tuple[Edge, ...] = field(default_factory=tuple)
    _nodes_by_id: Mapping[str, Node] = field(default_factory=dict, repr=False, compare=False)
    _node_ids_by_key: Mapping[str, tuple[str, ...]] = field(
        default_factory=dict, repr=False, compare=False
    )
    _edges_from_id: Mapping[str, tuple[Edge, ...]] = field(
        default_factory=dict, repr=False, compare=False
    )
    _edges_to_id: Mapping[str, tuple[Edge, ...]] = field(
        default_factory=dict, repr=False, compare=False
    )
    _resolved_edges: tuple[Edge, ...] = field(default_factory=tuple, repr=False, compare=False)
    _unresolved_legacy_edges: tuple[Edge, ...] = field(
        default_factory=tuple, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        nodes_by_id: dict[str, Node] = {}
        node_ids_by_key: dict[str, list[str]] = {}
        for node in self.nodes:
            node_id = node.id or canonical_node_id(node.kind, (node.key,))
            if node_id in nodes_by_id:
                raise NodeIdentityConflict(f"duplicate node id in graph: {node_id!r}")
            nodes_by_id[node_id] = node
            node_ids_by_key.setdefault(node.key, []).append(node_id)

        resolved_edges: list[Edge] = []
        unresolved_legacy_edges: list[Edge] = []
        seen_resolved: set[tuple[str, str, str]] = set()
        for edge in self.edges:
            src_id = edge.source_id
            tgt_id = edge.target_id
            candidate = edge
            # Legacy compatibility bridge: resolve only when both endpoint display
            # keys map unambiguously to exactly one canonical node each. Never infer
            # IDs from ambiguous keys.
            if not src_id and not tgt_id and edge.source_key and edge.target_key:
                src_matches = node_ids_by_key.get(edge.source_key, [])
                tgt_matches = node_ids_by_key.get(edge.target_key, [])
                if len(src_matches) == 1 and len(tgt_matches) == 1:
                    src_id = src_matches[0]
                    tgt_id = tgt_matches[0]
                    candidate = Edge(
                        source=edge.source_key,
                        target=edge.target_key,
                        kind=edge.kind,
                        evidence_id=edge.evidence_id,
                        source_id=src_id,
                        target_id=tgt_id,
                        source_key=edge.source_key,
                        target_key=edge.target_key,
                    )
                else:
                    unresolved_legacy_edges.append(edge)
                    continue
            if src_id and tgt_id and src_id in nodes_by_id and tgt_id in nodes_by_id:
                dedupe_key = (src_id, tgt_id, candidate.kind)
                if dedupe_key in seen_resolved:
                    continue
                seen_resolved.add(dedupe_key)
                resolved_edges.append(candidate)
            else:
                # Preserve every unresolved legacy edge; do not collapse by display key/kind.
                unresolved_legacy_edges.append(edge)

        edges_from_id: dict[str, list[Edge]] = {}
        edges_to_id: dict[str, list[Edge]] = {}
        for edge in resolved_edges:
            edges_from_id.setdefault(edge.source_id, []).append(edge)
            edges_to_id.setdefault(edge.target_id, []).append(edge)

        object.__setattr__(self, "_nodes_by_id", nodes_by_id)
        object.__setattr__(
            self,
            "_node_ids_by_key",
            {k: tuple(v) for k, v in node_ids_by_key.items()},
        )
        object.__setattr__(
            self, "_edges_from_id", {k: tuple(v) for k, v in edges_from_id.items()}
        )
        object.__setattr__(
            self, "_edges_to_id", {k: tuple(v) for k, v in edges_to_id.items()}
        )
        object.__setattr__(self, "_resolved_edges", tuple(resolved_edges))
        object.__setattr__(self, "_unresolved_legacy_edges", tuple(unresolved_legacy_edges))

    @property
    def nodes_by_id(self) -> Mapping[str, Node]:
        return self._nodes_by_id

    @property
    def node_ids_by_key(self) -> Mapping[str, tuple[str, ...]]:
        return self._node_ids_by_key

    @property
    def resolved_edges(self) -> tuple[Edge, ...]:
        return self._resolved_edges

    @property
    def unresolved_legacy_edges(self) -> tuple[Edge, ...]:
        """Legacy edges that could not be resolved unambiguously to canonical IDs."""
        return self._unresolved_legacy_edges

    def nodes_of(self, kind: str) -> tuple[Node, ...]:
        return tuple(n for n in self.nodes if n.kind == kind)

    def find_by_id(self, node_id: str) -> Optional[Node]:
        return self._nodes_by_id.get(node_id)

    def find_by_key(self, key: str, kind: str | None = None) -> tuple[Node, ...]:
        ids = self._node_ids_by_key.get(key, ())
        nodes = tuple(self._nodes_by_id[i] for i in ids if i in self._nodes_by_id)
        if kind is None:
            return nodes
        return tuple(n for n in nodes if n.kind == kind)

    def find(self, key: str) -> Optional[Node]:
        """Legacy display-key lookup. Fail closed on ambiguity."""
        matches = self.find_by_key(key)
        if not matches:
            return None
        if len(matches) > 1:
            kinds = ",".join(sorted({m.kind for m in matches}))
            raise NodeLookupAmbiguity(
                f"ambiguous legacy node lookup for key {key!r}; matches kinds [{kinds}]"
            )
        return matches[0]

    def edges_from_id(self, node_id: str) -> tuple[Edge, ...]:
        return self._edges_from_id.get(node_id, ())

    def edges_to_id(self, node_id: str) -> tuple[Edge, ...]:
        return self._edges_to_id.get(node_id, ())

    def neighbors_by_id(self, node_id: str) -> tuple[Node, ...]:
        targets = []
        seen: set[str] = set()
        for edge in self.edges_from_id(node_id):
            tid = edge.target_id
            if tid and tid not in seen and tid in self._nodes_by_id:
                seen.add(tid)
                targets.append(self._nodes_by_id[tid])
        return tuple(targets)

    def _require_unambiguous_key(self, key: str) -> tuple[str, ...]:
        ids = self._node_ids_by_key.get(key, ())
        if len(ids) > 1:
            kinds = ",".join(sorted({self._nodes_by_id[i].kind for i in ids if i in self._nodes_by_id}))
            raise NodeLookupAmbiguity(
                f"ambiguous legacy key traversal for key {key!r}; matches kinds [{kinds}]"
            )
        return ids

    def edges_from(self, key: str) -> tuple[Edge, ...]:
        """Legacy key traversal. Fail closed on ambiguous keys."""
        ids = self._require_unambiguous_key(key)
        if not ids:
            return ()
        return self.edges_from_id(ids[0])

    def edges_to(self, key: str) -> tuple[Edge, ...]:
        """Legacy key traversal. Fail closed on ambiguous keys."""
        ids = self._require_unambiguous_key(key)
        if not ids:
            return ()
        return self.edges_to_id(ids[0])

    def neighbors(self, key: str) -> tuple[Node, ...]:
        """Legacy key traversal. Fail closed on ambiguous keys."""
        ids = self._require_unambiguous_key(key)
        if not ids:
            return ()
        return self.neighbors_by_id(ids[0])

    @property
    def orphan_ids(self) -> tuple[str, ...]:
        """Canonical node IDs with no incident resolved edge."""
        linked = {e.source_id for e in self._resolved_edges} | {
            e.target_id for e in self._resolved_edges
        }
        return tuple(n.id for n in self.nodes if n.id not in linked)

    @property
    def orphan_keys(self) -> tuple[str, ...]:
        """Display-key compatibility view derived from canonical orphan IDs.

        Computed only from canonical resolved edge references. Unresolved legacy
        edges are observable via ``unresolved_legacy_edges`` and may temporarily
        cause orphan classifications until Stage 2A.2.
        """
        orphan_ids = set(self.orphan_ids)
        return tuple(n.key for n in self.nodes if n.id in orphan_ids)


def record_node(record: Any) -> Node:
    """Mirror any correlation record into a graph ``Node`` (kind = record type)."""
    kind = type(record).__name__.removesuffix("Record").lower()
    attributes: dict[str, str] = {}
    for name, value in vars(record).items():
        if name == "evidence_id":
            continue
        if isinstance(value, tuple):
            attributes[name] = "|".join(str(v) for v in value)
        else:
            attributes[name] = str(value)
    return Node(
        key=record.key,
        kind=kind,
        evidence_id=record.evidence_id,
        attributes=attributes,
        id=canonical_node_id(kind, _record_identity_components(record)),
    )