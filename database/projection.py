"""Phase 15 canonical read projection: PostgreSQL -> ``correlation.records`` -> graph.

This is the *read* side of the canonical store. Phase 14 established the write path
(``ToolExecution.artifacts`` -> ``recon.ingest`` -> PostgreSQL, with an ``evidence`` row
per canonical fact). That write path stopped at the database: nothing ever read those
facts back, so ``correlation``/``ai``/``reports`` were production-dead even though they
were built and tested. This module closes that gap and nothing else.

Pipeline
--------
::

    PostgreSQL
        -> run-scoped projection      (this module: SQL reads + pure transformation)
        -> correlation.records        (already-committed frozen dataclasses)
        -> correlation.asset_graph    (already-committed, unchanged)
        -> correlation.relationship_engine (already-committed, unchanged)
        -> AttackSurface              (in-memory, derived, never persisted)

Architecture rule: **read-only**. This module never writes PostgreSQL, never mutates
evidence, never resolves DNS, never performs HTTP, never invokes a tool or an AI agent,
never touches scope, and never creates or executes a task. It is a ``SELECT`` composed
into derived dataclasses that already exist. No new inference kinds, no change to graph
or inference semantics.

Run scoping -- why evidence, not ownership
------------------------------------------
A canonical entity is **not** owned by a run: ``assets`` are unique per
``(program_id, hostname)``, ``ips`` are unique per ``address`` globally, and
``ports``/``web_apps`` are reachable from several runs. Timestamps, "latest row"
heuristics and program membership are all deliberately **not** used to decide run
membership, because none of them is provenance.

The schema already records real provenance, and Phase 14 writes it: every canonical fact
gets one ``evidence`` row tagged with ``entity_type``/``entity_id`` and joined to the
``tool_run`` that observed it, which belongs to a ``task``, which belongs to a ``run``.
So the authoritative chain is::

    evidence.tool_run_id -> tool_runs.task_id -> tasks.run_id -> runs.id

An entity is projected into a run's graph **iff** that run holds an ``evidence`` row
whose ``entity_type`` matches and whose ``entity_id`` names the entity. Nothing else
qualifies: not ``discovered_at``, not ``first_seen``, not ``observed_at``, not
``created_at``, not program membership. Two runs that observed the same IP therefore both
project it, and a run that never observed it never does.

Association rows (``asset_ips``, ``asset_technologies``) cannot be attributed to a run
from the existing schema: their Phase 14 evidence rows carry a NULL ``entity_id``
(``asset_ips`` has a composite primary key, so there is no single row id to cite), and
``asset_technologies`` stores its ``evidence_id`` inline rather than in ``evidence``. So
the projection does **not** claim to know which run created an edge. It uses endpoint
containment instead: an association is projected only when *both* of its endpoints are
themselves evidenced in the same run. That is strictly conservative -- it is impossible
for a projected edge to reference a fact the run did not observe, and therefore impossible
for one run's graph to contain an edge only another run can justify. No schema migration
is required, and none is performed.

Entities whose required graph parents are not themselves evidenced are **not** projected,
because the committed correlation records cannot represent them without inventing a
value. ``PortRecord`` needs its IP and ``WebAppRecord`` needs its port and IP; if those
parents are not run-evidenced the fact is withheld rather than rendered with a fabricated
linkage. Records with no derivable link that *can* be represented honestly are still
emitted, landing as orphans -- which is ``03_RECON_PIPELINE.md`` 25's documented failure
condition ("stored without an edge rather than dropped"). Phase 22 applies the same rule
to crawl facts: ``UrlRecord`` needs its web app projected, ``EndpointRecord`` needs its
URL, ``ParameterRecord`` needs its endpoint, and ``JavaScriptRecord`` needs its web app;
if the parent is not run-evidenced the fact is withheld, not stitched to a stand-in.

What is deliberately absent
--------------------------
Only record types with real persisted producers are projected. Phase 22 (deterministic
web crawling) added a producer for ``urls``, ``endpoints``, ``parameters`` and
``javascript_files``, so records for those are created from their crawled facts. Still
unproduced -- and therefore never created, because inventing them would fabricate attack
surface that was never observed -- are ``apis``, ``graphql_operations``,
``websocket_endpoints`` and ``auth_mechanisms``, and the schema has no ``certificates``
table at all, so no ``ApiRecord``, ``AuthRecord`` or ``CertificateRecord`` is ever
created here. Those five kinds remain listed in ``UNPRODUCED_RECORD_KINDS`` so the API
payload keeps telling "no producers yet" from "nothing was found".

``dns_records`` has a real producer and run evidence, but the committed correlation model
has **no** record type for it, and adding one is out of scope. An address-valued DNS
record is not lost: it is the same fact as the ``asset_ips`` binding, which the graph
already represents as the ``resolves_to`` edge. Non-address records (CNAME/MX/NS/TXT)
have no graph representation at all and are therefore not projected -- an honest gap, not
a silent one.

Determinism
-----------
``evidence`` carries no timestamp, so ordering is fixed on stable identifiers: evidence
rows are ordered by their primary key and the first row per ``(entity_type, entity_id)``
supplies the record's ``evidence_id``; entity rows are ordered by their natural key
before transformation; the final record list is sorted by ``(type, key, evidence_id)``.
Projecting the same persisted run twice yields the same records, the same graph, and the
same inferences. No caching, no background work, no graph persistence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence
from uuid import UUID

from correlation.asset_graph import build as build_graph
from correlation.endpoint_graph import ENDPOINT_KINDS, endpoint_subgraph
from correlation.records import (
    DomainRecord,
    EndpointRecord,
    Graph,
    IpRecord,
    JavaScriptRecord,
    Node,
    ParameterRecord,
    PortRecord,
    TechnologyRecord,
    UrlRecord,
    WebAppRecord,
    endpoint_key,
)
from correlation.relationship_engine import Inference
from correlation.relationship_engine import run as run_relationship_engine
from recon.ingest import (
    ENTITY_ASSET,
    ENTITY_DNS_RECORD,
    ENTITY_ENDPOINT,
    ENTITY_IP,
    ENTITY_JAVASCRIPT,
    ENTITY_PARAMETER,
    ENTITY_PORT,
    ENTITY_TECHNOLOGY,
    ENTITY_URL,
    ENTITY_WEB_APP,
)

#: Entity types that denote a canonical graph node. This is the Phase 14 producer set,
#: pinned by test so a new tag cannot silently stop projecting. Everything else Phase 14
#: writes (``asset_ip``/``asset_technology`` edges, ``observed_host``/``observed_ip``/
#: ``observed_web_app`` out-of-scope observations, ``artifact_cap``) has no canonical
#: entity and can never become a graph node. Phase 22's crawl tags (``url``/``endpoint``/
#: ``parameter``/``javascript``) also name canonical entities with a non-NULL ``entity_id``
#: when rooted; they are intentionally absent here -- their records are built in the
#: dedicated crawl sections below, not as Phase 14 producers, and this tuple drives the
#: report's asset-counts section only.
CANONICAL_ENTITY_TYPES: tuple[str, ...] = (
    ENTITY_ASSET,
    ENTITY_IP,
    ENTITY_PORT,
    ENTITY_WEB_APP,
    ENTITY_DNS_RECORD,
    ENTITY_TECHNOLOGY,
)

#: Records whose absence is a known, deliberate gap rather than a bug. Surfaced in the
#: API payload so an operator can tell "no producers yet" from "nothing was found".
#: Phase 22 (deterministic web crawling) added real crawled producers for
#: urls/endpoints/parameters/javascript_files, so only the still-unproduced kinds stay.
UNPRODUCED_RECORD_KINDS: tuple[str, ...] = (
    "api",
    "auth",
    "certificate",
)

#: Sentinel for a web application whose ``status_code`` column is NULL. ``WebAppRecord``
#: types the field as ``int``, and 0 is not a valid HTTP status, so it cannot be mistaken
#: for an observation. Nothing branches on it: ``correlation.asset_graph`` keys and edges
#: on ``ip``/``port`` only.
_UNKNOWN_STATUS_CODE = 0


@dataclass(frozen=True)
class RunFacts:
    """The raw, run-scoped rows the projection transforms.

    Kept as plain ``dict`` rows rather than new entities: the repositories already speak
    rows, and inventing entity dataclasses for a read path would duplicate types that
    ``database/models/entities.py`` either already has or deliberately does not need.
    """

    #: ``entity_type`` -> ``{entity_id: evidence_id}``. Only evidence rows with a
    #: non-NULL ``entity_id`` appear here, because only those name a canonical entity.
    #: First evidence row per entity wins (rows arrive ordered by evidence primary key),
    #: which is what makes the choice of ``evidence_id`` deterministic.
    fact_evidence: Mapping[str, Mapping[UUID, str]] = field(default_factory=dict)
    #: Count of run-scoped evidence rows per ``entity_type``, including the
    #: observation-only tags (out-of-scope hosts/IPs/web apps, the artifact cap). Those
    #: rows carry no canonical entity and so project no node, but counting them keeps the
    #: reported picture complete instead of quietly dropping denied observations.
    evidence_counts: Mapping[str, int] = field(default_factory=dict)
    assets: tuple[Mapping[str, Any], ...] = ()
    ips: tuple[Mapping[str, Any], ...] = ()
    ports: tuple[Mapping[str, Any], ...] = ()
    web_apps: tuple[Mapping[str, Any], ...] = ()
    technologies: tuple[Mapping[str, Any], ...] = ()
    #: Phase 22 crawl facts, batch-read by the ids this run's evidence names. Bounds are
    #: deliberately loose -- plain dict rows like every other fact surface, because
    #: ``urls``/``endpoints``/``parameters``/``javascript_files`` are new tables that the
    #: committed entity models do not (and need not) define for this read path.
    urls: tuple[Mapping[str, Any], ...] = ()
    endpoints: tuple[Mapping[str, Any], ...] = ()
    parameters: tuple[Mapping[str, Any], ...] = ()
    javascript_files: tuple[Mapping[str, Any], ...] = ()
    #: ``(asset_id, ip_id)`` pairs, restricted to assets/ips evidenced in this run.
    asset_ips: tuple[Mapping[str, Any], ...] = ()
    #: ``(asset_id, technology_id)`` pairs, restricted to the same.
    asset_technologies: tuple[Mapping[str, Any], ...] = ()

    @classmethod
    def from_evidence_rows(
        cls, rows: Sequence[Mapping[str, Any]]
    ) -> tuple["RunFacts", Mapping[str, set[UUID]]]:
        """Split run-scoped evidence rows into provenance and per-type entity ids.

        Rows must arrive ordered by evidence id so the "first row wins" rule that makes
        ``evidence_id`` selection deterministic is stable. Returns the id sets alongside
        so the caller can batch one ``WHERE id = ANY(...)`` read per entity table instead
        of a query per fact.
        """
        fact_evidence: dict[str, dict[UUID, str]] = {}
        counts: dict[str, int] = {}
        entity_ids: dict[str, set[UUID]] = {}
        for row in rows:
            entity_type = str(row["entity_type"])
            counts[entity_type] = counts.get(entity_type, 0) + 1
            entity_id = row.get("entity_id")
            if entity_id is None:
                continue
            seen = fact_evidence.setdefault(entity_type, {})
            if entity_id in seen:
                continue
            seen[entity_id] = str(row["evidence_id"])
            entity_ids.setdefault(entity_type, set()).add(entity_id)
        return (
            cls(
                fact_evidence=fact_evidence,
                evidence_counts={k: counts[k] for k in sorted(counts)},
            ),
            entity_ids,
        )


@dataclass(frozen=True)
class AttackSurface:
    """A run's derived attack surface: records, graph, and deterministic inferences."""

    run_id: Optional[UUID]
    records: tuple[Any, ...] = ()
    graph: Graph = field(default_factory=Graph)
    inferences: tuple[Inference, ...] = ()
    endpoint_graph: Graph = field(default_factory=Graph)
    evidence_counts: Mapping[str, int] = field(default_factory=dict)
    #: False when the storage backend has no canonical fact store to project from (e.g.
    #: the in-memory development double). Distinct from "available but empty", which is
    #: a real run that observed nothing.
    available: bool = True

    def record_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in self.records:
            kind = type(record).__name__.removesuffix("Record").lower()
            counts[kind] = counts.get(kind, 0) + 1
        return {k: counts[k] for k in sorted(counts)}


def build_records(facts: RunFacts) -> tuple[Any, ...]:
    """Transform run-scoped rows into committed ``correlation.records`` types.

    Pure: no I/O, no database, no clock, no randomness. ``facts`` is the only input, so
    this is unit-testable with hand-built rows and returns an identical tuple for an
    identical input.

    The walk is bottom-up so that every emitted record's graph parents are themselves
    emitted. Each step therefore has three outcomes: projected, withheld because no run
    evidence names it, or withheld because a required parent is absent. Nothing is
    fabricated to fill a gap.
    """
    evidenced = facts.fact_evidence

    def ref(entity_type: str, entity_id: Any) -> Optional[str]:
        """The run's evidence id for an entity, or ``None`` if this run never saw it."""
        if entity_id is None:
            return None
        return (evidenced.get(entity_type) or {}).get(entity_id)

    records: list[Any] = []

    # -- domains: the root of every other record ---------------------------
    assets: dict[UUID, Mapping[str, Any]] = {}
    for row in sorted(facts.assets, key=lambda r: (str(r.get("hostname", "")), str(r.get("id")))):
        evidence_id = ref(ENTITY_ASSET, row.get("id"))
        if evidence_id is None:
            continue
        assets[row["id"]] = row
        records.append(DomainRecord(hostname=str(row.get("hostname", "")), evidence_id=evidence_id))

    # -- IPs: a host -> IP binding needs the hostname it resolves for --------
    #
    # One ``IpRecord`` per evidenced IP. Several hosts may share an IP, but
    # ``IpRecord.key`` is the address, so the graph holds exactly one IP node and
    # therefore exactly one ``resolves_to`` edge per address. The surviving hostname is
    # chosen deterministically (lowest sorted hostname) rather than by row order, and the
    # limitation is inherent to the committed record model, not introduced here.
    ips: dict[UUID, Mapping[str, Any]] = {}
    for row in sorted(facts.ips, key=lambda r: (str(r.get("address", "")), str(r.get("id")))):
        evidence_id = ref(ENTITY_IP, row.get("id"))
        if evidence_id is None:
            continue
        ips[row["id"]] = row
    if ips:
        owner: dict[UUID, str] = {}
        for link in sorted(
            facts.asset_ips,
            key=lambda r: (str(r.get("asset_id")), str(r.get("ip_id"))),
        ):
            ip_id = link.get("ip_id")
            asset = assets.get(link.get("asset_id"))
            if ip_id is None or asset is None or ip_id not in ips:
                continue
            hostname = str(asset.get("hostname", ""))
            current = owner.get(ip_id)
            if current is None or hostname < current:
                owner[ip_id] = hostname
        for ip_id in sorted(ips, key=str):
            row = ips[ip_id]
            records.append(
                IpRecord(
                    address=str(row.get("address", "")),
                    # An evidenced IP with no evidenced owner is still a real observation.
                    # It is emitted with an empty hostname so it lands as a stored orphan
                    # node rather than being dropped; a hostname is never invented.
                    hostname=owner.get(ip_id, ""),
                    evidence_id=(evidenced.get(ENTITY_IP) or {})[ip_id],
                )
            )

    # -- ports: require the IP to be projected, else the node cannot link ----
    ports: dict[UUID, Mapping[str, Any]] = {}
    for row in sorted(
        facts.ports,
        key=lambda r: (str(r.get("port_number", 0)), str(r.get("ip_id")), str(r.get("id"))),
    ):
        evidence_id = ref(ENTITY_PORT, row.get("id"))
        ip_row = ips.get(row.get("ip_id"))
        if evidence_id is None or ip_row is None:
            continue
        ports[row["id"]] = row
        records.append(
            PortRecord(
                ip=str(ip_row.get("address", "")),
                number=int(row.get("port_number") or 0),
                # ``ports.service`` is nullable and Phase 14 never populates it (no
                # service-fingerprinting adapter exists). An empty string is the honest
                # "not observed"; it is never guessed from the port number.
                service=str(row.get("service") or ""),
                evidence_id=evidence_id,
            )
        )

    # -- web apps: require both the port and the asset to be projected -------
    web_app_records: dict[UUID, WebAppRecord] = {}
    for row in sorted(facts.web_apps, key=lambda r: str(r.get("id"))):
        evidence_id = ref(ENTITY_WEB_APP, row.get("id"))
        port_row = ports.get(row.get("port_id"))
        asset = assets.get(row.get("asset_id"))
        if evidence_id is None or port_row is None or asset is None:
            continue
        ip_row = ips.get(port_row.get("ip_id"))
        if ip_row is None:
            continue
        status = row.get("status_code")
        web_app_records[row["id"]] = WebAppRecord(
            host=str(asset.get("hostname", "")),
            port=int(port_row.get("port_number") or 0),
            status_code=int(status) if status is not None else _UNKNOWN_STATUS_CODE,
            title=str(row.get("title") or ""),
            ip=str(ip_row.get("address", "")),
            evidence_id=evidence_id,
        )
        records.append(web_app_records[row["id"]])

    # -- crawl URLs: require the web app below to be projected ----------------
    #
    # A URL is anchored to its ``web_apps`` row (the graph links it to the web app's
    # ``host:port`` node). If that app is not itself run-evidenced the URL is withheld;
    # it is still counted in ``evidence_counts``, so nothing observed is silently lost.
    url_records: dict[UUID, UrlRecord] = {}
    for row in sorted(
        facts.urls,
        key=lambda r: (str(r.get("path", "")), str(r.get("id"))),
    ):
        evidence_id = ref(ENTITY_URL, row.get("id"))
        web_record = web_app_records.get(row.get("web_app_id"))
        if evidence_id is None or web_record is None:
            continue
        url_records[row["id"]] = UrlRecord(
            host=web_record.host,
            port=web_record.port,
            path=str(row.get("path", "")),
            source=str(row.get("source") or ""),
            evidence_id=evidence_id,
            historical=bool(row.get("historical")),
        )
        records.append(url_records[row["id"]])

    # -- crawl endpoints: require the parent URL to be projected ---------------
    #
    # ``EndpointRecord`` carries the hostname only (committed model, unchanged); the
    # port that disambiguates two apps on the same host is deliberately not part of the
    # endpoint key.
    endpoint_keys: dict[UUID, str] = {}
    for row in sorted(
        facts.endpoints,
        key=lambda r: (
            str(r.get("pattern", "")),
            str(r.get("method", "")),
            str(r.get("id")),
        ),
    ):
        evidence_id = ref(ENTITY_ENDPOINT, row.get("id"))
        url_record = url_records.get(row.get("url_id"))
        if evidence_id is None or url_record is None:
            continue
        key = endpoint_key(
            str(row.get("method", "")), str(row.get("pattern", "")), url_record.host
        )
        endpoint_keys[row["id"]] = key
        records.append(
            EndpointRecord(
                method=str(row.get("method", "")),
                pattern=str(row.get("pattern", "")),
                host=url_record.host,
                evidence_id=evidence_id,
            )
        )

    # -- crawl parameters: require the parent endpoint to be projected ---------
    for row in sorted(
        facts.parameters,
        key=lambda r: (str(r.get("name", "")), str(r.get("id"))),
    ):
        evidence_id = ref(ENTITY_PARAMETER, row.get("id"))
        parent_key = endpoint_keys.get(row.get("endpoint_id"))
        if evidence_id is None or parent_key is None:
            continue
        records.append(
            ParameterRecord(
                endpoint_key=parent_key,
                name=str(row.get("name", "")),
                location=str(row.get("location") or ""),
                significance=str(row.get("significance") or ""),
                evidence_id=evidence_id,
            )
        )

    # -- crawl JavaScript files: require the web app below to be projected ------
    for row in sorted(
        facts.javascript_files,
        key=lambda r: (str(r.get("url", "")), str(r.get("id"))),
    ):
        evidence_id = ref(ENTITY_JAVASCRIPT, row.get("id"))
        web_record = web_app_records.get(row.get("web_app_id"))
        if evidence_id is None or web_record is None:
            continue
        records.append(
            JavaScriptRecord(
                js_url=str(row.get("url", "")),
                host=web_record.host,
                evidence_id=evidence_id,
            )
        )

    # -- technologies: linked to a projected asset, one node per host -------
    for row in sorted(facts.technologies, key=lambda r: (str(r.get("name", "")), str(r.get("id")))):
        evidence_id = ref(ENTITY_TECHNOLOGY, row.get("id"))
        if evidence_id is None:
            continue
        for link in sorted(
            facts.asset_technologies,
            key=lambda r: (str(r.get("technology_id")), str(r.get("asset_id"))),
        ):
            if link.get("technology_id") != row["id"]:
                continue
            asset = assets.get(link.get("asset_id"))
            if asset is None:
                continue
            records.append(
                TechnologyRecord(
                    # ``category`` is the stored value. Phase 14 writes the honest
                    # ``"other"`` default because no adapter reports a category, and it
                    # is passed through verbatim rather than reinterpreted.
                    name=str(row.get("name", "")),
                    category=str(row.get("category") or ""),
                    host=str(asset.get("hostname", "")),
                    evidence_id=evidence_id,
                )
            )

    # A stable total order makes the whole projection reproducible regardless of the
    # order rows came back from PostgreSQL.
    return tuple(
        sorted(records, key=lambda r: (type(r).__name__, r.key, r.evidence_id))
    )


def project(run_id: Optional[UUID], facts: RunFacts) -> AttackSurface:
    """Run the already-committed correlation pipeline over projected records.

    ``correlation.asset_graph.build`` and ``correlation.relationship_engine.run`` are
    invoked exactly as committed -- no wrapping, no altered arguments, no new inference
    kinds. With a Phase-14-shaped dataset this yields a connected graph
    (domain/IP/port/web-app/technology with ``parent_of``/``resolves_to``/``hosts``/
    ``serves``/``runs``) and zero inferences, because every inference rule in the engine
    is gated on endpoint-class nodes that Phase 14 cannot produce. Once Phase 22 crawl
    facts exist the endpoint records are projected from real crawled endpoints, and any
    inference rule whose gate they genuinely satisfy fires; an empty inference result is
    still reported honestly rather than padded when no gate is met.
    """
    records = build_records(facts)
    graph = build_graph(records)
    return AttackSurface(
        run_id=run_id,
        records=records,
        graph=graph,
        inferences=tuple(run_relationship_engine(graph)),
        endpoint_graph=endpoint_subgraph(graph),
        evidence_counts=facts.evidence_counts,
        available=True,
    )


def _node_payload(node: Node) -> dict[str, Any]:
    return {
        "key": node.key,
        "kind": node.kind,
        "evidence_id": node.evidence_id,
        "attributes": {k: node.attributes[k] for k in sorted(node.attributes)},
    }


def serialize(surface: AttackSurface) -> dict[str, Any]:
    """Render an ``AttackSurface`` as a JSON-safe, deterministic payload.

    No Python object escapes to the wire: every value is a ``str``/``int``/``bool``/list
    or a mapping of those, and every list is ordered by a stable key so two reads of an
    unchanged run produce byte-identical output. No DSN, credential, or authorization
    material is present -- the only identifiers are entity ids, evidence ids, and
    tool-run-free facts already reachable through the run's own report.
    """
    nodes = sorted(surface.graph.nodes, key=lambda n: (n.kind, n.key))
    edges = sorted(surface.graph.edges, key=lambda e: (e.source, e.kind, e.target))
    orphans = set(surface.graph.orphan_keys)
    inferences = sorted(
        surface.inferences,
        key=lambda i: (i.kind, i.target_host, i.statement),
    )
    return {
        "run_id": str(surface.run_id) if surface.run_id is not None else None,
        "available": bool(surface.available),
        "evidence_counts": {k: int(v) for k, v in sorted(surface.evidence_counts.items())},
        "records": {
            "count": len(surface.records),
            "by_kind": surface.record_counts(),
        },
        "graph": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "orphan_count": len(orphans),
            "nodes": [_node_payload(n) for n in nodes],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "kind": e.kind,
                    "evidence_id": e.evidence_id,
                }
                for e in edges
            ],
            "orphans": sorted(orphans),
        },
        "endpoint_subgraph": {
            "kinds": sorted(ENDPOINT_KINDS),
            "node_count": len(surface.endpoint_graph.nodes),
            "edge_count": len(surface.endpoint_graph.edges),
            "empty": not surface.endpoint_graph.nodes,
        },
        "inferences": {
            "count": len(inferences),
            "items": [
                {
                    "kind": i.kind,
                    "statement": i.statement,
                    "target_host": i.target_host,
                    "evidence_ids": list(i.evidence_ids),
                    # Always the correlation layer's own label. An inference is never a
                    # finding, and this field is passed through unchanged so no consumer
                    # can mistake one for the other.
                    "truth_label": i.truth_label,
                }
                for i in inferences
            ],
        },
        "unproduced_record_kinds": list(UNPRODUCED_RECORD_KINDS),
    }


def unavailable(run_id: Optional[UUID] = None) -> dict[str, Any]:
    """An honest empty surface for a storage backend with no canonical fact store.

    Kept structurally identical to :func:`serialize` so a consumer never has to branch on
    a missing key. ``available: false`` distinguishes "this backend cannot project
    anything" (the in-memory development double) from ``available: true`` with zero
    counts, which means a real run that genuinely observed nothing.
    """
    return serialize(AttackSurface(run_id=run_id, available=False))
