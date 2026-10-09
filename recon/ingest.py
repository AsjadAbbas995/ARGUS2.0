"""Phase 14 evidence ingestion: ``ToolExecution.artifacts`` -> canonical records.

Pure mapping, scope-classification and evidence-planning layer (Phase 14.1). It
performs **no I/O**: no database writes, no network, no subprocess. Persistence is
Phase 14.2; this module decides *what* should be persisted and *why*.

Design constraints (see ``docs/PHASE_14_PROPOSAL.md`` section 2.1):

* Artifacts are attacker-controlled. Nothing here trusts an ``evidence_id`` and
  nothing here constructs SQL.
* ``recon/normalize.py`` is the only hostname normalizer (no second one).
* Every observed destination passes the run's ``ScopeGuard`` before it can become a
  graph row. Hostnames go through ``check_host``; IPs go through ``check_ip``
  because ``04_SCOPE_SAFETY.md`` requires ``hostname -> DNS -> IP`` to be checked
  and lists "DNS-discovered targets (hostname resolves to a new IP)" as a discovery
  surface. A destination that fails is preserved as an observation only, is never
  promoted, and never triggers a follow-up request.
* A ``web_apps`` row requires a known IP (``web_apps.port_id`` is NOT NULL), but
  ``WebAppObservation`` carries no IP, so a web app is emitted only for a host whose
  IP was itself recorded. This module never resolves a host and never invents one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Sequence

from core.scope_guard import ScopeGuard
from recon.dns.resolver import DnsRecordObservation, IpObservation
from recon.normalize import normalize_hostname
from recon.ports.nmap import PortObservation
from recon.web.httpx_probe import (
    AssetTechnologyObservation,
    TechnologyObservation,
    WebAppObservation,
)
from recon.web.katana import (
    EndpointObservation,
    JavascriptFileObservation,
    ParameterObservation,
    UrlObservation,
)

#: ``technologies.category`` is ``NOT NULL`` with a CHECK over a fixed set, but
#: ``TechnologyObservation`` carries only a name. ``'other'`` is the only honest
#: value; a category is never guessed from the name.
DEFAULT_TECHNOLOGY_CATEGORY = "other"

#: ``asset_technologies.confidence`` is ``NOT NULL`` and the adapter reports none.
#: A technology httpx directly observed is a *fact*, not an inference, so it is
#: recorded at full confidence.
OBSERVED_TECHNOLOGY_CONFIDENCE = 1.0

#: Observation kinds for out-of-scope destinations.
KIND_HOST = "host"
KIND_IP = "ip"

#: Entity-type tags written to the polymorphic ``evidence`` table.
ENTITY_ASSET = "asset"
ENTITY_IP = "ip"
ENTITY_PORT = "port"
ENTITY_WEB_APP = "web_app"
ENTITY_DNS_RECORD = "dns_record"
ENTITY_TECHNOLOGY = "technology"
ENTITY_ASSET_TECHNOLOGY = "asset_technology"
ENTITY_ASSET_IP = "asset_ip"
ENTITY_OBSERVED_HOST = "observed_host"
ENTITY_OBSERVED_IP = "observed_ip"
#: A web observation that could not be rooted, because ``web_apps.port_id`` is
#: NOT NULL and the observation carries no IP. Preserved, never fabricated.
ENTITY_OBSERVED_WEB_APP = "observed_web_app"
ENTITY_ARTIFACT_CAP = "artifact_cap"
#: Crawl facts (Phase 22): canonical ``urls``/``endpoints``/``parameters``/
#: ``javascript_files`` entity tags. A crawl fact whose parent web app is not
#: persisted is preserved with the **same** tag and a NULL ``entity_id``
#: (observation only), so it is counted but never promoted to a graph row.
ENTITY_URL = "url"
ENTITY_ENDPOINT = "endpoint"
ENTITY_PARAMETER = "parameter"
ENTITY_JAVASCRIPT = "javascript"


@dataclass(frozen=True)
class AssetRecord:
    """An in-scope hostname to upsert into ``assets`` (``source`` = tool name)."""

    hostname: str
    source: str


@dataclass(frozen=True)
class DnsRecordPlan:
    """One ``dns_records`` row, attributed to its in-scope asset host."""

    hostname: str
    record_type: str
    value: str


@dataclass(frozen=True)
class IpLinkPlan:
    """An ``ips`` + ``asset_ips`` association (both host and IP passed scope)."""

    hostname: str
    address: str


@dataclass(frozen=True)
class WebAppPlan:
    """A ``web_apps`` row for an in-scope host (persistence roots it to the IP)."""

    hostname: str
    port: int
    status_code: Optional[int]
    title: Optional[str]
    server_header: Optional[str]
    url: str


@dataclass(frozen=True)
class TechnologyLinkPlan:
    """A ``technologies`` + ``asset_technologies`` association for an in-scope host."""

    hostname: str
    name: str
    category: str = DEFAULT_TECHNOLOGY_CATEGORY
    confidence: float = OBSERVED_TECHNOLOGY_CONFIDENCE


@dataclass(frozen=True)
class PortPlan:
    """A standalone ``ports`` row observed by port discovery (Phase 20A).

    Unlike a web app's implicit port, this port was observed directly. ``address``
    is the in-scope IP the port belongs to (its own discovery surface, so it is
    scope-checked independently). ``host`` is the hostname the port was discovered
    through, when the task target was a name rather than a bare address; it is used
    to link the IP to the asset, and is empty otherwise.
    """

    address: str
    port_number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    host: str = ""


@dataclass(frozen=True)
class OutOfScopeObservation:
    """A discovered host/IP the run's scope rejects: evidence only, never a row."""

    kind: str
    value: str
    reason: str


@dataclass(frozen=True)
class UrlPlan:
    """One ``urls`` row for an in-scope host (path, source = plan source tool)."""

    hostname: str
    port: int
    path: str


@dataclass(frozen=True)
class EndpointPlan:
    """One ``endpoints`` row under its url, with the method Katana reported."""

    hostname: str
    port: int
    path: str
    method: str


@dataclass(frozen=True)
class ParameterPlan:
    """One ``parameters`` row under its endpoint (query location, honesty unknown).

    ``method`` names the crawl endpoint the parameter was observed on, keeping
    exact provenance when one path is served under several methods.
    """

    hostname: str
    port: int
    path: str
    name: str
    method: str = "GET"
    location: str = "query"
    significance: str = "unknown"


@dataclass(frozen=True)
class JavascriptFilePlan:
    """One ``javascript_files`` row for its web app (full canonical URL)."""

    hostname: str
    port: int
    url: str


@dataclass(frozen=True)
class IngestionPlan:
    """Everything one execution may persist, already scope-classified.

    ``unrecognized`` counts artifacts of no known shape (malformed/foreign) that
    produced no record, preserving the non-fatal parse contract. ``truncated``
    counts artifacts dropped by the cardinality cap. Both are zero on a clean run.
    """

    assets: tuple[AssetRecord, ...] = ()
    dns_records: tuple[DnsRecordPlan, ...] = ()
    ip_links: tuple[IpLinkPlan, ...] = ()
    web_apps: tuple[WebAppPlan, ...] = ()
    technologies: tuple[TechnologyLinkPlan, ...] = ()
    ports: tuple[PortPlan, ...] = ()
    urls: tuple[UrlPlan, ...] = ()
    endpoints: tuple[EndpointPlan, ...] = ()
    parameters: tuple[ParameterPlan, ...] = ()
    javascript_files: tuple[JavascriptFilePlan, ...] = ()
    out_of_scope: tuple[OutOfScopeObservation, ...] = ()
    unrecognized: int = 0
    truncated: int = 0
    source: str = ""

    @property
    def is_empty(self) -> bool:
        return not (
            self.assets
            or self.dns_records
            or self.ip_links
            or self.web_apps
            or self.technologies
            or self.ports
            or self.urls
            or self.endpoints
            or self.parameters
            or self.javascript_files
            or self.out_of_scope
        )


def _canon(value: Optional[str]) -> Optional[str]:
    return normalize_hostname(value)


def plan_ingestion(
    artifacts: Sequence[Any],
    *,
    scope: ScopeGuard,
    source: str,
    target_host: Optional[str] = None,
    max_artifacts: int = 10000,
) -> IngestionPlan:
    """Classify ``artifacts`` into canonical, scope-checked records.

    ``target_host`` is the canonical host of the task that produced the artifacts.
    It is used to attribute ``IpObservation`` objects, which by design carry no
    hostname of their own -- a resolution is always *for* the task's target.

    Every destination is checked against ``scope``: hostnames via ``check_host`` and
    IPs via ``check_ip``. Only in-scope destinations yield graph records;
    out-of-scope ones are returned as observations. Nothing leaves this function
    with an unchecked destination.
    """
    limit = max(0, int(max_artifacts))
    considered = list(artifacts)
    truncated = max(0, len(considered) - limit)
    considered = considered[:limit]

    canonical_target = _canon(target_host)

    # One decision per (kind, value) so a destination is never checked or emitted
    # twice within a single execution.
    scope_cache: dict[tuple[str, str], bool] = {}
    out_of_scope: dict[tuple[str, str], OutOfScopeObservation] = {}
    assets: dict[str, AssetRecord] = {}
    dns_records: list[DnsRecordPlan] = []
    seen_dns: set[tuple[str, str, str]] = set()
    ip_links: list[IpLinkPlan] = []
    seen_ip: set[tuple[str, str]] = set()
    web_apps: list[WebAppPlan] = []
    seen_web: set[tuple[str, int]] = set()
    technologies: list[TechnologyLinkPlan] = []
    seen_tech: set[tuple[str, str]] = set()
    ports: list[PortPlan] = []
    seen_ports: set[tuple[str, int, str]] = set()
    urls: list[UrlPlan] = []
    seen_url: set[tuple[str, int, str]] = set()
    endpoints: list[EndpointPlan] = []
    seen_endpoint: set[tuple[str, int, str, str]] = set()
    parameters: list[ParameterPlan] = []
    seen_parameter: set[tuple[str, int, str, str, str]] = set()
    javascript_files: list[JavascriptFilePlan] = []
    seen_js: set[tuple[str, int, str]] = set()
    unrecognized = 0

    def check(kind: str, value: str) -> bool:
        key = (kind, value)
        cached = scope_cache.get(key)
        if cached is None:
            decision = (
                scope.check_ip(value) if kind == KIND_IP else scope.check_host(value)
            )
            cached = decision.in_scope
            scope_cache[key] = cached
            if not cached:
                out_of_scope.setdefault(
                    key, OutOfScopeObservation(kind=kind, value=value, reason=decision.reason)
                )
        return cached

    def classify_host(host: Optional[str]) -> Optional[str]:
        """Normalize, then record the asset when in scope; else mark out-of-scope."""
        canon = _canon(host)
        if canon is None:
            return None
        if check(KIND_HOST, canon):
            assets.setdefault(canon, AssetRecord(hostname=canon, source=source))
            return canon
        return None

    for artifact in considered:
        if isinstance(artifact, str):
            # ``subfinder`` yields already-normalized hostnames as plain strings.
            classify_host(artifact)
        elif isinstance(artifact, DnsRecordObservation):
            host = classify_host(artifact.hostname)
            if host is not None:
                key = (host, artifact.record_type, artifact.value)
                if key not in seen_dns:
                    seen_dns.add(key)
                    dns_records.append(
                        DnsRecordPlan(
                            hostname=host,
                            record_type=artifact.record_type,
                            value=artifact.value,
                        )
                    )
        elif isinstance(artifact, IpObservation):
            # IpObservation carries no hostname: attribute it to the task target.
            # ``04_SCOPE_SAFETY.md``: the resolved IP is its own discovery surface.
            host = classify_host(canonical_target)
            if host is not None and artifact.address and check(KIND_IP, artifact.address):
                key = (host, artifact.address)
                if key not in seen_ip:
                    seen_ip.add(key)
                    ip_links.append(IpLinkPlan(hostname=host, address=artifact.address))
        elif isinstance(artifact, WebAppObservation):
            host = classify_host(artifact.host)
            if host is not None:
                key = (host, artifact.port)
                if key not in seen_web:
                    seen_web.add(key)
                    web_apps.append(
                        WebAppPlan(
                            hostname=host,
                            port=artifact.port,
                            status_code=artifact.status_code,
                            title=artifact.title or None,
                            server_header=artifact.webserver or None,
                            url=artifact.url,
                        )
                    )
        elif isinstance(artifact, AssetTechnologyObservation):
            host = classify_host(artifact.host)
            if host is not None:
                key = (host, artifact.technology)
                if key not in seen_tech:
                    seen_tech.add(key)
                    technologies.append(
                        TechnologyLinkPlan(
                            hostname=host, name=artifact.technology, category=artifact.category
                        )
                    )
        elif isinstance(artifact, TechnologyObservation):
            # A bare technology with no host cannot be attributed to an asset
            # without inventing the association; the paired
            # ``AssetTechnologyObservation`` is the host-bearing form.
            host = classify_host(canonical_target)
            if host is not None:
                key = (host, artifact.name)
                if key not in seen_tech:
                    seen_tech.add(key)
                    technologies.append(
                        TechnologyLinkPlan(hostname=host, name=artifact.name, category=artifact.category)
                    )
        elif isinstance(artifact, PortObservation):
            # A port's authoritative discovery surface is its IP
            # (``04_SCOPE_SAFETY.md``): the address is checked independently of any
            # hostname. When the port was reached through a hostname, the host must
            # also pass scope before a fact is keyed to it -- a fact is never
            # attributed to a denied host.
            address = (artifact.address or "").strip()
            if not address or not check(KIND_IP, address):
                continue
            host = classify_host(artifact.host) if artifact.host else None
            if artifact.host and host is None:
                continue
            key = (address, artifact.port, artifact.protocol)
            if key not in seen_ports:
                seen_ports.add(key)
                ports.append(
                    PortPlan(
                        address=address,
                        port_number=artifact.port,
                        protocol=artifact.protocol,
                        state=artifact.state,
                        service=artifact.service,
                        version=artifact.version,
                        host=host or "",
                    )
                )
        elif isinstance(artifact, UrlObservation):
            host = classify_host(artifact.host)
            if host is not None:
                key = (host, artifact.port, artifact.path)
                if key not in seen_url:
                    seen_url.add(key)
                    urls.append(UrlPlan(hostname=host, port=artifact.port, path=artifact.path))
        elif isinstance(artifact, EndpointObservation):
            host = classify_host(artifact.host)
            if host is not None:
                key = (host, artifact.port, artifact.path, artifact.method)
                if key not in seen_endpoint:
                    seen_endpoint.add(key)
                    endpoints.append(
                        EndpointPlan(
                            hostname=host, port=artifact.port, path=artifact.path, method=artifact.method
                        )
                    )
        elif isinstance(artifact, ParameterObservation):
            host = classify_host(artifact.host)
            if host is not None:
                key = (host, artifact.port, artifact.path, artifact.method, artifact.name)
                if key not in seen_parameter:
                    seen_parameter.add(key)
                    parameters.append(
                        ParameterPlan(
                            hostname=host,
                            port=artifact.port,
                            path=artifact.path,
                            name=artifact.name,
                            method=artifact.method,
                            location=artifact.location,
                            significance=artifact.significance,
                        )
                    )
        elif isinstance(artifact, JavascriptFileObservation):
            host = classify_host(artifact.host)
            if host is not None:
                key = (host, artifact.port, artifact.url)
                if key not in seen_js:
                    seen_js.add(key)
                    javascript_files.append(
                        JavascriptFilePlan(hostname=host, port=artifact.port, url=artifact.url)
                    )
        else:
            unrecognized += 1

    return IngestionPlan(
        assets=tuple(assets.values()),
        dns_records=tuple(dns_records),
        ip_links=tuple(ip_links),
        web_apps=tuple(web_apps),
        technologies=tuple(technologies),
        ports=tuple(ports),
        urls=tuple(urls),
        endpoints=tuple(endpoints),
        parameters=tuple(parameters),
        javascript_files=tuple(javascript_files),
        out_of_scope=tuple(out_of_scope.values()),
        unrecognized=unrecognized,
        truncated=truncated,
        source=source,
    )
