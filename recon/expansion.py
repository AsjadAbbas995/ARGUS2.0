"""Deterministic discovery-to-task expansion (Phase 20A).

When a discovery task completes, the artifacts it produced often *imply* the next
piece of reconnaissance: a subdomain wants DNS resolution, a resolved IP wants a
port scan, an open web port wants an HTTP probe. This module turns those implied
follow-ups into child :class:`~database.models.entities.Task` objects.

It is a **pure function**: no I/O, no scope side effects, no tool execution. The
served wiring calls it from inside the ingestion callback (``api/serve.py``) and
persists whatever it returns into the *same* run. The orchestrator then picks the
children up on its next scheduling pass because their ``parent_task_id`` points at
the just-completed task.

Safety rules, all enforced here *before* a task can be proposed:

* Every proposed target is independently re-checked against the run's
  ``ScopeGuard`` -- a discovered hostname via ``check_host`` and a discovered IP
  via ``check_ip`` (``04_SCOPE_SAFETY.md`` §Discovered Targets). A destination
  that fails is simply never proposed.
* Only task types already registered by the composition are proposed
  (``available_types`` allowlist), so expansion can never invent a task the
  server would refuse.
* A discovered web application warrants three children: a ``tech_detect`` for
  technology fingerprinting, a deterministic crawl when crawling is enabled
  (``web.crawling`` in the run's configuration, default true) and
  ``web_crawl``/``katana`` is registered, and, when the run *approved* a content
  discovery wordlist (``web.content_discovery.wordlist``), a bounded
  ``content_discover``/``ffuf`` against the same app. The crawl and the
  content-discovery child share the app's own recorded URL as their seed.
* The output is bounded (``max_tasks``) and sorted by ``(type, target)`` so the
  same artifacts always propose the same children in the same order.
* No exploit, credential, brute-force, or scope-expanding behavior is expressed
  here; the mapping is fixed and documented.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Optional, Sequence

from core.scope_guard import ScopeGuard, extract_host
from core.task_planner import task_fingerprint
from database.models.entities import Task
from recon.dns.resolver import IpObservation
from recon.normalize import normalize_hostname
from recon.ports.nmap import PortObservation
from recon.web.httpx_probe import WebAppObservation
from recon.web.katana import JavascriptFileObservation

#: Task types this module may propose, keyed by the trigger artifact. The actual
#: emission is still filtered by the caller's ``available_types`` allowlist.
CHILD_TYPE_DNS = "dns_resolve"
CHILD_TYPE_PORT_SCAN = "port_scan"
CHILD_TYPE_HTTP_PROBE = "http_probe"
CHILD_TYPE_TECH_DETECT = "tech_detect"
CHILD_TYPE_WEB_CRAWL = "web_crawl"
CHILD_TYPE_CONTENT_DISCOVER = "content_discover"
CHILD_TYPE_JS_ANALYSIS = "js_analysis"

#: Ports worth an HTTP probe. Deliberately conservative: a full "anything that
#: might speak HTTP" list would fan out; these are the conventional clear-text and
#: TLS web ports. An operator can widen this later without touching the pipeline.
WEB_PORTS: frozenset[int] = frozenset({80, 443, 8000, 8008, 8080, 8081, 8443, 8888})

#: Task types that count as subdomain *discovery*. An ``IpObservation`` only
#: warrants a ``port_scan`` child when it was produced inside a discovery chain
#: feeding from one of these (i.e. the completing ``dns_resolve`` task is itself a
#: child of a discovery task). A user-requested root ``dns_resolve`` keeps its
#: narrow contract: the run executes exactly the tasks that were enqueued, and
#: never gains scan work from an operator's explicit one-off lookup.
DISCOVERY_TASK_TYPES: frozenset[str] = frozenset({"subdomain_enum", "subfinder"})

DEFAULT_MAX_TASKS = 256


def _tech_detect_reuse_reason(artifact: WebAppObservation) -> Optional[str]:
    """Package already-captured ``WebAppObservation`` signals for fingerprint reuse.

    The payload mirrors the fields ``WebAppRepository.upsert`` persists in the
    ``web_apps`` table: ``server_header`` / ``title`` / ``content_type``. Only
    non-empty signals are admitted; when the probe captured nothing usable, no
    payload is attached and the ``tech_detect`` task performs its own bounded
    fetch instead (``06_TOOL_CONTRACTS.md`` §tech_detect "reuse").
    """
    payload: dict[str, str] = {}
    if (artifact.webserver or "").strip():
        payload["server_header"] = artifact.webserver.strip()
    if (artifact.title or "").strip():
        payload["title"] = artifact.title.strip()
    if (artifact.content_type or "").strip():
        payload["content_type"] = artifact.content_type.strip()
    if not payload:
        return None
    return json.dumps(payload, sort_keys=True)


#: Web-application ports whose probe target doubles as a crawl seed; HTTPS is implied
#: for the conventional TLS ports. Mirrors the ``Catalog`` decision in §8.
_CRAWL_HTTPS_PORTS: frozenset[int] = frozenset({443, 8443})


def _crawl_seed(artifact: WebAppObservation) -> str:
    """A crawl seed for the probed application: its recorded URL, else ``scheme://host:port/``.

    ``artifact.url`` is the canonical seed Katana is told to crawl. Guard the fallback
    (an adapter that never recorded a ``url``): the scheme is chosen deterministically --
    https for the conventional TLS ports, http otherwise -- so the same probe always
    yields the same seed.
    """
    url = (getattr(artifact, "url", "") or "").strip()
    if url:
        return url
    scheme = "https" if artifact.port in _CRAWL_HTTPS_PORTS else "http"
    return f"{scheme}://{artifact.host}:{artifact.port}/"


def _crawl_reuse_reason(seed: str) -> str:
    """The seed doubles as the fingerprint-reuse payload (``{"url": seed}``)."""
    return json.dumps({"url": seed}, sort_keys=True)


def _approved_content_discovery(config: Optional[dict]) -> bool:
    """Whether the run actually approved a content-discovery wordlist.

    Approval means the operator set ``web.content_discovery.wordlist``, which the
    snapshot persists as the mapping form ``{"enabled": ..., "wordlist": ...}``
    (``core/config.py::WebConfig._content_discovery_section``). A plain boolean
    ``content_discovery`` gate is *enabled but unapproved*: the FFUF adapter is
    fail-closed without a wordlist, so proposing a fuzz task for it would only
    schedule a run that must refuse. Only the approved mapping form triggers the
    ``content_discover`` child.
    """
    if not isinstance(config, dict):
        return False
    web = config.get("web")
    if not isinstance(web, dict):
        return False
    cd = web.get("content_discovery")
    if not isinstance(cd, dict):
        return False
    if not cd.get("enabled", True):
        return False
    wordlist = cd.get("wordlist")
    return isinstance(wordlist, str) and bool(wordlist.strip())


def plan_discovery_expansion(
    artifacts: Sequence[Any],
    *,
    parent: Task,
    scope: Optional[ScopeGuard],
    available_types: Iterable[str],
    config: Optional[dict] = None,
    max_tasks: int = DEFAULT_MAX_TASKS,
    ancestor_type: Optional[str] = None,
) -> list[Task]:
    """Map one completed task's artifacts to scope-checked child tasks.

    ``parent`` is the task that produced ``artifacts``; its ``run_id`` and ``id``
    become the children's ``run_id`` and ``parent_task_id``. ``scope`` is the
    run's guard -- when it is absent (an unscoped run) nothing is proposed, because
    no discovered destination can be verified. ``config`` is the run's
    configuration snapshot, used only to derive the children's dedup fingerprints
    the same way the orchestrator's planner does. ``ancestor_type`` is the type of
    ``parent``'s own parent task; the ``port_scan`` proposal is gated on it so only
    discovery-chain continuations deepen into scanning (see ``DISCOVERY_TASK_TYPES``).
    """
    if scope is None:
        return []

    allowed = frozenset(available_types)
    parent_host = normalize_hostname(extract_host(getattr(parent, "target", "")))

    seen: set[tuple[str, str]] = set()
    proposals: list[tuple[str, str, Optional[float], Optional[str]]] = []

    def propose(
        child_type: str,
        target: str,
        priority: Optional[float] = None,
        reason: Optional[str] = None,
    ) -> None:
        if child_type not in allowed:
            return
        key = (child_type, target)
        if key in seen:
            return
        seen.add(key)
        proposals.append((child_type, target, priority, reason))

    for artifact in artifacts:
        if isinstance(artifact, str):
            # A subdomain discovered by passive enumeration: resolve it next.
            host = normalize_hostname(artifact)
            if host and scope.check_host(host).in_scope:
                propose(CHILD_TYPE_DNS, host)
        elif isinstance(artifact, IpObservation):
            # A resolved IP. Scanning the parent hostname (rather than the bare
            # address) keeps the port's asset attribution and lets a follow-up HTTP
            # probe use the hostname. Both surfaces must be in scope: the host
            # (re-validated at execution) and the specific address discovered.
            address = (artifact.address or "").strip()
            if not parent_host or not address:
                continue
            # Only a discovery-chain continuation may deepen into port scanning; a
            # user-requested root ``dns_resolve`` (ancestor type ``None``) must not
            # silently add scan work to an explicit task list.
            if ancestor_type not in DISCOVERY_TASK_TYPES:
                continue
            if scope.check_host(parent_host).in_scope and scope.check_ip(address).in_scope:
                propose(CHILD_TYPE_PORT_SCAN, parent_host)
        elif isinstance(artifact, PortObservation):
            # An open, conventional web port: probe it over HTTP(S).
            if (artifact.state or "").lower() != "open":
                continue
            if artifact.port not in WEB_PORTS:
                continue
            host = normalize_hostname(artifact.host) or parent_host
            if host and scope.check_host(host).in_scope:
                propose(CHILD_TYPE_HTTP_PROBE, f"{host}:{artifact.port}")
        elif isinstance(artifact, WebAppObservation):
            # A probed web app: fingerprint its technology/WAF/CDN stack. In the
            # served chain this artifact is produced by the completing ``http_probe``
            # task and its child hangs off that task, but scope gates everything
            # regardless of which task type handed it over. The child does its own
            # bounded work and is permitted to **reuse** already-captured non-empty
            # signals instead of issuing another request.
            host = normalize_hostname(artifact.host)
            if not host or not scope.check_host(host).in_scope:
                continue
            if artifact.port not in WEB_PORTS:
                continue
            propose(
                CHILD_TYPE_TECH_DETECT,
                f"{host}:{artifact.port}",
                reason=_tech_detect_reuse_reason(artifact),
            )
            # Phase 22: crawl the probed app. The canonical child type is ``web_crawl``;
            # when the composition only registered the ``katana`` spelling, one
            # katana-typed task is proposed instead (same dedup key, never both).
            # ``reason`` doubles as the seed-reuse payload the adapter reads back.
            preferred = allowed & {"web_crawl", "katana"}
            if preferred and (config or {}).get("web", {}).get("crawling", True):
                seed = _crawl_seed(artifact)
                key = (CHILD_TYPE_WEB_CRAWL, seed)
                if key not in seen:
                    seen.add(key)
                    if CHILD_TYPE_WEB_CRAWL in allowed:
                        proposals.append(
                            (CHILD_TYPE_WEB_CRAWL, seed, None, _crawl_reuse_reason(seed))
                        )
                    elif "katana" in allowed:
                        proposals.append(("katana", seed, None, _crawl_reuse_reason(seed)))
            # Phase 23: discover content on the probed app. The canonical child type
            # is ``content_discover``; when the composition only registered the
            # ``ffuf`` spelling, a ffuf-typed task is proposed instead (same dedup
            # key, never both). The seed is the app's own recorded URL, exactly like
            # the crawl, and ``reason`` carries it back to the adapter; the child is
            # proposed only when the run approved a wordlist, because the adapter is
            # fail-closed without one.
            preferred_cd = allowed & {"content_discover", "ffuf"}
            if preferred_cd and _approved_content_discovery(config):
                seed = _crawl_seed(artifact)
                key = (CHILD_TYPE_CONTENT_DISCOVER, seed)
                if key not in seen:
                    seen.add(key)
                    if CHILD_TYPE_CONTENT_DISCOVER in allowed:
                        proposals.append(
                            (CHILD_TYPE_CONTENT_DISCOVER, seed, None, _crawl_reuse_reason(seed))
                        )
                    elif "ffuf" in allowed:
                        proposals.append(("ffuf", seed, None, _crawl_reuse_reason(seed)))
        elif isinstance(artifact, JavascriptFileObservation):
            # Phase 25: an already-crawled JavaScript file. The crawl persists only
            # the JS URL (never its body), so the ``js_analysis`` adapter fetches it
            # under the same scope/SSRF policy and extracts endpoints/parameters.
            # The child is gated purely by ``available_types``: the adapter is
            # registered only when ``config.javascript.enabled`` is set, so a
            # disabled gate leaves this type absent and ``propose`` a no-op -- the
            # expansion branch reads no config and needs no snapshot gate.
            url = (getattr(artifact, "url", "") or "").strip()
            host = normalize_hostname(getattr(artifact, "host", "")) or normalize_hostname(
                extract_host(url)
            )
            if not url or not host or not scope.check_host(host).in_scope:
                continue
            propose(CHILD_TYPE_JS_ANALYSIS, url)

    ordered = sorted(proposals, key=lambda item: (item[0], item[1]))
    limit = max(0, int(max_tasks))
    ordered = ordered[:limit]

    children: list[Task] = []
    for child_type, target, priority, reason in ordered:
        fingerprint = task_fingerprint(child_type, target, config, parent)
        children.append(
            Task(
                run_id=parent.run_id,
                type=child_type,
                target=target,
                parent_task_id=parent.id,
                priority=priority,
                reason=reason,
                fingerprint=fingerprint,
            )
        )
    return children