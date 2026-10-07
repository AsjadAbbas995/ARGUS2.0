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
* The output is bounded (``max_tasks``) and sorted by ``(type, target)`` so the
  same artifacts always propose the same children in the same order.
* No exploit, credential, brute-force, or scope-expanding behavior is expressed
  here; the mapping is fixed and documented.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional, Sequence

from core.scope_guard import ScopeGuard, extract_host
from core.task_planner import task_fingerprint
from database.models.entities import Task
from recon.dns.resolver import IpObservation
from recon.normalize import normalize_hostname
from recon.ports.nmap import PortObservation

#: Task types this module may propose, keyed by the trigger artifact. The actual
#: emission is still filtered by the caller's ``available_types`` allowlist.
CHILD_TYPE_DNS = "dns_resolve"
CHILD_TYPE_PORT_SCAN = "port_scan"
CHILD_TYPE_HTTP_PROBE = "http_probe"

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
    proposals: list[tuple[str, str, Optional[float]]] = []

    def propose(child_type: str, target: str, priority: Optional[float] = None) -> None:
        if child_type not in allowed:
            return
        key = (child_type, target)
        if key in seen:
            return
        seen.add(key)
        proposals.append((child_type, target, priority))

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

    ordered = sorted(proposals, key=lambda item: (item[0], item[1]))
    limit = max(0, int(max_tasks))
    ordered = ordered[:limit]

    children: list[Task] = []
    for child_type, target, priority in ordered:
        fingerprint = task_fingerprint(child_type, target, config, parent)
        children.append(
            Task(
                run_id=parent.run_id,
                type=child_type,
                target=target,
                parent_task_id=parent.id,
                priority=priority,
                fingerprint=fingerprint,
            )
        )
    return children