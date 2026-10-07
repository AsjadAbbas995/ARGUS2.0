"""Discovery-to-task expansion tests (Phase 20A).

``recon.expansion.plan_discovery_expansion`` is a pure function turning one
completed discovery task's artifacts into scope-checked child tasks. No I/O, no
tools, no database -- the served wiring persists the children afterwards
(``api/serve._enqueue_expansion``), so this module only needs to prove the
*mapping*: what an artifact implies, when it is proposed, and how the result is
bounded, allowlisted, deduplicated and deterministic.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from core.scope_guard import ScopeConfig, ScopeGuard
from database.models.entities import Task
from recon.dns.resolver import IpObservation
from recon.expansion import (
    CHILD_TYPE_DNS,
    CHILD_TYPE_HTTP_PROBE,
    CHILD_TYPE_PORT_SCAN,
    plan_discovery_expansion,
)
from recon.ports.nmap import PortObservation


def _scope() -> ScopeGuard:
    return ScopeGuard.from_config(
        ScopeConfig(
            allowed_domains=("example.com",),
            allowed_ips=("203.0.113.0/24",),
            excluded=("internal.example.com",),
        )
    )


def _parent(*, target: str = "example.com", task_type: str = "subfinder") -> Task:
    return Task(id=uuid4(), run_id=uuid4(), type=task_type, target=target)


def _expand(artifacts, *, parent=None, available_types=None, **kwargs):
    return plan_discovery_expansion(
        artifacts,
        parent=parent or _parent(),
        scope=_scope(),
        available_types=available_types
        or ("dns_resolve", "port_scan", "http_probe"),
        **kwargs,
    )


def _types(tasks) -> set[str]:
    return {t.type for t in tasks}


def _targets(tasks, child_type: str) -> list[str]:
    return sorted(t.target for t in tasks if t.type == child_type)


# -- mapping ------------------------------------------------------------------


def test_subdomain_string_implies_dns_resolution() -> None:
    tasks = _expand(["www.example.com", "api.example.com"])
    assert _types(tasks) == {"dns_resolve"}
    assert _targets(tasks, CHILD_TYPE_DNS) == ["api.example.com", "www.example.com"]


def test_resolved_ip_implies_port_scan_of_the_parent_host() -> None:
    parent = _parent(target="www.example.com", task_type="dns_resolve")
    tasks = _expand(
        [IpObservation(address="203.0.113.10", record_type="A")],
        parent=parent,
        ancestor_type="subfinder",
    )
    assert _types(tasks) == {"port_scan"}
    assert _targets(tasks, CHILD_TYPE_PORT_SCAN) == ["www.example.com"]


def test_root_dns_resolve_never_injects_a_port_scan() -> None:
    # Phase 14 contract: a user-enqueued root ``dns_resolve`` must execute exactly
    # the tasks that were planned. Its resolved IP is evidence, not a mandate to
    # scan -- only a discovery-chain continuation deepens into ``port_scan``.
    parent = _parent(target="www.example.com", task_type="dns_resolve")
    assert (
        _expand(
            [IpObservation(address="203.0.113.10", record_type="A")], parent=parent
        )
        == []
    )


def test_subdomain_enum_ancestor_also_allows_port_scan() -> None:
    # ``subdomain_enum`` is an alias of ``subfinder``; both seed the chain.
    parent = _parent(target="www.example.com", task_type="dns_resolve")
    tasks = _expand(
        [IpObservation(address="203.0.113.10", record_type="A")],
        parent=parent,
        ancestor_type="subdomain_enum",
    )
    assert _targets(tasks, CHILD_TYPE_PORT_SCAN) == ["www.example.com"]


def test_open_web_port_implies_http_probe_of_host_port() -> None:
    parent = _parent(target="www.example.com", task_type="port_scan")
    tasks = _expand(
        [
            PortObservation(
                address="203.0.113.10",
                port=443,
                state="open",
                service="https",
                host="www.example.com",
            )
        ],
        parent=parent,
    )
    assert _types(tasks) == {"http_probe"}
    assert _targets(tasks, CHILD_TYPE_HTTP_PROBE) == ["www.example.com:443"]


def test_http_probe_falls_back_to_parent_host_when_host_is_empty() -> None:
    parent = _parent(target="www.example.com", task_type="port_scan")
    tasks = _expand(
        [PortObservation(address="203.0.113.10", port=80, state="open")],
        parent=parent,
    )
    assert _targets(tasks, CHILD_TYPE_HTTP_PROBE) == ["www.example.com:80"]


# -- safety -------------------------------------------------------------------


def test_out_of_scope_subdomain_is_never_proposed() -> None:
    tasks = _expand(["attacker-controlled.example.net"])
    assert tasks == []


def test_excluded_subdomain_is_never_proposed() -> None:
    tasks = _expand(["internal.example.com"])
    assert tasks == []


def test_resolved_out_of_scope_ip_is_never_proposed() -> None:
    parent = _parent(target="www.example.com", task_type="dns_resolve")
    tasks = _expand(
        [IpObservation(address="198.51.100.5", record_type="A")],
        parent=parent,
        ancestor_type="subfinder",
    )
    assert tasks == []


def test_non_web_or_closed_ports_are_never_proposed() -> None:
    parent = _parent(target="www.example.com", task_type="port_scan")
    tasks = _expand(
        [
            PortObservation(address="203.0.113.10", port=22, state="open"),
            PortObservation(address="203.0.113.10", port=443, state="closed"),
            PortObservation(address="203.0.113.10", port=443, state="filtered"),
        ],
        parent=parent,
    )
    assert tasks == []


def test_nothing_is_proposed_without_a_scope() -> None:
    tasks = plan_discovery_expansion(
        ["www.example.com"],
        parent=_parent(),
        scope=None,
        available_types=("dns_resolve", "port_scan", "http_probe"),
    )
    assert tasks == []


def test_allowlist_blocks_unregistered_types() -> None:
    tasks = _expand(["www.example.com"], available_types=("port_scan",))
    assert tasks == []


# -- structure / determinism --------------------------------------------------


def test_children_carry_provenance_and_fingerprint() -> None:
    parent = _parent(target="example.com")
    tasks = _expand(["www.example.com"], parent=parent)
    assert len(tasks) == 1
    child = tasks[0]
    assert child.run_id == parent.run_id
    assert child.parent_task_id == parent.id
    assert child.fingerprint
    assert child.status == "pending"


def test_same_artifacts_are_deduplicated_and_deterministic() -> None:
    artifacts = ["www.example.com", "www.example.com", "api.example.com"]
    first = _expand(artifacts)
    second = _expand(artifacts)
    assert [t.target for t in first] == [t.target for t in second]
    assert len([t for t in first if t.type == CHILD_TYPE_DNS]) == 2


def test_max_tasks_bounds_the_output() -> None:
    hosts = [f"h{i}.example.com" for i in range(10)]
    tasks = _expand(hosts, max_tasks=3)
    assert len(tasks) == 3
    # Deterministic frontier: the same artifacts always propose the same three.
    again = _expand(hosts, max_tasks=3)
    assert [t.target for t in tasks] == [t.target for t in again]


def test_children_tasks_are_plain_tasks() -> None:
    tasks = _expand(["www.example.com"])
    assert all(isinstance(t, Task) for t in tasks)
    assert all(t.id for t in tasks)