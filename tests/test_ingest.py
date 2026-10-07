"""Phase 14.1 ingestion mapping tests (``13_TESTING_STRATEGY.md`` UNIT tier).

Covers artifact -> canonical record mapping, hostname normalization, scope
classification (host **and** IP, per ``04_SCOPE_SAFETY.md``), deduplication,
malformed-input tolerance, and the artifact cardinality cap. No database, no
network -- ``plan_ingestion`` is a pure function.
"""

from __future__ import annotations

from core.config import ScopeConfig
from core.scope_guard import ScopeGuard
from recon.dns.resolver import DnsRecordObservation, IpObservation
from recon.ingest import (
    DEFAULT_TECHNOLOGY_CATEGORY,
    KIND_HOST,
    KIND_IP,
    OBSERVED_TECHNOLOGY_CONFIDENCE,
    plan_ingestion,
)
from recon.ports.nmap import PortObservation
from recon.web.httpx_probe import (
    AssetTechnologyObservation,
    TechnologyObservation,
    WebAppObservation,
)


def make_guard() -> ScopeGuard:
    return ScopeGuard.from_config(
        ScopeConfig(
            allowed_domains=("example.com",),
            allowed_ips=("203.0.113.0/24",),
            excluded=("internal.example.com",),
        )
    )


def plan(artifacts, *, target_host="example.com", max_artifacts=10000, guard=None):
    return plan_ingestion(
        artifacts,
        scope=guard or make_guard(),
        source="test_tool",
        target_host=target_host,
        max_artifacts=max_artifacts,
    )


# -- mapping ----------------------------------------------------------------


def test_subfinder_strings_become_in_scope_assets() -> None:
    result = plan(["www.example.com", "api.example.com"])
    assert {a.hostname for a in result.assets} == {"www.example.com", "api.example.com"}
    assert all(a.source == "test_tool" for a in result.assets)
    assert result.out_of_scope == ()


def test_dns_and_ip_observations_map_to_records_and_links() -> None:
    result = plan(
        [
            DnsRecordObservation("example.com", "A", "203.0.113.17"),
            IpObservation("203.0.113.17", "A"),
        ]
    )
    assert [(r.hostname, r.record_type, r.value) for r in result.dns_records] == [
        ("example.com", "A", "203.0.113.17")
    ]
    assert [(l.hostname, l.address) for l in result.ip_links] == [
        ("example.com", "203.0.113.17")
    ]


def test_ip_observation_is_attributed_to_the_task_target() -> None:
    # IpObservation carries no hostname of its own.
    result = plan([IpObservation("203.0.113.17", "A")], target_host="sub.example.com")
    assert [l.hostname for l in result.ip_links] == ["sub.example.com"]


def test_httpx_web_app_and_technology_map() -> None:
    result = plan(
        [
            WebAppObservation(
                host="example.com",
                url="https://example.com/",
                scheme="https",
                port=443,
                status_code=200,
                title="Home",
                webserver="nginx",
            ),
            AssetTechnologyObservation(host="example.com", technology="Nginx"),
        ]
    )
    assert len(result.web_apps) == 1
    web = result.web_apps[0]
    assert (web.hostname, web.port, web.status_code, web.title, web.server_header) == (
        "example.com",
        443,
        200,
        "Home",
        "nginx",
    )
    assert [(t.hostname, t.name) for t in result.technologies] == [
        ("example.com", "Nginx")
    ]


def test_technology_defaults_category_and_confidence() -> None:
    result = plan([AssetTechnologyObservation(host="example.com", technology="React")])
    tech = result.technologies[0]
    assert tech.category == DEFAULT_TECHNOLOGY_CATEGORY
    assert tech.confidence == OBSERVED_TECHNOLOGY_CONFIDENCE


# -- ports (Phase 20A) --------------------------------------------------------


def test_port_observation_maps_to_a_port_plan() -> None:
    result = plan(
        [
            PortObservation(
                address="203.0.113.12",
                port=443,
                protocol="tcp",
                state="open",
                service="https",
                version="nginx 1.25.1",
            )
        ]
    )
    assert len(result.ports) == 1
    port = result.ports[0]
    assert (port.address, port.port_number, port.protocol, port.state) == (
        "203.0.113.12",
        443,
        "tcp",
        "open",
    )
    assert (port.service, port.version) == ("https", "nginx 1.25.1")
    assert port.host == ""  # no hostname on the observation -> no asset link


def test_port_with_host_links_the_asset_but_never_invents_one() -> None:
    result = plan(
        [
            PortObservation(
                address="203.0.113.12",
                port=80,
                host="www.example.com",
            )
        ]
    )
    assert [a.hostname for a in result.assets] == ["www.example.com"]
    assert result.ports[0].host == "www.example.com"


def test_port_for_out_of_scope_ip_is_observed_not_promoted() -> None:
    result = plan([PortObservation(address="198.51.100.9", port=443)])
    assert result.ports == ()
    assert [(o.kind, o.value) for o in result.out_of_scope] == [
        (KIND_IP, "198.51.100.9")
    ]


def test_port_for_a_denied_host_is_not_promoted() -> None:
    result = plan(
        [
            PortObservation(
                address="203.0.113.12", port=443, host="internal.example.com"
            )
        ]
    )
    # The IP is in scope but the host is excluded: no fact may be keyed to it.
    assert result.ports == ()
    assert [o.value for o in result.out_of_scope] == ["internal.example.com"]


def test_duplicate_port_observations_collapse() -> None:
    result = plan(
        [
            PortObservation(address="203.0.113.12", port=443, protocol="tcp"),
            PortObservation(address="203.0.113.12", port=443, protocol="tcp"),
            PortObservation(address="203.0.113.12", port=443, protocol="udp"),
        ]
    )
    assert [(p.address, p.port_number, p.protocol) for p in result.ports] == [
        ("203.0.113.12", 443, "tcp"),
        ("203.0.113.12", 443, "udp"),
    ]


def test_port_makes_a_plan_non_empty() -> None:
    result = plan([PortObservation(address="203.0.113.12", port=443)])
    assert result.is_empty is False


# -- normalization ----------------------------------------------------------


def test_trailing_dot_and_case_normalize() -> None:
    result = plan(["Example.COM.", "example.com"])
    assert [a.hostname for a in result.assets] == ["example.com"]


def test_subdomain_stays_distinct_from_apex() -> None:
    result = plan(["example.com", "www.example.com"])
    assert {a.hostname for a in result.assets} == {"example.com", "www.example.com"}


# -- scope security ---------------------------------------------------------


def test_out_of_scope_host_is_observed_not_promoted() -> None:
    result = plan(["attacker-controlled.example.net"])
    assert result.assets == ()
    assert len(result.out_of_scope) == 1
    obs = result.out_of_scope[0]
    assert obs.kind == KIND_HOST
    assert obs.value == "attacker-controlled.example.net"
    assert obs.reason


def test_excluded_host_is_not_promoted() -> None:
    result = plan(["internal.example.com"])
    assert result.assets == ()
    assert [o.value for o in result.out_of_scope] == ["internal.example.com"]


def test_out_of_scope_ip_is_not_linked() -> None:
    result = plan(
        [
            DnsRecordObservation("example.com", "A", "198.51.100.9"),
            IpObservation("198.51.100.9", "A"),
        ]
    )
    # The hostname is in scope, so the DNS record is kept...
    assert [r.value for r in result.dns_records] == ["198.51.100.9"]
    # ...but the resolved IP is its own discovery surface and is NOT in scope.
    assert result.ip_links == ()
    assert [(o.kind, o.value) for o in result.out_of_scope] == [
        (KIND_IP, "198.51.100.9")
    ]


def test_web_app_for_out_of_scope_host_is_dropped() -> None:
    result = plan(
        [
            WebAppObservation(
                host="attacker.example.net",
                url="https://attacker.example.net/",
                scheme="https",
                port=443,
                status_code=200,
            )
        ]
    )
    assert result.web_apps == ()
    assert [o.value for o in result.out_of_scope] == ["attacker.example.net"]


# -- tolerance / dedup / cap ------------------------------------------------


def test_malformed_artifacts_are_counted_not_fatal() -> None:
    result = plan([object(), 123, {"unexpected": True}, "www.example.com"])
    assert result.unrecognized == 3
    assert [a.hostname for a in result.assets] == ["www.example.com"]


def test_duplicate_observations_collapse() -> None:
    result = plan(
        [
            "example.com",
            "Example.COM.",
            DnsRecordObservation("example.com", "A", "203.0.113.17"),
            DnsRecordObservation("example.com", "A", "203.0.113.17"),
            IpObservation("203.0.113.17", "A"),
            IpObservation("203.0.113.17", "A"),
            AssetTechnologyObservation(host="example.com", technology="Nginx"),
            AssetTechnologyObservation(host="example.com", technology="Nginx"),
        ]
    )
    assert [a.hostname for a in result.assets] == ["example.com"]
    assert len(result.dns_records) == 1
    assert len(result.ip_links) == 1
    assert len(result.technologies) == 1


def test_cardinality_cap_truncates_and_reports() -> None:
    result = plan(
        ["a.example.com", "b.example.com", "c.example.com"], max_artifacts=2
    )
    assert result.truncated == 1
    assert [a.hostname for a in result.assets] == ["a.example.com", "b.example.com"]


def test_empty_artifacts_yield_empty_plan() -> None:
    result = plan([])
    assert result.is_empty
    assert result.unrecognized == 0
    assert result.truncated == 0
