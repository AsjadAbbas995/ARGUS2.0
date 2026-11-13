"""Scope Guard tests (``13_TESTING_STRATEGY.md`` §Scope Tests).

Covers: allowed target, excluded target, out-of-scope redirect, out-of-scope
discovered host, disallowed port, and the authoritative Redirect and
Discovered-Target Policy (``04_SCOPE_SAFETY.md``).
"""

from __future__ import annotations

import ipaddress

import pytest

from core.config import ConfigError, ScopeConfig
from core.scope_guard import (
    ScopeDecision,
    ScopeGuard,
    ScopeRule,
    ScopeRuleType,
    _excluded_rule,
    _ip_in_network,
    extract_host,
    normalize_host,
)


def build_guard() -> ScopeGuard:
    return ScopeGuard.from_config(
        ScopeConfig(
            allowed_domains=("example.com",),
            allowed_ips=(),
            excluded=("internal-staging.example.com",),
        )
    )


ALLOWED = ["example.com", "www.example.com", "app.example.com"]
EXCLUDED = ["internal-staging.example.com", "a.internal-staging.example.com"]
OUT_OF_SCOPE_HOSTS = ["attacker.io", "example.net", "other-domain.example"]


@pytest.mark.parametrize("host", ALLOWED)
def test_allowed_target(host: str) -> None:
    assert build_guard().check_host(host).in_scope is True


@pytest.mark.parametrize("host", EXCLUDED)
def test_excluded_target(host: str) -> None:
    decision = build_guard().check_host(host)
    assert decision.in_scope is False
    assert "excluded" in decision.reason


@pytest.mark.parametrize("host", OUT_OF_SCOPE_HOSTS)
def test_out_of_scope_discovered_host(host: str) -> None:
    assert build_guard().check_host(host).in_scope is False


def test_out_of_scope_redirect_rejected() -> None:
    decision = build_guard().check_redirect(
        "https://example.com/", "https://other-domain.example/"
    )
    assert decision.allowed is False
    assert decision.destination_in_scope is False


def test_in_scope_redirect_allowed() -> None:
    decision = build_guard().check_redirect(
        "https://www.example.com/", "https://app.example.com/"
    )
    assert decision.allowed is True
    assert decision.destination_in_scope is True


def test_redirect_to_excluded_host_rejected() -> None:
    decision = build_guard().check_redirect(
        "https://example.com/", "https://internal-staging.example.com/"
    )
    assert decision.allowed is False
    assert decision.destination_in_scope is False


def test_dns_discovered_ip_out_of_cidr_rejected() -> None:
    guard = ScopeGuard.from_config(
        ScopeConfig(allowed_domains=("example.com",), allowed_ips=("203.0.113.0/24",))
    )
    assert guard.check_ip("203.0.113.17").in_scope is True
    assert guard.check_ip("198.51.100.9").in_scope is False


def test_exact_ip_allowed() -> None:
    guard = ScopeGuard.from_config(
        ScopeConfig(allowed_domains=(), allowed_ips=("198.51.100.7",))
    )
    assert guard.check_ip("198.51.100.7").in_scope is True
    assert guard.check_ip("198.51.100.8").in_scope is False


def test_explicit_ip_exclusion_wins() -> None:
    guard = ScopeGuard(
        [
            ScopeRule(rule_type=ScopeRuleType.CIDR, value="203.0.113.0/24", allowed=True),
            ScopeRule(rule_type=ScopeRuleType.IP, value="203.0.113.10", allowed=False),
        ]
    )
    assert guard.check_ip("203.0.113.11").in_scope is True
    assert guard.check_ip("203.0.113.10").in_scope is False


@pytest.mark.parametrize(
    ("rule_value", "target"),
    [
        ("2001:0DB8:0:0:0:0:0:1", "2001:db8::1"),
        ("2001:db8::1", "2001:0DB8:0:0:0:0:0:1"),
        ("2001:0DB8::1", "2001:db8:0:0:0:0:0:1"),
    ],
)
def test_ipv6_ip_rule_matching_is_canonical(rule_value: str, target: str) -> None:
    guard = ScopeGuard(
        [
            ScopeRule(
                rule_type=ScopeRuleType.CIDR,
                value="2001:db8::/32",
                allowed=True,
            ),
            ScopeRule(
                rule_type=ScopeRuleType.IP,
                value=rule_value,
                allowed=False,
            ),
        ]
    )
    decision = guard.check_ip(target)
    assert decision.in_scope is False
    assert "excluded" in decision.reason


def test_noncanonical_ipv6_allow_rule_matches_canonical_target() -> None:
    guard = ScopeGuard(
        [
            ScopeRule(
                rule_type=ScopeRuleType.IP,
                value="2001:0DB8:0:0:0:0:0:1",
                allowed=True,
            )
        ]
    )
    assert guard.check_ip("2001:db8::1").in_scope is True


@pytest.mark.parametrize(
    ("value", "rule_type"),
    [
        ("203.0.113.10", ScopeRuleType.IP),
        ("203.0.113.0/24", ScopeRuleType.CIDR),
        ("2001:0DB8:0:0:0:0:0:1", ScopeRuleType.IP),
        ("2001:db8:1::/48", ScopeRuleType.CIDR),
    ],
)
def test_ip_like_exclusion_forces_deny_classification(
    value: str, rule_type: str
) -> None:
    rule = ScopeRule(
        rule_type=ScopeRuleType.EXCLUSION,
        value=value,
        allowed=True,
    )
    assert rule.rule_type == rule_type
    assert rule.allowed is False


@pytest.mark.parametrize("allowed", [True, False])
@pytest.mark.parametrize(
    ("allow_cidr", "exclusion_value", "excluded_target", "allowed_target"),
    [
        ("203.0.113.0/24", "203.0.113.10", "203.0.113.10", "203.0.113.11"),
        ("203.0.113.0/24", "203.0.113.128/25", "203.0.113.200", "203.0.113.10"),
        (
            "2001:db8::/32",
            "2001:0DB8:0:0:0:0:0:1",
            "2001:db8::1",
            "2001:db8::2",
        ),
        ("2001:db8::/32", "2001:db8:1::/48", "2001:db8:1::1", "2001:db8:2::1"),
    ],
)
def test_direct_exclusion_ip_or_cidr_is_enforced(
    allow_cidr: str,
    exclusion_value: str,
    excluded_target: str,
    allowed_target: str,
    allowed: bool,
) -> None:
    guard = ScopeGuard(
        [
            ScopeRule(
                rule_type=ScopeRuleType.CIDR,
                value=allow_cidr,
                allowed=True,
            ),
            ScopeRule(
                rule_type=ScopeRuleType.EXCLUSION,
                value=exclusion_value,
                allowed=allowed,
            ),
        ]
    )
    assert guard.check_ip(excluded_target).in_scope is False
    assert guard.check_ip(allowed_target).in_scope is True


@pytest.mark.parametrize("allowed", [True, False])
@pytest.mark.parametrize(
    ("allow_cidr", "exclusion_value", "excluded_target", "allowed_target"),
    [
        ("203.0.113.0/24", "203.0.113.10", "203.0.113.10", "203.0.113.11"),
        ("203.0.113.0/24", "203.0.113.128/25", "203.0.113.200", "203.0.113.10"),
        (
            "2001:db8::/32",
            "2001:0DB8:0:0:0:0:0:1",
            "2001:db8::1",
            "2001:db8::2",
        ),
        ("2001:db8::/32", "2001:db8:1::/48", "2001:db8:1::1", "2001:db8:2::1"),
    ],
)
def test_from_row_exclusion_ip_or_cidr_is_enforced(
    allow_cidr: str,
    exclusion_value: str,
    excluded_target: str,
    allowed_target: str,
    allowed: bool,
) -> None:
    guard = ScopeGuard(
        [
            {
                "rule_type": ScopeRuleType.CIDR,
                "value": allow_cidr,
                "allowed": True,
            },
            {
                "rule_type": ScopeRuleType.EXCLUSION,
                "value": exclusion_value,
                "allowed": allowed,
            },
        ]
    )
    assert guard.check_ip(excluded_target).in_scope is False
    assert guard.check_ip(allowed_target).in_scope is True


def test_direct_hostname_exclusion_remains_effective() -> None:
    guard = ScopeGuard(
        [
            ScopeRule(
                rule_type=ScopeRuleType.DOMAIN,
                value="example.com",
                allowed=True,
            ),
            ScopeRule(
                rule_type=ScopeRuleType.EXCLUSION,
                value="admin.example.com",
                allowed=False,
            ),
        ]
    )
    assert guard.check_host("admin.example.com").in_scope is False
    assert guard.check_host("www.example.com").in_scope is True


@pytest.mark.parametrize("allowed", [True, False])
def test_direct_exclusion_wins_over_direct_ip_allow(allowed: bool) -> None:
    guard = ScopeGuard(
        [
            ScopeRule(
                rule_type=ScopeRuleType.IP,
                value="2001:0DB8:0:0:0:0:0:1",
                allowed=True,
            ),
            ScopeRule(
                rule_type=ScopeRuleType.EXCLUSION,
                value="2001:db8::1",
                allowed=allowed,
            ),
        ]
    )
    assert guard.check_ip("2001:db8::1").in_scope is False


@pytest.mark.parametrize("allowed", [True, False])
@pytest.mark.parametrize(
    "value",
    [
        "203.0.113.1..2",
        "203.0.113.128/33",
        "2001:db8::/129",
        "2001:db8:::1/64",
    ],
)
def test_direct_malformed_ip_like_exclusion_rejected(
    value: str, allowed: bool
) -> None:
    with pytest.raises(ConfigError, match="scope rule"):
        ScopeRule(
            rule_type=ScopeRuleType.EXCLUSION,
            value=value,
            allowed=allowed,
        )


def test_ip_in_network_does_not_suppress_malformed_network() -> None:
    with pytest.raises(ValueError):
        _ip_in_network(
            ipaddress.ip_address("203.0.113.1"),
            "203.0.113.0/33",
        )


@pytest.mark.parametrize("allowed", [True, False])
@pytest.mark.parametrize("value", ["203.0.113.0/33", "2001:db8::/129"])
def test_direct_malformed_cidr_rule_rejected(value: str, allowed: bool) -> None:
    with pytest.raises(ConfigError, match="scope rule"):
        ScopeRule(rule_type=ScopeRuleType.CIDR, value=value, allowed=allowed)


@pytest.mark.parametrize(
    "value",
    ["", "not-an-ip", "203.0.113.256", "2001:db8:::1", "203.0.113.0/24"],
)
def test_direct_malformed_ip_rule_rejected(value: str) -> None:
    with pytest.raises(ConfigError, match="scope rule"):
        ScopeRule(rule_type=ScopeRuleType.IP, value=value, allowed=True)


def test_scope_guard_rejects_malformed_cidr_rule_from_mapping() -> None:
    with pytest.raises(ConfigError, match="scope rule"):
        ScopeGuard(
            [
                {
                    "rule_type": ScopeRuleType.CIDR,
                    "value": "203.0.113.0/33",
                    "allowed": False,
                }
            ]
        )


def test_direct_valid_ip_rules_still_work() -> None:
    guard = ScopeGuard(
        [
            ScopeRule(rule_type=ScopeRuleType.IP, value="203.0.113.10", allowed=True),
            ScopeRule(rule_type=ScopeRuleType.IP, value="2001:db8::1", allowed=True),
        ]
    )
    assert guard.check_ip("203.0.113.10").in_scope is True
    assert guard.check_ip("2001:db8::1").in_scope is True
    assert guard.check_ip("203.0.113.11").in_scope is False
    assert guard.check_ip("2001:db8::2").in_scope is False


def test_direct_valid_ipv4_and_ipv6_cidr_rules_still_work() -> None:
    guard = ScopeGuard(
        [
            ScopeRule(
                rule_type=ScopeRuleType.CIDR, value="203.0.113.0/24", allowed=True
            ),
            ScopeRule(
                rule_type=ScopeRuleType.CIDR, value="2001:db8::/32", allowed=True
            ),
            ScopeRule(
                rule_type=ScopeRuleType.CIDR,
                value="203.0.113.128/25",
                allowed=False,
            ),
            ScopeRule(
                rule_type=ScopeRuleType.CIDR, value="2001:db8:1::/48", allowed=False
            ),
        ]
    )
    assert guard.check_ip("203.0.113.10").in_scope is True
    assert guard.check_ip("203.0.113.200").in_scope is False
    assert guard.check_ip("2001:db8:2::1").in_scope is True
    assert guard.check_ip("2001:db8:1::1").in_scope is False


def test_excluded_cidr_wins_over_allowed_cidr() -> None:
    guard = ScopeGuard.from_config(
        ScopeConfig(
            allowed_ips=("203.0.113.0/24",),
            excluded=("203.0.113.128/25",),
        )
    )
    assert guard.check_ip("203.0.113.10").in_scope is True
    assert guard.check_ip("203.0.113.200").in_scope is False


def test_excluded_ipv6_cidr_wins_over_allowed_cidr() -> None:
    guard = ScopeGuard.from_config(
        ScopeConfig(
            allowed_ips=("2001:db8::/32",),
            excluded=("2001:db8:1::/48",),
        )
    )
    assert guard.check_ip("2001:db8:1::1").in_scope is False
    assert guard.check_ip("2001:db8:2::1").in_scope is True


def test_malformed_exclusion_cannot_be_ignored() -> None:
    with pytest.raises(ConfigError, match="scope.excluded"):
        ScopeGuard.from_config(
            ScopeConfig(
                allowed_ips=("203.0.113.0/24",),
                excluded=("203.0.113.128/33",),
            )
        )


@pytest.mark.parametrize(
    "value",
    [
        "203.0.113.1..2",
        "203.0.113.1.2",
        "203..0.113.1",
        "203.0.113.999..",
        "203.0.113.128/33",
        "2001:db8::/129",
    ],
)
def test_excluded_rule_rejects_malformed_ip_or_cidr_like_values(
    value: str,
) -> None:
    with pytest.raises(ConfigError, match="scope.excluded"):
        _excluded_rule(value)


def test_excluded_rule_preserves_hostname_normalization() -> None:
    rule = _excluded_rule("Admin.Example.Com.")
    assert rule.rule_type == ScopeRuleType.EXCLUSION
    assert rule.value == "admin.example.com"
    assert rule.allowed is False


@pytest.mark.parametrize(
    ("value", "rule_type"),
    [
        ("203.0.113.7", ScopeRuleType.IP),
        ("203.0.113.0/24", ScopeRuleType.CIDR),
        ("2001:db8::1", ScopeRuleType.IP),
        ("2001:db8::/32", ScopeRuleType.CIDR),
    ],
)
def test_excluded_rule_classifies_valid_ip_and_cidr(
    value: str, rule_type: str
) -> None:
    rule = _excluded_rule(value)
    assert rule.rule_type == rule_type
    assert rule.allowed is False


def test_excluded_host_rule_is_normalized() -> None:
    guard = ScopeGuard.from_config(
        ScopeConfig(
            allowed_domains=("example.com",),
            excluded=("Admin.Example.Com.",),
        )
    )
    assert guard.check_host("admin.example.com").in_scope is False


@pytest.mark.parametrize("port", [80, 443, 1000])
def test_allowed_port_in_range(port: int) -> None:
    guard = ScopeGuard(
        [ScopeRule(rule_type=ScopeRuleType.PORT, value="1-1000", allowed=True)]
    )
    assert guard.check_port(port).in_scope is True


def test_disallowed_port_rejected_outside_range() -> None:
    guard = ScopeGuard(
        [ScopeRule(rule_type=ScopeRuleType.PORT, value="1-1000", allowed=True)]
    )
    assert guard.check_port(8443).in_scope is False


def test_denied_port_rejected_without_allow_rules() -> None:
    guard = ScopeGuard(
        [ScopeRule(rule_type=ScopeRuleType.PORT, value="22", allowed=False)]
    )
    assert guard.check_port(22).in_scope is False
    assert guard.check_port(443).in_scope is True


def test_denied_port_wins_over_allowed_range() -> None:
    guard = ScopeGuard(
        [
            ScopeRule(rule_type=ScopeRuleType.PORT, value="1-1000", allowed=True),
            ScopeRule(rule_type=ScopeRuleType.PORT, value="22", allowed=False),
        ]
    )
    assert guard.check_port(22).in_scope is False
    assert guard.check_port(80).in_scope is True


def test_no_port_rules_means_unrestricted() -> None:
    assert build_guard().check_port(9999).in_scope is True
    assert build_guard().check_port(1).in_scope is True


def test_check_accepts_full_urls() -> None:
    guard = build_guard()
    assert guard.check("https://www.example.com:443/path?q=1").in_scope is True
    assert guard.check("http://example.com/admin").in_scope is True
    assert guard.check("attacker.io/login").in_scope is False


def test_normalize_host_strips_case_and_dot() -> None:
    assert normalize_host("WWW.Example.COM.") == "www.example.com"


def test_extract_host_from_url() -> None:
    assert extract_host("https://app.example.com/x") == "app.example.com"
    assert extract_host("203.0.113.7") == "203.0.113.7"
    assert extract_host("app.example.com:8080/path") == "app.example.com"


def test_same_domain_redirect_loop_allowed_both_ways() -> None:
    guard = build_guard()
    assert guard.check_redirect(
        "http://example.com/", "http://example.net/"
    ).allowed is False
    assert guard.check_redirect(
        "http://www.example.com/", "http://example.com/"
    ).allowed is True


def test_subdomain_rule_targeted() -> None:
    guard = ScopeGuard(
        [
            ScopeRule(
                rule_type=ScopeRuleType.SUBDOMAIN, value="app.example.com", allowed=True
            )
        ]
    )
    assert guard.check_host("app.example.com").in_scope is True
    assert guard.check_host("api.app.example.com").in_scope is True
    assert guard.check_host("example.com").in_scope is False
    assert guard.check_host("www.example.com").in_scope is False


def test_rejected_decision_is_loggable() -> None:
    guard = build_guard()
    decision = guard.check_host("example.net")
    assert isinstance(decision, ScopeDecision)
    assert decision.in_scope is False
    assert "example.net" in decision.reason


def test_empty_scope_rejects_everything() -> None:
    guard = ScopeGuard.from_config(ScopeConfig(allowed_domains=(), allowed_ips=()))
    assert guard.check_host("example.com").in_scope is False
    assert guard.check_host("anything.io").in_scope is False


def test_from_row_accepts_dicts_and_objects() -> None:
    row_dict = {"rule_type": "domain", "value": "Example.COM.", "allowed": True}
    row_obj = ScopeRule(rule_type="domain", value="EXAMPLE.com.", allowed=True)
    guard = ScopeGuard([row_dict, row_obj])
    assert guard.check_host("www.example.com").in_scope is True