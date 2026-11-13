"""Deterministic Scope Guard (``04_SCOPE_SAFETY.md``).

The Scope Guard is the only component that decides in/out-of-scope status. It
evaluates fixed ``scope_rules`` from ``05_DATA_MODEL.md``; AI agents, parsers,
and adapters cannot override it. Scope is always evaluated **before** any active
interaction with a target, including redirect or discovery destinations.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional, Sequence, Union
from urllib.parse import urlparse

from core.config import (
    ConfigError,
    ScopeConfig,
    _looks_like_ip_or_cidr,
    _normalize_ip_or_cidr_candidate,
)


class ScopeRuleType:
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    CIDR = "cidr"
    PORT = "port"
    EXCLUSION = "exclusion"


@dataclass(frozen=True)
class ScopeRule:
    """Mirror of the ``scope_rules`` table row (``05_DATA_MODEL.md``)."""

    rule_type: str
    value: str
    allowed: bool = True

    def __post_init__(self) -> None:
        if self.rule_type == ScopeRuleType.EXCLUSION:
            if not isinstance(self.value, str) or not _looks_like_ip_or_cidr(
                self.value
            ):
                return
            candidate = _normalize_ip_or_cidr_candidate(self.value)
            try:
                network = ipaddress.ip_network(candidate, strict=False)
            except ValueError as exc:
                raise ConfigError(
                    "scope rule exclusion value is not a valid IP/CIDR: "
                    f"{self.value!r}"
                ) from exc
            single = network.num_addresses == 1
            object.__setattr__(
                self,
                "rule_type",
                ScopeRuleType.IP if single else ScopeRuleType.CIDR,
            )
            object.__setattr__(
                self,
                "value",
                str(network.network_address if single else network),
            )
            object.__setattr__(self, "allowed", False)
            return
        if self.rule_type not in (ScopeRuleType.IP, ScopeRuleType.CIDR):
            return
        if not isinstance(self.value, str) or not self.value:
            raise ConfigError(
                f"scope rule {self.rule_type} value must be a non-empty string"
            )
        try:
            if self.rule_type == ScopeRuleType.IP:
                canonical = str(ipaddress.ip_address(self.value))
            else:
                ipaddress.ip_network(self.value, strict=False)
                return
        except ValueError as exc:
            raise ConfigError(
                f"scope rule {self.rule_type} value is not a valid IP/CIDR: "
                f"{self.value!r}"
            ) from exc
        object.__setattr__(self, "value", canonical)

    @classmethod
    def from_row(cls, row: Union["ScopeRule", dict, object]) -> "ScopeRule":
        if isinstance(row, ScopeRule):
            return row
        if isinstance(row, dict):
            return cls(
                rule_type=str(row["rule_type"]),
                value=str(row["value"]).lower().rstrip("."),
                allowed=bool(row["allowed"]),
            )
        return cls(
            rule_type=str(row.rule_type),
            value=str(row.value).lower().rstrip("."),
            allowed=bool(row.allowed),
        )


@dataclass(frozen=True)
class ScopeDecision:
    """Result of evaluating one target (host / IP / port) against scope."""

    in_scope: bool
    reason: str
    matched_rule: Optional[str] = None

    def __bool__(self) -> bool:
        return self.in_scope


@dataclass(frozen=True)
class RedirectDecision:
    """Result of evaluating a redirect / discovered destination."""

    allowed: bool
    destination_in_scope: bool
    reason: str


class ScopeGuard:
    """Evaluates targets against a fixed rule set, deterministically.

    Rules may be provided from ``DB`` rows (``ScopeRule.from_row``) or built from
    ``core.config.ScopeConfig`` (``from_config``). Exclusions always win over
    allow rules.
    """

    def __init__(self, rules: Sequence[Union["ScopeRule", dict, object]] = ()):
        parsed = [ScopeRule.from_row(r) for r in rules]
        self._allows: list[ScopeRule] = [r for r in parsed if r.allowed]
        self._exclusions: list[ScopeRule] = [r for r in parsed if not r.allowed]

    @classmethod
    def from_config(cls, scope: ScopeConfig) -> "ScopeGuard":
        """Build a guard from ``scope`` config section (``14_CONFIG_EXAMPLE.md``)."""
        rules: list[ScopeRule] = []
        for domain in scope.allowed_domains:
            rules.append(
                ScopeRule(
                    rule_type=ScopeRuleType.DOMAIN,
                    value=normalize_host(domain),
                    allowed=True,
                )
            )
        for entry in scope.allowed_ips:
            network = ipaddress.ip_network(entry, strict=False)
            single = network.num_addresses == 1
            rules.append(
                ScopeRule(
                    rule_type=(
                        ScopeRuleType.IP if single else ScopeRuleType.CIDR
                    ),
                    # For a single address the rule is matched by exact equality in
                    # ``check_ip``, so the value must be the bare address. Keeping the
                    # entry verbatim would store "1.2.3.4/32" for an IP rule, which no
                    # address can ever equal, silently authorizing nothing.
                    value=str(network.network_address if single else network),
                    allowed=True,
                )
            )
        rules.extend(_excluded_rule(entry) for entry in scope.excluded)
        return cls(rules)

    # -- public API --------------------------------------------------------

    def check(self, target: str) -> ScopeDecision:
        """Check a raw target string (hostname, IP, or URL).

        URLs are reduced to their host. This is the single entry point for
        adapter and orchestrator targets.
        """
        host = extract_host(target)
        if host is None:
            return ScopeDecision(
                in_scope=False,
                reason=f"target {target!r} is not a recognizable hostname/IP/URL",
            )
        if _looks_like_ip(host):
            return self.check_ip(host)
        return self.check_host(host)

    def check_host(self, hostname: str) -> ScopeDecision:
        host = normalize_host(hostname)
        if not host or not _is_valid_hostname(host):
            return ScopeDecision(
                in_scope=False, reason=f"invalid hostname {hostname!r}"
            )
        for rule in self._exclusions:
            if rule.rule_type in (ScopeRuleType.EXCLUSION, ScopeRuleType.DOMAIN):
                if _host_matches(host, rule.value):
                    return ScopeDecision(
                        in_scope=False,
                        reason=f"host {host} excluded by rule {rule.value!r}",
                        matched_rule=rule.value,
                    )
        matched: Optional[ScopeRule] = None
        for rule in self._allows:
            if rule.rule_type in (ScopeRuleType.DOMAIN, ScopeRuleType.SUBDOMAIN):
                if _host_matches(host, rule.value):
                    matched = rule
                    break
        if matched is None:
            return ScopeDecision(
                in_scope=False,
                reason=f"host {host} not covered by any allowed domain/subdomain rule",
            )
        return ScopeDecision(
            in_scope=True,
            reason=f"host {host} allowed by rule {matched.value!r}",
            matched_rule=matched.value,
        )

    def check_ip(self, address: str) -> ScopeDecision:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return ScopeDecision(
                in_scope=False, reason=f"invalid IP address {address!r}"
            )
        for rule in self._exclusions:
            if rule.rule_type == ScopeRuleType.IP and rule.value == str(ip):
                return ScopeDecision(
                    in_scope=False,
                    reason=f"IP {ip} explicitly excluded",
                    matched_rule=rule.value,
                )
            if rule.rule_type == ScopeRuleType.CIDR and _ip_in_network(
                ip, rule.value
            ):
                return ScopeDecision(
                    in_scope=False,
                    reason=f"IP {ip} excluded by CIDR {rule.value!r}",
                    matched_rule=rule.value,
                )
        for rule in self._allows:
            if rule.rule_type == ScopeRuleType.IP and rule.value == str(ip):
                return ScopeDecision(
                    in_scope=True,
                    reason=f"IP {ip} explicitly allowed",
                    matched_rule=rule.value,
                )
            if rule.rule_type == ScopeRuleType.CIDR and _ip_in_network(
                ip, rule.value
            ):
                return ScopeDecision(
                    in_scope=True,
                    reason=f"IP {ip} inside CIDR {rule.value!r}",
                    matched_rule=rule.value,
                )
        return ScopeDecision(
            in_scope=False, reason=f"IP {ip} not covered by any allowed rule"
        )

    def check_port(self, port: int) -> ScopeDecision:
        for rule in self._exclusions:
            if rule.rule_type == ScopeRuleType.PORT and _port_in_rule(
                port, rule.value
            ):
                return ScopeDecision(
                    in_scope=False,
                    reason=f"port {port} excluded by rule {rule.value!r}",
                    matched_rule=rule.value,
                )
        allowed = [r for r in self._allows if r.rule_type == ScopeRuleType.PORT]
        for rule in allowed:
            if _port_in_rule(port, rule.value):
                return ScopeDecision(
                    in_scope=True,
                    reason=f"port {port} allowed by rule {rule.value!r}",
                    matched_rule=rule.value,
                )
        if not allowed:
            return ScopeDecision(
                in_scope=True,
                reason="no port rule configured; port access not restricted",
            )
        return ScopeDecision(
            in_scope=False, reason=f"port {port} not allowed by any port rule"
        )

    def check_redirect(self, source: str, destination: str) -> RedirectDecision:
        """Evaluate a redirect/discovered destination per the authoritative
        Redirect and Discovered-Target Policy (``04_SCOPE_SAFETY.md``).

        The destination is *never acted on*; this only reports whether the
        destination is in scope so the caller can follow policy (follow when in
        scope; when out of scope: record evidence, mark out-of-scope, and
        optionally create a skipped task — no active interaction).
        """
        dest = extract_host(destination)
        if dest is None:
            return RedirectDecision(
                allowed=False,
                destination_in_scope=False,
                reason=f"redirect destination {destination!r} is not a hostname/IP",
            )
        if _looks_like_ip(dest):
            decision = self.check_ip(dest)
        else:
            decision = self.check_host(dest)
        return RedirectDecision(
            allowed=decision.in_scope,
            destination_in_scope=decision.in_scope,
            reason=(
                f"redirect {source!r} -> {dest!r}: {decision.reason}"
                if not decision.in_scope
                else f"redirect {source!r} -> {dest!r}: destination in scope; "
                "follow per normal task policy"
            ),
        )


# -- helpers ----------------------------------------------------------------


def normalize_host(hostname: str) -> str:
    """Lowercase and strip a trailing root dot (``05_DATA_MODEL.md`` assets)."""
    return hostname.strip().lower().rstrip(".")


def extract_host(target: str) -> Optional[str]:
    """Extract a host/IP from a hostname, IP, or URL string."""
    if not target:
        return None
    candidate = target.strip()
    if _looks_like_ip(candidate):
        return candidate
    if "://" in candidate or candidate.startswith("//"):
        parsed = urlparse(candidate)
        host = parsed.hostname
        return normalize_host(host) if host else None
    # bare hostname, strip optional scheme-less port/path
    first = candidate.split("/", 1)[0].split(":", 1)[0]
    return normalize_host(first) if first else None


def _looks_like_ip(value: str) -> bool:
    candidate = value.strip()
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _excluded_rule(value: str) -> ScopeRule:
    """Classify one exclusion, failing closed for malformed IP/CIDR-like values.

    Hostnames keep generic ``EXCLUSION`` semantics and are normalized. Values
    shaped like an IP address or CIDR must parse; otherwise a ``ConfigError`` is
    raised rather than silently degrading into an exclusion that ``check_ip``
    would ignore.
    """
    if not _looks_like_ip_or_cidr(value):
        return ScopeRule(
            rule_type=ScopeRuleType.EXCLUSION,
            value=normalize_host(value),
            allowed=False,
        )
    candidate = _normalize_ip_or_cidr_candidate(value)
    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError as exc:
        raise ConfigError(
            f"config.scope.excluded is not a valid IP/CIDR: {value!r}"
        ) from exc
    single = network.num_addresses == 1
    return ScopeRule(
        rule_type=ScopeRuleType.IP if single else ScopeRuleType.CIDR,
        value=str(network.network_address if single else network),
        allowed=False,
    )


def _is_valid_hostname(host: str) -> bool:
    """True when ``host`` could actually be a DNS name.

    Scope rules match by suffix, so without a syntax check any string ending in
    an allowed domain is treated as in scope -- including strings that no resolver
    can ever answer for, such as ``evil'; DROP TABLE assets; --.example.com``.
    Those are not hostnames; they are malformed input, and promoting one to an
    asset would persist attacker-chosen bytes into the asset graph.

    Underscores are deliberately permitted: real reconnaissance output contains
    service names such as ``_dmarc.example.com`` and ``_sip._tcp.example.com``.
    Punycode (``xn--``) labels are valid ASCII and pass unchanged. This checks only
    that the name is *possible*; it makes no claim that it resolves.
    """
    if not host or len(host) > 253:
        return False
    if host.startswith("."):
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_.")
    if not set(host) <= allowed:
        return False
    labels = host.split(".")
    return all(0 < len(label) <= 63 for label in labels)


def _host_matches(host: str, rule_value: str) -> bool:
    value = rule_value.lstrip("*.")
    return host == value or host.endswith("." + value)


def _ip_in_network(ip, network_value: str) -> bool:
    network = ipaddress.ip_network(network_value, strict=False)
    return ip in network


def _port_in_rule(port: int, rule_value: str) -> bool:
    value = rule_value.strip()
    if value == "*" or value.lower() == "all":
        return True
    if "-" in value:
        start_s, end_s = value.split("-", 1)
        try:
            return int(start_s) <= port <= int(end_s)
        except ValueError:
            return False
    try:
        return int(value) == port
    except ValueError:
        return False