"""Nmap port/service discovery adapter (Phase 20A).

TCP connect port discovery against one in-scope ``host`` (or IP), reusing the
Phase 13 execution chain unchanged: ``Task -> ScopeGuard -> RateLimiter ->
ToolAdapter -> ToolRunner -> Target`` (``02_ARCHITECTURE.md``). This adapter never
shells out itself and never constructs a shell string -- it hands an argument
array to the controlled :class:`core.tool_runner.ToolRunner`.

- **Command construction:** ``nmap -sT -Pn -n -p <start>-<end> -oX - <target>``
  (argument array). The range comes from ``config.network.tcp_ports``
  (``14_CONFIG_EXAMPLE.md``); the default is Nmap's top-ports-equivalent
  ``1-1000`` as declared by :class:`core.config.TcpPortRange`.
- **Scope:** the target is validated against the run's ``ScopeGuard`` before any
  packet is sent. A discovered host/IP is never re-scanned here; expansion
  (``recon.expansion``) re-checks every newly discovered destination against the
  same guard before proposing a follow-up task.
- **Output format:** Nmap XML (``-oX -``), parsed with the standard library.
- **Parser:** XML -> :class:`PortObservation`. Malformed or DTD/entity-bearing
  input yields no artifacts without raising (``13_TESTING_STRATEGY.md``). Only
  the ``(address, port, protocol)`` triples the schema can represent are kept.
- **Normalized object:** :class:`PortObservation` (``ports`` row + ``ip`` +
  ``asset_ip`` evidence). Port/service observations are **facts**, not findings:
  nothing here promotes a ``VALIDATED_FINDING`` or a hypothesis.
- **Raw output:** preserved by the Tool Runner under ``storage/raw/nmap/``.
- **No exploit/credential/brute force:** ``-sT`` (TCP connect) only; no scripts,
  no version-intensity escalation beyond Nmap's default fingerprinting, no
  ``-sU`` sweep by default.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, replace
from typing import Any, Optional
from xml.etree import ElementTree

from core.scope_guard import ScopeGuard
from core.tool_runner import CommandResult, ToolRunner
from recon.base import ToolAdapter, ToolExecution, ToolUnavailable, extract_host

log = logging.getLogger("argus.recon.nmap")

#: Fallback TCP range when no configuration is available.
DEFAULT_PORT_RANGE: tuple[int, int] = (1, 1000)

#: Protocols/port states the ``ports`` table can represent (migration ``0001``).
PROTOCOLS: frozenset[str] = frozenset({"tcp", "udp"})
STATES: frozenset[str] = frozenset({"open", "closed", "filtered"})

#: A full-range TCP connect scan is slow; give it a longer budget than the
#: runner's 60s default rather than truncating the scan.
DEFAULT_TIMEOUT: float = 300.0


@dataclass(frozen=True)
class PortObservation:
    """One normalized port/service observation (``ports`` row).

    ``host`` is filled by :meth:`NmapAdapter.execute` from the task target when
    that target is a hostname (not a bare IP), so the ingestion layer can link the
    port to its asset. ``service``/``version`` are ``""`` when Nmap reported none.
    """

    address: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    host: str = ""


class NmapAdapter(ToolAdapter):
    """TCP connect port discovery with ``nmap``, XML-parsed and scope-checked."""

    name = "nmap"
    executables = ("nmap",)

    def __init__(self, *, timeout: float = DEFAULT_TIMEOUT) -> None:
        super().__init__()
        self.timeout = float(timeout)

    # -- scope ---------------------------------------------------------------

    def validate(self, task: Any, scope: ScopeGuard) -> None:
        self._require_in_scope(extract_host(getattr(task, "target", "")), scope)

    # -- command construction ------------------------------------------------

    def build_command(self, task: Any, config: Any) -> list[str]:
        target = extract_host(getattr(task, "target", ""))
        if not target:
            raise ValueError(
                f"nmap: task.target must be a host[:port] or IP, got "
                f"{getattr(task, 'target', '')!r}"
            )
        start, end = port_range(config)
        return [
            "nmap",
            "-sT",
            "-Pn",
            "-n",
            "-p",
            f"{start}-{end}",
            "-oX",
            "-",
            target,
        ]

    # -- parse ---------------------------------------------------------------

    def parse(self, result: CommandResult) -> list[Any]:
        """Nmap XML -> :class:`PortObservation` list (non-fatal parsing)."""
        text = result.stdout or ""
        if not text.strip():
            return []
        # XML entity expansion / external entities are never parsed: an attacker-
        # influenced scan result must not be able to expand a billion laughs or
        # fetch a remote DTD.
        if "<!DOCTYPE" in text or "<!ENTITY" in text:
            log.warning("nmap: refusing to parse output containing a DTD/entity")
            return []
        try:
            root = ElementTree.fromstring(text)
        except ElementTree.ParseError:
            log.warning("nmap: output is not well-formed XML; no ports recovered")
            return []
        return _parse_ports(root)

    # -- execution -----------------------------------------------------------

    def execute(
        self,
        task: Any,
        runner: ToolRunner,
        config: Any,
        scope: ScopeGuard,
    ) -> ToolExecution:
        """Run Nmap through the controlled Tool Runner and stamp the host.

        The adapter's own ``execute`` (rather than the base implementation) is
        used so the longer scan timeout is honoured and so each observation can
        carry the resolved hostname of its task target when the target is a name
        rather than an address. When the target is an IP the host stays empty and
        the observation is attributed by ``address`` alone.
        """
        if not self.is_available():
            raise ToolUnavailable(
                f"nmap: none of {self.executables} found on PATH; skipping port "
                "discovery"
            )
        self.validate(task, scope)
        target = extract_host(getattr(task, "target", ""))
        if not target:
            raise ValueError(
                f"nmap: task.target must be a host[:port] or IP, got "
                f"{getattr(task, 'target', '')!r}"
            )
        command = self.build_command(task, config)
        result = runner.run_command(command, tool=self.name, timeout=self.timeout)
        artifacts = tuple(self.parse(result))
        host = "" if _is_ip(target) else target.lower().rstrip(".")
        if host:
            artifacts = tuple(
                replace(artifact, host=host)
                if isinstance(artifact, PortObservation)
                else artifact
                for artifact in artifacts
            )
        return ToolExecution(
            tool=self.name,
            command=command,
            exit_code=result.exit_code,
            raw_output_ref=result.raw_output_ref,
            artifacts=artifacts,
            timed_out=result.timed_out,
        )


def port_range(config: Any) -> tuple[int, int]:
    """The configured TCP range, falling back to :data:`DEFAULT_PORT_RANGE`."""
    network = getattr(config, "network", None)
    tcp = getattr(network, "tcp_ports", None) if network is not None else None
    if tcp is None:
        return DEFAULT_PORT_RANGE
    try:
        start = int(getattr(tcp, "start", DEFAULT_PORT_RANGE[0]))
        end = int(getattr(tcp, "end", DEFAULT_PORT_RANGE[1]))
    except (TypeError, ValueError):
        return DEFAULT_PORT_RANGE
    if start < 1 or end > 65535 or start > end:
        return DEFAULT_PORT_RANGE
    return start, end


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _parse_ports(root: ElementTree.Element) -> list[PortObservation]:
    seen: set[tuple[str, int, str]] = set()
    out: list[PortObservation] = []
    for host_el in root.iter("host"):
        address = _host_address(host_el)
        if not address:
            continue
        for port_el in host_el.iter("port"):
            protocol = (port_el.get("protocol") or "").strip().lower()
            if protocol not in PROTOCOLS:
                continue
            try:
                number = int(port_el.get("portid"))
            except (TypeError, ValueError):
                continue
            if number < 1 or number > 65535:
                continue
            state = _port_state(port_el)
            if state is None:
                continue
            service, version = _service(port_el)
            key = (address, number, protocol)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                PortObservation(
                    address=address,
                    port=number,
                    protocol=protocol,
                    state=state,
                    service=service,
                    version=version,
                )
            )
    return out


def _host_address(host_el: ElementTree.Element) -> str:
    candidates = host_el.findall("address")
    ordered: list[Optional[str]] = []
    ordered += [c.get("addr") for c in candidates if c.get("addrtype") == "ipv4"]
    ordered += [c.get("addr") for c in candidates if c.get("addrtype") == "ipv6"]
    ordered += [c.get("addr") for c in candidates]
    for addr in ordered:
        if addr and _is_ip(addr.strip()):
            return addr.strip()
    return ""


def _port_state(port_el: ElementTree.Element) -> Optional[str]:
    state_el = port_el.find("state")
    raw = state_el.get("state") if state_el is not None else "open"
    state = (raw or "open").strip().lower()
    return state if state in STATES else None


def _service(port_el: ElementTree.Element) -> tuple[str, str]:
    service_el = port_el.find("service")
    if service_el is None:
        return "", ""
    name = (service_el.get("name") or "").strip()
    parts = [
        part.strip()
        for part in (
            service_el.get("product"),
            service_el.get("version"),
            service_el.get("extrainfo"),
        )
        if part and part.strip()
    ]
    return name, " ".join(parts)