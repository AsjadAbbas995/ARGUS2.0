"""Nmap port/service discovery adapter fixture tests (Phase 20A).

All parse/scope/execution tests drive the adapter against inline Nmap XML
samples -- no live scan and no shelled binary, so CI stays deterministic and
offline (``13_TESTING_STRATEGY.md`` §Adapter Fixture Tests).

Cases covered:

- XML parse -> ``PortObservation`` list (address/port/protocol/state/service/
  version), document order preserved, ``(address, port, protocol)`` dedup.
- Non-fatal tolerance: malformed XML, empty output, non-XML garbage.
- DTD/entity-bearing output is refused (XML entity-expansion safety).
- Only representable protocols/states surface; ambiguous states and unknown
  protocols are skipped, never guessed.
- Command construction honours ``config.network.tcp_ports`` and the documented
  ``-sT -Pn -n -oX -`` shape; never a shell string.
- Scope validation and the safe-default execution path; the observation's
  ``host`` is stamped from the task target only when it is a hostname.
"""

from __future__ import annotations

from typing import Any

import pytest

from core.scope_guard import ScopeConfig, ScopeGuard, ScopeRule, ScopeRuleType
from core.tool_runner import CommandResult
from recon.base import ScopeViolation, ToolUnavailable
from recon.ports.nmap import (
    DEFAULT_PORT_RANGE,
    NmapAdapter,
    PortObservation,
    port_range,
)

TWO_PORTS = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
<host starttime="1" endtime="2"><status state="up"/>
<address addr="93.184.216.34" addrtype="ipv4" />
<ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.25.1"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx"/></port>
</ports>
</host>
</nmaprun>
"""

CLOSED_AND_FILTERED = """<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/>
<address addr="203.0.113.7" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
<port protocol="tcp" portid="25"><state state="filtered"/></port>
<port protocol="tcp" portid="53"><state state="open|filtered"/></port>
<port protocol="sctp" portid="9"><state state="open"/></port>
</ports>
</host>
</nmaprun>
"""


def _result(stdout: str, exit_code: int = 0) -> CommandResult:
    return CommandResult(
        tool="nmap",
        command=["nmap", "-sT", "-Pn", "-n", "-p", "1-1000", "-oX", "-", "example.com"],
        stdout=stdout,
        stderr="",
        exit_code=exit_code,
        timed_out=False,
    )


@pytest.fixture
def adapter() -> NmapAdapter:
    return NmapAdapter()


@pytest.fixture
def scope() -> ScopeGuard:
    return ScopeGuard(
        [ScopeRule(rule_type=ScopeRuleType.DOMAIN, value="example.com", allowed=True)]
    )


@pytest.fixture
def config() -> Any:
    class _Net:
        class _Tcp:
            start = 1
            end = 1000

        tcp_ports = _Tcp()

    class _Networks:
        network = _Net()

    return _Networks()


class _Task:
    def __init__(self, target: str):
        self.target = target


# -- parse --------------------------------------------------------------------


def test_parse_surfaces_ports_with_service_and_version(adapter: NmapAdapter) -> None:
    out = adapter.parse(_result(TWO_PORTS))
    assert out == [
        PortObservation(
            address="93.184.216.34",
            port=80,
            protocol="tcp",
            state="open",
            service="http",
            version="nginx 1.25.1",
        ),
        PortObservation(
            address="93.184.216.34",
            port=443,
            protocol="tcp",
            state="open",
            service="https",
            version="nginx",
        ),
    ]


def test_parse_keeps_document_order(adapter: NmapAdapter) -> None:
    out = adapter.parse(_result(TWO_PORTS))
    assert [o.port for o in out] == [80, 443]


def test_parse_represents_closed_and_filtered_but_skips_ambiguous(adapter: NmapAdapter) -> None:
    out = adapter.parse(_result(CLOSED_AND_FILTERED))
    states = {(o.port, o.state) for o in out}
    assert (22, "closed") in states
    assert (25, "filtered") in states
    # ``open|filtered`` and ``sctp`` cannot be represented honestly: skipped.
    assert all(o.protocol == "tcp" for o in out)
    assert 53 not in {o.port for o in out}
    assert 9 not in {o.port for o in out}


def test_parse_duplicate_triples_collapse(adapter: NmapAdapter) -> None:
    dup = """<nmaprun>
<host><status state="up"/><address addr="93.184.216.34" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="443"><state state="open"/></port>
</ports></host>
</nmaprun>"""
    out = adapter.parse(_result(dup))
    assert len(out) == 2


def test_parse_empty_output(adapter: NmapAdapter) -> None:
    assert adapter.parse(_result("")) == []


def test_parse_malformed_xml_not_fatal(adapter: NmapAdapter) -> None:
    assert adapter.parse(_result("<nmaprun><host>unterminated")) == []


def test_parse_non_xml_garbage_not_fatal(adapter: NmapAdapter) -> None:
    assert adapter.parse(_result("plain text, not XML at all")) == []


def test_parse_refuses_dtd_and_entities(adapter: NmapAdapter) -> None:
    evil = "<!DOCTYPE foo [<!ENTITY x 'y'>]><nmaprun/>"
    assert adapter.parse(_result(evil)) == []
    assert adapter.parse(_result("<!ENTITY boom SYSTEM 'file:///etc/passwd'>")) == []


def test_parse_skips_bogus_port_ids_and_ips(adapter: NmapAdapter) -> None:
    bogus = """<nmaprun><host><status state="up"/>
<address addr="203.0.113.9" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="not-a-number"><state state="open"/></port>
<port protocol="tcp" portid="-1"><state state="open"/></port>
<port protocol="tcp" portid="70000"><state state="open"/></port>
</ports>
</host>
</nmaprun>"""
    assert adapter.parse(_result(bogus)) == []


def test_parse_skips_host_without_a_valid_address(adapter: NmapAdapter) -> None:
    noaddr = """<nmaprun><host><status state="up"/>
<address addr="not-an-ip" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
</host></nmaprun>"""
    assert adapter.parse(_result(noaddr)) == []


def test_parse_ipv6_address_supported(adapter: NmapAdapter) -> None:
    raw = """<nmaprun><host><status state="up"/>
<address addr="2606:2800:220:1::17" addrtype="ipv6"/>
<ports><port protocol="tcp" portid="443"><state state="open"/></port></ports>
</host></nmaprun>"""
    out = adapter.parse(_result(raw))
    assert out[0].address == "2606:2800:220:1::17"


# -- scope --------------------------------------------------------------------


def test_validate_in_scope_ok(adapter: NmapAdapter, scope: ScopeGuard) -> None:
    adapter.validate(_Task("app.example.com"), scope)


def test_validate_out_of_scope_raises(adapter: NmapAdapter, scope: ScopeGuard) -> None:
    with pytest.raises(ScopeViolation):
        adapter.validate(_Task("evil.example.net"), scope)


# -- build_command ------------------------------------------------------------


def test_build_command_shape(adapter: NmapAdapter, config: Any) -> None:
    command = adapter.build_command(_Task("app.example.com"), config)
    assert command[0] == "nmap"
    assert command[1] == "-sT"
    assert command[4] == "-p"
    assert command[5] == "1-1000"
    assert command[6:] == ["-oX", "-", "app.example.com"]


def test_build_command_uses_configured_range() -> None:
    adapter = NmapAdapter()

    class _Net:
        class _Tcp:
            start = 80
            end = 444

        tcp_ports = _Tcp()

    class _Networks:
        network = _Net()

    command = adapter.build_command(_Task("example.com"), _Networks())
    assert command[5] == "80-444"


def test_build_command_rejects_empty_target(adapter: NmapAdapter, config: Any) -> None:
    with pytest.raises(ValueError):
        adapter.build_command(_Task(""), config)


# -- port_range helper --------------------------------------------------------


def test_port_range_falls_back_when_unconfigured() -> None:
    assert port_range(None) == DEFAULT_PORT_RANGE
    assert port_range(object()) == DEFAULT_PORT_RANGE


def test_port_range_rejects_invalid_ranges() -> None:
    class _Net:
        class _Tcp:
            start = 0
            end = 70000

        tcp_ports = _Tcp()

    class _Networks:
        network = _Net()

    assert port_range(_Networks()) == DEFAULT_PORT_RANGE


# -- execution ----------------------------------------------------------------


class _FakeRunner:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout

    def run_command(
        self, command: list[str], *, tool: str, timeout: float = 300.0
    ) -> CommandResult:
        return _result(self.stdout)


def test_execute_stamps_host_when_target_is_a_hostname(scope: ScopeGuard, config: Any) -> None:
    class _Available(NmapAdapter):
        def is_available(self) -> bool:
            return True

    execution = _Available().execute(
        _Task("app.example.com"), _FakeRunner(TWO_PORTS), config, scope
    )
    assert execution.tool == "nmap"
    assert all(isinstance(a, PortObservation) and a.host == "app.example.com"
               for a in execution.artifacts)


def test_execute_leaves_host_empty_when_target_is_an_ip(scope: ScopeGuard, config: Any) -> None:
    ip_scope = ScopeGuard.from_config(
        ScopeConfig(
            allowed_domains=("example.com",),
            allowed_ips=("93.184.216.34/32",),
        )
    )

    class _Available(NmapAdapter):
        def is_available(self) -> bool:
            return True

    execution = _Available().execute(
        _Task("93.184.216.34"), _FakeRunner(TWO_PORTS), config, ip_scope
    )
    assert [o.host for o in execution.artifacts] == ["", ""]


def test_execute_missing_binary_raises_unavailable(scope: ScopeGuard, config: Any) -> None:
    class _Missing(NmapAdapter):
        executables = ("definitely-not-installed-nmap-argus",)

        def is_available(self) -> bool:
            return False

    with pytest.raises(ToolUnavailable):
        _Missing().execute(_Task("example.com"), _FakeRunner(TWO_PORTS), config, scope)