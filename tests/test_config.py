"""Configuration tests: parsing, validation, defaults, env-var secrets override."""

import os
from pathlib import Path

import pytest

from core.config import (
    AiMode,
    Config,
    ConfigError,
    JavascriptConfig,
    LimitsConfig,
    ScopeConfig,
    TcpPortRange,
    WebConfig,
    run_snapshot_from_dict,
)

MINIMAL_YAML = """
database:
  url: postgresql://user:pass@localhost:5432/argus
scope:
  allowed_domains:
    - example.com
  allowed_ips:
    - 203.0.113.0/24
  excluded:
    - internal-staging.example.com
"""


def write_config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_minimal_config(tmp_path: Path) -> None:
    cfg = Config.load(write_config(tmp_path, MINIMAL_YAML))
    assert cfg.project.name == "ARGUS"
    assert cfg.database.url.startswith("postgresql://")
    assert cfg.scope.allowed_domains == ("example.com",)
    assert cfg.scope.allowed_ips == ("203.0.113.0/24",)
    assert cfg.scope.excluded == ("internal-staging.example.com",)
    assert cfg.limits == LimitsConfig()
    assert cfg.network.tcp_ports == TcpPortRange()
    assert cfg.ai.mode is AiMode.HYBRID


def test_full_config_matches_example(tmp_path: Path) -> None:
    text = """
project:
  name: ARGUS
database:
  url: postgresql://u:p@localhost:5432/argus
scope:
  allowed_domains: [example.com, test.net]
  allowed_ips: []
  excluded: []
recon:
  aggressive_subdomain_discovery: false
network:
  tcp_ports: {start: 1, end: 1000}
web:
  http_probe: true
  crawling: false
  content_discovery: true
  historical_urls: false
javascript:
  deep_analysis: true
  source_maps: false
api:
  rest: true
  openapi: false
  swagger: false
  graphql: true
  websocket: false
  authentication_analysis: false
ai:
  mode: local
  local_model: llama3
  cloud_model: gpt-4o
limits:
  requests_per_second: 20
  concurrency: 8
outputs:
  json: true
  markdown: false
  html: false
"""
    cfg = Config.load(write_config(tmp_path, text))
    assert cfg.recon.aggressive_subdomain_discovery is False
    assert cfg.web.crawling is False
    assert cfg.web.http_probe is True
    assert cfg.javascript.source_maps is False
    assert cfg.api.authentication_analysis is False
    assert cfg.ai.mode is AiMode.LOCAL
    assert cfg.ai.local_model == "llama3"
    assert cfg.limits.requests_per_second == pytest.approx(20.0)
    assert cfg.limits.concurrency == 8
    assert cfg.outputs.markdown is False
    assert cfg.outputs.json is True


def test_database_url_required(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="database.url"):
        Config.load(write_config(tmp_path, "scope:\n  allowed_domains: [example.com]\n"))


def test_env_var_overrides_database_url(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ARGUS_DATABASE_URL", "postgresql://env:secret@db:5432/argus")
    cfg = Config.load(write_config(tmp_path, "database:\n  url: postgresql://bad\n"))
    assert cfg.database.url == "postgresql://env:secret@db:5432/argus"


def test_invalid_cidr_rejected(tmp_path: Path) -> None:
    text = """
database:
  url: postgresql://u:p@localhost:5432/argus
scope:
  allowed_ips: [not-an-ip]
"""
    with pytest.raises(ConfigError, match="allowed_ips"):
        Config.load(write_config(tmp_path, text))


def test_malformed_ipv4_exclusion_prefix_rejected() -> None:
    with pytest.raises(ConfigError, match="scope.excluded"):
        ScopeConfig.from_dict({"excluded": ["203.0.113.128/33"]})


@pytest.mark.parametrize(
    "value",
    [
        "203.0.113.1..2",
        "203.0.113.1.2",
        "203..0.113.1",
        "203.0.113.999..",
    ],
)
def test_malformed_ipv4_like_exclusion_rejected(value: str) -> None:
    with pytest.raises(ConfigError, match="scope.excluded"):
        ScopeConfig.from_dict({"excluded": [value]})


@pytest.mark.parametrize("value", ["123.456.789.012", "999.999.999.999"])
def test_numeric_dotted_hostname_exclusion_fails_closed(value: str) -> None:
    with pytest.raises(ConfigError, match="scope.excluded"):
        ScopeConfig.from_dict({"excluded": [value]})


def test_three_label_numeric_hostname_exclusion_remains_a_hostname() -> None:
    assert ScopeConfig.from_dict({"excluded": ["123.456.789"]}).excluded == (
        "123.456.789",
    )


def test_malformed_ipv4_exclusion_syntax_rejected() -> None:
    with pytest.raises(ConfigError, match="scope.excluded"):
        ScopeConfig.from_dict({"excluded": ["203.0.113.0/not-a-prefix"]})


def test_malformed_ipv6_exclusion_prefix_rejected() -> None:
    with pytest.raises(ConfigError, match="scope.excluded"):
        ScopeConfig.from_dict({"excluded": ["2001:db8::/129"]})


def test_malformed_ipv6_exclusion_syntax_rejected() -> None:
    with pytest.raises(ConfigError, match="scope.excluded"):
        ScopeConfig.from_dict({"excluded": ["2001:db8:::1/64"]})


def test_direct_scope_config_rejects_malformed_exclusion() -> None:
    with pytest.raises(ConfigError, match="scope.excluded"):
        ScopeConfig(
            allowed_ips=("203.0.113.0/24",),
            excluded=("203.0.113.128/33",),
        )


def test_direct_scope_config_rejects_malformed_ipv4_like_exclusion() -> None:
    with pytest.raises(ConfigError, match="scope.excluded"):
        ScopeConfig(
            allowed_ips=("203.0.113.0/24",),
            excluded=("203.0.113.1..2",),
        )


def test_valid_ip_and_hostname_exclusions_accepted() -> None:
    excluded = (
        "203.0.113.7",
        "203.0.113.0/24",
        "2001:db8::1",
        "2001:db8::/32",
        "Admin.Example.Com.",
    )
    assert ScopeConfig.from_dict({"excluded": excluded}).excluded == excluded


def test_invalid_ai_mode_rejected(tmp_path: Path) -> None:
    text = """
database:
  url: postgresql://u:p@localhost:5432/argus
ai:
  mode: turbo
"""
    with pytest.raises(ConfigError, match="ai.mode"):
        Config.load(write_config(tmp_path, text))


def test_invalid_port_range_rejected(tmp_path: Path) -> None:
    text = """
database:
  url: postgresql://u:p@localhost:5432/argus
network:
  tcp_ports: {start: 70000, end: 5}
"""
    with pytest.raises(ConfigError, match="tcp_ports"):
        Config.load(write_config(tmp_path, text))


def test_invalid_limits_rejected(tmp_path: Path) -> None:
    text = """
database:
  url: postgresql://u:p@localhost:5432/argus
limits:
  concurrency: 0
"""
    with pytest.raises(ConfigError, match="concurrency"):
        Config.load(write_config(tmp_path, text))


def test_to_dict_roundtrip_is_json_safe(tmp_path: Path) -> None:
    cfg = Config.load(write_config(tmp_path, MINIMAL_YAML))
    import json

    payload = json.dumps(cfg.to_dict())
    assert "example.com" in payload
    assert '"url"' in payload


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        Config.load(tmp_path / "nope.yaml")


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="invalid YAML"):
        Config.load(write_config(tmp_path, "database: [unclosed\n"))


# -- web.content_discovery.wordlist (Phase 23) --------------------------------


def test_wordlist_defaults_to_unapproved(tmp_path: Path) -> None:
    cfg = Config.load(write_config(tmp_path, MINIMAL_YAML))
    assert cfg.web.content_discovery is True
    assert cfg.web.content_discovery_wordlist is None


def test_wordlist_bool_gate_form_still_parses(tmp_path: Path) -> None:
    text = """
database:
  url: postgresql://u:p@localhost:5432/argus
web:
  content_discovery: false
"""
    cfg = Config.load(write_config(tmp_path, text))
    assert cfg.web.content_discovery is False
    assert cfg.web.content_discovery_wordlist is None


def test_wordlist_mapping_form_with_approved_path(tmp_path: Path) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("/admin\n/api\n", encoding="utf-8")
    text = f"""
database:
  url: postgresql://u:p@localhost:5432/argus
web:
  content_discovery:
    enabled: true
    wordlist: {wordlist}
"""
    cfg = Config.load(write_config(tmp_path, text))
    assert cfg.web.content_discovery is True
    assert cfg.web.content_discovery_wordlist == str(wordlist)


def test_wordlist_mapping_form_defaults_enabled(tmp_path: Path) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("/admin\n", encoding="utf-8")
    text = f"""
database:
  url: postgresql://u:p@localhost:5432/argus
web:
  content_discovery:
    wordlist: {wordlist}
"""
    cfg = Config.load(write_config(tmp_path, text))
    assert cfg.web.content_discovery is True
    assert cfg.web.content_discovery_wordlist == str(wordlist)


def test_wordlist_empty_and_null_are_unapproved(tmp_path: Path) -> None:
    for blank in ('wordlist: ""', "wordlist:"):
        text = f"""
database:
  url: postgresql://u:p@localhost:5432/argus
web:
  content_discovery:
    enabled: true
    {blank}
"""
        cfg = Config.load(write_config(tmp_path, text))
        assert cfg.web.content_discovery_wordlist is None


def test_wordlist_missing_file_fails_closed(tmp_path: Path) -> None:
    text = """
database:
  url: postgresql://u:p@localhost:5432/argus
web:
  content_discovery:
    enabled: true
    wordlist: C:/definitely/not/here.txt
"""
    with pytest.raises(ConfigError, match="wordlist"):
        Config.load(write_config(tmp_path, text))


def test_wordlist_non_string_fails_closed(tmp_path: Path) -> None:
    text = """
database:
  url: postgresql://u:p@localhost:5432/argus
web:
  content_discovery:
    enabled: true
    wordlist: [a, b]
"""
    with pytest.raises(ConfigError, match="wordlist"):
        Config.load(write_config(tmp_path, text))


def test_wordlist_disabled_gate_still_requires_a_valid_path(tmp_path: Path) -> None:
    # Fail-closed: even with the gate off, a present-but-invalid path is rejected.
    text = """
database:
  url: postgresql://u:p@localhost:5432/argus
web:
  content_discovery:
    enabled: false
    wordlist: C:/definitely/not/here.txt
"""
    with pytest.raises(ConfigError, match="wordlist"):
        Config.load(write_config(tmp_path, text))


def test_wordlist_render_roundtrips_through_the_snapshot(tmp_path: Path) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("/admin\n", encoding="utf-8")
    cfg = Config.load(write_config(tmp_path, MINIMAL_YAML))
    data = dict(cfg.to_dict())
    data["web"] = {
        "content_discovery": {"enabled": True, "wordlist": str(wordlist)},
    }
    rebuilt = Config.from_dict(data)
    assert rebuilt.web.content_discovery_wordlist == str(wordlist)


def test_wordlist_snapshot_emits_bool_when_unapproved(tmp_path: Path) -> None:
    snapshot = run_snapshot_from_dict(Config().to_dict())
    assert snapshot["web"]["content_discovery"] is True


def test_wordlist_snapshot_emits_the_approved_path(tmp_path: Path) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("/admin\n", encoding="utf-8")
    payload = {
        "scope": {"allowed_domains": ["example.com"]},
        "web": {"content_discovery": {"enabled": True, "wordlist": str(wordlist)}},
    }
    snapshot = run_snapshot_from_dict(payload)
    assert snapshot["web"]["content_discovery"] == {
        "enabled": True,
        "wordlist": str(wordlist),
    }


def test_wordlist_config_requires_explicit_approval_for_direct_construction(
    tmp_path: Path,
) -> None:
    # The dataclass itself remains a plain value: approval is an intake-time check.
    assert WebConfig(content_discovery_wordlist=None).content_discovery_wordlist is None


def test_historical_urls_defaults_disabled_fail_closed() -> None:
    # Phase 24: historical recon is an explicit opt-in; the gate (and its snapshot)
    # defaults to False so the stage is never enabled by omission.
    assert WebConfig().historical_urls is False
    assert WebConfig.from_dict({}).historical_urls is False


# -- javascript.enabled (Phase 25) ---------------------------------------------


def test_javascript_enabled_defaults_disabled_fail_closed() -> None:
    # Phase 25: JavaScript analysis is an explicit opt-in. A config that predates
    # the field, or omits it, loads disabled rather than enabling the stage.
    assert JavascriptConfig().enabled is False
    assert JavascriptConfig.from_dict({}).enabled is False
    assert JavascriptConfig.from_dict({"deep_analysis": True, "source_maps": True}).enabled is False


def test_javascript_enabled_is_read_from_dict() -> None:
    cfg = Config.from_dict(
        {
            "database": {"url": "postgresql://u:p@localhost/argus"},
            "javascript": {"enabled": True},
        }
    )
    assert cfg.javascript.enabled is True


def test_javascript_enabled_round_trips_through_to_dict() -> None:
    section = Config(javascript=JavascriptConfig(enabled=True)).to_dict()["javascript"]
    assert section == {"deep_analysis": True, "source_maps": True, "enabled": True}
    assert JavascriptConfig.from_dict(section).enabled is True


def test_run_snapshot_has_no_javascript_section() -> None:
    # Phase 25 makes no change to ``run_snapshot_from_dict``: the persisted run
    # snapshot carries no ``javascript`` section, so the gate is read only at
    # adapter-registration time, never from the snapshot.
    assert "javascript" not in run_snapshot_from_dict({})
    assert run_snapshot_from_dict({})["web"]["historical_urls"] is False
