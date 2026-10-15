"""Typed configuration for ARGUS.

Mirrors ``docs/14_CONFIG_EXAMPLE.md``. Loaded from YAML, validated
deterministically, and serializable back to a plain dict so that intake can
persist the ``configuration_snapshot`` on the ``runs`` record
(``05_DATA_MODEL.md``).

Security rule from ``14_CONFIG_EXAMPLE.md`` §Secrets: secrets such as
``database.url`` may be supplied via environment variables instead of the
committed file.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    """Raised when configuration is invalid."""


class AiMode(str, Enum):
    LOCAL = "local"
    CLOUD = "cloud"
    HYBRID = "hybrid"


class RuleType(str, Enum):
    """Scope rule types matching ``scope_rules.rule_type`` in ``05_DATA_MODEL.md``."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    CIDR = "cidr"
    EXCLUSION = "exclusion"


def _require_non_empty(value: Any, path: str) -> None:
    if value in (None, ""):
        raise ConfigError(f"config.{path} must be provided")


def _require_positive(value: Any, path: str) -> None:
    if not isinstance(value, (int, float)) or value <= 0:
        raise ConfigError(f"config.{path} must be a number > 0")


def _validate_rule_value(value: Any, rule_type: RuleType, path: str) -> None:
    _require_non_empty(value, path)
    if not isinstance(value, str):
        raise ConfigError(f"config.{path} must be a string")
    lowered = value.lower().rstrip(".")
    if rule_type in (RuleType.IP, RuleType.CIDR):
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:  # pragma: no cover - exercised via ConfigError
            raise ConfigError(f"config.{path} is not a valid IP/CIDR: {value!r}") from exc
    return None


@dataclass(frozen=True)
class ProjectConfig:
    name: str = "ARGUS"

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ProjectConfig":
        data = data or {}
        name = data.get("name", "ARGUS")
        _require_non_empty(name, "project.name")
        return cls(name=str(name))


@dataclass(frozen=True)
class DatabaseConfig:
    url: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "DatabaseConfig":
        data = data or {}
        url = str(data.get("url", "") or "")
        env_url = os.environ.get("ARGUS_DATABASE_URL")
        if env_url:
            url = env_url
        if not url:
            raise ConfigError(
                "config.database.url is required (or set ARGUS_DATABASE_URL); "
                "never commit real credentials"
            )
        return cls(url=url)


@dataclass(frozen=True)
class ScopeConfig:
    allowed_domains: tuple[str, ...] = ()
    allowed_ips: tuple[str, ...] = ()
    excluded: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ScopeConfig":
        data = data or {}
        allowed_domains = tuple(data.get("allowed_domains") or ())
        allowed_ips = tuple(data.get("allowed_ips") or ())
        excluded = tuple(data.get("excluded") or ())
        for entry in allowed_domains:
            _validate_rule_value(entry, RuleType.DOMAIN, "scope.allowed_domains")
        for entry in allowed_ips:
            _validate_rule_value(entry, RuleType.CIDR, "scope.allowed_ips")
        for entry in excluded:
            _validate_rule_value(entry, RuleType.EXCLUSION, "scope.excluded")
        return cls(
            allowed_domains=allowed_domains,
            allowed_ips=allowed_ips,
            excluded=excluded,
        )


@dataclass(frozen=True)
class TcpPortRange:
    start: int = 1
    end: int = 1000

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "TcpPortRange":
        data = data or {}
        start = int(data.get("start", 1))
        end = int(data.get("end", 1000))
        if start < 1 or end > 65535 or start > end:
            raise ConfigError(
                f"config.network.tcp_ports must satisfy 1 <= start <= end <= 65535 "
                f"(got {start}..{end})"
            )
        return cls(start=start, end=end)


@dataclass(frozen=True)
class NetworkConfig:
    tcp_ports: TcpPortRange = field(default_factory=TcpPortRange)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "NetworkConfig":
        data = data or {}
        return cls(tcp_ports=TcpPortRange.from_dict(data.get("tcp_ports")))


@dataclass(frozen=True)
class ReconConfig:
    aggressive_subdomain_discovery: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ReconConfig":
        data = data or {}
        return cls(
            aggressive_subdomain_discovery=bool(
                data.get("aggressive_subdomain_discovery", True)
            )
        )


@dataclass(frozen=True)
class WebConfig:
    http_probe: bool = True
    crawling: bool = True
    content_discovery: bool = True
    #: Phase 24: historical recon reaches into third-party archives (and, in the
    #: deferred follow-up, could lead to active probing), so its gate fails closed:
    #: the default is disabled and enablement is an explicit operator opt-in.
    historical_urls: bool = False
    content_discovery_wordlist: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "WebConfig":
        data = data or {}
        cd = data.get("content_discovery")
        if isinstance(cd, dict):
            enabled = bool(cd.get("enabled", True))
            raw_wordlist = cd.get("wordlist")
        else:
            enabled = bool(cd if cd is not None else True)
            raw_wordlist = data.get("content_discovery_wordlist")
        wordlist = None
        if raw_wordlist is not None and str(raw_wordlist).strip():
            if not isinstance(raw_wordlist, str):
                raise ConfigError(
                    "config.web.content_discovery.wordlist must be a path string"
                )
            wordlist = raw_wordlist.strip()
            path = Path(wordlist)
            if not path.is_file():
                raise ConfigError(
                    f"config.web.content_discovery.wordlist must reference an existing "
                    f"file: {wordlist!r}"
                )
            if not os.access(path, os.R_OK):
                raise ConfigError(
                    f"config.web.content_discovery.wordlist must be readable: {wordlist!r}"
                )
        return cls(
            http_probe=bool(data.get("http_probe", True)),
            crawling=bool(data.get("crawling", True)),
            content_discovery=enabled,
            historical_urls=bool(data.get("historical_urls", False)),
            content_discovery_wordlist=wordlist,
        )

    def _content_discovery_section(self) -> dict[str, Any]:
        """The ``web.content_discovery`` snapshot section for ``to_dict``.

        Emitted as the plain boolean gate when no wordlist is approved, and as a
        mapping carrying the approved local path when one is (the path is the
        authoritative approval record, so it must survive into the snapshot the
        run reproduces from -- ``02_ARCHITECTURE.md`` ``runs.configuration_snapshot``).
        """
        if self.content_discovery_wordlist:
            return {
                "content_discovery": {
                    "enabled": self.content_discovery,
                    "wordlist": self.content_discovery_wordlist,
                }
            }
        return {"content_discovery": self.content_discovery}


@dataclass(frozen=True)
class JavascriptConfig:
    deep_analysis: bool = True
    source_maps: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "JavascriptConfig":
        data = data or {}
        return cls(
            deep_analysis=bool(data.get("deep_analysis", True)),
            source_maps=bool(data.get("source_maps", True)),
        )


@dataclass(frozen=True)
class ApiConfig:
    rest: bool = True
    openapi: bool = True
    swagger: bool = True
    graphql: bool = True
    websocket: bool = True
    authentication_analysis: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ApiConfig":
        data = data or {}
        return cls(
            rest=bool(data.get("rest", True)),
            openapi=bool(data.get("openapi", True)),
            swagger=bool(data.get("swagger", True)),
            graphql=bool(data.get("graphql", True)),
            websocket=bool(data.get("websocket", True)),
            authentication_analysis=bool(data.get("authentication_analysis", True)),
        )


@dataclass(frozen=True)
class AiConfig:
    """AI/intelligence-layer settings (``14_CONFIG_EXAMPLE.md`` ``ai.*``).

    ``enabled`` (Phase 16) defaults to **False**. It is the single switch that decides whether
    ``create_serve_app`` passes an ``analysis=`` hook to the ``Orchestrator``, and therefore
    whether the adaptive loop runs at all. Defaulting it off means:

    * the loop cannot be turned on by accident, by an omitted key, or by a config default;
    * with it off, ``analysis`` stays ``None`` and the run walks straight to ``COMPLETED`` --
      byte-identical to Phase 15 behaviour;
    * a deployment can adopt the intelligence layer deliberately, per-environment, instead of
      inheriting it from whatever the defaults happen to be.

    ``mode``/``local_model``/``cloud_model`` remain the Phase-6 routing configuration. Phase 16
    makes no model call, so they are recorded on each ``ai_analysis`` row rather than used to
    select a provider; Phase 17 consumes them at that seam.

    ``max_loop_passes`` (Phase 17) is the adaptive loop's instability/safety limit. It was a
    hardcoded ``Orchestrator`` dataclass default of 32, which meant an operator had no way to
    tighten or relax the budget short of editing Python. It is process-level policy rather than
    per-run configuration, for the same reason ``enabled`` is: the loop budget is fixed when the
    orchestrator is composed, so it does not belong in ``runs.configuration_snapshot``, where a
    recorded-but-unenforced value would be a lie. A deployment sets it under ``ai:``.
    """

    mode: AiMode = AiMode.HYBRID
    local_model: str = ""
    cloud_model: str = ""
    enabled: bool = False
    #: Instability/safety limit on the adaptive loop (01_PRODUCT_SPEC.md §10). Reached, the run
    #: ends as ``CANCELLED`` rather than looping. Must be > 0; the default preserves the
    #: pre-Phase-17 behaviour exactly.
    max_loop_passes: int = 32

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "AiConfig":
        data = data or {}
        mode_raw = str(data.get("mode", "hybrid")).lower()
        try:
            mode = AiMode(mode_raw)
        except ValueError as exc:
            raise ConfigError(
                f"config.ai.mode must be one of "
                f"{', '.join(m.value for m in AiMode)} (got {mode_raw!r})"
            ) from exc
        max_loop_passes = data.get("max_loop_passes", 32)
        # Same ``_require_positive`` guard the limits section uses. A zero or negative budget
        # would end the run ``CANCELLED`` before its first analysis pass could contribute, so it
        # is a configuration mistake and is rejected at load rather than honoured.
        _require_positive(max_loop_passes, "ai.max_loop_passes")
        # A pass count is a count, not a rate: ``_require_positive`` accepts a float (correctly,
        # for e.g. ``requests_per_second``), and ``int(3.5)`` would silently turn a budget of
        # 3.5 into 3. Rejected rather than truncated -- a budget an operator did not mean is
        # worse than a config error.
        if isinstance(max_loop_passes, bool) or int(max_loop_passes) != max_loop_passes:
            raise ConfigError("config.ai.max_loop_passes must be a whole number")
        return cls(
            mode=mode,
            local_model=str(data.get("local_model") or ""),
            cloud_model=str(data.get("cloud_model") or ""),
            enabled=bool(data.get("enabled", False)),
            max_loop_passes=int(max_loop_passes),
        )


@dataclass(frozen=True)
class LimitsConfig:
    requests_per_second: float = 10.0
    concurrency: int = 5
    # Phase 14: cap on the artifacts ingested from a *single* tool execution, so a
    # hostile or runaway tool cannot turn one task into an unbounded graph write.
    # Ingestion truncates at this bound and records that it did; it never fails the
    # run merely because a tool produced too much (06_TOOL_CONTRACTS.md).
    max_artifacts_per_run: int = 10000

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "LimitsConfig":
        data = data or {}
        rps = data.get("requests_per_second", 10.0)
        concurrency = data.get("concurrency", 5)
        max_artifacts = data.get("max_artifacts_per_run", 10000)
        _require_positive(rps, "limits.requests_per_second")
        _require_positive(concurrency, "limits.concurrency")
        _require_positive(max_artifacts, "limits.max_artifacts_per_run")
        return cls(
            requests_per_second=float(rps),
            concurrency=int(concurrency),
            max_artifacts_per_run=int(max_artifacts),
        )


@dataclass(frozen=True)
class OutputsConfig:
    json: bool = True
    markdown: bool = True
    html: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "OutputsConfig":
        data = data or {}
        return cls(
            json=bool(data.get("json", True)),
            markdown=bool(data.get("markdown", True)),
            html=bool(data.get("html", True)),
        )


@dataclass(frozen=True)
class StorageConfig:
    root: Path = Path("storage")
    raw_dir: Path = Path("storage/raw")
    evidence_dir: Path = Path("storage/evidence")
    reports_dir: Path = Path("storage/reports")

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "StorageConfig":
        data = data or {}
        root = Path(str(data.get("root") or "storage"))
        raw = data.get("raw", "raw")
        evidence = data.get("evidence", "evidence")
        reports = data.get("reports", "reports")
        return cls(
            root=root,
            raw_dir=root / str(raw),
            evidence_dir=root / str(evidence),
            reports_dir=root / str(reports),
        )


@dataclass(frozen=True)
class Config:
    project: ProjectConfig = field(default_factory=ProjectConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    recon: ReconConfig = field(default_factory=ReconConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    web: WebConfig = field(default_factory=WebConfig)
    javascript: JavascriptConfig = field(default_factory=JavascriptConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    ai: AiConfig = field(default_factory=AiConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    outputs: OutputsConfig = field(default_factory=OutputsConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        return cls(
            project=ProjectConfig.from_dict(data.get("project")),
            database=DatabaseConfig.from_dict(data.get("database")),
            scope=ScopeConfig.from_dict(data.get("scope")),
            recon=ReconConfig.from_dict(data.get("recon")),
            network=NetworkConfig.from_dict(data.get("network")),
            web=WebConfig.from_dict(data.get("web")),
            javascript=JavascriptConfig.from_dict(data.get("javascript")),
            api=ApiConfig.from_dict(data.get("api")),
            ai=AiConfig.from_dict(data.get("ai")),
            limits=LimitsConfig.from_dict(data.get("limits")),
            outputs=OutputsConfig.from_dict(data.get("outputs")),
            storage=StorageConfig.from_dict(data.get("storage")),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializable snapshot for persistence (``runs.configuration_snapshot``)."""
        return {
            "project": {"name": self.project.name},
            "database": {"url": self.database.url},
            "scope": {
                "allowed_domains": list(self.scope.allowed_domains),
                "allowed_ips": list(self.scope.allowed_ips),
                "excluded": list(self.scope.excluded),
            },
            "recon": {
                "aggressive_subdomain_discovery": self.recon.aggressive_subdomain_discovery,
            },
            "network": {
                "tcp_ports": {
                    "start": self.network.tcp_ports.start,
                    "end": self.network.tcp_ports.end,
                }
            },
            "web": {
                "http_probe": self.web.http_probe,
                "crawling": self.web.crawling,
                "historical_urls": self.web.historical_urls,
                **self.web._content_discovery_section(),
            },
            "javascript": {
                "deep_analysis": self.javascript.deep_analysis,
                "source_maps": self.javascript.source_maps,
            },
            "api": {
                "rest": self.api.rest,
                "openapi": self.api.openapi,
                "swagger": self.api.swagger,
                "graphql": self.api.graphql,
                "websocket": self.api.websocket,
                "authentication_analysis": self.api.authentication_analysis,
            },
            "ai": {
                "mode": self.ai.mode.value,
                "local_model": self.ai.local_model,
                "cloud_model": self.ai.cloud_model,
                "enabled": self.ai.enabled,
                "max_loop_passes": self.ai.max_loop_passes,
            },
            "limits": {
                "requests_per_second": self.limits.requests_per_second,
                "concurrency": self.limits.concurrency,
                "max_artifacts_per_run": self.limits.max_artifacts_per_run,
            },
            "outputs": {
                "json": self.outputs.json,
                "markdown": self.outputs.markdown,
                "html": self.outputs.html,
            },
            "storage": {
                "root": str(self.storage.root),
                "raw": str(self.storage.raw_dir),
                "evidence": str(self.storage.evidence_dir),
                "reports": str(self.storage.reports_dir),
            },
        }

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        """Load and validate a YAML configuration file."""
        config_path = Path(path)
        try:
            with config_path.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
        except OSError as exc:
            raise ConfigError(f"cannot read config file {config_path}: {exc}") from exc
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {config_path}: {exc}") from exc
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ConfigError(f"config root in {config_path} must be a mapping")
        return cls.from_dict(data)


def run_snapshot_from_dict(data: dict[str, Any] | None) -> dict[str, Any]:
    """Validate execution-relevant configuration into a ``runs.configuration_snapshot``.

    ``05_DATA_MODEL.md`` §runs stores the configuration a run was created with so a
    later process reproduces the same run instead of inventing its own. This builds
    that payload and enforces two properties:

    * **Validated.** Every section goes through the same ``from_dict`` validators the
      YAML loader uses, so an invalid scope entry, port range or limit is rejected at
      intake (fail closed) rather than discovered halfway through a run.
    * **Credential-free.** The ``database`` section is deliberately never included.
      :meth:`Config.to_dict` serializes it because it describes the whole process, but
      a run row is durable, widely readable data, and a DSN routinely embeds a password.
      A credential must never be persisted there.

    The ``scope`` section is **always** present, even when empty. Combined with the
    orchestrator's ``_scope_for`` that makes an unspecified scope deny-all (fail
    closed) rather than silently widening to "unscoped".
    """
    if data is not None and not isinstance(data, dict):
        raise ConfigError("run configuration must be a mapping")

    scope = ScopeConfig.from_dict((data or {}).get("scope"))
    limits = LimitsConfig.from_dict((data or {}).get("limits"))
    network = NetworkConfig.from_dict((data or {}).get("network"))
    recon = ReconConfig.from_dict((data or {}).get("recon"))
    web = WebConfig.from_dict((data or {}).get("web"))
    api = ApiConfig.from_dict((data or {}).get("api"))
    outputs = OutputsConfig.from_dict((data or {}).get("outputs"))

    return {
        "scope": {
            "allowed_domains": list(scope.allowed_domains),
            "allowed_ips": list(scope.allowed_ips),
            "excluded": list(scope.excluded),
        },
        "limits": {
            "requests_per_second": limits.requests_per_second,
            "concurrency": limits.concurrency,
        },
        "network": {
            "tcp_ports": {
                "start": network.tcp_ports.start,
                "end": network.tcp_ports.end,
            }
        },
        "recon": {
            "aggressive_subdomain_discovery": recon.aggressive_subdomain_discovery,
        },
        "web": {
            "http_probe": web.http_probe,
            "crawling": web.crawling,
            "historical_urls": web.historical_urls,
            **web._content_discovery_section(),
        },
        "api": {
            "rest": api.rest,
            "openapi": api.openapi,
            "swagger": api.swagger,
            "graphql": api.graphql,
            "websocket": api.websocket,
            "authentication_analysis": api.authentication_analysis,
        },
        "outputs": {
            "json": outputs.json,
            "markdown": outputs.markdown,
            "html": outputs.html,
        },
    }


def load_config(path: str | Path) -> Config:
    """Backwards-compatible entry point; forwards to :meth:`Config.load`."""
    return Config.load(path)