"""Deterministic technology + WAF/CDN fingerprinting adapter (Phase 21A).

Serves the documented ``tech_detect`` recon stage (``03_RECON_PIPELINE.md``) as a
registration in the served adapter registry. It fingerprints **one already
discovered, in-scope web application** into canonical technology observations
with an **explicit category** from the existing ``technologies.category`` CHECK
set (``framework``/``cms``/``api_technology``/``cdn``/``waf``/``cloud``/``auth``/
``other``).

This is an **in-process** adapter in the same style as
``recon.dns.resolver.DnsResolverAdapter``:

- ``executables = ()`` and ``is_available()`` is always true: no subprocess, no
  shell, no ``shell=True``, no arbitrary commands.
- It performs at most **one bounded HTTP(S)-favouring request** (plain HTTP only:
  TLS/certificate probing is a declared non-goal) to the task's own in-scope
  target, or, when the task carries the documented reuse payload of already
  captured ``WebAppObservation`` signals, fingerprints **from those signals
  without issuing a request** (``06_TOOL_CONTRACTS.md`` §tech_detect "reuse").
  A request follows no redirect, extracts nothing from the page, and never
  recurses: no crawling, no recursive enumeration, no vulnerability scanning.
- Raw output is preserved through the controlled Tool Runner
  (``runner.save_raw`` under ``storage/raw/tech_detect/``), exactly like the
  in-process DNS adapter preserves its serialized resolution result.

Determinism
-----------
The fingerprint is a pure function of a bounded signal snapshot: response
headers (normalized to lowercase keys), the first ``<title>``, and a bounded
body prefix. Same snapshot, same pair set, same order. Timeouts and oversized
responses are recorded non-fatally; a fetch failure produces **no** artifacts
rather than a guess. WAF/CDN technologies are claimed **only** on explicit,
documented signals; weak or generic evidence produces **no** classification.

Adapter contract (``recon/base.py``) is implemented with ``validate`` /
``build_command`` (a diagnostic marker array, never executed) / ``parse``
(capture JSON -> canonical observations) / ``execute``.
"""

from __future__ import annotations

import http.client
import json
import logging
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from core.scope_guard import ScopeGuard
from core.tool_runner import CommandResult, ToolRunner, ToolUnavailableError
from recon.base import ScopeViolation, ToolAdapter, ToolExecution, extract_host
from recon.web.httpx_probe import AssetTechnologyObservation

log = logging.getLogger("argus.recon.tech_detect")

#: The category recorded when no explicit signal justifies another value. Mirrors
#: ``recon.ingest.DEFAULT_TECHNOLOGY_CATEGORY`` / ``recon.web.httpx_probe`` -- a
#: category is never guessed, only observed.
DEFAULT_TECHNOLOGY_CATEGORY = "other"

#: The exact ``technologies.category`` CHECK vocabulary (migration ``0001``).
ALLOWED_CATEGORIES: frozenset[str] = frozenset(
    {
        "framework",
        "cms",
        "api_technology",
        "cdn",
        "waf",
        "cloud",
        "auth",
        "other",
    }
)

#: Fetch budget. Short timeout and a capped body prefix: fingerprinting needs the
#: response metadata, never the whole page.
DEFAULT_TIMEOUT = 5.0
DEFAULT_MAX_BYTES = 65536

_USER_AGENT = "argus-tech-detect/1.0"
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

#: Documented reuse payload keys admitted on ``Task.reason`` (JSON object).
_REUSE_SERVER = "server_header"
_REUSE_TITLE = "title"
_REUSE_CONTENT_TYPE = "content_type"

# -- rule kinds -------------------------------------------------------------

RULE_HEADER_PRESENT = "header_present"
RULE_HEADER_CONTAINS = "header_contains"
RULE_TITLE_CONTAINS = "title_contains"
RULE_BODY_CONTAINS = "body_contains"


@dataclass(frozen=True)
class FingerprintSignals:
    """A bounded, deterministic snapshot a fingerprint is computed from."""

    headers: Mapping[str, str] = field(default_factory=dict)
    title: str = ""
    body: str = ""


@dataclass(frozen=True)
class TechnologyMatch:
    """One determined technology: a name plus an explicit, allowed category."""

    name: str
    category: str
    #: Human-readable provenance for the match (e.g. ``header:server``).
    signal: str = ""


@dataclass(frozen=True)
class FingerprintRule:
    """One deterministic signal rule. Header names/values match case-insensitively."""

    kind: str
    name: str
    category: str
    header: str = ""
    needle: str = ""

    def matches(self, signals: FingerprintSignals) -> bool:
        if self.kind == RULE_HEADER_PRESENT:
            value = signals.headers.get(self.header, "")
            return bool(value and value.strip())
        if self.kind == RULE_HEADER_CONTAINS:
            value = signals.headers.get(self.header, "")
            return bool(value and self.needle.lower() in value.lower())
        if self.kind == RULE_TITLE_CONTAINS:
            return bool(signals.title and self.needle.lower() in signals.title.lower())
        if self.kind == RULE_BODY_CONTAINS:
            return bool(signals.body and self.needle.lower() in signals.body.lower())
        return False


def _rule(kind: str, name: str, category: str, header: str = "", needle: str = "") -> FingerprintRule:
    return FingerprintRule(
        kind=kind, name=name, category=category, header=header, needle=needle
    )


#: The fingerprint table. WAF/CDN entries list **only** explicit, reliable
#: signals; everything else yields no classification. One entry per signal;
#: the first matching entry per technology name wins (deduplicated by name).
FINGERPRINT_RULES: tuple[FingerprintRule, ...] = (
    # -- explicit CDN / WAF signals -----------------------------------------
    _rule(RULE_HEADER_PRESENT, "cloudflare", "cdn", "cf-ray"),
    _rule(RULE_HEADER_PRESENT, "cloudflare", "cdn", "cf-cache-status"),
    _rule(RULE_HEADER_CONTAINS, "cloudflare", "cdn", "server", "cloudflare"),
    _rule(RULE_HEADER_PRESENT, "sucuri", "waf", "x-sucuri-id"),
    _rule(RULE_HEADER_PRESENT, "sucuri", "waf", "x-sucuri-cache"),
    _rule(RULE_HEADER_CONTAINS, "sucuri", "waf", "server", "sucuri"),
    _rule(RULE_HEADER_PRESENT, "akamai", "cdn", "x-akamai-transformed"),
    _rule(RULE_HEADER_CONTAINS, "akamai", "cdn", "server", "akamai"),
    # -- conventional web servers (no category fits; honest "other") --------
    _rule(RULE_HEADER_CONTAINS, "nginx", "other", "server", "nginx"),
    _rule(RULE_HEADER_CONTAINS, "apache", "other", "server", "apache"),
    _rule(RULE_HEADER_CONTAINS, "microsoft-iis", "other", "server", "microsoft-iis"),
    _rule(RULE_HEADER_CONTAINS, "microsoft-iis", "other", "server", "microsoft iis"),
    _rule(RULE_HEADER_CONTAINS, "openresty", "other", "server", "openresty"),
    _rule(RULE_HEADER_CONTAINS, "litespeed", "other", "server", "litespeed"),
    # -- frameworks / runtimes (X-Powered-By) -------------------------------
    _rule(RULE_HEADER_CONTAINS, "express", "framework", "x-powered-by", "express"),
    _rule(RULE_HEADER_CONTAINS, "asp.net", "framework", "x-powered-by", "asp.net"),
    _rule(RULE_HEADER_CONTAINS, "django", "framework", "x-powered-by", "django"),
    _rule(RULE_HEADER_CONTAINS, "php", "other", "x-powered-by", "php"),
    # -- CMS via structural markers (body prefix / generator meta) ----------
    _rule(RULE_BODY_CONTAINS, "wordpress", "cms", "", 'name="generator" content="wordpress'),
    _rule(RULE_BODY_CONTAINS, "wordpress", "cms", "", "/wp-content/"),
    _rule(RULE_BODY_CONTAINS, "joomla", "cms", "", 'name="generator" content="joomla'),
    _rule(RULE_BODY_CONTAINS, "drupal", "cms", "", 'name="generator" content="drupal'),
)


def fingerprint(signals: FingerprintSignals) -> tuple[TechnologyMatch, ...]:
    """Determine technologies from a bounded signal snapshot, deterministically.

    Header names are normalized to lowercase before matching (HTTP semantics);
    header values match case-insensitively per rule. Deduplicated by technology
    name (the ``technologies`` table is unique per name), sorted by
    ``(name, category)``. Rules whose category is not one of
    :data:`ALLOWED_CATEGORIES` are skipped: a misconfigured rule must never
    write a value the schema rejects.
    """
    normalized = FingerprintSignals(
        headers={str(k).lower(): v for k, v in (signals.headers or {}).items()},
        title=signals.title or "",
        body=signals.body or "",
    )
    matches: list[TechnologyMatch] = []
    seen: set[str] = set()
    for rule in FINGERPRINT_RULES:
        if rule.name in seen:
            continue
        if rule.category not in ALLOWED_CATEGORIES:
            log.warning("tech_detect: rule for %r has invalid category %r; skipped", rule.name, rule.category)
            continue
        if rule.matches(normalized):
            seen.add(rule.name)
            signal = rule.header or rule.kind
            matches.append(TechnologyMatch(name=rule.name, category=rule.category, signal=signal))
    return tuple(sorted(matches, key=lambda m: (m.name, m.category)))


def extract_title(body: str) -> str:
    """The first ``<title>`` text from an HTML body, trimmed and bounded."""
    match = _TITLE_RE.search(body or "")
    if match is None:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200]


def extract_port(target: str) -> Optional[int]:
    """The explicit port of a ``host[:port]`` / URL target, or ``None``."""
    text = (target or "").strip()
    if not text:
        return None
    if "://" in text:
        from urllib.parse import urlparse

        return urlparse(text).port
    head, sep, tail = text.rpartition(":")
    if not sep or not tail:
        return None
    raw = tail.split("/", 1)[0]
    if not raw.isdigit():
        return None
    port = int(raw)
    return port if 1 <= port <= 65535 else None


# -- fetch -------------------------------------------------------------------


@dataclass(frozen=True)
class FetchOutcome:
    """Result of the single bounded request, or a recorded failure."""

    host: str
    port: int
    status: int = 0
    headers: Mapping[str, str] = field(default_factory=dict)
    title: str = ""
    body: str = ""
    error: Optional[str] = None
    timed_out: bool = False
    requested: bool = False


FetcherFn = Callable[[str, int, float, int], FetchOutcome]


def default_fetcher(
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> FetchOutcome:
    """One bounded plain-HTTP ``GET /`` to ``host:port`` via the standard library.

    Never follows a redirect, never parses page contents beyond title extraction,
    never recurses. A connect/read/timeout failure returns an outcome with
    ``error`` set and no metadata -- the caller treats it as "nothing observed"
    rather than raising.
    """
    effective_port = port if port else 80
    try:
        conn = http.client.HTTPConnection(host, effective_port, timeout=timeout)
        try:
            conn.request(
                "GET",
                "/",
                headers={
                    "Host": _host_header(host, effective_port),
                    "User-Agent": _USER_AGENT,
                    "Accept": "*/*",
                    "Connection": "close",
                },
            )
            response = conn.getresponse()
            headers: dict[str, str] = {}
            for key, value in response.getheaders():
                headers.setdefault(key.lower(), value)
            raw = response.read(max_bytes)
            body = raw.decode("utf-8", errors="replace")
            return FetchOutcome(
                host=host,
                port=effective_port,
                status=int(response.status or 0),
                headers=headers,
                title=extract_title(body),
                body=body,
                requested=True,
            )
        finally:
            conn.close()
    except (OSError, socket.timeout, http.client.HTTPException, ValueError) as exc:
        timed_out = isinstance(exc, socket.timeout)
        return FetchOutcome(
            host=host,
            port=effective_port,
            error=f"{type(exc).__name__}: {exc}",
            timed_out=timed_out,
            requested=True,
        )


def _host_header(host: str, port: int) -> str:
    return host if port in (80,) else f"{host}:{port}"


# -- adapter -----------------------------------------------------------------


class TechDetectAdapter(ToolAdapter):
    """In-process deterministic technology/WAF/CDN fingerprinting adapter.

    - ``tech_detect`` / ``whatweb`` task types (registered by the served
      composition).
    - Scope: host **and** explicit port are validated against the run's guard
      before anything happens.
    - Reuse: a task whose ``reason`` carries the documented reuse payload
      ``{"server_header": ..., "title": ..., "content_type": ...}`` is
      fingerprinted from those already-captured signals with **no request**.
    - Fetch: otherwise one bounded ``GET /`` to the target.
    """

    name = "tech_detect"
    executables: tuple[str, ...] = ()

    def __init__(
        self,
        *,
        fetcher_fn: Optional[FetcherFn] = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        super().__init__()
        self._fetcher_fn = fetcher_fn or default_fetcher
        self.timeout = float(timeout)
        self.max_bytes = max(1, int(max_bytes))

    # -- availability -------------------------------------------------------

    def is_available(self) -> bool:
        return True  # in-process; stdlib HTTP only

    # -- scope ---------------------------------------------------------------

    def validate(self, task: Any, scope: ScopeGuard) -> None:
        host = extract_host(getattr(task, "target", ""))
        self._require_in_scope(host, scope)
        port = extract_port(getattr(task, "target", ""))
        if port is not None:
            decision = scope.check_port(port)
            if not decision.in_scope:
                raise ScopeViolation(
                    f"tech_detect: port {port} not allowed by scope: {decision.reason}"
                )

    # -- command construction ------------------------------------------------

    def build_command(self, task: Any, config: Any) -> list[str]:
        """Diagnostic marker array; never executed (in-process adapter)."""
        return ["tech-detect", str(getattr(task, "target", ""))]

    # -- reuse ---------------------------------------------------------------

    @staticmethod
    def _signals_from_task(task: Any) -> Optional[FingerprintSignals]:
        """Already-captured ``WebAppObservation`` signals carried on ``reason``."""
        reason = getattr(task, "reason", None)
        if not reason or not isinstance(reason, str):
            return None
        try:
            data = json.loads(reason)
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        headers: dict[str, str] = {}
        server = data.get(_REUSE_SERVER)
        content_type = data.get(_REUSE_CONTENT_TYPE)
        if isinstance(server, str) and server.strip():
            headers["server"] = server.strip()
        if isinstance(content_type, str) and content_type.strip():
            headers["content-type"] = content_type.strip()
        title = str(data.get(_REUSE_TITLE) or "")
        if not headers and not title:
            return None
        return FingerprintSignals(headers=headers, title=title)

    # -- parse ----------------------------------------------------------------

    def parse(self, result: CommandResult) -> list[AssetTechnologyObservation]:
        """Capture JSON -> canonical, host-bearing technology observations.

        A capture is ``{"host": ..., "headers": {...}, "title": ...,
        "body_prefix": ...}``. Empty or malformed captures yield no artifacts
        without raising (``13_TESTING_STRATEGY.md`` §Adapter Fixture Tests).
        """
        try:
            data = json.loads(result.stdout or "null")
        except ValueError:
            log.warning("tech_detect: parse: output is not valid JSON")
            return []
        if not isinstance(data, dict):
            return []
        host = str(data.get("host") or "")
        if not host:
            return []
        headers = data.get("headers") or {}
        if not isinstance(headers, dict):
            headers = {}
        signals = FingerprintSignals(
            headers={str(k).lower(): str(v) for k, v in headers.items()},
            title=str(data.get("title") or ""),
            body=str(data.get("body_prefix") or ""),
        )
        return [
            AssetTechnologyObservation(host=host, technology=m.name, category=m.category)
            for m in fingerprint(signals)
        ]

    # -- execution -----------------------------------------------------------

    def execute(
        self,
        task: Any,
        runner: ToolRunner,
        config: Any,
        scope: ScopeGuard,
    ) -> ToolExecution:
        """Fingerprint ``task.target`` in-process (reuse or one bounded fetch).

        Scope is validated before anything; a fetch failure is recorded non-fatally
        with empty artifacts; raw output is preserved via ``runner.save_raw``.
        """
        if not self.is_available():
            raise ToolUnavailableError("tech_detect: in-process adapter unavailable")
        self.validate(task, scope)
        target = str(getattr(task, "target", "") or "")
        host = extract_host(target)
        if not host:
            raise ValueError(f"tech_detect: task.target must be a host[:port], got {target!r}")
        port = extract_port(target)

        reused = self._signals_from_task(task)
        if reused is not None:
            log.info(
                "tech_detect: reusing captured web-app signals for %s; no request issued",
                host,
            )
            capture: dict[str, Any] = {
                "target": target,
                "host": host,
                "port": port if port is not None else 80,
                "source": "reuse",
                "headers": dict(sorted(reused.headers.items())),
                "title": reused.title,
            }
        else:
            effective_port = port if port is not None else 80
            outcome = self._fetcher_fn(
                host, effective_port, timeout=self.timeout, max_bytes=self.max_bytes
            )
            if outcome.error:
                log.warning(
                    "tech_detect: fetch of %s:%s failed: %s; no technologies reported",
                    host,
                    effective_port,
                    outcome.error,
                )
                return ToolExecution(
                    tool=self.name,
                    command=["tech-detect", target],
                    exit_code=1,
                    raw_output_ref=None,
                    artifacts=(),
                    timed_out=outcome.timed_out,
                    error=outcome.error,
                )
            capture = {
                "target": target,
                "host": host,
                "port": effective_port,
                "status": outcome.status,
                "source": "fetch",
                "headers": dict(sorted((outcome.headers or {}).items())),
                "title": outcome.title,
                "body_prefix": (outcome.body[: self.max_bytes]) if outcome.body else "",
            }

        capture_json = json.dumps(capture, sort_keys=True, indent=2)
        raw_ref = runner.save_raw(
            self.name, capture_json, extension="json", tag="fingerprint"
        )
        artifacts = tuple(
            self.parse(CommandResult(tool=self.name, command=[], stdout=capture_json))
        )
        return ToolExecution(
            tool=self.name,
            command=["tech-detect", target],
            exit_code=0,
            raw_output_ref=raw_ref,
            artifacts=artifacts,
        )