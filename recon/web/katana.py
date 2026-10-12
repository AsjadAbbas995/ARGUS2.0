"""Deterministic in-scope web crawling adapter (Phase 22).

Serves the documented ``web_crawl`` recon stage (``03_RECON_PIPELINE.md`` §11) as a
registration in the served adapter registry. Given one already-probed, in-scope web
application URL (the seed), it runs Katana with **bounded depth and timeouts**, parses
its JSONL output, and normalizes the results into four canonical observation kinds:
URLs, HTTP endpoints, query parameters, and linked JavaScript files.

This is a **subprocess** adapter in the same style as ``recon.web.nmap`` /
``recon.subdomains.subfinder``:

- ``executables = ("katana",)`` and ``is_available()`` reports whether the binary is
  on ``PATH``; a missing binary raises ``recon.base.ToolUnavailable`` (never a crash,
  ``14_FAILURE_HANDLING.md``-style — the orchestrator logs and continues).
- The command is built as an argument array (never a shell string) and executed
  through the controlled ``ToolRunner`` (``subprocess.run(... shell=False)``), which
  enforces the **overall timeout** and preserves raw output under
  ``storage/raw/katana/``. A per-request timeout is passed to Katana itself plus a
  ``-cs`` scope regex pinned to the seed host, so follow-up crawling cannot leave the
  single in-scope application the task was created for.
- JSONL output is parsed **non-fatally**: malformed lines are skipped and logged,
  valid records are kept, and empty/partial output yields what was actually seen
  (``13_TESTING_STRATEGY.md`` §Adapter Fixture Tests).

Recorded JSONL shape (``tests/fixtures/katana/``): one object per line with a nested
``request`` record carrying the HTTP method and the requested URL::

    {"request": {"method": "GET", "endpoint": "http://host:8080/path?q=1"},
     "response": {"status_code": 200}}

Flat ``method`` / ``endpoint`` keys are accepted as fallbacks so a future Katana
output format stays parseable without code changes.

Honest normalization rules
--------------------------
- The URL **path is query-stripped** (``urls.path``), while query parameters become
  ``ParameterObservation`` objects with ``location="query"`` and
  ``significance="unknown"`` — the value required by the ``parameters`` CHECK
  constraint and never a guess (``parameters.location``/``significance``).
- ``endpoints.method`` is taken verbatim from each record and defaults to ``GET``
  only for Katana's own navigations; a method is never fabricated for routes the
  record did not name.
- A path that ends in ``.js`` (and is not a ``.js.map`` source map) also yields a
  ``JavascriptFileObservation`` carrying the full canonical URL.
- Only ``http(s)://`` URLs are admitted; a record with no parseable host is skipped.
- Output is deduplicated per kind and returned in a deterministic sort independent
  of JSONL line order.

Scope is enforced at every layer exactly as documented: the adapter validates the
seed host **and** its explicit port against the run's ``ScopeGuard`` before anything
runs; ``recon.expansion`` re-checked the host before proposing the task; ingestion
re-checks every discovered host again. Katana itself is additionally confined to the
seed host by the ``-cs`` regex, and out-of-scope findings are never graph rows.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional
from urllib.parse import parse_qsl, urlparse

from core.scope_guard import ScopeGuard
from core.tool_runner import CommandResult, ToolRunner, ToolTimeoutError
from recon.base import ScopeViolation, ToolAdapter, ToolExecution, ToolUnavailable, extract_host

log = logging.getLogger("argus.recon.katana")

#: Bounded crawl depth (Katana ``-depth``). Small default: this stage confirms a live
#: web app's structure, it does not mass-enumerate a site (non-goal, ``04_SCOPE_SAFETY``).
DEFAULT_DEPTH = 1
#: Per-request timeout in seconds passed to Katana (``-timeout``): a slow single
#: response must not stall the whole crawl.
DEFAULT_PER_REQUEST_TIMEOUT = 10.0
#: Overall bound enforced at the ToolRunner for the whole Katana invocation.
DEFAULT_OVERALL_TIMEOUT = 60.0

#: Mandatory output format and JavaScript-following flags (06_TOOL_CONTRACTS §Katana).
_MODE_ARGS = ("-jsonl", "-js-crawl")


@dataclass(frozen=True)
class UrlObservation:
    """One normalized crawl URL (path only; query belongs to parameters).

    ``metadata`` carries additive per-observation signal (Phase 23: the FFUF
    result's HTTP status code). It is deliberately excluded from ``key`` so the
    canonical identity of a URL never depends on metadata.
    """

    host: str
    port: int
    path: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple:
        return (0, self.host, self.port, self.path, "")


@dataclass(frozen=True)
class EndpointObservation:
    """One crawled HTTP endpoint (method verbatim from the record).

    ``metadata`` mirrors :attr:`UrlObservation.metadata` (Phase 23: FFUF status).
    """

    host: str
    port: int
    path: str
    method: str = "GET"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple:
        return (1, self.host, self.port, self.path, self.method)


@dataclass(frozen=True)
class ParameterObservation:
    """One query parameter of a crawled endpoint (never a guessed significance).

    ``method`` names the endpoint the parameter was observed on, so a parameter
    keeps exact provenance when the same path is served under several methods.
    """

    host: str
    port: int
    path: str
    name: str
    method: str = "GET"
    location: str = "query"
    significance: str = "unknown"

    @property
    def key(self) -> tuple:
        return (2, self.host, self.port, self.path, self.method, self.name)


@dataclass(frozen=True)
class JavascriptFileObservation:
    """One linked JavaScript file, recorded as its full canonical URL."""

    host: str
    port: int
    url: str

    @property
    def key(self) -> tuple:
        return (3, self.host, self.port, self.url, "")


def _record_url(record: dict) -> Optional[str]:
    """The endpoint URL of a Katana JSONL record (nested or flat shape)."""
    request = record.get("request")
    endpoint = None
    if isinstance(request, dict):
        endpoint = request.get("endpoint")
    if not endpoint:
        endpoint = record.get("endpoint")
    if not isinstance(endpoint, str):
        return None
    text = endpoint.strip()
    return text or None


def _record_method(record: dict) -> str:
    """The HTTP method of a record, verbatim; ``GET`` only as the honest default."""
    request = record.get("request")
    if isinstance(request, dict):
        method = request.get("method")
        if isinstance(method, str) and method.strip():
            return method.strip()
    method = record.get("method")
    if isinstance(method, str) and method.strip():
        return method.strip()
    return "GET"


def parse_jsonl(stdout: str) -> list[Any]:
    """Normalize Katana JSONL output into canonical crawl observations.

    Empty, malformed, or partial output never raises: unusable lines are skipped and
    logged, valid records are kept, and the result is deduplicated per kind and
    returned in a deterministic order (``parse`` contract, ``recon/base.py``).
    """
    artworks: dict[tuple, Any] = {}
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError as exc:
            log.warning("katana: malformed JSONL line skipped: %s", exc)
            continue
        if not isinstance(record, dict):
            log.warning("katana: JSONL record is not an object; skipped")
            continue

        endpoint = _record_url(record)
        if endpoint is None:
            continue
        try:
            parsed = urlparse(endpoint)
        except ValueError:
            continue
        if parsed.scheme not in ("http", "https"):
            continue
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        if parsed.port is None:
            port = 443 if parsed.scheme == "https" else 80
        else:
            port = parsed.port
        path = parsed.path or "/"
        method = _record_method(record)

        artworks.setdefault(
            UrlObservation(host, port, path).key,
            UrlObservation(host, port, path),
        )
        artworks.setdefault(
            EndpointObservation(host, port, path, method).key,
            EndpointObservation(host, port, path, method),
        )
        for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
            if not name:
                continue
            artworks.setdefault(
                ParameterObservation(host, port, path, name, method).key,
                ParameterObservation(host, port, path, name, method),
            )
        if path.endswith(".js") and not path.endswith(".js.map"):
            query = f"?{parsed.query}" if parsed.query else ""
            js_url = f"{parsed.scheme}://{host}:{port}{path}{query}"
            artworks.setdefault(
                JavascriptFileObservation(host, port, js_url).key,
                JavascriptFileObservation(host, port, js_url),
            )

    return list(sorted(artworks.values(), key=lambda o: o.key))


def _seed_from(task: Any) -> str:
    """The application URL to crawl: the reuse payload when present, else the target.

    The expansion layer stores the observed application URL in ``Task.reason`` as
    ``{"url": <url>}``; reading it here means the crawl is seeded with what was
    actually probed and needs no second HTTP request to establish it. Falls back to
    ``task.target`` when no reuse payload is present.
    """
    reason = getattr(task, "reason", None)
    if isinstance(reason, str):
        try:
            data = json.loads(reason)
        except ValueError:
            data = None
        if isinstance(data, dict):
            url = data.get("url")
            if isinstance(url, str) and url.strip():
                return url.strip()
    return str(getattr(task, "target", "") or "")


def _explicit_port(target: str) -> Optional[int]:
    """The explicit port of a URL target, or ``None`` when the URL names none."""
    try:
        return urlparse(target).port
    except ValueError:
        return None


class KatanaAdapter(ToolAdapter):
    """Deterministic, bounded, in-scope web crawling adapter for ``web_crawl``.

    - Task types ``web_crawl`` / ``katana`` (registered by the served composition).
    - Scope: the seed host and its explicit port are validated before anything runs.
    - Seed: the already-observed application URL from ``Task.reason`` (``{"url": ...}``)
      or, failing that, ``task.target`` — never a second request.
    - Execution: ``katana -u <seed> -jsonl -js-crawl -depth <n> -timeout <n>
      -cs <seed-regex>`` through the controlled ToolRunner with an overall timeout.
    - Failure behavior: missing binary -> :class:`ToolUnavailable`; non-zero exit and
      malformed lines are reported, never fatal, and partial results are preserved.
    """

    name = "katana"
    executables: tuple[str, ...] = ("katana",)

    def __init__(
        self,
        *,
        depth: int = DEFAULT_DEPTH,
        per_request_timeout: float = DEFAULT_PER_REQUEST_TIMEOUT,
        overall_timeout: float = DEFAULT_OVERALL_TIMEOUT,
    ) -> None:
        super().__init__()
        self.depth = max(1, int(depth))
        self.per_request_timeout = max(1.0, float(per_request_timeout))
        self.overall_timeout = max(1.0, float(overall_timeout))

    # -- scope ---------------------------------------------------------------

    def validate(self, task: Any, scope: ScopeGuard) -> None:
        host = extract_host(getattr(task, "target", ""))
        self._require_in_scope(host, scope)
        port = _explicit_port(str(getattr(task, "target", "") or ""))
        if port is not None:
            decision = scope.check_port(port)
            if not decision.in_scope:
                raise ScopeViolation(
                    f"katana: port {port} not allowed by scope: {decision.reason}"
                )

    # -- command construction ------------------------------------------------

    def build_command(self, task: Any, config: Any) -> list[str]:
        seed = _seed_from(task)
        if not seed:
            raise ValueError("katana: task carries no application URL to crawl")
        host = (urlparse(seed).hostname or extract_host(seed) or "").lower()
        if not host:
            raise ValueError(f"katana: cannot derive a crawl host from seed {seed!r}")
        return [
            "katana",
            "-u", seed,
            *_MODE_ARGS,
            "-depth", str(self.depth),
            "-timeout", str(int(self.per_request_timeout)),
            # Pin follow-up crawling to the seed host: a newly discovered domain can
            # only ever be re-checked through the Scope Guard, never crawled freely.
            "-cs", re.escape(host),
        ]

    # -- parse ---------------------------------------------------------------

    def parse(self, result: CommandResult) -> list[Any]:
        return parse_jsonl(result.stdout)

    # -- execution -----------------------------------------------------------

    def execute(
        self,
        task: Any,
        runner: ToolRunner,
        config: Any,
        scope: ScopeGuard,
    ) -> ToolExecution:
        """Run the bounded Katana crawl and return its normalized observations.

        Contract order: availability, scope, command, controlled subprocess, parse.
        Partial output is parsed and returned even when the run exits non-zero; a
        runner-level timeout is recorded non-fatally with no artifacts.
        """
        if not self.is_available():
            raise ToolUnavailable(
                f"{self.name}: none of {self.executables or ('?',)} found on PATH; "
                "skipping this discovery source"
            )
        self.validate(task, scope)
        command = self.build_command(task, config)
        try:
            result = runner.run_command(command, tool=self.name, timeout=self.overall_timeout)
        except ToolTimeoutError as exc:
            log.warning(
                "katana: crawl of %r timed out: %s",
                getattr(task, "target", ""),
                exc,
            )
            return ToolExecution(
                tool=self.name,
                command=command,
                exit_code=None,
                raw_output_ref=None,
                artifacts=(),
                timed_out=True,
                error=str(exc),
            )
        artifacts = tuple(self.parse(result))
        return ToolExecution(
            tool=self.name,
            command=result.command,
            exit_code=result.exit_code,
            raw_output_ref=result.raw_output_ref,
            artifacts=artifacts,
            timed_out=result.timed_out,
        )