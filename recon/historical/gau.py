"""Deterministic passive historical-URL discovery adapter (Phase 24).

Serves the documented ``historical_recon`` recon stage (``03_RECON_PIPELINE.md`` §13)
as a registration in the served adapter registry. Given one in-scope root domain it
runs GAU **passively**, parses its JSON/plain output, and normalizes the results into
:class:`HistoricalUrlObservation` objects — URLs marked ``historical: true``.

This is a **subprocess** adapter in the same style as ``recon.web.katana``:

- ``executables = ("gau",)`` and ``is_available()`` reports whether the binary is on
  ``PATH``; a missing binary raises ``recon.base.ToolUnavailable`` (never a crash).
- The command is built as an argument array (never a shell string) and executed
  through the controlled ``ToolRunner`` (``subprocess.Popen(..., shell=False)``), which
  enforces the overall timeout, bounds retained output, and preserves raw output under
  ``storage/raw/gau/``.
- **Passive only.** No request is ever issued to a discovered URL, and no downstream
  task probes a passively-discovered host in this phase: a historical discovery
  produces ``urls`` rows and evidence only (no ``http_probe`` expansion).

The exact GAU flag spelling/position and JSON field names vary by GAU version; the
argument array matches the contract (``docs/06_TOOL_CONTRACTS.md`` §GAU) and the
parser accepts JSON lines, a JSON array/document, and plain one-URL-per-line output so
a version difference degrades gracefully rather than failing. Fixtures under
``tests/fixtures/gau/`` define the accepted shapes.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Iterator, Optional
from urllib.parse import urlparse

from core.scope_guard import ScopeGuard
from core.tool_runner import CommandResult, ToolRunner, ToolTimeoutError
from recon.base import ToolAdapter, ToolExecution, ToolUnavailable, extract_host
from recon.historical import SOURCE_GAU, HistoricalUrlObservation

log = logging.getLogger("argus.recon.gau")

#: Overall bound enforced at the ToolRunner for the whole GAU invocation.
DEFAULT_OVERALL_TIMEOUT = 60.0


def _urls_from_payload(payload: Any) -> Iterator[str]:
    """Yield candidate URL strings from one decoded JSON value (any shape)."""
    if isinstance(payload, str):
        yield payload
    elif isinstance(payload, list):
        for item in payload:
            yield from _urls_from_payload(item)
    elif isinstance(payload, dict):
        url = payload.get("url")
        if isinstance(url, str):
            yield url
        for key in ("results", "urls"):
            nested = payload.get(key)
            if isinstance(nested, list):
                yield from _urls_from_payload(nested)


def _iter_url_strings(text: str) -> Iterator[str]:
    """Yield candidate URL strings from GAU output.

    Accepts a whole-document JSON array/object, newline-delimited JSON objects, and
    plain one-URL-per-line text (the parser falls back to line-splitting). Malformed
    JSON lines are treated as plain URLs, so a version that emits bare URLs is still
    parsed.
    """
    whole = (text or "").strip()
    if not whole:
        return
    try:
        payload = json.loads(whole)
    except ValueError:
        payload = None
    if payload is not None:
        yield from _urls_from_payload(payload)
        return
    for raw_line in whole.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            yield line
            continue
        yield from _urls_from_payload(record)


def _observation(url_text: str, source: str) -> Optional[HistoricalUrlObservation]:
    """Normalize one URL string into a :class:`HistoricalUrlObservation` or ``None``.

    Only ``http(s)`` URLs with a host are admitted; the port defaults by scheme and
    the path is query-stripped (``urls.path`` convention). ``url`` is the canonical,
    query-stripped URL.
    """
    try:
        parsed = urlparse((url_text or "").strip())
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    try:
        explicit_port = parsed.port
    except ValueError:
        # An out-of-range or non-numeric port makes the URL unusable; skip it.
        return None
    if explicit_port is None:
        port = 443 if parsed.scheme == "https" else 80
    else:
        port = explicit_port
    path = parsed.path or "/"
    canonical = f"{parsed.scheme}://{host}:{port}{path}"
    return HistoricalUrlObservation(
        host=host, port=port, path=path, url=canonical, source=source
    )


def parse_gau(text: str, source: str = SOURCE_GAU) -> list[HistoricalUrlObservation]:
    """Normalize GAU output into canonical historical-URL observations.

    Empty, malformed, or partial output never raises: unusable lines are skipped and
    logged, valid records are kept, and the result is deduplicated on
    ``(host, port, path, source)`` and returned in a deterministic sort independent of
    provider ordering (``parse`` contract, ``recon/base.py``).
    """
    artworks: dict[tuple, HistoricalUrlObservation] = {}
    for url_text in _iter_url_strings(text):
        observation = _observation(url_text, source)
        if observation is None:
            continue
        artworks.setdefault(observation.key, observation)
    return list(sorted(artworks.values(), key=lambda o: o.key))


def _historical_enabled(config: Any) -> bool:
    """Whether ``web.historical_urls`` is enabled in a typed ``Config`` or snapshot dict.

    Fail-closed: a missing/None config, a missing ``web`` section, or an absent key is
    ``False``, so the adapter refuses rather than running by omission.
    """
    if config is None:
        return False
    web = getattr(config, "web", None) if not isinstance(config, dict) else config.get("web")
    if web is None:
        return False
    if isinstance(web, dict):
        return bool(web.get("historical_urls", False))
    return bool(getattr(web, "historical_urls", False))


class GauAdapter(ToolAdapter):
    """Passive, bounded, in-scope historical-URL discovery adapter for ``historical_recon``.

    - Task types ``historical_recon`` / ``gau`` (registered by the served composition,
      only while ``web.historical_urls`` is enabled).
    - Scope: the root domain is validated before anything runs.
    - Execution: ``gau --json <domain>`` through the controlled ToolRunner with an
      overall timeout.
    - Failure behavior: missing binary -> :class:`ToolUnavailable`; non-zero exit and
      malformed lines are reported, never fatal, and partial results are preserved.
    """

    name = "gau"
    executables: tuple[str, ...] = ("gau",)

    def __init__(self, *, overall_timeout: float = DEFAULT_OVERALL_TIMEOUT) -> None:
        super().__init__()
        self.overall_timeout = max(1.0, float(overall_timeout))

    # -- scope ---------------------------------------------------------------

    def validate(self, task: Any, scope: ScopeGuard) -> None:
        host = extract_host(getattr(task, "target", ""))
        self._require_in_scope(host, scope)

    # -- command construction ------------------------------------------------

    def build_command(self, task: Any, config: Any) -> list[str]:
        # Defense in depth: registration is already gated on the config flag, so this
        # path should never be reached while disabled -- but it refuses if it is.
        if not _historical_enabled(config):
            raise ValueError(
                "gau: web.historical_urls is disabled; refusing historical recon"
            )
        domain = extract_host(getattr(task, "target", ""))
        if not domain:
            raise ValueError("gau: task carries no in-scope domain")
        return ["gau", "--json", domain]

    # -- parse ---------------------------------------------------------------

    def parse(self, result: CommandResult) -> list[Any]:
        return parse_gau(result.stdout)

    # -- execution -----------------------------------------------------------

    def execute(
        self,
        task: Any,
        runner: ToolRunner,
        config: Any,
        scope: ScopeGuard,
    ) -> ToolExecution:
        """Run the bounded GAU discovery and return its normalized observations.

        Contract order: availability, scope, command, controlled subprocess, parse.
        Partial output is parsed and returned even when the run exits non-zero; a
        runner-level timeout is recorded non-fatally.
        """
        if not self.is_available():
            raise ToolUnavailable(
                f"{self.name}: none of {self.executables or ('?',)} found on PATH; "
                "skipping this discovery source"
            )
        self.validate(task, scope)
        command = self.build_command(task, config)
        try:
            result = runner.run_command(
                command, tool=self.name, timeout=self.overall_timeout
            )
        except ToolTimeoutError as exc:
            log.warning(
                "gau: historical recon of %r timed out: %s",
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
