"""Deterministic, approved-wordlist content discovery adapter (Phase 23).

Serves the documented ``content_discover`` recon stage (``03_RECON_PIPELINE.md``)
as a registration in the served adapter registry. Given one already-probed,
in-scope web application URL (the seed), it runs FFUF against ``<seed>/FUZZ``
with an **explicitly approved local wordlist**, parses the JSON it writes, and
normalizes the results into two canonical observation kinds: URLs and HTTP
endpoints, each carrying the FFUF-reported HTTP status code as additive metadata.

This is a **subprocess** adapter in the same style as ``recon.web.katana``:

- ``executables = ("ffuf",)`` and ``is_available()`` reports whether the binary is
  on ``PATH``; a missing binary raises ``recon.base.ToolUnavailable`` (never a
  crash -- the orchestrator logs and continues).
- The command is built as an argument array (never a shell string) and executed
  through the controlled ``ToolRunner`` (``subprocess.run(... shell=False)``),
  which enforces the **overall timeout** and preserves raw output under
  ``storage/raw/ffuf/``. FFUF writes its JSON to the ``-o`` outfile, so the
  adapter reads that file after execution and re-persists it verbatim through
  ``ToolRunner.save_raw`` so ``raw_output_ref`` points at the full recorded JSON.
- Scope is enforced at every layer: the adapter validates the seed host and its
  explicit port against the run's ``ScopeGuard`` before anything runs;
  ``recon.expansion`` re-checked the host before proposing the task; ingestion
  re-checks every discovered host again. FFUF only ever requests the seed host
  (no ``FUZZ`` keyword beyond it), redirects are **not followed** (no ``-r``), and
  no recursion flags are added, so a run cannot silently leave its seed.

Wordlist approval (fail-closed, ``PHASE_23_PROPOSAL.md`` §7/§1b)
----------------------------------------------------------------
The wordlist is never downloaded, generated, or silently defaulted. It must be
explicitly approved in the run's configuration (``web.content_discovery.wordlist``,
``core/config.py::WebConfig``), which validates at intake that the path exists and
is readable. Here the same value is read back from the run's persisted snapshot and
*re-verified* before every invocation: missing, unreadable, or unapproved ->
``build_command`` refuses (no ``-w`` is ever fabricated). Presence or readability
of a file does not by itself approve it -- the operator must set the key.

Budgets, timeouts and rate limits (``PHASE_23_PROPOSAL.md`` §7/§2)
-----------------------------------------------------------------
- Concurrency is bounded with ``-t`` (FFUF's documented threads flag; the
  proposal's ``-c`` spelling is FFUF's *colorize* flag) by the run's
  ``limits.concurrency``, falling back to :data:`DEFAULT_MAX_CONCURRENCY`.
- Request rate is bounded with ``-rate`` by ``limits.requests_per_second`` when
  the configuration names one; the orchestrator's ``RateLimiter`` caps the whole
  invocation either way.
- A per-request timeout flag is passed only when the installed FFUF binary's help
  verifies one exists (``-request-timeout`` / ``-http-timeout`` / ``-timeout``);
  otherwise the ``ToolRunner`` overall timeout is the only per-invocation bound --
  a flag is never fabricated for a version that does not support it.
- Redirects stay disabled (no ``-r``): a 3xx is recorded as the URL/endpoint with
  its status in ``metadata``, never followed.

JSON parsing (``PHASE_23_PROPOSAL.md`` §7/§?? "try NDJSON first")
-----------------------------------------------------------------
FFUF writes a single JSON document with a ``results`` array to ``-o`` and newer
``-json`` modes emit one newline-delimited result per line. Both are accepted and
parsed non-fatally: malformed fragments are skipped and logged, valid records are
kept, and empty/partial output yields what was actually seen. Results are
deduplicated per observation kind by canonical key (first-seen wins, so the status
metadata of the *kept* observation is the first one reported), and returned in a
deterministic sort independent of input order.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from core.scope_guard import ScopeGuard
from core.tool_runner import (
    CommandResult,
    ToolRunner,
    ToolTimeoutError,
    is_executable_on_path,
)
from recon.base import ScopeViolation, ToolAdapter, ToolExecution, ToolUnavailable, extract_host
from recon.web.katana import (
    EndpointObservation,
    UrlObservation,
    _explicit_port,
    _seed_from,
)

log = logging.getLogger("argus.recon.ffuf")

#: Per-request timeout in seconds passed to FFUF when a supported flag exists
#: (``-timeout``): a slow single response must not stall the whole discovery.
DEFAULT_PER_REQUEST_TIMEOUT = 10.0
#: Overall bound enforced at the ToolRunner for the whole FFUF invocation.
DEFAULT_OVERALL_TIMEOUT = 60.0
#: Fallback concurrency bound (``-t``) when the run's configuration names none.
DEFAULT_MAX_CONCURRENCY = 20
#: Where FFUF's ``-o`` outfile lands before it is re-persisted under storage/raw.
DEFAULT_OUTPUT_DIR = Path(tempfile.gettempdir()) / "argus-ffuf"

#: Candidate per-request timeout flags, longest first so ``-http-timeout`` is not
#: mistaken for ``-timeout`` when matching help-text tokens.
_TIMEOUT_FLAGS_IN_PRIORITY = ("-request-timeout", "-http-timeout", "-timeout")


def _record_status(record: dict) -> Optional[int]:
    """The integer HTTP status of an FFUF result, or ``None`` when unset/garbage."""
    status = record.get("status")
    if isinstance(status, bool) or not isinstance(status, (int, float)):
        return None
    return int(status)


def parse_discovery(text: str) -> list[Any]:
    """Normalize FFUF JSON output into canonical URL/endpoint observations.

    Accepts (a) a single JSON document carrying a ``results`` array -- the shape
    FFUF ``-o`` writes, compact or pretty-printed -- or (b) newline-delimited
    records (a full payload or a bare result on each line), the ``-json`` stdout
    shape. Empty, malformed, or partial output never raises: unusable fragments
    are skipped, valid records are kept, and the result is deduplicated per kind
    and returned in a deterministic order (``parse`` contract, ``recon/base.py``).
    """
    artworks: dict[tuple, Any] = {}
    records: list[dict] = []
    whole = (text or "").strip()

    if whole:
        try:
            payload = json.loads(whole)
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            results = payload.get("results")
            if isinstance(results, list):
                records.extend(r for r in results if isinstance(r, dict))
            else:
                records.append(payload)
        if not records:
            for raw_line in whole.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    per_line = json.loads(line)
                except ValueError:
                    log.warning("ffuf: malformed JSON record skipped")
                    continue
                if not isinstance(per_line, dict):
                    log.warning("ffuf: JSON record is not an object; skipped")
                    continue
                results = per_line.get("results")
                if isinstance(results, list):
                    records.extend(r for r in results if isinstance(r, dict))
                else:
                    records.append(per_line)

    for record in records:
        url = record.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        try:
            parsed = urlparse(url.strip())
        except ValueError:
            continue
        if parsed.scheme not in ("http", "https"):
            continue
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        port = parsed.port if parsed.port is not None else (
            443 if parsed.scheme == "https" else 80
        )
        path = parsed.path or "/"
        status = _record_status(record)
        metadata = {"status": status} if status is not None else {}
        artworks.setdefault(
            UrlObservation(host, port, path, metadata=metadata).key,
            UrlObservation(host, port, path, metadata=metadata),
        )
        artworks.setdefault(
            EndpointObservation(host, port, path, "GET", metadata=metadata).key,
            EndpointObservation(host, port, path, "GET", metadata=metadata),
        )

    return list(sorted(artworks.values(), key=lambda o: o.key))


def _positive_int(value: Any, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def _limits_of(config: Any) -> Optional[Any]:
    """The ``limits`` section of a typed ``Config`` or a plain snapshot dict."""
    if config is None:
        return None
    if hasattr(config, "limits"):
        return config.limits
    if isinstance(config, dict) and isinstance(config.get("limits"), dict):
        return config["limits"]
    return None


def _configured_wordlist(config: Any) -> Optional[str]:
    """The approved wordlist from a typed ``Config`` or a plain snapshot dict.

    Returns ``None`` when content discovery is disabled or no wordlist is
    approved -- never a default. Presence of a path does not approve it: it must
    come from ``web.content_discovery.wordlist``.
    """
    if config is None:
        return None
    web = getattr(config, "web", None) if not isinstance(config, dict) else config.get("web")
    if web is None:
        return None
    if isinstance(web, dict):
        cd = web.get("content_discovery")
        if not isinstance(cd, dict):
            return None
        if not cd.get("enabled", True):
            return None
        raw = cd.get("wordlist")
        return raw.strip() if isinstance(raw, str) and raw.strip() else None
    if not web.content_discovery:
        return None
    return (
        str(web.content_discovery_wordlist).strip()
        if web.content_discovery_wordlist
        else None
    )


class FfufAdapter(ToolAdapter):
    """Bounded, approved-wordlist content discovery adapter for ``content_discover``.

    - Task types ``content_discover`` / ``ffuf`` (registered by the served
      composition; the stage and its alias map to the same adapter).
    - Scope: the seed host and its explicit port are validated before anything runs.
    - Seed: the already-observed application URL from ``Task.reason``
      (``{"url": ...}``) or, failing that, ``task.target`` -- never a second request.
    - Wordlist: read from the run's configuration snapshot and re-verified; a run
      with no approved wordlist is refused (fail-closed) and never fuzzes.
    - Execution: ``ffuf -u <seed>/FUZZ -w <approved> -json -o <outfile>`` with
      bounded threads/rate and an overall timeout through the controlled ToolRunner.
    - Failure behavior: missing binary -> :class:`ToolUnavailable`; non-zero exit
      and malformed records are reported, never fatal, and partial results are
      preserved.
    """

    name = "ffuf"
    executables: tuple[str, ...] = ("ffuf",)

    def __init__(
        self,
        *,
        per_request_timeout: float = DEFAULT_PER_REQUEST_TIMEOUT,
        overall_timeout: float = DEFAULT_OVERALL_TIMEOUT,
        max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
        timeout_flag: Optional[str] = None,
        output_dir: Optional[Path] = None,
    ) -> None:
        super().__init__()
        self.per_request_timeout = max(1.0, float(per_request_timeout))
        self.overall_timeout = max(1.0, float(overall_timeout))
        self.max_concurrency = max(1, int(max_concurrency))
        #: An explicitly-injected flag (tests/admins that verified their FFUF build)
        #: bypasses the help-text probe; ``None`` means "probe the binary".
        self.timeout_flag = timeout_flag
        self._probed_timeout_flag: Optional[str] = None
        self.output_dir = output_dir or DEFAULT_OUTPUT_DIR

    # -- scope ---------------------------------------------------------------

    def validate(self, task: Any, scope: ScopeGuard) -> None:
        host = extract_host(getattr(task, "target", ""))
        self._require_in_scope(host, scope)
        port = _explicit_port(str(getattr(task, "target", "") or ""))
        if port is not None:
            decision = scope.check_port(port)
            if not decision.in_scope:
                raise ScopeViolation(
                    f"ffuf: port {port} not allowed by scope: {decision.reason}"
                )

    # -- command construction ------------------------------------------------

    def build_command(self, task: Any, config: Any) -> list[str]:
        seed = _seed_from(task)
        if not seed:
            raise ValueError("ffuf: task carries no application URL to fuzz")
        host = (urlparse(seed).hostname or extract_host(seed) or "").lower()
        if not host:
            raise ValueError(f"ffuf: cannot derive a fuzz host from seed {seed!r}")

        wordlist = _configured_wordlist(config)
        if not wordlist:
            raise ValueError(
                "ffuf: no approved wordlist (config web.content_discovery.wordlist); "
                "refusing to guess paths"
            )
        wordlist_path = Path(wordlist)
        if not wordlist_path.is_file():
            raise ValueError(f"ffuf: approved wordlist is no longer readable: {wordlist}")
        if not os.access(wordlist_path, os.R_OK):
            raise ValueError(f"ffuf: approved wordlist is not readable: {wordlist}")

        base = seed.rstrip("/")
        command = [
            "ffuf",
            "-u", f"{base}/FUZZ",
            "-w", str(wordlist_path),
            "-json",
            "-o", str(self._outfile_for(task)),
            "-t", str(self._concurrency(config)),
        ]
        rate = self._rate(config)
        if rate is not None:
            command += ["-rate", str(rate)]
        timeout_flag = self._timeout_flag()
        if timeout_flag:
            command += [timeout_flag, str(int(self.per_request_timeout))]
        return command

    def _concurrency(self, config: Any) -> int:
        limits = _limits_of(config)
        if limits is None:
            return self.max_concurrency
        value = getattr(limits, "concurrency", None)
        if isinstance(limits, dict):
            value = limits.get("concurrency")
        return _positive_int(value, self.max_concurrency)

    def _rate(self, config: Any) -> Optional[int]:
        limits = _limits_of(config)
        if limits is None:
            return None
        value = getattr(limits, "requests_per_second", None)
        if isinstance(limits, dict):
            value = limits.get("requests_per_second")
        if value in (None, 0):
            return None
        return _positive_int(value, 1)

    def _timeout_flag(self) -> Optional[str]:
        """A per-request timeout flag supported by the installed FFUF, or ``None``.

        When ``timeout_flag`` was explicitly injected, trust it. Otherwise probe
        the binary's own ``-h`` text (local, target-free, shell=False) and only
        pass a flag the binary actually lists -- never an invented one.
        """
        if self.timeout_flag is not None:
            return self.timeout_flag
        if self._probed_timeout_flag is None:
            self._probed_timeout_flag = self._probe_timeout_flag()
        return self._probed_timeout_flag

    def _probe_timeout_flag(self) -> Optional[str]:
        executable = next(
            (name for name in self.executables if is_executable_on_path(name)), None
        )
        if executable is None:
            return None
        try:
            proc = subprocess.run(
                [executable, "-h"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        tokens = ((proc.stdout or "") + (proc.stderr or "")).split()
        for flag in _TIMEOUT_FLAGS_IN_PRIORITY:
            if flag in tokens:
                return flag
        return None

    def _outfile_for(self, task: Any) -> Path:
        identity = _seed_from(task) or str(getattr(task, "target", "") or "")
        digest = hashlib.sha1(identity.encode("utf-8")).hexdigest()[:16]
        directory = self.output_dir / digest
        return directory / f"ffuf-{digest}.json"

    # -- parse ---------------------------------------------------------------

    def parse(self, result: CommandResult) -> list[Any]:
        return parse_discovery(result.stdout)

    # -- execution -----------------------------------------------------------

    def execute(
        self,
        task: Any,
        runner: ToolRunner,
        config: Any,
        scope: ScopeGuard,
    ) -> ToolExecution:
        """Run the bounded FFUF discovery and return its normalized observations.

        Contract order: availability, scope, command, controlled subprocess, parse.
        FFUF writes its JSON to the ``-o`` outfile, so the full document is read
        back and re-persisted through the runner (``storage/raw/ffuf/``), with the
        outfile read falling back to captured stdout for versions/modes that only
        emit NDJSON to the terminal. Partial output is parsed and returned even
        when the run exits non-zero; a runner-level timeout is recorded
        non-fatally with whatever partial document FFUF managed to write.
        """
        if not self.is_available():
            raise ToolUnavailable(
                f"{self.name}: none of {self.executables or ('?',)} found on PATH; "
                "skipping this discovery source"
            )
        self.validate(task, scope)
        command = self.build_command(task, config)
        outfile = self._outfile_for(task)

        try:
            result = runner.run_command(
                command, tool=self.name, timeout=self.overall_timeout
            )
        except ToolTimeoutError as exc:
            log.warning(
                "ffuf: fuzz of %r timed out: %s",
                getattr(task, "target", ""),
                exc,
            )
            content = self._read_outfile(outfile)
            raw_ref = self._persist_outfile(runner, content) if content else None
            execution = ToolExecution(
                tool=self.name,
                command=command,
                exit_code=None,
                raw_output_ref=raw_ref,
                artifacts=tuple(parse_discovery(content)),
                timed_out=True,
                error=str(exc),
            )
            self._cleanup_outfile(outfile)
            return execution

        content = self._read_outfile(outfile) or result.stdout
        raw_ref = self._persist_outfile(runner, content) or result.raw_output_ref
        execution = ToolExecution(
            tool=self.name,
            command=result.command,
            exit_code=result.exit_code,
            raw_output_ref=raw_ref,
            artifacts=tuple(parse_discovery(content)),
            timed_out=result.timed_out,
        )
        self._cleanup_outfile(outfile)
        return execution

    # -- raw preservation ----------------------------------------------------

    def _read_outfile(self, outfile: Path) -> str:
        try:
            return Path(outfile).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _persist_outfile(self, runner: ToolRunner, content: str) -> Optional[str]:
        if not content:
            return None
        return runner.save_raw(self.name, content, extension="json", tag="out")

    def _cleanup_outfile(self, outfile: Path) -> None:
        try:
            Path(outfile).unlink(missing_ok=True)
        except OSError:
            pass