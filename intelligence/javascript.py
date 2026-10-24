"""Bounded, deterministic, offline JavaScript source parser (Phase 25).

This module is the extraction engine for the documented ``js_analysis`` recon
stage (``03_RECON_PIPELINE.md`` §14). It turns **already-fetched** JavaScript
text into canonical, evidence-only observations. It has **no network side
effects**: it never fetches a URL, never resolves a host, never launches a
subprocess and never executes JavaScript.

Contract
--------
``parse_javascript(text, *, base_url=..., max_bytes=..., max_observations=...)``

* Input is a ``str`` (the body of one JavaScript file). Anything else is treated
  as empty input.
* Output is a :class:`JsParseResult` whose ``observations`` are **exactly** the
  canonical types :class:`~recon.web.katana.UrlObservation`,
  :class:`~recon.web.katana.EndpointObservation` and
  :class:`~recon.web.katana.ParameterObservation` -- the same shapes the crawl
  stage already produces, so ingestion and the graph need no new columns.
* The parser **never** emits ``JavascriptFileObservation``,
  ``WebAppObservation``, a bare ``str`` or any other artifact type that
  ``recon.expansion`` reacts to. This is what makes a completed ``js_analysis``
  task provably non-recursive and non-probing: the expansion loop branches only
  on ``str``/``IpObservation``/``PortObservation``/``WebAppObservation``
  (``recon/expansion.py:189-231``), so a ``Url``/``Endpoint``/``Parameter``
  observation seeds no further task.
* Malformed, empty, unusual or oversized input never raises. Valid candidates
  are kept, unusable ones are skipped and counted, and the result order is
  deterministic (sorted by the observation ``key``).

What is extracted (heuristic, bounded)
--------------------------------------
Only string literals that look like a URL or an absolute path:

* absolute ``http(s)://host[:port]/path?query`` strings *and* protocol-relative
  forms are **not** fetched; the host/port is taken from the literal, except
  that protocol-relative ``//host/...`` literals are skipped because their
  scheme (and therefore default port) is unknowable from the literal alone;
* root-relative ``/path?query`` strings, anchored on ``base_url``'s host/port;
* query parameter **names** parsed from those literals become
  ``ParameterObservation`` objects with ``location="query"`` and
  ``significance="unknown"`` -- a significance is never guessed;
* an ``EndpointObservation`` is emitted **only** when a well-known call site
  names the HTTP method (``axios.<method>(...)``, ``<xhr>.open("METHOD", ...)``,
  ``fetch(..., {method: "METHOD"})``). A method is otherwise never fabricated,
  matching the crawl stage's "a method is never fabricated" rule.

Explicit non-claims
-------------------
This is a **static, best-effort lexical scan**, not a JavaScript interpreter.
It does not evaluate template literals, string concatenation, minified variable
indirection or computed route tables, so its output is a lower bound on the
endpoints a running application might use -- never a claim of completeness. With
no candidates it reports nothing rather than asserting "there are no endpoints".
Every emitted row is an *observation* (OBSERVATION/FACT-shaped), never a
validated finding or a vulnerability. Obfuscated or unsupported source yields no
guessed rows; unusable tokens are only counted in ``skipped``.

Bounded work
------------
``max_bytes`` truncates the input before scanning (and is reported via
``truncated``); ``max_observations`` caps the result set (also reported via
``truncated``). Individual literals longer than ``_MAX_LITERAL_LENGTH`` are
skipped. Method detection reads only a fixed-size window around each literal.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional, Union
from urllib.parse import parse_qsl, urlsplit

from recon.web.katana import (
    EndpointObservation,
    ParameterObservation,
    UrlObservation,
)

log = logging.getLogger("argus.intelligence.javascript")

#: Default input cap (2 MiB) enforced before any scanning.
DEFAULT_MAX_BYTES = 2 * 1024 * 1024
#: Default cap on total emitted observations across all kinds.
DEFAULT_MAX_OBSERVATIONS = 1024
#: Longest string literal considered a URL/path candidate.
_MAX_LITERAL_LENGTH = 2048
#: Size of the context window (bytes of source) searched for a method call.
_CONTEXT_WINDOW = 64

#: The only three artifact kinds this parser is permitted to emit.
JsObservation = Union[UrlObservation, EndpointObservation, ParameterObservation]

#: Matches a single- or double-quoted or backtick string literal, honoring
#: backslash escapes so a quoted quote does not end the literal early.
_STRING_RE = re.compile(r"""(['"`])((?:\\.|(?!\1)[^\\])*)\1""")

#: ``axios.post(`` / ``http.get(`` / ``client.delete(`` style call sites.
_AXIOS_RE = re.compile(
    r"""\b[A-Za-z_$][\w$]*\.(get|post|put|patch|delete|head|options)\s*\(\s*$""",
    re.IGNORECASE,
)
#: ``<xhr>.open("POST",`` style call sites.
_OPEN_RE = re.compile(
    r"""\.open\s*\(\s*(['"])(get|post|put|patch|delete|head|options)\1\s*,\s*$""",
    re.IGNORECASE,
)
#: The options object that follows a URL in ``fetch(url, {method: "POST"})``.
_FETCH_METHOD_RE = re.compile(
    r"""^\s*,\s*\{[^}]*\bmethod\s*:\s*(['"])(get|post|put|patch|delete|head|options)\1""",
    re.IGNORECASE,
)

_ESCAPES = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "b": "\b",
    "f": "\f",
    "/": "/",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "`": "`",
}


@dataclass(frozen=True)
class JsParseResult:
    """Deterministic outcome of parsing one JavaScript source string.

    ``observations`` are canonical URL/endpoint/parameter observations, sorted by
    ``key``. ``truncated`` is true when the input exceeded ``max_bytes`` or the
    result set hit ``max_observations``. ``candidates_seen`` counts literals that
    parsed as URL/path candidates; ``skipped`` counts literals that did not.
    """

    observations: tuple[JsObservation, ...] = ()
    truncated: bool = False
    source_bytes: int = 0
    candidates_seen: int = 0
    skipped: int = 0


def parse_javascript(
    text: object,
    *,
    base_url: Optional[str] = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_observations: int = DEFAULT_MAX_OBSERVATIONS,
) -> JsParseResult:
    """Extract URL/endpoint/parameter observations from JavaScript source.

    Pure and total: the same ``(text, base_url, max_bytes, max_observations)``
    always yields the same result, and no input raises. ``base_url`` anchors
    root-relative paths to a host/port; when it is absent or unusable, relative
    candidates are skipped (there is no host to attribute them to).
    """
    raw = text if isinstance(text, str) else ""
    source_bytes = len(raw)

    truncated = False
    limit = int(max_bytes) if isinstance(max_bytes, int) else DEFAULT_MAX_BYTES
    if limit > 0 and source_bytes > limit:
        raw = raw[:limit]
        truncated = True

    cap = int(max_observations) if isinstance(max_observations, int) else DEFAULT_MAX_OBSERVATIONS
    base_host, base_port = _base_host_port(base_url)

    observations: dict[tuple, JsObservation] = {}
    candidates = 0
    skipped = 0

    if cap <= 0:
        return JsParseResult(
            observations=(),
            truncated=bool(raw),
            source_bytes=source_bytes,
            candidates_seen=0,
            skipped=0,
        )

    for match in _STRING_RE.finditer(raw):
        literal = _unescape(match.group(2)).strip()
        if not literal or len(literal) > _MAX_LITERAL_LENGTH or _has_whitespace(literal):
            if literal:
                skipped += 1
            continue
        candidate = _candidate(literal, base_host, base_port)
        if candidate is None:
            skipped += 1
            continue

        candidates += 1
        host, port, path, query = candidate
        method = _method_for(raw, match.start(), match.end())

        url_key = ("url", host, port, path)
        observations.setdefault(url_key, UrlObservation(host=host, port=port, path=path))

        if method is not None:
            endpoint_key = ("endpoint", host, port, path, method)
            observations.setdefault(
                endpoint_key,
                EndpointObservation(host=host, port=port, path=path, method=method),
            )

        for name, _value in parse_qsl(query, keep_blank_values=True):
            if not name:
                continue
            param_key = ("param", host, port, path, method or "GET", name)
            observations.setdefault(
                param_key,
                ParameterObservation(
                    host=host,
                    port=port,
                    path=path,
                    name=name,
                    method=method or "GET",
                    location="query",
                    significance="unknown",
                ),
            )

        if len(observations) >= cap:
            truncated = True
            break

    ordered = tuple(sorted(observations.values(), key=_observation_key))[:cap]
    if skipped:
        log.debug(
            "js parse: %d candidate(s), %d literal(s) skipped, %d observation(s)",
            candidates,
            skipped,
            len(ordered),
        )
    return JsParseResult(
        observations=ordered,
        truncated=truncated,
        source_bytes=source_bytes,
        candidates_seen=candidates,
        skipped=skipped,
    )


def _observation_key(observation: JsObservation) -> tuple:
    return observation.key


def _has_whitespace(value: str) -> bool:
    return any(ch.isspace() for ch in value)


def _unescape(value: str) -> str:
    """Decode the common backslash escapes found in JS string literals."""
    if "\\" not in value:
        return value
    out: list[str] = []
    i = 0
    length = len(value)
    while i < length:
        ch = value[i]
        if ch == "\\" and i + 1 < length:
            out.append(_ESCAPES.get(value[i + 1], value[i + 1]))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _base_host_port(base_url: Optional[str]) -> tuple[Optional[str], int]:
    """Split an anchoring base URL into ``(host, port)`` or ``(None, 0)``."""
    if not base_url or not isinstance(base_url, str):
        return None, 0
    parts = urlsplit(base_url.strip())
    if parts.scheme not in ("http", "https"):
        return None, 0
    host = parts.hostname
    if not host:
        return None, 0
    if parts.port is not None:
        port = parts.port
    else:
        port = 443 if parts.scheme == "https" else 80
    return host.lower().rstrip("."), port


def _candidate(
    literal: str, base_host: Optional[str], base_port: int
) -> Optional[tuple[str, int, str, str]]:
    """Classify one literal into ``(host, port, path, query)`` or ``None``."""
    if any(ord(ch) < 32 for ch in literal):
        return None

    if literal.startswith("//"):
        # Protocol-relative: the scheme (hence the default port) is unknowable
        # from the literal alone, so it is not attributed to a guess.
        return None

    if literal.startswith("http://") or literal.startswith("https://"):
        parts = urlsplit(literal)
        host = parts.hostname
        if not host:
            return None
        try:
            port = parts.port
        except ValueError:
            return None
        if port is None:
            port = 443 if parts.scheme == "https" else 80
        path = parts.path or "/"
    elif literal.startswith("/"):
        if base_host is None:
            return None
        parts = urlsplit(literal)
        host = base_host
        port = base_port
        path = parts.path or "/"
    else:
        return None

    if not path.startswith("/"):
        return None
    query = parts.query
    if path == "/" and not query:
        return None
    return host.lower().rstrip("."), port, path, query


def _method_for(raw: str, start: int, end: int) -> Optional[str]:
    """Best-effort HTTP method named at the literal's call site, else ``None``."""
    before = raw[max(0, start - _CONTEXT_WINDOW):start]
    after = raw[end:end + _CONTEXT_WINDOW]

    match = _OPEN_RE.search(before)
    if match is not None:
        return match.group(2).upper()
    match = _AXIOS_RE.search(before)
    if match is not None:
        return match.group(1).upper()
    match = _FETCH_METHOD_RE.match(after)
    if match is not None:
        return match.group(2).upper()
    return None


__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_OBSERVATIONS",
    "JsObservation",
    "JsParseResult",
    "parse_javascript",
]
