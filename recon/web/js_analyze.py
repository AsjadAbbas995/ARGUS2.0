"""Bounded in-process JavaScript fetcher (Phase 25 foundation).

This module supplies the *content fetcher* required by the ``js_analysis`` stage
(``docs/PHASE_25_PROPOSAL.md`` §4.1): the crawl stage persists JavaScript **URLs**
only (never bodies -- ``recon/ingest.py:473-481``), so the analyzer needs a way
to retrieve one already-discovered, in-scope script over HTTP(S) before parsing
it with :mod:`intelligence.javascript`.

Scope of this module
--------------------
It contains:

* :func:`fetch_javascript` -- one bounded, scope-checked, SSRF-safe ``GET`` of a
  single JavaScript URL;
* :class:`JsFetchResult` -- the fetch outcome (body or a recorded, non-fatal
  failure);
* :class:`JsFetchBudget` -- the shared, run-scoped total-byte budget;
* :class:`JsAnalyzeAdapter` -- the in-process ``js_analysis`` adapter
  (``06_TOOL_CONTRACTS.md`` in-process pattern) that fetches one JS URL, parses
  it with :mod:`intelligence.javascript`, and emits only URL/endpoint/parameter
  observations. It is registered by ``api.serve._default_adapters`` **only** when
  ``config.javascript.enabled`` is set, and is never instantiated otherwise.

Safety model (``docs/PHASE_25_PROPOSAL.md`` §4.1)
-------------------------------------------------
* **Standard library only** -- ``http.client``, ``ssl``, ``socket``,
  ``ipaddress``, ``zlib``; no new dependency, following the ``tech_detect``
  in-process precedent.
* **Target-host authorization** (ARGUS boundary) is separate from **SSRF
  destination filtering**: the host must pass :meth:`ScopeGuard.check` /
  :meth:`ScopeGuard.check_host` and the port must pass
  :meth:`ScopeGuard.check_port`; the resolved addresses are then filtered by a
  fail-closed *global-routability* allowlist (``ipaddress.is_global``, after
  unwrapping IPv4-mapped/6to4/NAT64 forms). ``ScopeGuard.check_ip`` is
  intentionally **not** required of every resolved address -- it only allow-lists
  operator-enumerated IPs and would wrongly deny an in-scope hostname whose
  address is not itself IP-listed (existing adapters authorize by host only).
* **Fail closed:** a DNS error, an empty answer set, a prohibited address, or a
  mixed prohibited/allowed answer set fails the **whole** fetch -- addresses are
  never silently filtered to pick another.
* **No second DNS lookup:** the hostname is resolved exactly once and the TCP
  connection is opened directly to a validated IP; the TLS layer is driven with
  the *original* hostname as ``server_hostname`` so SNI and certificate hostname
  verification still apply. The HTTP ``Host`` header is never a substitute for
  TLS verification, which is always enabled via ``ssl.create_default_context()``.
* **No redirects, no retries:** any 3xx is a recorded skip; a failed or
  timed-out request is never retried.
* **Bounded resources:** connect/read timeout, a per-response byte cap, bounded
  gzip/deflate decompression and a shared per-run total-byte budget. TLS
  failures, invalid destinations and resource-limit failures produce **no**
  observations (empty body), never a partial or guessed result.

Determinism is by construction: ``recon.web.js_analyze`` is a pure function of
its injected ``resolver``/``connection_factory`` and the URL.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import re
import socket
import ssl
import zlib
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Optional, Union
from urllib.parse import urlsplit

from core.scope_guard import ScopeGuard
from core.tool_runner import CommandResult, ToolRunner
from intelligence.javascript import JsObservation, parse_javascript
from recon.base import (
    ScopeViolation,
    ToolAdapter,
    ToolExecution,
    ToolUnavailable,
    extract_host,
)

#: A parsed IP address (v4 or v6).
IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

log = logging.getLogger("argus.recon.js_analyze")

#: Connect/read timeout for the single request.
DEFAULT_TIMEOUT = 10.0
#: Hard cap on the (compressed) response body read from the socket, per response.
DEFAULT_MAX_BYTES = 1_048_576  # 1 MiB
#: Shared budget across every ``js_analysis`` task of one run.
DEFAULT_TOTAL_BYTES_PER_RUN = 16 * 1024 * 1024  # 16 MiB
#: Upper bound on the number of run budgets retained in one process (see
#: :class:`JsFetchBudget`), so repeated runs cannot grow memory without bound.
DEFAULT_MAX_RUNS_TRACKED = 1024

_USER_AGENT = "argus-js-analysis/1.0"
_SUPPORTED_SCHEMES = ("http", "https")
#: Accepted JavaScript-content subtypes (JSON is admitted for ``.js.map`` maps).
_JS_CONTENT_SUBTYPES = ("javascript", "ecmascript", "x-javascript", "json")

#: ``(host) -> A/AAAA address strings``. Injected so tests stay offline.
ResolverFn = Callable[[str], tuple[str, ...]]
#: ``(scheme, host, port, validated_ip, timeout, context) -> connection``.
ConnectionFactory = Callable[
    [str, str, int, str, float, Optional[ssl.SSLContext]],
    "http.client.HTTPConnection",
]


@dataclass(frozen=True)
class JsFetchResult:
    """Outcome of one bounded JavaScript fetch, or a recorded, non-fatal failure.

    A successful fetch has ``body`` set and ``error``/``skipped_reason`` ``None``.
    Every other outcome carries an empty ``body`` so the caller observes nothing
    (``error`` is a hard failure such as DNS refusal or a TLS error;
    ``skipped_reason`` is a policy skip such as a redirect or a non-success
    status). ``requested`` distinguishes "no request was made" (budget
    exhausted) from "a request was made and produced nothing".
    """

    url: str
    host: str = ""
    port: int = 0
    status: int = 0
    content_type: str = ""
    body: str = ""
    bytes_read: int = 0
    requested: bool = False
    error: Optional[str] = None
    skipped_reason: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.skipped_reason is None


class JsFetchBudget:
    """Shared, run-scoped total-byte budget for JavaScript fetches.

    Each run gets ``total_bytes_per_run`` bytes. Entries are created lazily on
    first use and keyed by ``run_id``, so one budget object can be shared across
    every adapter instance of a process without cross-run leakage.

    The served composition creates one budget per process and captures it in
    every ``js_analysis`` adapter (``api.serve._default_adapters``), keyed by
    ``run_id``. The orchestrator exposes no run-completion hook, so production
    does **not** call :meth:`release`; memory stays bounded by the LRU alone
    (oldest entries beyond ``max_runs`` are evicted deterministically) rather
    than by adding run-lifecycle plumbing that would have to be threaded from
    the orchestrator back into the adapter closure. :meth:`release` remains the
    explicit cleanup primitive for a caller that owns a run's whole lifecycle
    (and for tests). Execution is single-threaded per run
    (``core/orchestrator.py:549``), so no lock is required.
    """

    def __init__(
        self,
        total_bytes_per_run: int = DEFAULT_TOTAL_BYTES_PER_RUN,
        *,
        max_runs: int = DEFAULT_MAX_RUNS_TRACKED,
    ) -> None:
        self._total = max(0, int(total_bytes_per_run))
        self._max_runs = max(1, int(max_runs))
        self._remaining: "OrderedDict[str, int]" = OrderedDict()

    @property
    def total_bytes_per_run(self) -> int:
        return self._total

    def remaining(self, run_id: object) -> int:
        """Remaining bytes for ``run_id`` (creating the entry at full budget)."""
        key = str(run_id)
        if key not in self._remaining:
            self._remaining[key] = self._total
        else:
            self._remaining.move_to_end(key)
        self._evict()
        return self._remaining[key]

    def consume(self, run_id: object, n: int) -> int:
        """Subtract ``n`` bytes from ``run_id``'s budget; return what remains."""
        key = str(run_id)
        current = self._remaining.get(key, self._total)
        updated = max(0, current - max(0, int(n)))
        self._remaining[key] = updated
        self._remaining.move_to_end(key)
        self._evict()
        return updated

    def release(self, run_id: object) -> None:
        """Drop a finished run's entry (call when the run completes)."""
        self._remaining.pop(str(run_id), None)

    def tracked_runs(self) -> int:
        return len(self._remaining)

    def _evict(self) -> None:
        while len(self._remaining) > self._max_runs:
            self._remaining.popitem(last=False)


def fetch_javascript(
    url: str,
    *,
    scope: ScopeGuard,
    run_id: object,
    budget: JsFetchBudget,
    resolver: Optional[ResolverFn] = None,
    connection_factory: Optional[ConnectionFactory] = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> JsFetchResult:
    """Fetch one JavaScript URL under scope, SSRF and resource policy.

    Resolves the host once, validates every A/AAAA answer, connects to a
    validated IP (no second DNS lookup), preserves TLS SNI + certificate
    hostname verification, refuses redirects, disables retries and enforces the
    shared per-run byte budget. Any failure yields a :class:`JsFetchResult` with
    an empty ``body`` and a recorded reason; the function never raises for a
    target/DNS/network/policy condition.
    """
    resolver = resolver or _system_resolver
    connection_factory = connection_factory or _default_connection_factory

    target = _validate_url(url)
    if target.error is not None:
        return JsFetchResult(url=url, error=target.error)

    decision = scope.check(url)
    if not decision.in_scope:
        return JsFetchResult(url=url, error=f"out of scope: {decision.reason}")

    port_decision = scope.check_port(target.port)
    if not port_decision.in_scope:
        return JsFetchResult(
            url=url,
            host=target.host,
            port=target.port,
            error=f"port {target.port} not allowed: {port_decision.reason}",
        )

    remaining = budget.remaining(run_id)
    if remaining <= 0:
        return JsFetchResult(url=url, host=target.host, port=target.port,
                             requested=False, skipped_reason="budget exhausted")
    read_cap = min(int(remaining), max(1, int(max_bytes)))

    try:
        answers = tuple(resolver(target.host))
    except Exception as exc:  # noqa: BLE001 - a resolver fault is a failed fetch
        return JsFetchResult(url=url, host=target.host, port=target.port,
                             error=f"dns error: {_bounded_error(exc)}")
    if not answers:
        return JsFetchResult(url=url, host=target.host, port=target.port,
                             error="dns: no answers")

    validated: list[ipaddress._BaseAddress] = []
    for answer in answers:
        address = _normalize_ip(answer)
        if address is None:
            return JsFetchResult(url=url, host=target.host, port=target.port,
                                 error=f"unparseable address {_sanitize_error_text(answer)!r}")
        if _is_prohibited(address):
            return JsFetchResult(url=url, host=target.host, port=target.port,
                                 error=f"prohibited address {address}")
        validated.append(address)
    connect_ip = str(validated[0])

    context = ssl.create_default_context() if target.scheme == "https" else None
    conn = None
    try:
        conn = connection_factory(
            target.scheme, target.host, target.port, connect_ip, timeout, context
        )
        conn.request(
            "GET",
            target.path_query,
            headers={
                "Host": target.host_header,
                "User-Agent": _USER_AGENT,
                "Accept": "*/*",
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        status = int(getattr(response, "status", 0) or 0)
        content_type = str(response.getheader("Content-Type", "") or "") \
            if hasattr(response, "getheader") else ""
        encoding = str(response.getheader("Content-Encoding", "") or "") \
            if hasattr(response, "getheader") else ""

        if 300 <= status < 400:
            return JsFetchResult(url=url, host=target.host, port=target.port,
                                 status=status, content_type=content_type,
                                 requested=True, skipped_reason="redirect refused")
        if not (200 <= status < 300):
            return JsFetchResult(url=url, host=target.host, port=target.port,
                                 status=status, content_type=content_type,
                                 requested=True,
                                 skipped_reason=f"non-success status {status}")
        if not _content_type_ok(content_type, target.path):
            return JsFetchResult(url=url, host=target.host, port=target.port,
                                 status=status, content_type=content_type,
                                 requested=True, skipped_reason="content-type rejected")

        raw = response.read(read_cap)
        raw = raw if isinstance(raw, bytes) else bytes(raw or b"")

        # Accounting model (M-2): the shared per-run budget is charged the
        # *decompressed* size the fetcher would hand to the parser, never the
        # compressed socket bytes on their own. For an identity body the two are
        # equal, so ordinary responses are charged exactly once; for a compressing
        # target the charge is the expanded work, so a small payload cannot amplify
        # into parsing effort beyond the run budget. ``read_cap`` and the
        # decompression ``limit`` are both ``min(remaining, max_bytes)``, so the
        # charged amount can never exceed what remains and the budget never goes
        # negative. An overflowing response still charges its (bounded) expansion
        # before failing closed, so repeated oversized payloads cannot avoid
        # depletion.
        body_bytes, overflow = _bounded_decompress(raw, encoding, read_cap)
        budget.consume(run_id, len(body_bytes))
        if overflow:
            return JsFetchResult(url=url, host=target.host, port=target.port,
                                 status=status, content_type=content_type,
                                 bytes_read=len(raw), requested=True,
                                 skipped_reason="decompression overflow")
        return JsFetchResult(
            url=url,
            host=target.host,
            port=target.port,
            status=status,
            content_type=content_type,
            body=body_bytes.decode("utf-8", errors="replace"),
            bytes_read=len(raw),
            requested=True,
        )
    except (OSError, socket.timeout, ssl.SSLError, http.client.HTTPException,
            ValueError) as exc:
        return JsFetchResult(url=url, host=target.host, port=target.port,
                             requested=True, error=_bounded_error(exc))
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - close must never mask the outcome
                pass


# -- URL validation ----------------------------------------------------------


@dataclass(frozen=True)
class _ValidatedUrl:
    error: Optional[str] = None
    scheme: str = ""
    host: str = ""
    port: int = 0
    path: str = "/"
    path_query: str = "/"
    host_header: str = ""


def _validate_url(url: str) -> _ValidatedUrl:
    """Validate scheme, credentials, host and port; never guesses."""
    text = (url or "").strip()
    if not text or any(ord(ch) < 32 for ch in text):
        return _ValidatedUrl(error="invalid target")
    parts = urlsplit(text)
    if parts.scheme not in _SUPPORTED_SCHEMES:
        return _ValidatedUrl(error=f"unsupported scheme {parts.scheme!r}")
    if parts.username or parts.password:
        return _ValidatedUrl(error="URL userinfo/credentials are not allowed")
    host = parts.hostname
    if not host:
        return _ValidatedUrl(error="missing host")
    host = host.lower().rstrip(".")
    try:
        port = parts.port
    except ValueError:
        return _ValidatedUrl(error="invalid port")
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    if not (1 <= port <= 65535):
        return _ValidatedUrl(error=f"invalid port {port}")
    path = parts.path or "/"
    if not path.startswith("/") or any(ord(ch) < 32 for ch in path):
        return _ValidatedUrl(error="invalid path")
    path_query = f"{path}?{parts.query}" if parts.query else path
    return _ValidatedUrl(
        scheme=parts.scheme,
        host=host,
        port=port,
        path=path,
        path_query=path_query,
        host_header=_host_header(host, port, parts.scheme),
    )


def _host_header(host: str, port: int, scheme: str) -> str:
    literal = f"[{host}]" if ":" in host else host
    default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    return literal if default else f"{literal}:{port}"


# -- error and log redaction -------------------------------------------------

#: Hard cap on any exception text surfaced in a result or a log line.
MAX_ERROR_CHARS = 200

#: ``key=value`` pairs whose value is redacted before text is surfaced.
_SECRET_KEY_RE = re.compile(
    r"(?i)\b(?:pass(?:word|wd)?|pwd|token|secret|api[_-]?key|access[_-]?key|"
    r"auth|session|signature|sig)=[^\s&;,'\"]*"
)
#: Any embedded URL, reduced to its origin (userinfo/query/fragment dropped).
_URL_RE = re.compile(r"(?i)\b(https?://)(?:[^/@\s]+@)?([^/?#\s]+)[^\s]*")


def _redact_url(url: str) -> str:
    """Origin + path of ``url``; userinfo, query and fragment are removed.

    Logs use this so a diagnostic line never carries a token or credential that
    a query string, fragment or userinfo may hold.
    """
    try:
        parts = urlsplit(str(url or ""))
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return "<url>"
    if not parts.scheme and not host:
        return parts.path or "<url>"
    if ":" in host:
        host = f"[{host}]"
    authority = f"{host}:{port}" if port is not None else host
    return f"{parts.scheme}://{authority}{parts.path or '/'}"


def _sanitize_error_text(text: object, *, limit: int = MAX_ERROR_CHARS) -> str:
    """Bound and sanitize exception text before it reaches a result or a log.

    Control characters are replaced, embedded URLs are reduced to their origin,
    credential/token ``key=value`` pairs are redacted, whitespace is collapsed,
    and the result is truncated to ``limit`` characters, so a long or
    secret-bearing remote-controlled message can neither leak nor flood.
    """
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", str(text or ""))
    cleaned = _URL_RE.sub(r"\1\2", cleaned)
    cleaned = _SECRET_KEY_RE.sub(
        lambda match: match.group(0).split("=", 1)[0] + "=[redacted]", cleaned
    )
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > limit:
        cleaned = cleaned[:limit].rstrip() + "..."
    return cleaned


def _bounded_error(exc: BaseException) -> str:
    """``ClassName: sanitized-message`` for a caught exception (bounded)."""
    detail = _sanitize_error_text(exc)
    return f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__


# -- SSRF destination filtering ----------------------------------------------


def _normalize_ip(value: object) -> Optional[ipaddress._BaseAddress]:
    """Parse an address, normalizing decimal-integer alternate forms."""
    text = str(value).strip()
    if not text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        pass
    if text.isdigit():
        try:
            return ipaddress.ip_address(int(text))
        except ValueError:
            return None
    return None


#: IPv6 prefixes that tunnel an IPv4 destination (6to4 and NAT64). ``is_global``
#: reports the encapsulated (outer) address as global, so these must be rejected
#: outright rather than trusted on their outer form. IPv4-mapped IPv6
#: (``::ffff:0:0/96``) is instead unwrapped to its IPv4 address and judged there.
_EMBEDDED_IPV4_NETWORKS = (
    ipaddress.ip_network("2002::/16"),       # 6to4 (RFC 3056)
    ipaddress.ip_network("64:ff9b::/96"),    # NAT64 well-known (RFC 6052)
    ipaddress.ip_network("64:ff9b:1::/48"),  # NAT64 local-use (RFC 8215)
)

#: Ranges CPython's ``is_global`` table reports as globally routable but that
#: ARGUS refuses on policy: IPv6 documentation (RFC 9637), SRv6 SIDs
#: (RFC 9602), historic 6bone (RFC 2471, deprecated) and the 6to4 relay anycast
#: block (RFC 7526, deprecated). Enumerated explicitly so a lagging ``is_global``
#: table can never weaken fail-closed destination filtering.
_PROHIBITED_NETWORKS = (
    ipaddress.ip_network("3fff::/20"),       # IPv6 documentation (RFC 9637)
    ipaddress.ip_network("5f00::/16"),       # SRv6 SIDs (RFC 9602)
    ipaddress.ip_network("3ffe::/16"),       # 6bone (RFC 2471, deprecated)
    ipaddress.ip_network("192.88.99.0/24"),  # 6to4 relay anycast (RFC 7526)
)


def _is_prohibited(address: ipaddress._BaseAddress) -> bool:
    """True unless ``address`` is a globally-routable destination.

    Fail-closed allowlist. An IPv4-mapped IPv6 address is unwrapped to its IPv4
    form and judged there; 6to4/NAT64 addresses (whose outer form is reported
    global) and an explicit deny of stale special-use ranges
    (:data:`_PROHIBITED_NETWORKS`) are rejected outright; every other address is
    permitted only when ``ipaddress`` reports it ``is_global``. Multicast is
    rejected explicitly because CPython's ``is_global`` reports ``224.0.0.0/4``
    and ``ff00::/8`` as global. This covers the special-use ranges a flag
    denylist missed -- most importantly CGNAT ``100.64.0.0/10`` (``is_private``
    is ``False``) and 6to4 ``2002::/16`` -- without enumerating them.
    """
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            address = mapped
        elif any(address in network for network in _EMBEDDED_IPV4_NETWORKS):
            return True
    if any(address in network for network in _PROHIBITED_NETWORKS):
        return True
    return address.is_multicast or not address.is_global


# -- resolution / connection -------------------------------------------------


def _system_resolver(host: str) -> tuple[str, ...]:
    """Resolve all A/AAAA answers once via the system resolver, deduplicated."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for info in infos:
        family = info[0]
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        sockaddr = info[4]
        address = sockaddr[0]
        if address not in seen:
            seen.append(address)
    return tuple(seen)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection whose TCP peer is a pre-validated IP (no new lookup)."""

    def __init__(self, host: str, port: int, *, validated_ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._validated_ip = validated_ip

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._validated_ip, self.port), self.timeout, self.source_address
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to a validated IP while keeping SNI + cert checks.

    The TCP socket is opened to ``validated_ip`` directly (so the address that
    was authorized is the address contacted, with no second DNS lookup), then it
    is wrapped with the *original* hostname as ``server_hostname`` so SNI and
    certificate hostname verification still target the requested host.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        validated_ip: str,
        timeout: float,
        context: ssl.SSLContext,
    ):
        super().__init__(host, port, timeout=timeout, context=context)
        self._validated_ip = validated_ip

    def connect(self) -> None:
        sock = socket.create_connection(
            (self._validated_ip, self.port), self.timeout, self.source_address
        )
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _default_connection_factory(
    scheme: str,
    host: str,
    port: int,
    validated_ip: str,
    timeout: float,
    context: Optional[ssl.SSLContext],
) -> http.client.HTTPConnection:
    if scheme == "https":
        assert context is not None
        return _PinnedHTTPSConnection(
            host, port, validated_ip=validated_ip, timeout=timeout, context=context
        )
    return _PinnedHTTPConnection(host, port, validated_ip=validated_ip, timeout=timeout)


# -- content handling --------------------------------------------------------


def _content_type_ok(content_type: str, path: str) -> bool:
    """Accept a JavaScript media type, or a ``.js`` path with **no declared type**.

    A declared ``Content-Type`` always governs: an explicit incompatible type
    (e.g. ``text/html``) is rejected even when the path ends in ``.js``, so HTML
    served at a ``.js`` URL is never parsed as JavaScript. A missing/empty
    ``Content-Type`` falls back to the path extension (the deliberate
    missing-type behavior); any other path without a JavaScript media type is
    rejected. Deterministic and fail-closed.
    """
    main = (content_type or "").split(";", 1)[0].strip().lower()
    if not main:
        return path.lower().endswith(".js")
    if "/" not in main:
        return False
    subtype = main.split("/", 1)[1].strip()
    return subtype in _JS_CONTENT_SUBTYPES or subtype.endswith("+json")


def _bounded_decompress(data: bytes, encoding: str, limit: int) -> tuple[bytes, bool]:
    """Decompress under a byte cap; ``(body, overflow)``.

    An unsupported encoding, a decompressed size beyond ``limit``
    (``unconsumed_tail``) or a stream that did not terminate within the read cap
    (``not eof``) reports ``overflow=True`` so the caller skips (no observations)
    rather than parsing a truncated or unreadable body. The produced ``body`` is
    returned even on overflow so the caller can charge the expansion against the
    run budget before failing closed.
    """
    enc = (encoding or "").split(",")[0].strip().lower()
    if not enc or enc == "identity":
        return data, False
    if enc in ("gzip", "x-gzip"):
        wbits = 16 + zlib.MAX_WBITS
    elif enc == "deflate":
        wbits = zlib.MAX_WBITS
    else:
        return b"", True
    try:
        decompressor = zlib.decompressobj(wbits)
        out = decompressor.decompress(data, max(0, int(limit)))
    except zlib.error:
        return b"", True
    overflow = bool(decompressor.unconsumed_tail) or not decompressor.eof
    return out, overflow


# -- adapter -----------------------------------------------------------------


def _js_url_from(task: Any) -> str:
    """The JavaScript URL to analyze: the reuse payload when present, else the target.

    Expansion seeds the child with ``target`` = the JS URL; the ``reason`` reuse
    form (``{"url": ...}``) is accepted for symmetry with the crawl adapters.
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


def _explicit_port(url: str) -> Optional[int]:
    """The explicit port of a URL, or ``None`` when it names none / is malformed."""
    try:
        return urlsplit(url).port
    except ValueError:
        return None


class JsAnalyzeAdapter(ToolAdapter):
    """In-process, bounded JavaScript content-analysis adapter for ``js_analysis``.

    - ``js_analysis`` task type (registered by the served composition **only** when
      ``config.javascript.enabled`` is set; disabled -> the stage is uncovered).
    - Scope: the JS URL host is validated against the run's guard before anything
      happens; the fetcher re-validates the port and the resolved destination.
    - Fetch: one bounded, scope-checked, redirect-refusing GET of the URL
      (:func:`fetch_javascript`), under a shared run-level byte budget.
    - Normalize: :func:`intelligence.javascript.parse_javascript` on the fetched
      text, emitting **only** URL/endpoint/parameter observations.
    - Failure/skip is non-fatal: no artifacts, and the task still completes -- a
      disabled budget, an out-of-scope destination, an SSRF rejection, a TLS
      failure, a redirect, a bad content type or an empty body all yield an empty
      result instead of a raised error.
    """

    name = "js_analysis"
    executables: tuple[str, ...] = ()

    def __init__(
        self,
        *,
        budget: Optional[JsFetchBudget] = None,
        fetcher: Optional[Callable[..., JsFetchResult]] = None,
        resolver: Optional[ResolverFn] = None,
        connection_factory: Optional[ConnectionFactory] = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        super().__init__()
        self._budget = budget or JsFetchBudget()
        self._fetcher = fetcher or fetch_javascript
        self._resolver = resolver
        self._connection_factory = connection_factory
        self.timeout = float(timeout)
        self.max_bytes = max(1, int(max_bytes))

    # -- availability -------------------------------------------------------

    def is_available(self) -> bool:
        return True  # in-process; stdlib HTTP(S) only

    # -- scope ---------------------------------------------------------------

    def validate(self, task: Any, scope: ScopeGuard) -> None:
        url = _js_url_from(task)
        self._require_in_scope(url, scope)
        port = _explicit_port(url)
        if port is not None:
            decision = scope.check_port(port)
            if not decision.in_scope:
                raise ScopeViolation(
                    f"js_analysis: port {port} not allowed by scope: {decision.reason}"
                )

    # -- command construction ------------------------------------------------

    def build_command(self, task: Any, config: Any) -> list[str]:
        """Diagnostic marker array; never executed (in-process adapter)."""
        return ["js-analyze", _js_url_from(task)]

    # -- parse ----------------------------------------------------------------

    def parse(self, result: CommandResult) -> list[JsObservation]:
        """Capture JSON -> canonical URL/endpoint/parameter observations.

        A capture is ``{"url": ..., "body_prefix": ...}``. Empty, malformed or
        non-JavaScript captures yield no artifacts without raising
        (``13_TESTING_STRATEGY.md`` §Adapter Fixture Tests).
        """
        try:
            data = json.loads(result.stdout or "null")
        except ValueError:
            log.warning("js_analysis: parse: output is not valid JSON")
            return []
        if not isinstance(data, dict):
            return []
        url = data.get("url") or data.get("target")
        body = data.get("body_prefix")
        if not isinstance(url, str) or not isinstance(body, str) or not body:
            return []
        parsed = parse_javascript(body, base_url=url, max_bytes=self.max_bytes)
        if parsed.truncated:
            log.info(
                "js_analysis: parse of %s truncated at max_bytes=%d",
                _redact_url(url),
                self.max_bytes,
            )
        return list(parsed.observations)

    # -- execution -----------------------------------------------------------

    def execute(
        self,
        task: Any,
        runner: ToolRunner,
        config: Any,
        scope: ScopeGuard,
    ) -> ToolExecution:
        """Fetch ``task``'s JS URL in-process, parse it, and emit observations.

        Scope is validated before anything; a fetch failure or policy skip is
        recorded non-fatally with no artifacts (the task still completes); raw
        output is preserved via ``runner.save_raw`` only when a body was fetched.
        """
        if not self.is_available():
            raise ToolUnavailable("js_analysis: in-process adapter unavailable")
        self.validate(task, scope)
        url = _js_url_from(task)
        if not url:
            raise ValueError("js_analysis: task carries no JavaScript URL")
        return self._execute_url(task, runner, scope, url)

    def _execute_url(
        self, task: Any, runner: ToolRunner, scope: ScopeGuard, url: str
    ) -> ToolExecution:
        command = ["js-analyze", url]
        run_id = getattr(task, "run_id", None)
        kwargs: dict[str, Any] = {
            "scope": scope,
            "run_id": run_id if run_id is not None else "",
            "budget": self._budget,
            "timeout": self.timeout,
            "max_bytes": self.max_bytes,
        }
        if self._resolver is not None:
            kwargs["resolver"] = self._resolver
        if self._connection_factory is not None:
            kwargs["connection_factory"] = self._connection_factory
        result = self._fetcher(url, **kwargs)

        if result.error is not None or result.skipped_reason is not None or not result.body:
            reason = result.error or result.skipped_reason or "empty body"
            log.info("js_analysis: skipping %s: %s", _redact_url(url), reason)
            return ToolExecution(
                tool=self.name,
                command=command,
                exit_code=0,
                raw_output_ref=None,
                artifacts=(),
            )

        capture = {
            "url": url,
            "host": result.host,
            "port": result.port,
            "status": result.status,
            "content_type": result.content_type,
            "source": "fetch",
            "bytes_read": result.bytes_read,
            "body_prefix": result.body[: self.max_bytes],
        }
        capture_json = json.dumps(capture, sort_keys=True, indent=2)
        raw_ref = runner.save_raw(
            self.name, capture_json, extension="json", tag="analysis"
        )
        artifacts = tuple(
            self.parse(CommandResult(tool=self.name, command=[], stdout=capture_json))
        )
        return ToolExecution(
            tool=self.name,
            command=command,
            exit_code=0,
            raw_output_ref=raw_ref,
            artifacts=artifacts,
        )


__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_RUNS_TRACKED",
    "DEFAULT_TIMEOUT",
    "DEFAULT_TOTAL_BYTES_PER_RUN",
    "ConnectionFactory",
    "JsAnalyzeAdapter",
    "JsFetchBudget",
    "JsFetchResult",
    "ResolverFn",
    "fetch_javascript",
]
