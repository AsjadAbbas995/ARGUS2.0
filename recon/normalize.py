"""Shared normalization layer (``10_IMPLEMENTATION_PLAN.md`` Phase 4).

Canonicalizes cross-tool observations into a single deduplicated asset surface.
Hostname canonicalization deliberately delegates to the already-green
``core.scope_guard.normalize_host`` so path/scope validation and normalization
never disagree. Deduplication is intentionally **narrow** - only exact
canonical-equivalent variants collapse (case, surrounding whitespace, one
trailing root dot); ``www.example.com`` vs ``example.com`` remain DISTINCT
(Phase 4 risk: over-aggressive normalization must never merge genuinely
different assets).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlsplit

from core.scope_guard import normalize_host


def normalize_hostname(host: str | None) -> str | None:
    """Canonical form of a single hostname (lowercase, no trailing dot).

    Delegates to the scope guard's normalization so DNS/httpx/subfinder and the
    Scope Guard resolve to the same canonical surface. Returns ``None`` for
    empty/whitespace-only input.
    """
    if host is None:
        return None
    return normalize_host(host) or None


def canonical_assets(hosts: Iterable[str | None]) -> Iterator[str]:
    """Yield deduplicated, normalized hostnames (first-seen wins, order kept)."""
    seen: set[str] = set()
    for host in hosts:
        canon = normalize_hostname(host)
        if canon is None or canon in seen:
            continue
        seen.add(canon)
        yield canon


def dedupe_observations(
    observations: Iterable[Any],
    *,
    host_key: str = "host",
) -> Iterator[Any]:
    """Collapse duplicate asset variants (one canonical host per program).

    ``host_key`` names the attribute holding the (possibly unnormalized)
    hostname on each observation; values normalizing to the same canonical
    host are emitted only for their first occurrence. Preserves document
    order.
    """
    seen: set[str] = set()
    for obs in observations:
        host = getattr(obs, host_key, None)
        canon = normalize_hostname(host)
        if canon is not None:
            if canon in seen:
                continue
            seen.add(canon)
        yield obs


# ---------------------------------------------------------------------------
# Read-only comparison keys (Phase 26, Step 3) - no persistence mutation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ComparisonKey:
    """Read-only comparison key. Equality is NOT proof of semantic equivalence.

    This key is never written back into observations, never used for ingestion
    plan keys, repository arguments, DB uniqueness, or upsert behavior, and
    never triggers deduplication/persistence merging. Creating a key does not
    mutate the original object or database state.
    """

    kind: str
    key: tuple[Any, ...]
    parsed: bool = True


def _host_header_like(host: str) -> str:
    host = (host or "").strip()
    if not host:
        return ""
    if ":" in host and not host.startswith("["):
        # IPv6 literal - leave as-is for comparison display; normalize_host may
        # not expect brackets, but we don't change scheme/port/identity semantics
        return host
    return host


def url_comparison_key(url: str) -> Optional[ComparisonKey]:
    """Read-only comparison key for an absolute HTTP(S) URL.

    Allowed (conservative): lowercase hostname, strip a single trailing dot from
    hostname (via scope-guard normalization when possible). Fragments are
    dropped only when parsing is unambiguous. Everything else is preserved
    exactly as observed (scheme, port, path case/trailing slash/duplicate
    slashes, percent-encoding/encoded separators, query string and ordering/
    repeated params). Non-absolute, relative, protocol-relative, or malformed
    URLs return None (no key; caller must not guess). This key is for
    comparison/grouping only and is never used for persistence identity.
    """
    if not isinstance(url, str):
        return None
    text = url.strip()
    if not text:
        return None
    # Reject obvious non-absolute forms
    if text.startswith("//"):
        return None
    if text.startswith("/") or text.startswith("?") or text.startswith("#"):
        return None
    # Credentials/userinfo are not expected; be conservative and reject
    if "@" in text.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]:
        return None
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        return None
    host = parts.hostname
    if not host:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    # Normalize hostname conservatively (lowercase, trailing dot)
    canon_host = normalize_hostname(host) or host.lower().rstrip(".")
    port = parts.port
    path = parts.path if parts.path != "" else "/"
    # Explicitly do NOT sort query, do NOT remove repeated params, do NOT normalize encoding
    query = parts.query
    # Fragments dropped only when unambiguous; parts.fragment is separate
    return ComparisonKey(
        kind="url",
        key=(scheme, canon_host, port, path, query),
        parsed=True,
    )


def endpoint_comparison_key(
    scheme: str, host: str, port: Optional[int], path: str, method: str
) -> Optional[ComparisonKey]:
    """Read-only comparison key for an endpoint identity tuple.

    Preserves method casing exactly as observed. Normalizes hostname case and
    a trailing dot only. Preserves path case/trailing slashes/encoding and all
    other components. Returns None if inputs are ambiguous/malformed. For
    comparison/grouping only; never used for ingestion/persistence identity.
    """
    if not all(isinstance(x, str) or x is None for x in (scheme, host, path, method)):
        return None
    s = (scheme or "").strip().lower()
    if s not in ("http", "https"):
        return None
    h = (host or "").strip()
    if not h:
        return None
    canon_host = normalize_hostname(h) or h.lower().rstrip(".")
    p = path if isinstance(path, str) and path != "" else "/"
    m = method if isinstance(method, str) else ""
    return ComparisonKey(kind="endpoint", key=(s, canon_host, port, p, m), parsed=True)


def parameter_comparison_key(
    scheme: str,
    host: str,
    port: Optional[int],
    path: str,
    method: str,
    name: str,
    location: str = "query",
) -> Optional[ComparisonKey]:
    """Read-only comparison key for a parameter identity tuple.

    Preserves parameter name casing and method casing exactly as observed.
    Preserves path/query encoding and structure. Hostname case/trailing dot
    normalized only. For comparison/grouping only; never used for
    ingestion/persistence identity.
    """
    if not all(isinstance(x, str) or x is None for x in (scheme, host, path, method, name, location)):
        return None
    s = (scheme or "").strip().lower()
    if s not in ("http", "https"):
        return None
    h = (host or "").strip()
    if not h:
        return None
    canon_host = normalize_hostname(h) or h.lower().rstrip(".")
    p = path if isinstance(path, str) and path != "" else "/"
    m = method if isinstance(method, str) else ""
    n = name if isinstance(name, str) else ""
    loc = location if isinstance(location, str) else "query"
    return ComparisonKey(
        kind="parameter", key=(s, canon_host, port, p, m, n, loc), parsed=True
    )


__all__ = [
    "ComparisonKey",
    "canonical_assets",
    "dedupe_observations",
    "endpoint_comparison_key",
    "normalize_hostname",
    "parameter_comparison_key",
    "url_comparison_key",
]
