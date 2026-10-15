"""Historical recon adapters (gau, wayback). Placeholder.

This package hosts the passive historical-URL discovery adapters. It defines the
shared :class:`HistoricalUrlObservation` type and the ``source`` constants in one
place so the GAU adapter (Phase 24) and the deferred Wayback adapter can share a
single observation type without importing each other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

#: Recorded ``urls.source`` / observation source for each adapter.
SOURCE_GAU = "gau"
SOURCE_WAYBACK = "wayback"


@dataclass(frozen=True)
class HistoricalUrlObservation:
    """One passively-discovered URL from a historical provider.

    This is a **distinct type** (never a reused live ``UrlObservation``) so the
    "historical" provenance is carried by the type itself and can never be silently
    dropped on the way to persistence. ``path`` is query-stripped, consistent with the
    ``urls.path`` convention; ``url`` is the canonical, query-stripped URL.

    ``metadata`` carries additive per-observation signal and is deliberately excluded
    from :attr:`key` so the canonical identity of a URL is independent of metadata.
    """

    host: str
    port: int
    path: str
    url: str
    source: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple:
        return (0, self.host, self.port, self.path, self.source)
