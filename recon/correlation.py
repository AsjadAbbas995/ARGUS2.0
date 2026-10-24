'''Phase 27: conservative, read-only endpoint/parameter correlation.

Groups EndpointRecords by exact identity via the existing
correlation.records.endpoint_key contract (method pattern host).
Attaches ParameterRecords only when their endpoint_key exactly matches.
Preserves all original records and evidence IDs. No mutation, no I/O, no
network, no database access. Groups represent derived co-occurrence/context
only - not semantic equivalence, not facts, not inferences, not findings.
'''
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

from correlation.records import EndpointRecord, ParameterRecord, endpoint_key


@dataclass(frozen=True)
class CorrelatedParameter:
    '''A parameter attached to a correlation group, preserving the original fact.'''
    name: str
    location: str
    significance: str
    endpoint_key: str
    evidence_id: str


@dataclass(frozen=True)
class EndpointCorrelationGroup:
    '''Read-only derived grouping of existing facts.

    NOT a fact, NOT an inference, NOT a finding. Co-occurrence/context only;
    no semantic equivalence is implied.
    '''
    group_id: str
    endpoint_key: str
    host: str
    method: str
    pattern: str
    endpoints: tuple[EndpointRecord, ...]
    parameters: tuple[CorrelatedParameter, ...]
    evidence_ids: tuple[str, ...]


def correlate_endpoints(
    endpoints: Iterable[Any],
    parameters: Optional[Iterable[Any]] = None,
) -> tuple[EndpointCorrelationGroup, ...]:
    '''Pure, read-only correlation of endpoints and their parameters.

    Groups EndpointRecords by exact identity (method, pattern, host) via
    endpoint_key(method, pattern, host). Attaches ParameterRecords only
    when their endpoint_key exactly matches a group. Orphan parameters
    are never attached and do not create groups. Preserves all original
    EndpointRecord instances and all evidence IDs. Deterministic ordering.
    No mutation, no I/O, no network, no database.

    ``endpoints`` may be a mixed iterable of EndpointRecords and
    ParameterRecords (as returned by the projection); when ``parameters``
    is omitted, ParameterRecords are extracted from that same iterable.
    Passing ``parameters`` explicitly uses that iterable instead and keeps
    the earlier split-input behavior. The input is materialized once, so
    one-shot generators are supported.
    '''
    items = list(endpoints or ())
    endpoint_list = [obj for obj in items if isinstance(obj, EndpointRecord)]
    if parameters is None:
        parameters = [obj for obj in items if isinstance(obj, ParameterRecord)]
    if not endpoint_list:
        return ()
    by_key = {}
    for ep in endpoint_list:
        try:
            method = getattr(ep, 'method')
            pattern = getattr(ep, 'pattern')
            host = getattr(ep, 'host')
            key = endpoint_key(method, pattern, host)
        except Exception:
            continue
        if not isinstance(key, str) or not key:
            continue
        by_key.setdefault(key, []).append(ep)
    if not by_key:
        return ()
    params_by_key = {}
    if parameters is not None:
        for obj in parameters:
            if not isinstance(obj, ParameterRecord):
                continue
            try:
                pk = getattr(obj, 'endpoint_key')
                if not isinstance(pk, str) or pk not in by_key:
                    continue
                cp = CorrelatedParameter(
                    name=getattr(obj, 'name'),
                    location=getattr(obj, 'location'),
                    significance=getattr(obj, 'significance'),
                    endpoint_key=pk,
                    evidence_id=getattr(obj, 'evidence_id'),
                )
            except Exception:
                continue
            params_by_key.setdefault(pk, []).append(cp)
    groups = []
    for ep_key in sorted(by_key.keys()):
        eps = list(by_key[ep_key])
        eps_sorted = sorted(
            eps,
            key=lambda e: (getattr(e, 'evidence_id', ''), getattr(e, 'method', ''), getattr(e, 'pattern', ''), getattr(e, 'host', ''), repr(e)),
        )
        try:
            first = eps_sorted[0]
            method_f = getattr(first, 'method', '')
            pattern_f = getattr(first, 'pattern', '')
            host_f = getattr(first, 'host', '')
        except Exception:
            continue
        cps = list(params_by_key.get(ep_key, []))
        cps_sorted = sorted(
            cps,
            key=lambda c: (c.endpoint_key, c.location, c.name, c.evidence_id, repr(c)),
        )
        ev_set = set()
        for e in eps_sorted:
            try:
                ev = getattr(e, 'evidence_id')
                if ev is not None:
                    ev_set.add(ev)
            except Exception:
                pass
        for c in cps_sorted:
            try:
                if c.evidence_id is not None:
                    ev_set.add(c.evidence_id)
            except Exception:
                pass
        ev_list = sorted(ev_set)
        groups.append(
            EndpointCorrelationGroup(
                group_id='ep:' + ep_key,
                endpoint_key=ep_key,
                host=host_f,
                method=method_f,
                pattern=pattern_f,
                endpoints=tuple(eps_sorted),
                parameters=tuple(cps_sorted),
                evidence_ids=tuple(ev_list),
            )
        )
    groups_sorted = sorted(
        groups,
        key=lambda g: (g.host, g.method, g.pattern, g.group_id),
    )
    return tuple(groups_sorted)
