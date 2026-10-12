"""Phase-16 agent context, built from one run's persisted facts ("07_AI_AGENTS.md" per-agent
inputs, "05_DATA_MODEL.md", "PHASE_16_PROPOSAL.md" §3).

Before this module the Phase-7 agents could only be exercised by hand-built fixtures: nothing
in production ever handed them a real run. This is the adapter between the Phase 15 read
projection and ``ai/context.py``.

Evidence is structural, not advisory
------------------------------------
Every :class:`~ai.context.ObservationRecord` and :class:`~ai.context.AssetRecord` this module
produces carries an ``evidence_id`` taken from a node the Phase 15 projection actually emitted,
which in turn came from an ``evidence`` row belonging to *this* run
(``evidence.tool_run_id -> tool_runs.task_id -> tasks.run_id``). The agents may cite only ids
present in their context (``ai/contract.py`` enforces it at construction, ``ai/validator.py``
re-checks), so the provenance chain an agent claim ends on is the same one Phase 15 verified.

This module therefore never invents a fact, never widens a claim, and never reads a fact the
run did not observe. A run with no facts yields empty context, which the agents correctly
treat as "no proposal".

Coverage gaps are intersected with capability
--------------------------------------------
``recon_agent.STAGE_PRIORITY`` names 17 documented recon stages. Only some have a registered
adapter, and ``api/serve.py`` refuses a task type with no adapter *before* constructing one, so
proposing an unexecutable stage would not merely waste a pass -- it would enqueue a task that
fails immediately.

So :func:`coverage_gaps` returns only stages that are **both uncovered and executable**, and
reports the unexecutable remainder separately as :func:`uncovered_without_capability`. The
agent therefore proposes real, runnable next work, and the gaps it cannot act on stay visible
as an honest record instead of becoming doomed tasks. This is the same "name the gap rather
than fill it" discipline Phase 15 applied to unproduced record kinds.

Determinism
-----------
Pure and total: the same surface payload, snapshot, and task list always yield byte-identical
context. Ordering is fixed on ``(kind, key)`` throughout, so the proposal an agent derives --
and therefore the row it persists -- is reproducible.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional, Sequence

from .context import (
    AssetRecord,
    HypothesisContext,
    ObservationRecord,
    ReconContext,
    ScopeRef,
)
from .recon_agent import STAGE_PRIORITY

#: Task type -> the documented recon stage it satisfies. Deliberately narrow: a stage counts as
#: covered only when a task of *exactly* that type has run. Anything else is treated as a gap.
#: The mapping errs toward reporting a stage uncovered, because over-reporting a gap costs one
#: extra loop pass while under-reporting one silently skips coverage.
TASK_TYPE_COVERS_STAGE: Mapping[str, str] = {
    "subfinder": "subdomain_enum",
    "dns_resolve": "dns_resolve",
    "dns": "dns_resolve",
    "resolve": "dns_resolve",
    "http_probe": "http_probe",
    "httpx_probe": "http_probe",
    "port_scan": "port_scan",
    "naabu": "port_scan",
    "tech_detect": "tech_detect",
    "whatweb": "tech_detect",
    # Phase 22: deterministic web crawling. ``katana`` is the adapter's tool spelling;
    # ``web_crawl`` is the stage name the coverage loop already knows, so a task of
    # either type satisfies the same stage.
    "web_crawl": "web_crawl",
    "katana": "web_crawl",
    # Phase 23: approved-wordlist content discovery. ``content_discover`` is the
    # stage name and the canonical task type; ``ffuf`` is the adapter's tool
    # spelling, so a task of either type satisfies the same stage.
    "content_discover": "content_discover",
    "ffuf": "content_discover",
}

#: Terminal task statuses that mean the stage actually produced coverage. A task that is still
#: pending or that failed has not covered anything, so its stage stays a gap.
_COVERED_STATUSES = frozenset({"completed"})

#: The single root target used when a run's snapshot names several allowed domains. The scope
#: guard -- not this module -- is what authorizes the resulting task, so this only has to be a
#: deterministic, in-scope choice.
_DEFAULT_ROOT = ""


def scope_ref(snapshot: Optional[Mapping[str, Any]]) -> ScopeRef:
    """Authorized program scope for a run, from its persisted ``configuration_snapshot``.

    Read straight from the snapshot the run was created with, so the agents are bounded by the
    same scope the orchestrator will later re-check. An agent proposing outside this is refused
    upstream; this function only reports what the run was authorized for.
    """
    scope = (snapshot or {}).get("scope") or {}
    allowed = tuple(str(d) for d in (scope.get("allowed_domains") or ()))
    root = allowed[0] if allowed else _DEFAULT_ROOT
    return ScopeRef(program="", root=root, allowed_hosts=allowed)


def _statement(node: Mapping[str, Any]) -> str:
    """One factual sentence describing a projected node, for use as an observation.

    Built only from the node's own key and attributes. Nothing is inferred here: the sentence
    restates what was recorded, and the ``evidence_id`` beside it is what makes it traceable.
    """
    kind = str(node.get("kind", ""))
    key = str(node.get("key", ""))
    attributes = node.get("attributes") or {}
    if kind == "domain":
        return f"in-scope asset `{key}` recorded"
    if kind == "ip":
        owner = str(attributes.get("hostname") or "")
        return f"IP `{key}` resolved{(' for ' + owner) if owner else ' with no recorded host'}"
    if kind == "port":
        service = str(attributes.get("service") or "")
        return f"port `{key}` open{(' (service: ' + service + ')') if service else ''}"
    if kind == "webapp":
        status = str(attributes.get("status_code") or "")
        title = str(attributes.get("title") or "")
        detail = ", ".join(x for x in (status, title) if x)
        return f"web application `{key}` probed" + (f" ({detail})" if detail else "")
    if kind == "technology":
        category = str(attributes.get("category") or "")
        return (
            f"technology `{key}` recorded"
            + (f" (category: {category})" if category else "")
        )
    return f"{kind or 'fact'} `{key}` recorded"


def observations(surface: Mapping[str, Any]) -> tuple[ObservationRecord, ...]:
    """One :class:`ObservationRecord` per projected node, in deterministic order.

    Nodes with no ``evidence_id`` are skipped rather than cited without provenance: the agents
    treat a missing citation as an unreferenced claim, and an unreferenced claim is exactly
    what this layer must never produce.
    """
    records: list[ObservationRecord] = []
    for node in surface.get("graph", {}).get("nodes", []) or []:
        if not isinstance(node, Mapping):
            continue
        evidence_id = str(node.get("evidence_id") or "")
        if not evidence_id:
            continue
        records.append(
            ObservationRecord(
                statement=_statement(node),
                evidence_id=evidence_id,
                source=str(node.get("kind", "")),
            )
        )
    return tuple(sorted(records, key=lambda r: (r.source, r.evidence_id, r.statement)))


def assets(surface: Mapping[str, Any]) -> tuple[AssetRecord, ...]:
    """Every evidenced ``domain`` node as an :class:`AssetRecord`."""
    records: list[AssetRecord] = []
    for node in surface.get("graph", {}).get("nodes", []) or []:
        if not isinstance(node, Mapping) or node.get("kind") != "domain":
            continue
        evidence_id = str(node.get("evidence_id") or "")
        if not evidence_id:
            continue
        records.append(
            AssetRecord(
                hostname=str(node.get("key", "")),
                evidence_id=evidence_id,
                source="phase15_projection",
            )
        )
    return tuple(sorted(records, key=lambda a: (a.hostname, a.evidence_id)))


def covered_stages(tasks: Iterable[Any]) -> frozenset[str]:
    """Documented recon stages that a completed task has actually satisfied."""
    covered: set[str] = set()
    for task in tasks:
        status = str(getattr(task, "status", "") or "")
        if status not in _COVERED_STATUSES:
            continue
        stage = TASK_TYPE_COVERS_STAGE.get(str(getattr(task, "type", "") or ""))
        if stage:
            covered.add(stage)
    return frozenset(covered)


def coverage_gaps(tasks: Iterable[Any], executable: Iterable[str]) -> tuple[str, ...]:
    """Uncovered stages that at least one registered adapter can actually run.

    This is the intersection the loop needs: a gap the system cannot act on is not a task, and
    enqueuing one would fail at execution (``api/serve.py`` refuses a task type with no
    adapter before constructing it).
    """
    runnable = {str(t) for t in executable}
    done = covered_stages(tasks)
    return tuple(s for s in STAGE_PRIORITY if s not in done and s in runnable)


def uncovered_without_capability(
    tasks: Iterable[Any], executable: Iterable[str]
) -> tuple[str, ...]:
    """Uncovered stages that no registered adapter can run -- reported, never proposed.

    Returned so the gap stays visible rather than silently dropped: "we did not cover
    web_crawl" and "we could not, there is no adapter for it" are different facts and a
    reader of the run should be able to tell them apart.
    """
    runnable = {str(t) for t in executable}
    done = covered_stages(tasks)
    return tuple(s for s in STAGE_PRIORITY if s not in done and s not in runnable)


def recon_context(
    surface: Mapping[str, Any],
    snapshot: Optional[Mapping[str, Any]],
    tasks: Iterable[Any],
    executable: Sequence[str],
) -> ReconContext:
    """Assemble the :class:`ReconContext` for ``ai.recon_agent``.

    ``executable`` must be the task types the served adapter table can actually dispatch --
    derived from the live adapter registry, never hardcoded, so the gate cannot drift from
    what the server can run.
    """
    return ReconContext(
        scope=scope_ref(snapshot),
        assets=assets(surface),
        observations=observations(surface),
        existing_tasks=tuple(
            str(getattr(t, "target", "") or "") for t in tasks if getattr(t, "target", "")
        ),
        gaps=coverage_gaps(tasks, executable),
    )


def hypothesis_context(
    surface: Mapping[str, Any],
    snapshot: Optional[Mapping[str, Any]],
) -> HypothesisContext:
    """Assemble the :class:`HypothesisContext` for ``ai.hypothesis_agent``.

    Deliberately built from *all* evidenced observations rather than a selected subset. The
    agent cites every observation it is given, so narrowing the input here would silently
    narrow what the resulting hypothesis is accountable for.
    """
    return HypothesisContext(
        scope=scope_ref(snapshot),
        observations=observations(surface),
    )
