"""Markdown projection of the committed JSON report (``09_OUTPUTS.md`` :Report Structure).

Projects the **same** underlying report dict that ``reports.json_report.build_report`` builds
(so JSON / Markdown / HTML all render one data object) and keeps the truth-label contract:

- Facts (run metadata, assets, task surface, tool runs, dedup, and the Phase 15 projected
  attack-surface graph) are rendered from their own committed sections.
- Phase 17 adds a ``# AI Analysis`` section: the run's persisted agent-invocation records. It is
  rendered *before* the hypotheses because it is upstream of them, and it is never merged into
  ``validated_findings`` -- an analysis record is what the intelligence layer did, not a claim
  about the target.
- Hypotheses stay in a clearly labelled ``# Hypotheses`` section; each item carries its stored
  ``truth_label`` and ``confidence`` - never re-ranked, never merged with validated findings.
- Validated findings and the evidence chain are separate, labelled sections.

Deterministic by construction: no wall-clock, no randomness, no module state; every nested list
is rendered in the exact order already fixed by ``build_report``; the emitted text depends only
on the report dict. Byte-reproducible for identical inputs.
"""

from __future__ import annotations

from typing import Any, Mapping

_TOP = "# ARGUS Run Report\n"
_DIVIDER = "\n---\n"

_HYPOTHESES = "hypotheses"
_FINDINGS = "validated_findings"
_EVIDENCE = "evidence"
_TASKS = "tasks"
_TOOL_RUNS = "tool_runs"
_DEDUP = "dedup"
_ASSETS = "assets"
_RUN = "run"
_ATTACK_SURFACE = "attack_surface"
_AI_ANALYSIS = "ai_analysis"
_AI_COVERAGE_GAPS = "ai_coverage_gaps"

_LABELS = {"HYPOTHESIS", "UNVERIFIED_CLAIM", "VALIDATED_FINDING"}


def _flat(value: Any) -> str:
    """Collapse a value to a single line.

    Markdown in this module is not escaped -- that is the established convention here -- so the
    one thing that must be guaranteed is that an interpolated value cannot break out of the line
    it was written into. Agent proposals are free text and may legitimately contain newlines,
    so every interpolated value is flattened rather than trusted.
    """
    return " ".join(str(value or "").split())


def render(report: Mapping[str, Any]) -> str:
    """Render ``report`` to deterministic, facts-vs-hypotheses-separated Markdown."""
    parts: list[str] = [_TOP]
    parts.append(_facts_section(report))
    parts.append(_ai_analysis_section(report))
    parts.append(_ai_coverage_gaps_section(report))
    parts.append(_hypotheses_section(report))
    parts.append(_findings_section(report))
    parts.append(_evidence_section(report))
    return "".join(parts)


def _facts_section(report: Mapping[str, Any]) -> str:
    out: list[str] = ["# Facts\n"]
    run = report.get(_RUN)
    if isinstance(run, Mapping):
        out.append(f"- **Run:** {run.get('id', ('missing',))}")
        out.append(f"- **Program:** {run.get('program_id', ('missing',))}")
        out.append(f"- **Status:** {run.get('status', ('missing',))}")
        out.append(f"- **Target:** {run.get('target', ('missing',))}")
    assets = report.get(_ASSETS)
    if isinstance(assets, Mapping) and assets:
        out.append("\n## Asset Counts\n")
        for name, count in sorted(assets.items()):
            out.append(f"- {name}: {int(count)}")
    tasks = report.get(_TASKS)
    _nested_section(out, "## Tasks", tasks)
    _nested_section(out, "## Tool Runs", report.get(_TOOL_RUNS))
    dedup = report.get(_DEDUP)
    if isinstance(dedup, Mapping) and dedup:
        out.append("\n## Deduplication\n")
        out.append(f"- suppressed_completed_fingerprints: {dedup.get('suppressed_completed_fingerprints', 0)}")
    out.append(_attack_surface_block(report))
    return "".join(out) + _DIVIDER


def _attack_surface_block(report: Mapping[str, Any]) -> str:
    """Render the Phase 15 projected graph, or nothing when it was not supplied.

    A ``*``-level subsection of Facts rather than a new top-level section, because the
    graph is a *descriptive projection of recorded facts*: every node and edge already
    carries its evidence id, so it belongs beside the other facts and must never read as
    an assertion. Inferences are printed with their own ``truth_label`` and are explicitly
    not findings.
    """
    surface = report.get(_ATTACK_SURFACE)
    if not isinstance(surface, Mapping):
        return ""
    out: list[str] = ["\n## Attack Surface\n"]
    if not surface.get("available", False):
        out.append(
            "_No canonical fact store available for this run "
            "(no attack surface was projected)._"
        )
        return "".join(out)

    records = surface.get("records")
    if isinstance(records, Mapping):
        out.append(f"- records: {int(records.get('count', 0))}")
        by_kind = records.get("by_kind")
        if isinstance(by_kind, Mapping) and by_kind:
            rendered = ", ".join(
                f"{name}={int(count)}" for name, count in sorted(by_kind.items())
            )
            out.append(f"- record kinds: {rendered}")
    graph = surface.get("graph")
    if isinstance(graph, Mapping):
        out.append(
            f"- graph: nodes={int(graph.get('node_count', 0))} "
            f"edges={int(graph.get('edge_count', 0))} "
            f"orphans={int(graph.get('orphan_count', 0))}"
        )
        orphans = graph.get("orphans")
        if isinstance(orphans, list) and orphans:
            out.append(f"- unlinked nodes: {', '.join(str(o) for o in orphans)}")
    endpoints = surface.get("endpoint_subgraph")
    if isinstance(endpoints, Mapping):
        out.append(
            f"- endpoint subgraph: {int(endpoints.get('node_count', 0))} node(s), "
            f"{int(endpoints.get('edge_count', 0))} edge(s)"
        )
    inferences = surface.get("inferences")
    if isinstance(inferences, Mapping):
        count = int(inferences.get("count", 0))
        out.append(f"- inferences: {count} (hypotheses, not findings)")
        items = inferences.get("items")
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, Mapping):
                    continue
                truth = str(item.get("truth_label", "UNVERIFIED_CLAIM"))
                if truth not in _LABELS:
                    truth = "UNVERIFIED_CLAIM"
                ids = ", ".join(str(e) for e in item.get("evidence_ids") or [])
                out.append(f"  - **{truth}** - {str(item.get('statement', ''))}")
                if ids:
                    out.append(f"    evidence=[{ids}]")
    unproduced = surface.get("unproduced_record_kinds")
    if isinstance(unproduced, list) and unproduced:
        out.append(
            f"- no producer yet (not projected): {', '.join(str(k) for k in unproduced)}"
        )
    return "".join(out)


def _nested_section(out: list[str], heading: str, section: Any) -> None:
    if not isinstance(section, Mapping):
        return
    total = section.get("total", 0)
    by = section.get("by_status") or section.get("by_tool")
    items = section.get("items")
    out.append(f"\n{heading} (total={int(total)})\n")
    if isinstance(by, Mapping):
        for k, v in sorted(by.items()):
            out.append(f"- {k}: {int(v)}")
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, Mapping):
                continue
            label = str(item.get("type", item.get("tool_name", item.get("id", ""))))
            status = str(item.get("status", ""))
            out.append(f"- {label} [{status}]: {str(item.get('target', ''))}")


def _ai_analysis_section(report: Mapping[str, Any]) -> str:
    """Render the run's persisted AI analysis, or nothing when the section is absent.

    A missing key means "this report was built by a caller with no analysis store", which is
    different from an empty list meaning "the run was analysed and proposed nothing". Only the
    latter is worth a heading, so the section is omitted entirely in the former case -- the same
    convention ``attack_surface`` already uses.

    Rendered before ``# Hypotheses`` because these are upstream of them: an analysis record is
    the intelligence layer's account of one agent invocation, and a hypothesis is what the
    operator reviews. Nothing here is a finding.
    """
    items = report.get(_AI_ANALYSIS)
    if not isinstance(items, list):
        return ""
    out: list[str] = ["# AI Analysis\n"]
    if not items:
        out.append("_No AI analysis recorded._\n")
        return "".join(out) + _DIVIDER
    for a in items:
        if not isinstance(a, Mapping):
            continue
        out.append(
            "- `{id}` **{kind}** agent={agent} truth_label={truth} model={model}".format(
                id=_flat(a.get("id")),
                kind=_flat(a.get("proposal_type") or "unknown"),
                agent=_flat(a.get("agent_name")),
                truth=_flat(a.get("truth_label") or "UNLABELLED"),
                model=_flat(a.get("model_used")),
            )
        )
        target = _flat(a.get("target"))
        if target:
            out.append(f"  target={target}")
        evidence = a.get("evidence")
        if isinstance(evidence, list) and evidence:
            ids = ", ".join(_flat(e) for e in evidence)
            out.append(f"  evidence=[{ids}]")
        created = _flat(a.get("created_at"))
        if created:
            out.append(f"  created_at={created}")
    return "".join(out) + _DIVIDER


def _ai_coverage_gaps_section(report: Mapping[str, Any]) -> str:
    """Render the run's persisted coverage gaps, or nothing when absent.

    Phase 18. The section is omitted entirely if the key is missing (caller has no
    coverage storage), matching the optional-section convention of the attack surface
    and AI analysis. An empty list means the run was analysed and has no gaps, which is
    reported truthfully as "No coverage gaps recorded".
    """
    gaps = report.get(_AI_COVERAGE_GAPS)
    if not isinstance(gaps, list):
        return ""
    out: list[str] = ["# AI Coverage Gaps\n"]
    if not gaps:
        out.append("_No coverage gaps recorded._\n")
        return "".join(out) + _DIVIDER
    for g in gaps:
        if not isinstance(g, Mapping):
            continue
        stage = _flat(g.get("stage") or "")
        if not stage:
            continue
        count = g.get("observation_count", 1)
        first = _flat(g.get("first_seen_at"))
        last = _flat(g.get("last_seen_at"))
        out.append(f"- **{stage}** (observed {count} time(s))")
        if first:
            out.append(f"  first_seen_at={first}")
        if last:
            out.append(f"  last_seen_at={last}")
    return "".join(out) + _DIVIDER


def _hypotheses_section(report: Mapping[str, Any]) -> str:
    out: list[str] = ["# Hypotheses\n"]
    items = report.get(_HYPOTHESES)
    if isinstance(items, list) and items:
        for h in items:
            if not isinstance(h, Mapping):
                continue
            truth = str(h.get("truth_label", "UNVERIFIED_CLAIM"))
            if truth not in _LABELS:
                truth = "UNVERIFIED_CLAIM"
            statement = str(h.get("statement", h.get("reasoning", "")))
            out.append(f'- **{truth}** - {statement}')
            out.append(f"  priority={h.get('priority', 'none')} confidence={h.get('confidence', 0.0)}")
            ev = h.get("evidence")
            if isinstance(ev, list) and ev:
                ids = ", ".join(str(e) for e in ev)
                out.append(f"  evidence=[{ids}]")
    else:
        out.append("_No hypotheses recorded._")
    return "".join(out) + _DIVIDER


def _findings_section(report: Mapping[str, Any]) -> str:
    out: list[str] = ["# Validated Findings\n"]
    items = report.get(_FINDINGS)
    if isinstance(items, list) and items:
        for f in items:
            if not isinstance(f, Mapping):
                continue
            truth = str(f.get("truth_label", "VALIDATED_FINDING"))
            statement = str(f.get("statement", f.get("reasoning", "")))
            out.append(f'- **{truth}** - {statement}')
            ev = f.get("evidence")
            if isinstance(ev, list) and ev:
                ids = ", ".join(str(e) for e in ev)
                out.append(f"  evidence=[{ids}]")
    else:
        out.append("_No validated findings recorded._")
    return "".join(out) + _DIVIDER


def _evidence_section(report: Mapping[str, Any]) -> str:
    out: list[str] = ["# Evidence\n"]
    items = report.get(_EVIDENCE)
    if isinstance(items, list) and items:
        for e in items:
            if not isinstance(e, Mapping):
                continue
            ref = str(e.get("raw_reference", ""))
            ent = str(e.get("entity_type", ""))
            idx = f"{e.get('entity_id') or '_'}/{e.get('tool_run_id') or '_'}"
            out.append(f"- `{ref}` ({ent}: {idx})")
    else:
        out.append("_No evidence recorded._")
    return "".join(out) + _DIVIDER
