"""JSON report (``09_OUTPUTS.md`` respect: same machine data, one deterministic shape).

Composes ``core/json_summary.build_json_summary`` (the committed single source for run/task/
tool-run facts) with the hypothesis / validated-finding / evidence / AI-analysis sections, so
the JSON report is the *one underlying data object* that the Markdown and HTML renderers both
project. Deterministic by construction: every nested list is sorted by a stable key, keys are
fixed and sorted by ``json.dumps(sort_keys=True)``, and value coercion uses a fixed
``default=str`` - the same inputs always produce byte-identical, machine-valid JSON.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

from core.json_summary import build_json_summary
from database.models.entities import Asset, Evidence, Run, Task, ToolRun

_HYPOTHESES_SECTION = "hypotheses"
_FINDINGS_SECTION = "validated_findings"
_EVIDENCE_SECTION = "evidence"
_ATTACK_SURFACE_SECTION = "attack_surface"
_AI_ANALYSIS_SECTION = "ai_analysis"
_AI_COVERAGE_GAPS_SECTION = "ai_coverage_gaps"

_PRIORITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


def _hypothesis_key(h: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        h.get("truth_label", ""),
        _PRIORITY_RANK.get(str(h.get("priority", "none")), 5),
        -float(h.get("confidence", 0.0) or 0.0),
        str(h.get("id", "")),
    )


def _evidence_key(e: Evidence) -> tuple[Any, ...]:
    return (e.raw_reference or "", str(e.id))


def _ai_analysis_key(a: Mapping[str, Any]) -> tuple[Any, ...]:
    """Deterministic analysis ordering: creation time, then id as the tie-break."""
    return (str(a.get("created_at") or ""), str(a.get("id", "")))


def _evidence_summary(e: Evidence) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "tool_run_id": str(e.tool_run_id) if e.tool_run_id else None,
        "entity_type": e.entity_type,
        "entity_id": str(e.entity_id) if e.entity_id else None,
        "raw_reference": e.raw_reference,
    }


def build_report(
    run: Run,
    tasks: Iterable[Task] = (),
    tool_runs: Iterable[ToolRun] = (),
    asset_counts: Optional[Mapping[str, int]] = None,
    evidence_count: int = 0,
    hypotheses: Iterable[Mapping[str, Any]] = (),
    validated_findings: Iterable[Mapping[str, Any]] = (),
    evidence: Iterable[Evidence] = (),
    attack_surface: Optional[Mapping[str, Any]] = None,
    ai_analysis: Optional[Iterable[Mapping[str, Any]]] = None,
    ai_coverage_gaps: Optional[Iterable[Mapping[str, Any]]] = None,
) -> dict[str, Any]:
    """Build the full report dict for ``run``.

    The run/task/tool-run surface is delegated verbatim to the committed
    ``core.json_summary.build_json_summary`` (facts), and the hypothesis / validated-finding /
    evidence sections are appended in stable order. Facts and hypotheses stay in *separate,
    correctly labelled* sections; a hypothesis is never promoted into ``validated_findings``.

    ``attack_surface`` is the Phase 15 projected graph (``database.projection.serialize``),
    passed in already-serialised so this module keeps no dependency on ``correlation``. It is
    optional and defaults to ``None``, which omits the key entirely rather than emitting an
    empty graph: a caller that has no canonical store (e.g. the in-memory double) must not be
    reported as a run with no attack surface, and every existing caller keeps its exact
    previous output.

    The section carries its own ``truth_label`` on each inference and is deliberately *not*
    merged into ``validated_findings``. An inference is a hypothesis; only the review
    workflow in ``validated_findings`` can promote one.

    ``ai_analysis`` (Phase 17) is the run's persisted intelligence-layer audit records: one
    entry per agent invocation that produced a proposal. It follows the same optional-section
    convention as ``attack_surface`` -- ``None`` omits the key entirely rather than emitting an
    empty list, so a caller with no canonical store is never reported as a run whose AI
    examined nothing and found nothing. An explicit empty list means "the run was analysed and
    no proposal was persisted", which is a different and truthful statement.

    The section is deliberately *not* merged into ``hypotheses`` or ``validated_findings``: an
    analysis record is the intelligence layer's account of what it did, not a claim about the
    target, and nothing here promotes it to one. Phase 17 still makes no model call, so each
    record's ``model_used`` names the rule-based router rather than a language model.
    """
    base = build_json_summary(
        run,
        tasks=tasks,
        tool_runs=tool_runs,
        evidence_count=evidence_count,
        asset_counts=asset_counts,
    )
    hyp_list = sorted(hypotheses, key=_hypothesis_key)
    finding_list = sorted(validated_findings, key=_hypothesis_key)
    ev_list = sorted(evidence, key=_evidence_key)
    report = {
        **base,
        _HYPOTHESES_SECTION: [_normalise(h) for h in hyp_list],
        _FINDINGS_SECTION: [_normalise(f) for f in finding_list],
        _EVIDENCE_SECTION: [_evidence_summary(e) for e in ev_list],
    }
    if attack_surface is not None:
        report[_ATTACK_SURFACE_SECTION] = dict(attack_surface)
    if ai_analysis is not None:
        report[_AI_ANALYSIS_SECTION] = [
            _normalise(a) for a in sorted(ai_analysis, key=_ai_analysis_key)
        ]
    if ai_coverage_gaps is not None:
        # Stable order by stage, then id as tie-break to be deterministic.
        gaps = sorted(
            ai_coverage_gaps,
            key=lambda g: (str(g.get("stage") or ""), str(g.get("id") or "")),
        )
        report[_AI_COVERAGE_GAPS_SECTION] = [_normalise(g) for g in gaps]
    return report


def _normalise(h: Mapping[str, Any]) -> dict[str, Any]:
    """Copy a stored hypothesis/finding item so reports never mutate the source record."""
    return {k: v for k, v in h.items()}


def render(report: Mapping[str, Any]) -> str:
    """Serialise ``report`` to deterministic, machine-valid JSON."""
    import json

    return json.dumps(report, indent=2, sort_keys=True, default=str)
