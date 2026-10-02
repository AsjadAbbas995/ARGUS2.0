"""HTML projection of the committed JSON report (``09_OUTPUTS.md`` :Report Structure).

Projects the **same** underlying report dict that ``build_report`` builds in
``reports/json_report.py`` (so JSON / Markdown / HTML all render one data object) and keeps the
truth-label contract: run/task/tool-run/asset/dedup facts and the Phase 15 projected attack-surface
graph in their own section, the Phase 17 ``ai_analysis`` records in their own section, hypotheses
in a clearly labelled ``# Hypotheses`` block with stored ``truth_label`` and ``confidence``,
validated findings separate, and the evidence chain traceable - facts are never blended with
hypotheses.

Deterministic by construction: no wall-clock, no randomness, no module state; every list is
rendered in the exact order fixed by ``build_report``; every emitted string is HTML-escaped so the
output depends only on the report dict. Byte-reproducible for identical inputs.
"""

from __future__ import annotations

from html import escape
from typing import Any, Iterable, Mapping

_SECTIONS = ("hypotheses", "validated_findings", "evidence")
_FACTS = ("run", "assets", "tasks", "tool_runs", "dedup")


def render(report: Mapping[str, Any]) -> str:
    """Render ``report`` to deterministic, escaped, facts-vs-hypotheses-separated HTML."""
    out: list[str] = [
        "<!DOCTYPE html>\n",
        "<html lang=\"en\">\n",
        "<head>\n",
        "<meta charset=\"utf-8\">\n",
        "<title>ARGUS Run Report</title>\n",
        "</head>\n",
        "<body>\n",
        "<h1>ARGUS Run Report</h1>\n",
        _facts_section(report),
        _ai_analysis_section(report),
        _hypotheses_section(report),
        _findings_section(report),
        _evidence_section(report),
        "</body>\n",
        "</html>\n",
    ]
    return "".join(out)


def _ai_analysis_section(report: Mapping[str, Any]) -> str:
    """Render the run's persisted AI analysis, or nothing when the section is absent.

    Phase 17. A missing key means "this report was built by a caller with no analysis store",
    which is different from an empty list meaning "the run was analysed and proposed nothing";
    only the latter gets a heading. Rendered before the hypotheses because these records are
    upstream of them, and never merged into ``validated_findings``.
    """
    items = report.get("ai_analysis")
    if not isinstance(items, list):
        return ""
    out: list[str] = ["<section id=\"ai_analysis\">\n", "<h2>AI Analysis</h2>\n"]
    if not items:
        out.append("<p>No AI analysis recorded.</p>\n")
        out.append("</section>\n")
        return "".join(out)
    out.append("<ul>\n")
    for item in items:
        if not isinstance(item, Mapping):
            continue
        out.append(_ai_analysis_item(item))
    out.append("</ul>\n")
    out.append("</section>\n")
    return "".join(out)


def _ai_analysis_item(item: Mapping[str, Any]) -> str:
    kind = escape(str(item.get("proposal_type") or "unknown"))
    truth = escape(str(item.get("truth_label") or "UNLABELLED"))
    agent = escape(str(item.get("agent_name") or ""))
    model = escape(str(item.get("model_used") or ""))
    ident = escape(str(item.get("id") or ""))
    out: list[str] = [
        "<li><code>{0}</code><br/>".format(ident),
        "<strong>{0}</strong> - agent={1} truth_label={2} model={3}".format(
            kind, agent, truth, model
        ),
    ]
    target = str(item.get("target") or "")
    if target:
        out.append("<br/>target={0}".format(escape(target)))
    evidence = item.get("evidence")
    if isinstance(evidence, list) and evidence:
        ids = ", ".join(escape(str(e)) for e in evidence)
        out.append("<br/>evidence=[{0}]".format(ids))
    created = str(item.get("created_at") or "")
    if created:
        out.append("<br/>created_at={0}".format(escape(created)))
    out.append("</li>\n")
    return "".join(out)


def _facts_section(report: Mapping[str, Any]) -> str:
    out: list[str] = ["<section id=\"facts\">\n", "<h2>Facts</h2>\n"]
    run = report.get("run")
    if isinstance(run, Mapping):
        out.append("<dl>\n")
        for k in ("id", "program_id", "status", "target"):
            if k in run:
                out.append("<dt>{0}</dt><dd>{1}</dd>\n".format(escape(k), escape(str(run[k]))))
        out.append("</dl>\n")
    assets = report.get("assets")
    if isinstance(assets, Mapping) and assets:
        out.append("<h3>Asset Counts</h3>\n<ul>\n")
        for name, count in sorted(assets.items()):
            out.append("<li>{0}: {1}</li>\n".format(escape(str(name)), escape(str(count))))
        out.append("</ul>\n")
    for key in ("tasks", "tool_runs", "dedup"):
        section = report.get(key)
        if isinstance(section, Mapping):
            out.append(_nested_section(key, section))
    out.append(_attack_surface_block(report))
    out.append("</section>\n")
    return "".join(out)


def _attack_surface_block(report: Mapping[str, Any]) -> str:
    """Render the Phase 15 projected graph, or nothing when it was not supplied.

    Part of the Facts section, not a sibling of it: the graph is a descriptive projection
    of recorded facts and every node/edge already carries an evidence id, so presenting it
    beside the other facts is what stops it being read as an assertion. Inferences are
    emitted with their stored ``truth_label`` and are never folded into findings. Every
    interpolated value is escaped, and key order is fixed by ``sorted()``, so the output
    stays byte-reproducible and injection-safe.
    """
    surface = report.get("attack_surface")
    if not isinstance(surface, Mapping):
        return ""
    if not surface.get("available", False):
        return (
            "<h3>Attack Surface</h3>\n<p>No canonical fact store available for this run "
            "(no attack surface was projected).</p>\n"
        )
    out: list[str] = ["<h3>Attack Surface</h3>\n", "<ul>\n"]

    records = surface.get("records")
    if isinstance(records, Mapping):
        out.append(
            "<li>records: {0}</li>\n".format(escape(str(int(records.get("count", 0)))))
        )
        by_kind = records.get("by_kind")
        if isinstance(by_kind, Mapping) and by_kind:
            rendered = ", ".join(
                "{0}={1}".format(escape(str(k)), escape(str(int(v))))
                for k, v in sorted(by_kind.items())
            )
            out.append("<li>record kinds: {0}</li>\n".format(rendered))

    graph = surface.get("graph")
    if isinstance(graph, Mapping):
        out.append(
            "<li>graph: nodes={0}, edges={1}, orphans={2}</li>\n".format(
                escape(str(int(graph.get("node_count", 0)))),
                escape(str(int(graph.get("edge_count", 0)))),
                escape(str(int(graph.get("orphan_count", 0)))),
            )
        )
        orphans = graph.get("orphans")
        if isinstance(orphans, list) and orphans:
            out.append(
                "<li>unlinked nodes: {0}</li>\n".format(
                    escape(", ".join(str(o) for o in orphans))
                )
            )

    endpoints = surface.get("endpoint_subgraph")
    if isinstance(endpoints, Mapping):
        out.append(
            "<li>endpoint subgraph: {0} node(s), {1} edge(s)</li>\n".format(
                escape(str(int(endpoints.get("node_count", 0)))),
                escape(str(int(endpoints.get("edge_count", 0)))),
            )
        )

    inferences = surface.get("inferences")
    if isinstance(inferences, Mapping):
        out.append(
            "<li>inferences: {0} (hypotheses, not findings)</li>\n".format(
                escape(str(int(inferences.get("count", 0))))
            )
        )
        items = inferences.get("items")
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, Mapping):
                    continue
                truth = escape(str(item.get("truth_label", "UNVERIFIED_CLAIM")))
                statement = escape(str(item.get("statement", "")))
                out.append(f"<li>{truth}: {statement}</li>\n")

    unproduced = surface.get("unproduced_record_kinds")
    if isinstance(unproduced, list) and unproduced:
        out.append(
            "<li>no producer yet (not projected): {0}</li>\n".format(
                escape(", ".join(str(k) for k in unproduced))
            )
        )
    out.append("</ul>\n")
    return "".join(out)


def _nested_section(name: str, section: Mapping[str, Any]) -> str:
    out: list[str] = [f"<h3>{escape(name)}</h3>\n", "<ul>\n"]
    total = section.get("total")
    if total is not None:
        out.append("<li>total: {0}</li>\n".format(escape(str(total))))
    for k, v in section.items():
        if k == "total":
            continue
        if isinstance(v, list) and v:
            out.append("<li>{0}: {1} item(s)</li>\n".format(escape(k), len(v)))
        else:
            out.append("<li>{0}: {1}</li>\n".format(escape(k), escape(str(v))))
    out.append("</ul>\n")
    return "".join(out)


def _hypotheses_section(report: Mapping[str, Any]) -> str:
    out: list[str] = ["<section id=\"hypotheses\">\n", "<h2>Hypotheses</h2>\n"]
    items = report.get("hypotheses")
    if isinstance(items, list) and items:
        out.append("<ul>\n")
        for item in items:
            if not isinstance(item, Mapping):
                continue
            out.append(_hypothesis_item(item))
        out.append("</ul>\n")
    else:
        out.append("<p>No hypotheses recorded.</p>\n")
    out.append("</section>\n")
    return "".join(out)


def _hypothesis_item(item: Mapping[str, Any]) -> str:
    truth = escape(str(item.get("truth_label", "UNVERIFIED_CLAIM")))
    statement = escape(str(item.get("statement", item.get("reasoning", ""))))
    priority = escape(str(item.get("priority", "none")))
    confidence = escape(str(item.get("confidence", 0.0)))
    out: list[str] = [
        "<li><strong>{0}</strong> - {1}<br/>".format(truth, statement),
        "<em>priority={0} confidence={1}</em></li>\n".format(priority, confidence),
    ]
    return "".join(out)


def _findings_section(report: Mapping[str, Any]) -> str:
    out: list[str] = ["<section id=\"validated_findings\">\n", "<h2>Validated Findings</h2>\n"]
    items = report.get("validated_findings")
    if isinstance(items, list) and items:
        out.append("<ul>\n")
        for item in items:
            if not isinstance(item, Mapping):
                continue
            truth = escape(str(item.get("truth_label", "VALIDATED_FINDING")))
            statement = escape(str(item.get("statement", item.get("reasoning", ""))))
            out.append("<li><strong>{0}</strong> - {1}</li>\n".format(truth, statement))
        out.append("</ul>\n")
    else:
        out.append("<p>No validated findings recorded.</p>\n")
    out.append("</section>\n")
    return "".join(out)


def _evidence_section(report: Mapping[str, Any]) -> str:
    out: list[str] = ["<section id=\"evidence\">\n", "<h2>Evidence</h2>\n"]
    items = report.get("evidence")
    if isinstance(items, list) and items:
        out.append("<ul>\n")
        for item in items:
            if not isinstance(item, Mapping):
                continue
            ref = escape(str(item.get("raw_reference", "")))
            entity = escape(str(item.get("entity_type", "")))
            entity_id = escape(str(item.get("entity_id", "")))
            run_id = escape(str(item.get("tool_run_id", "")))
            out.append(
                "<li>{0} ({1}: {2} / tool_run {3})</li>\n".format(ref, entity, entity_id, run_id)
            )
        out.append("</ul>\n")
    else:
        out.append("<p>No evidence recorded.</p>\n")
    out.append("</section>\n")
    return "".join(out)
