"""ReconAgent ("07_AI_AGENTS.md" §ReconAgent, "03_RECON_PIPELINE.md" §recon stages).

Proposes the next in-scope reconnaissance *task* (Common Output ``type="task"``) from the
caller-evidenced coverage gaps, in the documented recon-stage priority order. Emits no
proposal when no gap remains or when no recorded observation supports one. Never proposes an
out-of-scope target, never invents evidence, and never executes anything.

Only :data:`AI_SCHEDULABLE_STAGES` may be proposed here. The expansion-owned stages require an
evidence-backed URL seed, and this agent only knows the scope-root hostname; scheduling them
from here would enqueue an adapter call with the wrong kind of target.
"""

from __future__ import annotations

from typing import Optional

from .context import ReconContext
from .contract import evidence, proposal
from .route import route
from .router import RouteConfig

ROUTE_TASK = "complex_recon_planning"

# Documented recon stages in fixed planning priority (03_RECON_PIPELINE.md).
STAGE_PRIORITY = (
    "subdomain_enum",
    "dns_resolve",
    "port_scan",
    "http_probe",
    "tech_detect",
    "web_crawl",
    "content_discover",
    "historical_recon",
    "js_analysis",
    "api_discover",
    "openapi_schema",
    "graphql_recon",
    "websocket_recon",
    "parameter_intel",
    "auth_intel",
    "authz_analysis",
    "logic_analysis",
    "cloud_intel",
    "cdn_waf_intel",
)

#: Stages the AI planner may schedule directly. Their adapters accept the scope-root
#: hostname target :func:`_propose_stage` supplies.
AI_SCHEDULABLE_STAGES = frozenset(
    {
        "subdomain_enum",
        "dns_resolve",
        "port_scan",
        "http_probe",
        "tech_detect",
        "historical_recon",
    }
)

#: Stages scheduled only by deterministic discovery expansion. Their adapters require an
#: evidence-backed URL seed, not the bare hostname the AI planner has.
EXPANSION_OWNED_STAGES = frozenset({"web_crawl", "content_discover", "js_analysis"})

#: Stages in :data:`STAGE_PRIORITY` that no current adapter can execute. Derived rather than
#: listed so a newly added stage cannot silently disappear from the ownership partition.
NO_CAPABILITY_STAGES = frozenset(STAGE_PRIORITY) - AI_SCHEDULABLE_STAGES - EXPANSION_OWNED_STAGES

#: The single scheduling owner for every documented stage. Exactly one value per stage.
STAGE_OWNERSHIP: dict[str, str] = {
    stage: (
        "ai_schedulable"
        if stage in AI_SCHEDULABLE_STAGES
        else "expansion_owned"
        if stage in EXPANSION_OWNED_STAGES
        else "no_capability"
    )
    for stage in STAGE_PRIORITY
}


def run(ctx: ReconContext, cfg: Optional[RouteConfig] = None) -> Optional[dict]:
    """Return one schema-valid task proposal for the next uncovered AI-schedulable stage."""
    route(ROUTE_TASK, complexity="medium", reasoning_depth="high", cfg=cfg)

    for stage in STAGE_PRIORITY:
        if stage in AI_SCHEDULABLE_STAGES and stage in ctx.gaps:
            return _propose_stage(ctx, stage)
    return None


def _propose_stage(ctx: ReconContext, stage: str) -> Optional[dict]:
    obs = next((o for o in ctx.observations if stage in o.source.lower()), None)
    if obs is None:
        obs = ctx.observations[0] if ctx.observations else None
    asset = ctx.assets[0] if ctx.assets else None

    if obs is not None:
        cited = [evidence(statement=obs.statement, source=obs.evidence_id)]
    elif asset is not None:
        cited = [evidence(statement=f"asset `{asset.hostname}` recorded", source=asset.evidence_id)]
    else:
        return None

    return proposal(
        type="task",
        target=ctx.scope.root,
        observation=f"recon stage `{stage}` is uncovered",
        reasoning=f"{ROUTE_TASK}: next in-scope recon task by documented planning priority",
        potential_issue="task proposal; must pass the scope guard and Task Planner before execution",
        evidence=cited,
        confidence=0.85,
        priority="high",
        validation_step="scope-guard check, then schedule via Task Planner (DevMode)",
        truth_label="INFERENCE",
    )