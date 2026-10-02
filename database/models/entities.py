"""Milestone-relevant entity models (Step 3).

Maps the ``05_DATA_MODEL.md`` tables that Milestone 1 touches: organizations,
programs, runs, scope_rules, assets, dns_records, ips, asset_ips, ports, web_apps,
tasks, tool_runs, evidence, ai_analysis, hypotheses.

``Hypothesis`` is the canonical persistent hypothesis record backing the
``hypotheses`` table. It is distinct from the AI-layer ``ai.context.HypothesisRecord``,
which is an immutable agent input/output DTO and never persisted directly. Analytical
state (``truth_label`` / ``status``) and operator review state
(``review_status`` / ``review_reason``) are stored independently.

``AiAnalysis`` is distinct from both: it is the audit record of one agent
invocation (Phase 16), and it is where the evidence ids a proposal cited are
preserved, because ``hypotheses`` has no column for them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> UUID:
    return uuid4()


@dataclass
class Organization:
    id: UUID = field(default_factory=_uuid)
    name: str = ""
    created_at: datetime = field(default_factory=_now)


@dataclass
class Program:
    id: UUID = field(default_factory=_uuid)
    organization_id: UUID = field(default_factory=_uuid)
    name: str = ""
    status: str = "active"  # active / paused / closed


@dataclass
class Run:
    id: UUID = field(default_factory=_uuid)
    program_id: UUID = field(default_factory=_uuid)
    status: str = "CREATED"
    target: str = ""
    configuration_snapshot: dict = field(default_factory=dict)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=_now)
    updated_at: datetime = field(default_factory=_now)
    # Phase-8 adaptive-loop progress. These are properties of the *run*, not of
    # the process driving it, so they are persisted on the run row: a resumed run
    # must not restart its pass budget or forget that the last pass produced work.
    loop_pass: int = 0
    pass_new_tasks: bool = False


@dataclass
class ScopeRule:
    id: UUID = field(default_factory=_uuid)
    program_id: UUID = field(default_factory=_uuid)
    rule_type: str = "domain"  # domain / subdomain / ip / cidr / port / exclusion
    value: str = ""
    allowed: bool = True


@dataclass
class Asset:
    id: UUID = field(default_factory=_uuid)
    program_id: UUID = field(default_factory=_uuid)
    hostname: str = ""
    source: str = ""
    discovered_at: datetime = field(default_factory=_now)


@dataclass
class DnsRecord:
    id: UUID = field(default_factory=_uuid)
    asset_id: UUID = field(default_factory=_uuid)
    record_type: str = "A"
    value: str = ""
    resolved_at: datetime = field(default_factory=_now)


@dataclass
class Ip:
    id: UUID = field(default_factory=_uuid)
    address: str = ""
    first_seen: datetime = field(default_factory=_now)


@dataclass
class AssetIp:
    asset_id: UUID = field(default_factory=_uuid)
    ip_id: UUID = field(default_factory=_uuid)
    observed_at: datetime = field(default_factory=_now)


@dataclass
class Port:
    id: UUID = field(default_factory=_uuid)
    ip_id: UUID = field(default_factory=_uuid)
    port_number: int = 0
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None


@dataclass
class WebApp:
    id: UUID = field(default_factory=_uuid)
    asset_id: UUID = field(default_factory=_uuid)
    port_id: UUID = field(default_factory=_uuid)
    status_code: Optional[int] = None
    title: Optional[str] = None
    server_header: Optional[str] = None


@dataclass
class Task:
    id: UUID = field(default_factory=_uuid)
    run_id: UUID = field(default_factory=_uuid)
    type: str = ""
    target: str = ""
    parent_task_id: Optional[UUID] = None
    priority: Optional[float] = None
    status: str = "pending"  # pending / running / completed / failed / skipped / cancelled
    fingerprint: str = ""
    reason: Optional[str] = None
    created_at: datetime = field(default_factory=_now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass
class ToolRun:
    id: UUID = field(default_factory=_uuid)
    task_id: UUID = field(default_factory=_uuid)
    tool_name: str = ""
    command: list[str] = field(default_factory=list)
    exit_code: Optional[int] = None
    raw_output_ref: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass
class Evidence:
    id: UUID = field(default_factory=_uuid)
    tool_run_id: Optional[UUID] = None
    entity_type: str = ""
    entity_id: Optional[UUID] = None
    raw_reference: Optional[str] = None


@dataclass
class AiAnalysis:
    """One agent invocation and its structured output (``ai_analysis`` table).

    This is the Phase-16 record of *what the intelligence layer actually did*: which agent
    ran, which model the Phase-6 router selected, a reference to the context it was given,
    and the full Common Output Contract object it emitted.

    It exists because ``hypotheses`` cannot carry that. The table has no ``evidence_id``
    column, so the ``evidence`` array every proposal must cite (``07_AI_AGENTS.md`` "AI
    Safety Boundary") has nowhere to live on the hypothesis row itself. The cited ids are
    preserved here in ``output`` instead, which is why a hypothesis is only trustworthy
    when the ``ai_analysis`` row that produced it is retained alongside it.
    """

    id: UUID = field(default_factory=_uuid)
    agent_name: str = ""
    model_used: str = ""
    input_context_ref: Optional[str] = None
    output: dict = field(default_factory=dict)
    created_at: Optional[datetime] = None


@dataclass
class Hypothesis:
    id: UUID = field(default_factory=_uuid)
    run_id: UUID = field(default_factory=_uuid)
    endpoint_id: Optional[UUID] = None
    statement: str = ""
    truth_label: str = "HYPOTHESIS"
    confidence: float = 0.0
    severity: str = "low"
    priority: str = "low"
    status: str = "open"
    target: str = ""
    validation_step: str = ""
    review_status: str = "pending"
    review_reason: Optional[str] = None