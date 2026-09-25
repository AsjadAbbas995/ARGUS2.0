"""Concrete repositories mapping models to their ``05_DATA_MODEL.md`` tables.

All persistence honors the documented UNIQUE/CHECK constraints; duplicate-safe
inserts (upserts) are used where the data model allows deduplication.

Each per-table repository owns its SQL and speaks rows. The ``Repositories``
facade at the bottom of this module additionally implements the flat
``core.orchestrator.Storage`` contract, so the production chain is exactly
``Orchestrator -> Storage contract -> Repositories -> PostgreSQL`` with no
second storage abstraction. The contract methods are the single place the two
views meet: they delegate to the table repository that owns the SQL and map
rows back to the committed dataclass entities the contract is written in.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Iterable, Mapping, Optional
from uuid import UUID

import psycopg

from core.orchestrator import Storage
from database.models.entities import (
    Asset,
    AssetIp,
    DnsRecord,
    Evidence,
    Hypothesis,
    Ip,
    Organization,
    Port,
    Program,
    Run,
    ScopeRule,
    Task,
    ToolRun,
    WebApp,
)
from database.repositories.base import BaseRepository


# -- row -> entity mapping ---------------------------------------------------
#
# The Storage contract is expressed in the committed dataclasses, while the
# repositories speak dict rows. These mappers are the only translation point.
# ``numeric`` columns come back from psycopg as ``Decimal``; the entities
# declare ``float``, so they are narrowed here to keep the Postgres-backed
# storage observationally equal to the in-memory test double.

def _as_float(value: Any) -> Any:
    return float(value) if isinstance(value, Decimal) else value


def _run_from_row(row: Optional[Mapping[str, Any]]) -> Optional[Run]:
    if row is None:
        return None
    return Run(
        id=row["id"],
        program_id=row["program_id"],
        status=row["status"],
        target=row["target"],
        configuration_snapshot=row["configuration_snapshot"] or {},
        started_at=row["started_at"],
        completed_at=row["completed_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _task_from_row(row: Optional[Mapping[str, Any]]) -> Optional[Task]:
    if row is None:
        return None
    return Task(
        id=row["id"],
        run_id=row["run_id"],
        type=row["type"],
        target=row["target"],
        parent_task_id=row["parent_task_id"],
        priority=_as_float(row["priority"]),
        status=row["status"],
        fingerprint=row["fingerprint"],
        reason=row["reason"],
        created_at=row["created_at"],
        started_at=row["started_at"],
        completed_at=row["completed_at"],
    )


def _tool_run_from_row(row: Optional[Mapping[str, Any]]) -> Optional[ToolRun]:
    if row is None:
        return None
    return ToolRun(
        id=row["id"],
        task_id=row["task_id"],
        tool_name=row["tool_name"],
        command=list(row["command"] or []),
        exit_code=row["exit_code"],
        raw_output_ref=row["raw_output_ref"],
        started_at=row["started_at"],
        completed_at=row["completed_at"],
    )


def _hypothesis_from_row(row: Optional[Mapping[str, Any]]) -> Optional[Hypothesis]:
    if row is None:
        return None
    return Hypothesis(
        id=row["id"],
        run_id=row["run_id"],
        endpoint_id=row["endpoint_id"],
        statement=row["statement"],
        truth_label=row["truth_label"],
        confidence=_as_float(row["confidence"]),
        severity=row["severity"],
        priority=row["priority"],
        status=row["status"],
        target=row["target"],
        validation_step=row["validation_step"],
        review_status=row["review_status"],
        review_reason=row["review_reason"],
    )


class OrganizationRepository(BaseRepository):
    def upsert(self, name: str) -> dict:
        cur = self.conn.execute(
            "INSERT INTO organizations (name) VALUES (%s) "
            "ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name "
            "RETURNING *",
            (name,),
        )
        return cur.fetchone()

    def get(self, organization_id) -> Optional[dict]:
        return self._fetch_one(
            "SELECT * FROM organizations WHERE id = %s", (organization_id,)
        )


class ProgramRepository(BaseRepository):
    def upsert(self, organization_id, name: str, status: str = "active") -> dict:
        cur = self.conn.execute(
            "INSERT INTO programs (organization_id, name, status) VALUES (%s, %s, %s) "
            "ON CONFLICT (organization_id, name) "
            "DO UPDATE SET status = EXCLUDED.status "
            "RETURNING *",
            (organization_id, name, status),
        )
        return cur.fetchone()

    def get(self, program_id) -> Optional[dict]:
        return self._fetch_one("SELECT * FROM programs WHERE id = %s", (program_id,))


class RunRepository(BaseRepository):
    def insert(self, run: Run) -> dict:
        return self._insert(
            "runs",
            {
                # The entity id is authoritative: the Orchestrator holds the Run
                # object and later addresses it by this id, so the row must keep
                # it rather than let the database mint a different one.
                "id": run.id,
                "program_id": run.program_id,
                "status": run.status,
                "target": run.target,
                "configuration_snapshot": psycopg.types.json.Jsonb(
                    run.configuration_snapshot
                ),
                "started_at": run.started_at,
                "completed_at": run.completed_at,
                "created_at": run.created_at,
                "updated_at": run.updated_at,
            },
        )

    def get(self, run_id) -> Optional[dict]:
        return self._fetch_one("SELECT * FROM runs WHERE id = %s", (run_id,))

    def list_runs(self) -> list[dict]:
        return self._fetch_all("SELECT * FROM runs ORDER BY created_at, id")

    def update_status(self, run_id, status: str) -> dict:
        cur = self.conn.execute(
            "UPDATE runs SET status = %s, updated_at = now() WHERE id = %s RETURNING *",
            (status, run_id),
        )
        return cur.fetchone()

    def mark_started(self, run_id) -> dict:
        cur = self.conn.execute(
            "UPDATE runs SET status = 'RECONNING', started_at = now(), "
            "updated_at = now() WHERE id = %s RETURNING *",
            (run_id,),
        )
        return cur.fetchone()

    def mark_completed(self, run_id) -> dict:
        cur = self.conn.execute(
            "UPDATE runs SET status = 'COMPLETED', completed_at = now(), "
            "updated_at = now() WHERE id = %s RETURNING *",
            (run_id,),
        )
        return cur.fetchone()

    def mark_failed(self, run_id) -> dict:
        cur = self.conn.execute(
            "UPDATE runs SET status = 'FAILED', completed_at = now(), "
            "updated_at = now() WHERE id = %s RETURNING *",
            (run_id,),
        )
        return cur.fetchone()


class ScopeRuleRepository(BaseRepository):
    def upsert(self, rule: ScopeRule) -> dict:
        cur = self.conn.execute(
            "INSERT INTO scope_rules (program_id, rule_type, value, allowed) "
            "VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (program_id, rule_type, value) "
            "DO UPDATE SET allowed = EXCLUDED.allowed "
            "RETURNING *",
            (rule.program_id, rule.rule_type, rule.value, rule.allowed),
        )
        return cur.fetchone()

    def list_for_program(self, program_id) -> list[dict]:
        return self._fetch_all(
            "SELECT * FROM scope_rules WHERE program_id = %s", (program_id,)
        )


class AssetRepository(BaseRepository):
    def upsert(self, asset: Asset) -> dict:
        cur = self.conn.execute(
            "INSERT INTO assets (program_id, hostname, source, discovered_at) "
            "VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (program_id, hostname) "
            "DO UPDATE SET source = EXCLUDED.source "
            "RETURNING *",
            (asset.program_id, asset.hostname, asset.source, asset.discovered_at),
        )
        return cur.fetchone()

    def get_by_hostname(self, program_id, hostname: str) -> Optional[dict]:
        return self._fetch_one(
            "SELECT * FROM assets WHERE program_id = %s AND hostname = %s",
            (program_id, hostname),
        )

    def search_hostname(self, hostname: str) -> list[dict]:
        return self._fetch_all(
            "SELECT * FROM assets WHERE hostname = %s", (hostname,)
        )


class IpRepository(BaseRepository):
    def upsert(self, address: str) -> dict:
        cur = self.conn.execute(
            "INSERT INTO ips (address) VALUES (%s) "
            "ON CONFLICT (address) DO UPDATE SET address = EXCLUDED.address "
            "RETURNING id, address::text AS address, first_seen",
            (address,),
        )
        return cur.fetchone()


class AssetIpRepository(BaseRepository):
    def upsert(self, asset_id, ip_id) -> dict:
        cur = self.conn.execute(
            "INSERT INTO asset_ips (asset_id, ip_id) VALUES (%s, %s) "
            "ON CONFLICT (asset_id, ip_id) DO NOTHING RETURNING *",
            (asset_id, ip_id),
        )
        return cur.fetchone()


class DnsRecordRepository(BaseRepository):
    def insert(self, record: DnsRecord) -> dict:
        return self._insert(
            "dns_records",
            {
                "asset_id": record.asset_id,
                "record_type": record.record_type,
                "value": record.value,
                "resolved_at": record.resolved_at,
            },
            returning=("id", "asset_id", "record_type", "value"),
        )

    def list_for_asset(self, asset_id) -> list[dict]:
        return self._fetch_all(
            "SELECT * FROM dns_records WHERE asset_id = %s", (asset_id,)
        )


class PortRepository(BaseRepository):
    def upsert(self, port: Port) -> dict:
        cur = self.conn.execute(
            "INSERT INTO ports (ip_id, port_number, protocol, state, service, version) "
            "VALUES (%s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (ip_id, port_number, protocol) "
            "DO UPDATE SET state = EXCLUDED.state, service = EXCLUDED.service, "
            "version = EXCLUDED.version "
            "RETURNING *",
            (
                port.ip_id,
                port.port_number,
                port.protocol,
                port.state,
                port.service,
                port.version,
            ),
        )
        return cur.fetchone()

    def get_by_ip_port(self, ip_id, port_number: int, protocol: str = "tcp"):
        return self._fetch_one(
            "SELECT * FROM ports WHERE ip_id = %s AND port_number = %s "
            "AND protocol = %s",
            (ip_id, port_number, protocol),
        )


class WebAppRepository(BaseRepository):
    def upsert(self, app: WebApp) -> dict:
        cur = self.conn.execute(
            "INSERT INTO web_apps "
            "(asset_id, port_id, status_code, title, server_header) "
            "VALUES (%s, %s, %s, %s, %s) "
            "ON CONFLICT (asset_id, port_id) "
            "DO UPDATE SET status_code = EXCLUDED.status_code, "
            "title = EXCLUDED.title, server_header = EXCLUDED.server_header "
            "RETURNING *",
            (
                app.asset_id,
                app.port_id,
                app.status_code,
                app.title,
                app.server_header,
            ),
        )
        return cur.fetchone()


class TaskRepository(BaseRepository):
    def insert(self, task: Task) -> dict:
        return self._insert(
            "tasks",
            {
                "id": task.id,
                "run_id": task.run_id,
                "type": task.type,
                "target": task.target,
                "parent_task_id": task.parent_task_id,
                "priority": task.priority,
                "status": task.status,
                "fingerprint": task.fingerprint,
                "reason": task.reason,
                "created_at": task.created_at,
                "started_at": task.started_at,
                "completed_at": task.completed_at,
            },
        )

    def get_by_fingerprint(self, run_id, fingerprint: str) -> Optional[dict]:
        return self._fetch_one(
            "SELECT * FROM tasks WHERE run_id = %s AND fingerprint = %s",
            (run_id, fingerprint),
        )

    def list_for_run(self, run_id) -> list[dict]:
        return self._fetch_all(
            "SELECT * FROM tasks WHERE run_id = %s ORDER BY created_at", (run_id,)
        )

    def list_by_status(self, run_id, status: str) -> list[dict]:
        return self._fetch_all(
            "SELECT * FROM tasks WHERE run_id = %s AND status = %s ORDER BY created_at",
            (run_id, status),
        )

    def update_status(self, task_id, status: str, completed: bool = False) -> dict:
        completed_sql = ", completed_at = now()" if completed else ""
        cur = self.conn.execute(
            f"UPDATE tasks SET status = %s, "
            f"started_at = COALESCE(started_at, now()) {completed_sql} "
            f"WHERE id = %s RETURNING *",
            (status, task_id),
        )
        return cur.fetchone()


class ToolRunRepository(BaseRepository):
    def insert(self, run: ToolRun) -> dict:
        return self._insert(
            "tool_runs",
            {
                "id": run.id,
                "task_id": run.task_id,
                "tool_name": run.tool_name,
                "command": run.command,
                "exit_code": run.exit_code,
                "raw_output_ref": run.raw_output_ref,
                "started_at": run.started_at,
                "completed_at": run.completed_at,
            },
        )

    def finalize(self, tool_run_id, exit_code: int, raw_output_ref: Optional[str]):
        cur = self.conn.execute(
            "UPDATE tool_runs SET exit_code = %s, raw_output_ref = %s, "
            "completed_at = now() WHERE id = %s RETURNING *",
            (exit_code, raw_output_ref, tool_run_id),
        )
        return cur.fetchone()


class EvidenceRepository(BaseRepository):
    def insert(self, evidence: Evidence) -> dict:
        return self._insert(
            "evidence",
            {
                "tool_run_id": evidence.tool_run_id,
                "entity_type": evidence.entity_type,
                "entity_id": evidence.entity_id,
                "raw_reference": evidence.raw_reference,
            },
        )


class HypothesisRepository(BaseRepository):
    """Canonical ``hypotheses`` table access (05_DATA_MODEL.md).

    Hypotheses are run-scoped review items: every read and write is qualified by
    ``run_id`` so one run can never observe or mutate another run's hypotheses.
    Analytical state (``truth_label``/``status``) and operator review state
    (``review_status``/``review_reason``) are persisted as independent columns.
    """

    def insert(self, hypothesis: Hypothesis) -> dict:
        return self._insert(
            "hypotheses",
            {
                "id": hypothesis.id,
                "run_id": hypothesis.run_id,
                "endpoint_id": hypothesis.endpoint_id,
                "statement": hypothesis.statement,
                "truth_label": hypothesis.truth_label,
                "confidence": hypothesis.confidence,
                "severity": hypothesis.severity,
                "priority": hypothesis.priority,
                "status": hypothesis.status,
                "target": hypothesis.target,
                "validation_step": hypothesis.validation_step,
                "review_status": hypothesis.review_status,
                "review_reason": hypothesis.review_reason,
            },
        )

    def get(self, run_id, hypothesis_id) -> Optional[dict]:
        return self._fetch_one(
            "SELECT * FROM hypotheses WHERE run_id = %s AND id = %s",
            (run_id, hypothesis_id),
        )

    def list_for_run(self, run_id) -> list[dict]:
        return self._fetch_all(
            "SELECT * FROM hypotheses WHERE run_id = %s ORDER BY id", (run_id,)
        )

    def set_review(
        self,
        run_id,
        hypothesis_id,
        review_status: str,
        review_reason: Optional[str],
        truth_label: str,
        status: str,
    ) -> Optional[dict]:
        cur = self.conn.execute(
            "UPDATE hypotheses SET review_status = %s, review_reason = %s, "
            "truth_label = %s, status = %s "
            "WHERE run_id = %s AND id = %s RETURNING *",
            (review_status, review_reason, truth_label, status, run_id, hypothesis_id),
        )
        return cur.fetchone()


class Repositories(Storage):
    """Aggregate facade over all repositories sharing one connection.

    Doubles as the production implementation of the flat ``Storage`` contract
    (``core.orchestrator.Storage``): the orchestrator is written against that
    contract only, so making this class conform is what turns
    ``Orchestrator -> Storage -> PostgreSQL`` into a real chain instead of an
    aspiration. Every contract method delegates to the per-table repository
    that already owns the SQL; nothing here duplicates a query.
    """

    def __init__(self, conn: psycopg.Connection):
        self.conn = conn
        self.organizations = OrganizationRepository(conn)
        self.programs = ProgramRepository(conn)
        self.runs = RunRepository(conn)
        self.scope_rules = ScopeRuleRepository(conn)
        self.assets = AssetRepository(conn)
        self.ips = IpRepository(conn)
        self.asset_ips = AssetIpRepository(conn)
        self.dns_records = DnsRecordRepository(conn)
        self.ports = PortRepository(conn)
        self.web_apps = WebAppRepository(conn)
        self.tasks = TaskRepository(conn)
        self.tool_runs = ToolRunRepository(conn)
        self.evidence = EvidenceRepository(conn)
        self.hypotheses = HypothesisRepository(conn)

    # -- core.orchestrator.Storage contract ----------------------------------
    #
    # Returns the committed dataclass entities, never rows, so the orchestrator
    # cannot tell this apart from any other conforming Storage implementation.

    def create_run(self, run: Run) -> Run:
        return _run_from_row(self.runs.insert(run))

    def get_run(self, run_id: UUID) -> Optional[Run]:
        return _run_from_row(self.runs.get(run_id))

    def list_runs(self) -> list[Run]:
        return [_run_from_row(row) for row in self.runs.list_runs()]

    def set_run_status(self, run_id: UUID, status: str) -> None:
        self.runs.update_status(run_id, status)

    def insert_tasks(self, tasks: Iterable[Task]) -> None:
        for task in tasks:
            self.tasks.insert(task)

    def list_tasks(self, run_id: UUID) -> list[Task]:
        return [_task_from_row(row) for row in self.tasks.list_for_run(run_id)]

    def list_tasks_by_status(self, run_id: UUID, status: str) -> list[Task]:
        return [_task_from_row(row) for row in self.tasks.list_by_status(run_id, status)]

    def set_task_status(self, task_id: UUID, status: str) -> None:
        self.tasks.update_status(task_id, status)

    def insert_tool_run(self, tr: ToolRun) -> ToolRun:
        return _tool_run_from_row(self.tool_runs.insert(tr))

    def finalize_tool_run(
        self, tool_run_id: UUID, exit_code: int, raw_output_ref: Optional[str]
    ) -> None:
        self.tool_runs.finalize(tool_run_id, exit_code, raw_output_ref)

    def insert_hypothesis(self, hypothesis: Hypothesis) -> Hypothesis:
        return _hypothesis_from_row(self.hypotheses.insert(hypothesis))

    def get_hypothesis(
        self, run_id: UUID, hypothesis_id: UUID
    ) -> Optional[Hypothesis]:
        return _hypothesis_from_row(self.hypotheses.get(run_id, hypothesis_id))

    def list_hypotheses(self, run_id: UUID) -> list[Hypothesis]:
        return [_hypothesis_from_row(row) for row in self.hypotheses.list_for_run(run_id)]

    def set_hypothesis_review(
        self,
        run_id: UUID,
        hypothesis_id: UUID,
        review_status: str,
        review_reason: Optional[str],
        truth_label: str,
        status: str,
    ) -> Optional[Hypothesis]:
        return _hypothesis_from_row(
            self.hypotheses.set_review(
                run_id, hypothesis_id, review_status, review_reason, truth_label, status
            )
        )