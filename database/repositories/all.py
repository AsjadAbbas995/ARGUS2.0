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

from contextlib import contextmanager
from dataclasses import replace
from decimal import Decimal
from typing import Any, Iterable, Mapping, Optional, Sequence
from uuid import UUID

import psycopg

from core.orchestrator import Storage, _RUN_TERMINAL, _TASK_STARTED, _TASK_TERMINAL
from database.projection import RunFacts, project, serialize
from recon.ingest import (
    ENTITY_ARTIFACT_CAP,
    ENTITY_ASSET,
    ENTITY_ASSET_IP,
    ENTITY_ASSET_TECHNOLOGY,
    ENTITY_DNS_RECORD,
    ENTITY_ENDPOINT,
    ENTITY_IP,
    ENTITY_JAVASCRIPT,
    ENTITY_OBSERVED_HOST,
    ENTITY_OBSERVED_IP,
    ENTITY_OBSERVED_WEB_APP,
    ENTITY_PARAMETER,
    ENTITY_PORT,
    ENTITY_TECHNOLOGY,
    ENTITY_URL,
    ENTITY_WEB_APP,
    KIND_IP,
)
from database.models.entities import (
    AiAnalysis,
    AiCoverageGap,
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
        loop_pass=row["loop_pass"],
        pass_new_tasks=row["pass_new_tasks"],
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


def _evidence_from_row(row: Optional[Mapping[str, Any]]) -> Optional[Evidence]:
    if row is None:
        return None
    return Evidence(
        id=row["id"],
        tool_run_id=row["tool_run_id"],
        entity_type=row["entity_type"],
        entity_id=row["entity_id"],
        raw_reference=row["raw_reference"],
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
                "loop_pass": run.loop_pass,
                "pass_new_tasks": run.pass_new_tasks,
            },
        )

    def get(self, run_id) -> Optional[dict]:
        return self._fetch_one("SELECT * FROM runs WHERE id = %s", (run_id,))

    def list_runs(self) -> list[dict]:
        return self._fetch_all("SELECT * FROM runs ORDER BY created_at, id")

    def update_status(self, run_id, status: str) -> dict:
        # Terminal run statuses must stamp completed_at; otherwise a finished run
        # is indistinguishable from one that was abandoned mid-flight.
        completed_sql = ", completed_at = now()" if status in _RUN_TERMINAL else ""
        cur = self.conn.execute(
            f"UPDATE runs SET status = %s, updated_at = now() {completed_sql} "
            "WHERE id = %s RETURNING *",
            (status, run_id),
        )
        return cur.fetchone()

    def update_loop_progress(
        self, run_id, loop_pass: int, pass_new_tasks: bool
    ) -> dict:
        cur = self.conn.execute(
            "UPDATE runs SET loop_pass = %s, pass_new_tasks = %s, updated_at = now() "
            "WHERE id = %s RETURNING *",
            (loop_pass, pass_new_tasks, run_id),
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

    def list_by_ids(self, asset_ids: Sequence[UUID]) -> list[dict]:
        """Assets by primary key, for a caller that already resolved the ids.

        The caller supplies ids it legitimately owns (Phase 15 derives them from this
        run's own evidence rows), so this read is deliberately a primary-key lookup and
        not a second authorization decision. ``hostname`` is returned with an explicit
        collation-free ordering so the caller's transformation stays deterministic.
        """
        if not asset_ids:
            return []
        return self._fetch_all(
            "SELECT * FROM assets WHERE id = ANY(%s::uuid[]) ORDER BY hostname, id",
            (list(asset_ids),),
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

    def list_by_ids(self, ip_ids: Sequence[UUID]) -> list[dict]:
        """IPs by primary key, with ``address`` as the bare host address.

        ``host()`` rather than the ``address::text`` used by :meth:`upsert`, and the
        difference is deliberate. ``ips.address`` is ``inet``, so ``::text`` renders the
        prefix length too (``93.184.216.34/32``) -- PostgreSQL's canonical form, which is
        what the write path returns and what ``tests/test_database_live.py`` pins.

        This read feeds the correlation layer, where the same string becomes a graph node
        *key* and an ``IpRecord.address``/``PortRecord.ip`` value. Phase 14 was handed a
        bare address (``IpObservation.address``), and ``93.184.216.34/32:443`` is not the
        port key any other projection of that observation produces. Spelling the address
        the way it was observed is what keeps the Postgres-backed graph identical to the
        in-memory one.
        """
        if not ip_ids:
            return []
        return self._fetch_all(
            "SELECT id, host(address) AS address, first_seen FROM ips "
            "WHERE id = ANY(%s::uuid[]) ORDER BY address, id",
            (list(ip_ids),),
        )


class AssetIpRepository(BaseRepository):
    def upsert(self, asset_id, ip_id) -> dict:
        cur = self.conn.execute(
            "INSERT INTO asset_ips (asset_id, ip_id) VALUES (%s, %s) "
            "ON CONFLICT (asset_id, ip_id) DO NOTHING RETURNING *",
            (asset_id, ip_id),
        )
        return cur.fetchone()

    def list_for_asset(self, asset_id) -> list[dict]:
        """IPs already known for an asset.

        Phase 14 needs this because ``web_apps.port_id`` is NOT NULL and an
        ``ips`` row must exist before a port can be created: a web observation is
        only rooted when the asset already has a known IP. Ingestion never
        resolves a host itself to manufacture one.
        """
        return self._fetch_all(
            "SELECT * FROM asset_ips WHERE asset_id = %s ORDER BY observed_at",
            (asset_id,),
        )

    def ip_id_for_asset(self, asset_id) -> Optional[UUID]:
        row = self._fetch_one(
            "SELECT ip_id FROM asset_ips WHERE asset_id = %s ORDER BY observed_at LIMIT 1",
            (asset_id,),
        )
        return row["ip_id"] if row else None

    def list_for_assets(self, asset_ids: Sequence[UUID]) -> list[dict]:
        """Host -> IP bindings for a set of assets.

        Read-only support for the Phase 15 projection. Run attribution for this edge is
        resolved by the caller through endpoint containment (both endpoints evidenced in
        the same run), never from ``observed_at``: ``asset_ips`` has no ``evidence_id``
        column and its composite primary key gives no single row id to cite, so its own
        timestamps say nothing about *which run* created the binding.
        """
        if not asset_ids:
            return []
        return self._fetch_all(
            "SELECT asset_id, ip_id FROM asset_ips "
            "WHERE asset_id = ANY(%s::uuid[]) ORDER BY asset_id, ip_id",
            (list(asset_ids),),
        )


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

    def list_by_ids(self, port_ids: Sequence[UUID]) -> list[dict]:
        """Ports by primary key (Phase 15 projection read)."""
        if not port_ids:
            return []
        return self._fetch_all(
            "SELECT * FROM ports WHERE id = ANY(%s::uuid[]) "
            "ORDER BY port_number, ip_id, id",
            (list(port_ids),),
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

    def list_by_ids(self, web_app_ids: Sequence[UUID]) -> list[dict]:
        """Web applications by primary key (Phase 15 projection read)."""
        if not web_app_ids:
            return []
        return self._fetch_all(
            "SELECT * FROM web_apps WHERE id = ANY(%s::uuid[]) ORDER BY id",
            (list(web_app_ids),),
        )

    def get_by_asset_port(self, asset_id, port_id) -> Optional[dict]:
        """The web app for one (asset, port) pair, or None (Phase 22 rooting)."""
        return self._fetch_one(
            "SELECT * FROM web_apps WHERE asset_id = %s AND port_id = %s",
            (asset_id, port_id),
        )


class UrlRepository(BaseRepository):
    def upsert(self, web_app_id, path: str, source: str, historical: bool) -> dict:
        # Phase 24: ``historical`` is ANDed on conflict so a URL is only historical
        # while *every* observation of it has been historical. A live observation of
        # the same (web_app_id, path) clears the flag and takes over ``source``; a
        # historical re-observation of an already-live URL leaves the live source.
        cur = self.conn.execute(
            "INSERT INTO urls (web_app_id, path, source, historical) "
            "VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (web_app_id, path) DO UPDATE SET "
            "historical = urls.historical AND EXCLUDED.historical, "
            "source = CASE "
            "WHEN NOT EXCLUDED.historical THEN EXCLUDED.source "
            "WHEN urls.historical THEN EXCLUDED.source "
            "ELSE urls.source END "
            "RETURNING *",
            (web_app_id, path, source, historical),
        )
        return cur.fetchone()

    def list_by_ids(self, url_ids: Sequence[UUID]) -> list[dict]:
        if not url_ids:
            return []
        return self._fetch_all(
            "SELECT * FROM urls WHERE id = ANY(%s::uuid[]) "
            "ORDER BY path, web_app_id, id",
            (list(url_ids),),
        )


class EndpointRepository(BaseRepository):
    def upsert(self, url_id, method: str, pattern: str) -> dict:
        cur = self.conn.execute(
            "INSERT INTO endpoints (url_id, method, pattern) VALUES (%s, %s, %s) "
            "ON CONFLICT (url_id, method, pattern) DO UPDATE SET pattern = EXCLUDED.pattern "
            "RETURNING *",
            (url_id, method, pattern),
        )
        return cur.fetchone()

    def list_by_ids(self, endpoint_ids: Sequence[UUID]) -> list[dict]:
        if not endpoint_ids:
            return []
        return self._fetch_all(
            "SELECT * FROM endpoints WHERE id = ANY(%s::uuid[]) "
            "ORDER BY pattern, method, url_id, id",
            (list(endpoint_ids),),
        )


class ParameterRepository(BaseRepository):
    def upsert(
        self, endpoint_id, name: str, location: str, significance: str
    ) -> dict:
        cur = self.conn.execute(
            "INSERT INTO parameters (endpoint_id, name, location, significance) "
            "VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (endpoint_id, name, location) "
            "DO UPDATE SET significance = EXCLUDED.significance RETURNING *",
            (endpoint_id, name, location, significance),
        )
        return cur.fetchone()

    def list_by_ids(self, parameter_ids: Sequence[UUID]) -> list[dict]:
        if not parameter_ids:
            return []
        return self._fetch_all(
            "SELECT * FROM parameters WHERE id = ANY(%s::uuid[]) "
            "ORDER BY name, location, endpoint_id, id",
            (list(parameter_ids),),
        )


class JavascriptFileRepository(BaseRepository):
    def upsert(self, web_app_id, url: str) -> dict:
        cur = self.conn.execute(
            "INSERT INTO javascript_files (web_app_id, url) VALUES (%s, %s) "
            "ON CONFLICT (web_app_id, url) DO UPDATE SET url = EXCLUDED.url "
            "RETURNING *",
            (web_app_id, url),
        )
        return cur.fetchone()

    def list_by_ids(self, javascript_ids: Sequence[UUID]) -> list[dict]:
        if not javascript_ids:
            return []
        return self._fetch_all(
            "SELECT * FROM javascript_files WHERE id = ANY(%s::uuid[]) "
            "ORDER BY url, web_app_id, id",
            (list(javascript_ids),),
        )


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
        sets = ["status = %s"]
        params: list = [status]
        if status in _TASK_STARTED:
            sets.append("started_at = COALESCE(started_at, now())")
        if completed:
            sets.append("completed_at = now()")
        elif status == "pending":
            # Re-queued for retry ("no lost work"): the task is not finished, so a
            # completed_at left over from a previous attempt must not survive.
            sets.append("completed_at = NULL")
        params.append(task_id)
        cur = self.conn.execute(
            f"UPDATE tasks SET {', '.join(sets)} WHERE id = %s RETURNING *",
            tuple(params),
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

    def list_for_run(self, run_id: UUID) -> list[dict]:
        """Tool runs belonging to a run, resolved through ``tasks.run_id``.

        Read-only support for Phase 15's served report, which previously rendered an
        always-empty tool-run section because nothing ever read this back. ``tool_runs``
        has no ``run_id`` column of its own, so the join is the only way to scope it.
        """
        return self._fetch_all(
            "SELECT tr.* FROM tool_runs tr "
            "JOIN tasks t ON t.id = tr.task_id "
            "WHERE t.run_id = %s ORDER BY tr.started_at, tr.id",
            (run_id,),
        )


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

    def list_for_run(self, run_id: UUID) -> list[dict]:
        """Every evidence row belonging to a run, in stable id order.

        Scoped through the same documented chain the Phase 14 writer establishes::

            evidence.tool_run_id -> tool_runs.task_id -> tasks.run_id

        Rows with a NULL ``tool_run_id`` are excluded, as they must be: they are not
        attributable to any run, so including them would silently widen the scope.
        Ordering is by the evidence primary key rather than any timestamp, because
        ``evidence`` has no timestamp column and ordering by insertion would not be
        reproducible across reads.
        """
        return self._fetch_all(
            "SELECT e.* FROM evidence e "
            "JOIN tool_runs tr ON tr.id = e.tool_run_id "
            "JOIN tasks t ON t.id = tr.task_id "
            "WHERE t.run_id = %s ORDER BY e.id",
            (run_id,),
        )

    def list_fact_refs_for_run(self, run_id: UUID) -> list[dict]:
        """Run-scoped ``(evidence_id, entity_type, entity_id)`` triples for the projection.

        The same run chain as :meth:`list_for_run`, narrowed to the three columns
        ``database.projection.RunFacts.from_evidence_rows`` consumes and with the id
        aliased to ``evidence_id``. Kept separate from :meth:`list_for_run` on purpose:
        that one feeds ``_evidence_from_row`` and needs the full row, while this one feeds
        the projection and must not depend on how the entity mapper names its columns.
        ``entity_id`` is selected even when NULL, because the projection counts those
        observation-only rows instead of dropping them.
        """
        return self._fetch_all(
            "SELECT e.id AS evidence_id, e.entity_type, e.entity_id FROM evidence e "
            "JOIN tool_runs tr ON tr.id = e.tool_run_id "
            "JOIN tasks t ON t.id = tr.task_id "
            "WHERE t.run_id = %s ORDER BY e.id",
            (run_id,),
        )


class TechnologyRepository(BaseRepository):
    """Canonical ``technologies`` table access (Phase 14).

    ``technologies`` is global and program-independent; the per-program association
    lives in ``asset_technologies``. ``category`` is constrained by a CHECK and
    the adapters report no category, so callers pass the value they can actually
    justify (``recon.ingest.DEFAULT_TECHNOLOGY_CATEGORY``) rather than guessing.
    """

    def upsert(self, name: str, category: str) -> dict:
        cur = self.conn.execute(
            "INSERT INTO technologies (name, category) VALUES (%s, %s) "
            "ON CONFLICT (name) DO UPDATE SET category = EXCLUDED.category "
            "RETURNING *",
            (name, category),
        )
        return cur.fetchone()

    def list_by_ids(self, technology_ids: Sequence[UUID]) -> list[dict]:
        """Technologies by primary key (Phase 15 projection read)."""
        if not technology_ids:
            return []
        return self._fetch_all(
            "SELECT * FROM technologies WHERE id = ANY(%s::uuid[]) ORDER BY name, id",
            (list(technology_ids),),
        )


class AssetTechnologyRepository(BaseRepository):
    """Canonical ``asset_technologies`` table access (Phase 14).

    This is the one association table that carries ``evidence_id`` inline (a
    nullable ``REFERENCES evidence (id)``), so the asset->technology link keeps
    its provenance without a second provenance column.
    """

    def upsert(
        self, asset_id, technology_id, confidence: float, evidence_id=None
    ) -> dict:
        cur = self.conn.execute(
            "INSERT INTO asset_technologies "
            "(asset_id, technology_id, confidence, evidence_id) "
            "VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (asset_id, technology_id) "
            "DO UPDATE SET confidence = EXCLUDED.confidence, "
            "evidence_id = EXCLUDED.evidence_id "
            "RETURNING *",
            (asset_id, technology_id, confidence, evidence_id),
        )
        return cur.fetchone()

    def list_for_assets(self, asset_ids: Sequence[UUID]) -> list[dict]:
        """Asset -> technology bindings for a set of assets (Phase 15 read).

        Unlike ``asset_ips`` this table *does* carry ``evidence_id``, so the binding's own
        provenance exists. It still does not name a run, though: the id belongs to an
        ``evidence`` row whose ``entity_type`` is ``asset_technology`` with a NULL
        ``entity_id`` (the composite primary key has no id of its own to cite). The
        projection therefore does not treat ``evidence_id`` as run attribution and uses
        endpoint containment for this edge too.
        """
        if not asset_ids:
            return []
        return self._fetch_all(
            "SELECT asset_id, technology_id, evidence_id FROM asset_technologies "
            "WHERE asset_id = ANY(%s::uuid[]) ORDER BY asset_id, technology_id",
            (list(asset_ids),),
        )


class AiAnalysisRepository(BaseRepository):
    """Canonical ``ai_analysis`` table access (05_DATA_MODEL.md, Phase 16 / Phase 17).

    One row per agent invocation that produced a proposal. The table predates Phase 16
    (migration 0001) but had no entity and no repository, so it was unreachable: nothing
    in production could record that the intelligence layer had run at all.

    Phase 17 (migration ``0005``) added ``run_id``. Until then the table had no
    ``run_id`` column and run attribution was carried in the ``input_context_ref``
    *string*, so attributing a row to a run meant a caller matching a text prefix --
    a second, divergent notion of run membership next to the Phase 15 evidence chain.
    ``list_for_run`` is now a plain indexed ``WHERE run_id = %s``.

    ``input_context_ref`` is still written and still meaningful: it names the context
    the agent was given, which a run id does not carry. It is no longer the run filter.
    """

    def insert(self, analysis: AiAnalysis) -> dict:
        return self._insert(
            "ai_analysis",
            {
                "id": analysis.id,
                # The real run that owns this analysis. ``NULL`` is accepted by the
                # column but rejected by ``ai_analysis_run_id_required_check`` for any
                # new write, so a Phase 17 row is always run-scoped.
                "run_id": analysis.run_id,
                "agent_name": analysis.agent_name,
                "model_used": analysis.model_used,
                "input_context_ref": analysis.input_context_ref,
                # The full Common Output Contract object, including the ``evidence`` array
                # that cites this run's evidence ids. ``hypotheses`` has no column for
                # those ids, so this jsonb is the only place they survive.
                "output": psycopg.types.json.Jsonb(analysis.output or {}),
            },
        )

    def list_for_run(self, run_id) -> list[dict]:
        """Analysis rows belonging to ``run_id``.

        The primary run-scoped read. It is qualified by ``run_id`` alone -- never by
        ``input_context_ref`` -- so an unattributable legacy row (``run_id IS NULL``)
        cannot surface as this run's analysis, and no text prefix is involved.
        """
        return self._fetch_all(
            "SELECT * FROM ai_analysis WHERE run_id = %s ORDER BY created_at, id",
            (run_id,),
        )

    def list_all(self) -> list[dict]:
        """Every analysis row, in stable id order -- including unattributed ones.

        Deliberately not run-scoped, and deliberately not the production read: it spans
        every run in the database and cannot answer "what did the AI propose for *this*
        run". It exists for migration/backfill verification and internal auditing, and is
        not reachable from the run-scoped API.
        """
        return self._fetch_all("SELECT * FROM ai_analysis ORDER BY id")


class AiCoverageGapRepository(BaseRepository):
    """Canonical ``ai_coverage_gaps`` table access (Phase 18, migration ``0006``).

    One row per ``(run_id, stage)``: a reconnaissance stage this run structurally could
    not attempt because no registered adapter can run it. The value comes from
    :func:`ai.run_context.uncovered_without_capability`, which Phase 16 deliberately kept
    out of proposals and deferred persisting for want of a run-scoped table. Migration
    ``0006`` is that table.

    ``observe`` is an upsert rather than a plain insert because a gap is re-reported on
    every analysis pass of the same run, and a run may run many passes. Deduplicating
    is what keeps "how many gaps does this run have" a property of the run rather than a
    function of how many passes happened to execute. The pass count is not discarded by
    that collapse: ``observation_count`` and ``last_seen_at`` carry it, which is the
    difference between a stable capability gap and one the planner keeps re-proposing.

    ``stage`` is stored verbatim and is deliberately not a foreign key. There is no
    adapter-registry table -- the registered set is a runtime property of the serving
    process -- and a gap is by definition the statement that a stage exists with no way
    to execute it, so a key to an adapter table would make the row unrepresentable.
    """

    def observe(self, gap: AiCoverageGap) -> dict:
        """Record one observed gap, or re-observe an existing one for the same run/stage.

        ``ON CONFLICT ... DO UPDATE`` advances ``last_seen_at`` and increments
        ``observation_count`` rather than inserting a second row, and returns the row as it
        now stands. ``first_seen_at`` is left alone: it is the first time the run
        structurally could not do this stage and never moves afterwards.

        The conflict target is the table's own ``UNIQUE (run_id, stage)`` constraint, so the
        deduplication rule and the constraint cannot drift apart.
        """
        cur = self.conn.execute(
            'INSERT INTO "ai_coverage_gaps" '
            '("id", "run_id", "stage", "first_seen_at", "last_seen_at", "observation_count") '
            "VALUES (%s, %s, %s, now(), now(), 1) "
            "ON CONFLICT ON CONSTRAINT ai_coverage_gaps_run_stage_key DO UPDATE "
            "   SET last_seen_at = now(), observation_count = "
            "       ai_coverage_gaps.observation_count + 1 "
            "RETURNING *",
            [gap.id, gap.run_id, gap.stage],
        )
        return cur.fetchone()

    def list_for_run(self, run_id) -> list[dict]:
        """The gaps belonging to ``run_id``, in stable stage order.

        The production read: an indexed ``WHERE run_id = %s``. Every gap row carries a real
        ``run_id`` (the column is ``NOT NULL``), so unlike ``ai_analysis`` there is no
        unattributable-row case to worry about and no unfiltered variant is needed.
        """
        return self._fetch_all(
            "SELECT * FROM ai_coverage_gaps WHERE run_id = %s ORDER BY stage",
            (run_id,),
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
        self.urls = UrlRepository(conn)
        self.endpoints = EndpointRepository(conn)
        self.parameters = ParameterRepository(conn)
        self.javascript_files = JavascriptFileRepository(conn)
        self.tasks = TaskRepository(conn)
        self.tool_runs = ToolRunRepository(conn)
        self.evidence = EvidenceRepository(conn)
        self.technologies = TechnologyRepository(conn)
        self.asset_technologies = AssetTechnologyRepository(conn)
        self.ai_analysis = AiAnalysisRepository(conn)
        self.ai_coverage_gaps = AiCoverageGapRepository(conn)
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

    def set_run_progress(
        self, run_id: UUID, loop_pass: int, pass_new_tasks: bool
    ) -> None:
        self.runs.update_loop_progress(run_id, loop_pass, pass_new_tasks)

    def insert_tasks(self, tasks: Iterable[Task]) -> None:
        for task in tasks:
            self.tasks.insert(task)

    def list_tasks(self, run_id: UUID) -> list[Task]:
        return [_task_from_row(row) for row in self.tasks.list_for_run(run_id)]

    def list_tasks_by_status(self, run_id: UUID, status: str) -> list[Task]:
        return [_task_from_row(row) for row in self.tasks.list_by_status(run_id, status)]

    def set_task_status(self, task_id: UUID, status: str) -> None:
        # Terminal statuses must stamp ``completed_at``. Previously the flag was
        # never passed, so ``completed_at`` stayed NULL for every task in both
        # PostgreSQL and memory -- the lifecycle record the data model promises.
        self.tasks.update_status(
            task_id, status, completed=status in _TASK_TERMINAL
        )

    def insert_tool_run(self, tr: ToolRun) -> ToolRun:
        return _tool_run_from_row(self.tool_runs.insert(tr))

    def finalize_tool_run(
        self, tool_run_id: UUID, exit_code: int, raw_output_ref: Optional[str]
    ) -> None:
        self.tool_runs.finalize(tool_run_id, exit_code, raw_output_ref)

    # -- Phase 14: transactional evidence ingestion ---------------------------
    #
    # These are additive to the contract above: Phase 13 paths keep working
    # unchanged, and the orchestrator only uses them when the concrete storage
    # actually provides them (duck-typed, like ``set_run_progress``).

    @contextmanager
    def transaction(self):
        """Group several repository calls into one atomic unit (Phase 14).

        The connection is opened with ``autocommit=True`` so every repository
        operation is otherwise its own unit of work
        (``database/repositories/base.py``). psycopg's ``transaction()`` opens a
        real BEGIN/COMMIT around the block regardless of that autocommit default,
        so the default behaviour of every existing caller is unchanged and only
        this path opts into atomicity.
        """
        with self.conn.transaction():
            yield self

    def ingest_observations(
        self,
        plan,
        *,
        tool_run_id: UUID,
        raw_output_ref: Optional[str],
        program_id: UUID,
    ) -> None:
        """Persist a scope-checked :class:`recon.ingest.IngestionPlan`.

        Call inside :meth:`transaction` so the ToolRun, this evidence, these graph
        rows and the task's terminal state commit or roll back together. Canonical
        identity comes from the existing UNIQUE indexes and is never the evidence
        id, so repeating an execution converges on the same entities while this
        run's evidence is appended as provenance history.
        """
        if plan is None:
            return

        def _evidence(entity_type: str, entity_id=None) -> UUID:
            row = self.evidence.insert(
                Evidence(
                    tool_run_id=tool_run_id,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    raw_reference=raw_output_ref,
                )
            )
            return row["id"]

        asset_ids: dict[str, UUID] = {}
        for asset in plan.assets:
            row = self.assets.upsert(
                Asset(
                    program_id=program_id,
                    hostname=asset.hostname,
                    source=asset.source,
                )
            )
            _evidence(ENTITY_ASSET, row["id"])
            asset_ids[asset.hostname] = row["id"]

        # ``dns_records`` has no UNIQUE index, so the documented idempotency rule
        # is applied here against the existing read rather than by migrating.
        dns_seen: dict[UUID, set] = {}
        for record in plan.dns_records:
            asset_id = asset_ids.get(record.hostname)
            if asset_id is None:
                continue
            if asset_id not in dns_seen:
                dns_seen[asset_id] = {
                    (row["record_type"], row["value"])
                    for row in self.dns_records.list_for_asset(asset_id)
                }
            key = (record.record_type, record.value)
            if key in dns_seen[asset_id]:
                continue
            dns_seen[asset_id].add(key)
            row = self.dns_records.insert(
                DnsRecord(
                    asset_id=asset_id,
                    record_type=record.record_type,
                    value=record.value,
                )
            )
            _evidence(ENTITY_DNS_RECORD, row["id"])

        for link in plan.ip_links:
            asset_id = asset_ids.get(link.hostname)
            if asset_id is None:
                continue
            ip = self.ips.upsert(link.address)
            self.asset_ips.upsert(asset_id, ip["id"])
            _evidence(ENTITY_IP, ip["id"])
            # ``asset_ips`` has a composite primary key and no ``evidence_id``, so
            # the edge's provenance is a polymorphic row with a NULL entity_id.
            _evidence(ENTITY_ASSET_IP)

        for web in plan.web_apps:
            asset_id = asset_ids.get(web.hostname)
            if asset_id is None:
                continue
            ip_id = self.asset_ips.ip_id_for_asset(asset_id)
            if ip_id is None:
                # Unrootable: ``web_apps.port_id`` is NOT NULL and the observation
                # carries no IP. Preserved as evidence, never fabricated.
                _evidence(ENTITY_OBSERVED_WEB_APP)
                continue
            port = self.ports.upsert(
                Port(
                    ip_id=ip_id,
                    port_number=web.port,
                    protocol="tcp",
                    state="open",
                )
            )
            _evidence(ENTITY_PORT, port["id"])
            app = self.web_apps.upsert(
                WebApp(
                    asset_id=asset_id,
                    port_id=port["id"],
                    status_code=web.status_code,
                    title=web.title,
                    server_header=web.server_header,
                )
            )
            _evidence(ENTITY_WEB_APP, app["id"])

        for port in plan.ports:
            # Phase 20A: a directly observed port. The IP is the port's
            # authoritative discovery surface (``ports.ip_id`` is NOT NULL), so it
            # is upserted first; the asset link is added only when the port was
            # reached through an in-scope hostname and that asset was recorded.
            ip = self.ips.upsert(port.address)
            _evidence(ENTITY_IP, ip["id"])
            asset_id = asset_ids.get(port.host) if port.host else None
            if asset_id is not None:
                self.asset_ips.upsert(asset_id, ip["id"])
                _evidence(ENTITY_ASSET_IP)
            port_row = self.ports.upsert(
                Port(
                    ip_id=ip["id"],
                    port_number=port.port_number,
                    protocol=port.protocol,
                    state=port.state,
                    service=port.service or None,
                    version=port.version or None,
                )
            )
            _evidence(ENTITY_PORT, port_row["id"])

        for link in plan.technologies:
            asset_id = asset_ids.get(link.hostname)
            if asset_id is None:
                continue
            technology = self.technologies.upsert(link.name, link.category)
            _evidence(ENTITY_TECHNOLOGY, technology["id"])
            # asset_technologies is the one association carrying ``evidence_id``
            # inline; its composite PK means entity_id stays NULL.
            self.asset_technologies.upsert(
                asset_id,
                technology["id"],
                link.confidence,
                _evidence(ENTITY_ASSET_TECHNOLOGY),
            )

        # -- Phase 22: crawl facts ---------------------------------------------
        #
        # urls/endpoints/parameters/javascript_files hang below a *persisted*
        # web app, rooted through asset -> ip -> port -> web_app. A plan whose
        # web app cannot be rooted is preserved as evidence with the same entity
        # tag and a NULL entity_id -- counted, never fabricated as a graph row.
        crawl_source = str(plan.source or "katana")
        web_app_ids: dict[tuple[str, int], Optional[UUID]] = {}

        def _crawl_web_app_id(hostname: str, port_number: int) -> Optional[UUID]:
            key = (hostname, port_number)
            if key in web_app_ids:
                return web_app_ids[key]
            asset = self.assets.get_by_hostname(program_id, hostname)
            app_id: Optional[UUID] = None
            if asset is not None:
                ip_id = self.asset_ips.ip_id_for_asset(asset["id"])
                if ip_id is not None:
                    port_row = self.ports.get_by_ip_port(ip_id, port_number)
                    if port_row is not None:
                        app_row = self.web_apps.get_by_asset_port(
                            asset["id"], port_row["id"]
                        )
                        app_id = app_row["id"] if app_row is not None else None
            web_app_ids[key] = app_id
            return app_id

        url_ids: dict[tuple[str, int, str], UUID] = {}
        for url in plan.urls:
            app_id = _crawl_web_app_id(url.hostname, url.port)
            if app_id is None:
                _evidence(ENTITY_URL)
                continue
            row = self.urls.upsert(app_id, url.path, crawl_source, url.historical)
            _evidence(ENTITY_URL, row["id"])
            url_ids[(url.hostname, url.port, url.path)] = row["id"]

        endpoint_ids: dict[tuple[str, int, str, str], UUID] = {}
        for endpoint in plan.endpoints:
            app_id = _crawl_web_app_id(endpoint.hostname, endpoint.port)
            if app_id is None:
                _evidence(ENTITY_ENDPOINT)
                continue
            url_id = url_ids.get((endpoint.hostname, endpoint.port, endpoint.path))
            if url_id is None:
                _evidence(ENTITY_ENDPOINT)
                continue
            row = self.endpoints.upsert(url_id, endpoint.method, endpoint.path)
            _evidence(ENTITY_ENDPOINT, row["id"])
            endpoint_ids[
                (endpoint.hostname, endpoint.port, endpoint.path, endpoint.method)
            ] = row["id"]

        for parameter in plan.parameters:
            app_id = _crawl_web_app_id(parameter.hostname, parameter.port)
            if app_id is None:
                _evidence(ENTITY_PARAMETER)
                continue
            endpoint_id = endpoint_ids.get(
                (parameter.hostname, parameter.port, parameter.path, parameter.method)
            )
            if endpoint_id is None:
                _evidence(ENTITY_PARAMETER)
                continue
            row = self.parameters.upsert(
                endpoint_id, parameter.name, parameter.location, parameter.significance
            )
            _evidence(ENTITY_PARAMETER, row["id"])

        for javascript in plan.javascript_files:
            app_id = _crawl_web_app_id(javascript.hostname, javascript.port)
            if app_id is None:
                _evidence(ENTITY_JAVASCRIPT)
                continue
            row = self.javascript_files.upsert(app_id, javascript.url)
            _evidence(ENTITY_JAVASCRIPT, row["id"])

        for observation in plan.out_of_scope:
            # Preserved, never promoted. The evidence table has no reason column,
            # so the scope-denial reason is logged by the caller, not stored.
            _evidence(
                ENTITY_OBSERVED_IP
                if observation.kind == KIND_IP
                else ENTITY_OBSERVED_HOST
            )

        if plan.truncated:
            _evidence(ENTITY_ARTIFACT_CAP)

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

    # -- Phase 15: run-scoped canonical read projection -------------------------
    #
    # This is the read counterpart to ``ingest_observations``. It is strictly a SELECT
    # path: no writes, no task or tool creation, no scope evaluation, no network. It is
    # additive to the ``Storage`` contract above, and the orchestrator/API probe for it
    # duck-typed, exactly like ``set_run_progress``.

    def list_tool_runs(self, run_id: UUID) -> list[ToolRun]:
        """Tool runs for a run as entities (Phase 15 served-report input)."""
        return [_tool_run_from_row(row) for row in self.tool_runs.list_for_run(run_id)]

    def list_evidence(self, run_id: UUID) -> list[Evidence]:
        """Evidence for a run as entities (Phase 15 served-report input)."""
        return [_evidence_from_row(row) for row in self.evidence.list_for_run(run_id)]

    def attack_surface(self, run_id: UUID) -> dict:
        """Project one run's persisted facts into a serialized attack surface.

        The single production entry point for Phase 15. Composed from reads that already
        exist (each owned by the per-table repository that owns its SQL) plus the pure
        transformation in :mod:`database.projection`:

        1. read this run's evidence rows, scoped by
           ``evidence -> tool_runs -> tasks.run_id``;
        2. resolve the entity ids those rows actually name;
        3. batch-read exactly those entities and their associations;
        4. transform to ``correlation.records`` and run the committed graph and
           inference engine over them.

        Nothing is cached and nothing is persisted, so two reads of an unchanged run
        return equal payloads. Returns ``None`` for a run that does not exist, which lets
        the API answer 404 instead of projecting an empty surface for a bad id.
        """
        if self.runs.get(run_id) is None:
            return None
        facts, entity_ids = RunFacts.from_evidence_rows(
            self.evidence.list_fact_refs_for_run(run_id)
        )
        if not entity_ids:
            # A real run that observed nothing. Distinct from a storage backend with no
            # canonical store at all, which never reaches this method.
            return serialize(project(run_id, facts))

        asset_ids = sorted(entity_ids.get(ENTITY_ASSET, ()), key=str)
        facts = replace(
            facts,
            assets=tuple(self.assets.list_by_ids(asset_ids)),
            ips=tuple(self.ips.list_by_ids(sorted(entity_ids.get(ENTITY_IP, ()), key=str))),
            ports=tuple(self.ports.list_by_ids(sorted(entity_ids.get(ENTITY_PORT, ()), key=str))),
            web_apps=tuple(
                self.web_apps.list_by_ids(sorted(entity_ids.get(ENTITY_WEB_APP, ()), key=str))
            ),
            technologies=tuple(
                self.technologies.list_by_ids(
                    sorted(entity_ids.get(ENTITY_TECHNOLOGY, ()), key=str)
                )
            ),
            # Associations are restricted to this run's evidenced assets on purpose.
            # ``build_records`` then applies endpoint containment, so an edge is emitted
            # only once both of its endpoints are themselves run-evidenced.
            asset_ips=tuple(self.asset_ips.list_for_assets(asset_ids)),
            asset_technologies=tuple(
                self.asset_technologies.list_for_assets(asset_ids)
            ),
            # Phase 22 crawl facts, batch-read by the ids this run's evidence names.
            urls=tuple(
                self.urls.list_by_ids(sorted(entity_ids.get(ENTITY_URL, ()), key=str))
            ),
            endpoints=tuple(
                self.endpoints.list_by_ids(
                    sorted(entity_ids.get(ENTITY_ENDPOINT, ()), key=str)
                )
            ),
            parameters=tuple(
                self.parameters.list_by_ids(
                    sorted(entity_ids.get(ENTITY_PARAMETER, ()), key=str)
                )
            ),
            javascript_files=tuple(
                self.javascript_files.list_by_ids(
                    sorted(entity_ids.get(ENTITY_JAVASCRIPT, ()), key=str)
                )
            ),
        )
        return serialize(project(run_id, facts))

    # -- Phase 16: AI-analysis audit records ------------------------------------
    #
    # Additive to the ``Storage`` contract, duck-typed by the caller exactly like
    # ``attack_surface``. The Phase 16 hook writes through these two; nothing else in the
    # system creates an ``ai_analysis`` row, which is the point -- it is the audit trail of
    # the intelligence layer, not a side effect of anything else.

    def insert_ai_analysis(self, analysis: AiAnalysis) -> AiAnalysis:
        """Record one agent invocation and its structured output."""
        row = self.ai_analysis.insert(analysis)
        return AiAnalysis(
            id=row["id"],
            run_id=row.get("run_id"),
            agent_name=row["agent_name"],
            model_used=row["model_used"],
            input_context_ref=row["input_context_ref"],
            output=row["output"] or {},
            created_at=row.get("created_at"),
        )

    def list_ai_analysis(self, run_id: Optional[UUID] = None) -> list[AiAnalysis]:
        """Recorded agent invocations, run-scoped by default.

        ``list_ai_analysis(run_id)`` is the production read: an indexed
        ``WHERE run_id = %s`` (:meth:`AiAnalysisRepository.list_for_run`), which is what
        the Phase 17 API route and report use.

        ``run_id`` is optional and defaults to ``None`` only for the migration/backfill
        audit path, which needs to see rows -- including unattributable legacy rows with
        ``run_id IS NULL`` -- across every run. Callers that pass nothing therefore get
        the *unfiltered* set, which is why the run-scoped API always passes a run id and
        no operator-reachable surface exposes the unfiltered result.
        """
        rows = (
            self.ai_analysis.list_all()
            if run_id is None
            else self.ai_analysis.list_for_run(run_id)
        )
        return [
            AiAnalysis(
                id=row["id"],
                # A legacy row that migration 0005 could not attribute reports NULL here
                # rather than a fabricated run.
                run_id=row.get("run_id"),
                agent_name=row["agent_name"],
                model_used=row["model_used"],
                input_context_ref=row["input_context_ref"],
                output=row["output"] or {},
                created_at=row.get("created_at"),
            )
            for row in rows
        ]

    # -- Phase 18: capability coverage gaps -------------------------------------
    #
    # Additive to the ``Storage`` contract and duck-typed by the caller exactly like
    # ``insert_ai_analysis``. These record which reconnaissance stages a run structurally
    # could not attempt -- no registered adapter can run them -- so the distinction Phase 15
    # computes and Phase 16 kept out of proposals survives process exit.
    #
    # They are reported-only. Nothing here creates a task or a hypothesis, and a gap is
    # never a proposal: a stage the system cannot execute is not work to schedule.

    def observe_coverage_gaps(self, run_id: UUID, stages: Sequence[str]) -> list[AiCoverageGap]:
        """Record the coverage gaps observed on one analysis pass.

        One row per stage, deduplicated per ``(run_id, stage)``; a stage seen again on a
        later pass of the same run advances ``last_seen_at`` and ``observation_count``
        instead of inserting a second row.

        Returns the rows as they now stand, so the caller can report an accurate count
        without a second query.
        """
        observed: list[AiCoverageGap] = []
        for stage in stages:
            name = str(stage)
            # A blank stage would be rejected by ``ai_coverage_gaps_stage_not_blank``;
            # skipping it here keeps a malformed gap from failing the whole pass, since
            # a coverage gap is diagnostic output and must never break analysis.
            if not name.strip():
                continue
            row = self.ai_coverage_gaps.observe(
                AiCoverageGap(run_id=run_id, stage=name)
            )
            observed.append(
                AiCoverageGap(
                    id=row["id"],
                    run_id=row["run_id"],
                    stage=row["stage"],
                    first_seen_at=row.get("first_seen_at"),
                    last_seen_at=row.get("last_seen_at"),
                    observation_count=row.get("observation_count", 1),
                    created_at=row.get("created_at"),
                )
            )
        return observed

    def list_coverage_gaps(self, run_id: UUID) -> list[AiCoverageGap]:
        """The run's persisted coverage gaps, in stable stage order.

        Run-scoped by construction: there is no unfiltered variant and no optional
        ``run_id``, because ``ai_coverage_gaps.run_id`` is ``NOT NULL`` so no gap is
        unattributable and no caller has a reason to see across runs. This mirrors the
        Phase 17 principle that the audit path is the only place an unfiltered read is
        justified, and Phase 18 has no such path.
        """
        return [
            AiCoverageGap(
                id=row["id"],
                run_id=row["run_id"],
                stage=row["stage"],
                first_seen_at=row.get("first_seen_at"),
                last_seen_at=row.get("last_seen_at"),
                observation_count=row.get("observation_count", 1),
                created_at=row.get("created_at"),
            )
            for row in self.ai_coverage_gaps.list_for_run(run_id)
        ]
