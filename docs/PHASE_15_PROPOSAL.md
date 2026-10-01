# ARGUS — Phase 15 Context: Canonical Read Projection

> **Persistent project context, not an architectural authority.**
> This document records the approved Phase 15 plan and, after implementation, the actual
> behavior. It never overrides `OPENCODE.md`, `01_PRODUCT_SPEC.md`, `04_SCOPE_SAFETY.md`,
> `05_DATA_MODEL.md`, `06_TOOL_CONTRACTS.md`, or `08_ORCHESTRATOR.md`. Where this file and an
> authoritative document appear to disagree, the authoritative document wins and the conflict
> must be reported — see `OPENCODE.md` Rule 1 for the precedence chain.

**Status:** implemented, verified
**Phase 15 objective:** close the read seam so persisted PostgreSQL facts become the derived
attack-surface graph that `correlation`, `ai`, and `reports` already expect.
**Phase 14 baseline commit:** `d9e63321935cd4d6055591cc262c25cdfe8b91a8`
**Phase 14 status:** VERIFIED (final forensic audit, no BLOCKER/HIGH findings)

---

## 1. Current-state diagnosis

Phase 14 closed the **write** seam: `ToolExecution.artifacts` → `recon.ingest` → PostgreSQL,
with one `evidence` row per canonical fact, committed atomically with the `ToolRun` and the
task's terminal state. Every attack-surface table now has real rows.

That write path stopped at the database. **Nothing ever read those facts back.** Confirmed by
import/reference analysis before implementation:

- `correlation/asset_graph.py` and `correlation/relationship_engine.py` had no production
  importer. The record classes (`DomainRecord`, `IpRecord`, `PortRecord`, `WebAppRecord`,
  `TechnologyRecord`, …) were constructed by tests only.
- `reports/**` rendered from `ToolRun`/`Evidence`/`Hypothesis` lists assembled ad hoc in
  `api/server.py`, never from a graph.
- The `/api/v1/runs/{run_id}` report contained no projection of the run's own facts, so
  `Discovered Assets`, `IPs`, `Ports`, and `Technologies` were structurally unreachable.
- `ai/` remained unwired. Phase 15 does **not** wire it.

Phase 15 closes this one seam. It adds no capability beyond it.

## 2. Scope

**In scope**

- A read-only, run-scoped projection from persisted rows to the already-committed
  `correlation.records` types.
- Invocation of the already-committed `correlation.asset_graph.build`,
  `correlation.endpoint_graph.endpoint_subgraph`, and
  `correlation.relationship_engine.run`, unchanged.
- Batch read methods on the existing repositories, plus one facade method
  (`Repositories.attack_surface`).
- An authenticated, read-only `GET /api/v1/runs/{run_id}/attack-surface` route.
- An optional `attack_surface` section in all three report formats.
- An honest `available: false` payload for storage backends that have no canonical fact store.

**Out of scope**

No AI activation (no `ai/` import, no `analysis` hook, no `ai_analysis` writes). No new graph or
inference semantics, no new record types, no new inference kinds. No new recon tools, adapters,
or external binaries. No network, DNS resolution, or HTTP request. No scope evaluation, scope
mutation, rate limiting, or task creation/execution. No schema migration. No dashboard or CLI.
No changes to `api/auth.py`, `api/security.py`, `core/scope_guard.py`, `core/rate_limiter.py`,
`core/tool_runner.py`, or `core/executor.py`. `.byte/` untouched.

## 3. Architecture

```text
GET /api/v1/runs/{run_id}/attack-surface   (authenticated, read-only)
        ↓
Repositories.attack_surface(run_id)
        ↓
  ToolRunRepository.list_for_run        evidence.tool_run_id → tasks.run_id
  EvidenceRepository.list_fact_refs_for_run   (ordered by evidence id)
        ↓  RunFacts.from_evidence_rows  →  {entity_type: {entity_id: evidence_id}}
        ↓
  ONE batched read per entity table (WHERE id = ANY(...))
        ↓  build_records                [pure, deterministic]
  correlation.records types
        ↓
  correlation.asset_graph.build        (unchanged, as committed)
  correlation.endpoint_graph.endpoint_subgraph
  correlation.relationship_engine.run  (unchanged, as committed)
        ↓
  AttackSurface (in-memory, derived, never persisted)
        ↓
  serialize()  →  JSON-safe, deterministically ordered payload
```

### 3.1 Run scoping is evidence, never ownership

A canonical entity is **not** owned by a run. `assets` are unique per
`(program_id, hostname)`, `ips` are unique per `address` globally, and `ports`/`web_apps` are
reachable from several runs. `discovered_at`, `first_seen`, `observed_at`, `created_at`, and
program membership are all deliberately **not** used to decide membership, because none of them
is provenance.

The authoritative chain already exists and Phase 14 writes it:

```text
evidence.tool_run_id → tool_runs.task_id → tasks.run_id → runs.id
```

An entity is projected into a run's graph **iff** that run holds an `evidence` row whose
`entity_type` matches and whose `entity_id` names the entity. Two runs that observed the same IP
both project it; a run that never observed it never does. This is the property
`tests/test_projection_live.py::test_cross_run_evidence_isolation` asserts by direct SQL.

### 3.2 Association rows: endpoint containment, not migration

`asset_ips` and `asset_technologies` **cannot** be attributed to a run from the existing
schema: their Phase 14 evidence rows carry a NULL `entity_id` (`asset_ips` has a composite
primary key, so there is no single row id to cite), and `asset_technologies` stores its
`evidence_id` inline rather than in `evidence`.

Rather than migrate the schema, the projection uses **endpoint containment**: an association is
projected only when *both* of its endpoints are themselves evidenced in the same run. This is
strictly conservative — a projected edge cannot reference a fact the run did not observe, so one
run's graph can never contain an edge only another run can justify. **No migration is required
or performed.**

### 3.3 Withholding rather than fabricating

Entities whose required graph parents are not themselves evidenced are **not** projected, because
the committed correlation records cannot represent them without inventing a value:
`PortRecord` needs its IP, `WebAppRecord` needs its port, IP, and asset. If a parent is missing
the fact is withheld, never rendered with a fabricated linkage. Records that *can* be
represented honestly but have no derivable link are still emitted and land as orphans — the
documented failure condition in `03_RECON_PIPELINE.md` §25 ("stored without an edge rather than
dropped").

## 4. Requirements

**Read-only** — `database/projection.py` never writes PostgreSQL, never mutates evidence, never
resolves DNS, performs HTTP, invokes a tool or an AI agent, touches scope, or creates or executes
a task. It is a `SELECT` composed into dataclasses that already exist.

**Provenance** — every projected node and edge carries the `evidence_id` of the run-scoped
evidence row that justifies it. The graph is not a summary of the database; it is a summary of
*this run's observations*.

**Determinism** — `evidence` carries no timestamp, so ordering is fixed on stable identifiers:
evidence rows are ordered by primary key and the first row per `(entity_type, entity_id)` supplies
the record's `evidence_id`; entity rows are ordered by natural key before transformation; the
final record list is sorted by `(type, key, evidence_id)`; every serialized list is ordered by a
stable key. Projecting the same persisted run twice yields the same records, graph, inferences,
and **byte-identical** JSON. No cache, no background work, no persisted graph, no clock, no
randomness.

**Honest gaps** — `available: false` means the storage backend has no canonical fact store (the
in-memory development double). `available: true` with zero counts means a real run that observed
nothing. The two are never conflated.

**No fabricated attack surface** — only record types with real persisted producers are projected.
`UNPRODUCED_RECORD_KINDS` is returned in the payload so an operator can distinguish "no producers
yet" from "nothing was found":

| Record type | Status | Reason |
|---|---|---|
| `domain`, `ip`, `port`, `web_app`, `technology` | projected | Phase 14 producers exist |
| `endpoint`, `parameter`, `javascript`, `api`, `auth`, `certificate` | never created | no Phase 14 producer; no `certificates` table exists |
| `dns_record` | not projected | real producer, but the committed correlation model has no record type for it; adding one is out of scope |

An address-valued DNS record is not lost: it is the same fact as the `asset_ips` binding, which
the graph already represents as the `resolves_to` edge. Non-address records (CNAME/MX/NS/TXT)
have no graph representation at all and are therefore not projected — an honest gap, not a
silent one. Because every inference rule in the engine is gated on endpoint-class nodes, a
Phase-14-shaped dataset legitimately yields **zero** inferences; that empty result is reported
honestly rather than padded.

**Facts stay facts** — inferences are passed through with the correlation layer's own
`truth_label` and never enter `validated_findings`. The report's existing fact/hypothesis
separation is unchanged.

**Untrusted input** — no attacker-controlled value is interpolated into SQL. Batch reads bind id
lists through `%s::uuid[]`; only table and column identifiers are interpolated, and those come
from code.

## 5. Implementation stages

- **15.1 Pure projection** — `database/projection.py`, unit-tested with hand-built rows, no
  database.
- **15.2 Repository reads + facade** — batched, run-scoped reads; `Repositories.attack_surface`.
  INTEGRATION.
- **15.3 API + reports** — authenticated route; optional report section in JSON/Markdown/HTML.
  Backward-compatible.
- **15.4 Live acceptance** — real PostgreSQL, write → project → API → report, cross-run
  isolation, determinism, auth, read-only proof.

## 6. Non-goals

No AI activation. No graph/inference semantics change. No new record types. No new recon
capability. No network, DNS, or HTTP. No scope mutation. No task creation. No schema migration.
No dashboard or CLI. No report redesign. No weakening of any existing test.

## 7. Stop conditions

STOP and report rather than improvise if: a schema migration appears necessary; run membership
cannot be established from evidence; `correlation` would have to be modified; a record type would
have to be invented; endpoint containment cannot be applied conservatively; or Phase 14 behavior
would have to be altered. _None of these triggered; see §11._

## 8. Known environment limitations

Carried forward from Phase 14 and not to be reported as passing acceptance claims:

- `httpx` v1.12.0 loopback behaviour — ENVIRONMENT-UNVERIFIED (binary not installed)
- `subfinder` public-domain enumeration — ENVIRONMENT-UNVERIFIED (binary not installed)
- local PostgreSQL runs with `ssl = off`

No public or external targets are used in any test.

## 9. Acceptance criteria

1. A run with real Phase 14 facts projects a graph whose nodes and edges all resolve to
   run-scoped `evidence` rows, asserted by direct SQL against live PostgreSQL.
2. Cross-run isolation: a second run that never observed an entity does not project it.
3. `GET /api/v1/runs/{run_id}/attack-surface` returns the payload at top level; 401 without a
   Bearer token; 404 for an unknown run; no DSN, credential, or authorization material in the
   response.
4. The route performs no writes — asserted by comparing a full table checksum across the request.
5. All three report formats carry the section; existing report contracts are unchanged when the
   backend cannot project.
6. Two projections of an unchanged run are byte-identical.
7. No `BLOCKER`/`HIGH` finding remains open; all Phase 14 guarantees re-verify green.

## 10. Test classification

`UNIT` · `INTEGRATION` (fixtures, `MemoryStorage`) · `LIVE` (real PostgreSQL, served app, gated
on `ARGUS_TEST_DATABASE_URL`) · `SECURITY/NEGATIVE` · `REGRESSION` (Phase 14 gates) ·
`ENVIRONMENT-UNVERIFIED`. No test is weakened and no skip is added to obtain a green result.

## 11. Implemented behavior

_Recorded after implementation._

### 11.1 What was implemented

| Piece | Location | Summary |
| --- | --- | --- |
| Pure projection | `database/projection.py` | `RunFacts.from_evidence_rows` splits run-scoped evidence into provenance and per-type id sets; `build_records` walks bottom-up (assets → IPs → ports → web apps → technologies) emitting only committed `correlation.records` types; `project` invokes the unmodified graph builders; `serialize` renders a deterministic JSON-safe payload; `unavailable` returns the structurally identical empty form. |
| Repository reads | `database/repositories/all.py` | Per-table `list_by_ids` / `list_for_assets`; `ToolRunRepository.list_for_run`; `EvidenceRepository.list_for_run`; `EvidenceRepository.list_fact_refs_for_run`; `Repositories.list_tool_runs`, `.list_evidence`, `.attack_surface`; `_evidence_from_row`. |
| API | `api/server.py` | `GET /api/v1/runs/{run_id}/attack-surface`, plus `_attack_surface`, `_read_from_storage`, `_asset_counts`, `_VALIDATED_TRUTH_LABEL`. `get_report` now sources real tool runs, evidence, hypotheses, validated findings, canonical asset counts, and the surface from storage. |
| Reports | `reports/json_report.py`, `markdown_report.py`, `html_report.py` | Optional `attack_surface` section. JSON carries the payload verbatim; Markdown and HTML render a Facts subsection with counts and the graph's node/edge/orphan totals. Omitted entirely when the backend cannot project. |

### 11.2 Genuine defects found and fixed

1. **`EvidenceRepository.list_for_run` returned no `evidence_id`.** It selected `e.*`, and the
   joined `evidence` columns `id` as `tool_runs.id`, not `evidence.id`. Every projected record
   would have raised `KeyError: 'evidence_id'`, so the projection could not have worked at all.
   The projection path uses a dedicated `list_fact_refs_for_run` that selects
   `e.id AS evidence_id` explicitly. This defect was latent until the read path existed.
2. **PostgreSQL `inet` leaked a netmask into graph node keys.** `ips.address` is `inet`, so
   `address::text` renders `93.184.216.34/32` (IPv6: `/128`) — PostgreSQL always stores the
   prefix length. Because the value becomes a correlation node *key* and an
   `IpRecord.address`/`PortRecord.ip` value, the Postgres-backed graph would have keyed its IP
   nodes and port keys (`93.184.216.34/32:443`) differently from every other projection of the
   same observation. `IpRepository.list_by_ids` now projects `host(address)`.

   This is deliberately scoped to the read path only. `IpRepository.upsert` still returns
   `address::text`, because that is the documented canonical PostgreSQL round-trip form and
   `tests/test_database_live.py::test_asset_dedup_and_dns` pins it with an explicit rationale.
   The write path feeds `ingest_observations`, which needs `id`, not a node key.

### 11.3 Test results per tier

| Tier | Command / scope | Result |
| --- | --- | --- |
| UNIT | `pytest tests/test_projection.py` | 34 passed |
| LIVE | `pytest tests/test_projection_live.py` (real PostgreSQL + served app) | 19 passed |
| Full suite, live | `pytest` with `ARGUS_TEST_DATABASE_URL` set | **617 passed, 0 failed, 0 skipped** |
| Full suite, no DSN | `pytest` with the variable unset | 501 passed, 116 skipped |

The 53-test increase over the Phase 14 baseline of 564 is the new Phase 15 suites: 34 no-DSN unit
tests and 19 live tests, which skip on the same `ARGUS_TEST_DATABASE_URL` gate as the 97
pre-existing database-gated tests. No skip was added to obtain a green result, and no existing
test was weakened.

### 11.4 Live acceptance

`tests/test_projection_live.py` drives the real composition — real PostgreSQL, real
`Repositories`, real `recon.ingest` planning and transactional persistence, real FastAPI served
by `create_serve_app`, real bearer authentication — and asserts acceptance criteria 1–7. It
covers:

- write → project → API → report for a realistic domain/IP/port/web-app/technology chain;
- cross-run evidence isolation, both projection directions;
- every node and edge resolving to a run-scoped evidence row;
- byte-identical repeat projections (determinism);
- the route being a pure read (full table checksum unchanged across the request);
- 401 without a token, 404 for an unknown run, `available: false` for the in-memory double;
- IPv4 and IPv6 node keys carrying no netmask.

### 11.5 Database used for live verification

Same arrangement as Phase 14 and §11.5 of `PHASE_14_PROPOSAL.md`: the original PostgreSQL 17
service on port 5432 was never modified; the cluster was copied to a temporary directory and
served on port `5433` with loopback-only trust for the duration of verification. No DSN or
password appears in any tracked file; tests receive it only through `ARGUS_TEST_DATABASE_URL`.

The shared test database's `schema_migrations` bookkeeping had drifted (`version = 1` recorded
while migrations 1–4 were actually applied, an artifact of Phase 14's non-autocommit fixture
racing the served app's autocommit writer). Because `revert(conn, 0)` can only undo versions it
can see recorded, it left a stale table behind and `apply` then failed with
`column "run_id" of relation "hypotheses" already exists`. The Phase 15 live fixture therefore
rebuilds the schema with `DROP SCHEMA public CASCADE` / `CREATE SCHEMA public` instead of
`revert` + `apply`, which is immune to bookkeeping drift and cannot inherit another test's rows.

### 11.6 Deferred findings

- `httpx` v1.12.0 loopback behaviour — ENVIRONMENT-UNVERIFIED (binary not installed).
- `subfinder` public-domain enumeration — ENVIRONMENT-UNVERIFIED (binary not installed).
- Zero inferences from a Phase-14-shaped dataset is the correct result, not a gap: every
  inference rule in `correlation.relationship_engine` is gated on endpoint-class nodes that have
  no producer yet. Reported honestly, never padded.
- A domain-only scope intentionally yields no IP, port, or web-app rows, because `check_ip`
  denies by default. This is the documented security posture, not a gap.

### 11.7 Audit status

- `git diff --check` clean; all modified and added files compile and import.
- No linter or typechecker is configured in this repository; compile and import checks were used
  instead.
- `api/auth.py`, `api/security.py`, `core/scope_guard.py`, `core/rate_limiter.py`,
  `core/tool_runner.py`, `core/executor.py`, and `recon/ingest.py` are untouched
  (`git diff --name-only HEAD -- correlation/ api/auth.py api/security.py core/ recon/ ai/
  database/migrations/` is empty). Authentication remains fail-closed, and `correlation/**` is
  called exactly as committed.
- Only the files listed in §11.1 and this document are modified or added. `.byte/` remains
  untracked, unstaged, and unmodified.
- Secret scan: the only credential-shaped literals are the local test constants
  `phase15` / `phase15-key`, matching the Phase 14 `phase14-key` convention. No literal DSN,
  password, or key is in any tracked file; `tests/test_projection_live.py` asserts that no
  `postgresql://` string reaches an API response or report body.
- No test was weakened or skipped to obtain a green result.
- No BLOCKER or HIGH findings remain open.

- Status: VERIFIED.
- Feature commit: `77a2de35c47470dbe12657f72998270aeee1ecb3` (committed locally, not pushed).
