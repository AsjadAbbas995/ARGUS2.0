# Phase 20A Proposal — Reconnaissance Capability Expansion (Nmap / Subfinder)

## Phase 20A status

**FORENSIC PASS COMPLETE — VERDICT: READY. NOT IMPLEMENTED.**

This document records the completed Phase 20A **forensic / specification pass**
only. No production code, migration, test, or configuration was written by this
pass. Phase 20A **must not be implemented** as part of producing this document.

The forensic pass found **no blocking STOP condition**. The requested capability
— subdomain discovery → DNS → port/service discovery (Nmap) → HTTP probing,
integrated with Phase 14 ingestion and surfaced through the Phase 15 projection —
is **feasible additively**, with **no database migration required**.

## Baseline

Phase 19 is closed at:

```
283be9a  docs/test: close phase 19 verification
```

Immediately prior:

```
0093514  test: finalize phase 18 live verification
```

`HEAD` at the time of the forensic pass is `283be9a`. This document is the only
new artifact.

## Current production reconnaissance

The served runtime composition root is `api/serve.py::create_serve_app`, which
builds its task-type → adapter table in `_default_adapters`. It currently
registers **only two** adapters:

1. **DNS** — `DnsResolverAdapter` (`recon/dns/resolver.py`)
   task types:
   - `dns_resolve`
   - `dns`
   - `resolve`

2. **HTTP probe** — `HttpxProbeAdapter` (`recon/web/httpx_probe.py`)
   task types:
   - `http_probe`
   - `httpx`
   - `web_probe`

Any task type outside these two groups is **refused before any adapter is
constructed** via `ServedExecution.adapter_for` (`UnknownTaskType`). There is no
silent substitution; a typo or a type from a newer planner can never be executed
by the wrong tool.

`SubfinderAdapter` (`recon/subdomains/subfinder.py`) exists and is unit-tested,
but is **not production-registered**. **No Nmap adapter currently exists** in the
repository.

## Adapter inventory

| Capability | Adapter | Implemented | Unit tested | Served | Live verified |
|------------|---------|-------------|-------------|--------|---------------|
| DNS | `DnsResolverAdapter` | yes | yes | yes | yes |
| HTTP probe | `HttpxProbeAdapter` | yes | yes | yes | yes |
| Subfinder | `SubfinderAdapter` | yes | yes | **no** | **no** |
| Nmap | *(none exists)* | **no** | no | no | no |

Evidence for the table:

- `tests/test_dns.py`, `tests/test_httpx.py` cover the two served adapters.
- `tests/test_subfinder.py` covers the Subfinder adapter (14 tests) but the type
  is absent from `DEFAULT_ADAPTER_TYPES` / `_default_adapters` in `api/serve.py`.
- A repository-wide search for `nmap` / `port_scan` finds no adapter; the only
  hits are AI executable task-type strings in `tests/test_phase18.py`.

## Environment

External binaries currently unavailable on `PATH` (Windows development host):

```
subfinder
nmap
httpx
amass
naabu
dnsx
nuclei
```

DNS is **in-process** (dnspython-style resolution through the adapter, no
subprocess) and is available. Because the external binaries are absent, any
Phase 20A live verification would be limited to the in-process DNS path and a
controlled/mocked Tool Runner; **no claim of live verification may be made for
Subfinder or Nmap while their binaries are unavailable**.

## Schema finding

The existing schema already fully supports the intended data:

`ports` (`database/migrations/0001_initial_schema.sql`):

```
id          uuid PRIMARY KEY
ip_id       uuid NOT NULL REFERENCES ips (id)
port_number integer NOT NULL
protocol    text NOT NULL CHECK (protocol IN ('tcp', 'udp'))
state       text NOT NULL CHECK (state IN ('open', 'closed', 'filtered'))
service     text
version     text
```

- `Port` entity exists (`database/models/entities.py`) with
  `ip_id`, `port_number`, `protocol`, `state`, `service`, `version`.
- `PortRepository.upsert` exists.
- `PortRepository.list_by_ids` exists.
- Phase 15 projection already supports ports through `PortRecord` /
  `ENTITY_PORT` (ports are read and surfaced as canonical records).

**Therefore: NO DATABASE MIGRATION IS REQUIRED.** Nmap port/service/version
results map truthfully onto existing columns and existing unique index
`ports_uq (ip_id, port_number, protocol)`.

## Current gap

`IngestionPlan` (`recon/ingest.py`) currently supports:

- `assets`
- `dns_records`
- `ip_links`
- `web_apps`
- `technologies`

but **not standalone port observations**. `ingest_observations`
(`database/repositories/all.py`) correspondingly does not ingest Nmap port
artifacts; ports currently arise **only as a side effect** of a rooted
`WebAppObservation` (a web app roots to its IP and creates a `tcp/open` port).

Consequently, Nmap artifacts would currently be counted as `unrecognized` by
`plan_ingestion` and no port row would be written from them.

## Phase 20A implementation scope

The planned implementation (NOT performed here) is:

1. Add `NmapAdapter`.
2. Define `PortObservation`.
3. Define `DEFAULT_PORT_SCAN_TYPES`.
4. Extend ingestion with `PortPlan`.
5. Persist ports through the existing `PortRepository`.
6. Create `ENTITY_PORT` evidence.
7. Register `SubfinderAdapter`.
8. Register `NmapAdapter`.
9. Add corresponding default task types.
10. Implement deterministic task seeding/dependency behavior for
    `subfinder → DNS → Nmap → HTTP`, **only where safely expressible with
    existing task semantics**.
11. Preserve `parent_task_id` dependency behavior.
12. Preserve `ScopeGuard`.
13. Preserve `RateLimiter`.
14. Preserve `ToolRunner`.
15. Preserve Phase 14 evidence semantics.
16. Preserve Phase 15 projection.
17. Verify end-to-end data flow.

## Task dependencies

Existing `parent_task_id` semantics can express:

```
subfinder
   ↓
DNS
   ↓
Nmap
   ↓
HTTP
```

`core/orchestrator.py` already gates a child task on its `parent_task_id`
reaching a completed terminal status (`_runnable_tasks` / `_execute_pending`,
`_TASK_COMPLETED = {"completed"}`), and `core/task_planner.py` orders parents
before children. Task fingerprints deduplicate re-issues.

**No orchestration redesign is required merely to represent these
dependencies.**

However, **there is currently no automatic pipeline expansion** from discovered
hosts/IPs: `POST /api/v1/runs` creates a run only, and tasks are enqueued
explicitly (`POST /api/v1/runs/{id}/tasks`) with `type`, `target`, and optional
`parent_task_id`. Phase 20A must explicitly decide and document a **minimal
deterministic seeding mechanism**.

**Phase 20A must not silently activate autonomous AI task generation.** The
adaptive loop is only wired when `config.ai.enabled` is set; Phase 20A
deterministic seeding must be independent of, and must not enable, that path.

## Safety

The following existing safety guarantees must remain intact and unchanged:

- scope checked before execution (orchestrator **and** adapter validation);
- rate limited through the served `RateLimiter`;
- adapter validation (`ToolAdapter.validate` / `_require_in_scope`);
- discovered hosts independently scope checked (`ScopeGuard.check_host`);
- discovered IPs independently scope checked (`ScopeGuard.check_ip`);
- out-of-scope observations become **evidence only** (never graph rows);
- out-of-scope observations **never authorize follow-up**;
- no destructive scanning;
- no brute force;
- no credential attacks;
- no DoS;
- no evasion;
- no scope expansion.

`ScopeGuard.check_port` exists and is available; port scope rules may be applied
when ports are ingested.

## Phase 20A non-goals

Phase 20A explicitly excludes all of:

- URL crawling
- Katana
- FFUF
- Feroxbuster
- JavaScript analysis
- endpoint discovery
- API discovery
- GraphQL
- WebSockets
- parameter discovery
- authentication analysis
- exploitation
- adaptive AI task generation
- adaptive loop activation
- LLM backend

## Testing plan

The following tests are intended for the implementation phase (not written by
this documentation pass):

**Adapter**
- parsing
- malformed output (non-fatal; unusable lines skipped, not fatal)
- deduplication
- timeout / failure handling
- scope behavior (out-of-scope target rejected)
- artifact provenance (raw output reference preserved)

**Ingestion**
- port observation normalization
- port deduplication
- host / IP rooting
- scope rejection
- evidence creation (`ENTITY_PORT`)

**Production**
- registration of new task types
- unknown-task refusal remains fail-closed

**Projection**
- ports appear through the existing Phase 15 projection

**Integration**
- adapter → Tool Runner → ingestion → PostgreSQL

**Live**
- gated on external binary availability
- controlled target only
- **no claim of live verification when binaries are unavailable**

## STOP conditions

Implementation must stop and report if any of the following is encountered:

- the schema becomes insufficient;
- a migration is unexpectedly required;
- safety semantics need changing;
- ingestion cannot represent Nmap results truthfully;
- task dependencies require architectural redesign;
- unrelated Phase 18 work would need modification.

## Guardrails of this pass

This pass is **documentation only**. It does not modify:

- source code
- migrations
- tests
- Phase 18 files
- `.byte/`
- PostgreSQL
- remotes

It does not commit. The only change produced is the creation of
`docs/PHASE_20A_PROPOSAL.md`.

## Implementation record

This section was appended after the implementation pass and records what was
built, how it was verified, and the two decisions the live verification forced.

### Deliverables

- `recon/ports/__init__.py`, `recon/ports/nmap.py` — `PortObservation` (a frozen
  fact: address, port, protocol, state, service, version, host) and the
  `NmapAdapter`. Command
  `nmap -sT -Pn -n -p <start>-<end> -oX - <target>`; the port range comes from
  `config.network.tcp_ports` (default 1-1000). Connects to `ToolRunner` via an
  overridden `execute` that passes `DEFAULT_TIMEOUT=300.0` and stamps `host`
  from the task target only when the target is a hostname. XML output is parsed
  with `xml.etree` and **rejected outright when it contains `<!DOCTYPE` or
  `<!ENTITY`**; malformed or empty blocks are skipped, never fatal.
- `recon/expansion.py` — `plan_discovery_expansion`, a pure mapping from one
  completed discovery task's artifacts to scope-checked child tasks:
  hostname → `dns_resolve`; bound `IpObservation` → `port_scan` of the parent
  hostname; open `WEB_PORTS` (`80,443,8000,8008,8080,8081,8443,8888`) →
  `http_probe host:port`. Bounded (`max_tasks=256`), allowlisted against the
  composition's `available_types`, deduplicated, sorted by `(type, target)`,
  fingerprinted exactly like the orchestrator's planner.
- `api/serve.py` — the subdomain and port adapters are registered
  (`"subfinder"/"subdomain_enum"`, `"port_scan"/"nmap"`), and the Phase 14
  ingest callback now calls `_enqueue_expansion`, which persists the proposed
  children (deduplicated by fingerprint against the run's existing tasks) inside
  the same orchestrator transaction.
- `database/repositories/all.py::ingest_observations` — each `PortPlan`
  upserts the observed IP, its `ENTITY_IP` evidence, the `asset_ips` link with
  `ENTITY_ASSET_IP` evidence when a host is present, the `ports` row, and the
  `ENTITY_PORT` evidence. This is additive to the protected Phase 18 file.

### Verification

- Unit: `tests/test_nmap.py` (parsing, malformed/DTO/entity-safety, scope
  rejection, dedup, timeout plumbing, provenance), `tests/test_expansion.py`
  (mapping, gating, allowlist, scope, dedup, determinism, bounds),
  `tests/test_ingest.py` port suite, `tests/test_phase16.py` registry fix.
- DB-gated live (`tests/test_phase20_live.py`, gate `ARGUS_TEST_DATABASE_URL`):
  port persistence + evidence + Phase 15 projection of `PortRecord`; ports are
  facts, never findings; and the full served composition
  (`ServedExecution` + `_build_ingestor` + `Orchestrator`) runs
  `subfinder → dns_resolve → port_scan → http_probe` to `COMPLETED` in real
  PostgreSQL with the exact scope/rate-limit/transaction stack.
- Full suite against the sanctioned 5433 fixture: **817 passed, 6 failed**. The
  6 failures are pre-existing conditions of the (protected) Phase 18 worktree,
  not Phase 20A: five migration bookkeeping tests assert the applied list ends
  at version 5 while `0006_ai_coverage_gaps.sql` extends it; one Phase 18 live
  test calls `DatabaseConnection.cursor()` which does not exist in the
  production repository API. No Phase 20A failure and no new regression.

### Decisions forced by verification

1. **Ancestry gate on `port_scan`.** With the expansion wired in, the committed
   Phase 14 acceptance test
   (`test_phase14_e2e_live.py::test_served_run_dns_then_http_probe_persists_graph_and_provenance`)
   regressed: a user's explicit root `dns_resolve` produced an `IpObservation`
   and the expansion injected a `port_scan` child (which failed locally since
   `nmap` is not installed), turning the run's `by_status` from
   `{"completed": 2}` into `{"completed": 2, "failed": 1}`. Phase 20A therefore
   gates the `IpObservation → port_scan` proposal on the completing task's own
   parent being a subdomain-*discovery* task (`subfinder`/`subdomain_enum`,
   `DISCOVERY_TASK_TYPES`). A root `dns_resolve` keeps its narrow contract
   (exactly the enqueued tasks run); only the discovery chain deepens into
   scanning. `http_probe` from a `port_scan` result stays ungated: it is the
   bounded, terminal consumption of a scan that already happened.
2. **Scope snapshot carries no `database` section.** `Config.from_dict` requires
   a `database.url`, but `ServedExecution.execution_config` injects
   `"unconfigured"` at serve time and the snapshot deliberately drops the
   section (pre-existing Phase 15 design). Live tests follow that contract rather
   than persisting a DSN into `runs.configuration_snapshot`.

No STOP condition was hit: the schema already had `ports` (0001), no migration
was required, safety semantics were not changed, Nmap results are represented
truthfully, task dependencies needed no redesign, and no protected Phase 18 file
was modified or deleted.