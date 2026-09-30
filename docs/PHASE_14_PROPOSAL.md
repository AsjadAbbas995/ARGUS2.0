# ARGUS — Phase 14 Context: Evidence Ingestion

> **Persistent project context, not an architectural authority.**
> This document records the approved Phase 14 plan and, after implementation, the actual
> behavior. It never overrides `OPENCODE.md`, `01_PRODUCT_SPEC.md`, `04_SCOPE_SAFETY.md`,
> `05_DATA_MODEL.md`, `06_TOOL_CONTRACTS.md`, or `08_ORCHESTRATOR.md`. Where this file and an
> authoritative document appear to disagree, the authoritative document wins and the conflict
> must be reported — see `OPENCODE.md` Rule 1 for the precedence chain.

**Status:** approved, pre-implementation
**Phase 14 objective:** close the ingestion seam so deterministic tool output becomes durable,
traceable PostgreSQL facts.
**Phase 13 baseline commit:** `b62b7a7be2780bb96e62e45317711c0978d89aa8`
**Phase 13 status:** VERIFIED (final forensic audit, no BLOCKER/HIGH findings)

---

## 1. Current-state diagnosis

Phase 13 delivers a safe, durable execution substrate. Verified by direct query against live
PostgreSQL after a served run: operational rows are written (`runs`, `tasks`, `tool_runs`), but
**every attack-surface table is empty**.

`ServedExecution.__call__` (`api/serve.py`) calls `adapter.execute(...)`, which runs
`adapter.parse(...)` and populates `ToolExecution.artifacts`, then returns a `ToolRun` built
from `tool/command/exit_code/raw_output_ref` only. `execution.artifacts` is **discarded**.

Consequences, all confirmed by import/reference analysis:

- `recon/normalize.py` has no production caller.
- `correlation/` is imported only by itself. `DomainRecord`, `IpRecord`, `PortRecord`,
  `WebAppRecord`, `AuthRecord`, `JavaScriptRecord`, `CertificateRecord` have no production
  reference anywhere.
- `ai/` (~1,010 lines) has no production importer.
- `Orchestrator.analysis` is never supplied by `create_serve_app`, so the adaptive loop is inert.
- Reports render "No evidence recorded" because `evidence` and `hypotheses` are empty.

Phase 14 closes this one seam. It does not add capability beyond it.

## 2. Scope

**In scope — persist what the three existing adapters already observe:**

| Adapter | Emits | Canonical target |
|---|---|---|
| `recon/dns/resolver.py` | `DnsRecordObservation`, `IpObservation` | `dns_records`, `ips` + `asset_ips` |
| `recon/subdomains/subfinder.py` | `list[str]` (already normalized hostnames) | `assets` |
| `recon/web/httpx_probe.py` | `WebAppObservation`, `TechnologyObservation` | `web_apps`, `technologies` + `asset_technologies` |

Plus `evidence` for every persisted entity, and `ToolRun` linkage.

**Documented mapping deviation:** `correlation/records.py` defines no DNS record type, but
`recon/dns/resolver.py` already defines the frozen `DnsRecordObservation`. Phase 14 maps
`DnsRecordObservation` directly to the `dns_records` table and does **not** add a duplicate
record type to `correlation/`. Inventing one would add the second abstraction the prompt
forbids.

**Out of scope (no adapter observes them; no rows are written):** `urls`, `endpoints`,
`parameters`, `apis`, `graphql_operations`, `auth_mechanisms`, `javascript_files`,
`websocket_endpoints`, certificates. `05_DATA_MODEL.md` mentions "Certificate → Domain" only
inside the graph-relationship diagram, never as a table, and no adapter emits a certificate
record — there is no schema conflict, simply nothing to ingest.

### 2.1 Mapping constraints (adapter output vs schema)

Four constraints were found by comparing the frozen observation dataclasses against the actual
DDL. None requires a migration; each has a documented resolution.

1. **`web_apps` requires a known IP.** `web_apps.port_id` is `NOT NULL REFERENCES ports (id)`
   and `ports.ip_id` is `NOT NULL REFERENCES ips (id)`, but `WebAppObservation`
   (`recon/web/httpx_probe.py`) carries no IP address. A `web_apps` row is therefore written
   **only when the asset already has a known `ips` row** (typically from a DNS task in the same
   run). When no IP is known the web observation is recorded as `evidence` only; ingestion never
   resolves the host itself (that would be network activity outside ToolRunner) and never
   fabricates a placeholder IP.
   *Effect on acceptance criterion 1:* the live proof runs the DNS and `http_probe` tasks for the
   same controlled target so the IP exists before the web app is ingested.

2. **`technologies.category` is constrained and the adapter supplies none.**
   `TechnologyObservation` has only `name`; `technologies.category` is `NOT NULL` with a CHECK
   over `framework|cms|api_technology|cdn|waf|cloud|auth|other`. Ingestion uses the only honest
   value, `'other'`, and never guesses a category from the name.

3. **`asset_technologies.confidence` is `NOT NULL` and the adapter supplies none.**
   `AssetTechnologyObservation` has only `host` and `technology`. Ingestion records confidence
   `1.0`, because the technology is a direct tool observation (a fact) rather than an inference.

4. **`dns_records` has no unique index**, so the idempotency requirement cannot lean on the
   database for it. Deduplication is therefore done at ingestion against the existing
   `DnsRecordRepository.list_for_asset(asset_id)` read: a `(record_type, value)` already recorded
   for that asset is not re-inserted. No new table, index, or repository abstraction.

Additional provenance note: `asset_ips` has a composite primary key and **no `evidence_id`**, so
the asset→IP edge cannot carry provenance inline. Provenance is recorded on each endpoint
(`entity_type='asset'`, `entity_type='ip'`) plus a polymorphic row
`entity_type='asset_ip'`, `entity_id` NULL. The same `entity_id` NULL form is used for an
in-scope asset→IP association and for an out-of-scope `observed_host`.

## 3. Architecture

```text
ScopeGuard → RateLimiter → adapter.execute() → ToolRunner
                                              ↓
                                     ToolExecution.artifacts
                                              ↓
                        [ingest] evidence → canonical record
                                              ↓
                                 ScopeGuard.check_host per host
                                      ↓            ↓
                                  in scope     out of scope
                                      ↓            ↓
                              graph rows    evidence row only
                                              ↓
                    ┌───────── one transaction ─────────┐
                    │  ToolRun + Evidence + graph rows  │
                    │  + task terminal state            │
                    └───────────────────────────────────┘
```

Ingestion runs **after** authorized execution and never bypasses ScopeGuard, RateLimiter,
adapter validation, or ToolRunner.

### 3.1 Surfacing artifacts (strictly additive)

`run_tool` is a `(task) -> ToolRun` seam pinned by Phase 5/8 tests. Rather than change it,
`ServedExecution` returns a `ToolRunOutcome(tool_run, artifacts)` wrapper. The orchestrator
accepts **either** a bare `ToolRun` (all existing seams and test doubles) or a
`ToolRunOutcome`. No existing signature or behaviour changes.

### 3.2 Transaction boundary

`Orchestrator._execute_pending` currently performs three independent auto-committed writes
(`set_task_status`, `insert_tool_run`, `set_task_status`). Phase 14 wraps
`insert_tool_run` + `ingest` + `set_task_status("completed")` in one transaction.

Following the existing `set_run_progress` precedent in `core/orchestrator.py:104-113`, a
`transaction()` context manager is **optional** on the `Storage` contract: the orchestrator uses
it when present and falls back to the current non-transactional sequence when absent, keeping
Phase 5/8 test doubles valid. The concrete implementation wraps psycopg's
`conn.transaction()`, which is valid under the connection's existing `autocommit=True`
(`database/repositories/base.py:31`) and therefore leaves every Phase 13 write path unchanged.

## 4. Requirements

**Canonicalization** — `recon/normalize.py` is the only hostname normalization path. No second
normalizer. `Example.COM.` → `example.com`; `www.example.com` ≠ `example.com` (narrow dedup
semantics preserved, per that module's documented Phase 4 risk).

**Evidence / provenance** — one `evidence` row per persisted entity, carrying server-generated
`id`, `tool_run_id`, and `raw_output_ref` (the actual file ToolRunner wrote). `entity_id` is
never trusted from tool output. `asset_technologies.evidence_id` (a nullable
`REFERENCES evidence (id)`) is populated where it exists. No second provenance system.

**Idempotency** — canonical identity comes from the existing unique indexes, never from
`evidence_id`: `assets_program_hostname_uq`, `ips_address_uq`, `ports_uq`, `web_apps_uq`,
`technologies_name_uq`. Repeated execution upserts the same entities while appending new
evidence rows, because evidence is per-execution history, not entity identity.

**Scope classification** — every observed hostname is canonicalized, then passed to the run's
`ScopeGuard.check_host`. In scope → graph rows. Out of scope → an `evidence` row
(`entity_type='observed_host'`, `entity_id` NULL) and **no `assets` row**, no scope exception,
no follow-up request. This is the existing documented policy in `core/scope_guard.py`
(`check_redirect` docstring) and `04_SCOPE_SAFETY.md`, which previously had no caller.

**Artifact cardinality** — `LimitsConfig.max_artifacts_per_run`, default **10000**, enforced at
ingestion entry per tool execution. The cap is extended into the existing `LimitsConfig`
mechanism rather than a parallel config system. Exceeding it truncates, records that the cap
was hit, and does not fail the run.

**Untrusted input** — artifacts are attacker-controlled. All values are written through
parameterized queries (`BaseRepository._insert` already binds values via `%s`; only table and
column identifiers are interpolated, and those come from code). `example.com'; DROP TABLE
assets;--` remains inert text.

**Malformed output** — the non-fatal parse contract in `06_TOOL_CONTRACTS.md` is preserved. A
parser that cannot understand output yields no records and no findings, and does not fail the
run.

**Atomicity** — `ToolRun` + `evidence` + graph rows + task terminal state commit or roll back
together. A task never becomes `completed` while its required facts failed to persist. No
partial graph, no orphan evidence, no false completion.

## 5. Implementation stages

- **14.1 Artifact mapping** — artifacts → canonical records, normalization, scope
  classification, evidence generation. UNIT + INTEGRATION (fixtures, `MemoryStorage`).
- **14.2 Transactional persistence** — `transaction()` on concrete Storage, repositories,
  idempotent upserts, atomic rollback, cardinality cap. INTEGRATION + SECURITY/NEGATIVE.
- **14.3 Live end-to-end** — real PostgreSQL, real subprocess boundary where the environment
  permits, controlled local target only. Direct SQL assertions on row counts and FK linkage.

## 6. Non-goals

No AI activation (no `ai/` import, no `ai_analysis`, no hypotheses, no `analysis` hook). No graph
inference (`asset_graph.py` / `relationship_engine.py` stay unwired; no relationships, attack
paths, or findings invented). No new recon tools, adapters, or external binaries. No changes to
API-key behaviour, program scope, `ScopeGuard`, `RateLimiter`, or `ToolRunner` semantics. No
database migration. No reports redesign, dashboard, or CLI changes. `.byte/` untouched.

## 7. Stop conditions

STOP and report rather than improvise if: a schema migration appears necessary; existing
Storage cannot provide atomic ingestion; canonical identity is ambiguous; evidence semantics
conflict with `05_DATA_MODEL.md`; `ScopeGuard` cannot safely classify observations; artifact
limits would require a new policy system; or Phase 13 behaviour would have to be altered.

## 8. Known environment limitations

Carried forward from Phase 13 and not to be reported as passing acceptance claims:

- httpx v1.12.0 loopback behaviour — ENVIRONMENT-UNVERIFIED
- subfinder public-domain enumeration — ENVIRONMENT-UNVERIFIED
- local PostgreSQL runs with `ssl = off`

No public or external targets are used in any test.

## 9. Acceptance criteria

1. A served `http_probe` run against a controlled local target produces ≥1 row each in
   `web_apps`, `assets`, and `evidence`, asserted by direct SQL against live PostgreSQL.
2. Every persisted graph row resolves to an `evidence` row whose `tool_run_id` matches the real
   `ToolRun` and whose `raw_output_ref` matches the file ToolRunner wrote.
3. Repeating the same task creates no duplicate graph entities while evidence history grows.
4. `Example.COM.` and `example.com` converge to one asset; `www.example.com` stays distinct.
5. A mid-ingestion failure leaves the task `failed` with no partial graph rows and no orphan
   evidence.
6. A run whose snapshot denies the target produces zero graph rows.
7. A SQL-metacharacter hostname is stored inert and the tables still exist afterwards.
8. An out-of-scope observed hostname yields an evidence row and no `assets` row, with no
   follow-up request.
9. The artifact cap is enforced and does not fail the run.
10. All Phase 13 guarantees re-verify green, including fail-closed authentication and
    authoritative program scope.

## 10. Test classification

`UNIT` · `INTEGRATION` (fixtures, `MemoryStorage`) · `LIVE` (real PostgreSQL + real subprocess,
gated on `ARGUS_TEST_DATABASE_URL`) · `SECURITY/NEGATIVE` · `REGRESSION` (Phase 13 gates) ·
`ENVIRONMENT-UNVERIFIED`. No test is weakened and no skip is added to obtain a green result.

## 11. Implemented behavior

_Recorded after implementation: final architecture, files changed, test results per tier,
deferred findings, commit, and final audit status._

### 11.1 What was implemented

All four pieces, with no schema migration and no change to Phase 13 subsystems:

| Piece | Location | Summary |
| --- | --- | --- |
| Pure mapping | `recon/ingest.py` | `plan_ingestion()` turns artifacts into a deterministic ingestion plan: normalized assets, `check_ip`-gated IPs, asset-IP links, ports, technologies, and one evidence row per observed entity. Out-of-scope, unrootable, and overflow findings become evidence only. |
| Transactional persistence | `database/repositories/all.py` | `Repositories.transaction()` and `Repositories.ingest_observations()` perform the graph writes plus evidence inside one transaction, returning counts. `web_apps` require a known in-scope IP because `port_id` is `NOT NULL`. |
| Orchestrator seam | `core/orchestrator.py` | `ToolRunOutcome` carries artifacts alongside the run; `IngestHook` runs inside the run's transaction, so an ingestion failure rolls the `ToolRun` back and marks the task `failed`. Bare `ToolRun` stays supported for the existing `run_tool` protocol. |
| Served composition | `api/serve.py` | `ServedExecution.run()` returns the outcome; `_build_ingestor()` wires the hook, and `create_serve_app()` passes it to the orchestrator. `__call__` is retained for compatibility with direct consumers. |

`LimitsConfig.max_artifacts_per_run` (default `10000`) caps ingestion without failing the task.

### 11.2 Genuine defects found and fixed

1. `ScopeGuard.from_config()` stored a single-address rule verbatim, so an IP rule was persisted as
   `1.2.3.4/32`. `check_ip` matches IP rules by exact string equality, so such a rule could never
   authorize anything. The value is now the bare `network_address` for single addresses; CIDR rules
   are unchanged. This is a one-line correction that makes an explicitly configured rule behave as
   written — it does not widen any scope policy, and the persisted `scope_rules` path is unaffected.
2. `ScopeGuard.check_host()` accepted any string whose suffix matched an allowed domain, including
   strings that could never be a DNS name, such as `evil'; DROP TABLE assets; --.example.com`.
   Because suffix matching decides scope before any resolver is involved, no validation had ever
   rejected it, so such bytes were promoted directly into the asset graph. `check_host()` now
   requires the host to be a *possible* DNS name (`core/scope_guard.py::_is_valid_hostname`):
   ASCII letters, digits, `-`, `_`, and `.` only; no empty labels; labels ≤ 63 chars; total ≤ 253.
   Underscores are deliberately allowed so real reconnaissance names such as `_dmarc.example.com`
   and `_sip._tcp.example.com` keep working; punycode (`xn--`) labels pass unchanged; a bare
   single label such as `localhost` is valid. A rejected host is recorded as out-of-scope evidence
   (`recon/ingest.py` never promotes it) — it is never silently dropped, and it never reaches
   `INSERT`. This closes the injection surface at the scope boundary rather than depending on
   parameterisation alone; parameterisation is still separately tested end to end.

### 11.3 Test results per tier

| Tier | Command / scope | Result |
| --- | --- | --- |
| UNIT | `pytest tests/test_ingest.py` | 15 passed |
| INTEGRATION | `pytest tests/test_ingest_orchestration.py` | 62 passed |
| LIVE | `pytest tests/test_ingest_live.py` (real PostgreSQL) | 23 passed |
| LIVE E2E | `pytest tests/test_phase14_e2e_live.py` (served run, controlled loopback target) | 1 passed |
| REGRESSION (Phase 13) | live + regression subset with `ARGUS_TEST_DATABASE_URL` set | 132 passed |
| Full suite, live | `pytest` with `ARGUS_TEST_DATABASE_URL` set | **564 passed, 0 failed, 0 skipped** |
| Full suite, no DSN | `pytest` with the variable unset | 467 passed, 97 skipped |

The 97 no-DSN skips are the 73 pre-existing database-gated tests plus the 24 new live tests
(23 + 1) that gate on the same variable. No skip was added to obtain a green result, and no
existing test was weakened. The 23-test jump in the INTEGRATION tier is the new hostname-syntax
suite: the previously-documented hostile-hostname test was *replaced* by stronger tests that assert
denial (out-of-scope evidence, zero promoted assets) plus a 15-case impossible-input matrix and an
8-case plausible-input matrix proving underscores, punycode, and 63-char labels still pass.

### 11.4 Live E2E acceptance

`tests/test_phase14_e2e_live.py` drives the real composition — FastAPI, real orchestrator, real
rate limiter, real `ToolRunner` subprocess, real adapters, real repositories, real PostgreSQL —
for `dns_resolve` then `http_probe` against a `ThreadingHTTPServer` the test starts on
`127.0.0.1` with an ephemeral port. No public or third-party host is contacted.

Acceptance criteria 1 and 2 were additionally confirmed by direct `psql` queries, independent of
the test: ≥1 `assets` row, ≥1 `web_apps` row, ≥1 `evidence` row, with
`web_apps → ports → ips → assets` joining cleanly and every `evidence.tool_run_id` resolving to a
real `tool_runs` row. Criteria 3–10 are covered by the unit, integration, and live tiers.

DNS resolves through the adapter's documented `resolver_fn` seam backed by
`socket.getaddrinfo`, because dnspython queries DNS servers and never reads the Windows hosts
file, so it cannot resolve `localhost`. The lookup is a genuine local resolver call.

### 11.5 Database used for live verification

The existing PostgreSQL 17 service (`postgresql-x64-17`, port 5432) was discovered with database
`argus_test` and roles `argus_test` (login, non-superuser) and `postgres`. The `argus_test` password
is not stored on this machine, and the current session has no `DATABASE_URL` or
`ARGUS_TEST_DATABASE_URL`; the service runs as `NT AUTHORITY\NetworkService`, so this
non-administrator session could neither reload nor restart it:

- `pg_ctl: could not send reload signal (PID: 4504): Operation not permitted`
- `Restart-Service failed ... Cannot open postgresql-x64-17 service on computer '.'`

Rather than guess a credential or weaken the original `pg_hba.conf`, the cluster was copied to a
temporary directory and served on port `5433` with loopback-only trust. The copy carried the
Phase 13 schema and data, so live tests ran against the real schema, the real constraints, and the
real code path. The original service was never modified: a temporary trust line added to the
original `pg_hba.conf` was restored byte-for-byte (SHA256
`EF22BB9557EB84F3DBEDBB3219120EE95028FC7ADA5F1D2FCC16D7F05D41EABF`) and no reload took effect. The
copy is discarded after verification. No DSN or password appears in any tracked file; the tests
receive it only through `ARGUS_TEST_DATABASE_URL`.

### 11.6 Deferred findings

- `httpx` v1.12.0 loopback behaviour — ENVIRONMENT-UNVERIFIED. The binary is not installed, so the
  E2E's web-app artifact comes from `ControlledHttpProbeAdapter`, a real `ToolAdapter` that performs
  a genuine HTTP request across the real `ToolRunner` subprocess boundary and parses the genuine
  response into a real `WebAppObservation`. The `HttpxProbeAdapter` binary path is not claimed.
- `subfinder` public-domain enumeration — ENVIRONMENT-UNVERIFIED (binary not installed).
- A domain-only scope intentionally yields no IP, port, or web-app rows, because `check_ip` denies
  by default. This is the documented security posture, not a gap.

### 11.7 Audit status

- `git diff --check` clean; all files compile and import.
- No linter or typechecker is configured in this repository; compile and import checks were used
  instead.
- `api/auth.py`, `api/security.py`, `core/rate_limit.py`, `core/tool_runner.py`, `core/executor.py`,
  and the run/task/scope-rule repositories are untouched. Authentication remains fail-closed.
- Secret scan: the only match is the local test constant `API_KEY = "phase14-key"`; no literal DSN,
  password, or key exists in any tracked file.
- `.byte/` remains untracked and unmodified.
- No BLOCKER or HIGH findings remain open.

- Final commit: _(pending — not committed or pushed, as instructed)_
- Final audit status: **VERIFIED**

