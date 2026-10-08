# Phase 22 Proposal — Deterministic Web Crawling (Katana)

## Phase 22 status

**Authoring only — not implemented.** This document is the canonical specification.
Phase 21A is complete (`docs/PHASE_21A_PROPOSAL.md`, status closed). Phase 22 defines
the **next still-uncovered recon stage** after `tech_detect` in the documented stage
ordering (`ai/recon_agent.STAGE_PRIORITY`, `docs/03_RECON_PIPELINE.md` §9→§10→§11):

```
subdomain_enum → dns_resolve → port_scan → http_probe → tech_detect → web_crawl
```

Phase 22 **authoring pass** only: no source, test, migration or configuration file is
changed by this document. Implementation proceeds only after this proposal is accepted,
and every fact below was verified against the current repository.

### Authoring verification and discrepancies

Everything in this proposal was checked against the live code, not copied from the
Phase 22 brief. Discrepancies between the brief and the repository are **documented
here, not silently worked around**:

1. **The committed correlation model has no ``UrlRecord``.** `correlation/records.py`
   already defines `EndpointRecord`, `ParameterRecord`, `JavaScriptRecord` (plus
   `AuthRecord`, `ApiRecord`, `CertificateRecord`), and `correlation/asset_graph.py`
   already builds nodes/edges for `endpoint`, `parameter` and `javascript` kinds — but
   there is **no ``url`` record kind, no ``UrlRecord`` dataclass, and no url edge
   builder**. The brief asked only for `database/projection.py` to "emit projection
   records for url". That is impossible without adding a record type. Resolution in
   this proposal: add a new, **additive** `UrlRecord` dataclass and a `_url_edges`
   builder (`☑ 3` below), which the existing generic `record_node`/`dedupe_*` code
   already accommodates. No existing record, edge or inference rule changes.
2. **``urls``/``endpoints``/``parameters`` impose NOT-NULL or CHECKed columns the
   brief's observation model omitted.** `parameters.location`
   (`CHECK IN ('query','body','header','path')`) and `parameters.significance`
   (`CHECK IN ('object_id','pagination','filter','sort','unknown')`) are NOT NULL;
   `endpoints.method` is NOT NULL; `urls.web_app_id` and `urls.source` are NOT NULL.
   The data model must therefore say, honestly, what a crawl-derived parameter is:
   `location='query'`, `significance='unknown'` (never guessed), and endpoint method
   `GET` only for the navigations Katana actually performs (never fabricated for
   POST/PUT/… routes). See `☑ 1`, `☑ 2`, `☑ 7`.
3. **``urls.web_app_id NOT NULL`` and ``web_apps.port_id NOT NULL`` chain every crawl
   fact to a persisted web application, which itself requires a recorded IP** (the
   rule `recon/ingest.py` already applies to `WebAppObservation`). A crawl fact whose
   parent web app is not persisted is preserved as an observation only — mirroring the
   existing `ENTITY_OBSERVED_WEB_APP` pattern. See `☑ 7`.
4. **The `web.crawling` toggle must be honored inside expansion.** The brief requires
   it, but expansion currently reads `config` only for task fingerprints. The proposal
   adds an explicit `web.crawling` gate to the `WebAppObservation` branch (`☑ 8`).
5. **`13_TESTING_STRATEGY.md` shows a repo-root `fixtures/` tree; the real fixture
   root is `tests/fixtures/`** (existing: `subfinder/`, `httpx/`, `dns/`; convention
   `FIXTURES = Path(__file__).parent / "fixtures" / "<tool>"`). Phase 22 creates
   `tests/fixtures/katana/` (not a repo-root `fixtures/`).
6. **`web_crawl` will legitimately start the inference engine.** Emitting
   `endpoint`/`parameter`/`javascript` graph nodes activates the committed
   relationship engine, which gates its rules on `ENDPOINT_KINDS` (only `endpoint`,
   `parameter`, `auth`, `javascript`, `api`) — its first real inputs since Phase 8.
   That is an expected consequence, not a regression; the engine and its gating are
   not modified (`☑ 3`).

---

## 1. Status / rationale

- Status: **proposed** (authoring pass complete; not implemented).
- Rationale: Phase 20A built discovery breadth (`subfinder`→`dns_resolve`→`port_scan`
  →`http_probe`); Phase 21A added deterministic `tech_detect`. The next documented,
  still-uncovered recon stage in `STAGE_PRIORITY` after `tech_detect` is `web_crawl`
  (`docs/03_RECON_PIPELINE.md` §11 "Web Crawling"). `PHASE_20A_PROPOSAL.md`
  (non-goals) explicitly deferred URL crawling and Katana; `PHASE_21A_PROPOSAL.md`
  §12 still lists `web_crawl` as `uncovered_without_capability`. Phase 22 closes that
  gap exactly the way Phase 21A closed `tech_detect`: a registered capability that
  makes the existing coverage machinery fire, with no AI involvement.

## 2. Objective

After `http_probe` confirms a live in-scope web application (`WebAppObservation`),
deterministically crawl **bounded, in-scope** URLs/paths/forms/linked-JS and API
routes with Katana, and normalize the results into `urls`, `endpoints`, `parameters`
and `javascript_files` canonical records with run-scoped evidence provenance, under
the existing ARGUS safety guarantees (Scope Guard, Rate Limiter, bounded depth, bounded
timeouts, partial results preserved).

## 3. Scope

- The **`web_crawl` stage only** (Katana).
- Adapter, ingestion, persistence, expansion, served registration, coverage wiring,
  projection, tests.
- New, **additive** record type `UrlRecord` + url graph edges (discrepancy `1`).
- Recorded-fixture testing (never a live/external target in CI) plus a PG-gated live
  pipeline test in the Phase 20A/21A pattern.

## 4. Non-goals

Phase 22 explicitly does **not** implement:

- FFUF, Feroxbuster (content discovery, `docs/03_RECON_PIPELINE.md` §12)
- GAU, Wayback (historical recon, §13)
- JavaScript/src-map deep analysis (§14–15) — `javascript_files` rows are recorded
  with no endpoint linkage (empty `endpoint_keys`)
- API discovery, OpenAPI/Swagger, GraphQL, WebSockets (§16–19)
- Authentication/authorization intelligence, parameter *significance* inference (§20–22)
- Cloud/CDN/WAF intelligence (§23–24)
- Vulnerability confirmation, exploitation, brute force, destructive scanning
- AI/LLM analyst wiring, adaptive-loop changes, coverage-computation changes
- Report rendering sections (reports are out of scope; only the projection payload
  changes)
- New configuration options (reuses `WebConfig.crawling`)
- Database migrations (schema already has every table this phase needs)

## 5. Architecture / data flow

```
http_probe (completed)
   WebAppObservation (host in scope, port in WEB_PORTS)
        │  recon/expansion.py  (crawl seed = observed app URL; no second request)
        ▼
   task: type=web_crawl, target=<observed url>, reason={"url": ...}
        │  api/serve.py ServedExecution.adapter_for("web_crawl"|"katana")
        ▼
   KatanaAdapter  (recon/web/katana.py)
        │  is_available → validate(scope) → build_command → ToolRunner
        │  katana -u <url> -jsonl -js-crawl -depth <n>
        ▼
   ToolRunner (overall timeout; rate-limiter permit already taken by orchestrator)
        │  raw preserved → storage/raw/katana/<timestamp>_<tag>_<nonce>.out
        ▼
   parse()  (JSONL, non-fatal on malformed lines)
        ▼
   UrlObservation / EndpointObservation / ParameterObservation /
   JavascriptFileObservation
        │
        ▼
   recon/ingest.plan_ingestion  (scope-classified, host re-checked, capped)
        │  IngestionPlan gains urls/endpoints/parameters/javascript_files
        ▼
   Repositories persistence (same transaction as ToolRun via _build_ingestor)
        │  urls/endpoints/parameters/javascript_files (+evidence rows, entity_id)
        ▼
   database/projection.build_records
        │  DomainRecord/IpRecord/PortRecord/WebAppRecord/UrlRecord/
        │  EndpointRecord/ParameterRecord/JavaScriptRecord (+technology)
        ▼
   correlation.asset_graph (existing) → attack_surface.graph / by_kind
```

## 6. Exact implementation files

| File | Change |
|---|---|
| `recon/web/katana.py` | **new** — `KatanaAdapter(ToolAdapter)`, observations |
| `recon/ingest.py` | add plan dataclasses + 4 artifact branches + 4 entity tags |
| `database/repositories/all.py` | add `UrlRepository`, `EndpointRepository`, `ParameterRepository`, `JavascriptFileRepository` |
| `recon/expansion.py` | `WebAppObservation` → `web_crawl` child + crawl-reuse reason; `web.crawling` gate |
| `api/serve.py` | `DEFAULT_WEB_CRAWL_TYPES = ("web_crawl", "katana")` + `_default_adapters` registration |
| `ai/run_context.py` | `TASK_TYPE_COVERS_STAGE` += `web_crawl`→`web_crawl`, `katana`→`web_crawl` |
| `database/projection.py` | emit url/endpoint/parameter/javascript records; update `UNPRODUCED_RECORD_KINDS` |
| `correlation/records.py` | **new** `UrlRecord` (discrepancy `1`) |
| `correlation/asset_graph.py` | **new** `_url_edges` (url → web_app `serves_url` edge) |
| `core/config.py` | **no change** — `WebConfig.crawling` already exists (default `true`) |
| `tests/test_katana.py` | **new** — offline adapter/fixture tests |
| `tests/fixtures/katana/` | **new** — recorded JSONL fixtures |
| `tests/test_expansion.py` | extend — web_crawl mapping + reuse-reason + toggle |
| `tests/test_ingest.py` | extend — four crawl branches + scope + cap |
| `tests/test_phase16.py` | gate `covered` set += `web_crawl` |
| `tests/test_phase22_live.py` | **new** — PG-gated pipeline/persistence/projection test |
| `docs/PHASE_22_PROPOSAL.md` | this document |

## 7. Existing schema / repository assumptions (verified)

Tables already exist (1002-produced baseline migrations; **no migration in Phase 22**):

- `urls`: `web_app_id → web_apps` (NOT NULL), `path`, `source`, `historical` (default
  false) — **UNIQUE `(web_app_id, path)`**.
- `endpoints`: `url_id → urls` (NOT NULL), `method`, `pattern` — **UNIQUE
  `(url_id, method, pattern)`**, index on `pattern`.
- `parameters`: `endpoint_id → endpoints` (NOT NULL), `name`, `location`
  (`CHECK ('query','body','header','path')`), `significance`
  (`CHECK ('object_id','pagination','filter','sort','unknown')`) — **UNIQUE
  `(endpoint_id, name, location)`**.
- `javascript_files`: `web_app_id → web_apps` (NOT NULL), `url`, `has_source_map`
  (default false) — **UNIQUE `(web_app_id, url)`**.

Repository facade (`database/repositories/all.py`) currently has **no** url/endpoint/
parameter/javascript repositories — Phase 22 adds them following the existing
`BaseRepository`/`upsert` (+ `ON CONFLICT … DO UPDATE` returning `id`) and
`INSERT … RETURNING id` patterns (`TechnologyRepository.upsert`, `WebAppRepository.upsert`).
`urls.source = 'katana'` matches the documented source vocabulary. The design **does not
redesign the schema**.

Rooting constraint (discrepancy `3`): every crawl fact is parented to a persisted
`web_apps` row (`web_apps.port_id NOT NULL`). Ingestion reuses the Phase 14 rule: a web
app is persisted only for an in-scope host whose IP was itself recorded. A crawl fact
that cannot be rooted is preserved as an observation (new `ENTITY_OBSERVED_*`-family
tag, e.g. `entity_url` observation rows) and is **never** linked to an unrecorded
parent.

## 8. Expansion behavior

`recon/expansion.py` extends the existing `WebAppObservation` branch (the same branch
Phase 21A added). When all of these hold:

- `available_types` contains `web_crawl` or `katana` (allowlist, as today),
- the web app's host is in scope (`scope.check_host`),
- `artifact.port in WEB_PORTS`,
- the run's snapshot honors `web.crawling` (`config.get("web", {}).get("crawling", True)`
  — discrepancy `4`),

a child `Task(type="web_crawl")` is proposed with:

- `target` = the already-observed application URL (`WebAppObservation.url`), falling
  back to `f"http://{host}:{port}/"` (https when the port is a conventional TLS port);
  **no second HTTP request** is performed to establish the seed;
- `reason` = `_web_crawl_reuse_reason(artifact)` → `json.dumps({"url": <url>},
  sort_keys=True)` (the Phase 21A `Task.reason` reuse-payload pattern), so the adapter
  never re-derives the URL from the target and the first condition from
  `06_TOOL_CONTRACTS.md` §Katana ("Input: live web application URL") is satisfied
  deterministically;
- dedup fingerprint `task_fingerprint("web_crawl", target, config, parent)`.

Resulting chain:

```
http_probe ──► web_crawl ──► (completed artifacts → ingestion → projection)
```

`available_types` and `max_tasks` bounds, fingerprint dedup in
`api/serve._enqueue_expansion`, and the "absent scope ⇒ no expansion" rule are
unchanged.

## 9. Safety / scope rules

Phase 22 MUST:

- execute only after `http_probe` confirms a live web app (`docs/03_RECON_PIPELINE.md`
  §11 "Execution conditions");
- respect the Scope Guard at every layer (adapter `validate` against the run's guard;
  ingestion re-checks the host; expansion re-checks the host before proposing);
- respect the configured Rate Limiter (orchestrator takes the permit before the tool
  runs — unchanged);
- enforce **bounded crawl depth** (adapter passes `-depth <n>`, small configured
  default) and **overall + per-request timeouts** (runner-level overall timeout from
  config; per-request timeout argument passed to Katana), per §Katana "Safety:
  depth/time bounded, rate-limited";
- **re-check every discovered host through the Scope Guard before any follow-up
  crawling** of it (`docs/03_RECON_PIPELINE.md` §11 "Any newly-discovered domain from a
  link must pass the Scope Guard before being crawled itself");
- treat out-of-scope discoveries as **evidence only** — never a graph row, never a
  task (`04_SCOPE_SAFETY.md`, `PHASE_20A_PROPOSAL.md` non-goals);
- **never** use an out-of-scope discovery to authorize another task;
- **never** interpret discovery as vulnerability confirmation;
- never perform destructive scanning, brute force, DoS behavior, evasion, credential
  attacks, or automatic scope expansion;
- preserve **partial results** when execution produced partial evidence (per-URL
  failures non-fatal; `IngestionPlan.unrecognized/truncated` accounting unchanged).

## 10. Configuration behavior

- `web.crawling` (`core/config.WebConfig.crawling`, default `true`) gates the
  `WebAppObservation` → `web_crawl` expansion branch (discrepancy `4`). When false, no
  crawl task is proposed; `http_probe`/`tech_detect` behavior is unchanged.
- `network.tcp_ports` and scope rules are unchanged.
- `limits.max_artifacts_per_run` (default 10000) caps the ingested artifact count —
  crawl output is capped like any other tool, preserving partial results, honoring the
  `truncated` accounting.
- Adapter-specific bounds are pure constants on `KatanaAdapter` (depth default, overall
  timeout), consistent with how other subprocess adapters fix their own safe values.

## 11. Testing strategy

Following `13_TESTING_STRATEGY.md` (fixture parsing, no live/external targets in CI)
and the recorded-fixture pattern of `tests/test_httpx.py` /
`tests/test_dns.py` (`FIXTURES = Path(__file__).parent / "fixtures" / "<tool>"`):

- **`tests/fixtures/katana/`**: recorded Katana JSONL — `normal.ndjson`,
  `empty.ndjson`, `malformed.ndjson` (mixed good/bad lines), `duplicates.ndjson`.
- **`tests/test_katana.py`**: parse valid records → four observation kinds; malformed
  lines skipped non-fatal; empty input → no artifacts; duplicate URLs deduplicated;
  normalization (path extraction, query-stripping, method/parameter honesty);
  scope behavior (out-of-scope host refused via `ScopeViolation`); timeout plumbing;
  missing-binary behavior (`is_available() == False` → `ToolUnavailable`, never a
  crash); partial-result behavior (valid lines preserved even when others fail);
  registration (`web_crawl` and `katana` dispatch; `known_task_types()` contains both;
  unregistered types stay `UnknownTaskType`).
- **`tests/test_expansion.py`**: `WebAppObservation` → `web_crawl` mapping; seed URL
  from `artifact.url` (no re-request); `reason` reuse payload exact match; scope
  gating; `WEB_PORTS` gating; allowlist gating; `web.crawling: false` suppression.
- **`tests/test_ingest.py`**: four crawl artifact branches → plans; host re-scope;
  unrooted-fact observation-only path; cardinality cap/truncation.
- **`tests/test_phase16.py`**: gate `covered` set += `web_crawl`; registry
  membership (`web_crawl`, `katana`).
- **`tests/test_phase22_live.py`**: PG-gated (conftest `database_url` +
  Phase-20A/21A `schema`/`store` local fixtures). Uses harness doubles for the
  adapter's `execute` only (binary availability is not required for CI) with **real**
  orchestrator, scope guard, rate limiter, ingestion, expansion, repositories,
  projection and served registry. Asserts: expansion enqueues exactly one `web_crawl`
  child with the reuse payload; persisted `urls`/`endpoints`/`parameters`/
  `javascript_files` rows with correct uniqueness; `evidence` rows with `entity_id`
  provenance; `attack_surface` `by_kind` counts; `coverage_gaps()` no longer contains
  `web_crawl` and `uncovered_without_capability()` no longer does either; the web_crawl
  child is completed; no other stage regressed.

## 12. Offline verification (no database, no live target)

1. `pytest tests/test_katana.py tests/test_expansion.py tests/test_ingest.py
   tests/test_phase16.py -q` → all pass.
2. Full offline suite `pytest -q --ignore=tests/test_phase18_live2.py` (current
   baseline: **688 passed / 177 skipped / 0 failed**) — zero new failures.
3. `git diff --check` clean; no protected/migration/test_phase18 files touched.

## 13. Live verification (PG-gated)

1. Start the sandbox PostgreSQL (established pattern; `ARGUS_TEST_DATABASE_URL` set).
2. `pytest tests/test_phase22_live.py tests/test_phase20_live.py
   tests/test_phase21_live.py tests/test_phase16_live.py -q` → all pass.
3. Full suite with the DB up — no **new** failures beyond the 6 documented
   pre-existing ones (5 × `test_database_live.py` migration-bookkeeping list vs the
   baseline `0006` migration; 1 × `tests/test_phase18_live.py:29` `cursor()`
   attribute on `DatabaseConnection`). Phase 21A's live run recorded this exact set;
   Phase 22 must not grow it.

## 14. Failure / partial-result behavior

- **Missing Katana binary**: `KatanaAdapter.executables = ("katana",)`; `is_available()`
  false → base `execute` raises `ToolUnavailable`, which the orchestrator/log layer
  catches and logs; the run continues with other sources — graceful, never a crash.
- **Malformed JSONL**: individual records skipped and logged; valid records kept
  (`parse` accepts empty/malformed/partial output, per `recon/base.py` contract).
- **Per-URL crawl/request failures**: non-fatal, crawl continues
  (`06_TOOL_CONTRACTS.md` §Katana "crawl errors per-URL logged, crawl continues").
- **Timeout**: overall bound at the ToolRunner; timed-out execution is recorded
  (`CommandResult.timed_out`, raw preserved under `tag="timeout"`) and partial output
  still parsed.
- **Partial results**: any artifacts parsed before failure still enter ingestion;
  unrooted crawl facts are preserved as observations, never dropped and never
  fabricated into rows.
- **Ingestion caps**: `max_artifacts_per_run` truncation and `unrecognized` counts are
  reported without aborting the run.

## 15. Compatibility requirements

- **Additive only**: existing records, edges, inference rules, gate/served plumbing
  and reports paths are unchanged. `UNPRODUCED_RECORD_KINDS` is narrowed to
  `("api", "auth", "certificate")`.
- The new `UrlRecord` mirrors the documented graph spine
  (`correlation/asset_graph.py` docstring: "…Web App → URL → Endpoint → Parameter…") —
  a pre-designed, now-produced link, not a redesign.
- All key formats already exist for the other record kinds; `javascript`-kind naming
  (kind = `javascript`) is unchanged from committed code.
- Determinism: same persisted run → byte-identical projection; fixture order and
  `evidence` linkage follow the existing rules (first evidence row per entity wins).

## 16. Explicit protected files

Phase 22 must **not** modify:

- `ai/loop.py`, `api/server.py`, `dashboard/*`, `reports/*_report.py`
- `database/models/entities.py`, `database/migrations/000*.sql` (all 0001–0006),
  `.byte/`
- `docs/13_TESTING_STRATEGY.md`, `docs/PHASE_17_PROPOSAL.md`
- `tests/test_phase17.py`, `tests/test_phase18.py`, `tests/test_phase18_live*.py`
  (`test_phase18_live.py`, `test_phase18_live2.py`, `test_phase18_live_fast.py`,
  `test_phase18_live.py.b64`, `test_phase18_live_fast.py.tmp`)
- The pre-existing uncommitted Phase 18/20A/21A working-tree state is left as-is.

## 17. Acceptance criteria

1. `recon/web/katana.py` exists; `KatanaAdapter` passes fixture-parse, scope, timeout,
   missing-binary and partial-result tests; raw preserved under
   `storage/raw/katana/`.
2. Ingestion maps the four observation kinds into `IngestionPlan` fields with the DB's
   NOT-NULL/CHECK semantics respected (parameters always carry `location` +
   `significance`; endpoint method honest).
3. New repositories persist rows exactly per the existing UNIQUE constraints
   (`(web_app_id, path)`, `(url_id, method, pattern)`, `(endpoint_id, name, location)`,
   `(web_app_id, url)`); duplicate upserts update in place; no migration.
4. Expansion proposes exactly one in-scope `web_crawl` child per qualifying
   `WebAppObservation` with the reuse `reason`; honors the allowlist and the
   `web.crawling` toggle; never adds a second request.
5. Served registry: `("web_crawl", "katana")` registered through `_default_adapters`;
   `known_task_types()` contains both; unregistered types still fail with
   `UnknownTaskType`.
6. Coverage: `TASK_TYPE_COVERS_STAGE` maps both spellings; a completed `web_crawl`
   task removes `web_crawl` from both `coverage_gaps()` and
   `uncovered_without_capability()`; the gate test in `test_phase16.py` is updated and
   green.
7. Projection emits url/endpoint/parameter/javascript records with `evidence_id`
   provenance; `graph` gains url/endpoint/parameter/javascript nodes/edges; only
   `api`/`auth`/`certificate` remain in `UNPRODUCED_RECORD_KINDS`; relationship-engine
   changes (first real endpoint-class inputs) are expected and exercised by tests.
8. Offline + live suites: as defined in §12 and §13 — zero new failures, nothing
   committed.

## 18. Commit boundary

One logical commit after acceptance and green verification:

```
docs: author phase 22 proposal (web crawling / katana)
docs/test: phase 22 …      — subsequent implementation commits
```

The proposal commit contains **only** `docs/PHASE_22_PROPOSAL.md`. Implementation is
a separate, later change set that touches exactly the files in `☑ 6`, ships the tests
in `☑ 11`, and leaves every protected file (`§16`) untouched. Nothing is staged or
committed by this authoring pass.