# Phase 24 Proposal — Historical Recon (GAU)

**Status:** PROPOSAL ONLY. Nothing in this document is implemented. It defines the
next highest-value *uncovered* reconnaissance stage, the exact interfaces it would
touch, and the tests/acceptance criteria that would prove it. No code, migration,
config, or test is changed by authoring it.

**Baseline this proposal was authored against**

- Repository HEAD: `960cc602bb13dfe3a217e17c843649f3eee74baf` ("feat: implement
  phase 23 content discovery"), on branch `master`.
- Working tree carried pre-existing uncommitted/untracked changes (Phase 18/21A
  artifacts, `recon/web/tech_detect.py`, `database/migrations/0006_ai_coverage_gaps.*`,
  `.byte/`, etc.). None of them are touched by this phase.
- `docs/PHASE_24_PROPOSAL.md` did not previously exist.

**Interpretation caveat.** Everything below is a proposal and remains an
inference/hypothesis until validated at implementation time. Where an external
tool's exact flags or output shape could not be verified from the repository, this
document says so explicitly and marks it as requiring implementation-time
verification. No function, config key, column, or capability is invented; all named
interfaces below were read from the repository at the baseline above and are cited
by file path.

**Phase 24 review amendments (post-review revision).** A review gate amended this
proposal before approval. The following defaults were adopted and are reflected
throughout:

1. The config gate is fail-closed and **defaults to disabled** (`web.historical_urls:
   false`); enablement is an explicit operator opt-in (§6).
2. Historical URLs do **not** trigger active probing in this phase — the `http_probe`
   expansion is deferred to a separate, opt-in follow-up (§3, §5, §16).
3. The tool runner gains a **bounded streaming capture** — *not* post-capture
   truncation. stdout/stderr are read incrementally against a per-stream byte budget, so
   the **retained captured bytes** (not merely the returned string) are hard-capped; on
   overflow the process tree is terminated and `CommandResult.truncated=True`. The cap
   bounds retained output, not total process RSS (§4, §7, §16).
4. The `urls` upsert uses a **corrected `CASE`** with the full truth table in §10: a
   historical row promoted by a live observation takes the **incoming live** source; a
   live row keeps its source against a historical observation; live-to-live keeps
   last-writer-wins.
5. `historical` is a **required** parameter on `UrlPlan` and `UrlRepository.upsert`, so
   a passive adapter cannot silently promote a URL by omitting it (§4, §10).
6. The "re-propose indefinitely" risk was corrected: the loop is bounded by fingerprint
   dedup and terminates (§16).
7. This revision resolves the two remaining review blockers: the incorrect promotion
   `CASE` and the memory-unbound output capture. `§4`, `§7`, `§10`, `§12`, `§13`,
   `§14`, `§15`, and `§16` were updated to match.

---

## 1. Current status, baseline, and purpose

The pipeline is implemented through **content discovery** (Phase 23). The next
documented, separable reconnaissance stage that is not yet implemented and is not
blocked by an unbuilt subsystem is **Historical Recon**
(`docs/03_RECON_PIPELINE.md:181` §13), served by **GAU** (Wayback deferred; §16).
Historical recon passively recovers URLs/paths that may no longer be directly linked —
old API versions, deprecated routes, forgotten applications — and records them as
historical `urls` rows for later, separately-gated liveness verification.

Its substrate is unusually complete for a not-yet-implemented stage:

- `recon/historical/` exists as a package whose module docstring already names the
  adapters: `"""Historical recon adapters (gau, wayback). Placeholder."""`
  (`recon/historical/__init__.py`), and `tests/test_smoke.py:16` already imports it.
- The tool contract is written: `docs/06_TOOL_CONTRACTS.md:174` (GAU) and
  `:184` (Wayback), including command, output format, parser target, raw path, and
  safety rules.
- The config gate exists and is already serialized into run snapshots:
  `WebConfig.historical_urls` (`core/config.py:171`), emitted by `Config.to_dict`
  (`core/config.py:447`) and `run_snapshot_from_dict` (`core/config.py:557`). Its
  current default is `True`; **Phase 24 flips that default to `false`** so the stage is
  an explicit opt-in and fails closed (§6).
- The persistence column exists: `urls.historical boolean NOT NULL DEFAULT false`
  (`database/migrations/0001_initial_schema.sql:200`), with the documented lifecycle
  "flips to false only after a fresh liveness check" and a `source` vocabulary that
  already includes `gau`/`wayback` (`docs/05_DATA_MODEL.md:205-216`).

The purpose of Phase 24 is to turn that substrate into a working, bounded,
passive historical-URL discovery stage that reuses the existing observation →
ingestion → persistence → projection → coverage machinery, rather than adding a
parallel pipeline.

## 2. Verified coverage reconstruction and selected-stage rationale

### 2.1 Verified coverage

`ai/recon_agent.py:21` (`STAGE_PRIORITY`) lists 18 stage names (the module-level
comment at `ai/run_context.py:23` still says "17 documented recon stages" — a stale
count, noted under §16). A stage counts as **covered** only when a task of exactly
the mapped type reaches status `completed` (`ai/run_context.py:58-83`,
`_COVERED_STATUSES`).

| Stage | In `STAGE_PRIORITY` | Covered | Capability (verified) |
|---|---|---|---|
| subdomain_enum | yes | yes | `subfinder` (`api/serve.py:86,347`) |
| dns_resolve | yes | yes | `DnsResolverAdapter` (`api/serve.py:78,332`) |
| port_scan | yes | yes | `NmapAdapter` (`api/serve.py:87,350`) |
| http_probe | yes | yes | `HttpxProbeAdapter` (`api/serve.py:79,341`) |
| tech_detect | yes | yes | `TechDetectAdapter` (`api/serve.py:80,357`) |
| web_crawl | yes | yes | `KatanaAdapter` (`api/serve.py:92,363`) |
| content_discover | yes | yes | `FfufAdapter` (`api/serve.py:99,369`) |
| js_analysis | yes | **no** | none — `intelligence/` is an empty stub |
| api_discover | yes | **no** | none — depends on `js_analysis` |
| openapi_schema | yes | **no** | none |
| graphql_recon | yes | **no** | none |
| websocket_recon | yes | **no** | none |
| parameter_intel | yes | **no** | none — depends on `js_analysis` + `api_discover` |
| auth_intel | yes | **no** | none |
| authz_analysis | yes | **no** | none |
| logic_analysis | yes | **no** | none |
| cloud_intel | yes | **no** | largely covered already by `tech_detect` |
| cdn_waf_intel | yes | **no** | largely covered already by `tech_detect` |
| **historical_recon** | **no** (pipeline §13) | **no** | none — placeholder package exists |

So: **7 of 18** `STAGE_PRIORITY` stages are covered; `historical_recon` is a
documented pipeline stage (§13) that is absent from `STAGE_PRIORITY` entirely and
has no adapter.

### 2.2 Candidates compared (at least three)

**Candidate A — `js_analysis`** (`docs/03_RECON_PIPELINE.md:195` §14; next in
`STAGE_PRIORITY`).
Its only declared tool is an *internal* parser, `intelligence/javascript.py`
(`docs/03_RECON_PIPELINE.md:199`). The `intelligence/` package is an empty stub
(only `intelligence/__init__.py` exists — confirmed by directory listing and by
`docs/OPENCODE.md:133`). It also produces `apis` and `websocket_endpoints`
(`docs/03_RECON_PIPELINE.md:202-203`) for which no ingestion plan type or projection
producer exists (`recon/ingest.py` plan dataclasses stop at `JavascriptFilePlan`;
`database/projection.py` has producers for urls/endpoints/parameters/javascript only).
It additionally needs a path to obtain JavaScript *content*, which the current crawl
does not retain (only `javascript_files.url`). **Verdict: blocked** by an unbuilt
architectural layer; not the smallest safe step.

**Candidate B — `api_discover`** (`docs/03_RECON_PIPELINE.md`; `STAGE_PRIORITY`
position 9). Depends on crawling **and** JavaScript analysis. `js_analysis`
uncovered ⇒ transitively blocked. `apis`/projection producers absent.
**Verdict: deferred.**

**Candidate C — `parameter_intel`** (`STAGE_PRIORITY` position 13).
Depends on `js_analysis` **and** `api_discover`; both uncovered. **Verdict:
deferred.**

**Candidate D — `cloud_intel` / `cdn_waf_intel`** (`STAGE_PRIORITY` positions
17–18). Phase 21A `recon/web/tech_detect.py` already fingerprints WAF/CDN/cloud
categories from explicit probe signals, so a dedicated classifier would largely
duplicate existing coverage for low marginal value. **Verdict: deferred (low value).**

**Candidate E — `historical_recon`** (`docs/03_RECON_PIPELINE.md:181` §13).
Dependency is **Target Intake only** ("no live host required", `:191`) — no uncovered
stage precedes it. Passive-only. Substrate largely present (§1). Reuses the exact
subprocess-adapter pattern of `recon/web/katana.py` and `recon/web/ffuf.py`, and the
existing observation → ingestion → `urls` persistence → projection path.
**Verdict: SELECTED.**

### 2.3 Why not simply take the next `STAGE_PRIORITY` entry

`js_analysis` is the next *listed* stage but it is blocked by an unbuilt
`intelligence/` layer and undefined `apis`/`websocket_endpoints` producers; taking it
now would force a new execution paradigm and net-new record producers in one step.
`historical_recon` is the highest-value stage whose **only** dependency is already
satisfied, whose interfaces already exist, and whose addition is a bounded,
single-tool, passive adapter. Per the phase discipline ("propose the smallest safe
prerequisite when the next stage is blocked"), historical recon is selected.

## 3. Scope — in and out

**In scope (required)**

- A GAU adapter serving the new `historical_recon` stage: `recon/historical/gau.py`.
- The shared historical observation type `HistoricalUrlObservation`.
- Ingestion, persistence, projection, and coverage wiring that carries the
  `historical` flag end to end (no expansion; §5).
- Adding `historical_recon` to `STAGE_PRIORITY` and the two task-type maps so the
  loop can propose and cover it.
- Flipping the `web.historical_urls` default from `True` to `false` and gating adapter
  registration on it, so the stage is opt-in and fails closed (§6).
- A bounded **streaming** output capture on the tool runner (per-stream
  `DEFAULT_MAX_OUTPUT_BYTES`, process-tree termination on overflow) that hard-caps
  **retained output bytes** and bounds disk and wall-clock (§4, §7, §16).
- Unit tests plus one PG-gated live test; no expensive/live external scans.

**Out of scope (explicit non-goals)**

- Any active request to a historical URL. Historical URLs are **never** re-fetched or
  probed by this stage or as an automatic consequence of discovering them.
- **`http_probe` expansion from historical observations is deferred** (see §16): in
  this phase a historical discovery produces `urls` rows and evidence only. Wiring
  liveness probing of passively-discovered hosts is a separate, explicitly-gated
  follow-up so that archive data alone cannot cause active interaction with a target.
- A Wayback (`waybackurls`) adapter. The review resolved this to **GAU-only** for
  Phase 24 (§16); Wayback is deferred to a follow-up and its shared
  `HistoricalUrlObservation` keeps that add cheap.
- JavaScript analysis, API discovery, parameter intelligence, or any `intelligence/`
  work.
- Recursively expanding historical URLs (e.g. fuzzing old paths).
- Schema migrations (none are needed — the column exists).
- Refactoring Phase 22/23 behavior, fixing known unrelated repo hazards, or changing
  the `tech_detect`/`serve.py` import inconsistency.

## 4. Relevant files and interfaces (all verified at baseline)

**New files**

- `recon/historical/gau.py` — `GauAdapter(ToolAdapter)`, `name = "gau"`,
  `executables = ("gau",)`, plus `parse_gau(text) -> list[HistoricalUrlObservation]`.
- `recon/historical/__init__.py` — keeps the existing docstring; additionally defines
  the shared `HistoricalUrlObservation` dataclass and `SOURCE_GAU` (and, for the
  deferred follow-up, `SOURCE_WAYBACK`) constants so submodules share one type without
  importing each other.
- `tests/fixtures/gau/{normal,empty,malformed,duplicates,partial}.*` — parser fixtures.
- `tests/test_gau.py` and `tests/test_phase24_live.py` (PG-gated). `wayback.py`/
  `test_wayback.py` are **deferred** (§3, §16).

**Existing files to modify (interface touchpoints)**

- `recon/ingest.py`
  - `UrlPlan` (`:159`) gains a **required** `historical: bool` field (no default). Its
    only constructor (`:422`) already uses keywords, so both the live and historical
    branches must set it explicitly — a passive observation can never inherit a
    "live" default by omission.
  - `plan_ingestion` (`:249`) gains one branch for `HistoricalUrlObservation`
    alongside the existing `UrlObservation` branch (`:416`); the `UrlObservation`
    branch passes `historical=False`, the historical branch passes `historical=True`.
- `core/config.py`
  - `WebConfig.historical_urls` default flips `True → false` (`:171`), and the
    `from_dict` fallback flips `True → false` (`:205`), so the gate is fail-closed and
    opt-in. No new key is introduced.
- `core/tool_runner.py`
  - `ToolRunner.run_command` (`:111-140`) is reworked from
    `subprocess.run(command, capture_output=True, ...)` to a **bounded streaming capture**
    (`subprocess.Popen` + chunked incremental reads) so **retained captured bytes** — not
    total process memory (§7) — are bounded by a byte budget rather than by the tool's
    total output. A per-stream cap
    (`DEFAULT_MAX_OUTPUT_BYTES`) is enforced; on overflow the child's process tree is
    terminated, the bounded partial is kept, and `CommandResult` gains
    `truncated: bool = False`. The persisted raw is the bounded content. Applies to all
    tools, not only GAU. Design and policy: §7 and §16.
- `database/repositories/all.py`
  - `UrlRepository.upsert` (`:503`) gains a **required** `historical: bool` parameter
    and writes/updates the column (its one caller, `:1261`, is updated).
  - `ingest_observations` url loop (`:1256-1263`) passes `url.historical` through; the
    existing `crawl_source = str(plan.source or "katana")` (`:1234`) already carries
    the tool name (`"gau"`) into `urls.source`. The conflict clause uses the corrected
    `CASE` and truth table in §10.
- `database/projection.py`
  - `UrlRecord` population (`:394`) reads `row.get("historical")`; the record type in
    `correlation/records.py:71` gains an additive `historical: bool = False` field.
- `recon/expansion.py` — **not modified in this phase.** The historical→`http_probe`
  branch is deferred (§3, §16). `CHILD_TYPE_HTTP_PROBE` (`:53`) remains available for
  the follow-up.
- `ai/recon_agent.py` — insert `"historical_recon"` into `STAGE_PRIORITY` (`:21`) after
  `"content_discover"` (§13 sits before §14 JavaScript Analysis).
- `ai/run_context.py` — extend `TASK_TYPE_COVERS_STAGE` (`:58`) with
  `"historical_recon"` and `"gau"` → `"historical_recon"` (`"wayback"` is added with
  the deferred follow-up).
- `ai/loop.py` — extend `TASK_TYPE_FOR_STAGE` (`:157`) with
  `"historical_recon": "historical_recon"`.
- `api/serve.py` — add `DEFAULT_HISTORICAL_TYPES = ("historical_recon", "gau")` and
  register `GauAdapter` in `_default_adapters` (`:319`) **only when
  `web.historical_urls` is true**, mirroring `DEFAULT_CONTENT_DISCOVER_TYPES` (`:99`).
  This requires threading the resolved `Config` into `_default_adapters` (currently
  called with only `resolver_fn`/`dns_timeout` at `:575`; `effective_config` is
  available at `:570`), which the implementation plan includes (§16). When the gate is
  false the type is unregistered, so the stage is reported as
  `uncovered_without_capability` rather than as a failing task (§6).

**Interfaces reused unchanged**

- `recon.base.ToolAdapter` / `ToolExecution` / `ToolUnavailable` / `ScopeViolation`
  (`recon/base.py:27-126`): the five-step adapter contract.
- `core.tool_runner.ToolRunner.run_command` / `save_raw`: controlled subprocess,
  overall timeout, raw preservation under `storage/raw/<tool>/`.
- `core.scope_guard.ScopeGuard.check_host` / `check_port` / `extract_host`.
- `recon.normalize.normalize_hostname`: the single hostname normalizer.
- Observation key pattern (`recon/web/katana.py:84-153`): frozen dataclass with a
  `.key` tuple used for deterministic dedup.

## 5. Proposed architecture and end-to-end data flow

The stage is a passive subprocess adapter wired into the existing served chain;
nothing about the orchestrator, Tool Runner, scope guard, ingestion, or projection
changes shape.

```
ReconAgent (ai/recon_agent.py)
  STAGE_PRIORITY now includes "historical_recon"; gap exists
        │  proposal target = ctx.scope.root (the in-scope domain)
        ▼
ai/loop.py  TASK_TYPE_FOR_STAGE["historical_recon"] = "historical_recon"
        │  creates Task(type="historical_recon", target=<root domain>)
        ▼
api/serve.py registry: "historical_recon"/"gau" -> GauAdapter
        │
        ▼
GauAdapter.execute (recon/historical/gau.py)
  is_available()  -> "gau" on PATH else ToolUnavailable (non-fatal)
  validate()      -> ScopeGuard.check_host(root domain)
  build_command() -> ["gau", "--json", <domain>]        (bounded; no shell)
  runner.run_command(..., timeout=overall)               (raw -> storage/raw/gau/)
  parse()         -> [HistoricalUrlObservation(host,port,path,url,source="gau"), ...]
        │
        ▼
recon/ingest.py plan_ingestion
  HistoricalUrlObservation branch -> UrlPlan(hostname, port, path, historical=True)
  every host scope-checked (check_host); out-of-scope -> OutOfScopeObservation only
        │
        ▼
database/repositories/all.py ingest_observations
  _crawl_web_app_id(host, port) roots the URL to an existing web_app
    rooted   -> urls.upsert(app_id, path, "gau", historical=True)  + evidence
    unrooted -> evidence(ENTITY_URL) only (counted, never fabricated)
        │
        ▼
database/projection.py -> UrlRecord(..., historical=<bool>) in the read graph
        │
        ▼
recon/expansion.py
  NO historical branch in this phase: a historical discovery proposes no child
  task. Active probing of passively-discovered hosts is deferred (§3, §16).
        │
        ▼
ai/run_context.py covered_stages sees "historical_recon" once a task completes
```

**Design principle.** historical recon's product is *URLs marked historical*. The
stage performs no liveness request, and — unlike earlier drafts of this proposal —
**nothing downstream of it issues one either**: a historical URL stays a `urls` row
(path marked `historical=true`, source `gau`) or evidence-only, and is never
re-fetched or probed as a consequence of discovery. Liveness verification of
historical hosts is the documented follow-up (`docs/03_RECON_PIPELINE.md:189`) but is
deferred to a separate, opt-in phase (§16).

## 6. Configuration and operator approval

No new configuration key is introduced. The phase reuses the existing,
already-serialized gate `web.historical_urls` (`core/config.py:171,447,557`) and
**flips its default from `True` to `false`** (`:171` and the `from_dict` fallback
`:205`), making historical recon an explicit opt-in that fails closed.

- **Default `false`.** This deliberately diverges from the sibling web gates
  (`http_probe`/`crawling`/`content_discovery` all default `True`): historical recon
  reaches into third-party archives and (in the deferred follow-up) could lead to
  active probing, so the review required a gate that defaults to disabled.
- **Enforcement point (resolved): registration gating.** `_default_adapters`
  (`api/serve.py:319`) registers `GauAdapter` only when the gate is true. When false,
  the `historical_recon`/`gau` types are absent, so `ai/run_context.py` reports the
  stage under `uncovered_without_capability` (`:203-214`) — the honest "capability is
  off" signal — and an operator task of that type is rejected as `UnknownTaskType`
  rather than failing mid-run. The adapter **additionally** refuses in
  `build_command` when the gate is false (defense in depth), matching the ffuf
  precedent, but that path should never be reached under registration gating.
- The gate is read from either the typed `Config` *and* the persisted snapshot dict
  using the same dual-shape helper pattern already used by `recon/web/ffuf.py`
  (`_limits_of`/`_configured_wordlist`, `:199-236`), so a run honours the snapshot it
  started with.
- There is **no** operator-supplied wordlist and **no** approval artifact for this
  stage (unlike content discovery): GAU needs only the in-scope domain. The explicit
  config opt-in is the only gate.
- **No propose→refuse loop.** With registration gating, the disabled stage is simply
  "not capable", so it is never auto-proposed. Even if it were proposed and refused,
  the loop is bounded (see §16): the failed task's fingerprint already exists, so
  `_run_analysis_pass` observes no new fingerprint and `_next_pass` completes the run.

## 7. Scope enforcement and limits

- **Scope.** The task target is the scope root. `validate()` calls
  `ScopeGuard.check_host(extract_host(target))` and raises `ScopeViolation` if denied
  (pattern: `recon/web/katana.py:307-316`). GAU takes no port, so no port check is
  needed. Every destination parsed from GAU output is re-checked by
  `recon/ingest.py` via `check_host` before it can become a graph row; a denied host
  is preserved as an `OutOfScopeObservation` only. There is no expansion step in this
  phase, so no downstream task is created from a historical observation (§5).
- **Passivity.** No request is ever issued to a discovered URL, and no downstream task
  probes a passively-discovered host in this phase. GAU queries third-party historical
  providers for the in-scope domain only.
- **Bounds (memory, disk, time).** One subprocess per task, bounded by the `ToolRunner`
  overall timeout (default proposed: 60 s, mirroring
  `recon/web/katana.py:DEFAULT_OVERALL_TIMEOUT`) and by a **bounded streaming capture**
  (§4, §16). Three distinct things are bounded, and **only the first is an exact cap**:

  1. **Retained captured bytes (strict cap).** The runner reads stdout and stderr
     incrementally with a fixed-size read chunk and keeps at most
     `DEFAULT_MAX_OUTPUT_BYTES` decoded bytes **per stream**, tracked independently.
     Retained stdout+stderr is therefore hard-bounded at `2 × DEFAULT_MAX_OUTPUT_BYTES`.
     This — *not* process RSS — is the guarantee.
  2. **Bounded reader overhead (separate, constant).** The reader's own buffers (the read
     chunk, per-line decode buffers, and the accumulating `str`/`bytes` up to the cap)
     are bounded by a small fixed constant plus the retained bytes; they do not grow with
     the tool's total output, provided the implementation uses chunked reads (e.g.
     `stream.read(chunk)`) rather than `communicate()` or reading the whole pipe. This
     overhead is documented separately and is **not** folded into the `2 ×` figure.
  3. **Downstream copies (bounded in proportion to retained output).** Parsing,
     line-splitting, observation construction, and persistence operate on the bounded
     capture, so their memory is bounded *in proportion to* the retained bytes (a single
     line/record may be up to the cap), while row count is separately bounded by
     `max_artifacts` (below). These are bounded, but are **not** equal to `2 ×`.

  **Honest limitation.** Total process memory (RSS) is **not** claimed to equal, or be
  bounded by, `2 × DEFAULT_MAX_OUTPUT_BYTES`: RSS additionally includes the interpreter,
  allocator fragmentation, the `Popen`/poll machinery and reader-thread stacks, and the
  proportionally-bounded downstream copies above. A hard total-RSS bound is **not**
  guaranteed by this standard-library design; what is hard-capped is the *retained
  captured output*. The bounded capture is what is written under `storage/raw/gau/`,
  bounding disk. This replaces the earlier `subprocess.run(capture_output=True)` design,
  which buffered the tool's entire output before truncation and so bounded nothing (§16).
  No aggressive provider-concurrency flags are added by default.
- **Rate limiting (honest scope).** The orchestrator `RateLimiter` admits one permit
  **per task invocation** (`core/orchestrator.py:620-622`), not per HTTP request GAU
  makes internally. It bounds *how often ARGUS launches GAU*, **not** GAU's own
  provider request rate; GAU's `--threads`/rate flags are left at their defaults and
  their behaviour is the tool's, not ARGUS's. This is a deliberate limitation recorded
  in §16.
- **Cardinality.** `plan_ingestion` caps artifacts at `max_artifacts` (default 10000,
  `recon/ingest.py:255`) and reports `truncated`; this is a *post-parse* cap on rows,
  complementary to (not a substitute for) the subprocess output cap above.
- **Determinism.** Parsed observations are deduplicated by canonical key and returned
  in a fixed sort, independent of provider ordering (pattern:
  `recon/web/katana.py:245`).

## 8. Adapter command contract

Per `docs/06_TOOL_CONTRACTS.md:174-182`:

- **GAU** — command `gau <domain> --json`; output JSON lines; parser → `urls` marked
  `historical: true`; raw under `storage/raw/gau/`; passive; provider failure
  non-fatal.
- Proposed argument array (never a shell string), matching the contract while keeping
  the domain unambiguous: `["gau", "--json", <domain>]`.
- **Wayback** (deferred, §16) — would be `waybackurls <domain>`; plain text, one URL
  per line; parser → `urls` marked `historical: true`; raw under
  `storage/raw/wayback/`. Not implemented in this phase.

**Requires implementation-time verification (explicitly flagged, not asserted):**
the exact GAU flag spelling/position and the precise JSON field names vary by GAU
version. The implementation must verify the installed binary's behavior (as
`recon/web/ffuf.py:363` probes FFUF's own `-h` for a supported timeout flag) and
must not fabricate flags for a version that lacks them. Fixtures under
`tests/fixtures/gau/` define the parser's accepted shapes; the live shape is
confirmed only against an authorized, local/controlled target per §13.

## 9. Parsing, normalization, dedup, and evidence

- **Observation type.** `HistoricalUrlObservation(host: str, port: int, path: str,
  url: str, source: str, metadata: Mapping = {})` with a `.key` tuple for dedup. This
  is a distinct type (not a reused `UrlObservation`) so "historical" is carried by
  the type itself and can never be silently dropped.
- **Normalization.** Each GAU URL is parsed with `urllib.parse`; only `http(s)` URLs
  with a host are admitted. Port defaults by scheme (443 https / 80 http) exactly as
  `recon/web/katana.py:215-218`. The stored `path` is **query-stripped**, consistent
  with the `urls.path` convention (`recon/web/katana.py:219`). `host` is lowercased
  and passed through `normalize_hostname` in ingestion.
- **Deliberate scope decision:** query parameters of historical URLs are **not**
  mined in this phase. `docs/03_RECON_PIPELINE.md:187` limits normalized data to
  `urls`; parameter mining is the domain of `parameter_intel`. Recorded as a
  limitation in §16.
- **Non-fatal parsing.** NDJSON/JSON-or-plain-text is accepted; malformed lines are
  logged and skipped, valid records kept; empty/partial input yields what was seen
  (contract: `recon/base.py:93-98`, pattern: `recon/web/katana.py:182-245`).
- **Dedup.** Per-execution dedup on `(host, port, path, source)`; deterministic sort
  by key. Cross-run/duplicate persistence is resolved by the database upsert (§10).
- **Evidence.** Raw tool output is preserved under `storage/raw/gau/` via
  `ToolRunner.save_raw`. Rooted URLs get an `ENTITY_URL` evidence row linked to the
  `urls` row; unrooted (no persisted web app) URLs are preserved as evidence with a
  NULL `entity_id` and counted — the exact `recon/ingest.py:69-76` discipline reused.

## 10. Persistence, graph, and migration decision

**Migration: none required.** `urls.historical` already exists
(`database/migrations/0001_initial_schema.sql:200`) and `urls.source` already permits
`gau`/`wayback` (`docs/05_DATA_MODEL.md:211`). No new table, column, or index is
introduced.

**Repository upsert.** `UrlRepository.upsert` (`database/repositories/all.py:503`)
gains a **required** `historical: bool` parameter and:

```sql
INSERT INTO urls (web_app_id, path, source, historical)
VALUES (%s, %s, %s, %s)
ON CONFLICT (web_app_id, path) DO UPDATE
  SET historical = urls.historical AND EXCLUDED.historical,
      source = CASE
                 WHEN NOT EXCLUDED.historical THEN EXCLUDED.source
                 WHEN urls.historical THEN EXCLUDED.source
                 ELSE urls.source
               END
RETURNING *
```

The `historical` clause implements the documented lifecycle
(`docs/05_DATA_MODEL.md:215`): a URL stays `historical=true` until a **non-historical**
source records the same `(web_app_id, path)`, at which point it flips to `false`. If
either observation is live (`false`), the result is `false`; only
historical-AND-historical stays `true`.

The `source` clause is the corrected provenance rule (the earlier
`WHEN urls.historical AND EXCLUDED.historical THEN EXCLUDED.source ELSE urls.source END`
was wrong for the historical→live direction: it left `source='gau'` on a row that had
just flipped to live). The corrected rule chooses the source from the **resulting**
state: a row that ends up historical takes the incoming historical tool name; a row
that ends up live takes the **live** side's source (the incoming live tool when the
incoming observation is live, otherwise the existing live source). Both directions of
the contradiction are therefore avoided.

**Source-promotion truth table** (`EXCLUDED` = incoming observation; new-row `INSERT`
always takes the incoming value via `VALUES`):

| existing `urls.historical` | incoming `EXCLUDED.historical` | resulting `historical` | resulting `source` |
|---|---|---|---|
| live (`false`) | live (`false`) | `false` | incoming live tool (`EXCLUDED.source`) — **last-writer-wins retained** |
| live (`false`) | historical (`true`) | `false` | existing live source (`urls.source`) — **preserved** |
| historical (`true`) | live (`false`) | `false` | incoming live tool (`EXCLUDED.source`) — **promoted to the live tool** |
| historical (`true`) | historical (`true`) | `true` | incoming historical tool (`EXCLUDED.source`) |

Three consequences, stated explicitly:

1. **Historical row promoted by a live observation** (`historical=true` → live): the row
   flips to `historical=false` **and** `source` becomes the incoming live tool — the
   historical tool name is not carried forward onto a live row.
2. **Live row against a historical observation:** the row stays `historical=false` and
   the existing live source is preserved; a historical observation can never overwrite a
   live source.
3. **Historical + historical:** the row stays `historical=true` and the incoming
   historical tool name is recorded.
4. **Live-to-live:** the corrected expression routes `NOT EXCLUDED.historical` to
   `EXCLUDED.source`, so an incoming live observation **replaces** an existing live
   source. This deliberately **retains the existing last-writer-wins behavior** for live
   observations (the prior `source = EXCLUDED.source`, `database/repositories/all.py:506`).

`historical` is **required** on `upsert` and on `UrlPlan` (§4) so no caller can cause
the AND rule to be bypassed by omitting the flag — the intended "fail-safe" default was
to make the decision mandatory rather than defaulted. Column references are valid
against the schema: `source text NOT NULL` (`0001_initial_schema.sql:199`), `historical
boolean NOT NULL DEFAULT false` (`:200`), and `UNIQUE (web_app_id, path)` via `urls_uq`
(`:204`). This is a typed statement of intent only; it was **not** executed against a
database in this documentation task (§13 lists the PG-gated test that will exercise it).

**Rooting limitation (honest).** `urls.web_app_id` is NOT NULL
(`0001_initial_schema.sql:197`), and historical recon runs from a domain with no
guaranteed live host, so a historical URL whose host:port has no persisted
`web_app` row is preserved as **evidence only** (`recon/ingest.py:69-76` convention).
This mirrors Phase 22/23 exactly. Note also that an in-scope historical **hostname**
still enters the graph as an `assets` row via `classify_host`
(`recon/ingest.py:315-323`) — the same passive behaviour as `subfinder`, not a
liveness claim about that host. The deferred `http_probe` follow-up (§16) is the
intended remedy that would later root a web app and let the URL be persisted; it is
recorded as a known limitation rather than a silently faked live row.

**Graph.** `UrlRecord` (`correlation/records.py:71`) gains an additive
`historical: bool = False` field, populated in `database/projection.py:394` from
`row.get("historical")`, so the read graph and reports can distinguish historical
from live URLs. This is an additive dataclass field; any positional constructor
call sites in Phase 22/23 tests must be checked at implementation time (keyword use
is assumed but requires verification).

## 11. Scheduling, stage coverage, and adapter registration

- **`STAGE_PRIORITY`** (`ai/recon_agent.py:21`): insert `"historical_recon"` after
  `"content_discover"` and before `"js_analysis"`, matching the pipeline's §13-before-
  §14 ordering (`docs/03_RECON_PIPELINE.md`). Update the stale "17 documented recon
  stages" comment in `ai/run_context.py:23` to the new count.
- **`ai/run_context.py:58`** `TASK_TYPE_COVERS_STAGE`: add
  `"historical_recon" → "historical_recon"` and `"gau" → "historical_recon"`
  (`"wayback"` joins with the deferred follow-up).
- **`ai/loop.py:157`** `TASK_TYPE_FOR_STAGE`: add
  `"historical_recon": "historical_recon"` (the canonical task type). `_task_from`
  (`ai/loop.py:438-466`) then ties the agent's proposal back to the gap and creates
  the task with `target = scope.root`.
- **`api/serve.py`**: add `DEFAULT_HISTORICAL_TYPES = ("historical_recon", "gau")`
  and register `GauAdapter` in `_default_adapters` (`:319`) **only when
  `web.historical_urls` is true**, exactly as `DEFAULT_CONTENT_DISCOVER_TYPES` is
  registered (`:99,369`). This requires threading the resolved `Config` into
  `_default_adapters` (currently `resolver_fn, dns_timeout` at `:319`, called at `:575`
  where `effective_config` is available at `:570`) — an explicit implementation-plan
  step, verified in §16. The canonical `historical_recon` task type maps to the GAU
  adapter. When the gate is false the type is absent, so the stage resolves to
  `uncovered_without_capability` rather than to a failing task (§6).
- **Coverage visibility.** Once registered and uncovered, `historical_recon` appears
  in `coverage_gaps` (`ai/run_context.py:191`); once its adapter is *not* registered
  (e.g. disabled), it appears in `uncovered_without_capability` — the honest
  "we could not, there is no capability" signal.

## 12. Failure handling and graceful degradation

All of the following are non-fatal, matching Phase 22/23 and
`06_TOOL_CONTRACTS.md` §Missing-Tool Handling:

- **Missing binary** → `ToolUnavailable` from `is_available()`; the orchestrator logs
  and continues (`recon/base.py:31-37,110-114`).
- **Non-zero exit / provider failure** → partial output is still parsed and returned;
  `ToolExecution.exit_code` and `error` record the condition.
- **Timeout** → `ToolRunner` overall timeout; recorded non-fatally with whatever
  partial output was captured (pattern: `recon/web/katana.py:367-381`).
- **Malformed/partial output** → skipped and logged; valid records kept.
- **Out-of-scope result** → never a graph row; preserved as an observation.
- **Unrootable URL** → evidence only, counted, never fabricated.
- **Config disabled** (`web.historical_urls=false`) → the type is **not registered**
  (§6), so the stage is reported as `uncovered_without_capability` and no task runs;
  the adapter's `build_command` refusal is defense in depth.
- **Output overflow** → capture is bounded per stream at `DEFAULT_MAX_OUTPUT_BYTES`
  (§4, §7); on overflow the process tree is terminated, the bounded partial is kept, and
  `CommandResult.truncated=True` is set. Parsing proceeds over the partial capture
  non-fatally and partial results are kept.
- **No historical findings** → empty plan; the task completes and covers the stage.

## 13. Test plan

Unit/offline (no network, no live tools unless injected):

1. **Parser fixtures** — `tests/fixtures/gau/{normal,empty,malformed,duplicates,partial}`:
   verify canonical URL/endpoint normalization, query-stripping, scheme/port defaults,
   `.js` handling is *not* applied here (urls only), dedup, and deterministic order;
   empty/malformed/partial never raise.
2. **Adapter contract** — `is_available` false when `gau` absent (monkeypatched
   `is_executable_on_path`); `ToolUnavailable` raised; `validate` raises
   `ScopeViolation` for an out-of-scope target and passes an in-scope one;
   `build_command` returns the documented argument array with no shell string and
   refuses (defense in depth) when `web.historical_urls` is false.
3. **Ingestion** — a `HistoricalUrlObservation` yields exactly one
   `UrlPlan(historical=True)`; a `UrlObservation` yields `UrlPlan(historical=False)`;
   an out-of-scope host yields an `OutOfScopeObservation` and no `UrlPlan`; duplicate
   observations collapse; artifacts beyond the cap count as `truncated`.
4. **No expansion** — a completed `historical_recon` task proposes **no** child task;
   `plan_discovery_expansion` over historical observations returns no `http_probe`
   child (guards against accidental active probing of passively-found hosts).
5. **Coverage/loop wiring** — `TASK_TYPE_COVERS_STAGE` maps `historical_recon`/`gau`
   to `historical_recon`; `coverage_gaps` includes `historical_recon` when registered
   and `uncovered_without_capability` includes it when not;
   `TASK_TYPE_FOR_STAGE["historical_recon"]` resolves.
6. **Registry gating** — with `web.historical_urls=true`, `DEFAULT_HISTORICAL_TYPES`
   are present in `_default_adapters` output and dispatch to the GAU adapter; with
   `false`, the type is absent and dispatch raises `UnknownTaskType`.
7. **Persistence/upsert (PG-gated)** — a historical insert sets `historical=true` with
   `source='gau'`; a conflicting **live** upsert flips it to `false` **and** sets
   `source` to the incoming live tool; a conflicting **historical** upsert against a
   live row keeps `historical=false` and the live `source`; a conflicting historical
   upsert against a historical row keeps `historical=true` — the full §10 truth table.
8. **Projection** — a `urls` row with `historical=true` projects a `UrlRecord` with
   `historical=True`.
9. **Tool runner bounded capture** — driven by a deterministic in-process child (e.g.
   `python -c` emitting a known byte count; never a live target). Required cases:
   1. **Simultaneous stdout/stderr flood** — both streams exceed
      `DEFAULT_MAX_OUTPUT_BYTES`: retained bytes per stream never exceed the cap
      (total retained `≤ 2 × DEFAULT_MAX_OUTPUT_BYTES`), both pipes are drained
      concurrently without deadlock, `CommandResult.truncated=True`, and the bounded
      partial from both streams is preserved.
   2. **Output exactly at the limit** — a child emitting exactly
      `DEFAULT_MAX_OUTPUT_BYTES` per stream exits normally: the real exit code is
      preserved and `truncated=False` (truncation is `True` iff bytes were omitted).
   3. **Output exceeding the limit** — over the limit: retained bytes are capped,
      `truncated=True`, and the child's process tree is terminated.
   4. **Timeout during output** — the child is still producing when the overall timeout
      fires: `timed_out=True`, the bounded partial is retained, and the task degrades
      non-fatally.
   5. **Child-process cleanup** — after both overflow and timeout, the child **and its
      descendants** are gone (no orphaned process), asserted per platform (Windows Job
      Object / `taskkill /F /T`; POSIX process group).

   Memory is asserted on **retained captured bytes** (a hard cap), not on total RSS
   (§7, §16).
10. **Regression** — the existing Phase 22/23 suites (`tests/test_katana.py`/crawl,
    `tests/test_ffuf.py`, `tests/test_expansion.py`, `tests/test_config.py`,
    `tests/test_phase16.py`) and the smoke import test continue to pass.
11. **Live test (PG-gated)** — `tests/test_phase24_live.py`, mirroring
    `tests/test_phase23_live.py`, exercises ingest→persist→project of a historical
    observation on the local sandbox (`127.0.0.1:5434`). Marked/skipped without PG.

Explicitly **not** in the test plan: any real GAU run against a third-party service.
Where a real binary is needed, only an authorized, local/controlled target is used.
Proposed commands are recorded; no test is claimed to pass unless executed.

## 14. Objectively verifiable acceptance criteria

1. With `web.historical_urls=true`, `gau` on PATH, and an in-scope domain, a
   `historical_recon` task completes and the run's covered stages include
   `historical_recon`.
2. A fixture-run through `plan_ingestion` produces `UrlPlan` objects with
   `historical=True` for in-scope hosts only; `UrlObservation` inputs produce
   `historical=False`; out-of-scope hosts produce zero `UrlPlan`s.
3. After persistence, `SELECT historical, source FROM urls WHERE ...` is
   `(true, 'gau')` for a historical URL.
4. Per the §10 truth table: a subsequent **live** upsert of the same
   `(web_app_id, path)` sets `historical=false` **and** `source` to the **incoming
   live** tool (not `gau`); a subsequent **historical** upsert against an existing
   **live** row leaves `historical=false` and the live `source` unchanged; a
   live→live upsert keeps last-writer-wins on `source`.
5. Projection emits a `UrlRecord` whose `historical` equals the row value.
6. A historical discovery creates **no** child task: a completed `historical_recon`
   task produces zero `http_probe` children (no automatic active probing).
7. With `web.historical_urls=false`, the `historical_recon`/`gau` types are not
   registered; the stage appears in `uncovered_without_capability` and no GAU
   execution occurs.
8. With `web.historical_urls=true` but `gau` absent, the task degrades with
   `ToolUnavailable` and the run continues; no crash, no fabricated rows.
9. Malformed/empty/partial GAU output completes without raising and persists only the
   valid records.
10. The tool runner hard-caps **retained captured bytes** at
    `DEFAULT_MAX_OUTPUT_BYTES` per stream, so retained stdout+stderr is
    `≤ 2 × DEFAULT_MAX_OUTPUT_BYTES`; this is a bound on retained output, **not** a claim
    that total process memory (RSS) equals `2 ×` (see §7 for the separately documented
    reader overhead and proportionally-bounded downstream copies).
    `CommandResult.truncated` is `True` iff bytes were omitted; on overflow the child's
    process tree is terminated and reaped; and the persisted raw is the bounded content.
11. No new migration file is added; `git diff` shows changes only to the files listed
    in §4 (and **not** `recon/expansion.py`); all new tests pass and Phase 22/23 tests
    are unregressed.

## 15. Rollback and containment

- **No migration to roll back.** The schema is unchanged.
- **Feature disable:** set `web.historical_urls=false` (the default) in the run
  configuration; GAU is not registered, no GAU execution occurs, and no downstream
  task is created (§6).
- **Code rollback:** the change set is confined to adding a package's adapter module,
  one branch in `recon/ingest.py`, a required field/parameter, the config default flip,
  the tool-runner cap, the two AI maps, `STAGE_PRIORITY`, and the adapter registry.
  `recon/expansion.py` is **not** touched. Reverting those additions removes the stage
  cleanly; the placeholder `recon/historical/__init__.py` reverts to its docstring.
- **Containment properties:** passive-only; every host scope-checked at ingestion; no
  live request to historical URLs and no downstream probing of them; bounded by the
  Tool Runner timeout, the bounded streaming capture (§4, §7), and the existing
  artifact cap; raw output preserved for audit under `storage/raw/gau/`.

## 16. Risks, assumptions, and resolved decisions

**Assumptions (to verify at implementation time)**

- `gau --json` emits JSON lines parseable by the proposed parser; the exact flag and
  field names require verification against the installed binary (§8). If GAU emits
  plain URLs in some modes, the parser already falls back to line-splitting.
- Registering `historical_recon` in `STAGE_PRIORITY` does not distort other stages'
  planning beyond adding one entry before `js_analysis`.
- `UrlRecord` is constructed by keyword (its only site, `database/projection.py:394`,
  is) so the additive `historical` field is non-breaking; confirmed by the regression
  suite at implementation time.

**Risks**

- **Config-gate loop (corrected).** An earlier draft claimed the AI loop could
  re-propose a disabled/refused stage indefinitely. It cannot: `_TASK_SETTLED`
  (`core/orchestrator.py:75`) excludes `failed`, so a refused task is re-queued **once**
  by the planner, but `_run_analysis_pass` (`:319-324`) computes
  `produced_new = after - before` fingerprints and `_next_pass` (`:356-374`) completes
  the run when no **new** fingerprint appears. The loop therefore terminates after one
  extra pass. Registration gating (§6) removes the path entirely.
- **Tool output bound by streaming capture (addressed, with a stated scope).** The
  `ToolRunner` previously used `subprocess.run(command, capture_output=True, ...)`
  (`core/tool_runner.py:111-140`), which buffers the tool's **entire** output before the
  function returns — so post-capture truncation would not bound memory. The revised
  design uses `subprocess.Popen` with chunked incremental reads; each stream's **retained
  bytes** are hard-capped at `DEFAULT_MAX_OUTPUT_BYTES`, so retained stdout+stderr is
  `≤ 2 × DEFAULT_MAX_OUTPUT_BYTES`. On overflow it **terminates the child's process tree**
  and keeps the bounded partial with `CommandResult.truncated=True`. **Scope of the
  guarantee (honest limitation):** this bounds *retained captured output*; it does **not**
  provide a hard bound on total process RSS equal to `2 ×`. RSS additionally includes the
  interpreter, allocator/thread overhead, and downstream parser/ingest copies that are
  bounded only in proportion to the retained bytes (§7). Windows tree termination is
  handled with a Job Object via `ctypes` (stdlib) and `taskkill /F /T` as a fallback; the
  reader must drain both pipes concurrently to avoid stdio deadlock.
- **Rate limiting is per-invocation (limitation).** `RateLimiter` admits one permit per
  task (`core/orchestrator.py:620-622`); it does not bound GAU's internal provider
  request rate. Accepted for this phase; aggressive provider flags stay off by default
  (§7).
- **In-scope hosts become `assets` rows (limitation).** `classify_host`
  (`recon/ingest.py:315-323`) registers any in-scope discovered host as an asset — the
  same passive behaviour as `subfinder`. Accepted; it is inventory, not a liveness
  claim (§10).
- **Rooting limitation.** Many historical URLs may be evidence-only until their host is
  probed and rooted; the deferred `http_probe` follow-up is the intended remedy.
  Accepted evidence-only for this phase.
- **Provider variability.** GAU aggregates multiple third-party sources whose
  availability and rate behaviour vary; failures are non-fatal by design.
- **Overlap with `content_discover`.** Some historical paths will already be found by
  FFUF; the `historical` flag and the `AND` promotion rule keep the two reconciled.

**Decisions resolved by the review (adopted)**

1. **Config gate:** default **disabled** (`web.historical_urls=false`), explicit
   opt-in, fail-closed; enforced by **registration gating** with adapter refusal as
   defense in depth (§6). Rejected: leaving the default `True`.
2. **Active probing of historical hosts:** **deferred**; historical discovery produces
   no child task in this phase (§3, §5). Rejected: automatic `http_probe` expansion.
3. **`historical` flag default:** **required** (no default) on `UrlPlan` and
   `UrlRepository.upsert`, so omission cannot silently promote (§4, §10). Rejected:
   `historical=False`.
4. **Upsert `source` semantics (corrected):** use the §10 `CASE` and four-row truth
   table — a historical row promoted by a live observation takes the **incoming live**
   source; a historical observation never overwrites a live source; live-to-live retains
   **last-writer-wins** for live observations. Rejected: the earlier naïve `CASE` (wrong
   for historical→live) and the naïve `source = EXCLUDED.source` (produced the
   contradictory `(source='gau', historical=false)`).
5. **Output capture:** bounded **streaming** capture with a per-stream budget
   `DEFAULT_MAX_OUTPUT_BYTES`; the guarantee is a hard cap on **retained captured bytes**
   (`≤ 2 × DEFAULT_MAX_OUTPUT_BYTES`), **not** on total RSS (§7). **On overflow, terminate
   the process tree** (chosen over drain-and-discard because it hard-caps retained output,
   bounds disk and wall-clock, and prevents uncontrolled output; the cost is that the
   tool's true exit code is not preserved on overflow). Requires a `Popen` reader that
   drains stdout/stderr concurrently plus a platform tree-kill (§4, §7).
6. **Wayback:** **GAU-only** for Phase 24; Wayback deferred (§3).
7. **Historical hostnames as `assets`:** accepted (documented, §10).
8. **Stale stage count:** update the "17 documented recon stages" comment
   (`ai/run_context.py:23`) to the true post-Phase-24 count.

**Remaining implementation-time verifications**

- Confirm the installed GAU binary's exact flag spelling, JSON field names, and the
  argument order `["gau", "--json", <domain>]` against the installed binary — the
  contract doc shows `gau <domain> --json` (`docs/06_TOOL_CONTRACTS.md:177`), so the
  order is verified at implementation time (§8).
- Confirm `UrlRecord` has no positional constructor sites before the additive field is
  relied upon (regression suite).
- Confirm the registration-gating point in `api/serve.py` receives the typed `Config`
  (or snapshot): `_default_adapters` (`:319`) must be given the resolved config
  (`effective_config`, `:570`) rather than only `resolver_fn`/`dns_timeout` (`:575`).
- Confirm the `Popen`-based bounded reader drains stdout and stderr **concurrently**
  without deadlock and that **retained bytes** per stream never exceed
  `DEFAULT_MAX_OUTPUT_BYTES`; cover simultaneous floods, exactly-at-limit, over-limit,
  timeout-during-output, and child-process-cleanup cases (§13.9). Confirm Windows
  process-tree termination (Job Object via `ctypes`, or `taskkill /F /T`) reaps GAU's
  descendants (and POSIX process-group kill), and measure the constant reader overhead
  so §7's separate overhead bound can be stated with a concrete figure.
- Confirm the §10 `CASE`/truth table via the PG-gated upsert test (historical→live,
  live→historical, historical→historical, live→live) — this is the execution that
  validates the SQL; it was not run in this documentation task.
- Confirm dropping historical query parameters (query-stripped paths only) satisfies
  §13's "urls only" contract — the decision of record is to keep them dropped.

---

*Authored as a proposal only. No implementation, test, migration, or config change
accompanies this document.*
