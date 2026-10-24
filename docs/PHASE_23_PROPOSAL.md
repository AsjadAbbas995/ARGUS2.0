# ARGUS — Phase 23 Proposal Only: FFUF Content Discovery

**Status:** Proposed (not implemented).
**Current HEAD:** `eec6175` — Phase 22 (web crawling / Katana) committed.
**Target stage:** `content_discover` (§12, `docs/03_RECON_PIPELINE.md`).

This is a **proposal-only** document. No implementation, staging, or commit is performed. Only `docs/PHASE_23_PROPOSAL.md` is created/modified in this pass. The working tree remains dirty as-is.

## 1. Rationale

- **Priority order:** `content_discover` is the next uncovered stage after `web_crawl` in `ai/recon_agent.py:STAGE_PRIORITY` (positions 1–6: subdomain_enum, dns_resolve, port_scan, http_probe, tech_detect, web_crawl; 7 is `content_discover`).
- **Coverage:** `content_discover` currently has **no** task types registered in `api.serve._default_adapters`, **no** entries in `ai/run_context.TASK_TYPE_COVERS_STAGE`, and **no** mapping in `ai/loop.TASK_TYPE_FOR_STAGE`. The served registry (`ServedExecution.known_task_types()`) cannot dispatch a `content_discover` (or `ffuf`) task, so the stage will appear in `uncovered_without_capability()` and cannot be proposed as a runnable task by the existing loop.
- **Existing substrate:** Phase 22 established the full URL/endpoint pipeline (observations `UrlObservation`/`EndpointObservation`, plans `UrlPlan`/`EndpointPlan`, repos `UrlRepository`/`EndpointRepository`, projection `UrlRecord`/`EndpointRecord`, `serves_url` graph edge, `crawl_source = "katana"` semantics). The DB schema already has `urls(source text)` and `endpoints(method,pattern,url_id)` with constraints (`docs/05_DATA_MODEL.md:211` lists `katana / ffuf / feroxbuster / gau / wayback`).
- **Contract exists:** `docs/06_TOOL_CONTRACTS.md:153-163` documents FFUF (base URL + wordlist, `-u <url>/FUZZ -w <wordlist> -json -o <outfile>`, parser → `urls`,`endpoints` with status codes, raw under `storage/raw/ffuf/`, Rate-Limiter controlled, discovery ≠ vulnerability).

## 2. Discrepancies vs coverage summary

The previous read-only summary noted "absent vs unavailable". Actual code:
- Covered adapters are implemented (`recon/subdomains/subfinder.py`, `recon/dns/resolver.py`, `recon/ports/nmap.py`, `recon/web/httpx_probe.py`, `recon/web/katana.py`, `recon/web/tech_detect.py`).
- External binaries absent on this host (all subfinder/nmap/httpx/katana absent) — those adapters report unavailable gracefully via `ToolUnavailable` (raised by base `ToolAdapter.execute` when `is_available()` false).
- **Gap:** no `ffuf` adapter exists anywhere in `recon/`; `recon/web/__init__.py` is a placeholder. No registration for `content_discover`/`ffuf`.

Also noted: `ai/loop.py` **lacks** `web_crawl` mapping (it only maps subdomain_enum/dns_resolve/port_scan/http_probe/tech_detect). This is a small scheduling/translation gap (see §4) but not blocking a proposal; it does not justify broad refactoring in Phase 23.

## 3. Scope (single-tool)

- **Only FFUF.** Explicitly defer Feroxbuster.
- **Entry condition:** a confirmed, in-scope web application (from existing recon, e.g. completed `http_probe`/Phase 22 `web_app`). Expansion will propose `content_discover` only for qualifying web apps.
- **Wordlist source:** must be **explicitly configured and approved** (no silent download/generation). Configuration must expose a wordlist path/identity (not specified here — requires human approval, see §6). FFUF invocation must reference that approved wordlist via `-w <path>` and the adapter must refuse to run if none is approved.
- **Gating:** use existing `web.content_discovery` (default `true`, `core/config.py:169,179,404,514`) as the feature gate.
- **Seeds from crawl-discovered URLs:** expansion may consider in-scope crawl-discovered URLs as additional seeds **only** after re-validating each seed target against Scope Guard (host/port/path in-scope). Discovered hostnames never bypass Scope Guard.
- **Safety:** no evasion, destructive actions, brute-force auth, vulnerability confirmation, or out-of-scope requests. Scope re-checked at validate() and again for any discovered redirect targets if followed (but see §3.1).

### 3.1 Execution contract (FFUF)

- **Adapter:** `recon/web/ffuf.py::FfufAdapter(ToolAdapter)` with `name="ffuf"`, `executables=("ffuf",)`.
- **Input:** live in-scope web app base URL + approved wordlist.
- **Command construction (argument array, never shell string):** `["ffuf","-u","<base>/FUZZ","-w","<approved_wordlist>","-json","-o","<tmp_outfile>"]` plus rate/concurrency controls derived from `core.config.LimitsConfig`/RateLimiter (see below). Do not add `-mc`/`-fs`/recursive flags unless the approved config explicitly requires them; do not assume recursion.
- **Output format:** FFUF JSON (contract states `-json -o <outfile>`). Parser must treat output as JSON (not NDJSON unless observed in fixtures). Raw preserved under `storage/raw/ffuf/` by `ToolRunner`.
- **Timeouts:** per-request timeout controlled via FFUF flags consistent with config (if present) + overall task timeout via `ToolRunner.run_command(timeout=...)`.
- **Rate/concurrency:** use RateLimiter (global/per-tool) and reflect `limits.requests_per_second`/`limits.concurrency`. The Tool Runner enforces `shell=False` and captures stdout/stderr/exit code; non-zero exits are returned (not raised) and parsed best-effort per degrade-gracefully policy.
- **Availability:** if `ffuf` not on PATH → `is_available()` false → base `execute()` raises `ToolUnavailable` (logged, run continues). This matches existing behavior.
- **Scope:** `validate()` checks base URL against `ScopeGuard.check(...)`; any redirect destination must be re-checked before following (if follow enabled, which is **not** proposed by default).
- **Non-goals in invocation:** recursion depth, mutation, auth brute force, header fuzzing beyond what’s necessary; defer to later phases.

## 4. Scheduling and stage coverage

- **Coverage translation:**
  - `ai/run_context.TASK_TYPE_COVERS_STAGE` must map `content_discover → content_discover` and `ffuf → content_discover` (same aliasing pattern as Katana: `web_crawl/katana`).
  - `ai/loop.TASK_TYPE_FOR_STAGE` must add `content_discover: "ffuf"` (or `"content_discover"`)? But the adapter is registered by task type; Phase 22 uses canonical stage name `web_crawl` as the task type in expansion when allowed, and also registers `katana` alias. To be consistent, register both `content_discover` and `ffuf` in served adapters and allow either in expansion; also add `content_discover → content_discover` in `TASK_TYPE_COVERS_STAGE`.
  - `api/serve.py`: add `DEFAULT_CONTENT_DISCOVER_TYPES = ("content_discover","ffuf")` and include in `_default_adapters` (class `FfufAdapter` as factory like `KatanaAdapter`/`TechDetectAdapter`).
- **Expansion:** when completing `http_probe` (WebAppObservation), if `web.content_discovery` is true and `content_discover` or `ffuf` is in `available_types`, propose a `content_discover` task seeded with the app’s base URL (reuse pattern: seed from observed app URL or construct `scheme://host:port/`). Dedup key e.g. `(content_discover, base_url)`. Also consider crawl-discovered URLs as seeds only if they are in-scope and pass Scope Guard (never auto-follow to new hosts).
- **Web-crawl mapping gap:** `ai/loop.TASK_TYPE_FOR_STAGE` currently lacks `web_crawl`. This means if a proposal were to target `web_crawl` stage via loop’s translation, it would fail that translation gate. However, Phase 22’s expansion/serving works today (serves `web_crawl`/`katana` directly). The gap is minor but real; **smallest justified change** for Phase 23 is to add `content_discover` mapping only — do **not** broaden to unrelated refactoring. If `web_crawl` becomes relevant to loop translation later, handle separately.

## 5. Data and persistence

- **Reuse existing pipeline:** `UrlObservation` and `EndpointObservation` from `recon/web/katana.py` are generic (host/port/path/method, keying by (host,port,path,method) etc.). FFUF results map naturally: each discovered path → `UrlObservation(host,port,path)` and `EndpointObservation(host,port,path,method)` (default `GET` unless record specifies).
- **Status codes:** `docs/06_TOOL_CONTRACTS.md` says “with status codes”. The current `UrlObservation`/`EndpointObservation` dataclasses **do not** carry `status_code`. The DB schema (`urls`, `endpoints`) also has no `status_code` column. **Preferred:** treat status code as **observation metadata** (not persisted as a new column) unless a demonstrated requirement arises. Evidence references remain; do not add migration in this phase. If needed later, can extend observations without schema change by logging/attaching to evidence context.
- **Rooting/dedup:** same as Katana — resolve to web app via `asset->ip->port->web_app` (`repositories.all._crawl_web_app_id` logic) using host/port from base URL; only emit rows when rooted to existing in-scope web app. Unrootable → evidence only (NULL entity_id) per Phase 22 semantics.
- **Ingestion:** extend branches in `recon/ingest.plan_ingestion` to handle FFUF artifacts? Or reuse existing Url/Endpoint branches (they already exist). The adapter should emit the same canonical observation types (`UrlObservation`, `EndpointObservation`) so no new plan types required.
- **Malformed/partial/redirects/duplicates:** non-fatal parse (skip bad lines/records), preserve partial results, deduplicate by observation keys (existing keying), out-of-scope results never promoted. Redirects: if followed, each redirect target must be scope-checked; if not followed, only the base-scoped requests count.
- **Source tag:** when persisting, `crawl_source` is currently set to `str(plan.source or "katana")` in repositories (`database/repositories/all.py:1234`). FFUF ingestion should pass `source="ffuf"` (plan.source comes from task/tool name) so `urls.source='ffuf'` is honored.

## 6. Unresolved decisions (require human approval)

1. **Wordlist source & approval:** where is it configured (YAML under `web.content_discovery.wordlist` or separate)? Must be explicit path + approval; no auto-download.
2. **FFUF flags:** default concurrency/rate passed as flags vs relying only on RateLimiter? Need to align with installed FFUF version; avoid unsupported flags.
3. **Status code retention:** persist (needs migration) vs observation-only metadata? Prefer no migration now; confirm if reports need status codes for discovered URLs.
4. **Seeds from crawl URLs:** include/exclude JS/static paths as seeds? Probably include only HTML paths? Or all in-scope discovered URLs? Needs policy.
5. **Follow redirects:** default off (safer) or on with strict recheck?
6. **`ai/loop.TASK_TYPE_FOR_STAGE` web_crawl gap:** add `web_crawl: "web_crawl"` or `"katana"`? Smallest change — maybe add `content_discover` now and defer web_crawl unless loop needs it.

## 7. Test plan

- **Offline fixture tests (`tests/test_ffuf.py`, fixtures `tests/fixtures/ffuf/`):** `normal.json`, `empty.json`, `malformed.json` (mixed), `duplicates.json`, `partial.json`. Assert non-fatal parse, dedup, deterministic ordering.
- **Expansion (`tests/test_expansion.py`):** web app → content_discover child (gated by `web.content_discovery`), disabled when false, scope rejection, crawl-seed handling, dedup.
- **Ingestion (`tests/test_ingest.py`):** FFUF artifacts → Url/Endpoint plans, rooting, unrootable evidence-only, dedup, source=`ffuf`.
- **Orchestration (`tests/test_ingest_orchestration.py`):** similar to Katana patterns.
- **Adapter behavior (`tests/test_ffuf.py`):** `is_available()`/`ToolUnavailable`, timeout plumbing, command construction, scope validation.
- **Phase 16 gate (`tests/test_phase16.py`):** stage becomes runnable when registered; uncovered_without_capability/coverage_gaps semantics preserved.
- **Live test (`tests/test_phase23_live.py`, DB-gated):** end-to-end via served app with canned runner (no external binary), assert persisted `urls`/`endpoints` with `source='ffuf'`, evidence linkage, correct rooting. Follow existing Phase 22 live test pattern.
- **Regression:** run full offline suite and full DB-enabled suite (expect no new failures beyond documented pre-existing). Compare baselines.

## 8. Acceptance criteria

1. `recon/web/ffuf.py` exists with `FfufAdapter` following base contract; fixtures+parse tests pass.
2. Served registry registers `("content_discover","ffuf")`; `known_task_types()` includes both.
3. Coverage: `TASK_TYPE_COVERS_STAGE` has `content_discover→content_discover`, `ffuf→content_discover`; `ai/loop.TASK_TYPE_FOR_STAGE` updated minimally (add `content_discover`).
4. Expansion proposes `content_discover` child only when gated true and in-scope; scope re-checked; seeds from crawl URLs validated.
5. Ingestion reuses Url/Endpoint pipeline; `urls.source='ffuf'`; unrootable → evidence-only NULL entity_id.
6. No migration added; status codes treated as metadata (or explicitly deferred).
7. Graceful `ToolUnavailable` when ffuf absent; malformed/partial output non-fatal; timeouts handled via ToolRunner.
8. All relevant tests pass; no new failures in full suites; `git diff --check` clean and only `docs/PHASE_23_PROPOSAL.md` changed.

## 9. Implementation notes (for future code pass)

- Mirror `KatanaAdapter` structure: observations in same module style, `parse_jsonl`/`parse` analogous for FFUF JSON output, `build_command` with approved wordlist, `validate` checks base URL.
- Reuse `_crawl_web_app_id` rooting (works by host:port). Base URL must be normalized (scheme/host/port).
- Dedup keys: `UrlObservation.key` = (1,host,port,path); `EndpointObservation.key` = (1,host,port,path,method) in Katana — preserve same semantics.
- Expansion: when proposing, target should be the base URL (e.g. `http://host:port/`) consistent with how Katana seed is used.

## 10. Dirty-tree & safety confirmation

- **Only this file created/edited:** `docs/PHASE_23_PROPOSAL.md`
- **No git reset/clean/checkout/add -A/staging/commit.**
- **Safety chain preserved:** AI→Task Planner→Scope Guard→Rate Limiter→Tool Adapter→Tool Runner→Target; scope re-checked; discovery never treated as vulnerability; out-of-scope never promoted.
- **Defer Feroxbuster** as requested.

## 1b. Local wordlist configuration and approval (fail-closed)

Policy: FFUF wordlist must be explicitly approved and local; never downloaded/generated.

Configuration (WebConfig):
- Add wordlist_path: str | None = None to core/config.py::WebConfig.
- In WebConfig.from_dict(), when key web.content_discovery.wordlist is present and non-empty, validate path exists/is file/readable; if present but invalid, raise configuration error (fail-closed). If absent/empty -> None.
- to_dict() must not emit wordlist path by default; no DB migration.

Enforcement (adapter): validate() requires web.content_discovery enabled; if requested, requires approved wordlist (fail-closed). build_command() uses -w <approved> only after validation. No fallback/bundled defaults.

## 2. Enforceable budgets, timeouts, concurrency, rate limits

Existing components: LimitsConfig (rps,concurrency,max_artifacts_per_run,network_timeout,scan_timeout,...), RateLimiter (per-key concurrency + sliding-window RPS), ToolRunner (overall timeout, partial output, save_raw returning raw_output_ref), recon/base.ToolAdapter, api/serve.ServedExecution (max_artifacts_per_run enforced at ingestion).

Mapping: Per-task artifact budget = LimitsConfig.max_artifacts_per_run (enforced at ingestion; truncate + truncated). Overall timeout = ToolRunner.run_command(timeout) (prefer network_timeout/scan_timeout). Per-request timeout = FFUF flag if supported (-timeout/-http-timeout/-request-timeout); fallback to overall timeout if unsupported (log). Concurrency = RateLimiter per-host/tool + pass -c <= LimitsConfig.concurrency. Rate = RateLimiter per-host/tool + pass -rate <= configured RPS.

## 3. FFUF status codes: retention in metadata, association (no DB migration)

Status codes in UrlObservation/EndpointObservation.metadata (additive). Plans propagate metadata. source='ffuf'; evidence_id links to raw via ToolRunner.save_raw. Canonical URL is key; dedup by (source,url_key,method if endpoint); status in metadata of kept observation. No DB migration.

## 4. Task scheduling (content_discover canonical, ffuf alias)

Actual dispatch: api.serve._default_adapters registers task types; ai/run_context.TASK_TYPE_COVERS_STAGE maps task_type->stage; ai/loop.TASK_TYPE_FOR_STAGE maps stage->task_type; loop._task_from() looks up by stage. Currently missing content_discover/ffuf.

Preferred: expansion emits task_type 'content_discover' (canonical). Register adapter as 'content_discover' (impl 'ffuf'); optionally alias 'ffuf'. Minimal safe: add content_discover->content_discover, ffuf->content_discover to TASK_TYPE_COVERS_STAGE; set TASK_TYPE_FOR_STAGE['content_discover']='content_discover'. Do not add web_crawl unless expansion emits it.

## 5. Scope/seed acceptance cases

Hostname: in-scope (case-insensitive), lowercase; reject out-of-scope. Port: only if in-scope (80/443 default). Scheme: http/https only; redirect targets re-checked. Redirects: default off; if enabled, every target re-checked by ScopeGuard, out-of-scope rejected. Duplicate path: dedup by (base_url,path,method if endpoint). Unrootable: evidence-only (NULL entity_id), no forced graph edge. Out-of-scope discovery: ScopeGuard.check before ingestion/expansion; crawl-discovered hosts rechecked before follow-up.

## 6. FFUF JSON semantics (full vs JSONL, partial)

Expect JSON from -json -o <outfile>. If NDJSON (line-delimited), try NDJSON first; else parse as single JSON doc. Malformed lines skipped non-fatally. Partial output (timeout): parse best-effort; ToolRunner.save_raw preserves partial; non-zero exit -> parse best-effort if outfile/partial stdout available. Raw under storage/raw/ffuf/.

## 7. Finalized decisions and remaining notes

### 1. Wordlist configuration (finalized)
- Canonical key: web.content_discovery.wordlist.
- Approval required: presence/readability does not imply approval. Operator must explicitly select/approve. 
- Fail-closed: missing, unreadable, invalid, or unapproved -> validation/build_command() fails before execution. No download/generate/default.
- Implementation: WebConfig.wordlist_path; from_dict() reads web.content_discovery.wordlist (validate exists/is file/readable if present); to_dict() omits by default. No DB migration.

### 2. FFUF per-request timeout (finalized)
- No assumption of flag support; adapter must verify supported flags against FFUF binary (probe or documented). 
- Strategy: if verified supported flag exists (-timeout/-http-timeout/-request-timeout depending on version), pass it bounded by config; else rely on ToolRunner overall timeout and log limitation. 
- Never fabricate flags, never silently ignore unsupported flags in a way that weakens safety; do not weaken overall timeout. Use existing LimitsConfig/RateLimiter/ToolRunner. No new global limit type proposed unless inspection shows existing cannot enforce required boundary.

### 3. Redirect policy (finalized)
- Disabled by default. 
- If ever enabled, every redirect target (scheme/host/port/path) must be re-checked by ScopeGuard before follow; out-of-scope targets rejected; initial URL validation insufficient. 
- Remain disabled if architecture cannot guarantee this.

### 4. Crawl-discovered seed policy (finalized)
- Only eligible in-scope HTTP(S) URLs accepted as FFUF seeds. 
- Normalize (scheme, host lowercase, explicit/default ports), handle case-insensitive host, port restrictions, deduplicate by (base_url/normalized). 
- Recheck normalized seed via ScopeGuard before scheduling/execution. Reject unsupported schemes, out-of-scope hosts/ports. 
- Crawl-discovered hosts must be rechecked before follow-up (Phase 22). Unrootable observations -> evidence-only (NULL entity_id), no forced graph edge. Do not expand authorized scope; use existing scope/URL normalization mechanisms.

### 5. Canonical task mapping (finalized)
- Canonical: TASK_TYPE_FOR_STAGE['content_discover'] = 'content_discover'. 
- Add content_discover->content_discover and ffuf->content_discover to TASK_TYPE_COVERS_STAGE only if repository inspection confirms fit. 
- Register FFUF under canonical stage; ffuf retained as implementation/alias only if needed. Do not add web_crawl mapping unless expansion actually emits web_crawl task type. 
- Path: expansion (content_discover stage) -> task scheduling/loop -> adapter selection (ffuf/alias) -> execution (approved wordlist, limits/timeouts, scope) -> ingestion (metadata status, evidence, rooting).

### Compatibility notes
- Mapping changes are smallest safe; verify against actual ai/run_context.py, ai/loop.py, api/serve.py before implementation. Any unresolved compatibility issue must be recorded at implementation time (proposal notes this).


Resolved: explicit wordlist approval+fail-closed; enforceable budgets/timeouts/limits via existing components (per-request tool-native only, overall via ToolRunner); status metadata-only no migration with canonical URL association; canonical content_discover + alias ffuf with smallest safe loop/run_context changes; explicit scope/seed cases; JSON full/NDJSON/partial handling aligned.

Genuinely unresolved (human approval): 1) Wordlist key: web.content_discovery.wordlist vs web.wordlist (recommend first). 2) FFUF per-request timeout flag(s) version-dependent (-timeout/-http-timeout/-request-timeout) - probe/fallback. 3) Follow redirects default: off (proposed). 4) Crawl-seed policy: all in-scope crawl-discovered after recheck vs filtered. 5) Loop mapping: TASK_TYPE_FOR_STAGE['content_discover']='content_discover' (canonical) vs 'ffuf' (compat).
