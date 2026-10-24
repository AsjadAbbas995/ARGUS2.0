# ARGUS — Phase 25 Proposal Only: JavaScript Analysis Automation
 
**Status:** Proposed (not implemented).
**Current HEAD:** `a1852baccbd8ed7158b52cec1a91ecf8e1a31e11`
**Target stage:** `js_analysis` (03_RECON_PIPELINE.md §14)
 
This is a **proposal-only** document. No implementation, staging, or commit is performed. Only `docs/PHASE_25_PROPOSAL.md` is created/modified if absent. Existing work and untracked artifacts remain unchanged.
 
## 1. Rationale
 
- **Priority fit:** STAGE_PRIORITY includes `js_analysis` (after `historical_recon` at position 9). Phases 21A (tech_detect), 18 (coverage gaps), 24 (historical_recon) completed.
- **Missing capability:** `js_analysis` has no adapter in `recon/web/` or `recon/`, no registration in `api/serve.py`, no `TASK_TYPE_FOR_STAGE` mapping (only up to `historical_recon`), no `TASK_TYPE_COVERS_STAGE` entry, no expansion logic. It is uncovered and likely appears in coverage gaps when executable types do not include it.
- **Dependencies ready:** Phase 22 (web_crawl/katana) produces `javascript_files` and seeds URLs; Phase 23 (content_discovery) adds URL surface. Expansion already seeds `content_discover` after `http_probe`/crawl.
- **Value:** JS often exposes hidden endpoints, paths, parameters, API hints, WebSocket URLs. Structured extraction matches existing observation model without speculative vulnerability claims.
- **Safety:** Passive/static extraction (no in-browser execution, no dynamic instrumentation). No modification of targets. Scope Guard enforced. Respects RateLimiter/ToolRunner constraints.
 
## 2. Current Coverage (evidence)
 
From codebase inspection (read-only):
- `ai/recon_agent.py:21` `STAGE_PRIORITY` includes `js_analysis` at **position 9 (zero-based index 8)** — `subdomain_enum, dns_resolve, port_scan, http_probe, tech_detect, web_crawl, content_discover, historical_recon, js_analysis, ...`.
- `ai/loop.py:157` has `TASK_TYPE_FOR_STAGE` mapping only for subdomain_enum, dns_resolve, port_scan, http_probe, tech_detect, content_discover, historical_recon (no `js_analysis`). (loop.py:165 adds content_discover; 168 historical_recon).
- `ai/run_context.py:58` `TASK_TYPE_COVERS_STAGE` lacks `js_analysis` entry.
- `api/serve.py` registers adapters through `_default_adapters()` but has no js_analysis/adapter registration (has ffuf at 381, historical gated at 387).
- `recon/web/` has httpx_probe, katana, tech_detect, ffuf; no js_analysis adapter. `recon/web/__init__.py` placeholder.
- `recon/expansion.py` has logic for web_crawl and content_discover (lines 240-270) but no js_analysis branch.
- `docs/03_RECON_PIPELINE.md:195-211` defines js_analysis (inputs: JS files from crawling; tools: Internal JS parser `intelligence/javascript.py`).
- `intelligence/` exists but contains only `__init__.py` (placeholder). **`intelligence/javascript.py` does NOT exist** — the pipeline doc references it, but the module is absent from the repository. No JS extraction primitives are currently available.
- **Katana persists URLs, not bodies.** `recon/web/katana.py` normalizes crawl records into `UrlObservation` / `EndpointObservation` / `ParameterObservation` / `JavascriptFileObservation`; `recon/ingest.py:473-481` persists only the JS **URL** (`JavascriptFilePlan(hostname, port, url)` -> `javascript_files`). No JavaScript source text is stored. A content fetcher is therefore genuinely required; the analyzer cannot work from cached crawl output.

Conclusion: js_analysis is a documented stage with **no existing intelligence module and no execution path** (adapter, registration, mapping, expansion all missing). It is uncovered in coverage logic and not runnable. This proposal includes creating the parser contract (`intelligence/javascript.py`) **and a new bounded content fetcher** as part of the phase.
 
## 3. Candidate Comparison (proposal context)
 
Top candidates for next phase:
- **js_analysis (this proposal):** High value; reuses crawl results; minimal external tooling (parser, stdlib); no live fuzzing; easy to make offline-testable. Fits after crawl/content discovery.
- **api_discover/openapi/graphql/websocket (subsequent):** Build on js_analysis + crawl results; more complex parsing/normalization. Dependencies on js_analysis/crawl.
- **parameter_intel/auth_intel:** Later phases after surface mapped.
- **cdn_waf_intel/cloud_intel:** Detection already partially via tech_detect (WAF/CDN). Lower immediate incremental value vs JS surface.
 
Recommendation: **js_analysis** first. It consumes crawl-discovered JS files (Phase 22), produces endpoints/parameters (normalizes into existing entities), and unblocks API-related stages.
 
## 4. Design (revised after final approval gate)

### 4.0 Extraction engine (new production file)
- **Create `intelligence/javascript.py`** with a documented parser contract. The module does not exist today; the pipeline doc's reference was a false premise.
- Contract (bounded, offline, **no network side effects**):
  - `parse_javascript(text: str, *, max_bytes: int = ..., ...) -> JsParseResult` — takes raw JS text (already-fetched content) and returns extracted artifacts. It **never fetches URLs** and never executes JavaScript.
  - **Output is constrained to exactly three observation kinds:** `UrlObservation`, `EndpointObservation`, and `ParameterObservation` (`recon/web/katana.py:84-139`). Extracted candidates (routes, paths, query/body parameter names) are emitted as those types only. Token-like strings, WebSocket URLs, and other signals are recorded as `metadata`/`INFERENCE` on those observations, never as new artifact types.
  - **Must never emit** `JavascriptFileObservation`, `WebAppObservation`, a bare `str`, or any other artifact type that `recon.expansion` reacts to — because expansion branches on `str`/`IpObservation`/`PortObservation`/`WebAppObservation` (`recon/expansion.py:189-231`) and a `JavascriptFileObservation` in the artifact stream would self-seed further `js_analysis` tasks. Restricting output to `Url`/`Endpoint`/`Parameter` observations makes the expansion loop provably non-recursive.
  - Malformed, empty, or oversized input never raises: skipped records logged, valid ones kept, deterministic order (parse contract, `recon/base.py:93-98`).
  - Bounded: enforced `max_bytes` per file, bounded recursion for nested structures, no infinite loop on minified/obfuscated input; time bounds are the adapter's responsibility, not the parser's.
  - Obfuscated/unparseable JS recorded as `UNKNOWN`, not guessed at (`03_RECON_PIPELINE.md` §14 failure condition).

### 4.1 Bounded content fetcher (new capability)
There is **no existing general-purpose, scope-checked HTTPS fetcher for arbitrary paths**. The only in-process fetch in the codebase is `recon/web/tech_detect.py:257-310` `default_fetcher`, which uses plain `http.client.HTTPConnection`, requests only `GET /`, and supports neither HTTPS nor arbitrary paths; `core/tool_runner.py` is subprocess-only (`subprocess.Popen(..., shell=False)`) and is not a fetch API. A new in-process fetcher is therefore required.

- **Location:** a small private helper inside `recon/web/js_analyze.py`; stdlib only (`http.client`, `ssl`, `socket`, `ipaddress`, `urllib.parse`, `gzip`/`zlib`) — **no new external dependency** (the standard library provides everything needed; `tech_detect` sets the in-process precedent).
- **Target-host scope authorization (ARGUS boundary):** the target host must pass `ScopeGuard.check` (`core/scope_guard.py:127`) / `ScopeGuard.check_host` (`:143`), and the destination port must pass `ScopeGuard.check_port` (`:215`). This is the *authorization* decision and is separate from SSRF filtering below.
- **SSRF destination filtering (separate concern):** after resolving the hostname, **every** A/AAAA answer is classified as *prohibited* if it is private, loopback, link-local, multicast, unspecified, or reserved per `ipaddress` (`ip_address(a).is_private`, `is_loopback`, `is_link_local`, `is_multicast`, `is_unspecified`, `is_reserved`), including IPv4, IPv6, and IPv4-mapped IPv6 forms. Alternate textual forms (decimal/octal/hex integers, bracketed IPv6) are normalized through `ipaddress` before classification. **`ScopeGuard.check_ip` is *not* required of every resolved address**: that method only allow-lists IPs an operator explicitly enumerated and would wrongly deny an in-scope hostname whose address is not itself IP-listed (existing adapters authorize by host only — see `recon/web/httpx_probe.py:107-109`). Host authorization (above) plus prohibited-range filtering (here) is the SSRF boundary.
- **Fail-closed on any bad answer:** if **any** resolved answer is prohibited, the **entire fetch fails** (no observation); addresses are never silently filtered to pick another. A DNS resolution error also fails the fetch.
- **Rebinding resistance / no second lookup:** resolve **once**, validate all answers, then **open the TCP connection directly to a validated IP** using `socket.create_connection((validated_ip, port))`. Never re-resolve and never let the HTTP/TLS layer resolve the hostname again.
- **TLS IP pinning (SNI + certificate hostname preserved):** subclass `http.client.HTTPSConnection` and override `connect()` so it (a) creates the socket with `socket.create_connection((validated_ip, port), timeout=...)`, then (b) wraps it with `ssl_context.wrap_socket(sock, server_hostname=<original_hostname>)`, where `ssl_context = ssl.create_default_context()` (certificate verification enabled, system trust store). The **original hostname** is used for `server_hostname`, preserving SNI and hostname verification; the HTTP `Host` header is **never** used as a substitute for TLS verification. Certificate verification is **always enabled**; there is no plaintext fallback for an `https` URL.
- **Port policy:** the port is permitted iff `ScopeGuard.check_port(port)` is in scope. A **non-default port is not rejected merely for being non-default** (ARGUS scope and `WEB_PORTS` explicitly include non-default web ports such as `8000/8080/8443/8888`). Validate scheme/port consistency (e.g. explicit port must parse to 1-65535; reject control characters and malformed URLs).
- **No redirects (v1):** **refuse all redirects — not even one hop.** Any 3xx response is recorded as a skip/no-observation; the `Location` target is never resolved or contacted.
- **Timeouts / size:** connect+read timeout (small constant, e.g. 10s, mirroring `tech_detect.DEFAULT_TIMEOUT`); hard maximum response bytes enforced via bounded `response.read(max_bytes)`.
- **Content validation:** require a JavaScript-ish `Content-Type` (`javascript`, `ecmascript`, `json` for maps) or a `.js` path; skip otherwise. Bounded gzip/deflate decompression; a decompressed-size overflow is a skip.
- **Status handling:** non-2xx (including all 3xx) is a skip/no-observation, never a crash; an empty body is a skip.
- **TLS failures:** a certificate/handshake/TLS-verification failure produces **no observations** (a recorded skip), never a retry and never a downgrade.
- **Retries: disabled.** A failed fetch is never retried by the adapter; a duplicate URL is deduplicated before fetching and never refetched.
- **Isolation:** no subprocesses, no JavaScript execution, no dynamic instrumentation; pure in-process stdlib HTTP(S) GET.
- **Authorization:** fetching only occurs when the run is explicitly operator-enabled (§4.6); a disabled run never registers the adapter, so the fetcher is never constructed or invoked.

### 4.2 Adapter
- Create `recon/web/js_analyze.py::JsAnalyzeAdapter(ToolAdapter)`. Name: `js_analysis`.
- **In-process availability:** `executables = ()` and `is_available()` returns True (base `recon/base.py:63-69`); override `execute()` like `TechDetectAdapter` (`recon/web/tech_detect.py:432`), which is the established in-process pattern.
- **Input path (expansion-seeded; no DB access):** one task per unique in-scope JS URL, seeded by expansion from `JavascriptFileObservation` artifacts in the *current* artifact sequence (§4.4). The adapter reads the JS URL from its task target/`reason` payload and fetches via §4.1.
- **Scope:** `validate(task, scope)` calls `ScopeGuard.check` on the task target and rejects out-of-scope targets with `ScopeViolation` (`recon/base.py:74-82`); the fetcher re-validates the resolved IP (§4.1).
- **Normalization:** calls `intelligence/javascript.py::parse_javascript` on the fetched text and emits **only** `UrlObservation`/`EndpointObservation`/`ParameterObservation` (matching `recon/web/katana.py:84-152`). It never emits `JavascriptFileObservation`, `WebAppObservation`, or strings.
- **Rate limiting:** enforced by the orchestrator around `execute` (`core/orchestrator.py:620-634` — `RateLimiter.acquire/release`), same as every adapter; the adapter does not bypass it.
- **Evidence:** the fetched (bounded) JS and the extracted result are written via `runner.save_raw` (`ToolRunner`), matching `tech_detect` (`tech_detect.py:500-505`).

### 4.3 Registration/Mappings (fail-closed)
- Add `TASK_TYPE_FOR_STAGE["js_analysis"] = "js_analysis"` in `ai/loop.py:157`.
- Add `TASK_TYPE_COVERS_STAGE["js_analysis"] = "js_analysis"` in `ai/run_context.py:58`.
- Define `DEFAULT_JS_ANALYSIS_TYPES: tuple[str, ...] = ("js_analysis",)` in `api/serve.py` (alongside `:79-107`).
- **Conditional registration (historical pattern):** in `api/serve.py::_default_adapters()` register the JsAnalyze adapter **only when the opt-in gate is enabled**, guarded exactly like `DEFAULT_HISTORICAL_TYPES` (`api/serve.py:387-390`): `if config is not None and config.javascript.enabled:` (a `None` config is treated as disabled — fail-closed). When disabled, **no adapter is registered**. There is no "registered but non-executable" state.
- **Disabled coverage:** with no adapter registered, `js_analysis` is absent from the executable set, so `ai/run_context.py:209-220` reports it via `uncovered_without_capability` (not `coverage_gaps`); when enabled it appears in `coverage_gaps`. No task is ever enqueued for a disabled stage.

### 4.4 Expansion (no loops, no unintended probing)
- Add a branch to `recon/expansion.py:189-231` that matches **`JavascriptFileObservation` artifacts in the current `artifacts` sequence** (expansion has no database access and must not assume any). For each observation whose host is in scope (`scope.check_host`), propose one `js_analysis` child with target = the JS URL.
- **Dedup:** reuse the existing `propose(...)` mechanism and its `seen: set[(child_type, target)]` (`recon/expansion.py:172-187`), giving key `(js_analysis, js_url)`; bounded by `max_tasks` (`:273-274`) and emitted in sorted order, mirroring the `content_discover` branch (`:252-270`).
- **Gating (fail-closed via `available_types`):** expansion already receives `available_types` (`recon/expansion.py:145-169`) and its `propose()` helper refuses any `child_type not in allowed` (`:181-182`). Since the adapter is registered **only** when `config.javascript.enabled` is true (§4.3), the type `js_analysis` is in `available_types` only when enabled — so the expansion branch needs **no snapshot gate**: when disabled the type is absent and `propose("js_analysis", ...)` is a no-op. This is the same capability signal `web_crawl`/`content_discover` rely on. **No change to `run_snapshot_from_dict` is required** (the snapshot has no `javascript` section and is not used here).
- **No recursion:** because the analyzer emits only `Url`/`Endpoint`/`Parameter` observations (neither of which any expansion branch reacts to) and never `JavascriptFileObservation`/`WebAppObservation`/strings, a completed `js_analysis` seeds **no** further tasks. Combined with the completed-only fingerprint suppression (`core/task_planner.py:23,26-47`), the feature cannot form an unbounded retry loop.
- **No probing:** extracted endpoints/parameters are observations only; expansion does not branch on them, so no `http_probe` (or any other live task) is scheduled from JS output.
- **Empty/duplicate/partial:** no JS artifacts -> no proposals; duplicate JS URLs collapse via the dedup key; a partial crawl simply yields fewer observations.

### 4.5 Observations/Persistence (no migration)
- Reuse existing observation types (`UrlObservation`, `EndpointObservation`, `ParameterObservation`). Ingest maps them via `recon/ingest.py` (`UrlObservation` `:424`, `EndpointObservation` `:445`, `ParameterObservation` `:456`) and persists through `database/repositories/all.py::ingest_observations` (`:1092`) into existing tables: `urls` (`UrlRepository` `:502`), `endpoints` (`EndpointRepository` `:532`), `parameters` (`ParameterRepository` `:552`); JS URLs continue to land in `javascript_files` (`JavascriptFileRepository` `:575`) from Phase 22. **No new columns or migration.**
- Extracted endpoints/params are **observations** (FACT/OBSERVATION), never auto-upgraded to probes or vulnerabilities.
- **No-migration rationale:** the current URL/endpoint/parameter/JavaScript-file repositories are sufficient to store all analyzer output; status codes and similar fields are not required as new columns. This remains subject to confirmation during implementation, but no schema evidence currently justifies a migration.

### 4.6 Config
- Owner is **`Config.javascript` / `JavascriptConfig`** (`core/config.py:230-241`, wired at `core/config.py:404`), **not** `ReconConfig` (`ReconConfig` at `core/config.py:166-174` holds only `aggressive_subdomain_discovery`).
- **Add a new operator opt-in field `enabled: bool = False`** to `JavascriptConfig` (default **disabled**, fail-closed), and read it in `JavascriptConfig.from_dict` (`:236-241`) with default `False`, plus mirror it in `Config.to_dict` (`core/config.py:453-456`) and `docs/14_CONFIG_EXAMPLE.md`. The existing `deep_analysis`/`source_maps` fields are unchanged; `source_maps` remains unused this phase (source-map analysis is a follow-up).
- **Scope of the gate:** `config.javascript.enabled` is read **only at adapter registration time** (§4.3). Expansion inherits the gate transitively through `available_types` (§4.4) and does **not** read the config. Because the run snapshot (`core/config.py:508-576 run_snapshot_from_dict`) does not emit a `javascript` section, the proposal makes **no change to `run_snapshot_from_dict`** and makes **no claim** that a snapshot-based `javascript.enabled` gate exists.
- **Backward compatibility:** configs predating this field deserialize to disabled (`from_dict` defaults `enabled` to `False`); this is a config-compatibility change, not a database migration. A regression test in `tests/test_config.py` asserts (a) `JavascriptConfig()` defaults to `enabled is False`, (b) a `javascript` mapping without `enabled` loads as disabled, and (c) the `to_dict` round trip preserves the flag — mirroring the existing `historical_urls` fail-closed pattern (`tests/test_config.py:322-327`).

### 4.7 Resource bounds (deterministic)
- **Max files analyzed per task:** one JS URL per task (bounded by the per-crawl `max_tasks` in expansion).
- **Max bytes per response:** `DEFAULT_MAX_BYTES` (per-response hard cap; bounded `response.read(n)`).
- **Retries: disabled.** A failed/timed-out fetch is never retried; a duplicate URL is deduplicated before fetching and never refetched. Each unique JS URL results in **at most one** HTTP request per run.
- **Total bytes per run (shared budget):** a run-level `total` byte budget (`DEFAULT_TOTAL_BYTES_PER_RUN`) shared across all `js_analysis` tasks of a run.
  - **Where held/enforced:** a single `JsFetchBudget` instance created once by `api/serve.py::_default_adapters()` and captured by the JsAnalyze adapter factory, **keyed by `run_id`**. The fetcher decrements it immediately before reading each response body, reading **at most `min(remaining_budget, DEFAULT_MAX_BYTES)`** bytes.
  - **No race:** the orchestrator executes tasks **sequentially** on one thread (`core/orchestrator.py:549`, a single `for task in ordered` loop with no thread pool), so the shared counter is never accessed concurrently. If future concurrency is ever introduced, the counter must be guarded — this is noted as an invariant, not an assumption.
  - **Accounting (explicit):**
    - **Duplicate URLs** are deduplicated (dedup key `(js_analysis, js_url)`) before fetch, so they never consume budget twice.
    - **Failed fetches** (DNS error, prohibited answer, connect/TLS failure, non-2xx, bad content type) consume **0** bytes.
    - **Partially consumed responses** (truncated at the cap) consume **exactly the bytes read** (the bounded read length), never `Content-Length`.
    - **Repeated / resumed runs:** the counter is process-local and resets when a new process re-enters `_default_adapters()`. This cannot make the run unbounded because the deterministic task-count ceiling still holds: worst case per process is `(number of `js_analysis` tasks, itself bounded by expansion `max_tasks`) × DEFAULT_MAX_BYTES`, and the run-level counter can only lower it.
  - **Exhaustion behavior:** once the shared budget is exhausted, subsequent `js_analysis` tasks perform **no fetch** and emit **no observations**; they complete successfully with an empty result (deterministic skip), never fail. Because tasks run in sorted order, the set of tasks that fetch is deterministic.
- **Parser input limit:** `parse_javascript` truncates input at `max_bytes` and skips the remainder deterministically; oversized input never raises.
- **Timeouts:** connect/read timeout per fetch; an overall per-task bound; a timeout is a recorded skip (no artifact), never a crash.
- **Determinism on the edge cases:** partial crawls -> fewer tasks; duplicate URLs -> dedup key; empty files -> `[]`; malformed files -> skipped + logged; fetch failures/timeouts/TLS-failures -> skip (no observations); all produce a stable, sorted result set.
 
## 5. Non-goals
- Dynamic analysis/headless browser, authenticated crawling, vulnerability validation, secret verification.
- Executing JavaScript or using a subprocess to obtain JS content (in-process stdlib HTTPS GET only).
- Schema migrations. Changes to ScopeGuard/RateLimiter logic beyond wiring.
- Modifying historical discovery behavior.
- Following redirects (refused entirely in v1 — not even a single hop) or fetching any out-of-scope/private destination.
- Retrying failed/timed-out fetches (retries are disabled; one request per unique JS URL per run).
 
## 6. Acceptance Criteria (revised)
- **Extraction engine:** `intelligence/javascript.py` exists with a documented, bounded, offline parser contract (`parse_javascript`); output restricted to `UrlObservation`/`EndpointObservation`/`ParameterObservation` only; malformed/empty/oversized input never raises, returns deterministic output; obfuscated JS recorded as `UNKNOWN`, never guessed.
- **Content fetcher:** a bounded, in-process, stdlib HTTPS-capable fetcher exists (not `tech_detect.default_fetcher`, which is plain-HTTP `GET /` only); TLS certificate verification enabled via `ssl.create_default_context()` with the **original hostname as `server_hostname`** (SNI + hostname verification preserved; never substituted by the HTTP `Host` header); connection made directly to a **previously validated IP** with no second DNS lookup; connection/read timeout, max bytes, content-type validation, and the shared total-bytes budget enforced; non-2xx/empty/oversized/compressed handled without error; **all redirects refused (not even one hop)**; **retries disabled**; SSRF-safe (target host authorized by `check_host`/`check_port`; every resolved A/AAAA answer filtered for prohibited ranges and the fetch **fails entirely if any answer is prohibited**; no userinfo; alternate-IP forms normalized; no alternate-IP bypass).
- **TLS/pinning:** the TCP connection goes to a previously-validated IP, and the TLS layer is driven with the original hostname so that certificate hostname validation and SNI both apply; a TLS verification failure yields no observations.
- **Adapter:** `recon/web/js_analyze.py::JsAnalyzeAdapter(ToolAdapter)` exists; `is_available()` returns True in-process (no external binary); overrides `execute()`; `validate()` enforces ScopeGuard on the target; emits only `Url`/`Endpoint`/`Parameter` observations (never `JavascriptFileObservation`/`WebAppObservation`/strings).
- **Registration/mappings (fail-closed):** `DEFAULT_JS_ANALYSIS_TYPES` defined; adapter registered in `api/serve.py::_default_adapters()` **only when `config.javascript.enabled`** (historical pattern); `ai/loop.TASK_TYPE_FOR_STAGE` and `ai/run_context.TASK_TYPE_COVERS_STAGE` contain `js_analysis`; disabled -> `uncovered_without_capability`, enabled -> appears in `coverage_gaps`.
- **Expansion:** `recon/expansion.py` proposes `js_analysis` from `JavascriptFileObservation` artifacts in the **current artifact sequence** (no DB access); dedup key `(js_analysis, js_url)` via the existing `(child_type, target)` pattern; one task per unique in-scope JS URL; bounded by `max_tasks`; **gated fail-closed by `available_types`** (the type is absent unless the adapter is registered, so disabled -> zero proposals; no snapshot/config read and no `run_snapshot_from_dict` change); no recursion (analyzer emits no self-seeding artifact type).
- **Input path / SSRF:** adapter fetches JS only after destination authorization (`check_host` + `check_port`) and SSRF filtering (every resolved A/AAAA answer classified as non-prohibited; fetch fails entirely if any answer is prohibited; no credentials; scheme http/https); no cross-domain or private-network fetching; no redirects followed (all refused).
- **Normalization/persistence:** extracted endpoints/params emitted as `EndpointObservation`/`ParameterObservation`/`UrlObservation`; ingested into existing tables (`endpoints`, `parameters`, `urls`) via existing repositories without schema migration; observations rooted to the same host/port as the source JS.
- **No-probe guarantee:** extracted endpoints never spawn `http_probe` (or any other task) children (tested); they are observations (FACT/OBSERVATION), not probes or vulnerabilities.
- **Default gating:** js_analysis fails closed (disabled) unless the operator sets `javascript.enabled`; tests assert the adapter is not registered, no tasks proposed, and coverage is `uncovered_without_capability` when disabled; and that it is registered/executable when enabled.
- **Resource bounds:** max files per task (one URL/task), max bytes/response, shared run-level total-bytes budget (enforced in the fetcher via a `run_id`-keyed counter, race-free under sequential execution), parser input limits, **retries disabled**, and timeout behavior enforced with deterministic truncation/skip; partial crawls, duplicate URLs, empty files, malformed files, and fetch failures all handled without error.
- **Config compatibility:** `JavascriptConfig()` defaults to `enabled is False`; a `javascript` mapping without `enabled` loads disabled; `to_dict` round-trips the flag; asserted in `tests/test_config.py` (mirroring the `historical_urls` fail-closed pattern). No `run_snapshot_from_dict` change is claimed or required.
- **No migration:** existing URL/endpoint/parameter/JavaScript-file repositories are sufficient; no new columns required (subject to the implementation verification in §9).

## 7. Dependencies/Assumptions
- **`intelligence/javascript.py` is created as part of this phase** (new production file; currently does not exist — the pipeline doc's reference was a false premise, corrected in §2).
- Crawl results include `javascript_files` references (Phase 22 katana `-js-crawl`), but **only URLs are persisted — not bodies** (`recon/ingest.py:473-481`), so the new fetcher (§4.1) is required.
- No external CLI/dependency required: the parser and fetcher use only the standard library (`http.client`, `ssl`, `socket`, `ipaddress`, `urllib.parse`, `gzip`/`zlib`), following the `tech_detect` in-process precedent.
- In-process adapter availability is derived from the registered task type (`DEFAULT_JS_ANALYSIS_TYPES`), not from a binary check.

## 8. Rollback/Safety
- Fail-closed when `config.javascript.enabled` is off (no registration, no proposals); missing capability → `uncovered_without_capability` (reported, never a failing task).
- No target-side modifications. Observations remain evidence-only.
- TLS verification always enabled (original hostname pinned via `server_hostname`); redirects refused entirely; retries disabled; SSRF guards on every destination.
- Deterministic, offline-fixture driven tests.
- No changes to ScopeGuard/RateLimiter logic beyond wiring the adapter's existing checks.

## 9. Verification (proposed)
```bash
pytest -q tests/test_intelligence_javascript.py tests/test_js_analyze.py tests/test_config.py 2>&1 | tail -5
pytest -q --ignore=tests/test_phase18_live2.py -rs -k js 2>&1 | tail -5
```
- **No-migration verification:** after the parser/adapter tests pass, confirm via a fresh `pytest -q` (offline DB subset) that no new migration/column was required; if a schema change turns out to be necessary, it must be raised back to the approval gate rather than silently added.
 
## 10. Planned Files
**New:**
- `intelligence/javascript.py` — bounded, offline parser contract (`parse_javascript`); emits only `Url`/`Endpoint`/`Parameter` observations.
- `recon/web/js_analyze.py` — `JsAnalyzeAdapter` and the bounded in-process HTTPS fetcher (§4.1).
- `tests/test_intelligence_javascript.py` — parser fixtures (malformed/empty/oversized/obfuscated/duplicate/partial).
- `tests/test_js_analyze.py` — adapter registration/coverage, expansion dedup, disabled-by-default, `uncovered_without_capability`, fetch timeout/failure, unsafe-destination (SSRF) rejection, response-size limit, redirect refusal, no-probe guarantee, and ingestion/persistence via existing repositories.

**Modified:**
- `ai/loop.py` — add `TASK_TYPE_FOR_STAGE["js_analysis"]`.
- `ai/run_context.py` — add `TASK_TYPE_COVERS_STAGE["js_analysis"]`.
- `api/serve.py` — add `DEFAULT_JS_ANALYSIS_TYPES`, conditional registration (fail-closed), and the shared `JsFetchBudget` used by the adapter factory.
- `recon/expansion.py` — add `JavascriptFileObservation` -> `js_analysis` branch (gated by `available_types`).
- `tests/test_config.py` — default-disabled / missing-key / `to_dict` round-trip tests for `JavascriptConfig.enabled`.
- `core/config.py` — add `JavascriptConfig.enabled: bool = False` (+ `from_dict`/`to_dict`).
- `docs/03_RECON_PIPELINE.md` — correct §14 (module now created; add fetcher/scope note).
- `docs/14_CONFIG_EXAMPLE.md` — document `javascript.enabled` (default false).
- `docs/06_TOOL_CONTRACTS.md` — **only if** the in-process HTTPS fetcher warrants a documented contract; no change if existing adapter contracts suffice.

 
## Recommendation
Implement **js_analysis** next (Phase 25) per this revised design: create the missing extraction engine (`intelligence/javascript.py`) and the bounded in-process HTTPS fetcher, wire the in-process adapter/registration/expansion with fail-closed default-disabled gating, SSRF-safe destination validation, and the no-probe/no-recursion guarantees. It extends crawl results into structured endpoints/parameters with minimal risk, no schema migration, and unblocks API discovery stages. GAU remains unverified but not blocking this phase. **This proposal is ready for a fresh approval-gate review.**
