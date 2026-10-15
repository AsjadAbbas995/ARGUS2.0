# Phase 21A Proposal — Deterministic Technology + WAF/CDN Detection

## Phase 21A status

**FORENSIC PASS COMPLETE — VERDICT: READY. NOT IMPLEMENTED.**

This document records the completed Phase 21A **forensic / specification pass**
only. No production code, migration, test, or configuration was written by this
pass. Phase 21A **must not be implemented** as part of producing this document.

The forensic pass found **no blocking STOP condition**. The requested capability
— a served, deterministic `tech_detect` task type that fingerprints an already
discovered, in-scope web application into technology and WAF/CDN observations —
is **feasible additively**, with **no database migration required**, **no external
binary required**, and **no AI activation required**, by reusing the existing
technology schema, ingestion, evidence, projection, coverage, expansion and
served-execution machinery that Phase 20A and earlier phases already committed.

## 1. BASELINE

- `HEAD` is `2aaa05d` — `feat: implement phase 20a recon pipeline breadth`
  (12 files, 1979 insertions, 5 deletions). Phase 20A is **committed and closed**.
- The working tree still carries the **pre-existing Phase 18 uncommitted changes**
  only (12 tracked `M` files and 8 untracked entries including `.byte/`, the
  `0006` migrations, and the `test_phase18*` live test files). Those files are
  **protected and untouched by Phase 21A**.
- Full suite record (Phase 20A closure): **817 passed, 6 failed**, the 6 failures
  being pre-existing Phase 18 conditions (five migration bookkeeping assertions
  asserting an applied-list that ends at version 5 while `0006_ai_coverage_gaps`
  extends it; one Phase 18 live test calling the nonexistent
  `DatabaseConnection.cursor()`). Phase 21A must not regress this record and must
  not fix those failures.

## 2. PROBLEM

`tech_detect` is today a **declared but unfillable capability**:

- The AI coverage model declares it. `ai/recon_agent.py` (`STAGE_PRIORITY`) lists
  `tech_detect` fifth, directly after the four stages Phase 20A implemented;
  `ai/loop.py::TASK_TYPE_FOR_STAGE` already maps `"tech_detect": "tech_detect"`;
  and `ai/run_context.py::TASK_TYPE_COVERS_STAGE` already maps both
  `"tech_detect"` and `"whatweb"` to the `tech_detect` stage.
- **Coverage is keyed to completed task types, not to artifacts.** Coverage is
  computed exclusively from tasks whose `status` is `completed`
  (`ai/run_context.py::_COVERED_STATUSES = {"completed"}`, then matched through
  `TASK_TYPE_COVERS_STAGE`). No `tech_detect` task type exists anywhere in the
  served registry (`api/serve.py::_default_adapters` registers only
  `dns_resolve/dns/resolve`, `http_probe/httpx/web_probe`,
  `subfinder/subdomain_enum`, `port_scan/nmap` — 10 task types total). There is
  therefore **no way for any task to complete with a type that the coverage
  vocabulary recognises as `tech_detect`**, so the stage can never count as
  covered.
- **`httpx -tech-detect` is a side effect, not coverage.** `HttpxProbeAdapter`
  emits `AssetTechnologyObservation` objects as a by-product of probing
  (`recon/web/httpx_probe.py:173`), and those flow into
  `technologies`/`asset_technologies`. That is a *fact-gathering side effect of an
  `http_probe` task*; it never creates, runs, or completes a `tech_detect` task.
  Therefore:
  ```
  httpx -tech-detect  ≠  completion of task type tech_detect
  ```
  - the httpx side effect **does not close the stage**;
  - it is also gated on the `httpx` binary being present, and
  - it hardcodes the honest-but-blank category `"other"` — it performs **no
    WAF/CDN classification** at all.
- Consequently, on **every** run the stage is reported by
  `uncovered_without_capability()` as *structurally can't attempt* (the stage is
  not in the runnable/executable set), and Phase 18 persists it into
  `ai_coverage_gaps` as a capability gap. The system names the gap every pass and
  can never fill it.

## 3. OBJECTIVE

Implement a **deterministic, served** `tech_detect` capability:

- a `TechDetectAdapter` registered under the task types `tech_detect` (and the
  documented alias `whatweb`, mirroring how Phase 20A registered
  `subfinder`/`subdomain_enum` and `port_scan`/`nmap`);
- performs **bounded technology and WAF/CDN fingerprinting** against an **already
  discovered, in-scope web application**;
- emits canonical technology observations that reach the **existing** Phase 14
  ingestion and Phase 15 projection, so operators see real technology records and
  the WAF/CDN classification in `attack-surface` `records.by_kind.technology`;
- closes the declared `tech_detect` coverage gap for real on successful task
  completion, without enabling the AI loop.

Phase 21A is a **recon-capability phase**, exactly the same shape as Phase 20A:
a new served adapter on the documented execution chain. Nothing about AI, scope,
rate limiting, ingestion semantics, or the projection changes.

## 4. DATA FLOW

Reusing the Phase 20A discovery-to-task expansion inside the served ingest
callback (`api/serve.py::_enqueue_expansion`), the intended flow is:

```
discovered web app (WebAppObservation artifact)
        ↓
tech_detect task (proposed by recon.expansion, parent = completed http_probe)
        ↓
ScopeGuard                      (run scope re-checked, host AND port)
        ↓
RateLimiter                     (per-task permit, served RateLimiter)
        ↓
TechDetectAdapter               (recon/web/tech_detect.py, in-process)
        ↓
controlled HTTP mechanism       (single bounded request via stdlib; no subprocess)
        ↓
deterministic fingerprinting    (pure function over captured signals)
        ↓
TechnologyObservation / AssetTechnologyObservation
        ↓
existing Phase 14 ingestion     (recon.ingest.plan_ingestion, unchanged shape)
        ↓
technologies + asset_technologies   (existing repositories, unchanged SQL)
        ↓
evidence                        (ENTITY_TECHNOLOGY / ENTITY_ASSET_TECHNOLOGY)
        ↓
Phase 15 projection             (database.projection, unchanged)
        ↓
by_kind.technology              (attack-surface show_<...>_records)
```

Every hop except the new adapter and the new expansion branch already exists and
is committed. The data flow is deliberately **identical** to the one Phase 20A
wired for `subfinder → dns_resolve → port_scan → http_probe`.

## 5. FINGERPRINTING SCOPE

The fingerprinting library is a **pure, deterministic function** — same inputs
always yield the same `(technology name, category)` pairs. It consumes response
signals such as:

- `Server`
- `X-Powered-By`
- `Set-Cookie`
- `cf-ray` / `CF-RAY`
- `X-Sucuri-ID`
- `X-Served-By`
- `Via`
- `Content-Type`
- HTML `<title>`
- `generator` meta tag

Header names and values are matched **case-insensitively** where appropriate. The
function maps matched signals to:

```
technology name     (free text, e.g. "cloudflare", "nginx", "wordpress")
explicit category   (one of the EXISTING technologies.category CHECK values)
```

Allowed categories are **exactly** the schema CHECK set from migration `0001`
(`database/migrations/0001_initial_schema.sql`, `technologies.category`):

```
framework
cms
api_technology
cdn
waf
cloud
auth
other
```

**Phase 21A invents no new category.** Any technology that cannot be assigned one
of the eight truthful categories is recorded with category `"other"`, which is
the same honest default Phase 14 already uses (`recon/ingest.py:41`). The only
values that change from today's behaviour are the ones a fingerprint can justify
with an explicit signal.

**Determinism and single-sourcing.** `TechnologyRepository.upsert(name,
category)` (`database/repositories/all.py:648`) is global per `name` and
overwrites `category` on conflict. The fingerprint table is therefore the single
authoritative source for a technology name's category, and the table is a fixed
module constant — two paths (httpx side effect vs. `tech_detect`) can never fight
over a category because the table is one static mapping.

## 6. WAF/CDN

WAF/CDN classification is **gated on explicit, reliable signals only**. A
classification is emitted **only** when one of the documented signals below is
present; weak or generic evidence (for example a bare `Via` hop mentioning any
CDN, or a `Server` value that merely resembles a product) produces **no
classification at all** — no name, no category. "If evidence is insufficient,
produce no classification" is a hard rule, so certificates-of-absence are honest.

Initial deterministic fingerprints (exact table content is an implementation
artifact; the commitments below are the reliable signals):

| System | Explicit signal(s) | Proposed name | Proposed category |
|--------|--------------------|---------------|-------------------|
| Cloudflare | header `cf-ray`/`CF-RAY` present, or `Server == cloudflare`, or `cf-cache-status` present | `cloudflare` | `cdn` |
| Sucuri | header `X-Sucuri-ID` present, or `X-Sucuri-Cache` present, or `Server` containing `sucuri` | `sucuri` | `waf` |
| Akamai | `Server` containing `akamai` (e.g. `AkamaiGHost`), or header `X-Akamai-Transformed` present | `akamai` | `cdn` |

A single response can produce **multiple** technologies (e.g. a WAF in front of a
CMS); the fingerprint function returns every justified pair. Duplicates within
one response are deduplicated to one row per `(name, category)`.

## 7. ADAPTER

The proposal is a new file:

```
recon/web/tech_detect.py
```

`recon/web/` is the most appropriate package — it already owns HTTP(S) probing
(`recon/web/httpx_probe.py`) — and this is the repository's most appropriate
equivalent after implementation review (the final module location is confirmed
during implementation, but `recon/web/` is the expected location).

The adapter follows the committed `ToolAdapter` contract (`recon/base.py`) in
the same **in-process** style as `DnsResolverAdapter`
(`recon/dns/resolver.py`: `executables = ()`, `is_available() == True`, custom
`execute()` that never shells out):

- **name** `"tech_detect"`, task types `tech_detect` (+ alias `whatweb`).
- **validate(task, scope)** — re-check the target's host **and** port against the
  run's `ScopeGuard` (host via `check_host`/`check_ip`, port via the existing
  `ScopeGuard.check_port`, which permits when no port rule is configured and
  denies when a rule excludes the port — the semantics are unchanged).
- **deterministic arguments** — the only inputs are `task.type`, `task.target`
  (`host[:port]`), and the run's persisted `config` snapshot; there is no
  randomness, no clock dependence in the fingerprint, and no dependency on
  mutable global state. A `fetcher_fn` seam (the DNS adapter's `resolver_fn`
  pattern) is injected so tests are fully offline and deterministic.
- **timeout** — a short, bounded, configurable per-request timeout (default in
  the seconds range) enforced by the in-process fetch; it never blocks a run.
- **bounded response size** — the fetch reads response headers plus a bounded,
  capped body prefix (enough to recover `<title>` and `generator` meta). Oversized
  responses are truncated to the cap; the fingerprint never buffers unbounded
  input.
- **no arbitrary shell** — the adapter makes **no** subprocess call, constructs
  **no** shell string, and never passes `shell=True`; the HTTP mechanism is a
  stdlib request, the same way DNS is a stdlib/library call.
- **no crawling** — exactly one request to the task's own target.
- **no recursive requests** — no request is issued based on anything found *in* a
  response (no links, no assets, no further URLs).
- **no vulnerability scanning** — fingerprinting inspects response metadata only;
  it performs no probing beyond a single benign metadata request and makes no
  security judgement.

`build_command` returns a **diagnostic marker array** (e.g.
`["tech-detect", target]`, mirroring the DNS in-process precedent) that is
never executed. Raw output is preserved by calling
`runner.save_raw("tech_detect", ...)` under `storage/raw/tech_detect/`, exactly
as the DNS adapter preserves its serialized resolution result.

## 8. REQUEST BEHAVIOR

**Reuse before request.** When the deterministic expansion proposes the
`tech_detect` task from a `WebAppObservation`, the signals the probe already
captured (`WebAppObservation.webserver` = `Server` header, `title`,
`content_type`) are available to the planner. The expansion may stamp those
already-captured signals as **deterministic structured arguments** on the child
task so the adapter can fingerprint from them directly without issuing a new
request (`Task.reason` carrying a documented JSON shape is the available
channel, and the adapter treats an absent signal set as "no reuse available").

**When a request is required**, it must satisfy every one of:

- **in scope** — the target is the task's own `host:port`; it passes the
  orchestrator's scope enforcement **and** the adapter's `validate` before any
  request is attempted;
- **rate limited** — the served `RateLimiter` grants the per-task permit before
  execution (the orchestrator's existing chain), so a `tech_detect` task costs
  the same one throttle permit as any served task;
- **timeout bounded** — short per-request timeout;
- **response-size bounded** — capped read (headers + bounded body prefix);
- **deterministic** — the fingerprint result depends only on the captured
  signals;
- **limited to the target web application** — one request to the target, no other
  destination.

The adapter does **not** introduce a crawler, does **not** follow arbitrary
external links, and does **not** recursively enumerate resources. Redirects are
**not followed**: if the first response is a redirect, the adapter fingerprints
the initial response's own headers (`Server` on a 30x is still a real signal)
and stops; it never chases a `Location`.

## 9. EXPANSION

`recon/expansion.py::plan_discovery_expansion` currently maps completed discovery
artifacts to child tasks (`str → dns_resolve`, `IpObservation → port_scan` gated
on a discovery-chain ancestor, `PortObservation(open, conventional web port) →
http_probe`). Phase 21A **adds one branch**:

```
WebAppObservation (host, port, ...)  →  tech_detect host:port
```

- **Dependency / parent relationship:** the `tech_detect` child's
  `parent_task_id` is the completed `http_probe` task that produced the
  `WebAppObservation`; the orchestrator already gates children on their parent
  reaching `completed`, and `core/task_planner.py` orders parents first. The
  chain becomes `port_scan → http_probe → tech_detect`.
- **Why ungated:** mirroring the Phase 20A precedent for
  `port_scan → http_probe` (the "bounded, terminal consumption of a scan that
  already happened"), a single bounded fingerprint request against an already
  probed web application is terminal consumption of a probe that already happened.
  It is not a deepening of a root task's contract, so it needs no
  `DISCOVERY_TASK_TYPES` ancestor gate — but this decision is *made explicit* in
  the implementation, not assumed.
- **Bounded fan-out:** exactly one `tech_detect` per `WebAppObservation`
  (deduplicated inside `plan_discovery_expansion` by `(type, target)`), the
  whole proposal batch capped by `max_tasks` (`DEFAULT_MAX_TASKS = 256`), and
  `_enqueue_expansion` already refuses children whose fingerprint exists in the
  run. A resumed or re-executed parent cannot duplicate work.
- **Allowlist:** children are only emitted for types in the composition's
  `available_types`, so `tech_detect` children exist on a run only after the
  adapter is registered; nothing changes for a deployment that has not upgraded.
- **Every generated task continues through `ScopeGuard → RateLimiter → Adapter →
  ToolRunner`** exactly like operator-created tasks — expansion proposes tasks; it
  never executes and never bypasses the chain.

## 10. INGESTION

Phase 21A **reuses** the existing technology ingestion path and creates **no
duplicate persistence**:

- `recon/ingest.py::plan_ingestion` already handles `AssetTechnologyObservation`
  (and bare `TechnologyObservation`) into `TechnologyLinkPlan`
  (`recon/ingest.py:292-312`), and Phase 14.2 already persists each plan as
  **one** `technologies` row, **one** `asset_technologies` row, and **one**
  `ENTITY_TECHNOLOGY` + one `ENTITY_ASSET_TECHNOLOGY` evidence pair
  (`database/repositories/all.py:1115-1128`) — all unchanged.
- The single additive edit is to let an observation's **explicit category** reach
  the plan, because today "a category is never guessed from the name"
  (`recon/ingest.py:38-41`) and `TechnologyLinkPlan.category` defaults to
  `"other"`. The two observation dataclasses (`TechnologyObservation`,
  `AssetTechnologyObservation`, defined in `recon/web/httpx_probe.py`) gain an
  optional `category: str = DEFAULT_TECHNOLOGY_CATEGORY` field and the ingest
  branch passes it through to `TechnologyLinkPlan`. This is **additive**: the
  httpx side-effect path constructs observations without a category and therefore
  keeps producing `"other"` unchanged.
- `TechnologyRepository.upsert(name, category)` and
  `AssetTechnologyRepository.upsert(...)` are **NOT** modified — the SQL, conflict
  behaviour, and evidence semantics stay exactly as committed.

Result: a `tech_detect` classification persists through the same two rows and the
same two evidence rows as any other technology observation — there is no second
technology write path to drift out of sync.

## 11. PROJECTION

Phase 21A **reuses** the existing Phase 15 canonical projection
(`database/projection.py`) and creates **no** second projection:

- `build_records` already emits `TechnologyRecord` (name, category, host,
  evidence_id) for every evidenced `technologies` row tied to a projected asset
  (`database/projection.py:354-378`), passing `category` through **verbatim**.
- The expected operator-visible result is that `attack-surface` payload
  `records.by_kind` contains `"technology": N`, and the technology graph nodes
  appear with their category attribute. Today, in every Phase 20A-committed run,
  that count is produced only by the httpx side effect (or is empty); with
  `tech_detect` it is produced deliberately by a task whose *type* itself proves
  the coverage.

No projection, record, graph, or inference semantics change.

## 12. COVERAGE

Coverage machinery is untouched; Phase 21A only makes it able to fire:

- `ai/run_context.py` `TASK_TYPE_COVERS_STAGE` already maps
  `tech_detect → tech_detect` and `whatweb → tech_detect`, and
  `ai/loop.py` `TASK_TYPE_FOR_STAGE` already maps `tech_detect → tech_detect`.
- **Before registration:** the stage is neither covered nor runnable → it appears
  in `uncovered_without_capability()` and Phase 18 persists it to
  `ai_coverage_gaps` (reported, never proposed).
- **After registration** (no AI enablement needed): the served execution exposes
  `tech_detect`/`whatweb` in `known_task_types()`, and since the analysis hook and
  the expansion allowlist are both derived from the **live registry**, the stage
  becomes *executable*: it moves from `uncovered_without_capability` into
  `coverage_gaps()` (uncovered but runnable).
- **On successful completion** of a `tech_detect` (or `whatweb`) task
  (`status == "completed"`): `covered_stages()` includes `tech_detect`, so the
  stage leaves **both** `coverage_gaps` and `uncovered_without_capability`.
- **The distinction is preserved, not collapsed:** `uncovered_without_capability`
  continues to exist for every genuinely un-executable stage (`web_crawl`,
  `content_discover`, `js_analysis`, `api_discover`, ..., `cdn_waf_intel`).
  Phase 21A removes exactly one stage from that list and nothing else.
- **`httpx -tech-detect` still does not count.** The side-effect artifact path is
  untouched; coverage continues to be keyed exclusively to completed task types,
  so the httpx by-product and the `tech_detect` task remain conceptually distinct
  — which is precisely the property §2 states and the implementation must keep.

## 13. TESTING

Tests are for the **implementation phase**; none are written by this pass. The
following are planned, following the `tests/test_dns.py` / `tests/test_httpx.py`
(recorded-fixture) and `tests/test_expansion.py` (pure mapping) patterns:

**A. Fingerprint table**
- deterministic header matching;
- case-insensitivity where appropriate (headers and values);
- multiple technologies from one response;
- deduplication to one pair per `(name, category)`;
- category assignment within the eight-value CHECK set;
- weak/ambiguous signal rejection (WAF/CDN claimed only on explicit signals);
- absence of a signal yields no classification.

**B. Parser / response handling**
- missing headers;
- malformed HTML (title/generator recovery is non-fatal);
- missing `<title>`;
- `generator` meta present;
- bounded response body cap enforced;
- timeout path recorded non-fatally;
- oversized response truncated, never buffered unboundedly.

**C. Adapter**
- task arguments and target parsing (`host[:port]`);
- scope enforcement (out-of-scope host **and** out-of-policy port rejected);
- timeout plumbing;
- registration in the served registry (`tech_detect` and `whatweb` dispatch to
  the adapter; `known_task_types()` contains them);
- refusal of unknown task types stays fail-closed (`UnknownTaskType`);
- the in-process path never invokes a subprocess (no `run_command`, raw output
  preserved via `save_raw`).

**D. Expansion**
- `WebAppObservation → tech_detect host:port`;
- (existing) `PortObservation → http_probe` unaffected;
- dependency ordering (child `parent_task_id` = the completing `http_probe`);
- deduplication (`(type, target)` and run-level fingerprint);
- bounded fan-out (one per web app, global `max_tasks` cap, allowlist-gated so a
  registry without `tech_detect` proposes none).

**E. Ingestion / projection**
- a `tech_detect` observation reaches the existing `technologies` +
  `asset_technologies` rows and the existing two evidence rows;
- category is preserved verbatim through `TechnologyLinkPlan` and stored;
- Phase 15 projection contains `TechnologyRecord` with the stored category;
- `attack_surface` `records.by_kind.technology` is populated.

**F. Coverage**
- after a successfully completed `tech_detect` task, the stage is no longer
  reported uncovered (`coverage_gaps` drops it) **and** no longer reported as
  `uncovered_without_capability`;
- the httpx side-effect path alone still does **not** close the stage;
- the existing `tests/test_phase16.py` assertion that `tech_detect` is *not*
  runnable (`test_the_gate_excludes_every_stage_without_an_adapter`, which
  deliberately lists it among un-registered stages) is updated so the gate's
  covered set includes `tech_detect` — this is a required, intended edit to a
  committed-and-clean test file, exactly as Phase 20A updated the registry gate.

**G. Live verification**
- a sanctioned localhost/controlled fixture following the established precedent
  (`tests/test_served_execution_live.py`, `tests/test_phase17_live.py`: a
  `ThreadingHTTPServer` on `127.0.0.1` with an ephemeral port, program scope
  authorizing `127.0.0.1` only);
- canned responses exercise the WAF/CDN and framework fingerprints end-to-end
  through the real orchestrator, scope guard, rate limiter, ingestion,
  persistence and projection;
- capability-gated exactly like the Phase 20A/P17 live suites
  (`ARGUS_TEST_DATABASE_URL`),
- **no Internet reconnaissance** anywhere: the in-process adapter makes its
  request only over the fixture, and no test touches a public name.

## 14. NON-GOALS

Phase 21A explicitly excludes all of:

- AI/LLM activation (the adaptive loop stays gated on `config.ai.enabled`; nothing
  here turns it on);
- adaptive-loop changes (no edit to `ai/loop.py`, its stage map is already correct);
- TLS/certificate discovery;
- Nmap `-sV` / service-version escalation;
- crawling;
- URL enumeration;
- endpoint discovery;
- JavaScript analysis;
- API / GraphQL / WebSocket discovery;
- parameter discovery;
- vulnerability scanning;
- exploit execution;
- authentication attacks;
- credential attacks;
- brute force;
- DoS;
- WAF bypass / evasion.

## 15. MIGRATION

Expected: **NO MIGRATION.**

`technologies` (with its category CHECK), `asset_technologies`, their indexes, and
their repositories already exist in migration `0001` and are reused unchanged. The
category vocabulary, the association table, the integrity constraints, and the
projection read all support the intended data today.

**If implementation discovers that a migration is genuinely required: STOP AND
REPORT.** Do not silently create one.

## 16. SAFETY

The documented chain is preserved **unchanged and unbypassed**:

```
ScopeGuard
  ↓
RateLimiter
  ↓
ToolAdapter
  ↓
ToolRunner
```

- The orchestrator enforces scope and takes a rate-limit permit before execution;
  the adapter **re-validates** the target (host **and** port) against the run's
  guard before any request.
- **No direct AI → shell → target path.** The in-process adapter issues a single
  bounded stdlib request; there is no shell, no `shell=True`, no argument-string
  construction.
- **No arbitrary URLs:** the only destination is the task's own in-scope target.
- **No arbitrary commands:** nothing from a response, task, or artifact is ever
  executed.
- **No scope expansion:** discovered/redirected destinations (if any) are never
  acted on — redirects are not followed.
- The fingerprint function is pure and receives only the bounded captured
  signals, so a hostile response can influence the *observations* but cannot
  control execution.

## 17. STOP CONDITIONS

Implementation must stop and report if any of the following is encountered:

- existing ingestion cannot safely represent the observation (the additive
  category pass-through proves unrepresentable);
- technology classification requires an unsupported schema (a category outside
  the eight CHECK values becomes unavoidable);
- safe bounded HTTP cannot be enforced (no reliable timeout / response cap);
- scope validation cannot cover host+port for the target shape;
- expansion would create unbounded fan-out (dedup/bounds prove insufficient);
- implementation requires AI activation to close the coverage gap;
- implementation requires a migration;
- Phase 18 working-tree changes would need to be modified (the protected dirty
  files: `ai/loop.py`, `api/server.py`, `dashboard/*`, `database/models/entities.py`,
  `database/repositories/all.py`, the three `reports/*_report.py`,
  `docs/13_TESTING_STRATEGY.md`, `docs/PHASE_17_PROPOSAL.md`, `tests/test_phase17.py`,
  the `0006` migration files, `.byte/`, and the `test_phase18*` live tests);
- `.byte/` must be touched.

## 18. VERIFICATION TARGET

Closure criteria for the implementation phase — the phase is done only when **all**
hold:

- `tech_detect` registered and served (task types `tech_detect`/`whatweb` dispatch
  through `ServedExecution.adapter_for` and appear in `known_task_types()`);
- deterministic technology fingerprinting works (recorded-fixture tests, offline);
- CDN/WAF fingerprints work **for explicit signals** and nothing is claimed on weak
  evidence;
- technology evidence persisted through the existing ingestion path
  (`technologies`, `asset_technologies`, `ENTITY_TECHNOLOGY`,
  `ENTITY_ASSET_TECHNOLOGY`);
- `by_kind.technology` populated via the Phase 15 projection on a live run;
- the `tech_detect` coverage gap closes after successful execution (it leaves both
  `coverage_gaps` and `uncovered_without_capability`);
- no new migration;
- no AI activation;
- no safety boundary changes (the §16 chain is byte-for-byte the committed one);
- existing regression suite remains intact (817 passed, the same 6 pre-existing
  Phase 18 failures, plus the new `tech_detect` tests);
- `git diff --check` clean;
- no protected Phase 18 working-tree file or `.byte/` touched;
- nothing staged, committed, or pushed by the phase.

## Guardrails of this pass

This pass is **documentation only**. It does not modify:

- source code
- migrations
- tests
- Phase 18 files
- Phase 20A files
- `.byte/`
- PostgreSQL
- remotes

It does not stage or commit. The only change produced is the creation of
`docs/PHASE_21A_PROPOSAL.md`.