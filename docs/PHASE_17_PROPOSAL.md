# ARGUS — Phase 17: Run-Scoped AI Observability

## 1. Current-state diagnosis

Phase 16 made the intelligence layer reachable and durable. It did not make it *visible*.

Four concrete gaps, each verified in the code before this phase:

1. **`ai_analysis` had no `run_id`.** The table was created by migration `0001` with
   `agent_name`/`model_used`/`input_context_ref`/`output`/`created_at` only. Phase 16 wrote run
   attribution into the `input_context_ref` *string* (`"run:<uuid>"`, formatted by
   `ai.loop.context_ref`), so attributing a row to a run meant matching a text prefix. That is a
   second, divergent notion of run membership sitting next to the Phase 15 evidence chain
   (`evidence → tool_runs → tasks → runs`), and it is not queryable through a foreign key or an index.

2. **The rows were a write-only audit trail.** `Repositories.list_ai_analysis()` existed but was
   unfiltered, unindexed-by-run, and called only from tests. No route, no report, and no dashboard
   view could read them. An operator asking "did the AI run for this run?" had no supported way to
   find out; the only evidence was the side effect of `hypotheses` rows appearing.

3. **Production composition was never proven to work.** `api.serve.create_serve_app` has passed
   `analysis=...` to the `Orchestrator` since Phase 16, but no test built the real served app over
   real PostgreSQL and asserted a functional hook. Removing `analysis=...` from that call would
   have disabled the intelligence layer in production with the entire existing suite still green.

4. **A silent no-op looked exactly like a clean pass.** `AnalysisHook.__call__` returned `[]` in
   four different situations — storage without an `attack_surface` read, context construction
   failure, agent failure, and genuinely nothing to propose — and all four looked identical from
   outside. Only the last is a statement about the target.

Additionally, `max_loop_passes` was a hardcoded `Orchestrator` dataclass default of `32`, so an
operator had no way to tighten or relax the adaptive loop's budget short of editing Python.

## 2. Scope

### 2.1 In scope

| Area | Change |
|---|---|
| Schema | Migration `0005`: `ai_analysis.run_id uuid REFERENCES runs(id)`, `ai_analysis_run_id_idx`, `ai_analysis_run_id_required_check` |
| Backfill | Attribute legacy rows from a canonical `run:<uuid>` reference **that resolves to a real run**; leave everything else `NULL` |
| Repository | `AiAnalysisRepository.list_for_run(run_id)`; `Repositories.list_ai_analysis(run_id=None)` |
| API | `GET /api/v1/runs/{run_id}/ai-analysis` on the single existing Bearer auth |
| Diagnostics | Coarse, non-sensitive `status` on `AnalysisResult`, surfaced through the route and the dashboard |
| Reports | `ai_analysis` section in JSON, Markdown and HTML |
| Dashboard | Read-only AI analysis panel for the selected run |
| Config | `ai.max_loop_passes` (default `32`), validated, passed to `Orchestrator` |
| Tests | `tests/test_phase17.py` (45 gates, no DSN), `tests/test_phase17_live.py` (30 gates, PostgreSQL) |

### 2.2 Explicitly out of scope — and why

- **Real LLM provider backends.** Deferred again. Phase 17 makes no model call; `model_used` is
  reported verbatim and names the rule-based router. Wiring a provider is a supply-chain and
  data-handling decision, not an observability one.
- **New recon/discovery tools and `subfinder` wiring.** Unrelated to whether an operator can see
  what the intelligence layer already did.
- **Task provenance, loop/state-machine redesign, Scope Guard / Rate Limiter / Tool Runner
  changes.** The safety chain `AI → Task Planner → Scope Guard → Rate Limiter → Tool Adapter →
  Tool Runner → Target` is unchanged. `max_loop_passes` was already the limit; only its source
  moved from a Python literal to configuration.
- **CLI changes, dashboard redesign, unrelated cleanup.**
- **Promoting analysis records into findings.** An `ai_analysis` row is what the intelligence layer
  did; only an operator approving a `hypotheses` row writes `VALIDATED_FINDING`. Nothing here
  changes that.

## 3. Architecture

### 3.0 Why `run_id` is nullable with a NOT VALID check

The obvious migration — `ADD COLUMN run_id uuid NOT NULL REFERENCES runs(id)` — fails on any
populated database. Phase 16 was already deployed against real tables, and rows whose
`input_context_ref` is malformed or names a run that no longer exists have no honest run to be
given. Guessing one would put another run's name on a record, which is exactly the failure mode
this phase exists to remove.

So: nullable column, plus `CHECK (run_id IS NOT NULL) NOT VALID`. PostgreSQL applies a `NOT VALID`
check to every row written from that point on while exempting pre-existing rows. Every Phase 17
write is therefore run-scoped, enforced by the database, and legacy rows are neither rewritten nor
fabricated. A fresh install has no legacy rows, the constraint validates immediately, and the end
state is a fully enforced schema.

The backfill requires **both** conditions: the reference matches `^run:<canonical-uuid>$`, and that
uuid exists in `runs`. The regex is load-bearing, not cosmetic — PostgreSQL has no `try_cast`, so a
malformed value reaching `::uuid` would abort the entire migration and roll back the upgrade.

A row that fails either test keeps `run_id IS NULL`, stays invisible to every run-scoped read (all
of which are `WHERE run_id = %s`), and the constraint remains `NOT VALID` — which is the honest
state, rather than a validated constraint claiming something untrue about the data.

### 3.1 `input_context_ref` is kept, and demoted

`input_context_ref` is **not** dropped. It names the context an agent was given, which a run id
alone does not carry, and it is what the `0005` backfill attributes legacy rows from. After `0005`
it is a context label; `run_id` is the run filter. Both are written, and the live tests assert
both.

### 3.2 Why the route reports diagnostics

Without diagnostics, an empty `ai_analysis` list has three indistinguishable causes: AI disabled,
AI enabled but unwired, or AI ran and genuinely had nothing to propose. Only the third is a
statement about the target, and conflating them is how a broken deployment reads as a quiet target.

The route therefore returns a `diagnostics` block drawn from a **bounded** vocabulary:
`disabled`, `unwired`, `no_pass_yet`, and the five `ai.loop.ANALYSIS_STATUSES`
(`capability_unavailable`, `context_failed`, `no_proposals`, `proposed`, `pass_failed`). No
diagnostic carries exception text, a path, a DSN or a key — the detail stays in the process log,
and a test asserts that a poisoned `error` string cannot reach the response.

`disabled` and `unwired` are not in `ANALYSIS_STATUSES` because no hook exists in either case and a
hook therefore cannot report on itself; those two come from `app.state`.

### 3.3 Why `build_report` omits the key rather than emitting an empty list

A missing `ai_analysis` key means "this report was built by a caller with no analysis store".
An explicit empty list means "the run was analysed and no proposal was persisted". Those are
different claims, and only the second is worth showing. The same convention `attack_surface`
already uses, and every pre-existing caller keeps its exact previous output.

## 4. Requirements

Honoured:

- one existing authentication mechanism, no new auth surface;
- run-scoped reads only, never the unfiltered `list_ai_analysis()` from an operator-reachable path;
- `None`/no-op invocations still persist no row;
- per-agent transaction atomicity and independent committed results unchanged;
- human-only `VALIDATED_FINDING` promotion unchanged;
- no provider or network call introduced anywhere in this phase;
- deterministic, single-entity run scoped by id rather than a text prefix;
- no domain model changes, only a nullable FK column and an index;
- three reports, no CLI, no unrelated features.

## 5. Implemented behavior

### 5.1 Final architecture

```text
Orchestrator._run_analysis_pass                    (existing, unchanged)
        │  analysis(run, tasks) -> list[Task]
        ▼
ai/loop.py :: AnalysisHook                          (MODIFIED — attribution + diagnostics)
        │  AiAnalysis(run_id=<real run id>, ...)    ← new: real FK, not a text prefix
        │  AnalysisResult.status                    ← new: coarse, non-sensitive outcome
        ▼
database/repositories/all.py :: AiAnalysisRepository.list_for_run(run_id)
        │  WHERE run_id = %s                        ← indexed, never a LIKE
        ▼
api/server.py :: GET /runs/{run_id}/ai-analysis    (NEW — Bearer auth, run-scoped)
reports/{json,markdown,html}_report.py             (MODIFIED — ai_analysis section)
dashboard/app.js                                    (MODIFIED — read-only panel)

api/serve.py :: create_serve_app(...)
        │  max_loop_passes=effective_config.ai.max_loop_passes   ← was a dataclass literal
        │  analysis=AnalysisHook(...) when config.ai.enabled
        ▼
app.state.argus_analysis_hook / argus_analysis_wired             ← diagnostics source
```

### 5.2 Files changed

| File | Change |
|---|---|
| `database/migrations/0005_ai_analysis_run_scope.sql` | **NEW** — nullable FK, `NOT VALID` check, index, conservative backfill, conditional validate |
| `database/migrations/0005_ai_analysis_run_scope.down.sql` | **NEW** — revert |
| `database/models/entities.py` | **MODIFIED** — `AiAnalysis.run_id` |
| `database/repositories/all.py` | **MODIFIED** — `list_for_run`, `insert`, `list_ai_analysis(run_id=None)` |
| `ai/loop.py` | **MODIFIED** — `run_id` on the record, `AnalysisResult.status`/`error`/`ran`, `ANALYSIS_STATUSES`, logging on every silent path |
| `core/config.py` | **MODIFIED** — `AiConfig.max_loop_passes` (default `32`), validation, `to_dict()` |
| `api/serve.py` | **MODIFIED** — pass `max_loop_passes`, expose `argus_analysis_hook`/`argus_analysis_wired` |
| `api/server.py` | **MODIFIED/NEW** — `_ai_analysis_payload`, `_analysis_diagnostics`, the route, report wiring |
| `reports/json_report.py` | **MODIFIED** — optional `ai_analysis` section, deterministic ordering |
| `reports/markdown_report.py` | **MODIFIED** — `# AI Analysis` section |
| `reports/html_report.py` | **MODIFIED** — escaped `<section id="ai_analysis">` |
| `dashboard/index.html`, `dashboard/app.js` | **MODIFIED** — read-only panel, no new control |
| `tests/test_database.py` | **MODIFIED** — `DOC_COLUMNS["ai_analysis"]` includes `run_id` |
| `tests/test_phase17.py` | **NEW** — 45 gates, no DSN |
| `tests/test_phase17_live.py` | **NEW** — 30 gates over real PostgreSQL |

### 5.3 Fail-closed boundary

Unchanged from Phase 16: the entire pass — context construction, projection reads, agent
invocation, `ai_analysis` persistence, `hypotheses` persistence — stays inside one guard. Any
exception returns `[]` and writes nothing. Phase 17 adds status recording and log lines to the
existing early returns; it does not widen the boundary. `_persist` still fails closed per agent,
so one rejected row never affects another agent's committed result.

## 6. Test classification

| Class | Coverage |
|---|---|
| `UNIT` | `AnalysisResult` status vocabulary; `AiAnalysis.run_id` default; `ai.max_loop_passes` default / custom / invalid / non-integral; report section presence, absence, ordering, HTML escaping, Markdown line-flattening; payload projection honesty |
| `SECURITY` | Route requires auth and rejects a wrong key; unknown run is `404`; a poisoned `error` string never reaches a client; HTML escapes proposal content; a multi-line proposal cannot break the Markdown list; no provider or network call introduced |
| `NEGATIVE` | A row with no run is never attributed; a run with no analysis returns nothing rather than everything; an absent analysis read omits the section instead of claiming emptiness; a storage predating Phase 16 degrades to an empty list; unattributable legacy rows stay `NULL`; the FK rejects an orphan `run_id`; the check rejects a new `NULL` write |
| `DATA-MODEL` | Migration column / FK / index; fresh install fully validated; upgrade from a populated legacy table via the real revert; down-revert and re-apply; every legacy row survives |
| `COMPOSITION` | `create_serve_app` over real PostgreSQL with a real served run, real DNS resolution, real HTTP probe, real ingestion, real projection, real hook, real rows — and an assertion on `app.state.argus_orchestrator.analysis` that fails if `analysis=...` is removed |
| `ISOLATION` | Two runs' analysis never mix in the repository, the route, or the reports; a second served run sees none of the first's rows |
| `REGRESSION` | Full existing suite, unchanged expectations; every pre-existing `build_report` caller keeps its exact previous shape |

## 7. Known environment limitations

**ENVIRONMENT-UNVERIFIED (stated, not hidden)**

- **The `httpx` binary is not installed on this machine**, so the default `HttpxProbeAdapter`
  cannot run. The live composition test's web-app artifact comes from a real `ToolAdapter` that
  performs a genuine HTTP request through the real `ToolRunner` subprocess boundary and parses the
  genuine response. The `httpx` *binary* path remains unverified, exactly as in Phase 14.
- **dnspython never consults the Windows hosts file**, so DNS in the composition test goes through
  the adapter's documented `resolver_fn` seam backed by `socket.getaddrinfo`. The resolution is a
  real local resolver call, not a fixture or a fabricated answer.

Both are the same limitations Phase 14 documented, restated here because they bear on the
composition proof.

## 8. Test results

| Tier | Result |
|---|---|
| `tests/test_phase17.py` | **45 passed** |
| `tests/test_phase17_live.py` | **30 passed** against real PostgreSQL 17 |
| `tests/test_database_live.py` | **52 passed** against real PostgreSQL 17 |
| Full suite, live DSN set | **766 passed**, 2 warnings, 166.66s |
| Full suite, no DSN | **600 passed, 166 skipped**, 2 warnings |
| `compileall` on every changed module | clean |
| `node --check dashboard/app.js` | clean |

The 166 skipped tests without a DSN are exactly the 166 that pass with one: no test is skipped for
any reason other than the absent `ARGUS_TEST_DATABASE_URL`.

## 9. Non-goals

No LLM provider. No new recon capability. No task provenance. No loop or state-machine redesign. No
Scope Guard, Rate Limiter or Tool Runner change. No CLI. No dashboard redesign. No finding
promotion. No rewriting of legacy rows.

## 10. Stop conditions

- A migration that would require rewriting or discarding legacy `ai_analysis` rows.
- Any change to the `VALIDATED_FINDING` promotion path.
- Any new authentication mechanism.
- Any new outbound network call.
- A report or route that could show one run's analysis under another run.

None was hit.

## 11. Audit status

See `docs/PHASE_17_PROPOSAL.md` §12 for the final classified findings and the exact verification
record, including any tier that could not be executed in this environment.

## 12. Final verification record

### 12.1 Live PostgreSQL tier — executed

Verified against a real PostgreSQL **17.11** cluster, schema migrated through `0005`:

```
ARGUS_TEST_DATABASE_URL=postgresql://argus@127.0.0.1:5433/argus_test
tests/test_phase17_live.py tests/test_database_live.py   82 passed, 2 warnings, 43.23s
full suite (DSN set)                                     766 passed, 2 warnings, 166.66s
```

Every `0005` claim is proved on real rows, not asserted in Python: the FK to `runs`, the index over
`run_id`, upgrade of a **populated** pre-0005 table through the genuine
`0005_ai_analysis_run_scope.down.sql`, canonical-`run:<uuid>`-only attribution, `NOT VALID`
preserved while unattributable legacy rows exist, the check still rejecting a new write without a
run, revert-then-reapply, and run isolation across two runs over real rows.

### 12.2 How the live tier was reached

No password was used or needed. Per `docs/PHASE_14_PROPOSAL.md` §11.5 the password for the
production cluster is deliberately not stored on this machine, so live verification uses a
**throwaway copy** of the cluster on port **5433** with loopback-only `trust`, exactly as Phase 14
did. Two clusters are in play and they must not be confused:

| Cluster | Port | Roles | Auth |
|---|---|---|---|
| Production service (`postgresql-x64-17`) | 5432 | no `argus` role | `scram-sha-256` throughout |
| Temporary verification copy | 5433 | `argus` (`initdb -U argus`) | `trust` on loopback |

The copy's `pg_hba.conf` is the only one that has ever granted `trust`. The production
`pg_hba.conf` was read to confirm it remains `scram-sha-256` on every line, and the production
postmaster was never stopped, reloaded, or reconfigured.

The sanctioned, canonical description of this fixture — location, role, database, how to start and
stop it — is `13_TESTING_STRATEGY.md` §PostgreSQL Live-Test Fixture. This section records what Phase
17 specifically observed; that section is what a contributor should read.

### 12.3 Behaviour worth knowing: analysis is one pass behind ingestion

The served loop's analysis pass reads the projection **before** the pass's own task ingestion
commits. A `/run` whose only task creates the run's first data therefore analyses an empty surface
and honestly reports `ANALYSIS_NO_PROPOSALS`; the proposal appears on the following pass. Measured
on the served composition:

```
after /run            : no_proposals   (outcomes=0)
next pass, same run   : proposed       (dns_resolve -> "localhost")
rows persisted        : recon_agent, hypothesis_agent
```

This is **not** a defect and no code was changed for it: at the first pass there is genuinely
nothing to analyse, and declining is the fail-closed behaviour Phase 16 established. It is recorded
here because an operator reading `ANALYSIS_NO_PROPOSALS` off a fresh run needs to know it is
expected, not a misconfiguration. `tests/test_phase17_live.py::_drive_analysis` drives the deferred
pass explicitly so the acceptance proof exercises a pass that has rows to attribute.

### 12.4 Classified findings

- **BLOCKER** — none.
- **HIGH** — none.
- **MEDIUM** — none.
- **LOW** — none.
- **INFO** — Three documentation defects in *earlier* phases, corrected or noted here rather than
  silently inherited:
  1. `docs/PHASE_16_PROPOSAL.md` §11.5 states role `argus` with `trust` auth. True of the temporary
     copy, false of the production cluster, which has no `argus` role and is all-SCRAM. The two
     clusters' role sets are documented together in §12.2 above and the Phase 16 line now says
     which cluster it means.
  2. `docs/PHASE_14_PROPOSAL.md` §11.5 and `docs/PHASE_16_PROPOSAL.md` §11.5 describe **different
     clusters** (production vs. temporary copy) while reading as one continuous account. This is
     what makes the role name ambiguous across the two documents.
  3. `tests/test_database_live.py` hardcoded the migration set as `[1, 2, 3, 4]`. Adding `0005`
     correctly broke five pre-existing Phase 16 tests; they now assert `[1, 2, 3, 4, 5]` and the
     matching revert sequences. Expected test maintenance, not a regression.

### 12.5 Security posture

Secret scan over the staged diff finds no literal DSN, password, or key. The only credential-shaped
strings in the Phase 17 tests are the local constants `API_KEY = "phase17-key"` and the loopback
`postgresql://argus@127.0.0.1:5433/argus_test` DSN used to *drive* verification, never asserted
into a tracked file. No authentication mechanism changed; the API route reuses the existing
`_authed` dependency and remains fail-closed. `.byte/` remains untracked and unmodified.
