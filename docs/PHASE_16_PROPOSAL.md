# ARGUS — Phase 16 Context: Wiring the AI Layer

> **Persistent project context, not an architectural authority.**
> This document records the approved Phase 16 plan and, after implementation, the actual
> behavior. It never overrides `OPENCODE.md`, `01_PRODUCT_SPEC.md`, `04_SCOPE_SAFETY.md`,
> `05_DATA_MODEL.md`, `06_TOOL_CONTRACTS.md`, `07_AI_AGENTS.md`, or `08_ORCHESTRATOR.md`. Where
> this file and an authoritative document appear to disagree, the authoritative document wins
> and the conflict must be reported — see `OPENCODE.md` Rule 1 for the precedence chain.

**Status:** approved, pre-implementation
**Phase 16 objective:** make the intelligence layer reachable from a real run — build agent
context from persisted facts, run the agents, persist their proposals, and run the adaptive
loop in production.
**Phase 15 baseline commit:** `77a2de35c47470dbe12657f72998270aeee1ecb3`
**Phase 15 status:** VERIFIED (final forensic audit, no BLOCKER/HIGH findings)

---

## 1. Current-state diagnosis

Phase 15 made persisted facts readable and graph-projected. The `ai/` package (~1,010 lines)
is fully unit-tested — router, validator, contract shapers, context records, seven agents — and
**entirely unreachable from a real run**. Confirmed by import analysis:

- Zero production importers of `ai/`. Only `tests/test_ai_agents.py`, `tests/test_ai_router.py`,
  and `tests/test_smoke.py` import it.
- `api/serve.py:459` constructs `Orchestrator(storage=..., run_tool=..., rate_limiter=...,
  ingest=...)` with **no `analysis=` argument**, so `Orchestrator._run_analysis_pass` is never
  reached. `Orchestrator._next_pass` therefore takes the "no new work" branch and every run goes
  straight to `COMPLETED`. The adaptive loop documented in `01_PRODUCT_SPEC.md` §10 and
  `08_ORCHESTRATOR.md` does not run in production.
- Nothing in production ever writes an `ai_analysis` row. The table exists in migration 0001
  (`agent_name`, `model_used`, `input_context_ref`, `output jsonb`, `created_at`) but has **no
  entity dataclass in `database/models/entities.py` and no repository**. It is unreachable.
- Nothing in production ever writes a `hypotheses` row either. `Orchestrator.add_hypothesis`
  exists (`core/orchestrator.py:448`) but no API route calls it, so the dashboard's
  approve/reject workflow and the report's `hypotheses` / `validated_findings` sections have
  nothing to review in a real run.

The loop machinery itself is **not** the gap and must not be rewritten. `Orchestrator._run_analysis_pass`
(305–325) already calls the hook, dedupes by fingerprint, and persists pass progress through
migration 0004. `tests/test_execution_semantics.py` and `tests/test_database_live.py` already
exercise it — but only with **test-authored** `analysis` closures. The production hook does not
exist.

### 1.1 The agents do not call a model either

This is the finding that sets Phase 16's scope. `ai/recon_agent.py:45` calls
`route(ROUTE_TASK, ...)` and **discards the returned `RoutingDecision`**; the proposal that
follows comes from a fixed `STAGE_PRIORITY` table. `ai/local_model.py` and
`ai/cloud_model.py` expose only `simulate()` — deterministic canned dicts, no HTTP, no
provider client, no prompt construction.

So `ai/` today is a **contract library**: a deterministic router, a strict output validator,
and seven rule-based agents that cite caller-supplied evidence. Nothing infers anything, and
nothing is called.

## 2. Scope

### 2.1 In scope

- An `AiAnalysis` entity and repository for the existing, already-migrated `ai_analysis` table.
  No migration: the table is already there and already indexed.
- A context builder that turns one run's persisted, run-scoped facts — read through the Phase 15
  projection — into `ai/context.py` records, so every agent claim can cite a real `evidence_id`.
- An `AnalysisHook` implementation that builds context, invokes the agents, persists each
  proposal to `ai_analysis`, persists hypothesis-class proposals to `hypotheses`, and returns
  `Task`s for `type="task"` proposals.
- `AiConfig.enabled` (default **false**) and wiring in `create_serve_app` that passes
  `analysis=` only when enabled, so every existing test and default deployment is unchanged.
- A **capability gate**: the hook may only propose a task type that a registered adapter can
  actually execute, so the loop can never enqueue work that fails at execution.

### 2.2 Explicitly out of scope — and why

**Real LLM backends (Ollama, OpenAI, Anthropic) are deferred to Phase 17, not this phase.**
This is a deliberate scope decision, recorded here rather than silently taken:

1. **Nothing calls the agents.** Adding a provider to code that is never invoked builds the
   wrong end first. Phase 16 makes the agents reachable and their output durable; a backend in
   Phase 17 slots into the existing `RoutingDecision` seam without re-plumbing anything.
2. **No provider is reachable from this environment.** There is no model binary, no provider
   SDK, and no API credential here — the same situation as `httpx` and `subfinder`, which are
   recorded as ENVIRONMENT-UNVERIFIED rather than claimed. A backend added now could not be
   verified end-to-end and could not honestly be called done.
3. **A live LLM breaks determinism.** Phase 15 guarantees byte-identical repeat projections, and
   the reports are documented as deterministic by construction. Non-deterministic agent output
   inside the analysis pass would make the loop's contribution to a report unreproducible,
   without any way to assert what a correct pass should have produced.
4. **It would change already-tested semantics.** The seven agents are rule-based and
   contract-tested (`13_TESTING_STRATEGY.md` AI Contract suite). Making them LLM-backed is a
   semantic change to verified code, not an additive wiring step, and belongs in its own phase
   with its own acceptance criteria.

Also out of scope: new recon adapters; schema migration; CLI; dashboard changes; scope, rate
limit, tool runner, or orchestrator state-machine changes; any change to `correlation/**` or the
Phase 15 projection.

## 3. Architecture

```text
Orchestrator._run_analysis_pass        (existing, unchanged)
        │  analysis(run, tasks) -> list[Task]
        ▼
ai/loop.py :: build_analysis_hook()    (NEW)
        │
        ├─ context: Repositories.attack_surface(run_id)        (Phase 15, read-only)
        │     → ai/context.py records, every one carrying a real evidence_id
        │
        ├─ agents: ai.recon_agent.run(ReconContext)            (existing, unchanged)
        │     each proposal re-validated by ai/validator.py    (existing, unchanged)
        │
        ├─ persistence (one transaction PER AGENT INVOCATION):
        │     INSERT ai_analysis  (agent_name, model_used, input_context_ref, output)
        │     INSERT hypotheses  (run_id, statement, truth_label, confidence,
        │                         severity, priority, status='open', target,
        │                         validation_step, review_status='pending')
        │
        └─ tasks: type="task" proposals → Task(type=<capability-gated>, target=…)
                  anything without a registered adapter is refused, never enqueued
```

### 3.0 What `ai_analysis` means

`ai_analysis` represents **persisted AI analysis/proposals, not exhaustive invocation
telemetry.**

An `ai_analysis` row is persisted for each agent invocation **that produces a proposal**.
A no-op invocation that returns `None` produces **no** `ai_analysis` row. Each proposal's
persistence is atomic to its individual agent invocation: if an agent fails after beginning
persistence, its own analysis row is rolled back without affecting previously committed analysis
results.

```text
Agent invocation
    │
    +-- proposal produced --> persist ai_analysis row
    │
    +-- None / no-op -------> no ai_analysis row
    │
    +-- failure ------------> that invocation's transaction rolls back
```

Concretely, with a `recon_agent` task proposal and a `hypothesis_agent` proposal where the
hypothesis write fails:

```text
recon_agent      → ai_analysis row COMMITTED
hypothesis_agent → ai_analysis row ROLLED BACK, hypotheses row absent
```

This is deliberate. A no-op write would inflate `ai_analysis` with rows that record nothing, and
a telemetry table would invite readers to treat invocation counts as meaningful. The table's job
is to hold what the intelligence layer actually proposed, with the evidence it cited.

### 3.1 Capability gate (why the loop cannot enqueue doomed work)

`api/serve.py` refuses a task whose type has no adapter — `NoAdapterError` is raised *before* an
adapter is constructed. Only `dns_resolve`/`dns`/`resolve` and the http-probe types are
registered. `recon_agent.STAGE_PRIORITY` names 17 stages, most of which have **no adapter**.

So the hook must derive the proposable set from the actual adapter table, not from
`STAGE_PRIORITY`. A stage with no adapter is a coverage gap the hook reports as a gap and does
**not** propose. This is why Phase 16 cannot simply forward `recon_agent`'s output: without the
gate the first analysis pass on any run would enqueue a task that immediately fails.

### 3.2 Evidence and truth labels are structural, not advisory

- Every agent proposal already carries at least one `evidence` item whose `source` is an
  `evidence_id` present in the run's own context, enforced by `ai/contract.py` at construction
  and re-enforced by `ai/validator.py`. Phase 16 adds no way to bypass this.
- A proposal is persisted with the truth label the agent emitted. Only
  `Orchestrator.approve_hypothesis` may set `VALIDATED_FINDING`; the hook runs before any
  operator review, so everything it writes is `HYPOTHESIS` / `UNVERIFIED_CLAIM` / `INFERENCE`
  with `review_status='pending'`. The hook has no code path that writes `VALIDATED_FINDING`.
- `hypotheses` has no `evidence_id` column, so the cited evidence ids are preserved in the
  `ai_analysis.output` jsonb — the same object the report's evidence chain reads. This is a
  schema limitation to record, not to migrate around in this phase.

## 4. Requirements

**Opt-in** — `ai.enabled` defaults to **false**. With it off, `create_serve_app` passes no
`analysis=` hook and behavior is byte-identical to Phase 15. The loop cannot be turned on by
accident or by a config default.

**Read-only context** — the hook reads through the Phase 15 projection and never writes during
context building. It reuses `Repositories.attack_surface`, so run scoping, endpoint containment,
and evidence provenance are exactly the ones Phase 15 verified.

**Durable and atomic** — an agent's `ai_analysis` row and any `hypotheses` row it produces are
written in one transaction, using the existing `Repositories.transaction()` context manager
Phase 14 established. A failed write must not leave a hypothesis with no analysis record.

**Deterministic** — the same persisted run and the same task list produce the same proposals,
the same persisted rows, and the same proposed tasks. This is a property of the rule-based
agents, and it is the main reason Phase 16 is verifiable at all.

**Bounded** — the loop's existing `max_loop_passes` budget (persisted via migration 0004) is the
instability limit. Phase 16 adds no new unbounded recursion and no new loop counter.

**Fail-closed** — if context cannot be built, or an agent raises, or a proposal fails
re-validation, the pass proposes nothing and the run continues to `COMPLETED`. A broken
intelligence layer degrades to the Phase 15 behavior; it never crashes a run and never enqueues
work it cannot justify.

## 5. Implementation stages

- **16.1 Persistence** — `AiAnalysis` entity + repository + facade method. INTEGRATION + LIVE.
- **16.2 Context** — build `ai/context.py` records from the Phase 15 projection. UNIT + LIVE.
- **16.3 Hook** — proposal persistence, hypothesis persistence, proposal → `Task` translation
  behind the capability gate. INTEGRATION.
- **16.4 Wiring** — `AiConfig.enabled`, `create_serve_app` composition, snapshot round-trip.
  REGRESSION (Phase 15 must stay green with the flag off).
- **16.5 Acceptance** — live loop against real PostgreSQL: `ai_analysis` and `hypotheses` rows
  exist, are run-scoped, deterministic across repeats, and no `VALIDATED_FINDING` is ever
  written.

## 6. Non-goals

No LLM provider integration (Phase 17). No new recon adapters. No schema migration. No change to
`correlation/**`, the Phase 15 projection, `ai/router.py`, `ai/validator.py`, `ai/contract.py`, or
any existing agent's reasoning. No CLI. No dashboard change. No change to
`Orchestrator._run_analysis_pass`, `_next_pass`, `plan`, or the state machine. No scope, rate
limit, or tool runner change. `.byte/` untouched.

## 7. Stop conditions

STOP and report rather than improvise if: a schema migration appears necessary to persist agent
output; an agent cannot cite real evidence from a real run; the capability gate cannot be derived
from the adapter table; wiring `analysis=` would change behavior with `ai.enabled` false; or the
loop cannot be made deterministic. _Recorded outcome in §11._

## 8. Known environment limitations

Carried forward and not to be reported as passing acceptance claims:

- `httpx` v1.12.0 loopback behaviour — ENVIRONMENT-UNVERIFIED (binary not installed)
- `subfinder` public-domain enumeration — ENVIRONMENT-UNVERIFIED (binary not installed)
- local PostgreSQL runs with `ssl = off`
- No LLM provider is reachable from this environment, which is why §2.2 defers backends

No public or external targets are used in any test.

## 9. Acceptance criteria

1. With `ai.enabled=false` (the default), the served app behaves identically to Phase 15 and the
   full Phase 15 suite stays green.
2. With `ai.enabled=true`, a run whose first analysis pass has run-scoped facts produces at
   least one `ai_analysis` row, asserted by direct SQL against live PostgreSQL.
3. A `hypothesis`-class proposal produces a `hypotheses` row carrying the agent's statement,
   truth label, confidence, priority, target, and validation step, with `status='open'` and
   `review_status='pending'`.
4. No code path in the hook writes `VALIDATED_FINDING`; an assertion over the hook's persisted
   rows confirms it, and the report renders them under `hypotheses`, never `validated_findings`.
5. The capability gate prevents enqueuing any task type without a registered adapter: a run with
   the AI layer enabled completes rather than failing with `NoAdapterError`.
6. Every persisted `ai_analysis.output` validates against `ai/validator.py`.
7. Two identical passes over unchanged facts produce identical rows (determinism).
8. An agent that raises, or a proposal that fails validation, produces no tasks and no partial
   writes (fail-closed).
9. `ai_analysis` and `hypotheses` rows are scoped to the run that produced them.
10. No BLOCKER/HIGH finding remains open and all Phase 15 guarantees re-verify green.

## 10. Test classification

`UNIT` · `INTEGRATION` (fixtures, `MemoryStorage`) · `LIVE` (real PostgreSQL, served app, gated
on `ARGUS_TEST_DATABASE_URL`) · `SECURITY/NEGATIVE` (fail-closed, no-self-validation,
no-out-of-scope proposal) · `REGRESSION` (Phase 15 gates with the flag off) ·
`ENVIRONMENT-UNVERIFIED`. No test is weakened and no skip is added to obtain a green result.

## 11. Implemented behavior

Status: **implemented and verified** against real PostgreSQL 17.11.

### 11.1 Final architecture

```text
Orchestrator._run_analysis_pass                    (existing, unchanged)
        │  analysis(run, tasks) -> list[Task]
        ▼
api/serve.py :: create_serve_app()                 (MODIFIED)
        │  analysis=None unless config.ai.enabled  (default False)
        │  executable = execution.known_task_types()  ← the live adapter registry
        ▼
ai/loop.py :: AnalysisHook                          (NEW)
        │
        ├─ storage.attack_surface(run_id)           (Phase 15 projection, read-only)
        ├─ ai/run_context.py                        (NEW) projection → agent context
        ├─ ai.recon_agent.run / ai.hypothesis_agent.run   (existing, unmodified)
        ├─ ai/validator.py re-validation            (existing, unmodified)
        ├─ persistence, one transaction per agent invocation (see §3.0)
        └─ capability-gated Task proposals
```

The capability set is read from the same `ServedExecution` registry the server dispatches
through, so the gate cannot drift from what the server can actually run. The unit and live
suites both assert `hook.runnable == frozenset(execution.known_task_types())`.

### 11.2 Files changed

| File | Change |
| --- | --- |
| `ai/loop.py` | **NEW** — `AnalysisHook`, `build_analysis_hook`, per-invocation atomic persistence, capability gate, fail-closed pass |
| `ai/run_context.py` | **NEW** — `scope_ref`, `observations`, `assets`, `coverage_gaps`, `uncovered_without_capability` |
| `core/config.py` | **MODIFIED** — `AiConfig.enabled` (default `False`) + snapshot round-trip |
| `api/serve.py` | **MODIFIED** — wire `analysis=` from `execution.known_task_types()` when enabled |
| `database/models/entities.py` | **MODIFIED** — `AiAnalysis` entity |
| `database/repositories/all.py` | **MODIFIED** — `AiAnalysisRepository`, `insert_ai_analysis`, `list_ai_analysis` |
| `tests/test_phase16.py` | **NEW** — 54 unit/integration gates, no DSN |
| `tests/test_phase16_live.py` | **NEW** — 20 live gates over real PostgreSQL |

No schema migration. `ai_analysis` already existed in migration 0001; Phase 16 only added the
Python side. `hypotheses` gained no columns.

### 11.3 Fail-closed boundary

`AnalysisHook.__call__` wraps the **entire** pass — context construction, graph/projection
reading, agent invocation, `ai_analysis` persistence, and `hypotheses` persistence — in one
guard. Any exception returns `[]` and records the reason on `last_result`. Nothing escapes into
`Orchestrator._run_analysis_pass`.

### 11.4 Test results

| Tier | Result |
| --- | --- |
| Phase 16 unit (`tests/test_phase16.py`) | **54 passed** |
| Phase 16 live (`tests/test_phase16_live.py`) | **20 passed** |
| Full PostgreSQL-backed suite | **691 passed**, 2 warnings |
| Full no-DSN suite | **555 passed, 136 skipped**, 2 warnings |
| `compileall ai database core api tests` | clean |
| `git diff --check` | clean |

PostgreSQL: existing ARGUS test cluster, PostgreSQL 17.11, role `argus`, database `argus_test`,
`trust` auth on `127.0.0.1` as originally provisioned. No authentication change was made.

### 11.5 Defects found and fixed during implementation

1. **`UUID(int=0)` for every generated row.** The first draft passed a fixed all-zero UUID as
   the `id` of each `ai_analysis`, `hypotheses`, and proposed `Task` entity. Because the
   repositories insert the supplied id, the second row of any kind would collide on the primary
   key, and `Task.id` is used as a dict key for parent edges in the planner. Fixed by letting the
   dataclass `default_factory` generate ids.
2. **Hypothesis cap checked after the write.** `max_hypotheses_per_pass` was evaluated *after*
   `_persist`, so the cap throttled a counter but never a write. Fixed to decide before writing.
3. **Task translation misread the proposal.** The first draft derived a recon stage from
   `proposal["target"]`, but `ai.recon_agent` writes the scope root to `target` and names the
   stage only inside the `observation` prose. Task translation would have failed closed on every
   run — silently proposing nothing. Fixed by recomputing the stage from the ordered `gaps`
   tuple the agent was given and then *confirming* it against the observation text, so a
   behavior change in the agent yields a refusal rather than a guess.
4. **No-transaction fallback could leave partial writes.** A storage without `transaction()`
   would commit the `ai_analysis` row and then fail the hypothesis write. `_persist` now
   prefers the `insert_hypothesis` facade and fails closed if neither documented write surface
   exists.
5. **Fail-closed boundary was incomplete (found by audit).** `recon_context(...)` and
   `hypothesis_context(...)` were initially called outside the `try`, so a malformed
   `configuration_snapshot` or graph would propagate into the orchestrator and fail the run the
   hook exists only to advise. Both are now inside the guard, covered by
   `test_a_context_build_failure_yields_nothing_rather_than_failing_the_run` and
   `test_a_malformed_projection_does_not_fail_the_run`.

### 11.6 Deferred

- Real LLM provider backends (§2.2). `model_used` records `argus-rule-based (route mode=<m>)`,
  which is truthful about making no provider call.
- The 15 recon stages with no registered adapter remain coverage gaps. They are reported on
  `AnalysisResult.uncovered_without_capability` and are not persisted; persisting them would need
  a run-scoped storage surface that `ai_analysis` cannot express without a schema change.
- `ai_analysis` has no `run_id`. Run attribution is `input_context_ref = "run:<uuid>"`.
  `list_ai_analysis()` is therefore unfiltered and callers filter by exact ref.

### 11.7 Audit status

No `BLOCKER` or `HIGH` findings remain. See the Phase 16 forensic audit for the full
classification.

