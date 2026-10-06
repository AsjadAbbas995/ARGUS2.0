# Phase 19 Proposal — Canonical Attack-Surface Read Projection

## Phase 19 status

**ALREADY IMPLEMENTED / VERIFIED.**

Phase 19 introduces **no new implementation**. The capability it requests —
a canonical, deterministic, read-only projection from persisted PostgreSQL
facts through the existing correlation records and attack-surface graph to
deterministic read surfaces — already exists in committed code.

## Original objective

Canonical PostgreSQL facts → correlation records → attack-surface graph →
deterministic read surfaces (API / reports / dashboard), run-scoped,
evidence-bearing, and free of target activity.

## Implementation provenance

The projection was designed, implemented, and committed as **Phase 15**:

```
77a2de3  feat: implement phase 15 canonical read projection
```

It is present at the current baseline `HEAD` (`0093514`), unmodified by Phase 19.

## Verification

- `tests/test_projection.py` — **34 passed** (unit/contract).
- `tests/test_projection_live.py` — **19 passed** against real PostgreSQL
  `127.0.0.1:5433` (`argus_test`).
- Relevant regression (projection, correlation, ingest, reports, phase16,
  phase17, phase18) — **196 passed** (includes the 19 live projection tests;
  177 compose the non-live projection/correlation/ingest/reports/phase16/17/18 sets).

## Architecture

```
PostgreSQL (canonical facts + evidence)
    ↓  database/projection.RunFacts.from_evidence_rows      (run-scoped SELECT)
    ↓  database/repositories/all.py :: attack_surface()      (repository read method)
    ↓  database/projection.build_records                     (pure transformation)
    ↓  correlation.records (frozen dataclasses: Domain/Ip/Port/WebApp/Technology)
    ↓  correlation.asset_graph.build                         (committed graph builder)
    ↓  correlation.relationship_engine.run                   (deterministic inferences)
    ↓  database/projection.serialize                         (JSON-safe payload)
    ↓  API route + JSON/Markdown/HTML reports                (read-only surfaces)
```

The projection adapts canonical DB rows into the **existing** correlation
record types. No second graph model, no duplicated correlation code, no new
route, and no new report path were created.

## Run isolation

A canonical entity is not owned by a run. Projection membership is decided
**only** by real provenance:

```
evidence.tool_run_id → tool_runs.task_id → tasks.run_id → runs.id
```

An entity is projected into a run's graph **iff** that run holds an `evidence`
row naming it (matching `entity_type` and `entity_id`). Timestamps, "latest
row", and program membership are deliberately not used. Two runs that observed
the same fact both project it; a run that never observed it never does.
Association edges (`asset_ips`, `asset_technologies`) are projected only when
**both** endpoints are themselves evidenced in the same run, so no run can
contain an edge it did not observe. Verified by
`test_a_run_only_projects_the_facts_its_own_evidence_names`,
`test_two_runs_that_both_observe_the_same_fact_both_project_it`, and
`test_a_second_run_seeing_only_a_subset_projects_only_that_subset`.

## Deterministic behavior

`evidence` carries no timestamp, so ordering is fixed on stable identifiers:
evidence rows ordered by primary key, the first row per `(entity_type,
entity_id)` supplies the evidence id; entity rows ordered by natural key; the
final record tuple sorted by `(type, key, evidence_id)`. The same persisted run
projects the same records, graph, and inferences on every read. No caching, no
background work, no graph persistence. Verified by
`test_same_rows_always_produce_the_same_records_graph_and_inferences`,
`test_input_row_order_does_not_change_the_result`, and
`test_repeated_reads_return_an_identical_payload`.

## Evidence / provenance

Every projected node and edge carries an `evidence_id` from the run's own
evidence rows; none is fabricated. Records whose required graph parents are not
themselves evidenced are **withheld** rather than reparented (a `PortRecord`
needs its evidenced IP; a `WebAppRecord` needs its evidenced port and asset). An
evidenced IP with no evidenced owner is emitted with an empty hostname, landing
as a stored orphan node rather than being dropped. Verified by
`test_every_projected_node_and_edge_carries_its_evidence_id`,
`test_evidenced_ip_with_no_evidenced_owner_is_stored_as_an_orphan_node`, and
`test_port_without_an_evidenced_ip_is_withheld_not_reparented`.

## API

`GET /api/v1/runs/{run_id}/attack-surface` in `api/server.py`, behind the
existing `_authed` dependency (Bearer key, constant-time compare). Run-scoped,
read-only, no mutation endpoints, no unauthenticated access. An unknown run
returns 404 before any read, so the route cannot distinguish "run does not
exist" from "run has no facts". A storage without a canonical store degrades to
`available: false` rather than an empty-but-present graph. Verified by
`test_attack_surface_route_requires_authentication`,
`test_attack_surface_route_404s_for_an_unknown_run`, and the live
`test_served_attack_surface_route_requires_auth_and_404s`.

## Reports

All three renderers consume the same serialized projection; none queries
PostgreSQL independently. `api/server.py` builds the surface once and passes it
to `json_report.build_report(...)` as `attack_surface=`. Empty graphs and zero
inferences are rendered explicitly empty; no "findings" are manufactured.
Verified by `test_json_report_carries_the_surface_verbatim`,
`test_all_three_formats_render_the_same_surface`, and
`test_served_report_is_fed_from_real_persisted_facts`.

## Security properties

- **SQL parameterization**: reads use the repositories' existing parameterized
  statements; no string interpolation of run ids.
- **Run isolation**: enforced by the evidence→run provenance chain (above).
- **Authorization**: the route reuses `_authed`; no new auth path.
- **Provenance / truth labels**: evidence ids preserved; inferences keep the
  correlation layer's own `INFERENCE` label and are never promoted to findings.
- **No target network activity**: the projection is pure `SELECT` + in-memory
  transformation; no DNS, HTTP, tool, or AI invocation.
- **No mutation**: no writes, no task/hypothesis creation, no
  `VALIDATED_FINDING` creation.
- **No secret leakage**: serialized payload carries only entity/evidence ids;
  the database URL never appears in output (`test_served_report_never_leaks_the_database_url`).
- **No fabricated nodes/edges**: unprojectable facts are withheld honestly.

## Known limitations

- Only fact types with real Phase 14 producers are projected (assets, IPs,
  ports, web apps, technologies, DNS-derived address bindings). Record types
  with no producer — endpoints, parameters, JavaScript, APIs, GraphQL,
  authentication, WebSockets, certificates — are **not** fabricated; they are
  declared in `unproduced_record_kinds`.
- `dns_records` has a producer and run evidence, but the committed correlation
  model has no DNS record type; address-valued records are represented as the
  existing `resolves_to` edge, and non-address records are honestly not
  projected. Adding a record type is out of scope.
- Association rows (`asset_ips`, `asset_technologies`) cannot be attributed to a
  run individually (NULL `entity_id` on their Phase 14 evidence, or inline
  `evidence_id`); endpoint containment is used instead, which is strictly
  conservative.
- With a Phase-14-shaped dataset, inference rules are gated on endpoint-class
  nodes that have no producer yet, so **zero inferences** is the honest,
  expected result — not a defect.

## Why no duplicate implementation was created

The Phase 19 brief requested exactly the pipeline that Phase 15 already
provides. Per the phase's own guardrails — "Do NOT create a second competing
graph model", "Do NOT duplicate the graph implementation", and the STOP
condition against silently expanding scope — re-implementing the projection,
its API route, or its report integration would have been redundant and harmful.
No `tests/test_phase19.py` was created because equivalent (and more thorough)
coverage already exists in `tests/test_projection.py` and
`tests/test_projection_live.py`; adding a parallel suite would duplicate rather
than strengthen verification.

Phase 19 therefore closes as **already implemented / verified**, with no new
production code.

## Incidental correction

`tests/test_phase17_live.py::test_0005_reverts_and_can_be_reapplied` held a
stale expectation (`apply(schema) == [5]`) written before the Phase 18
migration `0006_ai_coverage_gaps` existed. Since reverting to version 4 now
reverts 5 and 6, re-applying correctly returns `[5, 6]`. Only the test
expectation (plus an explanatory comment) was updated; migration behavior and
migration files were not touched.