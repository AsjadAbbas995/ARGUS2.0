# ARGUS Outputs

Defines everything ARGUS produces: raw artifacts, evidence, screenshots, and reports.

## Storage Layout

```text
storage/
├── raw/           # unmodified tool output, per tool
├── evidence/       # evidence artifacts referenced by evidence.raw_reference
├── screenshots/    # visual captures (future web-app screenshots)
└── reports/        # generated JSON / Markdown / HTML reports
```

PostgreSQL holds the structured, canonical data (`05_DATA_MODEL.md`); `storage/` holds the raw
artifacts that back it up.

## Report Formats

- **JSON** — machine-readable; source for integrations, automation, the future dashboard, and
  further AI processing.
- **Markdown** — human-readable security report.
- **HTML** — interactive, report-friendly presentation.

## Report Structure

```text
Executive Summary
Scope
Run Metadata
Attack Surface Summary
Discovered Assets
DNS
IPs
Ports
Services
Web Applications
Technologies
URLs
Endpoints
Parameters
JavaScript Intelligence
API Intelligence
GraphQL
WebSockets
Authentication
Cloud/CDN/WAF
Hypotheses
Validated Findings
Evidence
Recon Timeline
Task History
Coverage
Errors
Limitations
```

**The report must clearly and consistently distinguish facts from hypotheses** — every
hypothesis and validated finding section carries its `truth_label`
(`01_PRODUCT_SPEC.md` §14) and never blends the two.

### Projected Attack Surface

Since Phase 15 the report also carries an optional `attack_surface` section: the run's derived
graph, its record counts, and its deterministic inferences.

```text
Attack Surface (Facts)
 ├─ evidence_counts        run-scoped evidence rows per entity type
 ├─ records.count/by_kind  projected canonical records
 ├─ graph                  nodes, edges, orphans — every one carrying its evidence_id
 ├─ endpoint_subgraph      summary; empty, because Phase 14 has no endpoint producer
 └─ inferences             correlation-layer output, each with its own truth_label
```

Rules that keep the section honest:

- **Facts only.** Every node and edge resolves to an `evidence` row belonging to *this* run.
- **Optional and backward-compatible.** The section is omitted entirely when the storage backend
  cannot project (the in-memory development double), so existing report contracts are unchanged.
- **`available` disambiguates.** `available: false` means the backend has no canonical fact
  store; `available: true` with zero counts means a real run that observed nothing.
- **Gaps are named, not hidden.** `unproduced_record_kinds` lists the record types with no
  persisted producer yet (endpoint, parameter, javascript, api, auth, certificate), so a reader
  can tell "ARGUS does not collect this yet" from "ARGUS found nothing".
- **Inferences are not findings.** The section never feeds `validated_findings`; it passes the
  correlation layer's `truth_label` through unchanged.
- **Deterministic.** Two reads of an unchanged run produce byte-identical output.

## Evidence Traceability

Every reported claim must be traceable back through this chain:

```text
Task
 ↓
Tool Run
 ↓
Observation
 ↓
Evidence
 ↓
AI Analysis
 ↓
Hypothesis
 ↓
Next Task
```

A report reader should always be able to answer: *why did ARGUS investigate this?*, *what
evidence caused this hypothesis?*, *which tool produced the original observation?*, and *which
AI analysis created the next task?* See `05_DATA_MODEL.md` `evidence` table and
`ai_analysis` table.

## Relationship to Other Documents

- `05_DATA_MODEL.md` — the tables (`evidence`, `hypotheses`, `ai_analysis`, `tasks`,
  `tool_runs`) that this traceability chain is built from
- `07_AI_AGENTS.md` — `ReportAgent` is responsible for rendering these reports
- `04_SCOPE_SAFETY.md` — reports must never present a hypothesis as a validated finding without
  the human/safe-validation step having occurred
- `PHASE_15_PROPOSAL.md` — how the projected attack surface is derived and why its gaps are
  reported rather than filled
- `02_ARCHITECTURE.md` — the read-only projection that feeds this section
