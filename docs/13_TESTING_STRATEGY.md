# ARGUS Testing Strategy

Testing happens throughout development, not as a final pass. No test in CI depends on live
external targets.

## Unit Tests

Cover: configuration parsing, scope matching, task fingerprinting, task scoring, normalization
logic, and individual parsers in isolation.

## Adapter Fixture Tests

Every tool adapter (`06_TOOL_CONTRACTS.md`) is tested against recorded fixture output, never a
live tool invocation, in normal CI:

```text
fixtures/
├── subfinder/
├── nmap/
├── httpx/
├── katana/
└── ffuf/
```

Each adapter's `parse()` method must produce the correct normalized objects from its fixture,
including edge cases (empty results, malformed lines, partial output).

## Database Tests

Verify: inserts, relationships (foreign keys resolve correctly), deduplication constraints
(`05_DATA_MODEL.md` unique constraints), migrations (apply and roll back cleanly), and error
handling on constraint violations.

## PostgreSQL Live-Test Fixture

Database tests are split in two. Everything above runs with no database at all. The PostgreSQL-backed
tiers — the `*_live.py` modules — are gated on `ARGUS_TEST_DATABASE_URL` and **skip** when it is
unset, so an ordinary checkout runs the whole suite offline and the live tiers opt in by setting
that variable.

That variable points at a **local live-test PostgreSQL fixture**. This is a test fixture only. It
exists so PostgreSQL-backed integration and live verification have something real to run against,
and it is **not production infrastructure**.

| Property | Value |
|---|---|
| PostgreSQL version | 17.11 |
| Cluster location | `Temp\opencode\pg15` (`%LOCALAPPDATA%\Temp\opencode\pg15`) |
| Live-test port | `5433` |
| Role | `argus` |
| Database | `argus_test` |
| Authentication | `trust`, loopback only |

Start and stop it around a live run:

```text
pg_ctl -D %LOCALAPPDATA%\Temp\opencode\pg15 -l pg15run.log -o "-p 5433 -h 127.0.0.1" -w start
set ARGUS_TEST_DATABASE_URL=postgresql://argus@127.0.0.1:5433/argus_test
pytest
set ARGUS_TEST_DATABASE_URL=
pg_ctl -D %LOCALAPPDATA%\Temp\opencode\pg15 -m fast stop
```

**Do not confuse this fixture with the installed PostgreSQL cluster on port 5432.** They are
separate clusters with different roles and different authentication:

| | Live-test fixture | Installed cluster |
|---|---|---|
| Port | `5433` | `5432` |
| Role `argus` | present | absent |
| Authentication | `trust`, loopback only | `scram-sha-256` |

Port 5432 is an unrelated installation and is **not** the live-test target. Phase verification has
no credential for it and must not reconfigure, reload, or stop it. If a live run appears to need
port 5432, the fixture on 5433 is not running.

No password or secret belongs in this fixture, in `ARGUS_TEST_DATABASE_URL`, or in any tracked
file. The fixture is `trust`-authenticated precisely so that none is needed; that is a property of a
disposable local fixture and is not a precedent for anything reachable from outside this machine.

## Scope Tests

```text
Allowed target                 → allowed
Excluded target                 → rejected
Out-of-scope redirect           → rejected; redirect recorded as observation; destination
                                  marked out-of-scope; no active interaction
Out-of-scope discovered host    → rejected
Disallowed port                 → rejected
```

Every rejection must be logged (`04_SCOPE_SAFETY.md`). Test coverage must include the
redirect/discovered-target policy (`04_SCOPE_SAFETY.md` §Redirect and Discovered-Target
Policy) across all discovery surfaces: redirects, DNS-discovered IPs, JavaScript-discovered
hosts, API destinations, WebSocket endpoints, and crawl-discovered links.

## Command Safety Tests

Verify: `shell=False` is used everywhere a subprocess is invoked, commands are constructed as
argument arrays (never string-concatenated), there is no command-injection path from untrusted
target input, timeouts are enforced, and stdout/stderr are captured without leaking secrets into
logs.

## Orchestrator Tests

Cover: state transitions (`08_ORCHESTRATOR.md` state machine), task dependency ordering, task
deduplication (same fingerprint does not re-run), resumability after a simulated crash,
failure-isolation (one task's failure doesn't halt the run), and retry behavior.

## AI Contract Tests

Verify every agent (`07_AI_AGENTS.md`):

- Returns schema-valid structured output (`12_AI_PROMPTS.md` §Output Schemas)
- Does not invent evidence not present in the supplied context
- Respects truth labels — never asserts `FACT` where only `HYPOTHESIS` is warranted
- Does not produce arbitrary commands or targets outside the supplied scope
- Never attempts to change scope

## Integration Tests

Run against controlled local labs only — never against external, uncontrolled targets. A
representative lab fixture should exercise the full pipeline: discovery → normalization →
persistence → (once implemented) AI analysis → task generation → scope check → execution →
correlation, to validate the adaptive loop end-to-end (`03_RECON_PIPELINE.md` §27,
`10_IMPLEMENTATION_PLAN.md` Phase 8).

## Relationship to Other Documents

- `04_SCOPE_SAFETY.md` — the rules Scope/Command Safety tests verify
- `08_ORCHESTRATOR.md` — the state machine Orchestrator tests verify
- `07_AI_AGENTS.md` / `12_AI_PROMPTS.md` — the contracts AI Contract tests verify
- `15_FIRST_MILESTONE.md` §Acceptance Criteria — the specific tests Milestone 1 must pass
