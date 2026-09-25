-- ARGUS migration 0003 (up): scope task-fingerprint uniqueness to real fingerprints.
--
-- 0001 declared ``tasks.fingerprint`` as ``text NOT NULL`` *and* made
-- ``(run_id, fingerprint)`` unconditionally unique. But the ``Task`` entity
-- defaults ``fingerprint`` to the empty string, so any task inserted without
-- going through the planner's fingerprinter stored ``''``. Combined with the
-- unconditional unique index, that permitted at most ONE un-fingerprinted task
-- per run, so ``Storage.insert_tasks`` -- a public contract operation that
-- accepts tasks directly -- raised ``UniqueViolation`` for a perfectly legal
-- batch. That is a persistence-layer defect, not a test artifact.
--
-- The planner already treats ``''`` as "no fingerprint": core/orchestrator.py
-- collects ``{t.fingerprint for t in ... if t.fingerprint}``, excluding empty
-- values, and core/task_planner.py always assigns a real fingerprint via
-- ``task_fingerprint(...)``. Dedup was therefore only ever *intended* over
-- non-empty fingerprints.
--
-- Scoping the unique index with ``WHERE fingerprint <> ''`` keeps the Phase-5
-- dedup contract exactly intact for real fingerprints while making the
-- un-fingerprinted case legal, matching the semantics the application code
-- already implements.
DROP INDEX IF EXISTS tasks_run_fingerprint_uq;

CREATE UNIQUE INDEX IF NOT EXISTS tasks_run_fingerprint_uq
    ON tasks (run_id, fingerprint)
    WHERE fingerprint <> '';
