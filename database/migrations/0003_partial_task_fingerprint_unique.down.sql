-- ARGUS revert for migration 0003: restore 0001's unconditional unique index.
--
-- Reverting re-tightens the constraint, so it can only succeed while no run
-- holds two un-fingerprinted tasks. That is the correct and expected behaviour
-- for restoring a constraint (a revert must not silently drop a guarantee), and
-- it is why the live-test fixture discards test data before reverting: reverting
-- to version 0 drops every table anyway, so the data is destroyed regardless.
DROP INDEX IF EXISTS tasks_run_fingerprint_uq;

CREATE UNIQUE INDEX IF NOT EXISTS tasks_run_fingerprint_uq
    ON tasks (run_id, fingerprint);
