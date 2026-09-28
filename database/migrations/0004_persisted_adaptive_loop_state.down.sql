-- ARGUS revert for migration 0004: drop the persisted adaptive-loop columns.
--
-- Reverting discards the loop progress of any run that has already spent passes,
-- so a reverted database sends resumed runs back to "pass 0, no new tasks". That
-- is the expected consequence of reverting: the columns did not exist before it.
-- The live-test fixture discards test data before reverting, so this only ever
-- runs against a database whose rows are about to be dropped anyway.
ALTER TABLE runs
    DROP COLUMN IF EXISTS pass_new_tasks,
    DROP COLUMN IF EXISTS loop_pass;
