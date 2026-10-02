-- ARGUS revert for migration 0005: remove the ``ai_analysis`` run relationship.
--
-- Reverting discards run attribution, so an ``ai_analysis`` row goes back to
-- carrying its run only inside the ``input_context_ref`` string -- the Phase 16
-- shape, where attributing a row to a run meant matching a text prefix rather
-- than a foreign key. The rows themselves survive; only the relationship goes.
--
-- ``input_context_ref`` is deliberately *not* touched, so the values Phase 16
-- wrote survive the round trip and a later re-apply can attribute them again.
-- The live-test fixture discards test data before reverting, so this only ever
-- runs against a database whose rows are about to be dropped anyway.
DROP INDEX IF EXISTS ai_analysis_run_id_idx;

ALTER TABLE ai_analysis
    DROP CONSTRAINT IF EXISTS ai_analysis_run_id_required_check,
    DROP COLUMN IF EXISTS run_id;
