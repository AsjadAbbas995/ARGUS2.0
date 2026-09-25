DROP INDEX IF EXISTS hypotheses_run_id_idx;

ALTER TABLE hypotheses
    DROP CONSTRAINT IF EXISTS hypotheses_run_id_required_check,
    DROP CONSTRAINT IF EXISTS hypotheses_review_status_check,
    DROP COLUMN IF EXISTS review_reason,
    DROP COLUMN IF EXISTS review_status,
    DROP COLUMN IF EXISTS validation_step,
    DROP COLUMN IF EXISTS target,
    DROP COLUMN IF EXISTS run_id;
