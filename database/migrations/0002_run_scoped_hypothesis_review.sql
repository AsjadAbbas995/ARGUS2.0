-- Reconcile the committed ``hypotheses`` table with the already-committed AI
-- (ai/hypothesis_agent.py), API (api/server.py) and operator dashboard
-- (dashboard/app.js) contracts, which are run-scoped and require an explicit
-- operator review state.
--
-- * run_id: hypotheses are run-scoped review items for the API/dashboard, so
--   ownership is an explicit FK rather than being inferred through
--   endpoint/evidence relationships. endpoint_id stays nullable.
-- * target/validation_step: already emitted by the committed AI output contract
--   (ai/contract.py proposal) and rendered by the dashboard, but never given
--   columns.
-- * review_status/review_reason: operator review state, kept strictly separate
--   from the existing analytical status (open/validated/rejected) and from
--   truth_label. Approval is the documented human/safe-validation boundary that
--   may promote truth_label to VALIDATED_FINDING.

ALTER TABLE hypotheses
    ADD COLUMN run_id uuid NOT NULL REFERENCES runs (id),
    ADD COLUMN target text NOT NULL DEFAULT '',
    ADD COLUMN validation_step text NOT NULL DEFAULT '',
    ADD COLUMN review_status text NOT NULL DEFAULT 'pending',
    ADD COLUMN review_reason text,
    ADD CONSTRAINT hypotheses_review_status_check
        CHECK (review_status IN ('pending', 'approved', 'rejected'));

CREATE INDEX IF NOT EXISTS hypotheses_run_id_idx ON hypotheses (run_id);
