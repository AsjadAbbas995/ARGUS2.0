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
--
-- Upgrade safety
-- --------------
-- A hypothesis row created before this migration is NOT run-scoped, and its
-- run cannot be derived from committed data: the only ownership chain in
-- ``05_DATA_MODEL.md`` is hypotheses -> endpoints -> urls -> web_apps ->
-- assets -> programs, and it contains no run at any hop. Assigning one would
-- fabricate provenance, so this migration refuses to do it.
--
-- Instead:
--   * run_id is added NULLABLE, so an existing populated ``hypotheses`` table
--     upgrades cleanly and its rows survive with run_id = NULL.
--   * A NOT VALID CHECK constraint enforces ``run_id IS NOT NULL`` on every
--     row written from now on (PostgreSQL enforces NOT VALID checks against
--     new INSERTs/UPDATEs while skipping only the pre-existing rows). Every new
--     hypothesis is therefore run-scoped; legacy rows stay honestly
--     un-attributed and remain invisible to run-scoped reads, which are always
--     qualified by ``WHERE run_id = %s``.
--   * On a fresh install the table is empty, so the constraint is validated
--     immediately and the end state is a fully enforced schema. On a populated
--     database it stays NOT VALID until an operator decides the ownership of
--     the legacy rows; that decision is a data question, not a schema one.

ALTER TABLE hypotheses
    ADD COLUMN run_id uuid REFERENCES runs (id),
    ADD COLUMN target text NOT NULL DEFAULT '',
    ADD COLUMN validation_step text NOT NULL DEFAULT '',
    ADD COLUMN review_status text NOT NULL DEFAULT 'pending',
    ADD COLUMN review_reason text,
    ADD CONSTRAINT hypotheses_review_status_check
        CHECK (review_status IN ('pending', 'approved', 'rejected')),
    ADD CONSTRAINT hypotheses_run_id_required_check
        CHECK (run_id IS NOT NULL) NOT VALID;

CREATE INDEX IF NOT EXISTS hypotheses_run_id_idx ON hypotheses (run_id);

-- Validate the constraint when nothing is left un-attributed (fresh database,
-- or a database whose legacy rows have since been resolved). On a populated
-- legacy database this is a no-op and the constraint remains NOT VALID.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM hypotheses WHERE run_id IS NULL) THEN
        ALTER TABLE hypotheses VALIDATE CONSTRAINT hypotheses_run_id_required_check;
    END IF;
END $$;
