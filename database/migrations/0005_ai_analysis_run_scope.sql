-- ARGUS migration 0005 (up): give ``ai_analysis`` a real run relationship.
--
-- Phase 16 made the intelligence layer reachable and durable, but the table it
-- writes to has no ``run_id`` column (``0001`` created it with
-- ``agent_name``/``model_used``/``input_context_ref``/``output``/``created_at``
-- only). Run attribution therefore lived in the ``input_context_ref`` *string*,
-- written by ``ai.loop.context_ref`` as ``"run:<uuid>"`` and matched by a caller
-- with a text prefix. That is a second, divergent notion of run membership next
-- to the Phase 15 evidence chain (``evidence -> tool_runs -> tasks -> runs``),
-- and it is the reason the analysis trail could not be read back for a specific
-- run through a foreign key, an index, or a plain ``WHERE run_id = %s``.
--
-- * run_id: analysis rows are run-scoped audit records, so ownership is an
--   explicit FK rather than a convention inside a text column. This mirrors what
--   ``0002`` did for ``hypotheses``.
--
-- Backfill -- what is and is not attributed
-- ----------------------------------------
-- Unlike ``0002``, this migration *can* attribute legacy rows honestly, because
-- ``ai.loop`` wrote attribution in a documented, parseable form. It is still done
-- conservatively: a row is attributed only when BOTH hold.
--
--   1. ``input_context_ref`` matches ``^run:<canonical-uuid>$``. The regex is not
--      cosmetic: PostgreSQL has no ``try_cast``, so a malformed value reaching
--      ``::uuid`` would abort the whole migration. Requiring the canonical shape
--      first makes the cast provably safe, and any value that fails the regex is
--      simply left NULL rather than guessed at.
--   2. The referenced run actually exists. Attribution is confirmed against
--      ``runs``, not inferred from the text.
--
-- A row failing either test keeps ``run_id IS NULL``. It is never assigned to an
-- arbitrary run, and it stays invisible to run-scoped reads -- which are always
-- qualified by ``WHERE run_id = %s`` -- rather than being surfaced as another
-- run's analysis.
--
-- Upgrade safety
-- --------------
-- ``run_id`` is added NULLABLE so a populated ``ai_analysis`` upgrades cleanly
-- and every legacy row survives. A ``NOT VALID`` CHECK enforces
-- ``run_id IS NOT NULL`` on every row written from now on (PostgreSQL applies NOT
-- VALID checks to new INSERTs/UPDATEs while skipping pre-existing rows), so every
-- Phase 17 write is run-scoped while unattributable legacy rows remain honestly
-- un-attributed. On a fresh install the table is empty, the constraint validates
-- immediately, and the end state is a fully enforced schema -- exactly the shape
-- ``0002`` established for ``hypotheses``.
--
-- ``input_context_ref`` is deliberately kept. Phase 16 wrote it, it names the
-- context an agent was given (which a run id alone does not), and dropping it
-- would rewrite history that already exists in production databases. After this
-- migration it is a context label, not the run filter.
ALTER TABLE ai_analysis
    ADD COLUMN run_id uuid REFERENCES runs (id),
    ADD CONSTRAINT ai_analysis_run_id_required_check
        CHECK (run_id IS NOT NULL) NOT VALID;

CREATE INDEX IF NOT EXISTS ai_analysis_run_id_idx ON ai_analysis (run_id);

-- Attribute only rows whose reference is a canonical ``run:<uuid>`` that resolves
-- to a real run. Anything else keeps run_id NULL.
UPDATE ai_analysis a
   SET run_id = substr(a.input_context_ref, 5)::uuid
 WHERE a.run_id IS NULL
   AND a.input_context_ref ~* '^run:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   AND EXISTS (
       SELECT 1 FROM runs r WHERE r.id = substr(a.input_context_ref, 5)::uuid
   );

-- Validate the constraint when nothing is left un-attributed (fresh database, or a
-- database whose legacy rows were all attributable). On a populated legacy database
-- with unattributable rows this is a no-op and the constraint remains NOT VALID.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM ai_analysis WHERE run_id IS NULL) THEN
        ALTER TABLE ai_analysis VALIDATE CONSTRAINT ai_analysis_run_id_required_check;
    END IF;
END $$;
