-- ARGUS migration 0006 (up): persist the reconnaissance stages a run structurally
-- could not attempt.
--
-- Phase 15 introduced ``ai.run_context.uncovered_without_capability()``, which
-- separates two facts that used to be indistinguishable in a run's output:
--
--   * a stage that was not covered even though an adapter for it exists, and
--   * a stage that was not covered because NO registered adapter can run it.
--
-- Phase 16 kept that distinction out of proposals deliberately -- a gap the
-- system cannot act on is not a task -- and then deferred persisting it, saying
-- so in PHASE_16_PROPOSAL.md 11.6: "persisting them would need a run-scoped
-- storage surface that ``ai_analysis`` cannot express without a schema change."
--
-- Phase 17 (migration ``0005``) built that surface: ``ai_analysis`` gained a
-- real ``run_id`` foreign key, an index, a required-check, and indexed run-scoped
-- reads. The documented blocker is gone, so this migration adds the table the gap
-- was waiting for.
--
-- Why a new table rather than a column on ``ai_analysis``
-- ------------------------------------------------------
-- ``ai_analysis`` rows are per *agent invocation* and their ``output`` jsonb is
-- the verbatim Common Output Contract object. A coverage gap is not an agent
-- output: it is a property of the run's capability surface, it exists even on a
-- pass that proposed nothing at all, and one gap is not one invocation. Writing
-- gaps into ``ai_analysis.output`` would both falsify that table's meaning and
-- make "the AI ran but proposed nothing" indistinguishable from "the AI ran and
-- recorded a gap". So the gap gets its own table.
--
-- run_id is NOT NULL
-- ------------------
-- Unlike ``0005``, there is no legacy data and no backfill to be conservative
-- about: this table is created empty and every row is written by Phase 18. There
-- is no honest way to attribute a coverage gap to a historical run -- the value
-- was never stored, and inferring it from historical task types would be a guess
-- dressed as data. So the column is declared NOT NULL outright rather than
-- nullable-plus-NOT-VALID: there is no legacy shape to accommodate, and the
-- simpler, fully-enforced constraint is the honest one.
--
-- (run_id, stage) uniqueness
-- --------------------------
-- A gap observed on four passes of one run is ONE fact about that run, not four
-- facts. Without this constraint a long run would accumulate a duplicate row per
-- pass per stage, and "how many gaps does this run have" would become a function
-- of how many analysis passes happened to run. The unique constraint makes the
-- row the unit of meaning.
--
-- ``observation_count`` and ``last_seen_at`` exist so that collapsing those rows
-- does not also destroy the signal. "This run cannot do web_crawl" (count 1) and
-- "this run tried to plan web_crawl on eleven separate passes and still could not"
-- (count 11) are different facts, and the first one is about capability while the
-- second is a signal worth investigating. Recording both is what keeps the
-- difference visible after deduplication.
--
-- Stage names are stored verbatim from ``ai.run_context.STAGE_PRIORITY``. They are
-- NOT foreign keys to an adapter registry: there is no such table, the set of
-- registered adapters is a runtime property of the process rather than of the
-- database, and a coverage gap is precisely the statement that a stage exists
-- without a way to execute it. A foreign key to an adapter table would make the
-- gap unrepresentable by construction.
CREATE TABLE IF NOT EXISTS ai_coverage_gaps (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id            uuid NOT NULL REFERENCES runs (id),
    stage             text NOT NULL,
    first_seen_at     timestamptz NOT NULL DEFAULT now(),
    last_seen_at      timestamptz NOT NULL DEFAULT now(),
    observation_count integer NOT NULL DEFAULT 1,
    CONSTRAINT ai_coverage_gaps_run_stage_key UNIQUE (run_id, stage),
    CONSTRAINT ai_coverage_gaps_stage_not_blank CHECK (btrim(stage) <> ''),
    CONSTRAINT ai_coverage_gaps_observation_count_positive
        CHECK (observation_count >= 1)
);

-- The production read is "this run's gaps", which is a prefix scan on run_id.
CREATE INDEX IF NOT EXISTS ai_coverage_gaps_run_id_idx
    ON ai_coverage_gaps (run_id);