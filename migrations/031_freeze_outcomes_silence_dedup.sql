-- 031_freeze_outcomes_silence_dedup.sql
--
-- v0.32.1 (worker-audit HIGH) — dedup the auto-recorded silence_14d
-- freeze outcome.
--
-- The freeze-followup cron (worker/_freeze_followup.py::
-- _write_silence_outcome) writes a freeze_outcomes row with
-- outcome_type='silence_14d' when a letter reaches the 14-day
-- internal-alert stage. That row is a measurable "issuer did not
-- respond" data point consumed by the per-issuer priors pipeline
-- (recovery.scorer) and surfaced in the LE-handoff Live Filing Status.
--
-- Pre-v0.32.1 the INSERT was unguarded. The followup_stage state
-- machine is monotonic and the candidate scan excludes letters already
-- at silence_14d, so the happy path writes exactly one row — but there
-- is no HARD guarantee. A re-run after a partial failure (stage advance
-- committed, outcome write retried), a manual cron invocation, or two
-- overlapping ticks racing the same letter could each append a SECOND
-- silence_14d row. Duplicate non-response rows DOUBLE-COUNT against the
-- issuer in the priors aggregation, biasing every downstream recovery
-- estimate and the Live Filing Status. For a forensic/financial system
-- this must be impossible at the schema level, not merely improbable.
--
-- A PARTIAL unique index enforces "at most one silence_14d row per
-- letter" WITHOUT constraining the other outcome_types — a single
-- letter legitimately produces many non-silence outcome events
-- (acknowledged -> partial_freeze -> full_freeze -> ...), and the
-- longer-timescale silence_30d / silence_90d remain free to coexist.
-- The cron's INSERT pairs this with
--   ON CONFLICT (letter_id) WHERE outcome_type = 'silence_14d' DO NOTHING
-- so a concurrent / retried write is a safe no-op rather than an error.
--
-- Additive + safe to run mid-deploy. If duplicate silence_14d rows
-- already exist the CREATE INDEX fails with a clear error; operators
-- de-dup manually (keep the earliest observed_at) before re-running.
--
-- Apply with: python scripts/apply_migration.py migrations/031_freeze_outcomes_silence_dedup.sql

BEGIN;

CREATE UNIQUE INDEX IF NOT EXISTS freeze_outcomes_one_silence_14d_per_letter
    ON public.freeze_outcomes (letter_id)
 WHERE outcome_type = 'silence_14d';

COMMENT ON INDEX public.freeze_outcomes_one_silence_14d_per_letter IS
    'v0.32.1 (worker-audit HIGH): at most one auto-recorded silence_14d '
    'outcome per freeze letter. Pairs with ON CONFLICT DO NOTHING in the '
    'freeze-followup cron so a retried / racing tick cannot double-count '
    'the same non-response in the per-issuer priors pipeline.';

COMMIT;
