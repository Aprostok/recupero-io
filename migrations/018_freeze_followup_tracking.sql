-- 018_freeze_followup_tracking.sql
--
-- v0.21.0 — Freeze letter follow-up cron (72h / 7d / 14d).
--
-- Pre-v0.21.0: a freeze letter went out, the operator manually
-- checked their inbox for a response, and if nothing came back...
-- nothing happened. Letters in compliance black holes (Binance,
-- offshore exchanges) sat indefinitely without escalation. The
-- aggregate freeze success rate suffered because escalation
-- timing was operator-attention-bound.
--
-- This migration adds two columns to freeze_letters_sent that
-- drive a scheduled escalation loop:
--
--   * last_followup_sent_at — when the cron most recently nudged
--     this letter's recipient. NULL until the 72h nudge fires.
--   * followup_stage — monotonic state machine:
--       'initial'        — letter sent; no follow-up yet
--       'nudge_72h'      — gentle reminder sent at 72h silence
--       'escalation_7d'  — firmer escalation sent at 7d silence
--       'silence_14d'    — internal alert to operator at 14d:
--                          "this issuer is non-responsive,
--                          recommend grand jury subpoena"
--
-- The cron (worker/_freeze_followup.py::run_freeze_followup_cron)
-- runs every 6 hours, scans for letters whose followup_stage hasn't
-- progressed beyond what their elapsed time warrants, sends the
-- next-stage email, and updates the stage + last_followup_sent_at
-- inside the same transaction. The `last_followup_sent_at NULLS FIRST`
-- partial index keeps the scan cheap (excludes letters already at
-- silence_14d, the terminal stage).
--
-- Extends freeze_outcomes.outcome_type CHECK to add 'silence_14d',
-- aligning with the new internal-alert stage. silence_30d and
-- silence_90d remain — they fire on a longer timescale when no
-- response ever materializes.
--
-- Apply with: python scripts/apply_migration.py migrations/018_freeze_followup_tracking.sql

BEGIN;

-- ----- freeze_letters_sent: follow-up tracking columns ----- --

ALTER TABLE public.freeze_letters_sent
    ADD COLUMN IF NOT EXISTS last_followup_sent_at TIMESTAMPTZ;

ALTER TABLE public.freeze_letters_sent
    ADD COLUMN IF NOT EXISTS followup_stage TEXT NOT NULL DEFAULT 'initial';

-- Drop any existing CHECK on followup_stage from a prior migration
-- attempt (idempotency for partial reruns) then add the canonical one.
ALTER TABLE public.freeze_letters_sent
    DROP CONSTRAINT IF EXISTS freeze_letters_followup_stage_chk;

ALTER TABLE public.freeze_letters_sent
    ADD CONSTRAINT freeze_letters_followup_stage_chk CHECK (
        followup_stage IN (
            'initial',
            'nudge_72h',
            'escalation_7d',
            'silence_14d'
        )
    );

COMMENT ON COLUMN public.freeze_letters_sent.followup_stage IS
    'Monotonic follow-up state machine. Cron progresses initial→nudge_72h '
    '→escalation_7d→silence_14d based on sent_at age and the absence '
    'of a matching freeze_outcomes row.';

COMMENT ON COLUMN public.freeze_letters_sent.last_followup_sent_at IS
    'Timestamp of the most recent cron-issued follow-up email. NULL '
    'until the first 72h nudge fires. Used by the cron to avoid '
    'double-sending during overlapping ticks.';

-- Partial index: only scan letters that haven't hit the terminal
-- silence_14d stage AND haven't received an outcome yet. The cron
-- query joins to freeze_outcomes to filter, but the partial index
-- on followup_stage keeps the candidate set small.
CREATE INDEX IF NOT EXISTS freeze_letters_followup_due_idx
    ON public.freeze_letters_sent (last_followup_sent_at NULLS FIRST, sent_at)
    WHERE followup_stage <> 'silence_14d';


-- ----- freeze_outcomes: extend outcome_type to include silence_14d ----- --
--
-- The follow-up cron writes a freeze_outcomes row with
-- outcome_type='silence_14d' when the 14d stage fires, so the
-- per-issuer prior-learning pipeline can count it as a "did not
-- respond" data point.
--
-- Postgres CHECK constraints can't be ALTERED in place — drop and
-- recreate. Wrapped in the same transaction so the table is never
-- without the constraint.

ALTER TABLE public.freeze_outcomes
    DROP CONSTRAINT IF EXISTS freeze_outcomes_outcome_type_check;

ALTER TABLE public.freeze_outcomes
    ADD CONSTRAINT freeze_outcomes_outcome_type_check CHECK (
        outcome_type IN (
            'acknowledged',
            'request_more_info',
            'declined',
            'partial_freeze',
            'full_freeze',
            'released',
            'returned_to_victim',
            'silence_14d',         -- NEW (v0.21.0)
            'silence_30d',
            'silence_90d'
        )
    );

COMMENT ON CONSTRAINT freeze_outcomes_outcome_type_check ON public.freeze_outcomes IS
    'v0.21.0: added silence_14d so the freeze-followup cron can record '
    'the internal alert stage as a measurable non-response outcome for '
    'the per-issuer priors pipeline.';

COMMIT;
