BEGIN;
-- 006_engagement_tracking.sql
--
-- Tracks Tier-2 engagement state per investigation so the worker
-- can auto-send weekly follow-up status emails to the victim
-- during the 30-day reporting commitment in the engagement letter.
--
-- Engagement lifecycle (manually managed by operator until the
-- admin UI surfaces these controls):
--
--   1. Victim receives diagnostic + victim_summary letter
--      (auto-sent on case completion).
--   2. Victim emails operator confirming Tier 2 engagement
--      (signs the engagement letter).
--   3. Operator runs:
--        UPDATE investigations
--           SET engagement_started_at = NOW(),
--               engagement_fee_paid_usd = 1500
--         WHERE id = '<inv_id>';
--      This activates the follow-up cron for this investigation.
--   4. Worker (--send-followups daily cron) auto-sends a weekly
--      status email to victim.email for 30 days. Each send sets
--      last_followup_sent_at and logs to emails_sent.
--   5. After 30 days OR when operator sets engagement_closed_at,
--      auto-follow-up stops. Operator can re-open by clearing
--      engagement_closed_at.
--
-- The columns are nullable + default NULL so this migration is a
-- pure add — no investigations get auto-engaged on apply.

ALTER TABLE public.investigations
  ADD COLUMN IF NOT EXISTS engagement_started_at timestamptz,
  ADD COLUMN IF NOT EXISTS engagement_closed_at  timestamptz,
  ADD COLUMN IF NOT EXISTS engagement_fee_paid_usd numeric(20, 2),
  ADD COLUMN IF NOT EXISTS last_followup_sent_at timestamptz;

COMMENT ON COLUMN public.investigations.engagement_started_at IS
    'When the victim signed the Tier-2 engagement letter and paid '
    'the incremental engagement fee. NULL = no active engagement '
    '(only the $499 diagnostic was paid).';
COMMENT ON COLUMN public.investigations.engagement_closed_at IS
    'When the operator manually closed the engagement (recovery '
    'complete, victim withdrew, OR auto-close after 30 days). '
    'Auto-follow-up stops once this is set.';
COMMENT ON COLUMN public.investigations.engagement_fee_paid_usd IS
    'Incremental engagement fee paid by the victim, USD. Excludes '
    'the original $499 diagnostic fee (which is on the original '
    'transaction record). Typical: $1,500 for Tier-2, $4,500 for '
    'Tier-3.';
COMMENT ON COLUMN public.investigations.last_followup_sent_at IS
    'Last time the worker sent a follow-up status email for this '
    'engagement. Used by the daily cron to decide which '
    'investigations need a fresh send (>= 6 days since last).';

-- Index for the follow-up cron's eligibility query
CREATE INDEX IF NOT EXISTS investigations_followup_eligibility_idx
    ON public.investigations (engagement_started_at, last_followup_sent_at)
    WHERE engagement_started_at IS NOT NULL
      AND engagement_closed_at IS NULL;

COMMIT;
