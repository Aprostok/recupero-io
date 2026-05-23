BEGIN;
-- 009_kyc_confirmation.sql
--
-- INVESTIGATE → FREEZABLE promotion path. When an issuer's
-- compliance team confirms an INVESTIGATE address's KYC over
-- email ("yes, we host that wallet; here is what we know"), the
-- operator runs:
--
--    recupero-ops promote-freezable <watchlist_id>
--        --reason "Circle confirmed KYC on 2026-05-20 via case ticket #1234"
--
-- That command flips is_freezeable to TRUE AND sets the columns
-- this migration adds. The kyc_* columns surface "why is this
-- freezeable?" — without them, freezeable status is just a bool
-- with no provenance, which is bad for audit.
--
-- Why on watchlist (not investigations)? The freezability
-- classification is a per-address property — the same victim's
-- funds can end up at multiple issuers (some KYC-confirmed,
-- some still under investigation), so it lives on the watchlist
-- row, not the case-wide investigation row.

ALTER TABLE public.watchlist
  ADD COLUMN IF NOT EXISTS kyc_confirmed_at        timestamptz,
  ADD COLUMN IF NOT EXISTS kyc_confirmed_by_operator text,
  ADD COLUMN IF NOT EXISTS kyc_confirmation_note   text;

COMMENT ON COLUMN public.watchlist.kyc_confirmed_at IS
    'When an operator promoted this watchlist row from INVESTIGATE '
    'to FREEZABLE based on issuer compliance confirmation. NULL = '
    'either still INVESTIGATE, or was FREEZABLE from initial '
    'classification (e.g., Tether USDT on a known issuer-controlled '
    'address) and never needed promotion.';
COMMENT ON COLUMN public.watchlist.kyc_confirmed_by_operator IS
    'Free-form operator identifier (email, name, or "auto"). Surfaces '
    '"who promoted this?" on the audit page.';
COMMENT ON COLUMN public.watchlist.kyc_confirmation_note IS
    'Required free-form reason recorded at promotion time. Should '
    'include the source of the confirmation (issuer ticket number, '
    'email thread, etc.) so we can re-verify later if challenged.';

-- Partial index for the dashboard's recently-promoted alert query.
CREATE INDEX IF NOT EXISTS watchlist_recently_promoted_idx
    ON public.watchlist (kyc_confirmed_at DESC)
 WHERE kyc_confirmed_at IS NOT NULL;

COMMIT;
