-- 013_freeze_outcomes.sql
--
-- Freeze-letter outcome tracking. Every freeze letter the operator
-- sends ends up here with the result the issuer / exchange returned.
-- After 50-100 letters, the aggregated data feeds:
--
--   * Per-issuer freeze-success rates (replacing the heuristic priors
--     in recupero.recovery.scorer).
--   * Per-issuer response-time distributions.
--   * Per-issuer success-by-LE-backing (does an FBI letter materially
--     beat a Recupero-only letter? data answers).
--
-- This is the compounding-moat capability: every recovery the
-- operator runs makes the next one more precise. TRM/Chainalysis
-- can't build this because they're not the requestor.
--
-- Apply with: python scripts/apply_migration.py migrations/013_freeze_outcomes.sql

BEGIN;

-- ----- freeze_letters_sent ----- --
-- One row per outbound freeze request. Created at send-time; updated
-- as the issuer responds (or doesn't).
CREATE TABLE IF NOT EXISTS public.freeze_letters_sent (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Linkage to the originating case + investigation.
    case_id                     UUID REFERENCES public.cases(id) ON DELETE CASCADE,
    investigation_id            UUID REFERENCES public.investigations(id) ON DELETE CASCADE,

    -- Which issuer / address / asset this letter targets.
    issuer                      TEXT NOT NULL,           -- 'Tether', 'Circle', 'Maple Finance', etc.
    target_address              TEXT NOT NULL,            -- the wallet holding the freezable balance
    chain                       TEXT NOT NULL,
    asset_symbol                TEXT NOT NULL,
    requested_freeze_usd        NUMERIC(20, 2) NOT NULL,

    -- Letter content snapshot. Free-form so we can experiment with
    -- different framings and measure which works best.
    letter_subject              TEXT,
    letter_body_excerpt         TEXT,                     -- first 1000 chars for audit
    letter_language             TEXT NOT NULL DEFAULT 'standard'
        CHECK (letter_language IN (
            'standard',          -- baseline operator-drafted
            'le_backed',         -- carries FBI/IC3 reference number
            'ausa_signed',       -- AUSA-signed cover letter
            'mlat_routed',       -- via DOJ-OIA
            '314b',              -- FinCEN 314(b) information sharing
            'subpoena'           -- grand jury subpoena
        )),

    -- Contact channel.
    contact_email               TEXT,
    contact_portal_url          TEXT,

    -- Audit + workflow timestamps.
    sent_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    operator                    TEXT NOT NULL,            -- who hit "send"

    -- Linkage from this freeze letter to its rendered deliverable
    -- (PDF in Supabase Storage; used to re-produce a letter from
    -- the audit trail).
    storage_path                TEXT,

    -- Idempotency guard against accidental double-sends.
    CONSTRAINT freeze_unique_per_issuer_target_case
        UNIQUE (case_id, issuer, target_address, asset_symbol)
);

CREATE INDEX IF NOT EXISTS freeze_letters_case_idx
    ON public.freeze_letters_sent (case_id);
CREATE INDEX IF NOT EXISTS freeze_letters_issuer_idx
    ON public.freeze_letters_sent (issuer, sent_at DESC);


-- ----- freeze_outcomes ----- --
-- One row per outcome event. A single freeze letter can produce
-- multiple outcome events (acknowledged → partial freeze → full
-- freeze → release). We log them all so the time-series can be
-- reconstructed for the per-issuer playbook learning.
CREATE TABLE IF NOT EXISTS public.freeze_outcomes (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    letter_id                   UUID NOT NULL REFERENCES
        public.freeze_letters_sent(id) ON DELETE CASCADE,

    -- What happened.
    outcome_type                TEXT NOT NULL
        CHECK (outcome_type IN (
            'acknowledged',        -- issuer confirms receipt; no action yet
            'request_more_info',   -- issuer asks for KYC / docs
            'declined',            -- issuer says no; reason in notes
            'partial_freeze',      -- some-but-not-all of requested amount frozen
            'full_freeze',         -- requested amount frozen pending resolution
            'released',            -- frozen funds released back to perpetrator (bad)
            'returned_to_victim',  -- recovered to victim wallet (THE WIN)
            'silence_30d',         -- 30+ days no response; treated as decline
            'silence_90d'          -- 90+ days; case-effectively-closed
        )),

    -- Quantity outcome (NULL for non-financial outcome_types like
    -- 'acknowledged' / 'request_more_info').
    frozen_usd                  NUMERIC(20, 2),
    returned_usd                NUMERIC(20, 2),

    -- Audit.
    observed_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    response_text               TEXT,                     -- issuer's actual reply
    operator_notes              TEXT
);

CREATE INDEX IF NOT EXISTS freeze_outcomes_letter_idx
    ON public.freeze_outcomes (letter_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS freeze_outcomes_type_idx
    ON public.freeze_outcomes (outcome_type, observed_at DESC);


-- ----- issuer_freeze_priors ----- --
-- Materialized view-like table that recovery.scorer reads from.
-- Refreshed by a nightly worker stage (or on-demand via
-- `recupero-ops refresh-freeze-priors`).
--
-- Pre-50-letter cases: scorer falls back to hand-coded heuristics
-- because the sample size is too small to be informative.
-- Post-50-letter cases per issuer: scorer reads from this table.
CREATE TABLE IF NOT EXISTS public.issuer_freeze_priors (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer                      TEXT NOT NULL,
    letter_language             TEXT NOT NULL,             -- 'standard' | 'le_backed' | ...
    sample_size                 INTEGER NOT NULL,
    p_any_freeze                NUMERIC(5, 4),             -- 0..1
    p_full_freeze               NUMERIC(5, 4),
    p_returned_to_victim        NUMERIC(5, 4),
    avg_response_hours          NUMERIC(10, 2),
    median_response_hours       NUMERIC(10, 2),
    refreshed_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT issuer_priors_unique_per_issuer_language
        UNIQUE (issuer, letter_language)
);

CREATE INDEX IF NOT EXISTS issuer_priors_lookup_idx
    ON public.issuer_freeze_priors (issuer, letter_language);


COMMENT ON TABLE public.freeze_letters_sent IS
    'Audit trail of every outbound freeze request, with letter '
    'language variant and target.';

COMMENT ON TABLE public.freeze_outcomes IS
    'Per-letter outcome time series. Multiple events per letter '
    'as the issuer''s response evolves.';

COMMENT ON TABLE public.issuer_freeze_priors IS
    'Aggregated per-issuer freeze-success priors, refreshed from '
    'freeze_outcomes. Consumed by recupero.recovery.scorer once '
    'sample_size >= 20 per issuer.';

COMMIT;
