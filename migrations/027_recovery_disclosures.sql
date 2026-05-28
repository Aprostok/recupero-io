-- 027_recovery_disclosures.sql
--
-- v0.32 Tier-0 gap #2 — honest recovery-rate disclosure.
--
-- Every customer who lands on the intake portal sees a quantitative
-- recovery-rate disclosure BEFORE being shown the Stripe checkout
-- button. They must tick an "I understand" checkbox to proceed.
--
-- This table is the legal audit trail of that interaction:
--   * What rate were they shown?
--   * When?
--   * Did they tick the acknowledge box, and when?
--
-- Critical for defending against "you told me I'd get my money back"
-- complaints in customer-support escalations or chargeback disputes.
-- Per docs/WHY_RECUPERO_WOULD_FAIL.md §0.2 — without this row, the
-- first paying customer who recovers $0 generates word-of-mouth that
-- destroys the funnel; with this row, we have a contemporaneous
-- defensible record that they were warned in writing.
--
-- Apply with: python scripts/apply_migration.py migrations/027_recovery_disclosures.sql

BEGIN;

CREATE TABLE IF NOT EXISTS public.recovery_disclosures (
    id                              BIGSERIAL PRIMARY KEY,

    -- Which case (intake row) saw the disclosure. NOT FK-constrained
    -- because the intake GET handler creates a placeholder
    -- disclosure row BEFORE the cases row is finalized in some
    -- code paths (defense-in-depth ordering). Operators can
    -- reconstruct the linkage via case_id at audit time.
    case_id                         UUID NOT NULL,

    shown_at_utc                    TIMESTAMPTZ NOT NULL,

    -- The point-in-time disclosure values.
    rate_displayed                  FLOAT NOT NULL,
    ci_low                          FLOAT NOT NULL,
    ci_high                         FLOAT NOT NULL,
    sample_size                     INT NOT NULL,
    is_our_data                     BOOLEAN NOT NULL,
    industry_baseline_used          TEXT,

    -- Did the customer tick the box, and when? GET-path inserts a row
    -- with customer_acknowledged=FALSE; POST-path inserts a separate
    -- row with customer_acknowledged=TRUE so the timeline preserves
    -- BOTH the initial display + the affirmative click.
    customer_acknowledged           BOOLEAN NOT NULL DEFAULT FALSE,
    customer_acknowledged_at_utc    TIMESTAMPTZ
);

-- Lookup index — operator support team will query by case_id when
-- responding to a customer complaint.
CREATE INDEX IF NOT EXISTS recovery_disclosures_case_idx
    ON public.recovery_disclosures (case_id, shown_at_utc DESC);

-- Time-window index for ops reporting ("how many disclosures last week?").
CREATE INDEX IF NOT EXISTS recovery_disclosures_shown_idx
    ON public.recovery_disclosures (shown_at_utc DESC);

COMMENT ON TABLE public.recovery_disclosures IS
    'Legal audit trail: every customer-facing recovery-rate '
    'disclosure on /v1/intake. Critical for defending against '
    'misrepresentation claims later.';

COMMIT;
