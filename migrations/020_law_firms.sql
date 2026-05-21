-- 020_law_firms.sql
--
-- v0.26.0 — Partner law-firm dashboard.
--
-- Recovery counsel referrals are how Recupero scales beyond direct
-- victim-funnel: a law firm sends N clients to the diagnostic, and
-- the firm wants a periodic statement showing
--   * how many of their clients have completed traces
--   * total $ traced + recovered across their portfolio
--   * median time-to-first-letter on referred cases
--   * per-issuer cooperation context relevant to the firm's caseload
--
-- This migration adds:
--
--   * law_firms — one row per partner firm (name, primary contact,
--     status, optional default jurisdiction). The dashboard is
--     keyed on law_firms.id; firms are created manually by ops in
--     v0.26.0 (a self-serve onboarding flow is a later iteration).
--
--   * case_referrals — many-to-one bridge tying a cases.id to the
--     referring law_firms.id. Inserted at case-intake time when
--     the intake form carries a referral_code, OR by ops via a
--     follow-up `recupero-ops` command (v0.26.0 ships ops-managed
--     only; victim-facing referral code field is a later step).
--
-- The dashboard builder
-- (recupero/monitoring/law_firm_dashboard.py) reads here +
-- aggregates from existing cases / investigations / freeze_letters_sent
-- / freeze_outcomes — no new write paths on the hot path of a trace.
--
-- Apply with: python scripts/apply_migration.py migrations/020_law_firms.sql

BEGIN;

-- ----- law_firms ----- --

CREATE TABLE IF NOT EXISTS public.law_firms (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Public-facing handle used in URLs, ops CLI, dashboard
    -- filenames. Lowercase ASCII slug, e.g. 'morgan-stanley-recovery'.
    slug                     TEXT NOT NULL UNIQUE
        CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,60}$'),

    -- Display name shown on the rendered dashboard.
    name                     TEXT NOT NULL,

    -- Primary contact at the firm — the partner Recupero corresponds
    -- with. Optional in v0.26.0 (some firms have group inboxes).
    primary_contact_name     TEXT,
    primary_contact_email    TEXT
        CHECK (
            primary_contact_email IS NULL
            OR primary_contact_email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$'
        ),

    -- Optional jurisdiction hint (ISO country code or US state) so
    -- the dashboard's recommendation column can prefer
    -- jurisdiction-relevant cooperation data when the firm asks
    -- "which issuers should I plan around in my market."
    default_jurisdiction     TEXT,

    -- Lifecycle.
    status                   TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'paused', 'closed', 'archived')),

    notes                    TEXT,

    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS law_firms_status_idx
    ON public.law_firms (status)
    WHERE status = 'active';

COMMENT ON TABLE public.law_firms IS
    'v0.26.0 — Partner law firms. Each firm has its own aggregated '
    'dashboard rendered by recupero/monitoring/law_firm_dashboard.py.';

-- ----- case_referrals ----- --

CREATE TABLE IF NOT EXISTS public.case_referrals (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    law_firm_id              UUID NOT NULL REFERENCES
        public.law_firms(id) ON DELETE RESTRICT,
    case_id                  UUID NOT NULL REFERENCES
        public.cases(id) ON DELETE CASCADE,

    -- Snapshot of the firm's slug at referral time so a firm
    -- rename doesn't rewrite historical referrals. The dashboard
    -- always joins to the live law_firms row by ID, but the slug
    -- snapshot lets the audit log stay readable after renames.
    referred_via_slug        TEXT NOT NULL,

    -- Optional: how the firm tracks this client internally
    -- (their case number / matter ID). Recupero never displays this
    -- to the victim; it appears only on the firm's dashboard.
    firm_internal_matter_id  TEXT,

    -- v0.26.0 — a case can be referred by exactly one firm. If
    -- two firms claim the same case, ops adjudicates manually.
    referred_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes                    TEXT,

    CONSTRAINT case_referrals_one_firm_per_case
        UNIQUE (case_id)
);

CREATE INDEX IF NOT EXISTS case_referrals_by_firm_idx
    ON public.case_referrals (law_firm_id, referred_at DESC);

COMMENT ON TABLE public.case_referrals IS
    'v0.26.0 — One referral per (law_firm, case). Used by the firm '
    'dashboard to aggregate per-firm portfolio metrics.';

COMMIT;
