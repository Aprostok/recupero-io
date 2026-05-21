-- 000_bootstrap_base_tables.sql
--
-- Bootstrap the base tables that every subsequent migration references.
--
-- HISTORICAL GAP (discovered during RIGOR-1, 2026-05-21):
-- Migrations 001-020 all reference `public.cases` and
-- `public.investigations` as if they exist (via foreign keys, JOINs,
-- and ALTER TABLE statements). But neither table was ever defined in
-- a migration — they were created manually in the Supabase admin UI
-- when Jacob first stood up production. A fresh environment could not
-- bootstrap from `migrations/*.sql` alone; new operators were silently
-- on their own.
--
-- This migration is the missing prequel. Idempotent: every CREATE
-- uses IF NOT EXISTS so applying it to a populated Supabase prod DB
-- is a safe no-op.
--
-- Schema is reconstructed from:
--   * src/recupero/worker/db.py  (T_INV, T_CASES + every COL_* constant)
--   * src/recupero/portal/intake.py  (INSERT INTO public.cases)
--   * src/recupero/payments/dispatcher.py  (SELECT / INSERT against both)
--   * worker/dashboard_summary.py  (read-only queries name many columns)
--
-- The pgcrypto extension is required for gen_random_uuid(); enabled
-- here so subsequent migrations don't need to declare it again.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =====================================================================
-- public.cases — one row per customer / victim
-- =====================================================================
CREATE TABLE IF NOT EXISTS public.cases (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Display identifier — looks like "RCP-INTAKE-2026-a1b2c3d4" for
    -- intake-form-created cases, or admin-UI-assigned for cases entered
    -- by an operator. UNIQUE so the portal-confirmation email + the
    -- intake idempotency check can dedupe on it.
    case_number         TEXT        UNIQUE,

    -- Victim / customer identity. client_name + client_email are
    -- required for any case that produces customer-visible artifacts
    -- (engagement letter, victim summary, portal confirmation).
    -- Nullable at the column level for backward compat with rows that
    -- pre-date the intake form.
    client_name         TEXT,
    client_email        TEXT,
    phone               TEXT,                -- COL_CLIENT_PHONE in worker/db.py
    country             TEXT,
    description         TEXT,

    -- Editorial pre-fill (v0.5.2). Populated by the admin-UI intake form
    -- when known so the operator review step is a 30-second sanity check
    -- rather than a re-typing exercise.
    address_line1       TEXT,
    address_line2       TEXT,
    jurisdiction        TEXT,
    ic3_case_id         TEXT,

    -- Incident details.
    incident_date       DATE,
    chain               TEXT,                -- primary chain of the seed_address
    seed_address        TEXT,                -- the victim's wallet that was drained

    -- Workflow state. Values used in code: 'intake', 'active',
    -- 'in_progress', 'complete', 'closed'. We don't enforce a CHECK
    -- here so the admin UI can add new states without a migration.
    status              TEXT        NOT NULL DEFAULT 'intake',

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS cases_status_idx       ON public.cases (status);
CREATE INDEX IF NOT EXISTS cases_created_at_idx   ON public.cases (created_at DESC);
CREATE INDEX IF NOT EXISTS cases_client_email_idx ON public.cases (client_email);

COMMENT ON TABLE public.cases IS
  'One row per customer / victim. Bootstrap-defined in migration 000.';


-- =====================================================================
-- public.investigations — one row per pipeline run on behalf of a case
-- =====================================================================
--
-- Schema MUST match src/recupero/worker/db.py constants (T_INV plus
-- every COL_* near the top of that file). Adding a new column there
-- without a matching migration produces a runtime-only failure on
-- claim_one() — surfaced via the v0.19.2 incident_time_null pattern.
CREATE TABLE IF NOT EXISTS public.investigations (
    id                       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Nullable per worker/db.py docstring: wallet-trace rows (intake
    -- calls, ZachXBT-tagged wallets, internal R&D) have no associated
    -- case row.
    case_id                  UUID        REFERENCES public.cases(id) ON DELETE SET NULL,

    -- Status machine — values defined in worker/state.py.
    -- Active: 'pending','claimed','tracing','editorial','review_required',
    --         'review_approved','emitting','building_package'.
    -- Terminal: 'complete','failed'.
    status                   TEXT        NOT NULL,

    triggered_by             TEXT,
    triggered_at             TIMESTAMPTZ DEFAULT NOW(),

    worker_id                TEXT,
    claimed_at               TIMESTAMPTZ,
    last_heartbeat_at        TIMESTAMPTZ,

    started_at               TIMESTAMPTZ,
    completed_at             TIMESTAMPTZ,
    failed_at                TIMESTAMPTZ,
    review_required_at       TIMESTAMPTZ,

    error_message            TEXT,
    error_stage              TEXT,

    -- Trace inputs.
    chain                    TEXT        NOT NULL,
    seed_address             TEXT        NOT NULL,
    -- Nullable per worker/db.py contract (wallet-trace rows have no
    -- incident moment).
    incident_time            TIMESTAMPTZ,
    max_depth                INTEGER     NOT NULL DEFAULT 1,
    dust_threshold_usd       NUMERIC,

    -- Outputs written by the worker.
    supabase_storage_path    TEXT,
    total_loss_usd           NUMERIC,
    max_recoverable_usd      NUMERIC,
    api_costs_usd            NUMERIC,
    freezable_issuers        JSONB,         -- list[str]

    -- Wallet-trace metadata (Phase 4 — Jacob spec).
    label                    TEXT,
    skip_editorial           BOOLEAN     NOT NULL DEFAULT FALSE,
    skip_freeze_briefs       BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS investigations_status_idx
    ON public.investigations (status);
CREATE INDEX IF NOT EXISTS investigations_case_id_idx
    ON public.investigations (case_id);
CREATE INDEX IF NOT EXISTS investigations_triggered_at_idx
    ON public.investigations (triggered_at DESC);
-- Claim path: claim_one() looks for status IN ('pending','review_approved')
-- ORDER BY triggered_at. A partial index here keeps claim-poll fast even
-- when the table grows large with terminal rows.
CREATE INDEX IF NOT EXISTS investigations_claimable_idx
    ON public.investigations (triggered_at)
    WHERE status IN ('pending', 'review_approved');
-- Reaper path: stale-heartbeat detection scans active rows by heartbeat.
CREATE INDEX IF NOT EXISTS investigations_heartbeat_idx
    ON public.investigations (last_heartbeat_at)
    WHERE status IN ('claimed','tracing','editorial','review_required',
                     'review_approved','emitting','building_package');

COMMENT ON TABLE public.investigations IS
  'One pipeline run. Bootstrap-defined in migration 000; schema must '
  'stay in sync with src/recupero/worker/db.py COL_* constants.';

-- Status-domain CHECK is INTENTIONALLY not declared. The admin-UI
-- repo evolves the state machine independently; adding values here
-- would create a foot-gun where new UI states fail INSERT silently.
-- worker/state.py is the source of truth — code-level guard.

COMMIT;
