-- 037_multitenancy.sql — the SaaS tenancy foundation.
--
-- Turns the single-tenant engine (flat named API keys, un-scoped
-- `investigations` queue) into a multi-tenant SaaS: organizations, users,
-- memberships, org-scoped API keys, and per-org usage metering. Every
-- tenant-owned row carries `org_id`; the app enforces `WHERE org_id = $current`
-- and Row-Level Security is enabled as defense-in-depth (the worker connects
-- with the service role, which bypasses RLS to drain the global queue).
--
-- Idempotent (IF NOT EXISTS) so it is safe to re-run. Backfills the existing
-- `investigations` rows onto a system org so nothing is orphaned.

BEGIN;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "citext";     -- case-insensitive email

-- ── organizations ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.organizations (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                text NOT NULL,
    slug                text NOT NULL UNIQUE,
    plan                text NOT NULL DEFAULT 'free',          -- free | pro | enterprise
    stripe_customer_id  text,
    -- rolling usage window for quota enforcement
    period_start        timestamptz NOT NULL DEFAULT now(),
    trace_used_period   integer NOT NULL DEFAULT 0,
    status              text NOT NULL DEFAULT 'active',         -- active | suspended
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

-- ── users (global identity; may belong to many orgs) ────────────────────────
CREATE TABLE IF NOT EXISTS public.users (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email             citext NOT NULL UNIQUE,
    password_hash     text NOT NULL,                            -- scrypt$… (never plaintext)
    name              text,
    email_verified_at timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    last_login_at     timestamptz
);

-- ── memberships (user ↔ org, with role) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.memberships (
    org_id     uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    role       text NOT NULL DEFAULT 'member',                 -- owner | admin | member | viewer
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX IF NOT EXISTS memberships_user_idx ON public.memberships (user_id);

-- ── org API keys (programmatic access; only a hash is stored) ────────────────
CREATE TABLE IF NOT EXISTS public.org_api_keys (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    name         text NOT NULL,
    key_hash     text NOT NULL UNIQUE,                          -- sha256 hex of the plaintext key
    last4        text NOT NULL,
    created_by   uuid REFERENCES public.users(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);
CREATE INDEX IF NOT EXISTS org_api_keys_org_idx ON public.org_api_keys (org_id) WHERE revoked_at IS NULL;

-- ── usage metering (append-only; drives billing + quota) ─────────────────────
CREATE TABLE IF NOT EXISTS public.usage_events (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id           uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    kind             text NOT NULL,                             -- trace_submitted | trace_completed | screen | …
    quantity         integer NOT NULL DEFAULT 1,
    investigation_id uuid,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS usage_events_org_time_idx ON public.usage_events (org_id, created_at DESC);

-- ── scope the existing job queue to a tenant ─────────────────────────────────
-- The `investigations` queue (drained by workers via FOR UPDATE SKIP LOCKED)
-- predates tenancy. Add org_id + submitted_by, backfill onto a system org.
ALTER TABLE IF EXISTS public.investigations
    ADD COLUMN IF NOT EXISTS org_id       uuid REFERENCES public.organizations(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS submitted_by uuid REFERENCES public.users(id) ON DELETE SET NULL;

INSERT INTO public.organizations (id, name, slug, plan, status)
VALUES ('00000000-0000-0000-0000-000000000000', 'System (legacy)', 'system', 'enterprise', 'active')
ON CONFLICT (id) DO NOTHING;

UPDATE public.investigations
   SET org_id = '00000000-0000-0000-0000-000000000000'
 WHERE org_id IS NULL;

CREATE INDEX IF NOT EXISTS investigations_org_idx ON public.investigations (org_id);

-- ── Row-Level Security (defense-in-depth) ────────────────────────────────────
-- App code already scopes every query by org_id; RLS is the belt-and-suspenders
-- layer for any future direct-DB access path. The worker/service role bypasses
-- RLS (BYPASSRLS) to process the global queue; per-request connections should
-- SET LOCAL app.current_org = '<uuid>' and rely on these policies.
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.memberships   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.org_api_keys  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.usage_events  ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'org_isolation_keys') THEN
        CREATE POLICY org_isolation_keys ON public.org_api_keys
            USING (org_id::text = current_setting('app.current_org', true));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'org_isolation_usage') THEN
        CREATE POLICY org_isolation_usage ON public.usage_events
            USING (org_id::text = current_setting('app.current_org', true));
    END IF;
END$$;

COMMIT;
