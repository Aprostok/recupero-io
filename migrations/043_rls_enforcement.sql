-- 043_rls_enforcement.sql — make multi-tenant RLS genuinely enforce.
--
-- Prior migrations (037/039/042) ENABLE'd RLS and added USING-only policies on
-- SOME tenant tables, but: (a) organizations/memberships had RLS enabled with NO
-- policy (default-deny), (b) audit_log/investigations had org_id but no RLS, and
-- (c) no table used FORCE, so the owning role bypassed everything. This migration
-- completes the picture so a RESTRICTED api role is genuinely org-scoped.
--
-- Enforcement model (see docs/RLS_ENFORCEMENT_PLAN.md):
--   * The API's per-request connection is a restricted (NOBYPASSRLS, non-owner)
--     role and sets `app.current_org` after auth; policies below scope every row.
--   * Pre-auth lookups (signup/login/resolve_api_key) and the worker/cron run as
--     a service role WITH BYPASSRLS — they intentionally cross the org boundary.
--
-- All policies are USING + WITH CHECK (reads, updates, deletes AND inserts are
-- org-scoped). `users` is global (no org_id) and deliberately has no RLS.

BEGIN;

-- audit_log + investigations were missing RLS entirely.
ALTER TABLE public.audit_log      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.investigations ENABLE ROW LEVEL SECURITY;

-- organizations is keyed by `id` (it IS the org); everything else by `org_id`.
DROP POLICY IF EXISTS org_isolation_orgs ON public.organizations;
CREATE POLICY org_isolation_orgs ON public.organizations
    USING      (id::text = current_setting('app.current_org', true))
    WITH CHECK (id::text = current_setting('app.current_org', true));

-- (org_table, policy_name) pairs scoped by org_id — recreated with WITH CHECK.
DO $$
DECLARE
    t record;
BEGIN
    FOR t IN
        SELECT * FROM (VALUES
            ('memberships',       'org_isolation_members'),
            ('org_api_keys',      'org_isolation_keys'),
            ('usage_events',      'org_isolation_usage'),
            ('org_invites',       'org_isolation_invites'),
            ('audit_log',         'org_isolation_audit'),
            ('investigations',    'org_isolation_investigations'),
            ('watched_addresses', 'org_isolation_watched'),
            ('wallet_alerts',     'org_isolation_wallet_alerts')
        ) AS v(tbl, pol)
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', t.pol, t.tbl);
        EXECUTE format(
            'CREATE POLICY %I ON public.%I '
            'USING (org_id::text = current_setting(''app.current_org'', true)) '
            'WITH CHECK (org_id::text = current_setting(''app.current_org'', true))',
            t.pol, t.tbl);
    END LOOP;
END$$;

-- FORCE so the table-owning role is subject too (belt-and-suspenders: enforcement
-- no longer depends on the api role being a non-owner). The service/worker role
-- keeps BYPASSRLS and is unaffected.
ALTER TABLE public.organizations     FORCE ROW LEVEL SECURITY;
ALTER TABLE public.memberships       FORCE ROW LEVEL SECURITY;
ALTER TABLE public.org_api_keys      FORCE ROW LEVEL SECURITY;
ALTER TABLE public.usage_events      FORCE ROW LEVEL SECURITY;
ALTER TABLE public.org_invites       FORCE ROW LEVEL SECURITY;
ALTER TABLE public.audit_log         FORCE ROW LEVEL SECURITY;
ALTER TABLE public.investigations    FORCE ROW LEVEL SECURITY;
ALTER TABLE public.watched_addresses FORCE ROW LEVEL SECURITY;
ALTER TABLE public.wallet_alerts     FORCE ROW LEVEL SECURITY;

COMMIT;
