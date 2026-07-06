-- 039_org_invites.sql — team collaboration for the SaaS layer.
--
-- A multi-tenant product needs a way to add teammates to an org. Memberships
-- already exist (037); this adds the INVITE flow: an owner/admin creates an
-- invite (email + role), we store only a hash of the single-use token (the
-- plaintext goes in the emailed link), and the invitee accepts it — creating a
-- membership, seat-quota permitting.
--
-- Idempotent (IF NOT EXISTS); safe to re-run.
--
-- Apply with: python -m recupero.ops apply-migration migrations/039_org_invites.sql

BEGIN;

CREATE TABLE IF NOT EXISTS public.org_invites (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    email       citext NOT NULL,
    role        text NOT NULL DEFAULT 'member',        -- admin | member | viewer
    token_hash  text NOT NULL UNIQUE,                  -- sha256 of the single-use token
    invited_by  uuid REFERENCES public.users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    accepted_at timestamptz,
    accepted_by uuid REFERENCES public.users(id) ON DELETE SET NULL
);

-- Pending invites for an org (the console listing).
CREATE INDEX IF NOT EXISTS org_invites_org_pending_idx
    ON public.org_invites (org_id) WHERE accepted_at IS NULL;

-- At most ONE pending invite per (org, email) — re-inviting replaces, never
-- duplicates (enforced in the DAO by clearing a prior pending row first).
CREATE UNIQUE INDEX IF NOT EXISTS org_invites_pending_uidx
    ON public.org_invites (org_id, email) WHERE accepted_at IS NULL;

-- Defense-in-depth: same per-org RLS posture as the other tenant tables (037).
ALTER TABLE public.org_invites ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'org_isolation_invites') THEN
        CREATE POLICY org_isolation_invites ON public.org_invites
            USING (org_id::text = current_setting('app.current_org', true));
    END IF;
END$$;

COMMIT;
