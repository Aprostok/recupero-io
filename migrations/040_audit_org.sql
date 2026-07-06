-- 040_audit_org.sql — tenant-scope the audit trail for the SaaS layer.
--
-- The append-only audit_log (034) is SOC 2 CC6/CC7 evidence: who did what. The
-- multi-tenant /v2 layer needs those events scoped to an org so an owner/admin
-- can review their own org's security events (GET /v2/audit). Adds a nullable
-- org_id (legacy /v1 rows leave it NULL) + a per-org recent-first index.
--
-- Idempotent (IF NOT EXISTS); safe to re-run.
--
-- Apply with: python -m recupero.ops apply-migration migrations/040_audit_org.sql

BEGIN;

ALTER TABLE IF EXISTS public.audit_log
    ADD COLUMN IF NOT EXISTS org_id uuid REFERENCES public.organizations(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS audit_log_org_recent_idx
    ON public.audit_log (org_id, occurred_at DESC) WHERE org_id IS NOT NULL;

COMMIT;
