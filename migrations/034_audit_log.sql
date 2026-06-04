-- 034_audit_log.sql
--
-- v0.38 (enterprise-readiness, SOC 2 CC6/CC7): an append-only audit log of
-- security-sensitive actions — who did what, when, to which target, and the
-- outcome. The first concrete control toward SOC 2 / enterprise procurement
-- (the #1 non-data gap vs Chainalysis/TRM/Elliptic).
--
-- Scope (v1): trusted-data mutations — label-candidate PROMOTE / REJECT (which
-- change the curated label set a forensic deliverable relies on). Broader
-- coverage (all admin endpoints) is wired the same way over time.
--
-- Append-only by convention: writers only INSERT; there is no UPDATE/DELETE
-- path in the store. Additive + safe to run mid-deploy — the recorder is
-- guarded (table-missing / DB error is caught + logged, NEVER breaks the action
-- being audited) and the read endpoint degrades to an empty list when the
-- table / DSN is absent.
--
-- Apply with: python -m recupero.ops apply-migration migrations/034_audit_log.sql

BEGIN;

CREATE TABLE IF NOT EXISTS public.audit_log (
    id           BIGSERIAL   PRIMARY KEY,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor        TEXT        NOT NULL,   -- API-key name / reviewer email / 'system'
    action       TEXT        NOT NULL,   -- e.g. 'label.promote' | 'label.reject'
    target       TEXT,                   -- the object acted on (address, candidate id…)
    target_kind  TEXT,                   -- 'label_candidate' | 'address' | 'case' …
    outcome      TEXT        NOT NULL DEFAULT 'success',  -- 'success' | 'failure'
    source_ip    TEXT,                   -- request client IP when available
    metadata     JSONB       NOT NULL DEFAULT '{}'::jsonb  -- non-secret context
);

COMMENT ON TABLE public.audit_log IS
    'v0.38 SOC 2 CC6/CC7: append-only audit trail of security-sensitive actions '
    '(trusted-data mutations: label promote/reject, …). Written guarded by the '
    'action sites; read by GET /v1/audit. NEVER stores secrets / API keys.';

-- Recent-first listing for the console.
CREATE INDEX IF NOT EXISTS audit_log_recent_idx
    ON public.audit_log (occurred_at DESC);
-- Per-actor + per-action filters.
CREATE INDEX IF NOT EXISTS audit_log_actor_idx  ON public.audit_log (actor);
CREATE INDEX IF NOT EXISTS audit_log_action_idx ON public.audit_log (action);

COMMIT;
