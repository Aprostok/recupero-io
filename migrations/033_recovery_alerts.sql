-- 033_recovery_alerts.sql
--
-- v0.35.30 (D6 persistence): persisted proactive recovery alerts so the
-- operator console can surface the "act-now / freeze-NOW" queue BETWEEN watch
-- ticks. D6 (recovery_alerts.evaluate_recovery_alerts) derives a prioritized
-- RecoveryAlert per material change from each watch tick; previously those were
-- ephemeral (only in the in-memory WatchTickReport). This table stores them so
-- GET /v1/recovery-alerts can show the live queue.
--
-- Additive + safe to run mid-deploy. The watch-tick persist is guarded
-- (table-missing is caught + logged, never breaks the tick) and the API read
-- degrades to an empty list when the table / DSN is absent — so deploying the
-- code before this migration is applied is non-fatal.
--
-- Apply with: python -m recupero.ops apply-migration migrations/033_recovery_alerts.sql

BEGIN;

CREATE TABLE IF NOT EXISTS public.recovery_alerts (
    id                 BIGSERIAL   PRIMARY KEY,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    tick_started_at    TIMESTAMPTZ,
    address            TEXT        NOT NULL,
    chain              TEXT        NOT NULL,
    severity           TEXT        NOT NULL,   -- 'critical' | 'high'
    kind               TEXT        NOT NULL,   -- freezable_outflow | tracked_outflow | dormant_reactivation | freezable_inflow
    delta_usd          TEXT,                   -- formatted, finite-guarded (string, as produced by D6)
    dormant_days       INTEGER,
    role               TEXT,
    label_name         TEXT,
    message            TEXT,
    recommended_action TEXT,
    status             TEXT        NOT NULL DEFAULT 'open',  -- 'open' | 'acknowledged'
    -- Dedup: one row per (address, chain, kind, tick). A replayed tick won't
    -- duplicate, but a NEW tick re-alerts a still-moving address.
    dedup_key          TEXT        NOT NULL,
    UNIQUE (dedup_key)
);

COMMENT ON TABLE public.recovery_alerts IS
    'v0.35.30 (D6): persisted proactive recovery alerts (act-now freeze prompts) '
    'derived from watch-tick material changes. Read by GET /v1/recovery-alerts; '
    'written (guarded) by the watch tick. dedup_key = address|chain|kind|tick.';

-- Recent-first listing for the console.
CREATE INDEX IF NOT EXISTS recovery_alerts_recent_idx
    ON public.recovery_alerts (created_at DESC);
-- Open/severity triage filter.
CREATE INDEX IF NOT EXISTS recovery_alerts_status_sev_idx
    ON public.recovery_alerts (status, severity);

COMMIT;
