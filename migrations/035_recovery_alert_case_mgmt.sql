-- 035_recovery_alert_case_mgmt.sql
--
-- v0.38 (enterprise non-data #10): KYT alert CASE-MANAGEMENT — turn the
-- recovery-alerts queue (033) into a triage workflow a compliance team can
-- actually run: assign an owner, move an alert through a lifecycle
-- (open → acknowledged → in_progress → resolved | dismissed), and attach a
-- resolution note. Every transition is audit-logged (034).
--
-- Additive columns on the existing public.recovery_alerts table; the status
-- column already exists (TEXT, no CHECK constraint) so the wider lifecycle
-- vocabulary needs no schema change — only the new ownership/notes columns.
-- Safe to run mid-deploy: the case-update path is admin-gated and the read
-- path tolerates the new columns being NULL.
--
-- Apply with: python -m recupero.ops apply-migration migrations/035_recovery_alert_case_mgmt.sql

BEGIN;

ALTER TABLE public.recovery_alerts
    ADD COLUMN IF NOT EXISTS assignee          TEXT,
    ADD COLUMN IF NOT EXISTS resolution_note    TEXT,
    ADD COLUMN IF NOT EXISTS status_changed_at  TIMESTAMPTZ;

COMMENT ON COLUMN public.recovery_alerts.assignee IS
    'v0.38 #10: case-management owner (operator/analyst handling this alert).';
COMMENT ON COLUMN public.recovery_alerts.resolution_note IS
    'v0.38 #10: free-text note recorded on a status transition (e.g. resolution).';
COMMENT ON COLUMN public.recovery_alerts.status_changed_at IS
    'v0.38 #10: when status last changed (set by the case-update path).';

-- Triage filter: open/assigned work by owner.
CREATE INDEX IF NOT EXISTS recovery_alerts_assignee_idx
    ON public.recovery_alerts (assignee);

COMMIT;
