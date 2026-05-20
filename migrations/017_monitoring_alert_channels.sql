-- 017_monitoring_alert_channels.sql
--
-- v0.21.0 — Live-filing capability: extend monitoring_subscriptions
-- to support fan-out across multiple alert channels (webhook + email)
-- per subscription. Pre-v0.21.0 every subscription had exactly one
-- webhook URL; an investigator who wanted both an integration ping
-- AND a personal email had to create two subscriptions with
-- different `created_by` values, defeating the per-creator UNIQUE
-- constraint and doubling the polling load.
--
-- Adds:
--   * alert_channels    — text[] of {'webhook', 'email'} (default
--                         ['webhook'] preserves pre-v0.21.0 behavior)
--   * alert_email       — recipient address for the email channel
--                         (nullable; only required when 'email' is
--                         in alert_channels)
--   * webhook_url now NULLABLE — so an email-only subscription is
--     legal. A CHECK constraint enforces "at least one channel must
--     have its target configured".
--
-- And extends monitoring_alerts to journal per-channel results in
-- ONE row per alert (vs. two rows that would inflate the audit log
-- and break the existing subscription_id+fired_at index):
--   * email_status_code     — 0 ok / 1 fail / NULL not-attempted
--   * email_message_id      — Resend message_id on success
--   * email_to              — captured recipient (for audit even if
--                             the subscription's alert_email later
--                             changes)
--   * email_error_message   — Resend error body / URLError reason
--
-- Backward compatibility:
--   * Pre-v0.21.0 rows get alert_channels=['webhook'] via the
--     default. No code change needed for existing subscriptions.
--   * Code that reads webhook_succeeded keeps working. v0.22.0
--     may rename to delivery_succeeded once all readers are updated.
--
-- Apply with: python scripts/apply_migration.py migrations/017_monitoring_alert_channels.sql

BEGIN;

-- ----- monitoring_subscriptions: alert_channels + alert_email ----- --

ALTER TABLE public.monitoring_subscriptions
    ADD COLUMN IF NOT EXISTS alert_channels TEXT[] NOT NULL
        DEFAULT ARRAY['webhook']::TEXT[];

ALTER TABLE public.monitoring_subscriptions
    ADD COLUMN IF NOT EXISTS alert_email TEXT;

-- Relax the webhook_url NOT NULL constraint so an email-only
-- subscription is representable. The CHECK below replaces the
-- guarantee with a per-channel requirement.
ALTER TABLE public.monitoring_subscriptions
    ALTER COLUMN webhook_url DROP NOT NULL;

-- Validate every active channel has its target set. This is a
-- row-level check so concurrent migrations don't have to wait on
-- a table scan.
--
-- 'webhook' in alert_channels → webhook_url IS NOT NULL
-- 'email'   in alert_channels → alert_email IS NOT NULL
-- alert_channels must be non-empty
ALTER TABLE public.monitoring_subscriptions
    ADD CONSTRAINT monitor_sub_channel_targets_present CHECK (
        cardinality(alert_channels) > 0
        AND (NOT ('webhook' = ANY(alert_channels)) OR webhook_url IS NOT NULL)
        AND (NOT ('email'   = ANY(alert_channels)) OR alert_email IS NOT NULL)
    );

COMMENT ON COLUMN public.monitoring_subscriptions.alert_channels IS
    'Fan-out channels for this subscription. Currently {webhook, email}; '
    'defaults to {webhook} for pre-v0.21.0 rows.';

COMMENT ON COLUMN public.monitoring_subscriptions.alert_email IS
    'Recipient address when the email channel is active. Defaults '
    'to NULL; the channel-targets-present CHECK requires it when '
    'alert_channels contains ''email''.';

-- ----- monitoring_alerts: per-channel result columns ----- --

ALTER TABLE public.monitoring_alerts
    ADD COLUMN IF NOT EXISTS email_status_code INTEGER;
    -- Sentinel: 0 = send succeeded (Resend 2xx), 1 = send failed,
    -- NULL = email channel not attempted on this alert (subscription
    -- had only the webhook channel, or per-sub daily quota tripped).

ALTER TABLE public.monitoring_alerts
    ADD COLUMN IF NOT EXISTS email_message_id TEXT;

ALTER TABLE public.monitoring_alerts
    ADD COLUMN IF NOT EXISTS email_to TEXT;

ALTER TABLE public.monitoring_alerts
    ADD COLUMN IF NOT EXISTS email_error_message TEXT;

COMMENT ON COLUMN public.monitoring_alerts.email_status_code IS
    '0 = email sent, 1 = email failed, NULL = email channel not attempted. '
    'Webhook result lives in webhook_status_code (HTTP status) separately.';

COMMENT ON COLUMN public.monitoring_alerts.email_to IS
    'Recipient captured at dispatch time. Preserved even if the '
    'subscription''s alert_email is later updated.';

-- Convenience index: find recent email-channel sends per subscription
-- for the per-sub daily quota check. Without this, the v0.21.0 daily
-- quota lookup (described in dispatcher.py::_email_quota_exhausted)
-- would scan the whole alerts table per dispatch on a hot subscription.
CREATE INDEX IF NOT EXISTS monitor_alerts_email_quota_idx
    ON public.monitoring_alerts (subscription_id, fired_at DESC)
    WHERE email_status_code IS NOT NULL;

COMMIT;
