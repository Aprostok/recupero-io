-- 012_monitoring_subscriptions.sql
--
-- Live address monitoring subscriptions + dispatch audit trail.
--
-- The watchlist table already records every address Recupero has
-- ever observed. This migration adds two new tables:
--
--   * monitoring_subscriptions — operator-created "watch this
--     address" rules. Carries the webhook URL to ping when a
--     trigger fires, the threshold (e.g. notify on ANY movement /
--     movement above $X / balance drop / OFAC contact).
--
--   * monitoring_alerts — one row per dispatched alert (success
--     or failure). Lets the operator answer "did the webhook
--     actually fire?" and "which alerts hit retry exhaustion?".
--
-- The monitoring worker (worker/monitor_tick.py) polls Esplora /
-- Etherscan / TronGrid for each active subscription on a cron
-- schedule, compares the latest tx to the subscription's
-- ``last_observed_tx_hash``, and fires the webhook on threshold
-- match.
--
-- Apply with: python scripts/apply_migration.py migrations/012_monitoring_subscriptions.sql

BEGIN;

-- ----- monitoring_subscriptions ----- --
CREATE TABLE IF NOT EXISTS public.monitoring_subscriptions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- What to watch.
    address                 TEXT NOT NULL,
    chain                   TEXT NOT NULL,

    -- Optional linkage to a case / investigation. NULL is allowed
    -- for standalone-subscription use cases (compliance teams
    -- watching addresses without an associated case).
    case_id                 UUID REFERENCES public.cases(id) ON DELETE SET NULL,
    investigation_id        UUID REFERENCES public.investigations(id) ON DELETE SET NULL,

    -- Who created this subscription. Free-form so an operator's
    -- email or a customer's user-id can both fit.
    created_by              TEXT NOT NULL,

    -- Friendly label for ops listing.
    label                   TEXT NOT NULL DEFAULT '(unlabeled)',

    -- Trigger configuration.
    -- 'any_movement'       : fire on any new outflow from address
    -- 'movement_above_usd' : fire when an outflow exceeds threshold_usd
    -- 'balance_drop'       : fire when balance drops below threshold_usd
    -- 'ofac_contact'       : fire when address sends to / receives from
    --                        an OFAC-listed wallet
    trigger_type            TEXT NOT NULL
        CHECK (trigger_type IN (
            'any_movement', 'movement_above_usd',
            'balance_drop', 'ofac_contact'
        )),
    threshold_usd           NUMERIC(20, 2),

    -- Webhook configuration. We POST a JSON payload to webhook_url
    -- and expect 2xx. Failed deliveries are retried with exponential
    -- backoff up to 5 attempts (handled by the worker).
    webhook_url             TEXT NOT NULL,
    webhook_secret          TEXT,  -- optional HMAC-SHA256 signing key

    -- Cursor: last tx_hash we've observed for this address. Set by
    -- the worker on every poll; the worker compares the chain's
    -- latest tx to this to decide whether activity is "new" vs
    -- "already-alerted".
    last_observed_tx_hash   TEXT,
    last_polled_at          TIMESTAMPTZ,
    last_alerted_at         TIMESTAMPTZ,

    -- Subscription lifecycle.
    status                  TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'paused', 'expired', 'deleted')),
    expires_at              TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Defensive uniqueness: same (address, chain, created_by) only
    -- gets one active subscription. Duplicate subscription
    -- creates update in place.
    CONSTRAINT monitor_sub_unique_per_creator
        UNIQUE (address, chain, created_by)
);

CREATE INDEX IF NOT EXISTS monitor_sub_active_idx
    ON public.monitoring_subscriptions (status, address, chain)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS monitor_sub_polling_queue_idx
    ON public.monitoring_subscriptions (last_polled_at NULLS FIRST)
    WHERE status = 'active';

-- ----- monitoring_alerts ----- --
-- One row per webhook-dispatch attempt. Successes AND failures both
-- land here so the operator can audit the full history.
CREATE TABLE IF NOT EXISTS public.monitoring_alerts (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id         UUID NOT NULL REFERENCES
        public.monitoring_subscriptions(id) ON DELETE CASCADE,

    -- What triggered the alert.
    trigger_type            TEXT NOT NULL,
    tx_hash                 TEXT,        -- the new tx that fired the trigger
    explorer_url            TEXT,
    amount_usd              NUMERIC(20, 2),
    counterparty_address    TEXT,        -- the OTHER side of the tx
    counterparty_label      TEXT,        -- OFAC name / mixer name / etc.

    -- Webhook dispatch result.
    webhook_status_code     INTEGER,     -- HTTP response code (NULL on connection error)
    webhook_response_body   TEXT,        -- truncated to 4000 chars
    webhook_attempt_number  INTEGER NOT NULL DEFAULT 1,
    webhook_succeeded       BOOLEAN NOT NULL DEFAULT FALSE,
    webhook_error_message   TEXT,

    -- Audit.
    fired_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at            TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS monitor_alerts_sub_idx
    ON public.monitoring_alerts (subscription_id, fired_at DESC);

CREATE INDEX IF NOT EXISTS monitor_alerts_failed_idx
    ON public.monitoring_alerts (subscription_id, fired_at DESC)
    WHERE webhook_succeeded = FALSE;

COMMENT ON TABLE public.monitoring_subscriptions IS
    'Live address-monitoring subscriptions. Polled by the worker '
    'monitor_tick stage; fires webhooks on trigger conditions.';

COMMENT ON TABLE public.monitoring_alerts IS
    'Audit log of every webhook dispatch attempt (success or '
    'failure). One row per attempt — retries land as additional rows.';

COMMIT;
