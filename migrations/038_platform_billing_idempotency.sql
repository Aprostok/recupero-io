-- 038_platform_billing_idempotency.sql — make the SaaS layer BILLABLE + retry-safe.
--
-- (a) Billing linkage on organizations so Stripe webhooks can map an event's
--     customer/subscription back to the tenant and drive plan/status/period.
-- (b) Idempotency on the paid async endpoint: a client that retries
--     POST /v2/traces with the same Idempotency-Key must NOT be charged twice
--     nor enqueue a duplicate job. Enforced by a UNIQUE(org_id, idempotency_key)
--     on the existing queue — a retry conflicts and replays the original id.
--
-- Idempotent (IF NOT EXISTS); safe to re-run.

BEGIN;

-- (a) billing linkage ────────────────────────────────────────────────────────
ALTER TABLE IF EXISTS public.organizations
    ADD COLUMN IF NOT EXISTS stripe_subscription_id text,
    ADD COLUMN IF NOT EXISTS stripe_price_id        text,
    ADD COLUMN IF NOT EXISTS plan_renews_at         timestamptz;

-- Fast lookup from a Stripe webhook (event carries the customer id).
CREATE INDEX IF NOT EXISTS organizations_stripe_customer_idx
    ON public.organizations (stripe_customer_id)
    WHERE stripe_customer_id IS NOT NULL;

-- (b) idempotent trace submission ─────────────────────────────────────────────
ALTER TABLE IF EXISTS public.investigations
    ADD COLUMN IF NOT EXISTS idempotency_key text;

-- One (org, key) maps to exactly one job. A retry hits this and we replay the
-- original investigation id instead of enqueuing (and metering) a second time.
CREATE UNIQUE INDEX IF NOT EXISTS investigations_org_idempotency_uidx
    ON public.investigations (org_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

COMMIT;
