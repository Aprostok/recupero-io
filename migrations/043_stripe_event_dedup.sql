-- 043 — Stripe webhook event de-duplication.
--
-- WHY: Stripe explicitly may deliver the same event more than once (at-least-once
-- delivery, plus operator-triggered resends). `billing.apply_webhook_event` maps
-- `invoice.paid` to a period reset (`period_start = now()`,
-- `trace_used_period = 0`), so a duplicate delivery silently re-granted the org a
-- fresh monthly quota — repeatable for free. There was no dedup anywhere: 038
-- added idempotency for TRACE submits (`investigations.idempotency_key`) but
-- nothing for billing events.
--
-- The table is intentionally minimal: the event id is the natural key, and a
-- plain INSERT ... ON CONFLICT DO NOTHING gives us atomic "first delivery wins"
-- without a read-then-write race.

BEGIN;

CREATE TABLE IF NOT EXISTS public.stripe_events (
    -- Stripe's own event id (e.g. "evt_1P..."). Natural primary key.
    event_id     text        PRIMARY KEY,
    event_type   text,
    -- Which org the event resolved to, when known. FK is nullable + SET NULL so
    -- purging an org never deletes the billing audit trail.
    org_id       uuid        REFERENCES public.organizations(id) ON DELETE SET NULL,
    applied      boolean     NOT NULL DEFAULT false,
    received_at  timestamptz NOT NULL DEFAULT now()
);

-- Operational queries: "what did Stripe send us recently", newest first.
CREATE INDEX IF NOT EXISTS stripe_events_received_at_idx
    ON public.stripe_events (received_at DESC);

COMMENT ON TABLE public.stripe_events IS
    'Processed Stripe webhook event ids — replay guard so a duplicate delivery '
    'cannot re-apply a plan change or re-grant monthly quota.';

COMMIT;
