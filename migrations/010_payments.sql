-- 010_payments.sql
--
-- Stripe payment-event audit trail + idempotency. Every payment
-- the worker processes (via the /webhooks/stripe handler) lands
-- here as one row keyed by stripe_event_id. The UNIQUE constraint
-- on stripe_event_id is the idempotency boundary — Stripe retries
-- failed webhooks up to 3 days, so the same event_id can arrive
-- many times; we record once and skip duplicates.
--
-- Why a payments table (not just additional columns on cases):
--   - Both $499 diagnostic and $1,500 engagement payments need
--     audit history; columns on cases would only show the latest.
--   - Refunds + chargebacks need their own rows (status=refunded /
--     status=disputed); a single column can't model that.
--   - A separate table cleanly isolates Stripe-vendor concerns
--     from the cases / investigations domain model.
--
-- Linkage to the workflow:
--   - metadata.case_id (Stripe Checkout Session metadata) → case_id
--   - metadata.investigation_id (when known) → investigation_id
--   - amount_type ('diagnostic' | 'engagement' | 'contingent' |
--     'unknown') → which workflow gate the payment unlocks.

CREATE TABLE IF NOT EXISTS public.payments (
    id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Stripe event + object IDs. event_id is unique (idempotency);
    -- checkout_session_id and payment_intent_id are populated when
    -- the event payload carries them (some webhook event types
    -- don't include the Checkout Session — e.g., refunds reference
    -- the PaymentIntent only).
    stripe_event_id          text NOT NULL UNIQUE,
    stripe_event_type        text NOT NULL,
    stripe_checkout_session_id text,
    stripe_payment_intent_id text,

    -- Workflow linkage. case_id is set when the Checkout Session
    -- metadata carries it (the operator-side Stripe Dashboard
    -- entry includes `case_id=<uuid>` in the session metadata).
    -- investigation_id is set later by the dispatcher when it
    -- correlates the payment with a specific investigation row
    -- (e.g., engagement fee for a particular investigation).
    case_id                  uuid REFERENCES public.cases(id) ON DELETE SET NULL,
    investigation_id         uuid REFERENCES public.investigations(id) ON DELETE SET NULL,

    -- Payment classification. Set by the dispatcher from the
    -- Checkout Session metadata's `type` field. 'unknown' is the
    -- conservative default so unparseable payments get logged
    -- (with a warning) instead of dropped silently.
    amount_type              text NOT NULL DEFAULT 'unknown'
        CHECK (amount_type IN (
            'diagnostic',     -- $499 first-pay (triggers investigation)
            'engagement',     -- $1,500 Tier-2 fee (activates engagement)
            'contingent',     -- 15% on recovered funds (future)
            'unknown'         -- couldn't classify — audit-only
        )),

    -- Amount + currency, captured verbatim from the Stripe event.
    -- We store amount in CENTS (Stripe's native unit) to avoid
    -- floating-point rounding bugs. amount_usd is a generated
    -- decimal for convenience.
    amount_cents             integer NOT NULL,
    currency                 text NOT NULL DEFAULT 'usd',
    amount_usd               numeric(20, 2) GENERATED ALWAYS AS (
        amount_cents::numeric / 100.0
    ) STORED,

    -- Payment status. Mirrors Stripe's Checkout Session payment
    -- status taxonomy: 'paid' for completed, 'unpaid' for sessions
    -- that expired without payment, 'refunded' / 'disputed' for
    -- post-payment events.
    status                   text NOT NULL
        CHECK (status IN ('paid', 'unpaid', 'refunded', 'disputed')),

    -- Full event payload for forensic re-processing. JSONB so we
    -- can index sub-fields if we ever need to (e.g., search by
    -- customer email).
    raw_event                jsonb NOT NULL,

    -- Audit timestamps.
    received_at              timestamptz NOT NULL DEFAULT NOW(),
    processed_at             timestamptz,

    -- Free-form notes the dispatcher writes when something
    -- non-fatal happened (e.g., 'metadata.case_id missing, manual
    -- linkage required'). Surfaces on the dashboard for operator
    -- triage.
    notes                    text
);

CREATE INDEX IF NOT EXISTS payments_case_id_idx
    ON public.payments (case_id);
CREATE INDEX IF NOT EXISTS payments_investigation_id_idx
    ON public.payments (investigation_id);
CREATE INDEX IF NOT EXISTS payments_received_at_idx
    ON public.payments (received_at DESC);

COMMENT ON TABLE public.payments IS
    'Stripe payment-event audit trail with idempotency on '
    'stripe_event_id. One row per webhook event, regardless of '
    'whether it succeeded or required operator triage.';
