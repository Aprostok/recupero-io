BEGIN;
-- 008_engagement_signatures.sql
--
-- Audit trail of electronic signatures captured through the
-- customer portal's /portal/<token>/sign flow. When a victim
-- types their full legal name + ticks the agreement box, we
-- record a row here AND set engagement_started_at on the
-- corresponding investigation (the same row recupero-ops
-- mark-engaged would write).
--
-- The portal signature is the lightest-touch e-sign we can do
-- legally — name + intent-to-be-bound + auditable timestamp +
-- request metadata (IP, user-agent). For higher-stakes cases
-- (>$50k recovery) the operator should still get a wet
-- signature or DocuSign envelope. The portal flow is for the
-- typical $5k-$50k victims who just want to get moving fast.
--
-- Schema notes:
--   - One row per signature event. A victim re-signing after a
--     mark-closed → mark-engaged cycle gets a second row.
--   - signature_name is the victim-typed full name. We do NOT
--     try to match this against the case's client_name (legal
--     names change, hyphenation differs); the existence of the
--     signed-name + timestamp is the evidence.
--   - ip_address is TEXT (not inet) because the portal sits
--     behind Railway's edge so the X-Forwarded-For header is the
--     real source; the inet type can't represent the full chain.

CREATE TABLE IF NOT EXISTS public.engagement_signatures (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id           uuid NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    investigation_id  uuid REFERENCES public.investigations(id) ON DELETE SET NULL,
    case_token_id     uuid REFERENCES public.case_tokens(id) ON DELETE SET NULL,

    -- The exact text the victim typed into the name field.
    -- Preserved verbatim for evidentiary value — don't normalize.
    signature_name    text NOT NULL,

    -- Intent confirmation: a copy of the agreement-checkbox text
    -- the victim ticked. Captured at sign time so future changes
    -- to the portal template don't retroactively change what the
    -- victim agreed to.
    agreement_text    text NOT NULL,

    -- Engagement fee the victim committed to at sign time, USD.
    -- The portal pre-fills this from the case's quoted_fee_usd
    -- (or the default $1500 if unset); the recorded value is
    -- what the victim saw + accepted.
    fee_usd           numeric(20, 2) NOT NULL,

    -- When the signature was captured.
    signed_at         timestamptz NOT NULL DEFAULT NOW(),

    -- Request-fingerprint metadata captured for the audit log.
    ip_address        text,
    user_agent        text
);

CREATE INDEX IF NOT EXISTS engagement_signatures_case_id_idx
    ON public.engagement_signatures (case_id);
CREATE INDEX IF NOT EXISTS engagement_signatures_investigation_id_idx
    ON public.engagement_signatures (investigation_id);

COMMENT ON TABLE public.engagement_signatures IS
    'Audit trail of electronic engagement-letter signatures '
    'captured through the customer portal. Existence + signed_at '
    '+ signature_name is the evidence of agreement.';

COMMIT;
