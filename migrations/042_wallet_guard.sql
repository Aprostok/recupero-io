-- 042_wallet_guard.sql — the Wallet Guard (WalletBlock) product.
--
-- A proactive, consumer/SMB-facing protection surface on top of the existing
-- screening engine: an org keeps an ADDRESS BOOK of wallets it watches, gets a
-- pre-send counterparty risk verdict, and accrues ALERTS when a watched address
-- (or an address it just checked) screens risky. This is the persistence layer;
-- the verdict logic lives in `recupero.platform.walletguard` and reuses
-- `screen.screener.screen_address` (offline, <50ms).
--
-- Every row is org-scoped (multi-tenant) with RLS as defense-in-depth, matching
-- 037_multitenancy. Idempotent (IF NOT EXISTS) so it is safe to re-run.

BEGIN;

-- ── watched_addresses: an org's address book / watchlist ─────────────────────
CREATE TABLE IF NOT EXISTS public.watched_addresses (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    chain            text NOT NULL,
    address          text NOT NULL,
    label            text,
    created_by       uuid REFERENCES public.users(id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    -- cached last screen (so the address book renders without a re-screen)
    last_verdict     text CHECK (last_verdict IN
                        ('sanctioned', 'high', 'medium', 'low', 'clean')),
    last_risk_score  integer CHECK (last_risk_score BETWEEN 0 AND 10),
    last_checked_at  timestamptz,
    -- one row per (org, chain, address): re-adding updates the label/screen
    UNIQUE (org_id, chain, address)
);
CREATE INDEX IF NOT EXISTS watched_addresses_org_idx
    ON public.watched_addresses (org_id, created_at DESC);

-- ── wallet_alerts: risk findings surfaced to an org ──────────────────────────
-- Raised when a guard check / watched address screens at or above the alert
-- threshold. watched_address_id is nullable (an ad-hoc pre-send check that was
-- never added to the book still produces an alert).
CREATE TABLE IF NOT EXISTS public.wallet_alerts (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    watched_address_id uuid REFERENCES public.watched_addresses(id) ON DELETE CASCADE,
    chain              text NOT NULL,
    address            text NOT NULL,
    verdict            text NOT NULL CHECK (verdict IN
                          ('sanctioned', 'high', 'medium', 'low', 'clean')),
    severity           integer NOT NULL CHECK (severity BETWEEN 0 AND 10),
    category           text,
    headline           text NOT NULL,
    source             text NOT NULL DEFAULT 'guard_check',   -- guard_check | watch_add | monitor
    created_at         timestamptz NOT NULL DEFAULT now(),
    acknowledged_at    timestamptz,
    acknowledged_by    uuid REFERENCES public.users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS wallet_alerts_org_time_idx
    ON public.wallet_alerts (org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS wallet_alerts_unacked_idx
    ON public.wallet_alerts (org_id, created_at DESC) WHERE acknowledged_at IS NULL;

-- ── Row-Level Security (defense-in-depth) ────────────────────────────────────
-- App code always scopes by org_id; these policies are the belt-and-suspenders
-- layer, mirroring 037. The worker/service role bypasses RLS.
ALTER TABLE public.watched_addresses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.wallet_alerts     ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'org_isolation_watched') THEN
        CREATE POLICY org_isolation_watched ON public.watched_addresses
            USING (org_id::text = current_setting('app.current_org', true));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'org_isolation_wallet_alerts') THEN
        CREATE POLICY org_isolation_wallet_alerts ON public.wallet_alerts
            USING (org_id::text = current_setting('app.current_org', true));
    END IF;
END$$;

COMMIT;
