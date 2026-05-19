-- 014_case_token_hmac.sql
--
-- v0.16.12 — Eliminate the portal-token timing side-channel.
--
-- Pre-v0.16.12 the verify-token query was `WHERE token = %s` with
-- `token` being the user-supplied bearer string. Postgres's btree
-- equality short-circuits on the first differing byte, leaking
-- comparison-byte timing information that lets an attacker incrementally
-- guess token prefixes given enough samples. 256 bits of entropy makes
-- a full brute-force infeasible, but combined with the partial index
-- on (token) WHERE revoked_at IS NULL (microsecond-scale lookup), the
-- timing distinguishability over thousands of probes is a real attack.
--
-- The fix:
--   * Add a `token_hmac` column storing HMAC-SHA256(server_pepper, token).
--   * Index the HMAC column instead of (or in addition to) the raw
--     token column.
--   * The app layer hashes the candidate token at lookup time and
--     queries by HMAC. The user-supplied secret is never compared
--     byte-by-byte against the stored value; only the HMAC is.
--
-- The server pepper lives in RECUPERO_TOKEN_PEPPER (32 bytes, base64
-- or hex). Rotating the pepper invalidates every existing token
-- (acceptable — operators can re-issue from the CLI).
--
-- Migration plan:
--   1. ADD COLUMN token_hmac (this migration). NULL allowed initially.
--   2. App ships v0.16.12 with dual-mode lookup: try HMAC first, fall
--      back to raw-token equality if no match (so existing tokens still
--      work during transition).
--   3. Operator runs a one-time backfill script (separate ops command)
--      that hashes every existing token and populates token_hmac.
--   4. Future migration 015 will NOT NULL the column + drop the raw
--      token column once the backfill is verified.
--
-- This file is purely additive — safe to run mid-deploy.

BEGIN;

ALTER TABLE public.case_tokens
    ADD COLUMN IF NOT EXISTS token_hmac TEXT;

-- Indexed lookup by HMAC. Partial-index pattern matches the existing
-- token-by-value index so the hot path remains a single index hit.
-- CREATE INDEX IF NOT EXISTS doesn't take CONCURRENTLY inside a tx;
-- 014 is intentionally fast-running on a small table (Recupero has
-- ~hundreds of rows, not millions) so a brief exclusive lock here is
-- acceptable. Larger deployments should split into a separate file
-- without BEGIN/COMMIT.
CREATE INDEX IF NOT EXISTS case_tokens_active_token_hmac_idx
    ON public.case_tokens (token_hmac)
 WHERE revoked_at IS NULL AND token_hmac IS NOT NULL;

COMMENT ON COLUMN public.case_tokens.token_hmac IS
    'HMAC-SHA256(server_pepper, token) hex digest. Hot-path lookup '
    'column. Eliminates the byte-by-byte timing side-channel of the '
    'legacy raw-token equality compare. Populated by the v0.16.12 '
    'backfill ops command for legacy rows; set on INSERT for new '
    'tokens.';

COMMIT;
