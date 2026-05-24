BEGIN;

-- 016_drop_case_tokens_raw_token.sql
--
-- S-5 final step: drop the raw `token` column from public.case_tokens.
-- This eliminates the at-rest plaintext storage of portal access
-- tokens. From this migration forward, only HMAC-SHA256(pepper, token)
-- is persisted; the raw token exists only in the customer's URL.
--
-- ORDER: apply ONLY after migration 015 (relaxed token constraints)
-- AND after the new portal/tokens.py code is deployed to prod. The
-- new code does not reference the `token` column at all (no INSERT,
-- no SELECT). Old code references it, so applying this before the
-- code deploy would break inflight portal operations.
--
-- Idempotent — re-running after the column is gone is a no-op.

ALTER TABLE public.case_tokens
    DROP COLUMN IF EXISTS token;

COMMIT;
