-- 041_user_tokens.sql — single-use email tokens (verification + password reset).
--
-- Both flows mint a random token, store ONLY its sha256 hash (the plaintext goes
-- in the emailed link), and consume it atomically (one UPDATE marks used_at +
-- checks expiry), so a token works exactly once and a leaked DB yields nothing
-- usable. `users.email_verified_at` (migration 037) is the verification target.
--
-- Idempotent (IF NOT EXISTS); safe to re-run.
--
-- Apply with: python -m recupero.ops apply-migration migrations/041_user_tokens.sql

BEGIN;

CREATE TABLE IF NOT EXISTS public.user_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    kind        text NOT NULL,                 -- 'verify_email' | 'password_reset'
    token_hash  text NOT NULL UNIQUE,          -- sha256 of the single-use token
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz
);

-- Pending (unused) tokens for a user.
CREATE INDEX IF NOT EXISTS user_tokens_user_pending_idx
    ON public.user_tokens (user_id) WHERE used_at IS NULL;

COMMIT;
