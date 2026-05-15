-- 004_watchlist_priority.sql
--
-- Adds a per-row "priority" column to public.watchlist so the
-- nightly watch-tick can poll high-priority rows more frequently
-- than the standard 12h cooldown.
--
-- Priority semantics:
--   'standard'  (default)  — 12h cooldown,  default tick coverage
--   'hot'                   —  1h cooldown,  active-investigation
--                             wallets the operator wants near-realtime
--   'paused'                — never snapshotted (kept on the list but
--                             not actively monitored; useful for rows
--                             we want to keep referenced from old cases
--                             without burning API budget on them)
--
-- The watch_tick eligibility query becomes:
--   WHERE status = 'active'
--     AND priority IN ('standard', 'hot')
--     AND (last_snapshot_at IS NULL
--          OR last_snapshot_at < NOW() - (
--               CASE priority
--                 WHEN 'hot'      THEN make_interval(secs => $hot_sec)
--                 WHEN 'standard' THEN make_interval(secs => $std_sec)
--               END
--             ))
--
-- Idempotent: ALTER ADD COLUMN IF NOT EXISTS lets re-runs no-op.

BEGIN;

ALTER TABLE public.watchlist
    ADD COLUMN IF NOT EXISTS priority TEXT NOT NULL DEFAULT 'standard'
        CHECK (priority IN ('standard', 'hot', 'paused'));

-- Index for the eligibility query — partial on the in-scope priorities
-- so 'paused' rows don't bloat the index for nightly ticks.
CREATE INDEX IF NOT EXISTS watchlist_priority_due_idx
    ON public.watchlist (priority, last_snapshot_at NULLS FIRST)
    WHERE status = 'active' AND priority IN ('standard', 'hot');

COMMIT;
