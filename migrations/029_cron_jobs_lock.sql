-- 029_cron_jobs_lock.sql
--
-- v0.32 Tier-1 gap #3 (docs/WHY_RECUPERO_WOULD_FAIL.md §1.3):
--   "Single-instance cron, no high availability."
--
-- The v0.31.4 cron scheduler runs as ONE process. If it dies mid-OFAC
-- sync, sanctions data goes stale silently for up to 24h. We need:
--   (a) leader election so two scheduler replicas can race safely,
--   (b) per-job success/failure tracking so a healthz endpoint can
--       answer "is the OFAC sync actually running?",
--   (c) consecutive-failure counters so a webhook alerter can page
--       only when we cross a real threshold (not on a one-time blip).
--
-- One row per job_name. The leader_id is whoever currently holds the
-- lease; expires_at_utc bounds how long a dead leader can hog the
-- row before a peer steals it.
--
-- Apply with: python scripts/apply_migration.py migrations/029_cron_jobs_lock.sql

BEGIN;

CREATE TABLE IF NOT EXISTS public.cron_jobs_lock (
    job_name              TEXT PRIMARY KEY,
    leader_id             TEXT NOT NULL,                    -- container id / hostname / random uuid
    acquired_at_utc       TIMESTAMPTZ NOT NULL,
    expires_at_utc        TIMESTAMPTZ NOT NULL,
    last_success_utc      TIMESTAMPTZ,
    last_error_utc        TIMESTAMPTZ,
    last_error_message    TEXT,
    consecutive_failures  INT NOT NULL DEFAULT 0
);

COMMENT ON TABLE public.cron_jobs_lock IS
    'v0.32 cron HA — leader election + job health tracking. One row per '
    'job_name. Acquire via INSERT ... ON CONFLICT DO UPDATE WHERE the '
    'existing lease has expired OR the same leader is re-acquiring. '
    'Two scheduler replicas can run in parallel; only the lock-holder '
    'fires the job.';

COMMIT;
