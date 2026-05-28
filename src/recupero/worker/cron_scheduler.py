"""Recupero cron scheduler (v0.31.4, HA + alerting v0.32).

A long-running process that fires Recupero's scheduled maintenance
jobs on a fixed cadence. Designed to be deployed as a second
Railway service (or any other always-on container runner) alongside
the main `recupero-worker`.

Why a daemon, not platform-managed cron
---------------------------------------

Railway, Render, and Fly all support cron *triggers* but with
extra setup (separate cron services, scheduled jobs in the UI).
The audit (`docs/V031_3_HONEST_GAPS.md` §5a) flagged that NONE of
that infra was provisioned. A single-file Python scheduler:

  * deploys with zero platform-config changes (just point a second
    `startCommand` at it)
  * fires entirely in-process so every job inherits the same env,
    DB pool, label store cache, etc.
  * is testable with frozen-time fixtures (the `_now()` indirection
    in this module is monkeypatch-able)
  * shows up in operator logs in one place

High-availability (v0.32)
-------------------------

Tier-1 gap #3 from ``docs/WHY_RECUPERO_WOULD_FAIL.md`` §1.3: the
v0.31.4 scheduler was a single point of failure. If the container
died mid-OFAC-sync, sanctions data went stale for up to 24h with
no alert. v0.32 adds:

  * **Postgres leader election** via ``public.cron_jobs_lock``
    (migration 029). Two scheduler replicas can run concurrently;
    only the lease-holder fires the job. Lease default 300s — well
    above any single-job runtime.
  * **Per-job success/failure tracking** in the same row.
    ``last_success_utc`` / ``last_error_utc`` / ``last_error_message``
    / ``consecutive_failures``.
  * **Error webhook** to ``RECUPERO_CRON_ALERT_WEBHOOK_URL``,
    fired only when ``consecutive_failures >= 2`` so one transient
    blip doesn't page the on-call.
  * **/cron/healthz** endpoint (in ``worker/_health_server.py``)
    that external uptime monitors (Better Uptime, Pingdom) hit
    every 5 minutes.

Local-dev fallback: when the DSN is unset, locking is bypassed
with a WARN log so the scheduler still runs end-to-end on a
laptop with no Supabase reachable.

Jobs
----

  * OFAC sync — once per day at 04:00 UTC. Refreshes sanctions data.
  * Retrace backfill — once per day at 05:00 UTC. Surfaces cases
    that would benefit from re-trace after label-DB updates.
  * Stale-label alert — once per week (Mondays 06:00 UTC).
    Reports labels whose `added_at` is > 90 days old AND haven't
    been refreshed — surfaces CEX hot-wallet rotation risk.

Each job is wrapped in try/except so a single failing job doesn't
take the scheduler down. Logs go to stdout; aggregator picks them
up.

Bounds + safety
---------------

  * Each job runs ONCE per scheduled window — if a job is still
    running when the next tick arrives, the second invocation is
    skipped (logged at WARNING).
  * The scheduler sleeps in 60s ticks; oversleep is bounded by
    the next-fire computation, so missed windows fire on the next
    tick rather than queueing up.
  * Graceful shutdown on SIGTERM/SIGINT — running jobs finish
    before the process exits.
"""

from __future__ import annotations

import logging
import os
import signal
import socket
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import uuid4

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# HA / alerting / health env-var defaults
# ─────────────────────────────────────────────────────────────────────────────

# Lease seconds — how long a leader holds the lock without renewing it.
# 300s is way more than any job's expected runtime (the OFAC sync,
# typically the slowest, runs in well under 60s). If a job exceeds
# this we have a bigger problem than the lock anyway.
_DEFAULT_LEASE_SECONDS = 300

# Healthz stale threshold — how many hours since last_success_utc
# before a job is considered "stale". 25h gives a daily job a one-hour
# grace window past its 24h cadence; the weekly stale-label job rolls
# into "stale" after 25h *of its window*, which is intentional — we
# want operators to notice if a weekly job missed its run too.
_DEFAULT_HEALTHZ_STALE_HOURS = 25

# Healthz "down" threshold — after 168h (1 week) without success the
# job is considered hard-down regardless of cadence. Even the weekly
# stale-label scan should have succeeded inside this window.
_HEALTHZ_DOWN_HOURS = 168

# Webhook fires only at >= this many consecutive failures. One blip
# (e.g. transient OFAC SDN feed 502) shouldn't page on-call.
_WEBHOOK_FAILURE_THRESHOLD = 2


def _lease_seconds_from_env() -> int:
    """Return ``RECUPERO_CRON_LEASE_SECONDS`` clamped to a sane range.

    Bad input (non-int, <= 0) falls back to the default with a WARN.
    """
    raw = os.environ.get("RECUPERO_CRON_LEASE_SECONDS", "").strip()
    if not raw:
        return _DEFAULT_LEASE_SECONDS
    try:
        val = int(raw)
    except (TypeError, ValueError):
        log.warning(
            "RECUPERO_CRON_LEASE_SECONDS=%r is not an int — using default %d",
            raw, _DEFAULT_LEASE_SECONDS,
        )
        return _DEFAULT_LEASE_SECONDS
    if val <= 0:
        log.warning(
            "RECUPERO_CRON_LEASE_SECONDS=%d must be > 0 — using default %d",
            val, _DEFAULT_LEASE_SECONDS,
        )
        return _DEFAULT_LEASE_SECONDS
    return val


def _healthz_stale_hours_from_env() -> float:
    """Return ``RECUPERO_CRON_HEALTHZ_STALE_HOURS`` clamped to > 0."""
    import math
    raw = os.environ.get("RECUPERO_CRON_HEALTHZ_STALE_HOURS", "").strip()
    if not raw:
        return float(_DEFAULT_HEALTHZ_STALE_HOURS)
    try:
        val = float(raw)
    except (TypeError, ValueError):
        log.warning(
            "RECUPERO_CRON_HEALTHZ_STALE_HOURS=%r is not a float — using "
            "default %d", raw, _DEFAULT_HEALTHZ_STALE_HOURS,
        )
        return float(_DEFAULT_HEALTHZ_STALE_HOURS)
    if not math.isfinite(val) or val <= 0:
        log.warning(
            "RECUPERO_CRON_HEALTHZ_STALE_HOURS=%r must be a positive "
            "finite float — using default %d", val, _DEFAULT_HEALTHZ_STALE_HOURS,
        )
        return float(_DEFAULT_HEALTHZ_STALE_HOURS)
    return val


def _resolve_leader_id() -> str:
    """Stable identifier for this scheduler replica.

    Order of preference:
      1. HOSTNAME (Docker / k8s / Railway all set this)
      2. RAILWAY_REPLICA_ID (Railway-specific)
      3. fallback: random UUID + pid (still unique enough)
    """
    raw = (os.environ.get("HOSTNAME") or "").strip()
    if raw:
        return f"{raw}:{os.getpid()}"
    railway = (os.environ.get("RAILWAY_REPLICA_ID") or "").strip()
    if railway:
        return f"railway:{railway}"
    try:
        host = socket.gethostname()
    except Exception:  # noqa: BLE001
        host = "unknown"
    return f"{host}:{os.getpid()}:{uuid4().hex[:8]}"


def _supabase_dsn() -> str:
    """Return ``SUPABASE_DB_URL`` or empty string. Centralised so tests
    can monkeypatch one place."""
    return (os.environ.get("SUPABASE_DB_URL") or "").strip()


# ─────────────────────────────────────────────────────────────────────────────
# Postgres leader election + job-health writes
# ─────────────────────────────────────────────────────────────────────────────


def _try_acquire_lock(
    job_name: str,
    *,
    lease_seconds: int | None = None,
    leader_id: str | None = None,
    dsn: str | None = None,
) -> bool:
    """Return True iff this replica owns the lock for ``job_name``.

    Implementation: ``INSERT ... ON CONFLICT (job_name) DO UPDATE
    SET leader_id = EXCLUDED.leader_id, ...
    WHERE the existing lease has expired OR we already hold it``.

    The WHERE clause on the UPDATE side is the load-bearing piece —
    Postgres evaluates it as part of the ON CONFLICT branch and skips
    the update if it fails, in which case the RETURNING clause yields
    zero rows and we report "not acquired".

    Two instances racing both run this query; the loser sees their
    leader_id != EXCLUDED.leader_id AND the existing lease still
    valid, so the WHERE fails and they get zero rows back.

    When ``dsn`` is empty (local dev), bypass locking with a WARN
    log so the scheduler still runs end-to-end. Pass ``dsn=None``
    to use the env var.
    """
    if dsn is None:
        dsn = _supabase_dsn()
    if not dsn:
        log.warning(
            "cron: SUPABASE_DB_URL unset — bypassing leader election "
            "for %s (local-dev mode; DO NOT run two schedulers like this "
            "in production)", job_name,
        )
        return True

    if lease_seconds is None:
        lease_seconds = _lease_seconds_from_env()
    if leader_id is None:
        leader_id = _resolve_leader_id()

    now = datetime.now(UTC)
    expires = now + timedelta(seconds=lease_seconds)
    sql = """
    INSERT INTO public.cron_jobs_lock
        (job_name, leader_id, acquired_at_utc, expires_at_utc)
    VALUES (%s, %s, %s, %s)
    ON CONFLICT (job_name) DO UPDATE
       SET leader_id = EXCLUDED.leader_id,
           acquired_at_utc = EXCLUDED.acquired_at_utc,
           expires_at_utc = EXCLUDED.expires_at_utc
       WHERE cron_jobs_lock.expires_at_utc < NOW()
          OR cron_jobs_lock.leader_id = EXCLUDED.leader_id
    RETURNING leader_id
    """
    try:
        from recupero._common import db_connect
        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(sql, (job_name, leader_id, now, expires))
            result = cur.fetchone()
    except Exception as exc:  # noqa: BLE001
        # Fail closed: if we can't talk to the DB we MUST NOT fire
        # the job — another replica might. Log loudly so an operator
        # noticing "no jobs running" can trace it to a DB outage.
        log.error(
            "cron: lock acquire failed for %s (DB error) — refusing to "
            "fire this job: %s", job_name, exc,
        )
        return False
    return result is not None and result[0] == leader_id


def _record_job_success(
    job_name: str, *, dsn: str | None = None,
) -> None:
    """Mark ``last_success_utc = NOW()`` + reset consecutive_failures."""
    if dsn is None:
        dsn = _supabase_dsn()
    if not dsn:
        return  # Local dev — nothing to write.
    sql = """
    UPDATE public.cron_jobs_lock
       SET last_success_utc = NOW(),
           consecutive_failures = 0,
           last_error_utc = NULL,
           last_error_message = NULL
     WHERE job_name = %s
    """
    try:
        from recupero._common import db_connect
        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(sql, (job_name,))
    except Exception as exc:  # noqa: BLE001
        # Job success is the cheap, common path — log but don't
        # surface. The next run's lock-acquire will repair the row.
        log.warning("cron: success-write failed for %s: %s", job_name, exc)


def _record_job_failure(
    job_name: str, error: Exception, *, dsn: str | None = None,
) -> int:
    """Mark ``last_error_*`` + bump ``consecutive_failures``.

    Returns the new ``consecutive_failures`` value (or 1 if the DB
    write fails — we want the webhook to fire even on DB-write hiccups).

    The error message is truncated to 1000 chars and any DSN-shaped
    substring is scrubbed by ``_common.db_connect``'s redact logic;
    we still cap defensively here so a giant traceback doesn't blow
    the row.
    """
    if dsn is None:
        dsn = _supabase_dsn()
    msg = _safe_error_text(error)
    if not dsn:
        return 1  # Local dev — assume "first failure" for tests.
    sql = """
    UPDATE public.cron_jobs_lock
       SET last_error_utc = NOW(),
           last_error_message = %s,
           consecutive_failures = consecutive_failures + 1
     WHERE job_name = %s
    RETURNING consecutive_failures
    """
    try:
        from recupero._common import db_connect
        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(sql, (msg, job_name))
            row = cur.fetchone()
            return int(row[0]) if row else 1
    except Exception as exc:  # noqa: BLE001
        log.warning("cron: failure-write failed for %s: %s", job_name, exc)
        return 1


def _looks_like_uuid(s: str) -> bool:
    """Return True for 8-4-4-4-12 UUID-shaped strings (don't redact these)."""
    import re as _re
    return bool(_re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        s,
    ))


def _looks_like_address(s: str) -> bool:
    """Return True for 0x-prefixed EVM-style addresses (don't redact)."""
    return s.startswith("0x") and len(s) in (42, 66) and all(
        c in "0123456789abcdefABCDEFx" for c in s
    )


def _safe_error_text(error: Exception) -> str:
    """Scrub + truncate an exception message for storage / webhook.

    v0.32.1 JACOB_SECURITY_AUDIT_v032 CRIT-2 close-out: the prior version
    only redacted ``api_key|token|secret|password|bearer`` labels and DSN
    URI credentials. Any cron exception that surfaced a bare vendor-key
    (``sk_live_xxx``, ``re_xxx``, ``whsec_xxx``, ``AKIA…``, JWT, Slack
    webhook URL, etc.) was shipped to Slack/Discord. This expansion also
    redacts:

    * Credentialed URI schemes beyond postgres: redis, mongodb, amqp,
      sftp, ftp, mysql, smtp, https-with-basic-auth.
    * Labeled secrets (existing).
    * Vendor key prefixes (Stripe ``sk_live`` / ``sk_test`` / ``rk_live``
      / ``pk_live``, Resend ``re_``, Anthropic ``sk-ant-``,
      ``sk-proj-``, GitHub ``ghp_``/``ghs_``/``gho_``, AWS ``AKIA``/
      ``ASIA``, Vercel ``vc_``, Slack ``xoxb-``, generic ``whsec_``).
    * JWT pattern (three dot-separated base64url chunks starting ``eyJ``).
    * Slack incoming-webhook URLs.
    * Generic high-entropy 32+ char base64/hex chunks NOT matching the
      UUID or 0x-address allow-lists.

    The webhook payload MUST NOT contain DSN credentials, API keys, or
    other secrets. ``_common.db_connect`` already redacts DSNs on the
    way up, but we belt-and-suspender here so a direct exception
    bypassing that path still gets scrubbed.
    """
    raw = f"{type(error).__name__}: {error}"
    import re

    # 1) Credentialed URI schemes — collapse user:pass@host to ***@host.
    raw = re.sub(
        r"((?:postgres(?:ql)?|redis|mongodb(?:\+srv)?|amqp(?:s)?|sftp|ftp|mysql|smtp|https?)://)"
        r"[^@\s/]+@",
        r"\1***@",
        raw,
        flags=re.IGNORECASE,
    )

    # 2) Labeled secrets (existing behavior, plus authorization header).
    raw = re.sub(
        r"(api[_-]?key|token|secret|password|passwd|bearer|authorization)"
        r"[=:\s]+\S+",
        r"\1=***",
        raw,
        flags=re.IGNORECASE,
    )

    # 3) JWT (three base64url segments separated by dots, starting eyJ).
    raw = re.sub(
        r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
        "***JWT***",
        raw,
    )

    # 4) Slack incoming-webhook URLs.
    raw = re.sub(
        r"https://hooks\.slack\.com/services/[A-Z0-9/]+",
        "https://hooks.slack.com/services/***",
        raw,
    )

    # 5) Vendor key prefixes. Match the prefix + a non-trivial suffix.
    vendor_prefixes = [
        r"sk_live_[A-Za-z0-9]{8,}",
        r"sk_test_[A-Za-z0-9]{8,}",
        r"rk_live_[A-Za-z0-9]{8,}",
        r"pk_live_[A-Za-z0-9]{8,}",
        r"whsec_[A-Za-z0-9]{8,}",
        r"re_[A-Za-z0-9]{16,}",  # Resend
        r"sk-ant-[A-Za-z0-9\-_]{16,}",
        r"sk-proj-[A-Za-z0-9\-_]{16,}",
        r"ghp_[A-Za-z0-9]{16,}",
        r"ghs_[A-Za-z0-9]{16,}",
        r"gho_[A-Za-z0-9]{16,}",
        r"AKIA[0-9A-Z]{16}",
        r"ASIA[0-9A-Z]{16}",
        r"vc_[A-Za-z0-9]{16,}",
        r"xoxb-[A-Za-z0-9\-]{16,}",
        r"xoxp-[A-Za-z0-9\-]{16,}",
        r"xapp-[A-Za-z0-9\-]{16,}",
    ]
    for pat in vendor_prefixes:
        raw = re.sub(pat, "***VENDOR_KEY***", raw)

    # 6) Generic high-entropy 32+ char base64/hex chunks. Skip UUIDs and
    # 0x-prefixed addresses by pattern-matching them first and masking
    # by token-by-token replacement.
    def _maybe_redact_token(match: re.Match) -> str:
        token = match.group(0)
        if _looks_like_uuid(token):
            return token
        if _looks_like_address(token):
            return token
        return "***HIGH_ENTROPY***"

    raw = re.sub(
        r"\b[A-Za-z0-9_\-+/=]{32,}\b",
        _maybe_redact_token,
        raw,
    )

    return raw[:1000]


# ─────────────────────────────────────────────────────────────────────────────
# Error webhook
# ─────────────────────────────────────────────────────────────────────────────


def _post_error_webhook(
    job_name: str,
    error: Exception,
    consecutive_failures: int,
) -> None:
    """POST a Slack-shaped alert payload to RECUPERO_CRON_ALERT_WEBHOOK_URL.

    Fires only when ``consecutive_failures >= _WEBHOOK_FAILURE_THRESHOLD``
    (= 2). One transient blip shouldn't page on-call.

    Webhook failure NEVER raises — that would defeat the entire
    alerting mechanism (a broken webhook URL would propagate up and
    take the scheduler down). On any error we log a WARN and return.

    The payload mirrors Slack's incoming-webhook format; Discord,
    PagerDuty, and OpsGenie all accept variants of the same shape.

    SECRETS HYGIENE: the error text passes through
    ``_safe_error_text`` so DSN passwords, API keys, and bearer
    tokens never reach the webhook receiver.
    """
    if consecutive_failures < _WEBHOOK_FAILURE_THRESHOLD:
        # Below threshold — no page.
        return

    url = (os.environ.get("RECUPERO_CRON_ALERT_WEBHOOK_URL") or "").strip()
    if not url:
        # No webhook configured — silent. Operators see the failure
        # via the /cron/healthz endpoint + the WARN log line.
        return

    payload = {
        "text": f"cron job {job_name} failed (#{consecutive_failures})",
        "attachments": [{
            "color": "danger",
            "fields": [
                {"title": "Job", "value": job_name, "short": True},
                {"title": "Failures", "value": str(consecutive_failures), "short": True},
                {
                    "title": "Error",
                    "value": _safe_error_text(error)[:500],
                    "short": False,
                },
            ],
            "ts": int(time.time()),
        }],
    }

    try:
        import httpx
        # 5s timeout — same order as the dispatcher's webhook timeout.
        # A receiver that takes longer than 5s to ACK an alert is
        # broken; we'd rather log the alert + give up than block the
        # scheduler thread.
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(url, json=payload)
        if 200 <= resp.status_code < 300:
            log.info(
                "cron: error webhook delivered (job=%s, failures=%d, "
                "status=%d)", job_name, consecutive_failures, resp.status_code,
            )
        else:
            log.warning(
                "cron: error webhook returned non-2xx (job=%s, status=%d) — "
                "alert may not have been received", job_name, resp.status_code,
            )
    except Exception as exc:  # noqa: BLE001
        # NEVER raise — webhook failure can't be allowed to crash the
        # scheduler. The failure is already journaled in cron_jobs_lock;
        # /cron/healthz will surface it to operators on the next poll.
        log.warning(
            "cron: error webhook delivery failed (job=%s): %s — "
            "consecutive_failures=%d remains journaled in cron_jobs_lock",
            job_name, exc, consecutive_failures,
        )


# ─────────────────────────────────────────────────────────────────────────────
# /cron/healthz support
# ─────────────────────────────────────────────────────────────────────────────


def build_cron_healthz_payload(*, dsn: str | None = None) -> dict:
    """Return the JSON payload served at GET /cron/healthz.

    Shape::

        {
          "status": "ok" | "degraded" | "down",
          "jobs": {
            "ofac_sync": {
                "last_success_utc": "...",
                "hours_since_last_success": 2.5,
                "consecutive_failures": 0,
                "status": "ok" | "stale" | "down"
            },
            ...
          }
        }

    Roll-up rules:
      * Any job with status="down" → top-level "down".
      * Else any job with status="stale" → top-level "degraded".
      * Else → "ok".

    Job-level thresholds:
      * last_success_utc IS NULL → "down" (never succeeded; or row missing)
      * hours_since_last_success > _HEALTHZ_DOWN_HOURS (168h) → "down"
      * hours_since_last_success > stale_hours (default 25h) → "stale"
      * else → "ok"

    The endpoint is hit by external uptime monitors every 5 minutes,
    so it must be cheap (one SELECT). No filters — return one row per
    job_name we've ever seen.
    """
    expected_jobs = [j.name for j in _build_default_jobs()]
    stale_hours = _healthz_stale_hours_from_env()

    if dsn is None:
        dsn = _supabase_dsn()
    rows_by_job: dict[str, dict] = {}
    if dsn:
        sql = """
        SELECT job_name, last_success_utc, last_error_utc,
               last_error_message, consecutive_failures
          FROM public.cron_jobs_lock
        """
        try:
            from recupero._common import db_connect
            with db_connect(dsn) as conn, conn.cursor() as cur:
                cur.execute(sql)
                for (
                    name, last_success, last_error,
                    last_error_msg, failures,
                ) in cur.fetchall():
                    rows_by_job[name] = {
                        "last_success_utc": last_success,
                        "last_error_utc": last_error,
                        "last_error_message": last_error_msg,
                        "consecutive_failures": int(failures or 0),
                    }
        except Exception as exc:  # noqa: BLE001
            log.warning("cron-healthz: query failed: %s", exc)
            # Return a "down" payload — an uptime monitor seeing this
            # alarms on it.
            return {
                "status": "down",
                "error": "cron_jobs_lock query failed",
                "jobs": {},
            }

    now = datetime.now(UTC)
    job_states: dict[str, dict] = {}
    worst_status = "ok"
    for name in expected_jobs:
        row = rows_by_job.get(name)
        last_success = row["last_success_utc"] if row else None
        failures = row["consecutive_failures"] if row else 0
        if last_success is None:
            status = "down"
            hours_since = None
        else:
            if last_success.tzinfo is None:
                last_success = last_success.replace(tzinfo=UTC)
            hours_since = (now - last_success).total_seconds() / 3600.0
            if hours_since > _HEALTHZ_DOWN_HOURS:
                status = "down"
            elif hours_since > stale_hours:
                status = "stale"
            else:
                status = "ok"
        job_states[name] = {
            "last_success_utc": (
                last_success.isoformat().replace("+00:00", "Z")
                if last_success else None
            ),
            "hours_since_last_success": (
                round(hours_since, 2) if hours_since is not None else None
            ),
            "consecutive_failures": int(failures),
            "status": status,
        }
        # Roll-up: down beats stale beats ok.
        if status == "down":
            worst_status = "down"
        elif status == "stale" and worst_status != "down":
            worst_status = "degraded"

    return {
        "status": worst_status,
        "jobs": job_states,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Job registry
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class CronJob:
    """One scheduled job.

    ``schedule_fn`` returns the NEXT datetime (UTC, tz-aware) the job
    should fire after ``now``. ``run_fn`` is the actual work; returns
    None on success, raises on failure.
    """
    name: str
    schedule_fn: Callable[[datetime], datetime]
    run_fn: Callable[[], None]
    last_fired: datetime | None = field(default=None)
    is_running: bool = field(default=False)


def _next_daily(hour_utc: int, minute_utc: int = 0) -> Callable[[datetime], datetime]:
    """Return a schedule_fn that fires at `hour_utc:minute_utc` daily."""
    def _next(now: datetime) -> datetime:
        target = now.replace(
            hour=hour_utc, minute=minute_utc,
            second=0, microsecond=0,
        )
        if target <= now:
            target = target + timedelta(days=1)
        return target
    return _next


def _next_hourly(minute_utc: int = 0) -> Callable[[datetime], datetime]:
    """Return a schedule_fn that fires once per hour at `minute_utc`."""
    def _next(now: datetime) -> datetime:
        target = now.replace(
            minute=minute_utc, second=0, microsecond=0,
        )
        if target <= now:
            target = target + timedelta(hours=1)
        return target
    return _next


def _next_weekly(weekday: int, hour_utc: int, minute_utc: int = 0) -> Callable[[datetime], datetime]:
    """Return a schedule_fn that fires weekly on `weekday` (0=Mon)
    at `hour_utc:minute_utc`."""
    def _next(now: datetime) -> datetime:
        days_ahead = (weekday - now.weekday()) % 7
        target = now.replace(
            hour=hour_utc, minute=minute_utc,
            second=0, microsecond=0,
        ) + timedelta(days=days_ahead)
        if target <= now:
            target = target + timedelta(days=7)
        return target
    return _next


# ─────────────────────────────────────────────────────────────────────────────
# Job implementations
# ─────────────────────────────────────────────────────────────────────────────


def _job_ofac_sync() -> None:
    """Refresh OFAC sanctions data.

    v0.31.5: calls ``sync_ofac_sdn(strict=True)`` directly so any
    failure (network unreachable, parse error, write failure) raises
    ``OFACSyncError``. The scheduler's per-job ``except Exception``
    then logs at ERROR level + records the failure — operators see
    a loud signal instead of a silently-stale sanctions DB.

    The CLI ``recupero-ops ofac-sync`` retains its legacy "print +
    exit-code" contract for interactive operator use; the cron path
    needs raise-on-fail so monitoring can act."""
    log.info("cron: running OFAC sync")
    from recupero.trace.ofac_sync import sync_ofac_sdn
    result = sync_ofac_sdn(strict=True)
    log.info(
        "cron: OFAC sync ok — %d live entries, fetched_at=%s",
        result.entries_written, result.fetched_at,
    )


def _job_retrace_backfill() -> None:
    """Find cases that would benefit from re-trace after label-DB updates."""
    log.info("cron: running retrace backfill scan")
    from recupero.worker import retrace_backfill
    retrace_backfill.main()


def _job_review_sla_scan() -> None:
    """v0.32 Tier-0 gap #1 — review SLA enforcement.

    Fires hourly. Surfaces brief_reviews rows still in
    status='awaiting_review' for > 24h (configurable via
    RECUPERO_REVIEW_SLA_HOURS). Each overdue row emits a WARNING log
    line that the production log-shipping pipeline forwards to the
    on-call channel.
    """
    log.info("cron: running review-SLA scan")
    from recupero.dispatcher.sla import run_review_sla_job
    n_overdue = run_review_sla_job()
    log.info("cron: review-SLA scan done — %d overdue row(s)", n_overdue)


def _job_label_auto_ingest() -> None:
    """v0.32 Tier-1 gaps #1 + #2 — daily label auto-ingest.

    Pulls candidate bridge + CEX-deposit addresses from public tag
    APIs (DeFiLlama, Tronscan, Solscan, Etherscan) into the
    ``label_candidates`` table with ``status='pending_review'``. An
    operator then promotes / rejects via the
    ``/v1/labels/candidates/*`` endpoints. We do NOT auto-promote —
    a tag-spammer could otherwise inject bogus labels straight into
    operator output.

    Defensive: any source unreachable → WARN, skip, continue. Daily
    cap (``RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP``, default 100)
    prevents review-queue overflow.
    """
    log.info("cron: running label auto-ingest")
    from recupero.labels import auto_ingest
    result = auto_ingest.run_daily_pull()
    log.info(
        "cron: label auto-ingest done — bridges=%d cex=%d persisted=%d",
        result["bridges_seen"], result["cex_seen"], result["persisted"],
    )


def _job_stale_label_alert() -> None:
    """Flag labels whose added_at is > 90 days old."""
    log.info("cron: running stale-label alert")
    from pathlib import Path
    import json
    from recupero._common import atomic_write_text

    seeds_dir = (
        Path(__file__).resolve().parents[1] / "labels" / "seeds"
    )
    now = _now()
    horizon = now - timedelta(days=90)

    stale: list[dict[str, str | int]] = []
    for path in sorted(seeds_dir.glob("*.json")):
        try:
            entries = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception as exc:  # noqa: BLE001
            log.warning("stale-label scan: %s unreadable: %s", path.name, exc)
            continue
        if not isinstance(entries, list):
            continue
        for i, e in enumerate(entries):
            if not isinstance(e, dict):
                continue
            added_at = e.get("added_at")
            if not isinstance(added_at, str):
                continue
            try:
                ts = datetime.fromisoformat(added_at.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            if ts < horizon:
                age_days = (now - ts).days
                stale.append({
                    "file": path.name,
                    "index": i,
                    "address": str(e.get("address", "?")),
                    "name": str(e.get("name", "?"))[:80],
                    "age_days": age_days,
                })

    # Write a report so operators can review.
    out_dir = Path(os.environ.get("RECUPERO_DATA_DIR", "./data"))
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "stale_labels.json"
    payload = {
        "generated_at_utc": now.isoformat().replace("+00:00", "Z"),
        "horizon_days": 90,
        "stale_count": len(stale),
        "stale_entries": sorted(stale, key=lambda x: -int(x["age_days"]))[:200],
    }
    atomic_write_text(out_path, json.dumps(payload, indent=2, ensure_ascii=False))
    log.info(
        "cron: stale-label scan complete — %d stale entries (report at %s)",
        len(stale), out_path,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Driver
# ─────────────────────────────────────────────────────────────────────────────


def _now() -> datetime:
    """Test seam — monkeypatch this to drive the scheduler with a
    frozen clock in tests."""
    return datetime.now(UTC)


def _build_default_jobs() -> list[CronJob]:
    """Return the canonical job set. Operators that need a different
    cadence can fork this function or set env-var overrides (future
    work — keeping the v0.31.4 surface minimal)."""
    return [
        CronJob(
            name="ofac_sync",
            schedule_fn=_next_daily(hour_utc=4),
            run_fn=_job_ofac_sync,
        ),
        CronJob(
            name="retrace_backfill",
            schedule_fn=_next_daily(hour_utc=5),
            run_fn=_job_retrace_backfill,
        ),
        CronJob(
            name="stale_label_alert",
            schedule_fn=_next_weekly(weekday=0, hour_utc=6),  # Monday 06:00 UTC
            run_fn=_job_stale_label_alert,
        ),
        CronJob(
            # v0.32 Tier-1 gaps #1 + #2 — daily auto-ingest of new
            # bridge contracts + CEX hot wallets from DeFiLlama /
            # Tronscan / Solscan. Fires at 02:00 UTC, before OFAC
            # sync (04:00) so a same-day promote-then-OFAC-sync flow
            # can land a new label and use it in the next trace.
            name="label_auto_ingest",
            schedule_fn=_next_daily(hour_utc=2),
            run_fn=_job_label_auto_ingest,
        ),
        CronJob(
            # v0.32 Tier-0 gap #1: 24h SLA enforcement on the
            # human-review queue. Hourly to give operators a tight
            # feedback loop without spamming on-call (the WARN logs
            # only fire on rows actually past SLA).
            name="review_sla_scan",
            schedule_fn=_next_hourly(minute_utc=15),
            run_fn=_job_review_sla_scan,
        ),
    ]


_SHUTDOWN = False


def _install_signal_handlers() -> None:
    """Wire SIGTERM / SIGINT to set the shutdown flag — running jobs
    finish, then the scheduler exits."""
    def _handler(signum, _frame):
        global _SHUTDOWN
        log.info("cron: received signal %d — graceful shutdown", signum)
        _SHUTDOWN = True

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handler)
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, _handler)


def _fire_job(j: CronJob) -> None:
    """Fire one job inside the HA wrapper.

    Order:
      1. Try to acquire the lock. If another replica holds it → INFO + skip.
      2. Run the job.
      3. On success: record success.
      4. On failure: log exception, record failure, maybe fire webhook.
    """
    if not _try_acquire_lock(j.name):
        log.info(
            "cron: job %s held by another leader, skipping this tick",
            j.name,
        )
        return

    try:
        j.run_fn()
    except Exception as exc:  # noqa: BLE001
        log.exception("cron: job %s failed: %s", j.name, exc)
        failures = _record_job_failure(j.name, exc)
        _post_error_webhook(j.name, exc, failures)
    else:
        _record_job_success(j.name)


def run_scheduler(
    jobs: list[CronJob] | None = None,
    *,
    tick_seconds: float = 60.0,
    max_ticks: int | None = None,
) -> None:
    """Run the scheduler loop.

    ``max_ticks`` is for testing — set to N to exit after N ticks.
    """
    if jobs is None:
        jobs = _build_default_jobs()

    _install_signal_handlers()
    log.info("cron: scheduler starting (%d jobs)", len(jobs))
    for j in jobs:
        next_fire = j.schedule_fn(_now())
        log.info("cron:   %s next fires at %s", j.name, next_fire.isoformat())

    tick = 0
    while not _SHUTDOWN:
        now = _now()
        for j in jobs:
            if j.is_running:
                continue
            # Compute when this job's next fire should be relative to the
            # most recent fire (or "now" if it has never fired).
            anchor = j.last_fired if j.last_fired else now - timedelta(seconds=1)
            next_fire = j.schedule_fn(anchor)
            if now >= next_fire:
                j.is_running = True
                try:
                    _fire_job(j)
                finally:
                    j.last_fired = now
                    j.is_running = False

        tick += 1
        if max_ticks is not None and tick >= max_ticks:
            log.info("cron: max_ticks reached, exiting")
            break

        # Sleep in 1s slices so a SIGTERM doesn't wait the full tick.
        slept = 0.0
        while slept < tick_seconds and not _SHUTDOWN:
            time.sleep(min(1.0, tick_seconds - slept))
            slept += 1.0

    log.info("cron: scheduler exited cleanly")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the `recupero-cron` console script."""
    logging.basicConfig(
        level=os.environ.get("RECUPERO_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    try:
        run_scheduler()
    except KeyboardInterrupt:
        log.info("cron: interrupted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
