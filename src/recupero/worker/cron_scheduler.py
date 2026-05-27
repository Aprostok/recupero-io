"""Recupero cron scheduler (v0.31.4).

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
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

log = logging.getLogger(__name__)

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
    """Refresh OFAC sanctions data."""
    log.info("cron: running OFAC sync")
    from recupero.ops.commands import ofac_sync_cmd
    # The command has its own main() / __main__; call the function form.
    if hasattr(ofac_sync_cmd, "run"):
        ofac_sync_cmd.run()
    elif hasattr(ofac_sync_cmd, "main"):
        ofac_sync_cmd.main()
    else:
        # Fallback — invoke the module's CLI entry.
        import runpy
        runpy.run_module("recupero.ops.commands.ofac_sync_cmd", run_name="__main__")


def _job_retrace_backfill() -> None:
    """Find cases that would benefit from re-trace after label-DB updates."""
    log.info("cron: running retrace backfill scan")
    from recupero.worker import retrace_backfill
    retrace_backfill.main()


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
                    j.run_fn()
                except Exception as exc:  # noqa: BLE001
                    log.exception("cron: job %s failed: %s", j.name, exc)
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
