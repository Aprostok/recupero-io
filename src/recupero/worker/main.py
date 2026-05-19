"""Entry point for the worker process.

Run as ``recupero-worker`` (registered console script) or
``python -m recupero.worker.main``. Loops forever, claiming and processing
investigations one at a time. Heartbeats while a row is in flight; another
worker may steal stale rows after the configured timeout.

Configuration is via env vars (loaded from .env):

    SUPABASE_URL                  Required. e.g. https://abc.supabase.co
    SUPABASE_SERVICE_ROLE_KEY     Required. Bucket access.
    SUPABASE_DB_URL               Required. Pooler URL (port 6543).
    ETHERSCAN_API_KEY             Required for chains using Etherscan.
    ANTHROPIC_API_KEY             Required for the editorial stage.
    RECUPERO_HEARTBEAT_INTERVAL_SEC   Default 30.
    RECUPERO_STALE_AFTER_SEC          Default 300 (5 min).
    RECUPERO_POLL_IDLE_SEC            Default 2.
    RECUPERO_POLL_MAX_SEC             Default 30.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import socket
import sys
import threading
from pathlib import Path
from typing import Final

from dotenv import load_dotenv

from recupero.config import load_config
from recupero.logging_setup import setup_logging
from recupero.storage.supabase_case_store import SupabaseCaseStore
from recupero.worker._health_server import start_health_server
from recupero.worker.db import Investigation, WorkerDB
from recupero.worker.pipeline import run_one

log = logging.getLogger(__name__)


# ----- Required env vars ----- #
# Splitting these into "required to start" vs "required to actually do work"
# is a temptation, but resist it: a worker that's missing ETHERSCAN_API_KEY
# will cheerfully claim every queued row and fail it on the trace stage. The
# user-visible result is "every investigation is broken" with no clear cause.
# Failing fast at startup turns it into "Railway shows the deploy unhealthy",
# which is the right signal.
_REQUIRED_ENV_VARS: Final = (
    "SUPABASE_URL",
    "SUPABASE_SERVICE_ROLE_KEY",
    "SUPABASE_DB_URL",
    "ETHERSCAN_API_KEY",
    "ANTHROPIC_API_KEY",
    "COINGECKO_API_KEY",
)


def _missing_env_vars() -> list[str]:
    return [name for name in _REQUIRED_ENV_VARS
            if not os.environ.get(name, "").strip()]


# ----- Config defaults ----- #

_HEARTBEAT_DEFAULT_SEC: Final = 30
_STALE_DEFAULT_SEC: Final = 300
_POLL_IDLE_DEFAULT_SEC: Final = 2.0
_POLL_MAX_DEFAULT_SEC: Final = 30.0


# ----- Heartbeat thread ----- #


class _Heartbeat:
    """Background thread that pings ``last_heartbeat_at`` every N seconds.

    Started before run_one(); stopped (and joined) after run_one() returns.
    Heartbeat failures are logged but don't kill the worker; missing one
    beat just means the next claim sweep might steal the row, which is
    acceptable.
    """

    def __init__(self, db: WorkerDB, inv: Investigation, interval_sec: float) -> None:
        self._db = db
        self._inv = inv
        self._interval = interval_sec
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name=f"hb-{inv.id}")

    def start(self) -> None:
        self._thread.start()

    # v0.18.1 (round-11 worker-CRIT-002): join timeout is now generous
    # but the heartbeat thread is also explicitly bounded — its DB
    # call uses connect_timeout=10 (via WorkerDB._PSYCOPG_KW), so a
    # blocked psycopg.connect can hold the thread at most ~10s.
    # Combined with the v0.18.1 reaper change that clears worker_id
    # AND the v0.18.1 mark_* terminal-state guards, a late heartbeat
    # write can no longer (a) re-write last_heartbeat_at on a reaped
    # row (worker_id filter) nor (b) let a zombie mark_* succeed
    # against a reaped row (status guard).
    _STOP_JOIN_TIMEOUT_SEC = 30

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=self._STOP_JOIN_TIMEOUT_SEC)
        if self._thread.is_alive():
            log.warning(
                "heartbeat thread did not exit within %ds — proceeding "
                "anyway; v0.18.1 reaper + mark_* guards prevent stale "
                "writes from corrupting row state.",
                self._STOP_JOIN_TIMEOUT_SEC,
            )

    def stop_idempotent(self) -> None:
        """Stop the heartbeat thread; safe to call multiple times.

        v0.16.13 (round-9 worker ARCH): pipeline.run_one invokes this
        before each final mark_* transition to eliminate the race
        where the heartbeat thread fires AFTER worker_id has been
        cleared, briefly making the row look "claimed but
        heartbeating" to the reaper. The outer `finally: hb.stop()`
        in main.py still runs as a safety net but is a no-op when
        the thread already exited.

        v0.18.1 (round-11 worker-CRIT-002): join uses the larger
        timeout. The reaper + mark_* guards in v0.18.1 make a stale
        heartbeat write provably safe (it'll match zero rows due to
        worker_id NULL after reap + status NOT IN terminal-states
        on every mark_*).
        """
        if not self._stop.is_set():
            self._stop.set()
            if self._thread.is_alive():
                self._thread.join(timeout=self._STOP_JOIN_TIMEOUT_SEC)

    def _run(self) -> None:
        # Wait the interval first; the claim already set the heartbeat to NOW().
        while not self._stop.wait(self._interval):
            try:
                self._db.heartbeat(self._inv.id)
            except Exception as e:  # noqa: BLE001
                log.warning("heartbeat failed for %s: %s", self._inv.id, e)


# ----- Graceful shutdown ----- #
# A single Event the polling loop checks between iterations. SIGTERM
# (Railway sends this on redeploy) and SIGINT (Ctrl+C) both flip it.
# After the flag is set, we finish the current investigation if one is
# in flight, then exit cleanly. The 30s shutdown grace period Railway
# allows is plenty for the polling loop to break; an in-flight trace
# stage may legitimately exceed that, in which case Railway forces
# SIGKILL — the stale-claim reaper recovers on next worker startup.
_shutdown = threading.Event()


def _install_signal_handlers() -> None:
    def handler(signum: int, _frame: object) -> None:
        name = signal.Signals(signum).name
        log.info("received %s — shutdown after current investigation completes", name)
        _shutdown.set()

    # SIGTERM is what Railway / Docker / Kubernetes send on stop/redeploy.
    # SIGINT is Ctrl+C in the terminal. Both should drain gracefully.
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)


# ----- Main loop ----- #


def run_forever(
    *,
    once: bool = False,
    poll_idle_sec: float = _POLL_IDLE_DEFAULT_SEC,
    poll_max_sec: float = _POLL_MAX_DEFAULT_SEC,
    heartbeat_sec: float = _HEARTBEAT_DEFAULT_SEC,
    stale_after_sec: int = _STALE_DEFAULT_SEC,
) -> None:
    cfg, env = load_config()

    missing = _missing_env_vars()
    if missing:
        log.error(
            "missing required env vars: %s. The worker refuses to start "
            "rather than claim work it can't process. Set them in Railway "
            "Variables (or the local .env) and redeploy.",
            ", ".join(missing),
        )
        sys.exit(2)

    supabase_url = os.environ["SUPABASE_URL"].strip()
    service_role = os.environ["SUPABASE_SERVICE_ROLE_KEY"].strip()
    db_url = os.environ["SUPABASE_DB_URL"].strip()

    worker_id = f"{socket.gethostname()}-{os.getpid()}"
    log.info("recupero-worker starting id=%s", worker_id)

    # HTTP healthcheck server. Runs only in long-lived mode so --once
    # tests don't have to bind a port. Daemon thread; dies with parent.
    if not once:
        try:
            start_health_server(lambda: _run_checks(verbose=False))
        except OSError as e:
            # Port-bind failures shouldn't kill the worker — Railway will
            # mark "unhealthy" but the polling loop is still useful.
            log.warning("health server failed to bind: %s (continuing without it)", e)
        # Wire SIGTERM/SIGINT to set _shutdown so the polling loop drains
        # cleanly on Railway redeploy instead of abandoning work mid-stage.
        _install_signal_handlers()

    db = WorkerDB(db_url, worker_id=worker_id)

    # One-shot eager reaper at startup. Catches rows orphaned by a
    # Railway redeploy faster than the standard 300s reaper — when
    # the OLD container gets SIGKILL'd mid-pipeline, its rows would
    # otherwise sit in 'claimed'/'tracing'/etc for 5 minutes before
    # the standard reaper notices. With this, the post-deploy
    # recovery window shrinks to ~90 seconds (3 missed heartbeats).
    # Only touches rows owned by OTHER workers; our own claims are
    # excluded by the WHERE clause.
    try:
        orphans = db.reap_post_deploy_orphans()
        if orphans:
            log.warning(
                "post-deploy reaper recovered %d orphaned row(s): %s",
                len(orphans),
                [(str(i), s) for i, s in orphans],
            )
        else:
            log.info("post-deploy reaper: no orphaned rows found")
    except Exception as e:  # noqa: BLE001
        log.error("post-deploy reaper failed (continuing): %s", e)

    backoff = poll_idle_sec
    try:
        while not _shutdown.is_set():
            # Reap stale claims before each polling attempt — turns dead
            # workers' orphaned rows into terminal `failed` so the admin
            # UI can surface them. Cheap (one UPDATE), idempotent.
            try:
                reaped = db.reap_stale_claims(stale_after_sec=stale_after_sec)
                for inv_id, prior_status in reaped:
                    log.warning(
                        "reaper failed stale row id=%s prior_status=%s",
                        inv_id, prior_status,
                    )
            except Exception as e:  # noqa: BLE001
                log.error("reaper failed (will retry on next poll): %s", e)

            inv = _try_claim(db)
            if inv is None:
                if once:
                    log.info("nothing to claim; --once exiting")
                    return
                # Use the shutdown event for the idle sleep so SIGTERM
                # interrupts immediately instead of waiting up to 30s.
                if _shutdown.wait(backoff):
                    break
                backoff = min(backoff * 1.5, poll_max_sec)
                continue
            backoff = poll_idle_sec  # reset

            # New work — open a per-investigation bucket store and run.
            # Once we've claimed, we always finish the current row before
            # checking _shutdown again. Mid-stage SIGKILL would corrupt
            # state; the reaper covers that case if Railway forces it.
            with SupabaseCaseStore(
                cfg, supabase_url, service_role,
                investigation_id=str(inv.id),
            ) as store:
                hb = _Heartbeat(db, inv, heartbeat_sec)
                hb.start()
                try:
                    # v0.16.13: pass hb.stop_idempotent as a pre-finalize
                    # hook so pipeline.run_one can shut the heartbeat
                    # thread down BEFORE issuing the final mark_*
                    # transition. Eliminates the race where the
                    # heartbeat overwrites last_heartbeat_at AFTER
                    # worker_id was cleared.
                    run_one(
                        inv, config=cfg, env=env, db=db, store=store,
                        stop_heartbeat=hb.stop_idempotent,
                    )
                finally:
                    hb.stop()

            if once:
                return
        log.info("shutdown signal received — drained cleanly, exiting")
    finally:
        db.close()


# Cooldown after a claim failure. Prevents a tight retry loop when
# something is fundamentally broken (schema drift, DB down, etc.) —
# we don't want to burn CPU + log spam re-trying the same broken
# claim 30 times a second. claim_one is now self-recovering for
# pydantic ValidationErrors (it marks the row failed and re-raises),
# so the next claim sweep will get a DIFFERENT row.
_CLAIM_FAILURE_COOLDOWN_SEC = 30.0


def _try_claim(db: WorkerDB) -> Investigation | None:
    try:
        inv = db.claim_one()
    except Exception as e:  # noqa: BLE001
        # Use log.exception so the full traceback lands in Railway logs.
        # The original bug was invisible for 12 hours because the brief
        # one-line log message ("invalid literal for int...") didn't
        # spell out the consequence (row stuck in 'claimed') or which
        # column was the offender. exception() includes the traceback
        # which makes pydantic ValidationErrors self-documenting.
        log.exception(
            "claim_one FAILED — investigation may be stuck in 'claimed' "
            "state; admin UI should surface it as failed within seconds. "
            "Cooling down %.0fs before next claim sweep. Cause: %s",
            _CLAIM_FAILURE_COOLDOWN_SEC, e,
        )
        _record_claim_metric("fail")
        # Sleep on the shutdown event so a SIGTERM during the cooldown
        # still drains cleanly instead of waiting the full 30s.
        _shutdown.wait(_CLAIM_FAILURE_COOLDOWN_SEC)
        return None
    _record_claim_metric("ok" if inv else "empty")
    return inv


def _record_claim_metric(outcome: str) -> None:
    """Best-effort metrics dispatch. See pipeline._record_stage_metric."""
    try:
        from recupero.observability.metrics import record_claim
        record_claim(outcome)
    except Exception:  # noqa: BLE001
        pass


# ----- CLI ----- #


def _run_checks(verbose: bool = True) -> tuple[bool, dict[str, str]]:
    """Run env + DB + bucket + package-integrity checks.

    Returns ``(all_ok, details_dict)`` where details maps each check
    name to ``"ok"`` or an error message. Logs human-readable lines
    when ``verbose=True`` (used by --health-check); the HTTP healthcheck
    handler calls with verbose=False to avoid log spam.

    Package-integrity verifies that data files declared in pyproject's
    setuptools.package-data actually shipped in the installed wheel —
    catches the regression class where a Path(__file__) lookup works
    locally (editable install reaches into source tree) but fails in
    production (non-editable install needs explicit package-data).
    """
    cfg, _env = load_config()
    details: dict[str, str] = {}

    env_ok = True
    for name in _REQUIRED_ENV_VARS:
        val = os.environ.get(name, "").strip()
        details[f"env:{name}"] = "ok" if val else "missing"
        if val:
            if verbose:
                log.info("env [OK]    %s set", name)
        else:
            env_ok = False
            if verbose:
                log.error("env [MISS]  %s missing", name)

    supabase_url = os.environ.get("SUPABASE_URL", "").strip()
    service_role = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    db_url = os.environ.get("SUPABASE_DB_URL", "").strip()

    # Package-integrity: load every Path(__file__)-resolved data file the
    # pipeline depends on. Run before DB/bucket so a fast local issue
    # surfaces without a Supabase round-trip.
    integrity_ok, integrity_msg = _check_package_integrity()
    details["package"] = "ok" if integrity_ok else f"fail: {integrity_msg}"
    if verbose:
        if integrity_ok:
            log.info("pkg [OK]    seeds + templates + default.yaml all loadable")
        else:
            log.error("pkg [FAIL]  %s", integrity_msg)

    if not env_ok:
        return False, details

    try:
        import psycopg
        with psycopg.connect(db_url, autocommit=True, connect_timeout=10, prepare_threshold=None) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
                cur.fetchone()
        details["db"] = "ok"
        if verbose:
            log.info("db  [OK]    connected to SUPABASE_DB_URL")
    except Exception as e:  # noqa: BLE001
        details["db"] = f"fail: {e}"
        if verbose:
            log.error("db  [FAIL]  %s", e)

    try:
        store = SupabaseCaseStore(
            cfg, supabase_url, service_role,
            investigation_id="00000000-0000-0000-0000-000000000000",
        )
        try:
            store.exists("does-not-exist.json")
            details["bucket"] = "ok"
            if verbose:
                log.info("bkt [OK]    investigation-files reachable")
        finally:
            store.close()
    except Exception as e:  # noqa: BLE001
        details["bucket"] = f"fail: {e}"
        if verbose:
            log.error("bkt [FAIL]  %s", e)

    all_ok = all(v == "ok" for v in details.values())
    return all_ok, details


def _check_package_integrity() -> tuple[bool, str]:
    """Verify every data file the pipeline reads is actually shipped.

    Loads (without I/O to external services):
      - bundled default.yaml via load_config()
      - all label seed JSONs via LabelStore.load()
      - the issuer database via freeze.asks.load_issuer_db()
      - report templates via reports.brief.TEMPLATES_DIR

    Returns ``(ok, error_message_if_any)``.
    """
    try:
        from recupero.config import load_config as _lc
        cfg, _ = _lc()  # exercises _defaults/default.yaml
    except Exception as e:  # noqa: BLE001
        return False, f"default.yaml not loadable: {e}"

    try:
        from recupero.labels.store import SEEDS_DIR
        if not SEEDS_DIR.is_dir():
            return False, f"seeds dir missing: {SEEDS_DIR}"
        seed_files = list(SEEDS_DIR.glob("*.json"))
        if not seed_files:
            return False, f"no *.json under {SEEDS_DIR}"
    except Exception as e:  # noqa: BLE001
        return False, f"seeds dir lookup failed: {e}"

    try:
        from recupero.freeze.asks import load_issuer_db
        db_entries = load_issuer_db()
        if not db_entries:
            return False, "issuer DB loaded but empty"
    except Exception as e:  # noqa: BLE001
        return False, f"issuer DB unreadable: {e}"

    try:
        from recupero.reports.brief import TEMPLATES_DIR
        if not TEMPLATES_DIR.is_dir():
            return False, f"templates dir missing: {TEMPLATES_DIR}"
        if not list(TEMPLATES_DIR.glob("*.j2")):
            return False, f"no *.j2 templates under {TEMPLATES_DIR}"
    except Exception as e:  # noqa: BLE001
        return False, f"templates dir lookup failed: {e}"

    return True, ""


def health_check() -> int:
    """CLI entry point for ``recupero-worker --health-check``.

    Returns 0 if everything is reachable, 1 otherwise.
    """
    ok, _ = _run_checks(verbose=True)
    return 0 if ok else 1


def _run_watch_tick_once(*, limit: int | None) -> int:
    """CLI entry point for ``recupero-worker --watch-tick``.

    Runs one pass of the nightly watchlist snapshot loop, renders the
    daily digest deliverable, uploads the digest to the
    ``watchlist-digest/<date>/`` bucket prefix, and prints a summary.
    Designed to be invoked from a Railway cron entry (e.g.
    ``0 3 * * *`` UTC).

    Returns 0 on a clean pass even when individual wallets fail —
    only env / DB misconfiguration produces a non-zero exit, so a
    partial-fail tick doesn't take down the cron.

    Materially-changed rows are also logged at WARNING level so they
    surface in Railway log search even before an operator opens the
    digest PDF.
    """
    import tempfile

    from recupero.worker.mini_freeze import generate_daily_digest
    from recupero.worker.watch_tick import run_watch_tick

    cfg, env = load_config()
    dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
    supabase_url = os.environ.get("SUPABASE_URL", "").strip()
    service_role = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    if not dsn:
        log.error("SUPABASE_DB_URL is not set; cannot run watch-tick")
        return 2

    log.info("watch-tick: starting; limit=%s", limit if limit else "none")
    report = run_watch_tick(
        dsn=dsn, config=cfg, env=env, limit=limit,
    )

    elapsed = (report.finished_at - report.started_at).total_seconds()
    log.info(
        "watch-tick: finished in %.1fs — candidates=%d snapshotted=%d "
        "skipped_cooldown=%d skipped_unsupported_chain=%d "
        "material_changes=%d errors=%d",
        elapsed, report.candidates, report.snapshotted,
        report.skipped_cooldown, report.skipped_unsupported_chain,
        len(report.material_changes), len(report.errors),
    )
    for mc in report.material_changes:
        log.warning(
            "watch-tick MATERIAL CHANGE: %s on %s (role=%s issuer=%s) — %s",
            mc.address, mc.chain, mc.role, mc.issuer or "-", mc.reason,
        )
    for err in report.errors:
        log.warning("watch-tick error: %s", err)

    # Total active watchlist count for the digest cover page (covers
    # both the rows snapshotted this tick AND those still in their
    # cooldown window — the operator wants to see "we monitor 1227,
    # snapshotted 245 today" not just "245 snapshotted").
    total_watched = _count_active_watchlist(dsn)

    # Render the digest unconditionally — even a no-material-change
    # tick produces an "all clear" page so the operator can confirm
    # the cron job actually ran today.
    with tempfile.TemporaryDirectory(prefix="recupero-digest-") as tmp:
        try:
            bundle = generate_daily_digest(
                report, output_dir=Path(tmp), total_watched=total_watched,
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("digest render failed: %s", exc)
            return 0  # don't fail cron on render error

        # Upload to bucket: watchlist-digest/<YYYY-MM-DD>/<digest_id>.html/.pdf
        if supabase_url and service_role:
            try:
                _upload_digest_to_bucket(
                    cfg=cfg, supabase_url=supabase_url,
                    service_role=service_role, bundle=bundle,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("digest upload skipped: %s", exc)
        else:
            log.info(
                "digest written locally to %s (bucket upload skipped — "
                "SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY not set)",
                bundle.html_path,
            )

        # Email delivery — best-effort, runs after the bucket upload
        # so the digest is durably stored before we try to push it
        # outbound. A send failure logs but doesn't fail the cron.
        try:
            from recupero.worker.digest_email import maybe_send_digest_email
            maybe_send_digest_email(
                html_path=bundle.html_path,
                pdf_path=bundle.pdf_path,
                digest_id=bundle.digest_id,
                material_count=bundle.summary.get("material_count", 0),
                freezeable_count=bundle.summary.get("freezeable_count", 0),
                total_outflow_usd=bundle.summary.get("total_outflow_usd", "0"),
                tick_date=bundle.summary.get(
                    "tick_started_at", ""
                )[:10] or "today",
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("digest email path failed: %s", exc)

    return 0


def _count_active_watchlist(dsn: str) -> int:
    """Total active rows in public.watchlist (irrespective of cooldown)."""
    import re as _re

    import psycopg as _psy
    pooled = dsn
    if "db." in pooled and ".supabase.co" in pooled:
        m = _re.search(
            r"postgres(?:ql)?://([^:]+):([^@]+)@db\.([^.]+)\.supabase\.co",
            pooled,
        )
        if m:
            user, pwd, ref = m.group(1), m.group(2), m.group(3)
            pooled = (
                f"postgresql://{user}.{ref}:{pwd}"
                f"@aws-1-us-east-1.pooler.supabase.com:6543/postgres"
            )
    try:
        with _psy.connect(pooled, autocommit=True, prepare_threshold=None,
                          connect_timeout=10) as conn, conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM public.watchlist WHERE status='active';")
            row = cur.fetchone()
            return int(row[0]) if row else 0
    except Exception as exc:  # noqa: BLE001
        log.warning("active watchlist count failed: %s", exc)
        return 0


def _upload_digest_to_bucket(
    *, cfg, supabase_url: str, service_role: str, bundle,
) -> None:
    """Upload the digest HTML + PDF to ``watchlist-digest/<date>/``.

    Uses the same ``_upload_to_subpath`` helper from worker.sync —
    the digest doesn't belong to any one investigation, so it lands
    at the bucket root prefix instead of under ``investigations/<id>/``.
    """
    from recupero.storage.supabase_case_store import SupabaseCaseStore
    # We use a placeholder investigation_id just so the SupabaseCaseStore
    # constructor is happy; we override the storage prefix per upload.
    store = SupabaseCaseStore(
        cfg, supabase_url, service_role,
        investigation_id="00000000-0000-0000-0000-000000000000",
    )
    try:
        html_dest = bundle.bucket_prefix + bundle.html_path.name
        store._upload(  # noqa: SLF001
            html_dest, bundle.html_path.read_bytes(),
            "text/html; charset=utf-8",
        )
        log.info("digest uploaded: %s", html_dest)
        if bundle.pdf_path is not None and bundle.pdf_path.exists():
            pdf_dest = bundle.bucket_prefix + bundle.pdf_path.name
            store._upload(  # noqa: SLF001
                pdf_dest, bundle.pdf_path.read_bytes(),
                "application/pdf",
            )
            log.info("digest uploaded: %s", pdf_dest)
        # Summary JSON for the admin UI's archive listing — same dir,
        # parallel filename. Listing the prefix and parsing only the
        # *.summary.json files lets the UI render the archive table
        # without downloading the much-larger HTML/PDF per row.
        if bundle.summary_path is not None and bundle.summary_path.exists():
            summary_dest = bundle.bucket_prefix + bundle.summary_path.name
            store._upload(  # noqa: SLF001
                summary_dest, bundle.summary_path.read_bytes(),
                "application/json",
            )
            log.info("digest uploaded: %s", summary_dest)
    finally:
        store.close()


def cli() -> None:
    """Console-script entry point. Wired up in pyproject.toml as
    ``recupero-worker``."""
    parser = argparse.ArgumentParser(description="Recupero investigations worker.")
    parser.add_argument(
        "--once", action="store_true",
        help="Process at most one investigation, then exit. Useful for tests "
             "and ops sanity checks.",
    )
    parser.add_argument(
        "--health-check", action="store_true",
        help="Verify env vars, DB connectivity, and bucket access; exit 0 "
             "on success / 1 on failure. Does not claim work.",
    )
    parser.add_argument(
        "--watch-tick", action="store_true",
        help="Run one watchlist snapshot pass: walks active watchlist rows, "
             "fetches current balance + tx count, writes a snapshot row, and "
             "reports material changes. Used as the entry point for the "
             "nightly Railway cron. Exits after one pass; does not claim "
             "investigations.",
    )
    parser.add_argument(
        "--watch-tick-limit", type=int, default=None,
        help="Cap how many watchlist rows --watch-tick processes in one pass. "
             "Useful for first-run validation and rate-limit budgeting.",
    )
    parser.add_argument(
        "--dashboard-summary", action="store_true",
        help="Print one-shot JSON of dashboard aggregate counters "
             "(cases, investigations, watchlist, snapshots). Same shape "
             "as the worker's /dashboard.json endpoint.",
    )
    parser.add_argument(
        "--send-followups", action="store_true",
        help="Send weekly follow-up status emails for active "
             "engagements. Used as the entry point for a daily "
             "Railway cron. Finds investigations where "
             "engagement_started_at is set, engagement_closed_at is "
             "null, and last_followup_sent_at is older than 6 days "
             "(or null). Sends one email per eligible investigation "
             "and updates last_followup_sent_at. Exits after one pass.",
    )
    parser.add_argument(
        "--monitor-tick", action="store_true",
        help="Run one monitoring-subscription poll pass (v0.14.6). "
             "Walks active rows in monitoring_subscriptions, fetches "
             "recent activity per chain adapter, evaluates against "
             "triggers, fires webhooks on matches, advances cursors. "
             "Entry point for the every-5-minutes Railway cron.",
    )
    parser.add_argument(
        "--log-level", default=os.environ.get("RECUPERO_LOG_LEVEL", "INFO"),
        help="Python logging level. Default INFO.",
    )
    args = parser.parse_args()

    load_dotenv()
    setup_logging(args.log_level.upper())

    # v0.17.0 (observability): init Sentry if SENTRY_DSN is set. No-op
    # when unset OR when sentry-sdk isn't installed; the worker keeps
    # running with JSON-formatted log output as the primary signal.
    try:
        from recupero.observability import init_sentry
        init_sentry()
    except Exception as exc:  # noqa: BLE001
        log.warning("Sentry init failed (non-fatal): %s", exc)

    if args.health_check:
        sys.exit(health_check())

    if args.watch_tick:
        sys.exit(_run_watch_tick_once(limit=args.watch_tick_limit))

    if args.dashboard_summary:
        import json as _json

        from recupero.worker.dashboard_summary import build_dashboard_summary
        dsn = os.environ.get("SUPABASE_DB_URL", "")
        if not dsn:
            log.error("SUPABASE_DB_URL is not set")
            sys.exit(2)
        print(_json.dumps(build_dashboard_summary(dsn=dsn), indent=2))
        sys.exit(0)

    if args.monitor_tick:
        from recupero.worker.monitor_tick import main as _monitor_main
        sys.exit(_monitor_main())

    if args.send_followups:
        from recupero.worker._followup import run_followup_cron
        dsn = os.environ.get("SUPABASE_DB_URL", "")
        if not dsn:
            log.error("SUPABASE_DB_URL is not set")
            sys.exit(2)
        report = run_followup_cron(dsn=dsn)
        log.info(
            "followup cron: candidates=%d sent=%d failed=%d "
            "skipped_no_email=%d skipped_disabled=%d",
            report["candidates"], report["sent"], report["failed"],
            report["skipped_no_email"],
            report.get("skipped_disabled", 0),
        )
        # Skipped-disabled is RECUPERO_DISABLE_EMAIL=1 (intentional),
        # not a failure. Only true failures trip non-zero exit code.
        sys.exit(0 if report["failed"] == 0 else 1)

    heartbeat_sec = float(
        os.environ.get("RECUPERO_HEARTBEAT_INTERVAL_SEC", _HEARTBEAT_DEFAULT_SEC)
    )
    stale_after_sec = int(
        os.environ.get("RECUPERO_STALE_AFTER_SEC", _STALE_DEFAULT_SEC)
    )
    poll_idle_sec = float(
        os.environ.get("RECUPERO_POLL_IDLE_SEC", _POLL_IDLE_DEFAULT_SEC)
    )
    poll_max_sec = float(
        os.environ.get("RECUPERO_POLL_MAX_SEC", _POLL_MAX_DEFAULT_SEC)
    )

    try:
        run_forever(
            once=args.once,
            heartbeat_sec=heartbeat_sec,
            stale_after_sec=stale_after_sec,
            poll_idle_sec=poll_idle_sec,
            poll_max_sec=poll_max_sec,
        )
    except KeyboardInterrupt:
        log.info("interrupted; shutting down")


if __name__ == "__main__":  # pragma: no cover
    cli()
