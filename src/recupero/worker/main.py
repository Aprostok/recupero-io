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
import socket
import sys
import threading
import time
from typing import Final

from dotenv import load_dotenv

from recupero.config import load_config
from recupero.logging_setup import setup_logging
from recupero.storage.supabase_case_store import SupabaseCaseStore
from recupero.worker import state as S
from recupero.worker._health_server import start_health_server
from recupero.worker.db import Investigation, WorkerDB
from recupero.worker.pipeline import run_one

log = logging.getLogger(__name__)


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

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=self._interval + 5)

    def _run(self) -> None:
        # Wait the interval first; the claim already set the heartbeat to NOW().
        while not self._stop.wait(self._interval):
            try:
                self._db.heartbeat(self._inv.id)
            except Exception as e:  # noqa: BLE001
                log.warning("heartbeat failed for %s: %s", self._inv.id, e)


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

    supabase_url = os.environ.get("SUPABASE_URL", "").strip()
    service_role = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    db_url = os.environ.get("SUPABASE_DB_URL", "").strip()
    if not supabase_url or not service_role or not db_url:
        log.error(
            "missing required env vars; need SUPABASE_URL, "
            "SUPABASE_SERVICE_ROLE_KEY, SUPABASE_DB_URL"
        )
        sys.exit(2)

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

    db = WorkerDB(db_url, worker_id=worker_id)

    backoff = poll_idle_sec
    try:
        while True:
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
                time.sleep(backoff)
                backoff = min(backoff * 1.5, poll_max_sec)
                continue
            backoff = poll_idle_sec  # reset

            # New work — open a per-investigation bucket store and run.
            with SupabaseCaseStore(
                cfg, supabase_url, service_role,
                investigation_id=str(inv.id),
            ) as store:
                hb = _Heartbeat(db, inv, heartbeat_sec)
                hb.start()
                try:
                    run_one(inv, config=cfg, env=env, db=db, store=store)
                finally:
                    hb.stop()

            if once:
                return
    finally:
        db.close()


def _try_claim(db: WorkerDB) -> Investigation | None:
    try:
        return db.claim_one()
    except Exception as e:  # noqa: BLE001
        log.error("claim_one failed (will retry): %s", e)
        return None


# ----- CLI ----- #


def _run_checks(verbose: bool = True) -> tuple[bool, dict[str, str]]:
    """Run env + DB + bucket reachability checks.

    Returns ``(all_ok, details_dict)`` where details maps each check
    name to ``"ok"`` or an error message. Logs human-readable lines
    when ``verbose=True`` (used by --health-check); the HTTP healthcheck
    handler calls with verbose=False to avoid log spam.
    """
    cfg, _env = load_config()
    details: dict[str, str] = {}

    supabase_url = os.environ.get("SUPABASE_URL", "").strip()
    service_role = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    db_url = os.environ.get("SUPABASE_DB_URL", "").strip()
    env_ok = bool(supabase_url and service_role and db_url)
    for name, val in (("SUPABASE_URL", supabase_url),
                      ("SUPABASE_SERVICE_ROLE_KEY", service_role),
                      ("SUPABASE_DB_URL", db_url)):
        details[f"env:{name}"] = "ok" if val else "missing"
        if verbose:
            if val:
                log.info("env [OK]    %s set", name)
            else:
                log.error("env [MISS]  %s missing", name)

    if not env_ok:
        return False, details

    try:
        import psycopg
        with psycopg.connect(db_url, autocommit=True, connect_timeout=10) as conn:
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


def health_check() -> int:
    """CLI entry point for ``recupero-worker --health-check``.

    Returns 0 if everything is reachable, 1 otherwise.
    """
    ok, _ = _run_checks(verbose=True)
    return 0 if ok else 1


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
        "--log-level", default=os.environ.get("RECUPERO_LOG_LEVEL", "INFO"),
        help="Python logging level. Default INFO.",
    )
    args = parser.parse_args()

    load_dotenv()
    setup_logging(args.log_level.upper())

    if args.health_check:
        sys.exit(health_check())

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
