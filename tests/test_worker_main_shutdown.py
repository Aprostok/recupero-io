"""Worker main() shutdown + supervision audit (Wave-9 narrow audit).

Hunts:
  1. SIGTERM handler is registered and flips a shutdown Event the run
     loop checks every iteration (Railway redeploy must drain
     gracefully, not abandon mid-stage).
  2. Crash-loop protection: if the worker startup crashes within a
     few seconds, Railway will restart immediately and burn quota +
     log spam. The entrypoint must enforce a *minimum-uptime* check
     before letting a crash bubble up as a normal non-zero exit —
     either by sleeping out the difference, or by tagging the exit
     code in a way ops can correlate.
  3. Exit codes: a clean shutdown (SIGTERM drained) must exit 0; a
     missing-env / crash must exit non-0. Railway distinguishes
     these in the deploy log so ops doesn't get woken at 3am for an
     intentional redeploy.
  4. Heartbeat thread is daemon=True (won't keep interpreter alive
     after a crash) AND its stop() join is bounded so a hung DB
     can't wedge worker exit indefinitely.
  5. In-flight investigation: shutdown signal mid-claim does not
     abandon the row — pipeline finishes the current investigation
     before the loop terminates. The reaper covers SIGKILL.

These tests use threading.Event mocks for signal handlers so they
run on Windows + POSIX without actually raising signals at the
process.
"""

from __future__ import annotations

import signal
import threading
import time
from unittest.mock import MagicMock, patch

from recupero.worker import main as worker_main


# ---------------------------------------------------------------------------
# Test 1: SIGTERM handler installs and sets shutdown event
# ---------------------------------------------------------------------------
def test_install_signal_handlers_registers_sigterm_and_sigint():
    """Pre-fix: any regression that drops _install_signal_handlers (e.g.
    moving the call inside a branch that's never taken on Railway)
    means SIGTERM kills the worker mid-stage instead of draining."""
    # Reset the module-level event between tests so a prior test
    # leaving it set doesn't poison this one.
    worker_main._shutdown.clear()

    installed: dict[int, object] = {}

    def fake_signal(sig, handler):
        installed[int(sig)] = handler
        return signal.SIG_DFL

    with patch.object(worker_main.signal, "signal", side_effect=fake_signal):
        worker_main._install_signal_handlers()

    assert int(signal.SIGTERM) in installed, "SIGTERM handler not registered"
    assert int(signal.SIGINT) in installed, "SIGINT handler not registered"

    # Invoke the handler the same way the kernel would and verify it
    # flips the shutdown event.
    handler = installed[int(signal.SIGTERM)]
    assert callable(handler)
    handler(signal.SIGTERM, None)
    assert worker_main._shutdown.is_set(), (
        "SIGTERM handler did not set the shutdown flag — the polling "
        "loop will not drain on Railway redeploy"
    )
    worker_main._shutdown.clear()


# ---------------------------------------------------------------------------
# Test 2: Crash-loop protection — minimum uptime before exit propagates
# ---------------------------------------------------------------------------
def test_crash_loop_protection_minimum_uptime_guard_exists():
    """If the worker crashes <N seconds after startup, the entrypoint
    must enforce a minimum-uptime delay before the non-zero exit
    actually propagates. Without it, Railway restarts the container
    in a tight loop, burning quota + flooding logs.

    Pre-fix: cli() has no _MIN_UPTIME_SEC constant and no _enforce_min_uptime
    helper. This RED test asserts the symbol exists; once it's added,
    GREEN.
    """
    assert hasattr(worker_main, "_MIN_UPTIME_SEC"), (
        "No minimum-uptime constant — a startup-crash will hot-loop "
        "on Railway. Add _MIN_UPTIME_SEC (e.g., 30s) and gate the "
        "non-zero exit on it."
    )
    val = worker_main._MIN_UPTIME_SEC
    assert isinstance(val, (int, float)) and val > 0
    assert hasattr(worker_main, "_enforce_min_uptime"), (
        "No _enforce_min_uptime helper — the constant alone isn't "
        "wired in."
    )


def test_enforce_min_uptime_sleeps_when_crash_too_fast(monkeypatch):
    """If the process has been up < _MIN_UPTIME_SEC, the helper must
    sleep out the remainder before returning. Verified via a fake
    time.sleep recorder."""
    sleeps: list[float] = []
    monkeypatch.setattr(worker_main.time, "sleep", lambda s: sleeps.append(s))

    # Simulate "started 0.5s ago"
    started_at = time.monotonic() - 0.5
    worker_main._enforce_min_uptime(started_at)

    # Must have slept SOMETHING (the gap to _MIN_UPTIME_SEC).
    assert sleeps, (
        "_enforce_min_uptime didn't sleep — Railway will crash-loop "
        "this container."
    )
    # Sanity: the sleep should be < _MIN_UPTIME_SEC and > 0.
    assert all(0 < s <= worker_main._MIN_UPTIME_SEC for s in sleeps)


def test_enforce_min_uptime_does_not_sleep_when_uptime_sufficient(monkeypatch):
    """If the worker ran for hours then crashed, no extra sleep."""
    sleeps: list[float] = []
    monkeypatch.setattr(worker_main.time, "sleep", lambda s: sleeps.append(s))

    # Simulate "started 1 hour ago"
    started_at = time.monotonic() - 3600
    worker_main._enforce_min_uptime(started_at)

    assert not sleeps, (
        "_enforce_min_uptime slept on a long-uptime crash; that's "
        "wasted Railway grace period."
    )


# ---------------------------------------------------------------------------
# Test 3: Clean-shutdown exit code is 0
# ---------------------------------------------------------------------------
def test_run_forever_clean_shutdown_returns_normally(monkeypatch):
    """Setting _shutdown before run_forever() loops once must return
    normally (no exception), so cli() exits with code 0."""
    # Stub out everything that hits the network / db.
    monkeypatch.setattr(worker_main, "load_config", lambda: ({}, {}))
    monkeypatch.setattr(worker_main, "_missing_env_vars", lambda: [])
    monkeypatch.setattr(
        worker_main, "start_health_server", lambda *_a, **_kw: None,
    )

    fake_db = MagicMock()
    fake_db.reap_post_deploy_orphans.return_value = []
    fake_db.reap_stale_claims.return_value = []
    fake_db.claim_one.return_value = None
    monkeypatch.setattr(
        worker_main, "WorkerDB", lambda *_a, **_kw: fake_db,
    )

    # Pre-set required env so the early-exit branch isn't taken.
    monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "sr")
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://x")

    worker_main._shutdown.set()
    try:
        # Should return cleanly, not raise.
        worker_main.run_forever(once=False)
    finally:
        worker_main._shutdown.clear()

    fake_db.close.assert_called_once()


# ---------------------------------------------------------------------------
# Test 4: Heartbeat thread is daemon + bounded-join
# ---------------------------------------------------------------------------
def test_heartbeat_thread_is_daemon_and_join_bounded():
    """Daemon=True so it can't keep the interpreter alive after main
    exits. Join timeout must be finite so a hung DB doesn't wedge
    shutdown."""
    fake_db = MagicMock()
    fake_inv = MagicMock(id="test-id")
    hb = worker_main._Heartbeat(fake_db, fake_inv, interval_sec=0.01)
    hb.start()
    try:
        assert hb._thread.daemon, "heartbeat thread must be daemon=True"
    finally:
        hb.stop()
    assert not hb._thread.is_alive(), (
        "heartbeat thread did not exit after stop()"
    )
    assert isinstance(
        worker_main._Heartbeat._STOP_JOIN_TIMEOUT_SEC, (int, float)
    )
    assert float("inf") > worker_main._Heartbeat._STOP_JOIN_TIMEOUT_SEC, (
        "stop() join timeout must be finite, else a hung DB blocks "
        "worker exit forever"
    )


# ---------------------------------------------------------------------------
# Test 5: Shutdown flag interrupts idle polling sleep (drains promptly)
# ---------------------------------------------------------------------------
def test_shutdown_during_idle_poll_breaks_loop_quickly(monkeypatch):
    """When the idle backoff is sleeping, setting _shutdown must
    interrupt it within the wait window so we don't burn the
    Railway 30s grace period on a single sleep."""
    monkeypatch.setattr(worker_main, "load_config", lambda: ({}, {}))
    monkeypatch.setattr(worker_main, "_missing_env_vars", lambda: [])
    monkeypatch.setattr(
        worker_main, "start_health_server", lambda *_a, **_kw: None,
    )

    fake_db = MagicMock()
    fake_db.reap_post_deploy_orphans.return_value = []
    fake_db.reap_stale_claims.return_value = []
    fake_db.claim_one.return_value = None
    monkeypatch.setattr(
        worker_main, "WorkerDB", lambda *_a, **_kw: fake_db,
    )

    monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "sr")
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://x")

    # Fire shutdown from a side thread 50ms into the loop.
    worker_main._shutdown.clear()

    def trigger():
        time.sleep(0.05)
        worker_main._shutdown.set()

    t = threading.Thread(target=trigger, daemon=True)
    t.start()

    start = time.monotonic()
    try:
        worker_main.run_forever(
            once=False,
            poll_idle_sec=5.0,  # would block 5s if shutdown weren't honored
            poll_max_sec=5.0,
            heartbeat_sec=1.0,
            stale_after_sec=300,
        )
    finally:
        worker_main._shutdown.clear()
    elapsed = time.monotonic() - start

    assert elapsed < 2.0, (
        f"shutdown flag did not interrupt idle poll promptly "
        f"(elapsed={elapsed:.2f}s); loop is using time.sleep() "
        f"instead of _shutdown.wait()"
    )
