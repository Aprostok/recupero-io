"""Wave-9 audit: leftover unguarded type coercions on EXTERNAL data.

These tests scan code paths that still call ``int()`` / ``float()`` /
``Decimal()`` on env vars or HTTP responses without a try/except guard.
Prior waves (1-8) hardened chains/, storage/, pricing/coingecko.py,
worker/_victim_summary, _freeze_followup, _email, pipeline, reports/, and
recovery/scorer. This file targets the remaining sites:

  * src/recupero/dormant/finder.py        (module-level _DORMANT_CONCURRENCY)
  * src/recupero/worker/_health_server.py (PORT env var)
  * src/recupero/worker/digest_email.py   (RECUPERO_SMTP_PORT)
  * src/recupero/worker/main.py           (4 heartbeat/poll env vars)

Pattern: when an operator (or container orchestrator) supplies a
malformed env var (``"abc"``, empty string, ``"1.5"`` for an int slot,
``"NaN"``), the program should fall back to a sane default instead of
raising ``ValueError`` and crashing on import / startup.
"""

from __future__ import annotations

import importlib
import os
import sys
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Test 1: dormant/finder.py module-level _DORMANT_CONCURRENCY
# ---------------------------------------------------------------------------
def test_dormant_finder_bad_concurrency_env_var_does_not_crash_import():
    """A malformed RECUPERO_DORMANT_CONCURRENCY env var should not crash
    the *module import*. Pre-fix the module-level ``int(os.environ.get(...))``
    runs at import time → ValueError propagates out of the import → the
    entire CLI and worker fail to start."""
    sys.modules.pop("recupero.dormant.finder", None)
    with patch.dict(os.environ, {"RECUPERO_DORMANT_CONCURRENCY": "five"}):
        # Pre-fix: ValueError: invalid literal for int() with base 10: 'five'
        mod = importlib.import_module("recupero.dormant.finder")
        importlib.reload(mod)
        # Default fallback (5) must apply; never crash.
        assert isinstance(mod._DORMANT_CONCURRENCY, int)
        assert mod._DORMANT_CONCURRENCY >= 1


def test_dormant_finder_empty_concurrency_env_var_does_not_crash():
    sys.modules.pop("recupero.dormant.finder", None)
    with patch.dict(os.environ, {"RECUPERO_DORMANT_CONCURRENCY": ""}):
        mod = importlib.import_module("recupero.dormant.finder")
        importlib.reload(mod)
        assert isinstance(mod._DORMANT_CONCURRENCY, int)
        assert mod._DORMANT_CONCURRENCY >= 1


def test_dormant_finder_negative_concurrency_clamped():
    """Negative concurrency would crash ThreadPoolExecutor(max_workers=-1)
    later. Validate at boundary."""
    sys.modules.pop("recupero.dormant.finder", None)
    with patch.dict(os.environ, {"RECUPERO_DORMANT_CONCURRENCY": "-3"}):
        mod = importlib.import_module("recupero.dormant.finder")
        importlib.reload(mod)
        assert mod._DORMANT_CONCURRENCY >= 1


# ---------------------------------------------------------------------------
# Test 2: worker/_health_server.py PORT env var
# ---------------------------------------------------------------------------
def test_health_server_bad_port_env_var_does_not_crash():
    """A misconfigured PORT="foo" should not crash start_health_server —
    it should fall back to the default 8080 (and ideally log a warning).
    Pre-fix: ValueError propagates out, worker fails to start."""
    from recupero.worker import _health_server

    def fake_check_fn():
        return True, {}

    with patch.dict(os.environ, {"PORT": "not-a-port"}):
        # Pre-fix raises ValueError. Post-fix: the inner ``_resolve_port``
        # helper returns 8080 and start_health_server can still spin up.
        # We don't actually bind a socket here — just import + call the
        # resolver path.
        port = _health_server._resolve_health_port()
        assert isinstance(port, int)
        assert 1 <= port <= 65535


def test_health_server_empty_port_env_var_defaults():
    from recupero.worker import _health_server
    with patch.dict(os.environ, {"PORT": ""}):
        port = _health_server._resolve_health_port()
        assert port == 8080


def test_health_server_out_of_range_port_clamped():
    """PORT="99999" is numerically valid but not a valid TCP port.
    Treat as misconfiguration and fall back."""
    from recupero.worker import _health_server
    with patch.dict(os.environ, {"PORT": "99999"}):
        port = _health_server._resolve_health_port()
        assert 1 <= port <= 65535


# ---------------------------------------------------------------------------
# Test 3: worker/digest_email.py RECUPERO_SMTP_PORT
# ---------------------------------------------------------------------------
def test_digest_email_bad_smtp_port_does_not_crash():
    """An operator setting ``RECUPERO_SMTP_PORT=auto`` (typo) should
    fall back to 587, not crash the nightly digest cron."""
    from recupero.worker import digest_email
    with patch.dict(os.environ, {"RECUPERO_SMTP_PORT": "auto"}):
        port = digest_email._resolve_smtp_port()
        assert isinstance(port, int)
        assert port == 587


def test_digest_email_negative_smtp_port_defaults():
    from recupero.worker import digest_email
    with patch.dict(os.environ, {"RECUPERO_SMTP_PORT": "-1"}):
        port = digest_email._resolve_smtp_port()
        assert port == 587


# ---------------------------------------------------------------------------
# Test 4: worker/main.py heartbeat / poll env vars
# ---------------------------------------------------------------------------
def test_worker_main_bad_heartbeat_env_var_falls_back():
    """A malformed RECUPERO_HEARTBEAT_INTERVAL_SEC must not prevent the
    worker entrypoint from starting. Pre-fix: float("oops") raises and
    the process exits before run_forever() is reached."""
    from recupero.worker import main as wmain
    with patch.dict(os.environ, {"RECUPERO_HEARTBEAT_INTERVAL_SEC": "oops"}):
        val = wmain._resolve_float_env(
            "RECUPERO_HEARTBEAT_INTERVAL_SEC",
            default=wmain._HEARTBEAT_DEFAULT_SEC,
        )
        assert isinstance(val, float)
        assert val > 0


def test_worker_main_nan_heartbeat_falls_back():
    """NaN passes ``float()`` but breaks every timing comparator
    downstream (NaN < x is False)."""
    from recupero.worker import main as wmain
    with patch.dict(os.environ, {"RECUPERO_POLL_IDLE_SEC": "NaN"}):
        val = wmain._resolve_float_env(
            "RECUPERO_POLL_IDLE_SEC",
            default=wmain._POLL_IDLE_DEFAULT_SEC,
        )
        # NaN must be rejected.
        assert val == wmain._POLL_IDLE_DEFAULT_SEC


def test_worker_main_bad_stale_after_int_falls_back():
    from recupero.worker import main as wmain
    with patch.dict(os.environ, {"RECUPERO_STALE_AFTER_SEC": "1.5"}):
        # "1.5" is not a valid int — pre-fix int("1.5") raises ValueError.
        val = wmain._resolve_int_env(
            "RECUPERO_STALE_AFTER_SEC",
            default=wmain._STALE_DEFAULT_SEC,
        )
        assert isinstance(val, int)
        assert val == wmain._STALE_DEFAULT_SEC
