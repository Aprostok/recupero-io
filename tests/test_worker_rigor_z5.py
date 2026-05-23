"""RIGOR-Jacob Z5: worker module adversarial-input hardening.

Two real bugs:

* Z5-1: ``worker/monitor_tick.py`` evaluates ``int(os.environ.get(...))``
  at MODULE LOAD time on ``RECUPERO_MONITOR_MAX_SUBS_PER_TICK`` and
  ``RECUPERO_MONITOR_MAX_ACTIVITY_PER_SUB``. A garbage / accidental
  non-numeric value in either env var raises ``ValueError`` from
  ``recupero.worker.monitor_tick`` import — and because that module is
  in the worker CLI's import graph (``recupero-worker monitor-tick``
  subcommand), the entire worker boot crashes. The other env-driven
  int conversions in the package (``pipeline._default_incident_time_for``)
  guard with try/except + fallback; this one doesn't.

* Z5-2: ``pipeline._parse_usd`` → ``_summarize_brief`` accepts
  ``"$NaN"`` / ``"$Infinity"`` from freeze_brief.json and returns a
  non-finite ``Decimal``. That value then flows into
  ``db.mark_built_package`` which writes it to ``investigations.
  total_loss_usd`` / ``max_recoverable_usd`` (Postgres ``numeric``).
  Postgres ``numeric`` accepts NaN and Infinity, and downstream
  dashboard / priors aggregation that sums or compares the column
  inherits the NaN — silently corrupting every aggregated metric.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path


def test_monitor_tick_module_imports_on_garbage_env_var(tmp_path: Path) -> None:
    """Z5-1 RED → GREEN: a non-numeric RECUPERO_MONITOR_MAX_SUBS_PER_TICK
    env var must NOT crash the worker process at module import.

    Sub-process so the test's own already-loaded copy of monitor_tick
    (with the bug pre-imported under a sane env) can't mask the issue.
    """
    env = os.environ.copy()
    env["RECUPERO_MONITOR_MAX_SUBS_PER_TICK"] = "not-a-number"
    env["RECUPERO_MONITOR_MAX_ACTIVITY_PER_SUB"] = "also-junk"
    # The import path that gets walked by `recupero-worker monitor-tick`.
    code = (
        "import importlib, sys\n"
        "m = importlib.import_module('recupero.worker.monitor_tick')\n"
        # Both constants must fall back to a usable default rather than
        # raise. The exact default isn't load-bearing; what matters is
        # that the module imports cleanly and exports a positive int.
        "assert isinstance(m._MAX_SUBSCRIPTIONS_PER_TICK, int), "
        "    m._MAX_SUBSCRIPTIONS_PER_TICK\n"
        "assert m._MAX_SUBSCRIPTIONS_PER_TICK > 0, "
        "    m._MAX_SUBSCRIPTIONS_PER_TICK\n"
        "assert isinstance(m._MAX_ACTIVITY_PER_SUB, int), "
        "    m._MAX_ACTIVITY_PER_SUB\n"
        "assert m._MAX_ACTIVITY_PER_SUB > 0, m._MAX_ACTIVITY_PER_SUB\n"
        "print('ok')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, (
        f"monitor_tick crashed on garbage env vars (Z5-1):\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    assert "ok" in result.stdout


def test_parse_usd_rejects_nan_and_infinity() -> None:
    """Z5-2 RED → GREEN: _parse_usd must reject non-finite Decimals.

    A freeze_brief carrying ``"$NaN"`` or ``"$Infinity"`` must NOT
    propagate a non-finite ``Decimal`` to the DB-write path.
    """
    from recupero.worker.pipeline import _parse_usd

    for poison in ("$NaN", "$nan", "$Infinity", "$-Infinity", "$inf"):
        result = _parse_usd(poison)
        assert result is None or (
            isinstance(result, Decimal) and result.is_finite()
        ), (
            f"_parse_usd({poison!r}) returned non-finite {result!r} — "
            "this writes NaN/Infinity to investigations.total_loss_usd "
            "and corrupts every downstream aggregation."
        )


def test_summarize_brief_never_emits_non_finite_decimal(tmp_path: Path) -> None:
    """Z5-2 end-to-end: a malicious freeze_brief.json with NaN /
    Infinity USD strings must produce ``None`` totals (which
    ``mark_built_package`` COALESCEs away), not a non-finite Decimal
    written to the DB.
    """
    from recupero.worker.pipeline import _summarize_brief

    brief_path = tmp_path / "freeze_brief.json"
    brief_path.write_text(json.dumps({
        "TOTAL_LOSS_USD": "$Infinity",
        "MAX_RECOVERABLE_USD": "$NaN",
        "FREEZABLE": [{"issuer": "Circle"}],
    }))
    out = _summarize_brief(brief_path)
    for key in ("total_loss_usd", "max_recoverable_usd"):
        value = out.get(key)
        assert value is None or (
            isinstance(value, Decimal) and value.is_finite()
        ), (
            f"_summarize_brief leaked non-finite Decimal at {key}: "
            f"{value!r}. This propagates through "
            "db.mark_built_package → investigations.{key}."
        )
