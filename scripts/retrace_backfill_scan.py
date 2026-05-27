#!/usr/bin/env python3
"""Scan all cases for re-trace candidates based on label DB updates.

Gap #14 (v0.31.2 trace-gap audit) — observability cron. Cases whose
trace_completed_at predates a "trace-shape-changing" label
(bridge / mixer / exchange_deposit / exchange_hot_wallet /
perpetrator) gaining a counterparty match are surfaced as
re-trace candidates. The cron WRITES A REPORT; it does not
auto-re-trace. Operators decide.

Usage:
  python scripts/retrace_backfill_scan.py [--out PATH] [--verbose]

Defaults to writing data/retrace_candidates.json relative to the
caller's cwd. Reads RECUPERO_DATA_DIR (the configured data dir,
where the LabelStore picks up local_*.json overrides and the
CaseStore reads cases/) the same way every other recupero CLI does.

This is the script-flavored entry point. The same logic is exposed
as ``recupero.worker.retrace_backfill.main``, and via the ops CLI as
``recupero-ops retrace-scan`` once that command lands.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add the project src/ to sys.path when invoked as a bare script so
# the import below resolves without an install step. No-op when the
# package is already installed (the path simply prepends a duplicate
# location).
_HERE = Path(__file__).resolve().parent
_SRC = _HERE.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from recupero.worker import retrace_backfill  # noqa: E402


if __name__ == "__main__":
    sys.exit(retrace_backfill.main())
