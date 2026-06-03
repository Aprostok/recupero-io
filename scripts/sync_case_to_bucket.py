#!/usr/bin/env python3
"""Upload an already-traced local case dir to the Supabase bucket.

Usage:
    python scripts/sync_case_to_bucket.py <case_id> <investigation_id>

Loads .env, locates the local case dir via CaseStore, and mirrors it to
``investigations/<investigation_id>/`` in the bucket — identical to
``recupero trace --investigation-id``'s final step, but WITHOUT re-running
the (slow) trace. Handy when a trace already wrote case.json locally but the
bucket sync was skipped/failed.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dotenv import load_dotenv  # noqa: E402


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: python scripts/sync_case_to_bucket.py <case_id> <investigation_id>")
        return 2
    case_id, investigation_id = sys.argv[1], sys.argv[2]

    load_dotenv()
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    if not url or not key:
        print("ERROR: SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY missing from .env")
        return 2

    from recupero.config import load_config
    from recupero.storage.case_store import CaseStore
    from recupero.storage.supabase_case_store import SupabaseCaseStore
    from recupero.worker.sync import upload_case_dir

    cfg, _env = load_config()
    case_dir = CaseStore(cfg).case_dir(case_id)
    if not (case_dir / "case.json").exists():
        print(f"ERROR: no case.json at {case_dir} — did the trace finish?")
        return 1

    with SupabaseCaseStore(cfg, url, key, investigation_id=investigation_id) as store:
        n = upload_case_dir(case_dir, store)
    print(f"synced {n} file(s) from {case_dir} to investigations/{investigation_id}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
