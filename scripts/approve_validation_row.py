"""Approve a validation row that's stuck at ``awaiting_review`` so the
worker re-claims it and runs ``building_package`` (where the new flow-
diagram + appendix rendering happens).

Mirrors what the admin UI's review-approval flow does:
  1. Fills any TODO placeholders in ``brief_editorial.json`` with a
     deterministic test value (the worker's emit-brief stage rejects
     editorials with leftover TODO markers).
  2. Sets ``REVIEW_REQUIRED = false`` on the editorial document.
  3. Flips the DB row to ``review_approved`` and clears worker_id.

Run:
    python scripts/approve_validation_row.py <investigation_id>
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import psycopg  # noqa: E402
from dotenv import load_dotenv  # noqa: E402


def _pooled_dsn(dsn: str) -> str:
    if "db." in dsn and ".supabase.co" in dsn:
        m = re.search(
            r"postgres(?:ql)?://([^:]+):([^@]+)@db\.([^.]+)\.supabase\.co", dsn
        )
        if m:
            user, pwd, ref = m.group(1), m.group(2), m.group(3)
            return (
                f"postgresql://{user}.{ref}:{pwd}"
                f"@aws-1-us-east-1.pooler.supabase.com:6543/postgres"
            )
    return dsn


def _fill_todos(obj: Any, _path: str = "") -> int:
    """Walk an editorial dict and replace any string containing "TODO:"
    with a deterministic test value. Skips the same metadata keys
    emit_brief skips (AI_GENERATED etc.) so we don't trample legitimate
    TODO mentions in REVIEW_INSTRUCTIONS."""
    skip = {"AI_GENERATED", "AI_MODEL", "AI_GENERATED_AT",
            "REVIEW_REQUIRED", "REVIEW_INSTRUCTIONS"}
    count = 0
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if not _path and k in skip:
                continue
            if isinstance(v, str) and "TODO:" in v:
                obj[k] = f"[validation fill-in for {k}]"
                count += 1
            else:
                count += _fill_todos(v, f"{_path}.{k}" if _path else k)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, str) and "TODO:" in item:
                obj[i] = f"[validation fill-in #{i}]"
                count += 1
            else:
                count += _fill_todos(item, f"{_path}[{i}]")
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("investigation_id", help="UUID of the row to approve.")
    args = parser.parse_args()

    load_dotenv(override=True)

    supabase_url = os.environ["SUPABASE_URL"]
    service_role = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    dsn = _pooled_dsn(os.environ["SUPABASE_DB_URL"])

    from recupero.config import load_config
    from recupero.storage.supabase_case_store import SupabaseCaseStore

    cfg, _ = load_config()

    inv_id = args.investigation_id

    # Fill TODOs and flip REVIEW_REQUIRED in the bucket.
    with SupabaseCaseStore(cfg, supabase_url, service_role,
                            investigation_id=inv_id) as store:
        ed = store.read_json("brief_editorial.json")
        n = _fill_todos(ed)
        ed["REVIEW_REQUIRED"] = False
        store.write_json("brief_editorial.json", ed)
        print(f"bucket: filled {n} TODO placeholder(s)")
        print(f"bucket: REVIEW_REQUIRED -> false")

    # Flip status on the DB row.
    sql = (
        "UPDATE public.investigations "
        "SET status='review_approved', worker_id=NULL, last_heartbeat_at=NULL "
        "WHERE id=%s;"
    )
    with psycopg.connect(dsn, autocommit=True, prepare_threshold=None) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (inv_id,))
    print(f"db: status -> review_approved")
    print()
    print("Railway should re-claim within ~10s and run building_package.")
    print("That stage exercises the new flow-diagram + appendix code.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
