#!/usr/bin/env python3
"""Alert on investigations stuck in ``awaiting_review`` for too long.

The worker pauses every investigation at ``awaiting_review`` so a human
can review the AI-drafted editorial before it ships. If nobody clicks
"approve" the row sits there forever — there's no automated escalation,
because the brief might genuinely need a rewrite. This script is the
escalation: scheduled daily, it queries Supabase for any awaiting_review
row older than the threshold and exits non-zero so a cron / GitHub
Action / monitoring tool can alert.

Usage:
    python scripts/check_stale_reviews.py
    python scripts/check_stale_reviews.py --threshold-hours 48
    python scripts/check_stale_reviews.py --json   # machine-readable output

Exit codes:
    0  no stale reviews
    1  stale reviews found
    2  configuration / connection error

Wire to cron / GitHub Actions for daily run; see docs/RAILWAY_DEPLOY.md
§"Stale review monitoring".
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import psycopg  # noqa: E402
from dotenv import load_dotenv  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402

_QUERY = """
    SELECT
        i.id,
        i.case_id,
        i.review_required_at,
        i.chain,
        i.seed_address,
        c.case_number,
        c.client_name,
        EXTRACT(EPOCH FROM (NOW() - i.review_required_at)) / 3600.0 AS age_hours
      FROM public.investigations i
      LEFT JOIN public.cases c ON c.id = i.case_id
     WHERE i.status = 'awaiting_review'
       AND i.review_required_at IS NOT NULL
       AND i.review_required_at < NOW() - make_interval(hours => %(hours)s)
     ORDER BY i.review_required_at ASC;
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--threshold-hours",
        type=int,
        default=24,
        help="Alert on awaiting_review rows older than this many hours (default: 24).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of human-readable text. Useful for piping to alerting tools.",
    )
    args = parser.parse_args()

    load_dotenv()
    dsn = os.getenv("SUPABASE_DB_URL")
    if not dsn:
        print("ERROR: SUPABASE_DB_URL is not set.", file=sys.stderr)
        return 2

    try:
        with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(_QUERY, {"hours": args.threshold_hours})
                rows = cur.fetchall()
    except psycopg.Error as exc:
        print(f"ERROR: database query failed: {exc}", file=sys.stderr)
        return 2

    if args.json:
        payload = {
            "threshold_hours": args.threshold_hours,
            "stale_count": len(rows),
            "investigations": [
                {
                    "id": str(r["id"]),
                    "case_id": str(r["case_id"]),
                    "case_number": r["case_number"],
                    "client_name": r["client_name"],
                    "chain": r["chain"],
                    "seed_address": r["seed_address"],
                    "review_required_at": r["review_required_at"].isoformat(),
                    "age_hours": round(float(r["age_hours"]), 1),
                }
                for r in rows
            ],
        }
        print(json.dumps(payload, indent=2))
        return 1 if rows else 0

    if not rows:
        print(f"OK: no awaiting_review rows older than {args.threshold_hours}h.")
        return 0

    print(
        f"STALE REVIEW ALERT: {len(rows)} investigation(s) "
        f"in awaiting_review > {args.threshold_hours}h:"
    )
    print()
    for r in rows:
        age_h = float(r["age_hours"])
        print(f"  • inv {r['id']}")
        print(f"    case   : {r['case_number'] or '-'}  ({r['client_name'] or '-'})")
        print(f"    chain  : {r['chain']}  seed: {r['seed_address']}")
        print(
            f"    waiting: {age_h:.1f}h "
            f"(since {r['review_required_at'].isoformat()})"
        )
        print()
    print("Action: open the admin UI and either approve, edit, or fail each row.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
