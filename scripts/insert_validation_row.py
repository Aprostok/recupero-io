"""Insert a fresh ``pending`` investigations row for Railway to claim.

Used to validate code changes against the live deployed worker: push
the change to main, wait ~2-3 min for Railway to redeploy, then run
this script. The new image picks up the row on its next claim_one()
pass (every ~10s when idle) and runs the full pipeline.

Differs from test_worker_e2e.py: that pre-claims with a local
worker_id and runs the pipeline IN-PROCESS to avoid racing Railway.
This script does the opposite — inserts a normal pending row that
Railway is *supposed* to pick up. After it lands, watch progress with
``scripts/check_stale_reviews.py`` or a direct DB query.

Defaults to the ALEC-TEST-2026 seed (0x8E3b...) at max_depth=1 to keep
the run cheap (~$0.13 in Anthropic, ~30s wall on a small trace).

Run:
    python scripts/insert_validation_row.py
    python scripts/insert_validation_row.py --max-depth 2  # deeper trace
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import psycopg  # noqa: E402
from dotenv import load_dotenv  # noqa: E402


def _pooled_dsn(dsn: str) -> str:
    """If the DSN points at the direct (db.<ref>.supabase.co) host that
    sometimes can't be resolved on home networks, rewrite to the
    transaction pooler URL on port 6543."""
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--seed", default="0x8E3b200f356724299643402148a25FD4B852Bd53",
        help="Seed wallet address to trace.",
    )
    parser.add_argument(
        "--chain", default="ethereum",
        choices=["ethereum", "arbitrum", "base", "polygon", "bsc",
                 "solana", "hyperliquid"],
    )
    parser.add_argument("--max-depth", type=int, default=1)
    parser.add_argument(
        "--incident", default="2026-01-02T00:00:00Z",
        help="ISO 8601 incident time.",
    )
    parser.add_argument(
        "--label", default=None,
        help="Optional label inserted into the case description for traceability.",
    )
    args = parser.parse_args()

    load_dotenv(override=True)
    dsn = _pooled_dsn(os.environ["SUPABASE_DB_URL"])

    today = datetime.now(timezone.utc).date()
    case_id = uuid.uuid4()
    inv_id = uuid.uuid4()
    # case_number is varchar(8) — match the E2E test's "E-xxxxxx" pattern
    # rather than the longer "VAL-xxxxxx" form that overflows.
    case_number = f"V-{uuid.uuid4().hex[:6]}"
    label = args.label or "post-pdf-deliverables push validation"

    insert_case = """
        INSERT INTO public.cases (
            id, case_number, status, client_name, client_email, country,
            preferred_contact, loss_types, asset_location, wallet_addresses,
            incident_date, awareness_date, reported_to_law_enforcement,
            ic3_reminder_sent_at, description, created_at
        ) VALUES (
            %(id)s, %(num)s, 'intake', 'Validation Run', 'val@test.local',
            'USA', 'email', %(loss)s, %(assets)s, %(wallet)s,
            %(incident)s, %(awareness)s, false, %(ic3)s, %(desc)s, NOW()
        );
    """
    insert_inv = """
        INSERT INTO public.investigations (
            id, case_id, status, triggered_by, triggered_at,
            chain, seed_address, incident_time, max_depth, dust_threshold_usd
        ) VALUES (
            %(id)s, %(case)s, 'pending', 'validation-script', NOW(),
            %(chain)s, %(seed)s, %(incident)s, %(depth)s, %(dust)s
        );
    """

    with psycopg.connect(dsn, autocommit=True, prepare_threshold=None) as conn:
        with conn.cursor() as cur:
            cur.execute(insert_case, {
                "id": case_id,
                "num": case_number,
                "loss": ["other"],
                "assets": ["self_custody"],
                "wallet": args.seed,
                "incident": today - timedelta(days=10),
                "awareness": today - timedelta(days=8),
                "ic3": [],
                "desc": f"Recupero validation run ({label}). Seed wallet "
                        f"{args.seed} on {args.chain}; max_depth={args.max_depth}.",
            })
            cur.execute(insert_inv, {
                "id": inv_id,
                "case": case_id,
                "chain": args.chain,
                "seed": args.seed,
                "incident": datetime.fromisoformat(
                    args.incident.replace("Z", "+00:00")
                ),
                "depth": args.max_depth,
                "dust": Decimal("50.0"),
            })

    print(f"Inserted validation row:")
    print(f"  case_id          {case_id}")
    print(f"  investigation_id {inv_id}")
    print(f"  case_number      {case_number}")
    print(f"  seed             {args.seed} ({args.chain})")
    print(f"  max_depth        {args.max_depth}")
    print(f"  label            {label}")
    print()
    print("Railway should claim this row within ~10s if redeploy is complete.")
    print(f"Watch:")
    print(f"  SELECT status, worker_id, claimed_at, completed_at,")
    print(f"         api_costs_usd, error_stage, error_message")
    print(f"    FROM public.investigations WHERE id = '{inv_id}';")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
