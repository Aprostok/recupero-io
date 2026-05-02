#!/usr/bin/env python3
"""Export the active watchlist for law-enforcement handoff.

Generates a clean CSV (or JSON) of every wallet currently flagged
``status='active'`` with the case context, last-seen balance, and the
explorer URL. This is what gets attached to LE submissions when they
ask "give me everything you've got on these guys".

Usage:
    python scripts/export_watchlist.py                        # CSV to stdout
    python scripts/export_watchlist.py --format json
    python scripts/export_watchlist.py --out le_handoff.csv
    python scripts/export_watchlist.py --case-id <uuid>       # single case
    python scripts/export_watchlist.py --include-cleared      # full audit list
    python scripts/export_watchlist.py --freezeable-only      # what they can act on
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import psycopg  # noqa: E402
from dotenv import load_dotenv  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402


_EXPLORERS: dict[str, str] = {
    "ethereum": "https://etherscan.io/address/",
    "arbitrum": "https://arbiscan.io/address/",
    "base": "https://basescan.org/address/",
    "polygon": "https://polygonscan.com/address/",
    "bsc": "https://bscscan.com/address/",
    "solana": "https://solscan.io/account/",
    "hyperliquid": "https://app.hyperliquid.xyz/explorer/address/",
}


_FIELDNAMES = [
    "address", "chain", "explorer_url",
    "case_number", "client_name",
    "role", "label_category", "label_name",
    "is_freezeable", "issuer", "asset_symbol",
    "last_balance_usd", "last_snapshot_at",
    "status", "flagged_at", "notes",
]


def _row_to_record(row: dict[str, Any]) -> dict[str, Any]:
    chain = row.get("chain") or ""
    addr = row.get("address") or ""
    explorer = (_EXPLORERS.get(chain) or "") + addr if addr else ""
    out = {
        "address": addr,
        "chain": chain,
        "explorer_url": explorer,
        "case_number": row.get("case_number") or "",
        "client_name": row.get("client_name") or "",
        "role": row.get("role") or "",
        "label_category": row.get("label_category") or "",
        "label_name": row.get("label_name") or "",
        "is_freezeable": "yes" if row.get("is_freezeable") else "no",
        "issuer": row.get("issuer") or "",
        "asset_symbol": row.get("asset_symbol") or "",
        "last_balance_usd": str(row["last_balance_usd"]) if row.get("last_balance_usd") is not None else "",
        "last_snapshot_at": row["last_snapshot_at"].isoformat() if row.get("last_snapshot_at") else "",
        "status": row.get("status") or "",
        "flagged_at": row["flagged_at"].isoformat() if row.get("flagged_at") else "",
        "notes": row.get("notes") or "",
    }
    return out


def _json_default(obj):
    if isinstance(obj, (datetime,)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return str(obj)
    if isinstance(obj, UUID):
        return str(obj)
    raise TypeError(f"not JSON-serializable: {type(obj).__name__}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("csv", "json"), default="csv")
    parser.add_argument("--out", type=Path, help="Output file (default: stdout).")
    parser.add_argument("--case-id", help="Filter to one case UUID.")
    parser.add_argument("--include-cleared", action="store_true",
                        help="Include rows with status != active. Off by default.")
    parser.add_argument("--freezeable-only", action="store_true",
                        help="Limit to is_freezeable=true rows.")
    args = parser.parse_args()

    load_dotenv()
    dsn = os.getenv("SUPABASE_DB_URL")
    if not dsn:
        print("ERROR: SUPABASE_DB_URL is not set.", file=sys.stderr)
        return 2

    sql = """
        SELECT w.*, c.case_number, c.client_name
          FROM public.watchlist w
          LEFT JOIN public.cases c ON c.id = w.case_id
         WHERE TRUE
    """
    params: list[Any] = []
    if not args.include_cleared:
        sql += " AND w.status = 'active'"
    if args.freezeable_only:
        sql += " AND w.is_freezeable = TRUE"
    if args.case_id:
        sql += " AND w.case_id = %s"
        params.append(args.case_id)
    sql += " ORDER BY w.flagged_at DESC"

    try:
        with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
    except psycopg.Error as exc:
        print(f"ERROR: query failed: {exc}", file=sys.stderr)
        return 2

    records = [_row_to_record(r) for r in rows]

    if args.format == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
        payload = buf.getvalue()
    else:
        payload = json.dumps(
            {"exported_at": datetime.utcnow().isoformat() + "Z",
             "row_count": len(records),
             "rows": records},
            indent=2, default=_json_default,
        )

    if args.out:
        args.out.write_text(payload, encoding="utf-8")
        print(f"wrote {len(records)} row(s) → {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
