#!/usr/bin/env python3
"""Manual CRUD over public.watchlist.

For ad-hoc additions (an investigator spots a fishy address that
didn't go through the worker pipeline) and lifecycle changes (mark a
wallet ``frozen`` once an issuer has acted, ``recovered`` once the
funds are returned, or ``cleared`` to drop it from monitoring).

Sub-commands:

    add      Add a manual entry. Auto-flagged is_freezeable unless --no-freezeable.
    list     Print active rows (or all with --all).
    set      Update status / notes on one row by id or address.
    clear    Shortcut for ``set --status cleared``.

Examples:

    python scripts/recupero_watch.py add 0xabc... --chain ethereum \\
        --reason "tipoff from victim" --issuer Tether --asset USDT
    python scripts/recupero_watch.py list --chain ethereum
    python scripts/recupero_watch.py set --address 0xabc... --chain ethereum \\
        --status frozen --note "Tether confirmed freeze on 2026-05-08"
    python scripts/recupero_watch.py clear --address 0xabc... --chain ethereum \\
        --reason "exchange determined was their internal wallet"
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import psycopg  # noqa: E402
from dotenv import load_dotenv  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402

_VALID_STATUS = {"active", "frozen", "recovered", "cleared"}
_VALID_CHAIN = {"ethereum", "arbitrum", "base", "polygon", "bsc", "solana", "hyperliquid"}


def _connect() -> psycopg.Connection:
    load_dotenv()
    dsn = os.getenv("SUPABASE_DB_URL")
    if not dsn:
        raise SystemExit("ERROR: SUPABASE_DB_URL is not set.")
    return psycopg.connect(dsn, autocommit=True, row_factory=dict_row)


def cmd_add(args: argparse.Namespace) -> int:
    if args.chain not in _VALID_CHAIN:
        print(f"ERROR: chain must be one of {sorted(_VALID_CHAIN)}", file=sys.stderr)
        return 2

    is_freezeable = not args.no_freezeable
    sql = """
        INSERT INTO public.watchlist
            (address, chain, role, is_freezeable, issuer, asset_symbol,
             flagged_by, notes, case_id)
        VALUES
            (%s, %s, 'manual', %s, %s, %s, %s, %s, %s)
        ON CONFLICT (address, chain) WHERE investigation_id IS NULL
        DO UPDATE SET
            is_freezeable = EXCLUDED.is_freezeable,
            issuer = COALESCE(EXCLUDED.issuer, public.watchlist.issuer),
            asset_symbol = COALESCE(EXCLUDED.asset_symbol, public.watchlist.asset_symbol),
            notes = EXCLUDED.notes
        RETURNING id;
    """
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (
                args.address, args.chain, is_freezeable,
                args.issuer, args.asset, args.flagged_by, args.reason,
                args.case_id,
            ))
            row = cur.fetchone()
    print(f"added/updated watchlist row id={row['id']} ({args.address} on {args.chain})")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    sql = """
        SELECT w.id, w.address, w.chain, w.role, w.is_freezeable,
               w.issuer, w.asset_symbol, w.status,
               w.last_balance_usd, w.last_snapshot_at,
               c.case_number, c.client_name
          FROM public.watchlist w
          LEFT JOIN public.cases c ON c.id = w.case_id
         WHERE TRUE
    """
    params: list[Any] = []
    if not args.all:
        sql += " AND w.status = 'active'"
    if args.chain:
        sql += " AND w.chain = %s"
        params.append(args.chain)
    if args.freezeable_only:
        sql += " AND w.is_freezeable = TRUE"
    sql += " ORDER BY w.flagged_at DESC LIMIT %s"
    params.append(args.limit)

    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()

    if not rows:
        print("(no rows)")
        return 0

    print(f"{'address':<46} {'chain':<10} {'role':<18} {'freeze':<6} {'usd':>12} {'status':<10} case")
    print("-" * 120)
    for r in rows:
        case_label = f"{r['case_number'] or '-'} ({r['client_name'] or '-'})"
        usd = f"${r['last_balance_usd']}" if r["last_balance_usd"] is not None else "-"
        print(
            f"{r['address']:<46} {r['chain']:<10} {r['role']:<18} "
            f"{'yes' if r['is_freezeable'] else 'no':<6} {usd:>12} "
            f"{r['status']:<10} {case_label}"
        )
    return 0


def cmd_set(args: argparse.Namespace) -> int:
    if not (args.id or (args.address and args.chain)):
        print("ERROR: provide --id, or both --address and --chain.", file=sys.stderr)
        return 2

    sets: list[str] = []
    params: list[Any] = []
    if args.status:
        if args.status not in _VALID_STATUS:
            print(f"ERROR: --status must be one of {sorted(_VALID_STATUS)}", file=sys.stderr)
            return 2
        sets.append("status = %s")
        params.append(args.status)
        if args.status in ("cleared", "recovered"):
            sets.append("cleared_at = NOW()")
            sets.append("cleared_reason = %s")
            params.append(args.note or args.reason or args.status)
    if args.note:
        sets.append("notes = %s")
        params.append(args.note)
    if not sets:
        print("ERROR: nothing to update — pass --status or --note.", file=sys.stderr)
        return 2

    where = "id = %s" if args.id else "address = %s AND chain = %s"
    if args.id:
        params.append(args.id)
    else:
        params.extend([args.address, args.chain])

    sql = f"UPDATE public.watchlist SET {', '.join(sets)} WHERE {where} RETURNING id, status"
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
    if not row:
        print("(no matching row)", file=sys.stderr)
        return 1
    print(f"updated id={row['id']} status={row['status']}")
    return 0


def cmd_clear(args: argparse.Namespace) -> int:
    args.status = "cleared"
    args.note = args.reason
    return cmd_set(args)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="Add a manual watchlist entry.")
    a.add_argument("address")
    a.add_argument("--chain", required=True)
    a.add_argument("--reason", required=True, help="Stored as notes / explanation.")
    a.add_argument("--issuer", help="USDC issuer (Circle), USDT (Tether), etc.")
    a.add_argument("--asset", dest="asset", help="Asset symbol (e.g. USDC).")
    a.add_argument("--case-id", help="Optional case UUID.")
    a.add_argument("--no-freezeable", action="store_true",
                   help="Manual entries default to is_freezeable=true; pass to override.")
    a.add_argument("--flagged-by", default=os.getenv("USER") or "manual")
    a.set_defaults(func=cmd_add)

    l = sub.add_parser("list", help="Print watchlist rows.")
    l.add_argument("--chain")
    l.add_argument("--all", action="store_true", help="Include cleared/frozen rows.")
    l.add_argument("--freezeable-only", action="store_true")
    l.add_argument("--limit", type=int, default=50)
    l.set_defaults(func=cmd_list)

    s = sub.add_parser("set", help="Update a watchlist row's status or notes.")
    s.add_argument("--id")
    s.add_argument("--address")
    s.add_argument("--chain")
    s.add_argument("--status", help=f"One of {sorted(_VALID_STATUS)}.")
    s.add_argument("--note")
    s.add_argument("--reason")  # alias used by `clear`
    s.set_defaults(func=cmd_set)

    c = sub.add_parser("clear", help="Mark a row as cleared.")
    c.add_argument("--id")
    c.add_argument("--address")
    c.add_argument("--chain")
    c.add_argument("--reason", required=True)
    c.set_defaults(func=cmd_clear)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
