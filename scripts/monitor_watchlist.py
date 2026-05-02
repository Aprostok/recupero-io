#!/usr/bin/env python3
"""Nightly balance monitor for the freezeable wallet watchlist.

Walks every ``status='active' AND is_freezeable=true`` row in
``public.watchlist``, fetches its current native balance + transaction
count from Etherscan v2, writes a snapshot to
``public.watchlist_snapshots``, and reports any movement vs the
previous snapshot.

Filter contract — only these rows are monitored:
  * ``status = 'active'``
  * ``is_freezeable = true``
  * either ``last_balance_usd > 0`` or ``last_snapshot_at IS NULL`` (first run)

Mixers, bridges, and dust wallets are skipped because they have
``is_freezeable=false`` (set by the worker pipeline) or because a prior
snapshot showed an empty balance. Skipping them keeps API usage bounded
and focuses on wallets we could actually recover from.

Output: JSON summary with the count, the rows that moved, and any
fetch errors. Exit code 1 if any movement was detected, so a scheduled
task / cron can alert.

Usage:
    python scripts/monitor_watchlist.py
    python scripts/monitor_watchlist.py --chain ethereum
    python scripts/monitor_watchlist.py --limit 10  # for smoke tests
    python scripts/monitor_watchlist.py --dry-run   # don't write snapshots

EVM chains only for v1. Solana / Hyperliquid wallets in the watchlist
are skipped with a warning until the chain dispatch is extended.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import httpx  # noqa: E402
import psycopg  # noqa: E402
from dotenv import load_dotenv  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402

log = logging.getLogger("monitor")


# ---- Chain → Etherscan v2 chain_id mapping ---- #
# Solana / Hyperliquid not yet supported; rows on those chains are
# skipped with a warning. The native_decimals constant is 18 for every
# EVM chain — explicit so future non-EVM additions don't silently
# inherit the wrong scale.
_CHAIN_PROFILES: dict[str, dict[str, Any]] = {
    "ethereum":  {"chain_id": 1,    "native_decimals": 18, "coingecko_id": "ethereum"},
    "arbitrum":  {"chain_id": 42161, "native_decimals": 18, "coingecko_id": "ethereum"},
    "base":      {"chain_id": 8453,  "native_decimals": 18, "coingecko_id": "ethereum"},
    "polygon":   {"chain_id": 137,   "native_decimals": 18, "coingecko_id": "matic-network"},
    "bsc":       {"chain_id": 56,    "native_decimals": 18, "coingecko_id": "binancecoin"},
}

_ETHERSCAN_BASE = "https://api.etherscan.io/v2/api"
_COINGECKO_BASE = "https://api.coingecko.com/api/v3"

# Etherscan free: 5 req/sec. We pace ourselves to ~3 to leave headroom.
_RATE_LIMIT_INTERVAL_SEC = 0.34


def _fetch_native_price_usd(coingecko_id: str, http: httpx.Client, api_key: str | None) -> Decimal | None:
    params = {"ids": coingecko_id, "vs_currencies": "usd"}
    headers = {"x-cg-demo-api-key": api_key} if api_key else {}
    try:
        resp = http.get(f"{_COINGECKO_BASE}/simple/price", params=params, headers=headers, timeout=10.0)
        resp.raise_for_status()
        return Decimal(str(resp.json()[coingecko_id]["usd"]))
    except Exception as e:  # noqa: BLE001
        log.warning("price fetch failed for %s: %s", coingecko_id, e)
        return None


def _etherscan_call(
    http: httpx.Client,
    api_key: str,
    chain_id: int,
    *,
    module: str,
    action: str,
    **params: str,
) -> dict[str, Any]:
    qp = {"module": module, "action": action, "apikey": api_key, "chainid": str(chain_id)}
    qp.update(params)
    resp = http.get(_ETHERSCAN_BASE, params=qp, timeout=20.0)
    resp.raise_for_status()
    return resp.json()


def _eth_balance_wei(http: httpx.Client, api_key: str, chain_id: int, address: str) -> int:
    payload = _etherscan_call(http, api_key, chain_id, module="account", action="balance",
                              address=address, tag="latest")
    return int(payload.get("result") or 0)


def _tx_count(http: httpx.Client, api_key: str, chain_id: int, address: str) -> int:
    """Total nonce / outbound tx count for the wallet. Cheap proxy for movement."""
    payload = _etherscan_call(http, api_key, chain_id, module="proxy",
                              action="eth_getTransactionCount",
                              address=address, tag="latest")
    raw = payload.get("result") or "0x0"
    try:
        return int(raw, 16)
    except (TypeError, ValueError):
        return 0


def _to_eth(wei: int, decimals: int = 18) -> Decimal:
    return Decimal(wei) / Decimal(10**decimals)


def _previous_snapshot(conn: psycopg.Connection, watchlist_id: str) -> dict[str, Any] | None:
    sql = """
        SELECT native_balance, tx_count, usd_value
          FROM public.watchlist_snapshots
         WHERE watchlist_id = %s
         ORDER BY taken_at DESC
         LIMIT 1
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, (watchlist_id,))
        return cur.fetchone()


def _write_snapshot(
    conn: psycopg.Connection,
    *,
    watchlist_id: str,
    native_balance: int | None,
    tx_count: int | None,
    usd_value: Decimal | None,
    delta_usd: Decimal | None,
    error: str | None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.watchlist_snapshots
                (watchlist_id, native_balance, tx_count, usd_value, delta_usd, source, error)
            VALUES (%s, %s, %s, %s, %s, 'etherscan_v2', %s)
            """,
            (watchlist_id, native_balance, tx_count, usd_value, delta_usd, error),
        )
        if error is None:
            cur.execute(
                """
                UPDATE public.watchlist
                   SET last_snapshot_at = NOW(),
                       last_native_balance = %s,
                       last_tx_count = %s,
                       last_balance_usd = %s
                 WHERE id = %s
                """,
                (native_balance, tx_count, usd_value, watchlist_id),
            )
    conn.commit()


def _select_targets(
    conn: psycopg.Connection,
    *,
    chain_filter: str | None,
    limit: int | None,
) -> list[dict[str, Any]]:
    sql = """
        SELECT w.id, w.address, w.chain, w.case_id, w.investigation_id,
               w.role, w.label_name, w.issuer, w.asset_symbol,
               w.last_balance_usd, w.last_snapshot_at,
               c.case_number, c.client_name
          FROM public.watchlist w
          LEFT JOIN public.cases c ON c.id = w.case_id
         WHERE w.status = 'active'
           AND w.is_freezeable = TRUE
           AND (w.last_snapshot_at IS NULL OR w.last_balance_usd > 0)
    """
    params: list[Any] = []
    if chain_filter:
        sql += " AND w.chain = %s"
        params.append(chain_filter)
    sql += " ORDER BY w.last_snapshot_at NULLS FIRST, w.flagged_at ASC"
    if limit:
        sql += " LIMIT %s"
        params.append(limit)

    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chain", help="Limit to one chain (ethereum, arbitrum, base, polygon, bsc).")
    parser.add_argument("--limit", type=int, help="Cap rows checked. For smoke tests.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Fetch balances + report movements but don't write snapshots.")
    parser.add_argument("--json-only", action="store_true",
                        help="Emit only the final JSON summary; suppress log lines.")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.WARNING if args.json_only else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # httpx INFO logs the full request URL including ?apikey=...; silence it.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    load_dotenv()

    dsn = os.getenv("SUPABASE_DB_URL")
    etherscan_key = os.getenv("ETHERSCAN_API_KEY")
    coingecko_key = os.getenv("COINGECKO_API_KEY")
    if not dsn:
        print("ERROR: SUPABASE_DB_URL is not set.", file=sys.stderr)
        return 2
    if not etherscan_key:
        print("ERROR: ETHERSCAN_API_KEY is not set.", file=sys.stderr)
        return 2

    movements: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    skipped_unsupported = 0
    snapshotted = 0

    with httpx.Client() as http:
        # One price-per-chain per run to bound CoinGecko traffic.
        prices: dict[str, Decimal | None] = {}

        with psycopg.connect(dsn, autocommit=False) as conn:
            targets = _select_targets(
                conn, chain_filter=args.chain, limit=args.limit,
            )
            log.info("monitoring %d wallet(s)", len(targets))

            for t in targets:
                chain = t["chain"]
                profile = _CHAIN_PROFILES.get(chain)
                if profile is None:
                    skipped_unsupported += 1
                    log.warning("skip %s on %s (unsupported chain)", t["address"], chain)
                    continue

                if chain not in prices:
                    prices[chain] = _fetch_native_price_usd(
                        profile["coingecko_id"], http, coingecko_key,
                    )
                price = prices[chain]

                try:
                    time.sleep(_RATE_LIMIT_INTERVAL_SEC)
                    bal_wei = _eth_balance_wei(http, etherscan_key, profile["chain_id"], t["address"])
                    time.sleep(_RATE_LIMIT_INTERVAL_SEC)
                    txc = _tx_count(http, etherscan_key, profile["chain_id"], t["address"])
                except Exception as e:  # noqa: BLE001
                    log.warning("fetch failed for %s on %s: %s", t["address"], chain, e)
                    errors.append({
                        "watchlist_id": str(t["id"]),
                        "address": t["address"],
                        "chain": chain,
                        "error": str(e)[:200],
                    })
                    if not args.dry_run:
                        _write_snapshot(
                            conn,
                            watchlist_id=t["id"],
                            native_balance=None, tx_count=None,
                            usd_value=None, delta_usd=None,
                            error=str(e)[:500],
                        )
                    continue

                bal_eth = _to_eth(bal_wei, profile["native_decimals"])
                usd_value: Decimal | None = (bal_eth * price).quantize(Decimal("0.01")) if price else None

                prev = _previous_snapshot(conn, t["id"])
                if prev:
                    prev_usd = prev.get("usd_value")
                    delta_usd = (usd_value - Decimal(prev_usd)) if (usd_value is not None and prev_usd is not None) else None
                    moved = (
                        (prev["tx_count"] is not None and txc != prev["tx_count"])
                        or (prev["native_balance"] is not None and bal_wei != int(prev["native_balance"]))
                    )
                else:
                    delta_usd = None
                    moved = False  # first snapshot — nothing to compare against

                if not args.dry_run:
                    _write_snapshot(
                        conn,
                        watchlist_id=t["id"],
                        native_balance=bal_wei,
                        tx_count=txc,
                        usd_value=usd_value,
                        delta_usd=delta_usd,
                        error=None,
                    )
                snapshotted += 1

                if moved:
                    movements.append({
                        "watchlist_id": str(t["id"]),
                        "address": t["address"],
                        "chain": chain,
                        "case_number": t["case_number"],
                        "client_name": t["client_name"],
                        "issuer": t["issuer"],
                        "asset_symbol": t["asset_symbol"],
                        "prev_tx_count": prev["tx_count"] if prev else None,
                        "tx_count": txc,
                        "tx_count_delta": txc - prev["tx_count"] if prev and prev["tx_count"] is not None else None,
                        "prev_native_balance_wei": str(prev["native_balance"]) if prev and prev["native_balance"] is not None else None,
                        "native_balance_wei": str(bal_wei),
                        "usd_value": str(usd_value) if usd_value is not None else None,
                        "delta_usd": str(delta_usd) if delta_usd is not None else None,
                    })

    summary = {
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "checked": len(targets),
        "snapshotted": snapshotted,
        "skipped_unsupported_chain": skipped_unsupported,
        "movement_count": len(movements),
        "movements": movements,
        "errors": errors,
        "dry_run": args.dry_run,
    }
    print(json.dumps(summary, indent=2, default=str))
    return 1 if movements else 0


if __name__ == "__main__":
    sys.exit(main())
