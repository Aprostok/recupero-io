"""Overnight watchlist snapshot + delta detection.

Walks ``public.watchlist`` for every wallet flagged ``status='active'``,
fetches its current native balance + tracked-token balances + total
transaction count from the appropriate chain explorer, prices the
holdings against the persistent CoinGecko cache, and writes a row into
``public.watchlist_snapshots``. Compares against the most recent prior
snapshot to compute ``delta_usd``; if the delta crosses a configurable
threshold or the wallet observed new outbound transfers, the row is
flagged as a "material change" in the returned report — which the
nightly digest deliverable (see :mod:`recupero.worker.mini_freeze`)
turns into a short letter for the operator/compliance team.

Designed to run as a Railway cron entry. Single-pass, idempotent
within a configurable cooldown window (default 12h) so a manual rerun
within the same day doesn't double-snapshot.

Cost shape per tick (rough):

  * Etherscan v2 free tier (5 rps): ~3 API calls per wallet —
    eth_getBalance, tokenbalance for the most-relevant ERC-20, and
    eth_getTransactionCount. With 100 active wallets and 4 rps
    sustained, ~75 sec wallclock per tick.
  * CoinGecko: cache-only — the pricing layer's persistent cache
    means re-pricing yesterday's set is free (no network calls).
  * Anthropic: zero — no LLM use in this stage.

Multi-chain: ethereum / arbitrum / base / polygon / bsc all route
through the Etherscan v2 multichain endpoint; we pick the
``chain_id`` from the watchlist row's ``chain`` column. Solana and
Hyperliquid are deferred (would need a chain-specific snapshot path).
"""

from __future__ import annotations

import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Chain, TokenRef

log = logging.getLogger(__name__)


# ----- Constants ----- #


# Etherscan v2 chain-id mapping for all EVM chains the worker supports.
# Solana / Hyperliquid go through different APIs (deferred for watch_tick).
_CHAIN_ID_BY_NAME: dict[str, int] = {
    "ethereum": 1,
    "arbitrum": 42161,
    "base":     8453,
    "polygon":  137,
    "bsc":      56,
}


# Defaults for the materiality bar. Both are env-overridable.
#   * 100 USD threshold for balance delta — small enough to catch
#     meaningful drains, big enough to ignore gas-dust drift.
#   * Any new outbound tx is interesting regardless of USD value;
#     even a 0-USD test transfer can indicate a perpetrator probing.
_DEFAULT_DELTA_USD_THRESHOLD = Decimal("100")


# How often a single wallet is re-snapshotted. Default 12h — running
# the tick twice in one day shouldn't burn API budget on the same
# rows. Operators can override via env if they want hourly polling
# on a high-priority case.
_DEFAULT_MIN_INTERVAL_SEC = 12 * 3600


# How many wallets to snapshot concurrently. Etherscan's free tier
# caps at 5 rps regardless of concurrency, so this is mostly about
# overlapping the network-latency stalls. 4 workers is a safe upper
# bound that doesn't risk burst-rejection on a misconfigured wallet.
_DEFAULT_PARALLELISM = 4


# ----- Data shapes ----- #


@dataclass
class MaterialChange:
    """One wallet's snapshot crossed a materiality threshold.

    The digest deliverable formats one paragraph per MaterialChange
    instance — kept narrow so the prose generator stays simple.
    """
    watchlist_id: UUID
    address: str
    chain: str
    role: str
    label_name: str | None
    is_freezeable: bool
    issuer: str | None
    asset_symbol: str | None

    prior_taken_at: datetime | None
    prior_usd: Decimal | None
    prior_tx_count: int | None

    new_taken_at: datetime
    new_usd: Decimal | None
    new_tx_count: int | None

    delta_usd: Decimal | None
    tx_count_delta: int | None

    # Free-form reason explaining what threshold tripped. Kept short
    # so the digest can render this verbatim in a bullet list.
    reason: str


@dataclass
class WatchTickReport:
    """Result of a single tick — what got snapshotted, what changed,
    what failed."""
    started_at: datetime
    finished_at: datetime
    candidates: int
    snapshotted: int
    skipped_cooldown: int
    skipped_unsupported_chain: int
    errors: list[str] = field(default_factory=list)
    material_changes: list[MaterialChange] = field(default_factory=list)


@dataclass
class _Snapshot:
    """Internal — what we computed for one wallet."""
    native_balance_raw: int | None
    tx_count: int | None
    total_usd: Decimal | None
    token_balances: list[dict[str, Any]] = field(default_factory=list)
    source: str = "etherscan_v2"
    error: str | None = None


# ----- Public entry ----- #


def run_watch_tick(
    *,
    dsn: str,
    config: RecuperoConfig,
    env: RecuperoEnv,
    min_interval_sec: int = _DEFAULT_MIN_INTERVAL_SEC,
    delta_usd_threshold: Decimal = _DEFAULT_DELTA_USD_THRESHOLD,
    parallelism: int = _DEFAULT_PARALLELISM,
    limit: int | None = None,
) -> WatchTickReport:
    """Snapshot every eligible active watchlist row.

    Eligible rows are ``status='active'`` AND
    (``last_snapshot_at IS NULL`` OR
     ``last_snapshot_at < NOW() - min_interval_sec``).

    Per-row processing is parallelized with a ``ThreadPoolExecutor``
    sized to ``parallelism``. Each task is a single
    ``_snapshot_one(...)`` call — fully self-contained, no shared
    mutable state — so the only coordination is the rate-limited
    Etherscan client they share.

    Returns a :class:`WatchTickReport` summarizing what happened. The
    caller (the cron entry, the deliverables generator, or the admin
    UI) decides what to do with the material changes.
    """
    started_at = datetime.now(timezone.utc)
    report = WatchTickReport(
        started_at=started_at,
        finished_at=started_at,  # filled in at end
        candidates=0,
        snapshotted=0,
        skipped_cooldown=0,
        skipped_unsupported_chain=0,
    )

    rows = _fetch_eligible(dsn, min_interval_sec=min_interval_sec, limit=limit)
    report.candidates = len(rows)
    if not rows:
        log.info("watch-tick: no eligible watchlist rows")
        report.finished_at = datetime.now(timezone.utc)
        return report

    # Group by chain so we instantiate one Etherscan client per chain
    # (shared rate limiter across all of that chain's wallets).
    by_chain: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        chain = r["chain"]
        if chain not in _CHAIN_ID_BY_NAME:
            report.skipped_unsupported_chain += 1
            continue
        by_chain.setdefault(chain, []).append(r)

    api_key = os.environ.get("ETHERSCAN_API_KEY", "").strip()
    if not api_key:
        report.errors.append("ETHERSCAN_API_KEY not set; cannot snapshot")
        report.finished_at = datetime.now(timezone.utc)
        return report

    # Per-chain client + pricing client are constructed lazily.
    from recupero.chains.ethereum.etherscan import EtherscanClient
    from recupero.pricing.coingecko import CoinGeckoClient

    cg = CoinGeckoClient(
        config=config,
        env=env,
        dsn=dsn,  # use the persistent pricing cache (Postgres-backed)
    )

    try:
        for chain, chain_rows in by_chain.items():
            client = EtherscanClient(
                api_key=api_key, chain_id=_CHAIN_ID_BY_NAME[chain],
            )
            try:
                _snapshot_chain(
                    dsn=dsn,
                    client=client,
                    price_client=cg,
                    rows=chain_rows,
                    parallelism=parallelism,
                    delta_usd_threshold=delta_usd_threshold,
                    report=report,
                )
            finally:
                client.close()
    finally:
        # CoinGeckoClient: nothing to close (httpx client is internal)
        pass

    report.finished_at = datetime.now(timezone.utc)
    log.info(
        "watch-tick done: candidates=%d snapshotted=%d cooldown=%d "
        "unsupported_chain=%d material_changes=%d errors=%d",
        report.candidates, report.snapshotted, report.skipped_cooldown,
        report.skipped_unsupported_chain, len(report.material_changes),
        len(report.errors),
    )
    return report


# ----- Internals ----- #


def _fetch_eligible(
    dsn: str, *, min_interval_sec: int, limit: int | None,
) -> list[dict[str, Any]]:
    """Pull active watchlist rows due for a fresh snapshot."""
    sql = """
        SELECT id, address, chain, role, label_category, label_name,
               is_freezeable, issuer, asset_symbol, asset_contract,
               last_snapshot_at
          FROM public.watchlist
         WHERE status = 'active'
           AND (last_snapshot_at IS NULL
                OR last_snapshot_at < NOW() - make_interval(secs => %s))
         ORDER BY last_balance_usd DESC NULLS LAST, flagged_at ASC
    """
    if limit:
        sql += " LIMIT %s"
    pooled_dsn = _pooled_dsn(dsn)
    with psycopg.connect(pooled_dsn, autocommit=True, row_factory=dict_row,
                         prepare_threshold=None, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            if limit:
                cur.execute(sql, (min_interval_sec, limit))
            else:
                cur.execute(sql, (min_interval_sec,))
            return list(cur.fetchall())


def _snapshot_chain(
    *,
    dsn: str,
    client: Any,
    price_client: Any,
    rows: list[dict[str, Any]],
    parallelism: int,
    delta_usd_threshold: Decimal,
    report: WatchTickReport,
) -> None:
    """Snapshot every wallet on a single chain, in parallel."""
    with ThreadPoolExecutor(max_workers=parallelism) as pool:
        futures = {
            pool.submit(_snapshot_one, row, client, price_client): row
            for row in rows
        }
        for fut in as_completed(futures):
            row = futures[fut]
            try:
                snap = fut.result()
            except Exception as exc:  # noqa: BLE001
                msg = f"snapshot failed for {row['address']} on {row['chain']}: {exc}"
                log.warning(msg)
                report.errors.append(msg)
                continue

            # Persist + diff. Persisting before diffing means a crash
            # mid-loop doesn't lose the work we already did.
            try:
                change = _persist_and_diff(
                    dsn=dsn, row=row, snap=snap,
                    delta_usd_threshold=delta_usd_threshold,
                )
                report.snapshotted += 1
                if change is not None:
                    report.material_changes.append(change)
            except Exception as exc:  # noqa: BLE001
                msg = f"persist failed for {row['address']} on {row['chain']}: {exc}"
                log.warning(msg)
                report.errors.append(msg)


def _snapshot_one(
    row: dict[str, Any], client: Any, price_client: Any,
) -> _Snapshot:
    """Fetch native balance, optional token balance, and tx count for
    one wallet. Returns a populated :class:`_Snapshot`."""
    addr = row["address"]
    chain_name = row["chain"]

    snap = _Snapshot(native_balance_raw=None, tx_count=None, total_usd=None)

    # Native balance.
    try:
        eth_raw = client.get_eth_balance(addr)
        snap.native_balance_raw = int(eth_raw)
    except Exception as exc:  # noqa: BLE001
        snap.error = f"native balance: {exc}"
        return snap

    # Tx count (lifetime). Etherscan v2 exposes this via the proxy
    # module — same JSON-RPC shape as `eth_getTransactionCount`.
    try:
        data = client._call(  # noqa: SLF001
            module="proxy", action="eth_getTransactionCount",
            address=addr, tag="latest",
        )
        # Result is hex string like "0x1f7"
        snap.tx_count = int(data.get("result", "0x0"), 16)
    except Exception as exc:  # noqa: BLE001
        log.debug("tx_count fetch failed for %s: %s", addr, exc)
        # Non-fatal — keep going with balance-only snapshot.
        snap.tx_count = None

    # Token balance — only fetch if the watchlist row carries the
    # asset_contract (i.e. this wallet was flagged because of a
    # specific freezable token). Don't sweep all known tokens on
    # every tick; that'd be 100s of API calls per wallet.
    contract = row.get("asset_contract")
    symbol = row.get("asset_symbol") or "TOKEN"
    if contract:
        try:
            token_raw = client.get_token_balance(contract, addr)
            if token_raw and int(token_raw) > 0:
                decimals = 6 if symbol.upper() in {"USDC", "USDT"} else 18
                decimal_amount = Decimal(int(token_raw)) / Decimal(10 ** decimals)
                token_ref = TokenRef(
                    chain=Chain(chain_name), contract=contract,
                    symbol=symbol, decimals=decimals,
                )
                price = price_client.price_now(token_ref)
                token_usd = (price.usd_value * decimal_amount
                             if price.usd_value is not None else None)
                snap.token_balances.append({
                    "symbol": symbol,
                    "contract": contract,
                    "raw_amount": str(token_raw),
                    "decimal_amount": str(decimal_amount),
                    "usd_value": str(token_usd) if token_usd is not None else None,
                })
        except Exception as exc:  # noqa: BLE001
            log.debug("token balance fetch failed for %s: %s", addr, exc)

    # Native value in USD.
    native_usd = Decimal(0)
    if snap.native_balance_raw and snap.native_balance_raw > 0:
        eth_decimal = Decimal(snap.native_balance_raw) / Decimal(10 ** 18)
        # Use the chain's native gas token. Ethereum/Arbitrum/Base/Optimism
        # use ETH; Polygon=MATIC; BSC=BNB. For chains we don't have a
        # CoinGecko ID mapping for, native_usd stays 0 and we annotate.
        native_token = _native_token_for(chain_name)
        if native_token is not None:
            try:
                price = price_client.price_now(native_token)
                if price.usd_value is not None:
                    native_usd = price.usd_value * eth_decimal
            except Exception as exc:  # noqa: BLE001
                log.debug("native price fetch failed for %s: %s", addr, exc)

    # Total = native + sum of token balances.
    total = native_usd
    for tb in snap.token_balances:
        if tb.get("usd_value"):
            try:
                total += Decimal(tb["usd_value"])
            except (ValueError, TypeError):
                pass
    snap.total_usd = total
    return snap


def _native_token_for(chain_name: str) -> TokenRef | None:
    """Return the chain's native gas token (for USD pricing). None
    when the chain is unmapped — caller treats native_usd as 0."""
    mapping = {
        "ethereum": ("ETH",  "ethereum"),
        "arbitrum": ("ETH",  "ethereum"),
        "base":     ("ETH",  "ethereum"),
        "polygon":  ("MATIC", "matic-network"),
        "bsc":      ("BNB",  "binancecoin"),
    }
    entry = mapping.get(chain_name)
    if not entry:
        return None
    symbol, coingecko_id = entry
    try:
        chain = Chain(chain_name)
    except ValueError:
        return None
    return TokenRef(
        chain=chain, contract=None, symbol=symbol, decimals=18,
        coingecko_id=coingecko_id,
    )


def _persist_and_diff(
    *,
    dsn: str,
    row: dict[str, Any],
    snap: _Snapshot,
    delta_usd_threshold: Decimal,
) -> MaterialChange | None:
    """Insert the new snapshot row, update watchlist denorm fields,
    and decide whether the change is material.

    A change is material when EITHER:
      * |delta_usd| >= ``delta_usd_threshold``, OR
      * tx_count strictly increased (any new outbound observed).

    First-ever snapshot (no prior row) is never material — there's
    nothing to compare against. We'd flag every wallet on the first
    tick otherwise and drown the operator in noise.
    """
    pooled_dsn = _pooled_dsn(dsn)
    with psycopg.connect(pooled_dsn, autocommit=True, row_factory=dict_row,
                         prepare_threshold=None, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            # Pull the most recent prior snapshot — single ORDER BY +
            # LIMIT 1 is index-served by watchlist_snapshots_recent_idx.
            cur.execute(
                """SELECT taken_at, native_balance, tx_count, usd_value
                     FROM public.watchlist_snapshots
                    WHERE watchlist_id = %s
                    ORDER BY taken_at DESC LIMIT 1;""",
                (row["id"],),
            )
            prior = cur.fetchone()

            new_taken_at = datetime.now(timezone.utc)
            delta_usd: Decimal | None = None
            if prior is not None and prior.get("usd_value") is not None and snap.total_usd is not None:
                delta_usd = Decimal(snap.total_usd) - Decimal(prior["usd_value"])
            tx_count_delta: int | None = None
            if (prior is not None and prior.get("tx_count") is not None
                    and snap.tx_count is not None):
                tx_count_delta = int(snap.tx_count) - int(prior["tx_count"])

            # Build the token_balances JSONB payload.
            import json
            token_balances_json = json.dumps(snap.token_balances) if snap.token_balances else None

            cur.execute(
                """INSERT INTO public.watchlist_snapshots (
                       watchlist_id, taken_at, native_balance, tx_count,
                       usd_value, delta_usd, token_balances, source, error
                   ) VALUES (
                       %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s
                   );""",
                (
                    row["id"], new_taken_at,
                    snap.native_balance_raw, snap.tx_count,
                    str(snap.total_usd) if snap.total_usd is not None else None,
                    str(delta_usd) if delta_usd is not None else None,
                    token_balances_json, snap.source, snap.error,
                ),
            )

            cur.execute(
                """UPDATE public.watchlist
                      SET last_snapshot_at = %s,
                          last_balance_usd = %s,
                          last_native_balance = %s,
                          last_tx_count = %s
                    WHERE id = %s;""",
                (
                    new_taken_at,
                    str(snap.total_usd) if snap.total_usd is not None else None,
                    snap.native_balance_raw,
                    snap.tx_count,
                    row["id"],
                ),
            )

    # Decide materiality.
    if prior is None:
        return None  # first snapshot — never material
    material_reasons: list[str] = []
    if (delta_usd is not None
            and abs(delta_usd) >= delta_usd_threshold):
        sign = "+" if delta_usd >= 0 else "-"
        material_reasons.append(
            f"balance {sign}${abs(delta_usd):,.2f} USD"
        )
    if tx_count_delta is not None and tx_count_delta > 0:
        material_reasons.append(
            f"{tx_count_delta} new outbound tx(s)"
        )
    if not material_reasons:
        return None

    return MaterialChange(
        watchlist_id=row["id"],
        address=row["address"],
        chain=row["chain"],
        role=row["role"],
        label_name=row.get("label_name"),
        is_freezeable=bool(row.get("is_freezeable")),
        issuer=row.get("issuer"),
        asset_symbol=row.get("asset_symbol"),
        prior_taken_at=prior["taken_at"] if prior else None,
        prior_usd=Decimal(prior["usd_value"]) if prior and prior.get("usd_value") is not None else None,
        prior_tx_count=int(prior["tx_count"]) if prior and prior.get("tx_count") is not None else None,
        new_taken_at=new_taken_at,
        new_usd=snap.total_usd,
        new_tx_count=snap.tx_count,
        delta_usd=delta_usd,
        tx_count_delta=tx_count_delta,
        reason=" · ".join(material_reasons),
    )


def _pooled_dsn(dsn: str) -> str:
    """Rewrite a direct-host Supabase DSN to the transaction pooler
    (port 6543) — same workaround used elsewhere for IPv6-only direct
    hosts that some home networks can't resolve."""
    if "db." in dsn and ".supabase.co" in dsn:
        m = re.search(
            r"postgres(?:ql)?://([^:]+):([^@]+)@db\.([^.]+)\.supabase\.co",
            dsn,
        )
        if m:
            user, pwd, ref = m.group(1), m.group(2), m.group(3)
            return (
                f"postgresql://{user}.{ref}:{pwd}"
                f"@aws-1-us-east-1.pooler.supabase.com:6543/postgres"
            )
    return dsn


__all__ = (
    "MaterialChange",
    "WatchTickReport",
    "run_watch_tick",
)
