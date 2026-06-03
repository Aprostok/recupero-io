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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Chain, TokenRef

log = logging.getLogger(__name__)


# ----- Constants ----- #


# Etherscan v2 chain-id mapping for the EVM chains we monitor.
# v0.20.0 (round-13 chain-coverage research): added 7 EVM chains.
# Each is a free chainid wire-up — Etherscan API V2's multichain
# endpoint routes the request to the right per-chain explorer using
# this id. Sources: optimistic.etherscan.io / snowtrace.io / etc.
# all support the V2 API with the same key.
_CHAIN_ID_BY_NAME: dict[str, int] = {
    "ethereum":  1,
    "arbitrum":  42161,
    "base":      8453,
    "polygon":   137,
    "bsc":       56,
    "optimism":  10,
    "avalanche": 43114,
    "linea":     59144,
    "blast":     81457,
    "zksync":    324,
    "scroll":    534352,
    "mantle":    5000,
    # v0.31.0 — destination-only chains promoted to full adapter coverage.
    # Pre-v0.31.0 these existed in `models.py::Chain` (so seed labels
    # could carry chain=<fantom/celo/...>) but the BFS stopped at the
    # bridge handoff because no Etherscan-V2 chainID was wired. Now the
    # EVM adapter routes through Etherscan V2 for all 6 — proven by the
    # V2 multichain coverage docs that list each.
    # Sources: etherscan.io/v2/chainlist, chainlist.org.
    "fantom":    250,
    "celo":      42220,
    "gnosis":    100,
    "moonbeam":  1284,
    "metis":     1088,
    "kava":      2222,
    # v0.35.3 — opBNB, verified present on the live Etherscan V2 chainlist.
    "opbnb":     204,
}

# Chains that need a non-EVM snapshot path. The watch_tick loop
# dispatches on the row's ``chain`` column: EVM names route through
# ``_snapshot_evm_one`` (Etherscan v2); ``solana`` routes through
# ``_snapshot_solana_one`` (Helius RPC); ``hyperliquid`` is a TODO
# (the existing scraper doesn't expose a wallet-balance endpoint —
# adding one means new API plumbing on the spotClearinghouseState /
# clearinghouseState info endpoints).
_SOLANA_CHAIN = "solana"
_HYPERLIQUID_CHAIN = "hyperliquid"
_BITCOIN_CHAIN = "bitcoin"


# Defaults for the materiality bar. All three are env-overridable —
# the cron operator can tune these without a code push (useful for a
# high-priority case where 12h cadence + $100 threshold is too lax).
#
#   * 100 USD threshold for balance delta — small enough to catch
#     meaningful drains, big enough to ignore gas-dust drift.
#   * Any new outbound tx is interesting regardless of USD value;
#     even a 0-USD test transfer can indicate a perpetrator probing.
_DEFAULT_DELTA_USD_THRESHOLD = Decimal("100")


# How often a single wallet is re-snapshotted. Default 12h — running
# the tick twice in one day shouldn't burn API budget on the same
# rows.
_DEFAULT_MIN_INTERVAL_SEC = 12 * 3600


# How many wallets to snapshot concurrently. Etherscan's free tier
# caps at 5 rps regardless of concurrency, so this is mostly about
# overlapping the network-latency stalls. 4 workers is a safe upper
# bound that doesn't risk burst-rejection on a misconfigured wallet.
_DEFAULT_PARALLELISM = 4


# Env var names — kept in one place so the runbook can reference
# them directly. ``RECUPERO_WATCH_*`` namespace mirrors the existing
# ``RECUPERO_*`` worker env vars (heartbeat interval, poll cadence,
# etc.).
_ENV_DELTA_USD_THRESHOLD = "RECUPERO_WATCH_DELTA_USD_THRESHOLD"
_ENV_MIN_INTERVAL_SEC    = "RECUPERO_WATCH_MIN_INTERVAL_SEC"
_ENV_PARALLELISM         = "RECUPERO_WATCH_PARALLELISM"
# Priority-tier cooldowns. Hot rows poll every hour by default,
# standard rows fall through to MIN_INTERVAL_SEC (default 12h).
_ENV_HOT_INTERVAL_SEC    = "RECUPERO_WATCH_HOT_INTERVAL_SEC"
_DEFAULT_HOT_INTERVAL_SEC = 3600   # 1 hour


def _env_decimal(name: str, default: Decimal) -> Decimal:
    """Read an env var as Decimal, falling back to default on missing
    or unparseable values. Logs a warning when a bad value is ignored
    so the operator sees the typo instead of silently inheriting the
    default."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return Decimal(raw)
    except Exception:  # noqa: BLE001
        log.warning("ignoring bad %s=%r (using default %s)", name, raw, default)
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except Exception:  # noqa: BLE001
        log.warning("ignoring bad %s=%r (using default %d)", name, raw, default)
        return default


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
    # v0.35.13 (D6): prioritized recovery alerts derived from the material
    # changes (freezable/tracked funds moving, dormant reactivation). Populated
    # at the end of run_watch_tick; consumed by the digest / notification path.
    alerts: list[Any] = field(default_factory=list)


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
    min_interval_sec: int | None = None,
    delta_usd_threshold: Decimal | None = None,
    parallelism: int | None = None,
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

    Tuning knobs (each is "explicit kwarg wins, else env var, else
    module default"):

      * ``min_interval_sec``  — env ``RECUPERO_WATCH_MIN_INTERVAL_SEC``
      * ``delta_usd_threshold`` — env ``RECUPERO_WATCH_DELTA_USD_THRESHOLD``
      * ``parallelism``      — env ``RECUPERO_WATCH_PARALLELISM``
    """
    # Resolve every tuning knob in one place: explicit kwarg wins,
    # else env var (RECUPERO_WATCH_*), else the module default. Logged
    # at INFO so the cron operator can verify in Railway logs that the
    # env overrides actually took effect.
    if min_interval_sec is None:
        min_interval_sec = _env_int(_ENV_MIN_INTERVAL_SEC, _DEFAULT_MIN_INTERVAL_SEC)
    if delta_usd_threshold is None:
        delta_usd_threshold = _env_decimal(
            _ENV_DELTA_USD_THRESHOLD, _DEFAULT_DELTA_USD_THRESHOLD,
        )
    if parallelism is None:
        parallelism = _env_int(_ENV_PARALLELISM, _DEFAULT_PARALLELISM)
    log.info(
        "watch-tick tuning: min_interval_sec=%d delta_usd_threshold=%s "
        "parallelism=%d limit=%s",
        min_interval_sec, delta_usd_threshold, parallelism,
        limit if limit else "none",
    )

    started_at = datetime.now(UTC)
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
        report.finished_at = datetime.now(UTC)
        return report

    # Group by chain so we instantiate one chain client per chain
    # (shared rate limiter across all of that chain's wallets). Rows
    # for chains we don't yet support are counted as skipped — they
    # remain on the watchlist for the next supported-chain tick.
    by_chain: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        chain = r["chain"]
        if (chain not in _CHAIN_ID_BY_NAME
                and chain != _SOLANA_CHAIN
                and chain != _HYPERLIQUID_CHAIN
                and chain != _BITCOIN_CHAIN):
            report.skipped_unsupported_chain += 1
            continue
        by_chain.setdefault(chain, []).append(r)

    # Pricing client is shared across chains (CoinGecko is chain-
    # agnostic — pricing is keyed by (chain, contract) for token
    # entries and by coingecko_id for native gas tokens).
    from recupero.pricing.coingecko import CoinGeckoClient
    cg = CoinGeckoClient(
        config=config,
        env=env,
        dsn=dsn,  # use the persistent pricing cache (Postgres-backed)
    )

    for chain, chain_rows in by_chain.items():
        if chain in _CHAIN_ID_BY_NAME:
            _run_evm_chain(
                chain=chain, rows=chain_rows, dsn=dsn,
                price_client=cg, parallelism=parallelism,
                delta_usd_threshold=delta_usd_threshold, report=report,
            )
        elif chain == _SOLANA_CHAIN:
            _run_solana_chain(
                rows=chain_rows, dsn=dsn,
                price_client=cg, parallelism=parallelism,
                delta_usd_threshold=delta_usd_threshold, report=report,
            )
        elif chain == _HYPERLIQUID_CHAIN:
            _run_hyperliquid_chain(
                rows=chain_rows, dsn=dsn,
                price_client=cg, parallelism=parallelism,
                delta_usd_threshold=delta_usd_threshold, report=report,
            )
        elif chain == _BITCOIN_CHAIN:
            _run_bitcoin_chain(
                rows=chain_rows, dsn=dsn,
                price_client=cg, parallelism=parallelism,
                delta_usd_threshold=delta_usd_threshold, report=report,
            )

    # v0.35.13 (D6): derive prioritized recovery alerts from the material
    # changes computed above. Pure + additive — never raises into the tick.
    try:
        from recupero.monitoring.recovery_alerts import evaluate_recovery_alerts
        report.alerts = evaluate_recovery_alerts(report.material_changes)
    except Exception as _exc:  # noqa: BLE001 — alerting must never break the tick
        log.warning("watch-tick: recovery-alert evaluation failed (%s)", _exc)

    # v0.35.30 (D6 persistence): store the alerts so the operator console
    # (/v1/recovery-alerts) can surface the freeze-NOW queue between ticks.
    # Additive + guarded — a missing table (migration 033 not yet applied) or
    # any DB error is logged, NEVER raised into the tick.
    try:
        if report.alerts:
            from recupero.monitoring.recovery_alerts_store import persist_alerts
            n = persist_alerts(dsn, report.alerts, tick_started_at=started_at)
            log.info("watch-tick: persisted %d new recovery alert(s)", n)
    except Exception as _exc:  # noqa: BLE001 — persistence must never break the tick
        log.warning("watch-tick: recovery-alert persist failed (%s)", _exc)

    report.finished_at = datetime.now(UTC)
    log.info(
        "watch-tick done: candidates=%d snapshotted=%d cooldown=%d "
        "unsupported_chain=%d material_changes=%d alerts=%d errors=%d",
        report.candidates, report.snapshotted, report.skipped_cooldown,
        report.skipped_unsupported_chain, len(report.material_changes),
        len(report.alerts), len(report.errors),
    )
    return report


# ----- Internals ----- #


def _fetch_eligible(
    dsn: str, *, min_interval_sec: int, limit: int | None,
    hot_interval_sec: int | None = None,
) -> list[dict[str, Any]]:
    """Pull active watchlist rows due for a fresh snapshot.

    Priority-aware eligibility (migration 004_watchlist_priority.sql
    must be applied for the ``priority`` column to exist):

      * ``hot``       — re-snapshot if older than ``hot_interval_sec``
                        (default 3600s / 1h, env
                        ``RECUPERO_WATCH_HOT_INTERVAL_SEC``)
      * ``standard``  — re-snapshot if older than ``min_interval_sec``
                        (default 43200s / 12h)
      * ``paused``    — never snapshotted; stays on the list for
                        cross-reference but burns no API budget

    Backward-compat: if the ``priority`` column doesn't exist yet
    (migration not applied), the query falls back to the legacy
    single-tier behavior — every active row uses ``min_interval_sec``.

    Concurrency (v0.32.1 forensic-audit, worker-resilience): this is an
    ATOMIC CLAIM, not a plain SELECT. Pre-fix the function ran a bare
    SELECT and ``last_snapshot_at`` was only advanced at the very end
    (in ``_persist_and_diff``, after the chain API call). watch-tick runs
    as an UNLEASED Railway cron — exactly like monitor_tick — so when one
    tick runs long (a big watchlist) and the cron fires again, OR two
    worker instances overlap, BOTH ticks selected the same eligible rows
    and BOTH burned an Etherscan/Helius call + wrote a duplicate snapshot
    row (and a spurious ~0 "material change" diff against the sibling's
    fresh row). Same race monitor_tick closed in PUNISH-B / RIGOR-1.

    The fix mirrors monitor_tick's claim: a single ``UPDATE ... FROM
    (SELECT ... FOR UPDATE SKIP LOCKED LIMIT) ... RETURNING`` advances
    ``last_snapshot_at = NOW()`` (the claim mark) atomically as it selects.
    Under ``autocommit=True`` the UPDATE commits immediately, so a second
    concurrent tick's cooldown filter (``last_snapshot_at < NOW() -
    interval``) now excludes the just-claimed rows — no double work.

    Trade-off (accepted, documented): the cooldown interval IS the claim
    TTL. If a tick crashes between claim and snapshot, that row waits one
    cooldown cycle (1h hot / 12h standard) before re-attempt rather than
    being retried on the very next tick. For periodic balance snapshots
    (not one-shot critical actions) a one-cycle freshness delay on the
    rare mid-tick crash is acceptable — and strictly better than the
    guaranteed double-work the bare SELECT caused on every cron overlap.
    """
    if hot_interval_sec is None:
        hot_interval_sec = _env_int(
            _ENV_HOT_INTERVAL_SEC, _DEFAULT_HOT_INTERVAL_SEC,
        )

    # Treat None and 0 as "no limit" so the CLI flag can default
    # safely to 0 without silently capping everything. The LIMIT lives
    # INSIDE the FOR-UPDATE-SKIP-LOCKED subquery (so we lock+claim at
    # most ``use_limit`` rows) and is ALWAYS present as a literal
    # ``LIMIT %s`` — Postgres treats ``LIMIT NULL`` as "no limit", so
    # binding ``use_limit=None`` is the unbounded case. Keeping it a
    # literal (not an f-string interpolation) keeps the statement a pure
    # string constant for the inline-SQL audit; only the bound %s
    # parameter ever carries the value.
    use_limit = limit if (limit is not None and limit > 0) else None

    claim_sql_with_priority = """
        UPDATE public.watchlist w
           SET last_snapshot_at = NOW()
          FROM (
            SELECT id
              FROM public.watchlist
             WHERE status = 'active'
               AND priority IN ('standard', 'hot')
               AND (last_snapshot_at IS NULL
                    OR last_snapshot_at < NOW() - (
                        CASE priority
                          WHEN 'hot' THEN make_interval(secs => %s)
                          ELSE             make_interval(secs => %s)
                        END
                    ))
             ORDER BY
               CASE priority WHEN 'hot' THEN 0 ELSE 1 END,
               last_balance_usd DESC NULLS LAST, flagged_at ASC
             LIMIT %s
             FOR UPDATE SKIP LOCKED
          ) c
         WHERE w.id = c.id
        RETURNING w.id, w.address, w.chain, w.role, w.label_category,
                  w.label_name, w.is_freezeable, w.issuer, w.asset_symbol,
                  w.asset_contract, w.last_snapshot_at, w.priority,
                  w.investigation_id
    """
    claim_sql_legacy = """
        UPDATE public.watchlist w
           SET last_snapshot_at = NOW()
          FROM (
            SELECT id
              FROM public.watchlist
             WHERE status = 'active'
               AND (last_snapshot_at IS NULL
                    OR last_snapshot_at < NOW() - make_interval(secs => %s))
             ORDER BY last_balance_usd DESC NULLS LAST, flagged_at ASC
             LIMIT %s
             FOR UPDATE SKIP LOCKED
          ) c
         WHERE w.id = c.id
        RETURNING w.id, w.address, w.chain, w.role, w.label_category,
                  w.label_name, w.is_freezeable, w.issuer, w.asset_symbol,
                  w.asset_contract, w.last_snapshot_at, w.investigation_id
    """

    pri_params: tuple[Any, ...] = (hot_interval_sec, min_interval_sec, use_limit)
    legacy_params: tuple[Any, ...] = (min_interval_sec, use_limit)

    pooled_dsn = _pooled_dsn(dsn)
    with db_connect(pooled_dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        try:
            cur.execute(claim_sql_with_priority, pri_params)
        except psycopg.errors.UndefinedColumn:
            # Migration 004 not applied — fall back to single-tier.
            # db_connect runs autocommit=True, so the failed UPDATE did
            # not open a poisoned transaction; a fresh cursor is clean.
            log.warning(
                "watchlist.priority column missing — fallback to "
                "single-tier cooldown (apply migration 004 to enable hot tier)"
            )
            with conn.cursor() as cur2:
                cur2.execute(claim_sql_legacy, legacy_params)
                return list(cur2.fetchall())
        return list(cur.fetchall())


def _run_evm_chain(
    *,
    chain: str,
    rows: list[dict[str, Any]],
    dsn: str,
    price_client: Any,
    parallelism: int,
    delta_usd_threshold: Decimal,
    report: WatchTickReport,
) -> None:
    """Snapshot one EVM chain's wallets via Etherscan v2."""
    api_key = os.environ.get("ETHERSCAN_API_KEY", "").strip()
    if not api_key:
        report.errors.append(
            f"ETHERSCAN_API_KEY not set; cannot snapshot {len(rows)} {chain} rows"
        )
        return

    from recupero.chains.ethereum.etherscan import EtherscanClient
    client = EtherscanClient(api_key=api_key, chain_id=_CHAIN_ID_BY_NAME[chain])
    try:
        _run_chain_pool(
            rows=rows, dsn=dsn,
            snapshot_fn=lambda row: _snapshot_evm_one(row, client, price_client),
            parallelism=parallelism,
            delta_usd_threshold=delta_usd_threshold,
            report=report,
        )
    finally:
        client.close()


def _run_hyperliquid_chain(
    *,
    rows: list[dict[str, Any]],
    dsn: str,
    price_client: Any,
    parallelism: int,
    delta_usd_threshold: Decimal,
    report: WatchTickReport,
) -> None:
    """Snapshot Hyperliquid wallets via the /info endpoint.

    No API key needed — Hyperliquid's info endpoint is public.
    Each wallet snapshot fetches the perp clearinghouse state +
    spot clearinghouse state and totals the USD across both.
    """
    from recupero.chains.hyperliquid.client import HyperliquidClient
    client = HyperliquidClient()
    try:
        _run_chain_pool(
            rows=rows, dsn=dsn,
            snapshot_fn=lambda row: _snapshot_hyperliquid_one(row, client, price_client),
            parallelism=parallelism,
            delta_usd_threshold=delta_usd_threshold,
            report=report,
        )
    finally:
        client.close()


def _snapshot_hyperliquid_one(
    row: dict[str, Any], client: Any, price_client: Any,
) -> _Snapshot:
    """Hyperliquid /info-based snapshot.

    Combines two info queries:
      * clearinghouseState     — perp account_value + withdrawable
      * spotClearinghouseState — spot balances (USDC, etc.)

    The total_usd is the sum of perp accountValue + spot USDC-equivalent
    balances. Hyperliquid USDC is already USD-priced 1:1 so we don't
    route through CoinGecko for it.

    tx_count is left None — Hyperliquid doesn't have a per-wallet
    "lifetime tx count" concept the way EVM does; the existing
    non-funding-ledger paginator could count events but at the cost
    of a much longer snapshot per wallet, so we keep this snapshot
    lightweight and defer ledger counting to the trace stage.
    """
    addr = row["address"]
    snap = _Snapshot(
        native_balance_raw=None, tx_count=None, total_usd=None,
        source="hyperliquid",
    )

    try:
        perp_state = client.get_clearinghouse_state(addr)
        spot_state = client.get_spot_clearinghouse_state(addr)
    except Exception as exc:  # noqa: BLE001
        snap.error = f"hl info: {exc}"
        return snap

    total_usd = Decimal(0)
    # Perp side — marginSummary.accountValue is USD-denominated.
    try:
        ms = (perp_state or {}).get("marginSummary") or {}
        av = ms.get("accountValue")
        if av:
            total_usd += Decimal(str(av))
    except (ValueError, TypeError):
        pass

    # Spot side — balances[].total per coin. USDC is USD 1:1.
    # Non-USDC spot tokens are rare on HL spot today — we'd need a
    # price-lookup path if they show up. For now we only sum coins
    # we can confidently 1:1 to USD; others get logged + skipped.
    try:
        balances = (spot_state or {}).get("balances") or []
        for b in balances:
            coin = (b.get("coin") or "").upper()
            total = b.get("total")
            if not total:
                continue
            if coin in {"USDC", "USDC0", "USD"}:
                total_usd += Decimal(str(total))
                snap.token_balances.append({
                    "symbol": coin, "contract": None,
                    "raw_amount": str(total), "decimal_amount": str(total),
                    "usd_value": str(Decimal(str(total))),
                })
            else:
                # Unknown spot coin — record balance but no USD.
                snap.token_balances.append({
                    "symbol": coin, "contract": None,
                    "raw_amount": str(total), "decimal_amount": str(total),
                    "usd_value": None,
                })
    except Exception as exc:  # noqa: BLE001
        log.debug("hl spot parse failed for %s: %s", addr, exc)

    snap.total_usd = total_usd
    return snap


def _run_solana_chain(
    *,
    rows: list[dict[str, Any]],
    dsn: str,
    price_client: Any,
    parallelism: int,
    delta_usd_threshold: Decimal,
    report: WatchTickReport,
) -> None:
    """Snapshot Solana wallets via Helius."""
    api_key = os.environ.get("HELIUS_API_KEY", "").strip()
    if not api_key:
        report.errors.append(
            f"HELIUS_API_KEY not set; cannot snapshot {len(rows)} solana rows"
        )
        return

    from recupero.chains.solana.helius import HeliusClient
    client = HeliusClient(api_key=api_key)
    try:
        _run_chain_pool(
            rows=rows, dsn=dsn,
            snapshot_fn=lambda row: _snapshot_solana_one(row, client, price_client),
            parallelism=parallelism,
            delta_usd_threshold=delta_usd_threshold,
            report=report,
        )
    finally:
        client.close()


def _run_bitcoin_chain(
    *,
    rows: list[dict[str, Any]],
    dsn: str,
    price_client: Any,
    parallelism: int,
    delta_usd_threshold: Decimal,
    report: WatchTickReport,
) -> None:
    """Snapshot Bitcoin wallets via Esplora (mempool.space / blockstream).

    v0.37.5 (deep-reach cleanup, Tier 2): closes the #4↔#5 loop. The
    THORChain decoder (v0.37.4) now reaches native-Bitcoin resting places, and
    auto-subscription adds them to the watchlist — but pre-v0.37.5 watch-tick
    skipped every ``bitcoin`` row (``skipped_unsupported_chain``), so a dormant
    BTC holder we could REACH we could not MONITOR. No API key needed (Esplora
    free tier). BTC has no token standard, so the snapshot is native-only.
    """
    from recupero.chains.bitcoin.esplora import EsploraClient
    client = EsploraClient()
    try:
        _run_chain_pool(
            rows=rows, dsn=dsn,
            snapshot_fn=lambda row: _snapshot_bitcoin_one(row, client, price_client),
            parallelism=parallelism,
            delta_usd_threshold=delta_usd_threshold,
            report=report,
        )
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass


def _snapshot_bitcoin_one(
    row: dict[str, Any], client: Any, price_client: Any,
) -> _Snapshot:
    """Esplora-based snapshot for a Bitcoin address: confirmed native balance
    (sats) priced via CoinGecko ``bitcoin``. No tokens on Bitcoin, so
    token_balances stays empty and tx_count is left None (the trace stage
    counts movement; the monitor only needs the balance delta)."""
    addr = row["address"]
    snap = _Snapshot(
        native_balance_raw=None, tx_count=None, total_usd=None,
        source="esplora",
    )
    try:
        snap.native_balance_raw = int(client.address_balance_sats(addr))
    except Exception as exc:  # noqa: BLE001
        snap.error = f"btc balance: {exc}"
        return snap

    total = Decimal(0)
    if snap.native_balance_raw and snap.native_balance_raw > 0:
        btc_decimal = Decimal(snap.native_balance_raw) / Decimal(10 ** 8)
        btc_token = _native_token_for("bitcoin")
        if btc_token is not None:
            try:
                price = price_client.price_now(btc_token)
                if price.usd_value is not None:
                    total = price.usd_value * btc_decimal
            except Exception as exc:  # noqa: BLE001
                log.debug("BTC price fetch failed for %s: %s", addr, exc)
    snap.total_usd = total
    return snap


def _emit_graph_event(dsn: str, row: dict[str, Any], change: MaterialChange) -> None:
    """Best-effort: NOTIFY the operator graph that a watched address moved
    (Phase 4.13). Routed by the watchlist row's investigation_id so only
    operators streaming that case receive it. Never raises — a monitoring
    nicety must not affect the tick."""
    inv = row.get("investigation_id")
    if not inv:
        return
    try:
        from recupero.reports.graph_events import build_delta_event, notify_pg
        node = {
            "id": change.address,
            "status": "intermediary",
            "reason": change.reason,
            "newUsd": (str(change.new_usd) if change.new_usd is not None else None),
            "deltaUsd": (str(change.delta_usd) if change.delta_usd is not None else None),
        }
        notify_pg(dsn, str(inv), build_delta_event(reason="watch", nodes=[node], edges=[]))
    except Exception as exc:  # noqa: BLE001
        log.debug("watch-tick: graph event emit skipped: %s", exc)


def _run_chain_pool(
    *,
    rows: list[dict[str, Any]],
    dsn: str,
    snapshot_fn,
    parallelism: int,
    delta_usd_threshold: Decimal,
    report: WatchTickReport,
) -> None:
    """Shared parallel loop for any chain — fan out snapshot_fn(row),
    persist + diff sequentially as results arrive."""
    with ThreadPoolExecutor(max_workers=parallelism) as pool:
        futures = {pool.submit(snapshot_fn, row): row for row in rows}
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
                    _emit_graph_event(dsn, row, change)  # best-effort live push
            except Exception as exc:  # noqa: BLE001
                msg = f"persist failed for {row['address']} on {row['chain']}: {exc}"
                log.warning(msg)
                report.errors.append(msg)


def _snapshot_evm_one(
    row: dict[str, Any], client: Any, price_client: Any,
) -> _Snapshot:
    """Fetch native balance, optional token balance, and tx count for
    one wallet. Returns a populated :class:`_Snapshot`."""
    addr = row["address"]
    chain_name = row["chain"]

    snap = _Snapshot(native_balance_raw=None, tx_count=None, total_usd=None)

    # v0.16.9 (round-9 worker-resilience HIGH): see eth_getTransactionCount
    # block-tag comment below — `finalized` avoids reorg-driven phantom
    # alerts. Apply to balance queries too so the whole snapshot is at
    # the same confirmation depth.
    block_tag = os.environ.get("RECUPERO_BLOCK_TAG", "finalized").strip() or "finalized"

    # Native balance.
    try:
        eth_raw = client.get_eth_balance(addr, tag=block_tag)
        snap.native_balance_raw = int(eth_raw)
    except Exception as exc:  # noqa: BLE001
        snap.error = f"native balance: {exc}"
        return snap

    # Tx count (lifetime). Etherscan v2 exposes this via the proxy
    # module — same JSON-RPC shape as `eth_getTransactionCount`.
    # block_tag is set above; `finalized` defaults avoid reorg-driven
    # phantom alerts. See the comment near the balance fetch.
    try:
        data = client._call(  # noqa: SLF001
            module="proxy", action="eth_getTransactionCount",
            address=addr, tag=block_tag,
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
            token_raw = client.get_token_balance(contract, addr, tag=block_tag)
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


def _snapshot_solana_one(
    row: dict[str, Any], client: Any, price_client: Any,
) -> _Snapshot:
    """Helius-based snapshot for a Solana address.

    Uses Helius RPC primitives directly:
      * ``getBalance`` — native SOL balance in lamports
      * ``getSignaturesForAddress`` (limit=1000) for the lifetime
        tx count proxy. Solana doesn't expose a tx-count number
        per address the way EVM does; we approximate by counting
        signatures. The cap at 1000 means very-busy addresses
        report a ceiling rather than the true count — flagged in
        materiality detection by also tracking when this hits 1000.

    SPL token balance: when the watchlist row carries an
    ``asset_contract`` (the SPL mint address for Solana), we use
    ``getTokenAccountsByOwner`` filtered by that mint and sum the
    balances across all token accounts the wallet owns of that
    mint. Most wallets have exactly one token account per mint;
    aggregating handles the unusual case of split positions.
    """
    addr = row["address"]
    snap = _Snapshot(
        native_balance_raw=None, tx_count=None, total_usd=None,
        source="helius",
    )

    try:
        data = client._rpc_call("getBalance", [addr])  # noqa: SLF001
        result = data.get("result") or {}
        # getBalance returns { context: {...}, value: <lamports int> }
        if isinstance(result, dict):
            snap.native_balance_raw = int(result.get("value") or 0)
        else:
            snap.native_balance_raw = int(result)
    except Exception as exc:  # noqa: BLE001
        snap.error = f"sol getBalance: {exc}"
        return snap

    # Tx count proxy via signatures.
    try:
        data = client._rpc_call(  # noqa: SLF001
            "getSignaturesForAddress", [addr, {"limit": 1000}],
        )
        sigs = data.get("result") or []
        snap.tx_count = len(sigs) if isinstance(sigs, list) else None
    except Exception as exc:  # noqa: BLE001
        log.debug("sol getSignaturesForAddress failed for %s: %s", addr, exc)

    # SPL token balance — sum across all token accounts the wallet
    # owns of the given mint. getTokenAccountsByOwner returns a list
    # of token-account entries each with a uiTokenAmount.amount
    # (string, raw integer) + decimals.
    contract = row.get("asset_contract")
    symbol = row.get("asset_symbol") or "TOKEN"
    if contract:
        try:
            data = client._rpc_call(  # noqa: SLF001
                "getTokenAccountsByOwner",
                [
                    addr,
                    {"mint": contract},
                    {"encoding": "jsonParsed"},
                ],
            )
            accounts = (data.get("result") or {}).get("value") or []
            raw_total = 0
            decimals = 9  # SPL default if we can't read it
            for acc in accounts:
                info = (((acc or {}).get("account") or {})
                        .get("data") or {}).get("parsed") or {}
                token_info = (info.get("info") or {}).get("tokenAmount") or {}
                if token_info:
                    try:
                        raw_total += int(token_info.get("amount") or 0)
                        decimals = int(
                            token_info.get("decimals") or decimals
                        )
                    except (ValueError, TypeError):
                        continue
            if raw_total > 0:
                decimal_amount = Decimal(raw_total) / Decimal(10 ** decimals)
                token_ref = TokenRef(
                    chain=Chain.solana, contract=contract,
                    symbol=symbol, decimals=decimals,
                )
                try:
                    price = price_client.price_now(token_ref)
                    token_usd = (
                        price.usd_value * decimal_amount
                        if price.usd_value is not None else None
                    )
                except Exception:  # noqa: BLE001
                    token_usd = None
                snap.token_balances.append({
                    "symbol": symbol,
                    "contract": contract,
                    "raw_amount": str(raw_total),
                    "decimal_amount": str(decimal_amount),
                    "usd_value": (
                        str(token_usd) if token_usd is not None else None
                    ),
                })
        except Exception as exc:  # noqa: BLE001
            log.debug("sol SPL fetch failed for %s/%s: %s",
                      addr, contract, exc)

    # Native value in USD. Solana lamports → SOL via 10^9.
    native_usd = Decimal(0)
    if snap.native_balance_raw and snap.native_balance_raw > 0:
        sol_decimal = Decimal(snap.native_balance_raw) / Decimal(10 ** 9)
        sol_token = _native_token_for("solana")
        if sol_token is not None:
            try:
                price = price_client.price_now(sol_token)
                if price.usd_value is not None:
                    native_usd = price.usd_value * sol_decimal
            except Exception as exc:  # noqa: BLE001
                log.debug("SOL price fetch failed for %s: %s", addr, exc)

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
        "ethereum": ("ETH",  "ethereum",      18),
        "arbitrum": ("ETH",  "ethereum",      18),
        "base":     ("ETH",  "ethereum",      18),
        "polygon":  ("MATIC", "matic-network", 18),
        "bsc":      ("BNB",  "binancecoin",   18),
        # Solana: SOL has 9 decimals (lamports), not 18 like EVM gas.
        "solana":   ("SOL",  "solana",         9),
        # Bitcoin: BTC has 8 decimals (satoshis). v0.37.5.
        "bitcoin":  ("BTC",  "bitcoin",        8),
    }
    entry = mapping.get(chain_name)
    if not entry:
        return None
    symbol, coingecko_id, decimals = entry
    try:
        chain = Chain(chain_name)
    except ValueError:
        return None
    return TokenRef(
        chain=chain, contract=None, symbol=symbol, decimals=decimals,
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
    with db_connect(pooled_dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
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

        new_taken_at = datetime.now(UTC)
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


# v0.19.0: single source moved to recupero._common.pooled_dsn (pre-v0.19.0
# this was duplicated verbatim in 4 worker modules).
from recupero._common import db_connect  # noqa: E402
from recupero._common import pooled_dsn as _pooled_dsn

__all__ = (
    "MaterialChange",
    "WatchTickReport",
    "run_watch_tick",
)
