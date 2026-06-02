"""Watchlist / Watcher overview (v0.35.0).

The operator-facing answer to "show me EVERYTHING we're watching, where it
sits, and whether it has MOVED since the last check." This is the
TRM/Chainalysis-style continuous-monitoring surface built on the infrastructure
we already have:

  * ``public.watchlist`` — every flagged address (TRACKED non-freezable funds,
    freezable holdings, mixer/exchange terminals), with denormalized last
    balance / tx-count from the latest snapshot.
  * ``public.watchlist_snapshots`` — the periodic balance/tx-count snapshots
    written by ``worker.watch_tick.run_watch_tick`` (the daily/monthly re-check
    engine; ``recupero-ops watchlist-run`` triggers it on demand).

This module turns those rows into a per-address overview with a MOVEMENT VERDICT
(moved / still-present / never-checked) and staleness (how long since the last
re-check), plus portfolio rollups by status and by chain. ``summarize_watchlist``
is a PURE function over already-fetched rows (trivially unit-testable);
``build_watchlist_overview`` is the thin DB read that feeds it.

No fabrication: every figure comes from a real watchlist row / snapshot. A
movement verdict of ``moved`` means a real snapshot recorded a balance delta or
a new outbound tx since the prior snapshot — never an inference.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import UUID

log = logging.getLogger(__name__)

# A watched row is "stale" (needs a re-check) when its last snapshot is older
# than this. Daily operators want ~24h; monthly operators can pass a larger
# value. Surfaced so the dashboard can highlight rows due for a re-run.
DEFAULT_STALE_AFTER_HOURS = 24
# A snapshot delta at/above this (USD) counts as MOVEMENT even if tx-count
# parsing is unavailable. Mirrors watch_tick's material-change threshold.
DEFAULT_MOVE_THRESHOLD_USD = Decimal("100")

# Display status → (emoji pill, human label). Mirrors the brief's vocabulary so
# the watcher UI reads the same as the LE handoff.
_STATUS_PILL = {
    "TRACKED": ("\U0001f7ea", "TRACKED"),        # 🟪 identified, monitored
    "FREEZABLE": ("\U0001f7e9", "FREEZABLE"),     # 🟩
    "UNRECOVERABLE": ("⬛", "UNRECOVERABLE"),  # ⬛ mixer/burned
    "EXCHANGE": ("\U0001f7e6", "EXCHANGE"),        # 🟦 subpoena target
    "FROZEN": ("\U0001f9ca", "FROZEN"),            # 🧊 freeze confirmed
    "RECOVERED": ("✅", "RECOVERED"),          # ✅ returned
    "INVESTIGATE": ("\U0001f7e7", "INVESTIGATE"),  # 🟧
    "UNKNOWN": ("⬜", "UNKNOWN"),              # ⬜
}

_EXPLORER_BASE = {
    "ethereum": "https://etherscan.io/address/",
    "arbitrum": "https://arbiscan.io/address/",
    "base": "https://basescan.org/address/",
    "optimism": "https://optimistic.etherscan.io/address/",
    "polygon": "https://polygonscan.com/address/",
    "bsc": "https://bscscan.com/address/",
    "solana": "https://solscan.io/account/",
    "tron": "https://tronscan.org/#/address/",
    "bitcoin": "https://mempool.space/address/",
}


@dataclass
class WatchedItem:
    """One watched address with its current monitored state + movement verdict."""
    address: str
    chain: str
    status: str                 # display status (TRACKED / FREEZABLE / ...)
    role: str = ""
    priority: str = "standard"  # standard / hot / paused
    issuer: str | None = None
    asset_symbol: str | None = None
    label_name: str | None = None
    investigation_id: str | None = None
    flagged_at: datetime | None = None
    last_checked_at: datetime | None = None
    balance_usd: Decimal = field(default_factory=lambda: Decimal(0))
    native_balance: Decimal | None = None
    tx_count: int | None = None
    # Movement verdict — the headline of the watcher view.
    movement: str = "never_checked"   # moved / still_present / never_checked
    last_delta_usd: Decimal | None = None
    days_watched: int | None = None
    hours_since_check: float | None = None
    stale: bool = True
    explorer_url: str | None = None


@dataclass
class WatchlistOverview:
    """Portfolio-level rollup of everything under watch."""
    items: list[WatchedItem] = field(default_factory=list)
    n_items: int = 0
    total_watched_usd: Decimal = field(default_factory=lambda: Decimal(0))
    total_still_present_usd: Decimal = field(default_factory=lambda: Decimal(0))
    total_moved_usd: Decimal = field(default_factory=lambda: Decimal(0))
    n_moved: int = 0
    n_still_present: int = 0
    n_never_checked: int = 0
    n_stale: int = 0
    by_status: dict[str, int] = field(default_factory=dict)
    by_chain: dict[str, dict[str, Any]] = field(default_factory=dict)
    stale_after_hours: int = DEFAULT_STALE_AFTER_HOURS
    generated_at: datetime | None = None


def _to_decimal(value: Any) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, Decimal):
        return value if value.is_finite() else None
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None
    return d if d.is_finite() else None


def _to_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        s = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _display_status(row: dict[str, Any]) -> str:
    """Map a watchlist row to the watcher UI's display status.

    Lifecycle status (frozen/recovered) wins; otherwise derive from
    freezability + label category, matching the brief's vocabulary.
    """
    wl_status = (row.get("status") or "active").lower()
    if wl_status == "frozen":
        return "FROZEN"
    if wl_status == "recovered":
        return "RECOVERED"
    if row.get("is_freezeable"):
        return "FREEZABLE"
    cat = (row.get("label_category") or "").lower()
    if cat == "mixer":
        return "UNRECOVERABLE"
    if cat in ("exchange_deposit", "exchange_hot_wallet"):
        return "EXCHANGE"
    # Everything else identified-but-not-freezable is monitored = TRACKED.
    return "TRACKED"


def summarize_watchlist(
    rows: list[dict[str, Any]],
    *,
    now: datetime,
    stale_after_hours: int = DEFAULT_STALE_AFTER_HOURS,
    move_threshold_usd: Decimal = DEFAULT_MOVE_THRESHOLD_USD,
) -> WatchlistOverview:
    """Pure: turn fetched watchlist+snapshot rows into the overview.

    Each row dict carries the watchlist columns plus, from the latest two
    snapshots: ``latest_delta_usd`` (delta_usd of the most recent snapshot) and
    ``prior_tx_count`` (tx_count of the snapshot before it). Movement verdict:
      * never_checked — no snapshot yet (last_snapshot_at is None);
      * moved — latest |delta_usd| ≥ threshold OR tx_count grew vs the prior
        snapshot (a real new outbound tx);
      * still_present — snapshotted, no material change.
    """
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    overview = WatchlistOverview(
        stale_after_hours=stale_after_hours, generated_at=now,
    )
    for row in rows:
        status = _display_status(row)
        bal = _to_decimal(row.get("last_balance_usd")) or Decimal(0)
        flagged = _to_dt(row.get("flagged_at"))
        checked = _to_dt(row.get("last_snapshot_at"))
        last_tx = _to_int(row.get("last_tx_count"))
        prior_tx = _to_int(row.get("prior_tx_count"))
        delta = _to_decimal(row.get("latest_delta_usd"))

        if checked is None:
            movement = "never_checked"
        else:
            moved_by_usd = delta is not None and delta.copy_abs() >= move_threshold_usd
            moved_by_tx = (
                last_tx is not None and prior_tx is not None and last_tx > prior_tx
            )
            movement = "moved" if (moved_by_usd or moved_by_tx) else "still_present"

        hours_since = (
            (now - checked).total_seconds() / 3600.0 if checked is not None else None
        )
        stale = hours_since is None or hours_since > stale_after_hours
        days_watched = (now - flagged).days if flagged is not None else None
        chain = (row.get("chain") or "").lower()
        addr = row.get("address") or ""
        base = _EXPLORER_BASE.get(chain)

        item = WatchedItem(
            address=addr,
            chain=chain,
            status=status,
            role=row.get("role") or "",
            priority=(row.get("priority") or "standard"),
            issuer=row.get("issuer"),
            asset_symbol=row.get("asset_symbol"),
            label_name=row.get("label_name"),
            investigation_id=(
                str(row["investigation_id"]) if row.get("investigation_id") else None
            ),
            flagged_at=flagged,
            last_checked_at=checked,
            balance_usd=bal,
            native_balance=_to_decimal(row.get("last_native_balance")),
            tx_count=last_tx,
            movement=movement,
            last_delta_usd=delta,
            days_watched=days_watched,
            hours_since_check=hours_since,
            stale=stale,
            explorer_url=(base + addr) if (base and addr) else None,
        )
        overview.items.append(item)

        # Rollups.
        overview.n_items += 1
        overview.total_watched_usd += bal
        overview.by_status[status] = overview.by_status.get(status, 0) + 1
        if movement == "moved":
            overview.n_moved += 1
            overview.total_moved_usd += bal
        elif movement == "still_present":
            overview.n_still_present += 1
            overview.total_still_present_usd += bal
        else:
            overview.n_never_checked += 1
        if stale:
            overview.n_stale += 1
        ch = overview.by_chain.setdefault(
            chain or "unknown", {"n": 0, "usd": Decimal(0)},
        )
        ch["n"] += 1
        ch["usd"] += bal

    # Sort: MOVED first (most urgent), then by USD desc — the operator's triage
    # order for a daily/monthly run.
    move_rank = {"moved": 0, "never_checked": 1, "still_present": 2}
    overview.items.sort(
        key=lambda it: (move_rank.get(it.movement, 3), -float(it.balance_usd)),
    )
    return overview


def build_watchlist_overview(
    *,
    dsn: str | None,
    investigation_id: UUID | str | None = None,
    stale_after_hours: int = DEFAULT_STALE_AFTER_HOURS,
    limit: int = 5000,
    now: datetime | None = None,
) -> WatchlistOverview:
    """Read the watchlist + latest-two snapshots and summarize.

    Empty overview when ``dsn`` is None, psycopg is unavailable, or the DB read
    fails (logged at WARN) — the renderer never crashes on a Supabase outage.
    Pass ``investigation_id`` to scope to one case; omit for the global view.
    """
    now = now or datetime.now(UTC)
    if not dsn:
        return WatchlistOverview(
            stale_after_hours=stale_after_hours, generated_at=now,
        )
    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return WatchlistOverview(
            stale_after_hours=stale_after_hours, generated_at=now,
        )

    from psycopg.rows import dict_row

    from recupero._common import db_connect

    # Two COMPLETE literal queries (no f-string / dynamic SQL — passes the
    # inline-SQL injection audit). The only difference is the optional
    # investigation filter; every value (investigation_id, limit) is bound via
    # %s, never interpolated.
    sql_global = """
        SELECT w.address, w.chain, w.role, w.is_freezeable, w.issuer,
               w.asset_symbol, w.asset_contract, w.flagged_at, w.status,
               w.priority, w.label_category, w.label_name, w.investigation_id,
               w.last_balance_usd, w.last_native_balance, w.last_tx_count,
               w.last_snapshot_at,
               s1.delta_usd AS latest_delta_usd,
               s2.tx_count  AS prior_tx_count
          FROM public.watchlist w
          LEFT JOIN LATERAL (
              SELECT delta_usd FROM public.watchlist_snapshots
               WHERE watchlist_id = w.id ORDER BY taken_at DESC LIMIT 1
          ) s1 ON TRUE
          LEFT JOIN LATERAL (
              SELECT tx_count FROM public.watchlist_snapshots
               WHERE watchlist_id = w.id ORDER BY taken_at DESC OFFSET 1 LIMIT 1
          ) s2 ON TRUE
         WHERE w.status <> 'cleared'
         ORDER BY w.last_balance_usd DESC NULLS LAST, w.flagged_at ASC
         LIMIT %s
    """
    sql_by_investigation = """
        SELECT w.address, w.chain, w.role, w.is_freezeable, w.issuer,
               w.asset_symbol, w.asset_contract, w.flagged_at, w.status,
               w.priority, w.label_category, w.label_name, w.investigation_id,
               w.last_balance_usd, w.last_native_balance, w.last_tx_count,
               w.last_snapshot_at,
               s1.delta_usd AS latest_delta_usd,
               s2.tx_count  AS prior_tx_count
          FROM public.watchlist w
          LEFT JOIN LATERAL (
              SELECT delta_usd FROM public.watchlist_snapshots
               WHERE watchlist_id = w.id ORDER BY taken_at DESC LIMIT 1
          ) s1 ON TRUE
          LEFT JOIN LATERAL (
              SELECT tx_count FROM public.watchlist_snapshots
               WHERE watchlist_id = w.id ORDER BY taken_at DESC OFFSET 1 LIMIT 1
          ) s2 ON TRUE
         WHERE w.status <> 'cleared' AND w.investigation_id = %s
         ORDER BY w.last_balance_usd DESC NULLS LAST, w.flagged_at ASC
         LIMIT %s
    """
    if investigation_id is not None:
        sql = sql_by_investigation
        params: list[Any] = [str(investigation_id), int(limit)]
    else:
        sql = sql_global
        params = [int(limit)]
    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        log.warning("build_watchlist_overview: DB read failed: %s", exc)
        return WatchlistOverview(
            stale_after_hours=stale_after_hours, generated_at=now,
        )

    return summarize_watchlist(
        list(rows), now=now, stale_after_hours=stale_after_hours,
    )


__all__ = (
    "WatchedItem",
    "WatchlistOverview",
    "summarize_watchlist",
    "build_watchlist_overview",
    "DEFAULT_STALE_AFTER_HOURS",
    "DEFAULT_MOVE_THRESHOLD_USD",
)
