"""Tron settled-outbound freeze-race watcher (roadmap-v4 Tier-2 #10).

Tron carries roughly half of all USDT laundering, yet the near-real-time
freeze-race watch was EVM-only (``mempool_watch`` = Alchemy pending-tx stream,
ETH/Polygon) and the Tron watch_tick is a once-nightly balance delta. Tron has
no public pending-mempool stream, so the analogue is a frequent poll of
recently-SETTLED outbound TRC-20 transfers: when a watched Tron wallet sends
USDT out — especially toward a known exchange deposit address — an operator can
race a freeze with the issuer/exchange before the cash-out completes.

This module is the pure classifier + a settled-outbound scan over TronGrid's
``/v1/accounts/{addr}/transactions/trc20?only_from=true&min_timestamp=…``. The
transfer row shape (from / to / value / token_info{symbol,address,decimals} /
block_timestamp / transaction_id) is LIVE-VERIFIED (2026-06) against real
TronGrid responses; the canonical USDT-TRC20 contract is pinned + verified.

Forensic posture: every alert is a SETTLED, confirmed on-chain transfer (a fact,
not a prediction). Tron addresses are base58check and CASE-SENSITIVE — they are
NEVER lowercased (unlike EVM hex). The freezable flag is set only when the
destination resolves to a known exchange label (the operator still confirms +
files); amounts are raw + human (token decimals). Nothing is fabricated.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

log = logging.getLogger(__name__)

# Canonical USDT-TRC20 contract (base58check) — LIVE-VERIFIED via TronGrid
# token_info.address on real transfers. Stable since 2019.
USDT_TRC20_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

CexLookup = Callable[[str], str | None]
"""address -> exchange/issuer name if it's a known freezable deposit, else None."""

# Label categories that mark a freezable exchange destination.
_EXCHANGE_CATEGORIES = frozenset(
    {"exchange", "exchange_deposit", "exchange_hot_wallet", "cex"}
)


@dataclass(frozen=True)
class TronOutboundAlert:
    """One settled outbound TRC-20 transfer FROM a watched Tron wallet."""
    from_address: str
    to_address: str
    token_symbol: str
    contract: str
    amount_raw: str
    amount_human: str           # decimal string scaled by token decimals
    tx_id: str
    block_time: datetime
    to_is_cex: bool
    cex_name: str | None
    freezable: bool             # to_is_cex (issuer/exchange can freeze)
    settled: bool               # always True — these are confirmed txs
    recommended_action: str


def _to_decimal_amount(value: Any, decimals: Any) -> str:
    try:
        raw = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return "0"
    try:
        d = int(decimals)
    except (TypeError, ValueError):
        d = 6
    d = max(0, min(d, 255))
    try:
        return format(raw / (Decimal(10) ** d), "f")
    except (InvalidOperation, ArithmeticError):
        return "0"


def _block_time(ms: Any) -> datetime:
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        return datetime.fromtimestamp(0, tz=UTC)


def classify_tron_outbound(
    tx: dict[str, Any],
    *,
    watched: set[str],
    cex_lookup: CexLookup | None = None,
    usdt_only: bool = True,
) -> TronOutboundAlert | None:
    """Classify one TronGrid TRC-20 transfer row into a freeze-race alert, or
    ``None`` when it isn't a watched outbound (or fails the USDT filter).

    ``watched`` is a set of base58check Tron addresses (case-sensitive). A
    transfer alerts only when its ``from`` is in ``watched``."""
    if not isinstance(tx, dict):
        return None
    frm = tx.get("from")
    to = tx.get("to")
    if not isinstance(frm, str) or not isinstance(to, str):
        return None
    if frm not in watched:                 # base58 exact match — never lowercased
        return None
    info = tx.get("token_info") or {}
    contract = str(info.get("address") or "")
    symbol = str(info.get("symbol") or "?")
    if usdt_only and contract != USDT_TRC20_CONTRACT:
        return None
    value = tx.get("value")
    if value is None:
        return None
    try:
        if int(str(value)) == 0:
            return None                     # zero-value / no-op
    except (TypeError, ValueError):
        return None
    cex_name = cex_lookup(to) if cex_lookup is not None else None
    to_is_cex = cex_name is not None
    if to_is_cex:
        action = (
            f"USDT moving to {cex_name} deposit — RACE A FREEZE NOW: file an "
            f"exchange freeze request with {cex_name} citing this tx."
        )
    else:
        action = (
            "USDT left the watched wallet to an unlabeled address — confirm the "
            "destination; if it is an exchange deposit, file a freeze request."
        )
    return TronOutboundAlert(
        from_address=frm,
        to_address=to,
        token_symbol=symbol,
        contract=contract,
        amount_raw=str(value),
        amount_human=_to_decimal_amount(value, info.get("decimals", 6)),
        tx_id=str(tx.get("transaction_id") or ""),
        block_time=_block_time(tx.get("block_timestamp")),
        to_is_cex=to_is_cex,
        cex_name=cex_name,
        freezable=to_is_cex,
        settled=True,
        recommended_action=action,
    )


def iter_tron_outbound_alerts(
    transfers: Iterable[Any],
    *,
    watched: set[str],
    cex_lookup: CexLookup | None = None,
    usdt_only: bool = True,
) -> list[TronOutboundAlert]:
    out: list[TronOutboundAlert] = []
    for tx in transfers or []:
        a = classify_tron_outbound(
            tx, watched=watched, cex_lookup=cex_lookup, usdt_only=usdt_only,
        )
        if a is not None:
            out.append(a)
    return out


def default_cex_lookup(config: Any = None) -> CexLookup:
    """A CexLookup backed by the LabelStore: returns the exchange/issuer name
    for a Tron address labeled as an exchange deposit/hot-wallet, else None.
    Best-effort — a store/load failure yields a lookup that returns None."""
    try:
        from recupero.config import load_config
        from recupero.labels.store import LabelStore
        from recupero.models import Chain
        cfg = config
        if cfg is None:
            cfg, _ = load_config()
        store = LabelStore.load(cfg)
    except Exception as exc:  # noqa: BLE001
        log.warning("tron-watch: label store unavailable, no CEX lookup: %s", exc)
        return lambda _addr: None

    def _lookup(address: str) -> str | None:
        try:
            label = store.lookup(address, Chain.tron)
        except Exception:  # noqa: BLE001
            return None
        if label is None:
            return None
        cat = (getattr(label, "category", "") or "").lower()
        if cat in _EXCHANGE_CATEGORIES or "exchange" in cat:
            return getattr(label, "name", None) or getattr(label, "exchange", None) or "exchange"
        return None

    return _lookup


def scan_tron_outbound(
    *,
    addresses: Iterable[str],
    client: Any,
    since_ms: int,
    cex_lookup: CexLookup | None = None,
    usdt_only: bool = True,
    max_per_address: int = 200,
) -> list[TronOutboundAlert]:
    """For each watched Tron address, fetch its SETTLED outbound TRC-20
    transfers since ``since_ms`` (server-side ``only_from`` + ``min_timestamp``)
    and classify. ``client`` must expose ``get_trc20_transfers(addr, *,
    only_from, min_timestamp, limit, contract_address=...)``. Best-effort per
    address."""
    watched = {a for a in addresses if isinstance(a, str) and a}
    if not watched:
        return []
    alerts: list[TronOutboundAlert] = []
    for addr in watched:
        try:
            rows = client.get_trc20_transfers(
                addr, only_from=True, min_timestamp=since_ms,
                limit=max_per_address,
                contract_address=(USDT_TRC20_CONTRACT if usdt_only else None),
            )
        except Exception as exc:  # noqa: BLE001 — best-effort per address
            log.warning("tron-watch: trc20 fetch failed addr=%s: %s", addr, exc)
            continue
        alerts.extend(iter_tron_outbound_alerts(
            rows, watched=watched, cex_lookup=cex_lookup, usdt_only=usdt_only,
        ))
    return alerts


def alerts_to_json(alerts: list[TronOutboundAlert]) -> dict[str, Any]:
    """Serialize alerts to a JSON-safe artifact."""
    return {
        "kind": "recupero_tron_outbound_alerts",
        "disclaimer": (
            "Settled (confirmed) outbound USDT-TRC20 transfers from watched "
            "Tron wallets. Each is an on-chain fact, surfaced near-real-time "
            "for a freeze race — destinations resolving to a known exchange "
            "deposit are flagged FREEZABLE (file with the exchange/issuer). "
            "Amounts are raw + human (token decimals). Confirm before acting."
        ),
        "alert_count": len(alerts),
        "alerts": [
            {
                "from_address": a.from_address,
                "to_address": a.to_address,
                "token_symbol": a.token_symbol,
                "contract": a.contract,
                "amount_raw": a.amount_raw,
                "amount_human": a.amount_human,
                "tx_id": a.tx_id,
                "block_time": a.block_time.isoformat(),
                "to_is_cex": a.to_is_cex,
                "cex_name": a.cex_name,
                "freezable": a.freezable,
                "recommended_action": a.recommended_action,
            }
            for a in alerts
        ],
    }


def tron_watch_enabled() -> bool:
    """Opt-in gate (RECUPERO_TRON_WATCH) for any auto-scheduled scan. The
    ``recupero-ops tron-watch`` CLI runs regardless (explicit invocation)."""
    return (os.environ.get("RECUPERO_TRON_WATCH", "") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


__all__ = (
    "USDT_TRC20_CONTRACT",
    "TronOutboundAlert",
    "classify_tron_outbound",
    "iter_tron_outbound_alerts",
    "default_cex_lookup",
    "scan_tron_outbound",
    "alerts_to_json",
    "tron_watch_enabled",
)
