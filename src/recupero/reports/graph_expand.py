"""On-demand hop expansion for the operator graph (Phase 3.6).

This is the core TRM Reactor / Chainalysis Reactor interaction: click a
node and pull in its next-hop counterparties live, growing the graph in
either direction (funds-in / funds-out) rather than viewing a single
precomputed picture.

``aggregate_expansion`` is a **pure** function over the adapter's
normalized transfer dicts — it does the grouping, USD estimation, capping
and journey-shaped node/edge construction with no IO, so it is fully
unit-testable with synthetic rows. ``expand_address`` is the thin network
wrapper that drives a :class:`recupero.chains.base.ChainAdapter`.

USD note: the adapter rows carry ``amount_raw`` + a ``TokenRef`` but no
priced USD (pricing happens later in the pipeline). For a *live* click we
don't run the price oracle; instead we apply a conservative **stablecoin
face-value** estimate (USDC/USDT/DAI/… ≈ $1) and leave everything else at
$0 (clearly an underestimate, never an overstatement). The merged nodes
can themselves be expanded again, so depth is unbounded by design but
guarded per-call.
"""

from __future__ import annotations

import logging
import time
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any

from recupero._common import canonical_address_key as _key
from recupero._common import short_addr as _short_addr
from recupero.reports.graph_ui import _CHAIN_COLOR, _explorer_url

if TYPE_CHECKING:  # pragma: no cover
    from recupero.chains.base import ChainAdapter
    from recupero.models import Chain

log = logging.getLogger(__name__)

# Default + hard ceiling on counterparties returned per expansion click.
# A single hot wallet can have thousands of counterparties; we return the
# top-N by value/activity so one click can't dump an unreadable hairball
# (and can't be used to amplify a huge upstream fetch into a huge payload).
_DEFAULT_MAX_CP = 40
_HARD_MAX_CP = 150

# Symbols treated as ≈ $1 for the live face-value estimate. Lower-cased.
_STABLES = frozenset({
    "usdc", "usdt", "dai", "usdp", "tusd", "busd", "gusd", "usds",
    "pyusd", "fdusd", "usde", "usdc.e", "usdbc",
})


# ---- in-process expansion cache ----
#
# A live "expand" click hits a third-party chain API; an operator clicking
# the same node twice (or re-expanding after a layout change) shouldn't pay
# that latency again. Small TTL cache keyed by (chain, address, direction,
# cap). Process-local only — fine for a single API worker; a multi-worker
# deploy that wants shared caching would move this to Redis.
_EXPANSION_TTL_SEC = 120.0
_expansion_cache: dict[tuple, tuple[float, dict[str, Any]]] = {}


def _cache_get(key: tuple, *, now: float) -> dict[str, Any] | None:
    hit = _expansion_cache.get(key)
    if hit is None:
        return None
    expires, data = hit
    if now >= expires:
        _expansion_cache.pop(key, None)
        return None
    return data


def _cache_put(key: tuple, data: dict[str, Any], *, now: float) -> None:
    # Bound the cache so a scan of many addresses can't grow it unbounded.
    if len(_expansion_cache) > 512:
        _expansion_cache.clear()
    _expansion_cache[key] = (now + _EXPANSION_TTL_SEC, data)


def clear_expansion_cache() -> None:
    _expansion_cache.clear()


def _amount_decimal(token: Any, amount_raw: Any) -> Decimal | None:
    """``amount_raw / 10**decimals`` as a Decimal, or None if unusable."""
    decimals = getattr(token, "decimals", None)
    if decimals is None:
        return None
    try:
        return Decimal(int(amount_raw)) / (Decimal(10) ** int(decimals))
    except (InvalidOperation, ValueError, TypeError):
        return None


def _stable_usd(token: Any, amount_raw: Any) -> Decimal:
    """Face-value USD for a stablecoin transfer; Decimal(0) otherwise."""
    sym = (getattr(token, "symbol", "") or "").lower()
    if sym not in _STABLES:
        return Decimal(0)
    amt = _amount_decimal(token, amount_raw)
    return amt if amt is not None else Decimal(0)


def _row_usd(
    token: Any, amount_raw: Any, price_fn: Any, memo: dict[Any, Any]
) -> Decimal:
    """USD for one transfer: stablecoin face-value fast path, else (if a
    ``price_fn`` is supplied) ``amount × spot price``. ``price_fn`` failures
    or missing prices fall through to Decimal(0) — never an overstatement."""
    stable = _stable_usd(token, amount_raw)
    if stable > 0:
        return stable
    if price_fn is None:
        return Decimal(0)
    amt = _amount_decimal(token, amount_raw)
    if amt is None:
        return Decimal(0)
    key = (getattr(token, "contract", None) or getattr(token, "symbol", None))
    if key in memo:
        price = memo[key]
    else:
        try:
            price = price_fn(token)
        except Exception:  # noqa: BLE001
            price = None
        memo[key] = price
    if price is None:
        return Decimal(0)
    try:
        return amt * Decimal(str(price))
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(0)


def _iso_date(dt: Any) -> str | None:
    if dt is None:
        return None
    try:
        return dt.date().isoformat()
    except Exception:  # noqa: BLE001
        return None


def aggregate_expansion(
    rows: list[dict[str, Any]],
    *,
    root_address: str,
    direction: str,
    chain: str,
    max_counterparties: int = _DEFAULT_MAX_CP,
    price_fn: Any = None,
) -> dict[str, Any]:
    """Group ``rows`` (adapter-normalized transfer dicts) by counterparty
    and emit journey-shaped ``{nodes, edges, meta}`` for the operator graph
    to merge. ``direction`` is ``"out"`` (counterparty = the ``to`` side)
    or ``"in"`` (counterparty = the ``from`` side).

    ``price_fn(token) -> price|None`` (optional) supplies a spot USD price
    for non-stablecoin tokens; without it, only stablecoin face-value is
    counted (everything else $0 — a deliberate underestimate)."""
    cap = max(1, min(int(max_counterparties or _DEFAULT_MAX_CP), _HARD_MAX_CP))
    out_dir = direction != "in"
    root = _key(root_address)
    chain_color = _CHAIN_COLOR.get((chain or "").lower(), "#94A3B8")
    price_memo: dict[Any, Any] = {}

    agg: dict[str, dict[str, Any]] = {}
    for r in rows:
        frm, to = _key(r.get("from")), _key(r.get("to"))
        cp = to if out_dir else frm
        if not cp or cp == root:
            continue
        token = r.get("token")
        usd = _row_usd(token, r.get("amount_raw"), price_fn, price_memo)
        sym = getattr(token, "symbol", None)
        date = _iso_date(r.get("block_time"))
        slot = agg.setdefault(cp, {
            "usd": Decimal(0), "count": 0, "symbols": {},
            "first": None, "last": None,
            "explorer": r.get("explorer_url") or _explorer_url(chain, cp),
            "txs": [],
        })
        slot["usd"] += usd
        slot["count"] += 1
        if sym:
            slot["symbols"][sym] = slot["symbols"].get(sym, 0) + 1
        if date and (slot["first"] is None or date < slot["first"]):
            slot["first"] = date
        if date and (slot["last"] is None or date > slot["last"]):
            slot["last"] = date
        if len(slot["txs"]) < 14:
            slot["txs"].append({
                "date": date,
                "usd": float(usd),
                "usdLabel": f"${usd:,.2f}",
                "token": sym,
                "txUrl": r.get("explorer_url") or None,
            })

    ranked = sorted(
        agg.items(),
        key=lambda kv: (float(kv[1]["usd"]), kv[1]["count"]),
        reverse=True,
    )
    truncated = max(0, len(ranked) - cap)
    ranked = ranked[:cap]

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for cp, s in ranked:
        dom = max(s["symbols"], key=s["symbols"].get) if s["symbols"] else None
        nodes.append({
            "id": cp,
            "label": _short_addr(cp),
            "short": _short_addr(cp),
            "status": "intermediary",
            "statusLabel": "Intermediary wallet",
            "statusColor": "#64748B",
            "chain": chain,
            "chainColor": chain_color,
            "inboundUsd": f"${s['usd']:,.2f}" if out_dir else "$0.00",
            "outboundUsd": "$0.00" if out_dir else f"${s['usd']:,.2f}",
            "explorerUrl": s["explorer"],
            "clusterId": None,
            "inByCategory": {},
            "outByCategory": {},
            "risk": None,
            "riskColor": "#64748B",
            "indirectExposureUsd": 0.0,
            "expanded": True,
        })
        src, dst = (root, cp) if out_dir else (cp, root)
        edges.append({
            "source": src,
            "target": dst,
            "totalUsd": f"${s['usd']:,.2f}",
            "totalUsdNumeric": float(s["usd"]),
            "transferCount": s["count"],
            "dominantSymbol": dom,
            "isCrossChain": False,
            "firstTime": s["first"],
            "lastTime": s["last"],
            "transfers": sorted(s["txs"], key=lambda t: t["usd"], reverse=True),
            "txMore": max(0, s["count"] - len(s["txs"])),
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "root": root,
            "direction": "out" if out_dir else "in",
            "counterpartyCount": len(nodes),
            "truncated": truncated,
            "usdEstimate": (
                "spot price + stablecoin face-value" if price_fn
                else "stablecoin face-value only"
            ),
        },
    }


def _build_price_fn() -> Any | None:
    """Best-effort spot-price callable backed by CoinGecko. Returns None if
    the client can't be constructed (no config / offline) so callers
    degrade to stablecoin-only USD."""
    try:
        from recupero.config import load_config
        from recupero.pricing.coingecko import CoinGeckoClient
        config, env = load_config()
        client = CoinGeckoClient(config, env)

        def _fn(token: Any) -> Any:
            res = client.price_now(token)
            return getattr(res, "usd_value", None)

        return _fn
    except Exception as exc:  # noqa: BLE001
        log.info("expansion pricing unavailable: %s", exc)
        return None


def expand_address(
    *,
    chain: Chain,
    address: str,
    direction: str = "out",
    config: Any = None,
    adapter: ChainAdapter | None = None,
    max_counterparties: int = _DEFAULT_MAX_CP,
    start_block: int = 0,
    use_cache: bool = True,
    with_pricing: bool = False,
    price_fn: Any = None,
    _clock: Any = time.monotonic,
) -> dict[str, Any]:
    """Fetch ``address``'s next-hop counterparties on ``chain`` and return
    journey-shaped ``{nodes, edges, meta}``.

    Pass ``adapter`` to inject a pre-built (or fake) adapter — otherwise one
    is constructed via :meth:`ChainAdapter.for_chain` from ``config`` (which
    falls back to :func:`recupero.config.load_config`). Always closes an
    adapter it constructed itself. Results from the constructed-adapter path
    are TTL-cached; an injected adapter bypasses the cache (tests own it).
    """
    direction = "in" if direction == "in" else "out"
    chain_str = getattr(chain, "value", str(chain))
    # Build a spot-price callable on the constructed path if requested.
    if price_fn is None and with_pricing and adapter is None:
        price_fn = _build_price_fn()
    priced = price_fn is not None
    cache_key = (chain_str, str(address).lower(), direction, int(max_counterparties), priced)
    if adapter is None and use_cache:
        cached = _cache_get(cache_key, now=_clock())
        if cached is not None:
            return cached

    own_adapter = False
    if adapter is None:
        if config is None:
            from recupero.config import load_config
            config, _env = load_config()
        from recupero.chains.base import ChainAdapter as _CA
        adapter = _CA.for_chain(chain, config)
        own_adapter = True
    try:
        out_dir = direction != "in"
        if out_dir:
            rows = list(adapter.fetch_native_outflows(address, start_block))
            rows += list(adapter.fetch_erc20_outflows(address, start_block))
        else:
            rows = list(adapter.fetch_native_inflows(address, start_block))
            rows += list(adapter.fetch_erc20_inflows(address, start_block))
    finally:
        if own_adapter:
            try:
                adapter.close()
            except Exception:  # noqa: BLE001
                pass

    data = aggregate_expansion(
        rows, root_address=address, direction=direction,
        chain=chain_str, max_counterparties=max_counterparties,
        price_fn=price_fn,
    )
    if own_adapter and use_cache:
        _cache_put(cache_key, data, now=_clock())
    return data


__all__ = ("aggregate_expansion", "expand_address")
