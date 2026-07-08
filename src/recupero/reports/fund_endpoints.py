"""Fund-endpoint rollup — "where the money is sitting now" (v0.42).

The operator question this answers: *pull up a case and see, at a glance, WHERE
the stolen funds ended up, HOW MUCH is still reachable vs. gone, and whether any
of it has MOVED since we last looked.*

Everything here is derived from a case's already-computed ``freeze_brief.json``
(the same artifact the LE handoff + freeze letters are built from) — this module
runs NO trace, makes NO network call, and infers NOTHING new. It re-shapes the
brief's per-address holdings into a flat list of terminal ENDPOINTS, each
classified by recoverability (the brief's own status vocabulary), plus a
portfolio rollup for the recoverability donut. An optional watchlist index
annotates each endpoint with its movement verdict (moved / still-present /
never-checked) — again, only what a real balance snapshot recorded.

``build_fund_endpoints`` is a PURE function over already-parsed dicts (trivially
unit-testable). The API layer (``api.fund_endpoints_api``) does the I/O: read the
brief, read the watchlist, call this, serialize.

Status vocabulary (mirrors ``emit_brief._classify_address_status`` + the watcher
UI so this reads identically to the LE handoff):

  FREEZABLE     — at a freezable issuer/venue; act now
  TRACKED       — identified, non-freezable today, still holds value; monitor
  INVESTIGATE   — labeled but unconfirmed; needs reviewer judgment
  EXCHANGE      — CEX deposit; recovery via subpoena/MLAT, not issuer freeze
  UNRECOVERABLE — mixer / burned / bridged-out / non-freezable-issuer; gone
"""

from __future__ import annotations

import re
from typing import Any

from recupero._common import canonical_address_key as _ck
from recupero._common import short_addr as _short_addr

# Recoverability buckets, in display order. "reachable" = still actionable
# (freeze / monitor / subpoena); UNRECOVERABLE is the only "gone" bucket.
_STATUS_ORDER = ("FREEZABLE", "TRACKED", "INVESTIGATE", "EXCHANGE", "UNRECOVERABLE")
_REACHABLE = frozenset({"FREEZABLE", "TRACKED", "INVESTIGATE", "EXCHANGE"})

# Block-explorer address URL by chain (mirrors watchlist_dashboard._EXPLORER_BASE
# so the endpoint cards link the same place the watcher does).
_EXPLORER_BASE = {
    "ethereum": "https://etherscan.io/address/",
    "arbitrum": "https://arbiscan.io/address/",
    "base": "https://basescan.org/address/",
    "optimism": "https://optimistic.etherscan.io/address/",
    "polygon": "https://polygonscan.com/address/",
    "bsc": "https://bscscan.com/address/",
    "avalanche": "https://snowtrace.io/address/",
    "solana": "https://solscan.io/account/",
    "tron": "https://tronscan.org/#/address/",
    "bitcoin": "https://mempool.space/address/",
    "ton": "https://tonviewer.com/",
    "stellar": "https://stellar.expert/explorer/public/account/",
    "sui": "https://suivision.xyz/account/",
    "aptos": "https://explorer.aptoslabs.com/account/",
}

_USD_RE = re.compile(r"\$\s*([\d,]+(?:\.\d+)?)")


def _usd_to_float(value: Any) -> float:
    """Best-effort USD magnitude from a formatted string / number.

    Handles ``"$1,066.27"``, ``"3.2 ETH (~$6,780)"``, ``1066.27``, ``None``.
    Returns 0.0 when no dollar figure can be recovered (never raises)."""
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value) if value == value else 0.0  # reject NaN
    s = str(value)
    m = _USD_RE.search(s)
    if m:
        try:
            return float(m.group(1).replace(",", ""))
        except ValueError:
            return 0.0
    # No "$" — try a bare number (e.g. a raw usd_value that slipped through).
    try:
        return float(s.replace(",", "").strip())
    except ValueError:
        return 0.0


def _explorer_url(chain: str | None, address: str | None) -> str | None:
    if not address:
        return None
    base = _EXPLORER_BASE.get((chain or "ethereum").strip().lower())
    return (base + address) if base else None


def _normalize_status(raw: Any) -> str:
    s = str(raw or "").strip().upper()
    return s if s in _STATUS_ORDER else ("UNKNOWN" if s else "UNKNOWN")


def _annotate_movement(
    endpoint: dict[str, Any],
    watchlist_index: dict[str, dict[str, Any]] | None,
) -> None:
    """Attach the watchlist movement verdict to an endpoint, in place.

    ``watchlist_index`` is keyed by canonical address. Absent / unwatched →
    ``never_checked`` (the honest default — we haven't looked)."""
    addr = endpoint.get("address")
    row = None
    if watchlist_index and addr:
        row = watchlist_index.get(_ck(addr))
    if not row:
        endpoint["movement"] = "never_checked"
        endpoint["last_delta_usd"] = None
        endpoint["last_checked_at"] = None
        return
    endpoint["movement"] = row.get("movement") or "never_checked"
    endpoint["last_delta_usd"] = row.get("last_delta_usd")
    endpoint["last_checked_at"] = row.get("last_checked_at")


def build_fund_endpoints(
    brief: dict[str, Any] | None,
    watchlist_index: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """PURE: a parsed ``freeze_brief.json`` → the fund-endpoint view model.

    Returns a JSON-serializable dict::

        {
          "total_loss_usd": "$3,500,000",          # brief's authoritative headline
          "max_recoverable_usd": "$1,066.27",
          "recoverable_percent": "0.03%",
          "total_freezable_usd": "$1,066.27",
          "total_unrecoverable_usd": "$850,000",
          "endpoints": [ {address, chain, issuer, token, amount, usd,
                          usd_numeric, status, evidence_type, observed_at,
                          explorer_url, short, movement, last_delta_usd,
                          last_checked_at, reason?}, ... ],
          "rollup": [ {status, usd, count}, ... ],   # donut segments, display order
          "reachable_usd_numeric": float,
          "gone_usd_numeric": float,
          "n_endpoints": int,
          "n_moved": int,
          "moved_usd_numeric": float,
          "note": str | None,                        # set only when brief is empty
        }

    ``watchlist_index`` (optional): ``{canonical_address: {movement,
    last_delta_usd, last_checked_at}}`` — best-effort movement annotation.
    """
    brief = brief or {}
    endpoints: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    def _key(addr: str | None, token: str | None) -> str:
        return f"{_ck(addr) if addr else ''}|{(token or '').lower()}"

    # 1) Primary source: ALL_ISSUER_HOLDINGS — the comprehensive per-address
    #    holdings list (includes UNRECOVERABLE-only issuers). Each holding
    #    already carries its recoverability `status`. This is the real "where a
    #    wallet is holding value now" feed. Falls back to FREEZABLE (letter list)
    #    when the comprehensive key is absent (older briefs).
    issuer_groups = brief.get("ALL_ISSUER_HOLDINGS")
    if not isinstance(issuer_groups, list) or not issuer_groups:
        issuer_groups = brief.get("FREEZABLE") or []
    for grp in issuer_groups:
        if not isinstance(grp, dict):
            continue
        issuer = grp.get("issuer") or grp.get("issuer_name")
        symbol = grp.get("symbol")
        for h in grp.get("holdings") or []:
            if not isinstance(h, dict):
                continue
            addr = h.get("address")
            token = symbol
            k = _key(addr, token)
            if k in seen_keys:
                continue
            seen_keys.add(k)
            chain = h.get("chain")
            ep = {
                "address": addr,
                "short": _short_addr(addr) if addr else None,
                "chain": chain,
                "issuer": issuer,
                "token": token,
                "amount": h.get("amount"),
                "usd": h.get("usd"),
                "usd_numeric": _usd_to_float(h.get("usd")),
                "status": _normalize_status(h.get("status")),
                "evidence_type": h.get("evidence_type"),
                "observed_at": h.get("observed_at"),
                "explorer_url": _explorer_url(chain, addr),
                "reason": None,
            }
            _annotate_movement(ep, watchlist_index)
            endpoints.append(ep)

    # 2) EXCHANGES (Path B) — CEX deposit addresses. Distinct from issuer
    #    holdings; recovery is subpoena/MLAT, not an issuer freeze.
    for grp in brief.get("EXCHANGES") or []:
        if not isinstance(grp, dict):
            continue
        exch = grp.get("exchange")
        for d in grp.get("deposits") or []:
            if not isinstance(d, dict):
                continue
            addr = d.get("address")
            k = _key(addr, exch)
            if k in seen_keys:
                continue
            seen_keys.add(k)
            chain = d.get("chain") or "ethereum"
            ep = {
                "address": addr,
                "short": _short_addr(addr) if addr else None,
                "chain": chain,
                "issuer": exch,
                "token": None,
                "amount": d.get("amount"),
                "usd": d.get("usd"),
                "usd_numeric": _usd_to_float(d.get("usd")),
                "status": "EXCHANGE",
                "evidence_type": "exchange_deposit",
                "observed_at": d.get("date") or None,
                "explorer_url": _explorer_url(chain, addr),
                "reason": None,
            }
            _annotate_movement(ep, watchlist_index)
            endpoints.append(ep)

    # 3) Editorial UNRECOVERABLE_ITEMS — off-issuer write-offs (mixer / burn /
    #    bridge-out) that have NO per-issuer holding row. Items that DO carry a
    #    (issuer,address) already represented above are skipped (the brief's own
    #    de-dup rule) so value isn't double-counted.
    for item in brief.get("UNRECOVERABLE") or []:
        if not isinstance(item, dict):
            continue
        addr = (item.get("address") or "").strip() or None
        if addr and _ck(addr) in {_ck(e["address"]) for e in endpoints if e.get("address")}:
            continue
        asset = item.get("asset")
        ep = {
            "address": addr,
            "short": _short_addr(addr) if addr else None,
            "chain": item.get("chain"),
            "issuer": (item.get("issuer") or "").strip() or None,
            "token": None,
            "amount": asset,
            "usd": asset,
            "usd_numeric": _usd_to_float(asset),
            "status": "UNRECOVERABLE",
            "evidence_type": "editorial_writeoff",
            "observed_at": None,
            "explorer_url": _explorer_url(item.get("chain"), addr),
            "reason": item.get("reason"),
        }
        _annotate_movement(ep, watchlist_index)
        endpoints.append(ep)

    # --- Rollup (donut segments) + reachable/gone split -------------------
    by_status: dict[str, dict[str, Any]] = {}
    for ep in endpoints:
        st = ep["status"]
        slot = by_status.setdefault(st, {"status": st, "usd": 0.0, "count": 0})
        slot["usd"] += ep["usd_numeric"]
        slot["count"] += 1
    rollup = [by_status[s] for s in _STATUS_ORDER if s in by_status]
    # Any non-canonical status (e.g. UNKNOWN) appended after the known order.
    rollup += [v for k, v in by_status.items() if k not in _STATUS_ORDER]

    reachable = sum(v["usd"] for k, v in by_status.items() if k in _REACHABLE)
    gone = sum(v["usd"] for k, v in by_status.items() if k not in _REACHABLE)

    moved = [e for e in endpoints if e.get("movement") == "moved"]

    result: dict[str, Any] = {
        # Authoritative headline figures — passed through from the brief verbatim
        # (never recomputed here, so this view can't contradict the LE handoff).
        "total_loss_usd": brief.get("TOTAL_LOSS_USD"),
        "max_recoverable_usd": brief.get("MAX_RECOVERABLE_USD"),
        "recoverable_percent": brief.get("RECOVERABLE_PERCENT"),
        "total_freezable_usd": brief.get("TOTAL_FREEZABLE_USD"),
        "total_unrecoverable_usd": brief.get("TOTAL_UNRECOVERABLE_USD"),
        "endpoints": endpoints,
        "rollup": rollup,
        "reachable_usd_numeric": round(reachable, 2),
        "gone_usd_numeric": round(gone, 2),
        "n_endpoints": len(endpoints),
        "n_moved": len(moved),
        "moved_usd_numeric": round(sum(e["usd_numeric"] for e in moved), 2),
        "note": None,
    }
    if not endpoints:
        result["note"] = (
            "No terminal fund endpoints in this case's freeze brief. Either the "
            "trace produced no classified holdings yet, or the brief predates the "
            "per-address holdings format. Re-run the trace / regenerate the brief."
        )
    return result


__all__ = ("build_fund_endpoints",)
