"""Pre-pricing poison-edge pruning (v0.34, operator-requested "elite recall").

Why this exists
---------------

The per-address fetch cap (``RECUPERO_MAX_TRANSFERS_PER_ADDRESS``) was a blunt
defense against address-poisoning / spam flooding a chatty address's outflow
list: it sliced the list to the first N rows and threw the rest away. On a
poison-heavy address (8-9k+ outflows) that can silently drop the ONE real
onward hop the trace needs — trading a poisoning denial-of-service for a
false negative, which is the single worst outcome for a forensic tracer.

This module removes that trade-off so the tracer can run **UNCAPPED** and still
stay tractable. It drops edges that are **unambiguously poison BEFORE they are
priced and followed**, while *never* dropping an edge that could carry real
value.

Why it also fixes the "freeze"
------------------------------

Pricing resolves each ERC-20 by a CoinGecko ``/coins/{platform}/contract/{addr}``
lookup on cache-miss. Poison campaigns mint thousands of throwaway scam-token
contracts, so an uncapped trace previously paid one contract-resolution call per
distinct poison token — the historical multi-hour stall. Zero-value poison
transfers are dropped here before that call is ever made.

Airtight signals only
---------------------

A forensic tracer must never drop a real fund movement, so v1 prunes on ONE
unconditionally-safe signal:

  * **Zero-value transfers** (``amount_raw == 0``). A transfer that moves no
    tokens cannot be part of a laundering path. Zero-value ERC-20 ``Transfer``
    events are the canonical address-poisoning primitive — a malicious contract
    can emit them without owning anything, purely to plant a look-alike address
    in the victim's history. Dropping them is safe unconditionally.

Anything value-bearing is ALWAYS kept and followed. An UNPARSEABLE amount is
kept (we never treat "I couldn't read it" as "it's zero"). Because this is
noise removal — it never drops real funds — it does NOT reduce coverage
(unlike the fetch cap, which can hide a real hop and therefore flips
``coverage.complete`` to False).
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any


def amount_is_zero(raw: dict[str, Any]) -> bool:
    """True ONLY when the outflow's raw amount parses to *exactly* zero.

    Conservative by construction: ``None`` / blank / unparseable amounts return
    ``False`` (kept), so a malformed or novel encoding is never mistaken for
    poison. Handles ``int``, decimal strings, and ``0x``-hex strings. ``bool``
    (an ``int`` subclass) is treated as non-amount and kept.
    """
    if not isinstance(raw, dict):
        return False
    amt = raw.get("amount_raw")
    if amt is None or isinstance(amt, bool):
        return False
    if isinstance(amt, int):
        return amt == 0
    if isinstance(amt, Decimal):
        return amt.is_finite() and amt == 0
    if isinstance(amt, str):
        s = amt.strip()
        if not s:
            return False  # blank -> unknown, keep
        try:
            if s.lower().startswith("0x"):
                return int(s, 16) == 0
            return int(s) == 0
        except ValueError:
            try:
                d = Decimal(s)
            except (InvalidOperation, ValueError):
                return False
            return d.is_finite() and d == 0
    return False


def prune_poison_outflows(
    raw_outflows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split raw outflows into ``(kept, pruned)``.

    ``pruned`` holds the unambiguous-poison rows (v1: zero-value transfers),
    each reduced to a small audit dict (``to`` / ``tx_hash`` / ``kind``). The
    relative order of ``kept`` is preserved. NEVER drops a value-bearing
    transfer.
    """
    kept: list[dict[str, Any]] = []
    pruned: list[dict[str, Any]] = []
    for raw in raw_outflows:
        if amount_is_zero(raw):
            pruned.append({
                "to": raw.get("to") if isinstance(raw, dict) else None,
                "tx_hash": raw.get("tx_hash") if isinstance(raw, dict) else None,
                "kind": "zero_value_poison",
            })
            continue
        kept.append(raw)
    return kept, pruned
