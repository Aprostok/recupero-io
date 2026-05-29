"""Bitcoin co-spending input-set registry (v0.32.1, CRIT-1).

Background
----------

Bitcoin transactions can have N input addresses (the common-input
heuristic: all inputs to one tx are presumed controlled by the same
wallet). The tracer's data model is account-style — a Transfer has
ONE ``from_address`` — so the adapter has to project the N inputs
down to one Transfer. Pre-v0.32.1 we used ``first_input_addr`` only,
which silently dropped the OTHER N-1 input addresses from the trace's
view. Downstream the H1 (co-spending) clustering heuristic — the
single most reliable clustering signal in all of blockchain forensics
— almost never fired because the multi-input set was no longer visible
anywhere in the case.

This module is the workaround. The Bitcoin adapter records the full
input-address set for every tx it normalizes; ``clustering.py`` reads
it back when building H1 edges. We pass through a module-level
registry rather than a Transfer.metadata field because the
``Transfer`` Pydantic model is ``extra="forbid"`` and the tracer
constructs Transfers from a tight whitelist (changing that touches
``tracer.py``, which is owned by another agent for v0.32.1).

Thread-safety
-------------

The tracer is single-threaded per-case (the adapter fetch loop is
serial). Multiple cases running in parallel processes do not share
this registry by construction. Within a single case, multiple BFS
hops touching the SAME tx_hash converge on the SAME input-set —
``register`` does an idempotent union under a single GIL-protected
dict mutation.

Lifecycle
---------

The registry has process-lifetime scope by default. The tracer's
``trace_case`` entrypoint should call ``clear_for_case`` at start so
two sequential cases in one process don't bleed each other's BTC
inputs together. For v0.32.1 the entrypoint is not in scope (tracer.py
is locked); the registry is bounded in practice because the same tx
hash can only contribute one set, and a typical case sees ≤ 10k txs.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable

# Map of tx_hash → frozenset of canonical-form input addresses.
_BTC_INPUTS_BY_TX: dict[str, frozenset[str]] = {}
_LOCK = threading.Lock()


def register(tx_hash: str, input_addresses: Iterable[str]) -> None:
    """Record the full input-address set for a Bitcoin tx.

    Idempotent: repeated registrations for the same tx_hash union
    in any newly-observed addresses (defensive against an Esplora
    response that omits some prevouts on one pass and includes them
    on another).
    """
    if not isinstance(tx_hash, str) or not tx_hash:
        return
    addrs = {a for a in input_addresses if isinstance(a, str) and a}
    if not addrs:
        return
    with _LOCK:
        existing = _BTC_INPUTS_BY_TX.get(tx_hash)
        if existing is None:
            _BTC_INPUTS_BY_TX[tx_hash] = frozenset(addrs)
        else:
            merged = set(existing) | addrs
            if len(merged) != len(existing):
                _BTC_INPUTS_BY_TX[tx_hash] = frozenset(merged)


def lookup(tx_hash: str) -> frozenset[str]:
    """Return the full input-address set for a Bitcoin tx, or empty
    frozenset if no inputs were registered (e.g., the tx was never
    visited by this case's BFS).
    """
    if not isinstance(tx_hash, str) or not tx_hash:
        return frozenset()
    with _LOCK:
        return _BTC_INPUTS_BY_TX.get(tx_hash, frozenset())


def clear_for_case() -> None:
    """Reset the registry. Safe to call between cases.

    Currently called only by tests; the production tracer is owned
    by another agent for v0.32.1 and the registry's bounded growth
    (one entry per BTC tx in a case) is acceptable for the ship.
    """
    with _LOCK:
        _BTC_INPUTS_BY_TX.clear()


def size() -> int:
    """Number of distinct tx_hashes currently registered. For tests
    and observability."""
    with _LOCK:
        return len(_BTC_INPUTS_BY_TX)


__all__ = (
    "register",
    "lookup",
    "clear_for_case",
    "size",
)
