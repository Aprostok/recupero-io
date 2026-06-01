"""Contract-detection cache (v0.32.1 trace gap G).

The BFS frontier expander has to decide, per hop, whether the
destination is a contract (don't expand — recovery isn't applicable
to contract balances) or an EOA / smart account (do expand).

The original tracer.py had a subtle cache poisoning bug: on RPC
failure (timeout, rate-limit), `get_code()` raises, the caller
catches and **assumes True (is a contract)** to be conservative,
caches True forever, and the trace forever skips that address —
even when the failure was transient.

This module fixes it. Three states:
  - (True, "verified-contract")  — bytecode confirmed
  - (False, "verified-eoa")      — empty bytecode confirmed
  - (None, "rpc-failure-do-not-cache")
                                  — RPC error after retry; DO NOT
                                  cache; let the BFS make a per-hop
                                  decision (typically: expand once,
                                  log, mark hop as uncertain).

Retry policy: one immediate retry on `Exception` (transient
network errors); if still failing, return None and leave cache
untouched.

Wired into ``trace.tracer`` (v0.32.1 W8): the BFS frontier expander
calls this instead of the inline ``try: adapter.is_contract ... except:
assume contract`` block, so a transient probe failure no longer
poisons the cache for the worker's lifetime. On a twice-failed probe
the tracer expands the hop once (conservative-but-not-permanent) and
leaves the cache untouched for a later pass to re-resolve.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


# Cache key shape: f"{chain}:{lowercased_address}"
# Cache value: bool (only verified results — never None).


def _cache_key(address: str, chain: str) -> str:
    return f"{chain.strip().lower()}:{address.strip().lower()}"


def _is_eoa_code(code: Any) -> bool:
    """Determine whether the returned bytecode is the "empty" form.

    EVM RPC returns "0x" or b"" for EOAs; some providers return
    "0x0" or None. We treat all empty-ish outputs as EOA.
    """
    if code is None:
        return True
    if isinstance(code, bytes):
        return len(code) == 0
    if isinstance(code, str):
        s = code.strip().lower()
        return s in ("", "0x", "0x0", "0x00")
    return False


def _probe_is_contract(evm_adapter: Any, address: str) -> bool:
    """Best-effort single probe: is ``address`` a contract?

    Resolution order, matching the adapter interface actually in use:

      1. ``adapter.get_code(address)`` if exposed — byte-code based EOA
         check (most precise; resistant to label-DB staleness). No
         current adapter implements this, but the path is kept so a
         future raw-RPC adapter gets the better signal for free.
      2. ``adapter.is_contract(address)`` — the canonical
         ``ChainAdapter`` interface (base.py:83). Every shipped adapter
         (evm/bitcoin/solana/tron/cosmos) implements this; it returns a
         bool directly.

    Raises whatever the adapter raises (so the caller's retry +
    don't-cache-on-failure policy can fire), or ``AttributeError`` if
    the adapter exposes neither method.
    """
    get_code = getattr(evm_adapter, "get_code", None)
    if callable(get_code):
        return not _is_eoa_code(get_code(address))
    is_contract_fn = getattr(evm_adapter, "is_contract", None)
    if callable(is_contract_fn):
        return bool(is_contract_fn(address))
    raise AttributeError("adapter exposes neither get_code() nor is_contract()")


def is_contract(
    address: str | None,
    chain: str | None,
    evm_adapter: Any,
    cache: dict[str, bool] | None,
) -> tuple[bool | None, str]:
    """Best-effort: is `address` on `chain` a contract?

    Returns:
        (True,  "verified-contract")    — has bytecode
        (True,  "cached-contract")      — cache hit
        (False, "verified-eoa")         — empty bytecode
        (False, "cached-eoa")           — cache hit
        (None,  "rpc-failure-do-not-cache")
                                        — RPC errored twice; cache untouched
        (None,  "invalid-input")        — garbage args; cache untouched

    The retry is intentional: a single transient RPC failure is the
    most common cause of bad cache state in production. One retry
    catches that without expanding the blast radius if the upstream
    is fully down.
    """
    if not isinstance(address, str) or not isinstance(chain, str):
        return (None, "invalid-input")
    addr = address.strip()
    if not addr:
        return (None, "invalid-input")

    key = _cache_key(addr, chain)

    # Cache lookup (only ever holds True / False — never None).
    if isinstance(cache, dict) and key in cache:
        cached = cache[key]
        if cached is True:
            return (True, "cached-contract")
        if cached is False:
            return (False, "cached-eoa")
        # If someone managed to insert None despite our policy, treat
        # it as cache miss and re-resolve.

    if evm_adapter is None:
        return (None, "rpc-failure-do-not-cache")

    # First attempt
    try:
        result = _probe_is_contract(evm_adapter, addr)
    except Exception as exc:
        log.debug("is_contract: first attempt failed for %s: %s", addr, exc)
        # Retry once
        try:
            result = _probe_is_contract(evm_adapter, addr)
        except Exception as exc2:
            log.info(
                "is_contract: %s on %s — probe failed twice (%s, %s). "
                "NOT caching; caller should treat as uncertain.",
                addr,
                chain,
                type(exc).__name__,
                type(exc2).__name__,
            )
            return (None, "rpc-failure-do-not-cache")

    # Success: cache and return.
    if isinstance(cache, dict):
        cache[key] = result
    return (result, "verified-contract" if result else "verified-eoa")
