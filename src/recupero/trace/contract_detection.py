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

# TODO(wave-4-integration): wire `is_contract` into trace.tracer
# replacing the inline `try: get_code... except: assume contract`
# block. Add a "uncertain-hop" annotation on the brief when None
# returns propagate.
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
        if s in ("", "0x", "0x0", "0x00"):
            return True
        return False
    return False


def _call_get_code(evm_adapter: Any, address: str) -> Any:
    """Invoke adapter.get_code(address). Raises whatever the adapter raises."""
    get_code = getattr(evm_adapter, "get_code", None)
    if not callable(get_code):
        raise AttributeError("evm_adapter has no get_code()")
    return get_code(address)


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
        code = _call_get_code(evm_adapter, addr)
    except Exception as exc:
        log.debug("is_contract: first attempt failed for %s: %s", addr, exc)
        # Retry once
        try:
            code = _call_get_code(evm_adapter, addr)
        except Exception as exc2:
            log.info(
                "is_contract: %s on %s — RPC failed twice (%s, %s). "
                "NOT caching; caller should treat as uncertain.",
                addr,
                chain,
                type(exc).__name__,
                type(exc2).__name__,
            )
            return (None, "rpc-failure-do-not-cache")

    # Success: cache and return.
    is_eoa = _is_eoa_code(code)
    result = not is_eoa
    if isinstance(cache, dict):
        cache[key] = result
    return (result, "verified-contract" if result else "verified-eoa")
