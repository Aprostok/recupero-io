"""Tests for contract-detection cache fix (v0.32.1 trace gap G).

The bug this module fixes: RPC failure was assumed to mean "is
contract" → cached True permanently → entire BFS branches lost.
The fix: RPC failure returns (None, ...) and does NOT touch cache.
"""

from __future__ import annotations

from typing import Any

from recupero.trace.contract_detection import is_contract


class _Adapter:
    """Fake EVM adapter with controllable get_code behavior."""

    def __init__(
        self,
        responses: list[Any] | None = None,
        always_raise: Exception | None = None,
    ) -> None:
        self._responses = list(responses) if responses else []
        self._always_raise = always_raise
        self.call_count = 0

    def get_code(self, address: str) -> Any:
        self.call_count += 1
        if self._always_raise is not None:
            raise self._always_raise
        if not self._responses:
            raise RuntimeError("Adapter has no more canned responses")
        resp = self._responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return resp


# ---- Verified-contract case ---- #


def test_contract_with_bytecode_returns_true_and_caches() -> None:
    cache: dict[str, bool] = {}
    adapter = _Adapter(responses=["0x6080604052348015..."])
    result, reason = is_contract(
        "0xabCDef1234567890ABcDef1234567890aBcdEF12",
        "ethereum",
        adapter,
        cache,
    )
    assert result is True
    assert reason == "verified-contract"
    # Cache was populated.
    assert cache["ethereum:0xabcdef1234567890abcdef1234567890abcdef12"] is True
    assert adapter.call_count == 1


# ---- Verified-EOA case ---- #


def test_eoa_empty_code_returns_false() -> None:
    cache: dict[str, bool] = {}
    adapter = _Adapter(responses=["0x"])
    result, reason = is_contract(
        "0xeoaeoaeoaeoaeoaeoaeoaeoaeoaeoaeoaeoaeoaee",
        "ethereum",
        adapter,
        cache,
    )
    assert result is False
    assert reason == "verified-eoa"
    assert cache["ethereum:0xeoaeoaeoaeoaeoaeoaeoaeoaeoaeoaeoaeoaeoaee"] is False


# ---- The cache-poisoning fix ---- #


def test_double_rpc_failure_returns_none_and_does_not_cache() -> None:
    """The audited bug — must return None, leave cache untouched."""
    cache: dict[str, bool] = {}
    adapter = _Adapter(always_raise=ConnectionError("RPC timeout"))
    result, reason = is_contract(
        "0xfailfailfailfailfailfailfailfailfailfail",
        "ethereum",
        adapter,
        cache,
    )
    assert result is None
    assert reason == "rpc-failure-do-not-cache"
    # The critical assertion: cache MUST NOT have been touched.
    assert "ethereum:0xfailfailfailfailfailfailfailfailfailfail" not in cache
    # Retry policy: 2 attempts total.
    assert adapter.call_count == 2


def test_transient_failure_then_success_caches() -> None:
    """One failure then success → returns True, caches, no None leak."""
    cache: dict[str, bool] = {}
    adapter = _Adapter(
        responses=[
            ConnectionError("transient"),
            "0x6080604052",  # bytecode on retry
        ]
    )
    result, reason = is_contract(
        "0xtransienttransienttransienttransienttran",
        "ethereum",
        adapter,
        cache,
    )
    assert result is True
    assert reason == "verified-contract"
    # Cached (True) for next time.
    assert cache["ethereum:0xtransienttransienttransienttransienttran"] is True
    assert adapter.call_count == 2


# ---- Cache hit ---- #


def test_cache_hit_short_circuits() -> None:
    """Cache hit → no RPC call."""
    addr = "0xcachedcachedcachedcachedcachedcachedcach"
    chain = "ethereum"
    cache: dict[str, bool] = {f"{chain}:{addr.lower()}": True}
    adapter = _Adapter(responses=[])  # would raise if called
    result, reason = is_contract(addr, chain, adapter, cache)
    assert result is True
    assert reason == "cached-contract"
    assert adapter.call_count == 0


def test_cache_hit_false() -> None:
    addr = "0xcachedeoa00000000000000000000000000000000"
    chain = "ethereum"
    cache: dict[str, bool] = {f"{chain}:{addr.lower()}": False}
    adapter = _Adapter(responses=[])
    result, reason = is_contract(addr, chain, adapter, cache)
    assert result is False
    assert reason == "cached-eoa"
    assert adapter.call_count == 0


# ---- Defensive ---- #


def test_invalid_input_returns_none() -> None:
    cache: dict[str, bool] = {}
    adapter = _Adapter(responses=[])
    assert is_contract(None, "ethereum", adapter, cache) == (None, "invalid-input")
    assert is_contract("0xabc", None, adapter, cache) == (None, "invalid-input")
    assert is_contract("", "ethereum", adapter, cache) == (None, "invalid-input")


def test_none_adapter_returns_none_no_cache() -> None:
    """No adapter → can't resolve, return None, don't cache."""
    cache: dict[str, bool] = {}
    result, reason = is_contract(
        "0xnoadapter0000000000000000000000000000000",
        "ethereum",
        None,
        cache,
    )
    assert result is None
    assert reason == "rpc-failure-do-not-cache"
    assert cache == {}
