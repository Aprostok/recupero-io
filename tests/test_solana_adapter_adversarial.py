"""RIGOR-Jacob G adversarial: Solana adapter defenses against
malformed Helius responses.

Helius is an external API that supplies every Solana transfer record
the tracer consumes. A compromised response (or a Helius-side bug)
can land:

  * ``amount: "Infinity"`` in the ERC-20 path. The current code does
    ``int(float("Infinity") * 10**decimals)`` which raises
    ``OverflowError`` UNCAUGHT — the entire BFS hop dies mid-trace.
  * ``decimals: 1000``. Same overflow path.
  * ``timestamp: 9_999_999_999_999`` (year 318367). The current code
    does ``datetime.fromtimestamp(99_999_999_999_999)`` which raises
    ``OverflowError`` UNCAUGHT — crashes the same way.

Lock the contract: each shape is silently skipped (transfer dropped
+ log entry), NOT propagated as an uncaught exception that aborts
the entire wave.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock


def _build_adapter():
    """Bypass __init__ — construct an adapter shell sufficient for
    the normalization tests."""
    from recupero.chains.solana.adapter import SolanaAdapter

    adapter = SolanaAdapter.__new__(SolanaAdapter)
    adapter.client = MagicMock()
    adapter.client.BASE = "https://fake-helius"
    return adapter


def test_erc20_amount_infinity_does_not_crash() -> None:
    """A Helius response with ``tokenAmount: 'Infinity'`` MUST NOT
    crash the BFS — the transfer should be silently dropped."""
    from recupero.chains.solana.adapter import SolanaAdapter

    adapter = _build_adapter()

    # Bypass the _fetch_all → just feed the txs directly.
    raw_txs = [
        {
            "timestamp": 1700000000,
            "signature": "abc",
            "slot": 1,
            "tokenTransfers": [
                {
                    "fromUserAccount": "test-addr",
                    "tokenAmount": "Infinity",  # ← attacker / bug
                    "mint": "FakeMint11111111111111111111111111111111111",
                    "rawTokenAmount": {
                        "tokenAmount": "not-an-int",
                        "decimals": "9",
                    },
                },
            ],
        },
    ]
    adapter._fetch_all = lambda *args, **kw: raw_txs  # type: ignore

    # The function should return (possibly empty) list, NOT raise.
    try:
        from recupero.chains.solana.normalize import (
            normalize_solana_address as _norm,
        )
        # Use the actual address normalizer to bypass it cleanly
        addr = _norm("test-addr") if hasattr(_norm, "__call__") else "test-addr"
    except Exception:
        addr = "test-addr"

    # Force the address comparison to match by stubbing the
    # normalizer to return what the fixture uses.
    import recupero.chains.solana.adapter as solana_mod
    original_norm = solana_mod.normalize_solana_address
    solana_mod.normalize_solana_address = lambda x: x
    try:
        result = SolanaAdapter.fetch_erc20_outflows(
            adapter, "test-addr", 0, max_results=None,
        )
    finally:
        solana_mod.normalize_solana_address = original_norm

    assert isinstance(result, list), (
        f"Helius Infinity tokenAmount crashed the BFS — got "
        f"{type(result).__name__}"
    )


def test_erc20_decimals_extreme_does_not_crash() -> None:
    """``decimals: 1000`` causes ``10**1000`` → huge int → float
    overflow on multiply. Pre-fix this raises OverflowError uncaught."""
    from recupero.chains.solana.adapter import SolanaAdapter

    adapter = _build_adapter()
    raw_txs = [
        {
            "timestamp": 1700000000,
            "signature": "abc",
            "slot": 1,
            "tokenTransfers": [
                {
                    "fromUserAccount": "test-addr",
                    "tokenAmount": "not-int",  # forces fallback path
                    "mint": "FakeMint11111111111111111111111111111111111",
                    "rawTokenAmount": {
                        "tokenAmount": "0.5",  # decimal forces fallback
                        "decimals": 1000,  # ← extreme exponent
                    },
                },
            ],
        },
    ]
    adapter._fetch_all = lambda *args, **kw: raw_txs  # type: ignore

    import recupero.chains.solana.adapter as solana_mod
    original_norm = solana_mod.normalize_solana_address
    solana_mod.normalize_solana_address = lambda x: x
    try:
        result = SolanaAdapter.fetch_erc20_outflows(
            adapter, "test-addr", 0, max_results=None,
        )
    finally:
        solana_mod.normalize_solana_address = original_norm

    assert isinstance(result, list)


def test_native_extreme_timestamp_does_not_crash_normalize() -> None:
    """``timestamp: 99_999_999_999_999`` is year 318367 — extreme
    enough that ``datetime.fromtimestamp`` raises OverflowError. The
    Solana adapter's _normalize_native passes the value through
    blindly. Pre-fix this crashes the BFS hop."""
    from recupero.chains.solana.adapter import SolanaAdapter

    adapter = _build_adapter()
    # Test the _normalize_native shape directly
    bad_tx = {
        "signature": "abc",
        "slot": 1,
        "timestamp": 99_999_999_999_999,  # year 318367
    }
    bad_nt = {
        "fromUserAccount": "test-addr",
        "toUserAccount": "to-addr",
        "amount": 1000,
    }
    try:
        result = SolanaAdapter._normalize_native(adapter, bad_tx, bad_nt, 1000)
        # Either succeeds with a sane block_time, or returns a
        # sentinel that the caller drops. Crashes are unacceptable.
        block_time = result.get("block_time")
        if isinstance(block_time, datetime):
            assert block_time.year < 9999, (
                f"Extreme timestamp produced year {block_time.year} — "
                f"will explode downstream renderers"
            )
    except (OverflowError, OSError, ValueError) as e:
        # Acceptable for the adapter to RAISE a documented exception,
        # but it MUST NOT be unhandled at higher levels. The current
        # caller (fetch_native_outflows loop) doesn't catch — fail
        # this test to force a contract change.
        raise AssertionError(
            f"_normalize_native raised {type(e).__name__} on extreme "
            f"timestamp: {e}. Adapter must clamp/skip instead."
        ) from e


def test_native_negative_timestamp_does_not_crash() -> None:
    """``timestamp: -99_999_999_999`` (pre-1970 by a lot). Windows
    raises OSError, Linux raises ValueError on fromtimestamp."""
    from recupero.chains.solana.adapter import SolanaAdapter

    adapter = _build_adapter()
    bad_tx = {
        "signature": "abc",
        "slot": 1,
        "timestamp": -99_999_999_999,
    }
    bad_nt = {
        "fromUserAccount": "test-addr",
        "toUserAccount": "to-addr",
        "amount": 1000,
    }
    try:
        result = SolanaAdapter._normalize_native(adapter, bad_tx, bad_nt, 1000)
        block_time = result.get("block_time")
        if isinstance(block_time, datetime):
            assert block_time.year >= 1970
    except (OverflowError, OSError, ValueError) as e:
        raise AssertionError(
            f"_normalize_native raised {type(e).__name__} on negative "
            f"timestamp: {e}"
        ) from e
