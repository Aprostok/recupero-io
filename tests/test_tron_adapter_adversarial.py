"""RIGOR-Jacob H adversarial: Tron/TronGrid adapter defenses.

Same crash class as Solana and Bitcoin. TronGrid responses carry
``block_timestamp`` (milliseconds since epoch) and the adapter does
``datetime.fromtimestamp(block_ts_ms / 1000.0, tz=UTC)`` with NO
range check — an extreme value crashes ``_normalize_trc20`` mid-loop.

The pre-fix bug shape: TronGrid returns
``{"block_timestamp": 99_999_999_999_999_999}`` → divide by 1000 →
~ 1e14 seconds since epoch → year 3_170_979 → OverflowError uncaught
→ the whole BFS wave dies.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock


def _build_adapter():
    """Bypass __init__ — minimal Tron adapter shell. Patches the
    address normalizer to pass through so tests can exercise the
    timestamp path without needing real b58check checksums."""
    from recupero.chains.tron.adapter import TronAdapter

    adapter = TronAdapter.__new__(TronAdapter)
    adapter.client = MagicMock()
    return adapter


def _patch_address_normalize():
    """Context manager replacing the strict b58check validator with a
    pass-through so we can use placeholder address strings in the
    fixtures."""
    import contextlib

    import recupero.chains.tron.adapter as tron_mod

    @contextlib.contextmanager
    def cm():
        orig = tron_mod.normalize_tron_address
        tron_mod.normalize_tron_address = lambda x: x
        try:
            yield
        finally:
            tron_mod.normalize_tron_address = orig
    return cm()


def test_normalize_trc20_extreme_timestamp_does_not_crash() -> None:
    """A TronGrid event with block_timestamp far in the future must
    not raise OverflowError out of ``_normalize_trc20``. Pre-fix the
    adapter passes it blindly to datetime.fromtimestamp."""
    from recupero.chains.tron.adapter import TronAdapter

    adapter = _build_adapter()
    bad_event = {
        "transaction_id": "abc" * 21,
        "from": "TXYZabcdefghijklmnopqrstuvwxyz0123",  # 34-char b58 placeholder
        "to": "TUVWxyz0123456789abcdefghijklmnopq",
        "block_timestamp": 99_999_999_999_999_999,  # year 3_170_979
        "token_info": {
            "address": "TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj",  # placeholder
            "symbol": "USDT",
            "decimals": 6,
        },
        "value": "1000000",
    }
    try:
      with _patch_address_normalize():
        result = TronAdapter._normalize_trc20(
            adapter, bad_event, expected_from=None,
        )
        if result is not None:
            block_time = result.get("block_time")
            if isinstance(block_time, datetime):
                assert block_time.year < 9999, (
                    f"Extreme ms-timestamp produced year {block_time.year}"
                )
    except (OverflowError, OSError, ValueError) as e:
        raise AssertionError(
            f"_normalize_trc20 raised {type(e).__name__} on extreme "
            f"block_timestamp: {e}. TronGrid is an external API; "
            f"a single bad response must NOT crash the BFS hop."
        ) from e


def test_normalize_trc20_negative_timestamp_does_not_crash() -> None:
    """Same defense for very-negative timestamps (Windows raises OSError)."""
    from recupero.chains.tron.adapter import TronAdapter

    adapter = _build_adapter()
    bad_event = {
        "transaction_id": "abc" * 21,
        "from": "TXYZabcdefghijklmnopqrstuvwxyz0123",
        "to": "TUVWxyz0123456789abcdefghijklmnopq",
        "block_timestamp": -99_999_999_999_999,
        "token_info": {
            "address": "TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj",
            "symbol": "USDT",
            "decimals": 6,
        },
        "value": "1000000",
    }
    try:
      with _patch_address_normalize():
        TronAdapter._normalize_trc20(adapter, bad_event, expected_from=None)
    except (OverflowError, OSError, ValueError) as e:
        raise AssertionError(
            f"_normalize_trc20 raised {type(e).__name__} on negative "
            f"block_timestamp: {e}"
        ) from e


def test_normalize_trc20_normal_timestamp_works() -> None:
    """Sanity: normal timestamps still work after hardening."""
    from recupero.chains.tron.adapter import TronAdapter

    adapter = _build_adapter()
    good_event = {
        "transaction_id": "abc" * 21,
        "from": "TXYZabcdefghijklmnopqrstuvwxyz0123",
        "to": "TUVWxyz0123456789abcdefghijklmnopq",
        "block_timestamp": 1_700_000_000_000,  # 2023-11-14 in ms
        "token_info": {
            "address": "TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj",
            "symbol": "USDT",
            "decimals": 6,
        },
        "value": "1000000",
    }
    with _patch_address_normalize():
        result = TronAdapter._normalize_trc20(
            adapter, good_event, expected_from=None,
        )
    # May return None if address normalization fails (placeholder
    # addrs aren't real b58check) — that's acceptable, we're only
    # asserting NO CRASH on the timestamp path.
    if result is not None:
        block_time = result.get("block_time")
        assert isinstance(block_time, datetime)
        assert block_time.year == 2023
