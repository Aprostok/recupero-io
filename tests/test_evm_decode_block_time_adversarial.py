"""RIGOR-Jacob J adversarial: EVM ``_decode_block_time`` against
extreme timeStamp values from Etherscan / Alchemy.

The existing ``_decode_block_time`` rejects:
  * non-integer strings (caught)
  * negative integers (caught)
  * future timestamps > now+1d (caught)

But it does ``datetime.fromtimestamp(ts_int, tz=UTC)`` BEFORE the
future-cap check. If ``ts_int`` exceeds ~253_402_300_799 (year
9999, datetime.MAX), the construction itself raises uncaught
``OverflowError`` — so the future-cap check is never reached.

A compromised Etherscan response with ``timeStamp = 999999999999999``
would crash the EVM normalization mid-trace.

Lock the contract: extreme timestamps raise ``ValueError`` (the
documented contract), NOT ``OverflowError``.
"""

from __future__ import annotations

import pytest


def test_decode_block_time_overflow_raises_valueerror() -> None:
    """A timeStamp > datetime.MAX (year > 9999, ts > 253_402_300_799)
    must NOT propagate OverflowError up the call stack. Either raise
    ValueError (the documented contract) or return a clamped sentinel.
    """
    from recupero.chains.evm.adapter import EvmAdapter

    extreme = 999_999_999_999_999  # year ~31693593
    try:
        EvmAdapter._decode_block_time(extreme)
    except ValueError:
        return  # documented contract
    except OverflowError as e:
        raise AssertionError(
            f"_decode_block_time leaked OverflowError on timeStamp={extreme}: "
            f"{e}. The fromtimestamp call happens before the future-cap "
            f"check, so the existing 'future timestamp' guard never fires."
        ) from e
    raise AssertionError(
        f"_decode_block_time silently accepted timeStamp={extreme}; "
        f"no exception raised."
    )


def test_decode_block_time_max_int_does_not_crash() -> None:
    """sys.maxsize → fromtimestamp raises OverflowError. Confirm
    contract holds for the boundary."""
    import sys

    from recupero.chains.evm.adapter import EvmAdapter

    try:
        EvmAdapter._decode_block_time(sys.maxsize)
    except ValueError:
        return
    except OverflowError as e:
        raise AssertionError(
            f"_decode_block_time leaked OverflowError on sys.maxsize: {e}"
        ) from e
    pytest.skip("sys.maxsize fit within datetime's range on this platform")


def test_decode_block_time_normal_value_still_works() -> None:
    """Sanity: post-hardening, a normal timestamp still parses."""
    from recupero.chains.evm.adapter import EvmAdapter

    result = EvmAdapter._decode_block_time(1_700_000_000)
    assert result.year == 2023
