"""Tests for the Gnosis Safe ownership-change detector.

Pins JACOB_ADVERSARY_AUDIT_v032 Route 1 Hop 2 mitigation:

* All 4 selectors decoded correctly (swapOwner, addOwnerWithThreshold,
  removeOwner, changeThreshold).
* Malformed calldata returns None (no false positives on short input,
  non-hex, missing slots).
* The verified_via_get_owners flag fires only when the adapter
  reports a non-empty owner list.
* Adapter-fetched path: input_data resolved through
  ``evm_adapter.get_transaction(tx_hash)`` when not passed directly.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from recupero.trace.safe_ownership_detector import (
    SAFE_SELECTORS,
    SafeOwnershipChange,
    detect_safe_ownership_change,
)


# Helper: pad a 20-byte EVM address into a 32-byte ABI slot (hex).
def _addr_slot(addr_hex_no_0x: str) -> str:
    return "00" * 12 + addr_hex_no_0x.lower()


def _uint_slot(n: int) -> str:
    return f"{n:064x}"


SAFE_ADDR = "0x1234567890abcdef1234567890abcdef12345678"
PREV_OWNER = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
OLD_OWNER = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
NEW_OWNER = "0xcccccccccccccccccccccccccccccccccccccccc"


def _build_calldata(selector: str, slots: list[str]) -> str:
    """Concatenate selector + slot hex into a 0x-prefixed calldata blob."""
    return "0x" + selector.removeprefix("0x") + "".join(slots)


# ---------------------------------------------------------------------
# Selectors round-trip
# ---------------------------------------------------------------------


def test_swap_owner_decoded():
    """swapOwner(prevOwner, oldOwner, newOwner): 3 addresses extracted."""
    calldata = _build_calldata(
        "0xe318b52b",
        [
            _addr_slot(PREV_OWNER[2:]),
            _addr_slot(OLD_OWNER[2:]),
            _addr_slot(NEW_OWNER[2:]),
        ],
    )
    res = detect_safe_ownership_change(
        tx_hash="0xtx1",
        evm_adapter=None,
        input_data=calldata,
        to_address=SAFE_ADDR,
    )
    assert isinstance(res, SafeOwnershipChange)
    assert res.method == "swapOwner"
    assert res.selector == "0xe318b52b"
    assert res.safe_address == SAFE_ADDR.lower()
    assert res.prev_owner == PREV_OWNER.lower()
    assert res.old_owner == OLD_OWNER.lower()
    assert res.new_owner == NEW_OWNER.lower()
    assert res.verified_via_get_owners is False
    assert res.tx_hash == "0xtx1"


def test_add_owner_with_threshold_decoded():
    """addOwnerWithThreshold(owner, threshold): 1 address + threshold."""
    calldata = _build_calldata(
        "0x0d582f13",
        [_addr_slot(NEW_OWNER[2:]), _uint_slot(3)],
    )
    res = detect_safe_ownership_change(
        tx_hash="0xtx2",
        evm_adapter=None,
        input_data=calldata,
        to_address=SAFE_ADDR,
    )
    assert res is not None
    assert res.method == "addOwnerWithThreshold"
    assert res.new_owner == NEW_OWNER.lower()
    assert res.new_threshold == 3
    assert res.prev_owner is None
    assert res.old_owner is None


def test_remove_owner_decoded():
    """removeOwner(prevOwner, owner, threshold): 2 addresses + threshold."""
    calldata = _build_calldata(
        "0xf8dc5dd9",
        [
            _addr_slot(PREV_OWNER[2:]),
            _addr_slot(OLD_OWNER[2:]),
            _uint_slot(1),
        ],
    )
    res = detect_safe_ownership_change(
        tx_hash="0xtx3",
        evm_adapter=None,
        input_data=calldata,
        to_address=SAFE_ADDR,
    )
    assert res is not None
    assert res.method == "removeOwner"
    assert res.prev_owner == PREV_OWNER.lower()
    assert res.old_owner == OLD_OWNER.lower()
    assert res.new_threshold == 1
    assert res.new_owner is None


def test_change_threshold_decoded():
    """changeThreshold(threshold): only threshold, no address args."""
    calldata = _build_calldata("0x694e80c3", [_uint_slot(2)])
    res = detect_safe_ownership_change(
        tx_hash="0xtx4",
        evm_adapter=None,
        input_data=calldata,
        to_address=SAFE_ADDR,
    )
    assert res is not None
    assert res.method == "changeThreshold"
    assert res.new_threshold == 2
    assert res.prev_owner is None
    assert res.old_owner is None
    assert res.new_owner is None


# ---------------------------------------------------------------------
# Non-Safe / malformed → None
# ---------------------------------------------------------------------


def test_non_safe_selector_returns_none():
    """An ERC-20 transfer's selector does NOT trigger detection."""
    transfer_calldata = _build_calldata(
        "0xa9059cbb",  # ERC-20 transfer
        [_addr_slot(NEW_OWNER[2:]), _uint_slot(1000)],
    )
    res = detect_safe_ownership_change(
        tx_hash="0xtx5",
        evm_adapter=None,
        input_data=transfer_calldata,
        to_address=SAFE_ADDR,
    )
    assert res is None


def test_malformed_calldata_returns_none():
    """Calldata too short to contain a selector → None."""
    for bad in ["", "0x", "0xab", "0xabcdef", "notahexstring", None]:
        res = detect_safe_ownership_change(
            tx_hash="0xtx-bad",
            evm_adapter=None,
            input_data=bad,
            to_address=SAFE_ADDR,
        )
        assert res is None, f"input {bad!r} should return None"


def test_swap_owner_missing_slots_partial_decode():
    """A swapOwner call with truncated args returns the method but
    None for missing slots — better partial than nothing."""
    # Only 2 slots present where 3 are required.
    calldata = _build_calldata(
        "0xe318b52b",
        [_addr_slot(PREV_OWNER[2:]), _addr_slot(OLD_OWNER[2:])],
    )
    res = detect_safe_ownership_change(
        tx_hash="0xtx-trunc",
        evm_adapter=None,
        input_data=calldata,
        to_address=SAFE_ADDR,
    )
    assert res is not None
    assert res.method == "swapOwner"
    assert res.prev_owner == PREV_OWNER.lower()
    assert res.old_owner == OLD_OWNER.lower()
    assert res.new_owner is None  # missing slot


def test_zero_address_slot_treated_as_none():
    """Zero-address sentinel never represents a meaningful owner."""
    calldata = _build_calldata(
        "0xe318b52b",
        [
            _addr_slot("00" * 20),  # zero
            _addr_slot(OLD_OWNER[2:]),
            _addr_slot(NEW_OWNER[2:]),
        ],
    )
    res = detect_safe_ownership_change(
        tx_hash="0xtx-zero",
        evm_adapter=None,
        input_data=calldata,
        to_address=SAFE_ADDR,
    )
    assert res is not None
    assert res.prev_owner is None  # zero rejected
    assert res.old_owner == OLD_OWNER.lower()


def test_missing_to_address_returns_none():
    """No safe_address → can't be a Safe call."""
    calldata = _build_calldata(
        "0xe318b52b",
        [
            _addr_slot(PREV_OWNER[2:]),
            _addr_slot(OLD_OWNER[2:]),
            _addr_slot(NEW_OWNER[2:]),
        ],
    )
    for bad in ["", None, "0xshort"]:
        res = detect_safe_ownership_change(
            tx_hash="0xtx-noto",
            evm_adapter=None,
            input_data=calldata,
            to_address=bad,
        )
        assert res is None, f"to_address {bad!r} should return None"


# ---------------------------------------------------------------------
# Adapter-verified path
# ---------------------------------------------------------------------


def test_verified_via_get_owners_flag_set_when_adapter_confirms():
    """If call_view('getOwners()') returns a non-empty list, the
    result's verified flag is True."""
    calldata = _build_calldata(
        "0xe318b52b",
        [
            _addr_slot(PREV_OWNER[2:]),
            _addr_slot(OLD_OWNER[2:]),
            _addr_slot(NEW_OWNER[2:]),
        ],
    )
    adapter = MagicMock()
    adapter.call_view.return_value = [PREV_OWNER, OLD_OWNER, NEW_OWNER]
    res = detect_safe_ownership_change(
        tx_hash="0xtx-verify",
        evm_adapter=adapter,
        input_data=calldata,
        to_address=SAFE_ADDR,
    )
    assert res is not None
    assert res.verified_via_get_owners is True
    adapter.call_view.assert_called_once_with("getOwners()", SAFE_ADDR.lower())


def test_verified_flag_false_when_adapter_returns_empty():
    """Adapter returns empty list → not a Safe (or unverifiable)."""
    calldata = _build_calldata(
        "0xe318b52b",
        [
            _addr_slot(PREV_OWNER[2:]),
            _addr_slot(OLD_OWNER[2:]),
            _addr_slot(NEW_OWNER[2:]),
        ],
    )
    adapter = MagicMock()
    adapter.call_view.return_value = []
    res = detect_safe_ownership_change(
        tx_hash="0xtx-verify-empty",
        evm_adapter=adapter,
        input_data=calldata,
        to_address=SAFE_ADDR,
    )
    assert res is not None
    assert res.verified_via_get_owners is False


def test_verified_flag_false_when_adapter_raises():
    """Adapter call_view raises → swallowed, verified=False."""
    calldata = _build_calldata(
        "0xe318b52b",
        [
            _addr_slot(PREV_OWNER[2:]),
            _addr_slot(OLD_OWNER[2:]),
            _addr_slot(NEW_OWNER[2:]),
        ],
    )
    adapter = MagicMock()
    adapter.call_view.side_effect = RuntimeError("RPC down")
    res = detect_safe_ownership_change(
        tx_hash="0xtx-verify-raise",
        evm_adapter=adapter,
        input_data=calldata,
        to_address=SAFE_ADDR,
    )
    assert res is not None
    assert res.verified_via_get_owners is False


def test_adapter_fetched_path():
    """When input_data + to_address are NOT passed directly, the
    adapter's get_transaction(tx_hash) is queried."""
    calldata = _build_calldata(
        "0xe318b52b",
        [
            _addr_slot(PREV_OWNER[2:]),
            _addr_slot(OLD_OWNER[2:]),
            _addr_slot(NEW_OWNER[2:]),
        ],
    )
    adapter = MagicMock()
    adapter.get_transaction.return_value = {
        "input": calldata,
        "to": SAFE_ADDR,
    }
    adapter.call_view.return_value = [PREV_OWNER]
    res = detect_safe_ownership_change(
        tx_hash="0xtx-adapter-fetch",
        evm_adapter=adapter,
    )
    assert res is not None
    assert res.method == "swapOwner"
    adapter.get_transaction.assert_called_once_with("0xtx-adapter-fetch")


# ---------------------------------------------------------------------
# Selector dict shape
# ---------------------------------------------------------------------


def test_safe_selectors_constant_has_four_entries():
    assert len(SAFE_SELECTORS) == 4
    assert SAFE_SELECTORS["0xe318b52b"] == "swapOwner"
    assert SAFE_SELECTORS["0x0d582f13"] == "addOwnerWithThreshold"
    assert SAFE_SELECTORS["0xf8dc5dd9"] == "removeOwner"
    assert SAFE_SELECTORS["0x694e80c3"] == "changeThreshold"
