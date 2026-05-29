"""v0.31.2 — Punishing tests for the Symbiosis MetaRouter decoder.

Symbiosis is a popular cross-chain bridge in the 2024-2025 drainer
scene; pre-v0.31.2 it was recognition-only via bridges.json seed
entries. The decoder added in v0.31.2 extracts:

  * `relayRecipient` (struct slot 7 inside MetaRouteTransaction) —
    the destination-chain receiver address.
  * Destination chain ID — best-effort scan of the early uint256
    slots inside `otherSideCalldata` (the nested metaMintSwap call
    payload), mapped through ``_EVM_CHAIN_BY_ID``.

Selector verified:
  metaRoute((bytes,bytes,address[],address,address,uint256,bool,address,bytes))
  = 0xa11b1198 (via 4byte.directory)

Mirror of tests/test_v031_decoders.py + tests/test_v031_2_hop_squid_decoders.py —
same helpers, same coverage shape.
"""

from __future__ import annotations

from recupero.trace.bridge_calldata import (
    BridgeDecodeResult,
    decode_bridge_calldata,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers — same shape as tests/test_v031_2_hop_squid_decoders.py
# ─────────────────────────────────────────────────────────────────────────────


def _pad_uint(value: int, slot_count: int = 1) -> str:
    """Right-align an integer into ``slot_count`` 32-byte slots."""
    return f"{value:0{64 * slot_count}x}"


def _pad_address(addr_hex_no_prefix: str) -> str:
    """Right-pad a 20-byte address to a 32-byte slot."""
    assert len(addr_hex_no_prefix) == 40, f"need 40 hex chars, got {len(addr_hex_no_prefix)}"
    return "0" * 24 + addr_hex_no_prefix.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Symbiosis metaRoute calldata builder.
#
# Layout (each slot = 32 bytes):
#   args_blob[0..32]           outer offset to the tuple (= 0x20 canonical)
#   Tuple body starts at args_blob[32]:
#     [+0..+32]   offset to firstSwapCalldata (bytes)
#     [+32..+64]  offset to secondSwapCalldata (bytes)
#     [+64..+96]  offset to approvedTokens (address[])
#     [+96..+128] firstDexRouter (address)
#     [+128..+160] secondDexRouter (address)
#     [+160..+192] amount (uint256)
#     [+192..+224] nativeIn (bool)
#     [+224..+256] relayRecipient (address)      <-- target
#     [+256..+288] offset to otherSideCalldata (bytes)
#   Then the dynamic tails.
# ─────────────────────────────────────────────────────────────────────────────


def _build_symbiosis_metaroute_calldata(
    *,
    method_id: str = "a11b1198",
    relay_recipient: str = "b" * 40,
    nested_chain_id: int = 137,         # Polygon
    nested_chain_id_slot: int = 1,      # Where in otherSideCalldata to embed chainID
    nested_extra_slots: int = 5,        # Additional zero slots in nested payload
    first_swap_calldata: bytes = b"",
    second_swap_calldata: bytes = b"",
    approved_tokens: list[str] | None = None,
    first_dex_router: str = "1" * 40,
    second_dex_router: str = "2" * 40,
    amount: int = 1_000_000_000,
    native_in: bool = False,
) -> str:
    """Build a synthetic Symbiosis metaRoute calldata blob.

    The ``nested_chain_id`` is embedded at slot index ``nested_chain_id_slot``
    inside the ``otherSideCalldata`` payload (after its 32-byte length
    prefix). The decoder scans the first 16 nested slots for a known
    EVM chain ID; placing the chainID at any of those slots should
    yield a high-confidence decode.
    """
    if approved_tokens is None:
        approved_tokens = [first_dex_router, second_dex_router]

    # Build the dynamic tails.
    # firstSwapCalldata tail: 32-byte length + body (zero-padded to 32 boundary)
    def _bytes_tail(b: bytes) -> str:
        pad = ((len(b) + 31) // 32) * 32
        return _pad_uint(len(b), 1) + b.hex() + "00" * (pad - len(b))

    first_tail = _bytes_tail(first_swap_calldata)
    second_tail = _bytes_tail(second_swap_calldata)

    # approvedTokens tail: 32-byte length, then each address right-padded
    approved_tail = _pad_uint(len(approved_tokens), 1) + "".join(
        _pad_address(addr) for addr in approved_tokens
    )

    # otherSideCalldata tail. We construct it so a known EVM chain ID
    # appears at slot index ``nested_chain_id_slot``. Total nested
    # body length = (max(nested_chain_id_slot, nested_extra_slots) + 1) * 32
    # bytes — enough slots to land the chainID at the desired index.
    max_slots = max(nested_chain_id_slot, nested_extra_slots) + 1
    nested_body_slots = []
    for i in range(max_slots):
        if i == nested_chain_id_slot:
            nested_body_slots.append(_pad_uint(nested_chain_id, 1))
        else:
            nested_body_slots.append(_pad_uint(0, 1))
    nested_body_hex = "".join(nested_body_slots)
    nested_body_bytes = max_slots * 32
    other_tail = _pad_uint(nested_body_bytes, 1) + nested_body_hex

    # Compute the offsets (in bytes, relative to start of tuple body).
    # 9 head slots = 288 bytes of head.
    head_len = 9 * 32
    off_first = head_len
    off_second = off_first + (len(first_tail) // 2)
    off_approved = off_second + (len(second_tail) // 2)
    off_other = off_approved + (len(approved_tail) // 2)

    tuple_head = (
        _pad_uint(off_first, 1)
        + _pad_uint(off_second, 1)
        + _pad_uint(off_approved, 1)
        + _pad_address(first_dex_router)
        + _pad_address(second_dex_router)
        + _pad_uint(amount, 1)
        + _pad_uint(1 if native_in else 0, 1)
        + _pad_address(relay_recipient)
        + _pad_uint(off_other, 1)
    )

    # Outer offset slot = 0x20 (canonical for a single-arg tuple)
    outer = _pad_uint(32, 1)
    return (
        "0x"
        + method_id
        + outer
        + tuple_head
        + first_tail
        + second_tail
        + approved_tail
        + other_tail
    )


# ─────────────────────────────────────────────────────────────────────────────
# Happy-path tests
# ─────────────────────────────────────────────────────────────────────────────


def test_symbiosis_metaroute_polygon_high_confidence() -> None:
    """EVM chain ID embedded in otherSideCalldata + valid recipient → high."""
    calldata = _build_symbiosis_metaroute_calldata(
        relay_recipient="b" * 40,
        nested_chain_id=137,        # Polygon
    )
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "polygon"
    assert out.destination_address == "0x" + "b" * 40
    assert out.confidence == "high"
    assert out.bridge_method == "metaRoute"


def test_symbiosis_metaroute_arbitrum_high_confidence() -> None:
    """Arbitrum chainID (42161) extracted from nested otherSideCalldata."""
    calldata = _build_symbiosis_metaroute_calldata(
        relay_recipient="c" * 40,
        nested_chain_id=42161,
        nested_chain_id_slot=3,    # Try a different slot to exercise the scan
    )
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "arbitrum"
    assert out.destination_address == "0x" + "c" * 40
    assert out.confidence == "high"


def test_symbiosis_metaroute_bsc_via_slot_index_zero() -> None:
    """ChainID at slot 0 of otherSideCalldata (first scan candidate)."""
    calldata = _build_symbiosis_metaroute_calldata(
        relay_recipient="d" * 40,
        nested_chain_id=56,         # BSC
        nested_chain_id_slot=0,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "bsc"
    assert out.destination_address == "0x" + "d" * 40
    assert out.confidence == "high"


# ─────────────────────────────────────────────────────────────────────────────
# Confidence-degradation tests
# ─────────────────────────────────────────────────────────────────────────────


def test_symbiosis_unknown_chain_id_medium_confidence() -> None:
    """Unknown chain ID (99999) → no chain mapping; address still extractable → medium."""
    calldata = _build_symbiosis_metaroute_calldata(
        relay_recipient="e" * 40,
        nested_chain_id=99999,      # Not in _EVM_CHAIN_BY_ID
    )
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain is None
    assert out.destination_address == "0x" + "e" * 40
    assert out.confidence == "medium"


def test_symbiosis_truncated_calldata_returns_low() -> None:
    """Less than the 10-slot minimum (320 bytes) → low confidence, no crash."""
    short = "0xa11b1198" + "00" * 64    # only 2 slots
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data=short,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"
    assert out.destination_chain is None
    assert out.destination_address is None
    assert out.bridge_method == "metaRoute"


def test_symbiosis_unknown_method_returns_none() -> None:
    """0xdeadbeef is not a Symbiosis selector → dispatcher returns None."""
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data="0xdeadbeef" + "00" * 400,
    )
    assert out is None


def test_symbiosis_zero_recipient_no_chain_returns_low() -> None:
    """Recipient = 0x00...00 AND unknown chain → low (both fields missing)."""
    calldata = _build_symbiosis_metaroute_calldata(
        relay_recipient="0" * 40,
        nested_chain_id=88888,          # Not in _EVM_CHAIN_BY_ID
    )
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"
    assert out.destination_chain is None
    assert out.destination_address is None


def test_symbiosis_malformed_outer_offset_does_not_crash() -> None:
    """A garbage outer offset (e.g. 0xffffffff) must not raise — the
    decoder falls back to the canonical layout and still tries to
    salvage the recipient."""
    method_id = "a11b1198"
    # 10 zero slots, but mangled outer offset
    blob = (
        _pad_uint(0xffffffff, 1)        # bad outer offset
        + "00" * 32 * 9                 # 9 fake tuple-head slots
    )
    # We do NOT crash; result is low or medium depending on whether the
    # canonical-layout fallback can still salvage anything.
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data="0x" + method_id + blob,
    )
    assert isinstance(out, BridgeDecodeResult)
    # The relayRecipient slot at canonical offset reads zero → low.
    assert out.confidence == "low"
    assert out.destination_address is None


def test_symbiosis_1mb_calldata_does_not_crash() -> None:
    """A massive 1MB blob with the Symbiosis selector must not crash
    or spin. Builds a valid blob then appends junk bytes at the end."""
    base = _build_symbiosis_metaroute_calldata(
        relay_recipient="a" * 40,
        nested_chain_id=10,
    )
    # 1MB = 1_048_576 bytes = 2_097_152 hex chars. Append junk to the
    # tail (does not affect the head/tuple-body decoding).
    junk = "00" * (1_048_576)
    big_calldata = base + junk
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data=big_calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    # The valid prefix should still decode cleanly to Optimism + recipient.
    assert out.destination_chain == "optimism"
    assert out.destination_address == "0x" + "a" * 40
    assert out.confidence == "high"


# ─────────────────────────────────────────────────────────────────────────────
# Protocol dispatch — case-insensitive
# ─────────────────────────────────────────────────────────────────────────────


def test_symbiosis_case_insensitive_protocol_dispatch() -> None:
    """All case variants of 'Symbiosis' must reach the decoder."""
    calldata = _build_symbiosis_metaroute_calldata(
        relay_recipient="9" * 40,
        nested_chain_id=137,
    )
    for label in (
        "Symbiosis",
        "symbiosis",
        "SYMBIOSIS",
        "SymBiOsIs",
        "Symbiosis: MetaRouter (Ethereum)",        # bridges.json-shaped label
        "Symbiosis: Portal",
    ):
        out = decode_bridge_calldata(
            bridge_protocol=label,
            input_data=calldata,
        )
        assert isinstance(out, BridgeDecodeResult), f"label={label!r}"
        assert out.destination_chain == "polygon", f"label={label!r}"
        assert out.destination_address == "0x" + "9" * 40, f"label={label!r}"


# ─────────────────────────────────────────────────────────────────────────────
# Cross-decoder dispatch sanity
# ─────────────────────────────────────────────────────────────────────────────


def test_dispatch_symbiosis_calldata_under_other_protocol_returns_none() -> None:
    """A Symbiosis selector under bridge_protocol='Hop' is not in
    _HOP_METHODS → decoder returns None (graceful)."""
    calldata = _build_symbiosis_metaroute_calldata()
    out = decode_bridge_calldata(
        bridge_protocol="Hop",
        input_data=calldata,
    )
    assert out is None


def test_dispatch_hop_calldata_under_symbiosis_protocol_returns_none() -> None:
    """A Hop selector under bridge_protocol='Symbiosis' is not in
    _SYMBIOSIS_METHODS → decoder returns None."""
    hop_calldata = "0xdeace8f5" + "00" * (7 * 32)
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data=hop_calldata,
    )
    assert out is None


def test_symbiosis_truncated_valid_selector_does_not_swallow() -> None:
    """Smoke: valid selector on truncated input still returns a
    BridgeDecodeResult (recognition + handoff surfacing must survive)."""
    truncated = "0xa11b1198" + "00" * 64       # well under the 320-byte minimum
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data=truncated,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"
    assert out.destination_chain is None
    assert out.destination_address is None
    assert out.bridge_method == "metaRoute"
