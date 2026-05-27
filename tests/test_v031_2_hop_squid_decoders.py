"""v0.31.1 — Punishing tests for Hop + Squid bridge calldata decoders.

Coverage targets:
  * Hop sendToL2 — uint256 EVM chainID dispatched through
    _EVM_CHAIN_BY_ID, recipient recovered from right-padded slot.
  * Squid bridgeCall / callBridgeCall — Axelar-shape string args
    parsed via _read_solidity_string, chain name routed through
    _AXELAR_CHAIN_NAMES, bech32 + EVM addresses both accepted.

Each decoder is also probed with:
  * Truncated calldata     → BridgeDecodeResult(confidence='low')
  * Unknown method id      → None (dispatcher contract)
  * Case-insensitive protocol dispatch (matches case sensitivity
    expectations from the v0.31.0 Connext/Axelar/LiFi pattern).

Mirror of tests/test_v031_decoders.py — same helpers, same shape.
"""

from __future__ import annotations

from recupero.trace.bridge_calldata import (
    BridgeDecodeResult,
    decode_bridge_calldata,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — copied verbatim from tests/test_v031_decoders.py so this file
# stays standalone (no cross-test import coupling).
# ─────────────────────────────────────────────────────────────────────────────


def _pad_uint(value: int, slot_count: int = 1) -> str:
    """Right-align an integer into `slot_count` 32-byte slots."""
    return f"{value:0{64 * slot_count}x}"


def _pad_address(addr_hex_no_prefix: str) -> str:
    """Right-pad a 20-byte address to a 32-byte slot."""
    assert len(addr_hex_no_prefix) == 40, f"need 40 hex chars, got {len(addr_hex_no_prefix)}"
    return "0" * 24 + addr_hex_no_prefix.lower()


def _encode_string_tail(s: str) -> str:
    """ABI dynamic-string tail: 32-byte length, then UTF-8 bytes padded
    to 32-byte multiple."""
    body = s.encode("utf-8")
    pad_to = ((len(body) + 31) // 32) * 32
    return _pad_uint(len(body), 1) + body.hex() + "00" * (pad_to - len(body))


# ─────────────────────────────────────────────────────────────────────────────
# Hop sendToL2 decoder
# ─────────────────────────────────────────────────────────────────────────────


def _build_hop_send_to_l2_calldata(
    *,
    method_id: str = "deace8f5",
    chain_id: int = 42161,                 # Arbitrum
    recipient: str = "b" * 40,
    amount: int = 1_000_000_000,
    amount_out_min: int = 990_000_000,
    deadline: int = 9_999_999_999,
    relayer: str = "0" * 40,
    relayer_fee: int = 0,
) -> str:
    """Build a synthetic Hop L1Bridge.sendToL2 calldata blob.

    sendToL2(uint256 chainId, address recipient, uint256 amount,
             uint256 amountOutMin, uint256 deadline,
             address relayer, uint256 relayerFee)
    """
    head = (
        _pad_uint(chain_id, 1)             # [0..32]    chainId (uint256)
        + _pad_address(recipient)          # [32..64]   recipient
        + _pad_uint(amount, 1)             # [64..96]   amount
        + _pad_uint(amount_out_min, 1)     # [96..128]  amountOutMin
        + _pad_uint(deadline, 1)           # [128..160] deadline
        + _pad_address(relayer)            # [160..192] relayer
        + _pad_uint(relayer_fee, 1)        # [192..224] relayerFee
    )
    return "0x" + method_id + head


def test_hop_send_to_l2_arbitrum_high_confidence() -> None:
    """Known EVM chainID (42161 = Arbitrum) + valid recipient → high."""
    calldata = _build_hop_send_to_l2_calldata(
        chain_id=42161,
        recipient="b" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Hop",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "arbitrum"
    assert out.destination_address == "0x" + "b" * 40
    assert out.confidence == "high"
    assert out.bridge_method == "sendToL2"


def test_hop_send_to_l2_polygon_high_confidence() -> None:
    """Polygon = 137 — covers the other common Hop L2 destination."""
    calldata = _build_hop_send_to_l2_calldata(
        chain_id=137,
        recipient="c" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Hop Protocol",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "polygon"
    assert out.destination_address == "0x" + "c" * 40
    assert out.confidence == "high"


def test_hop_send_to_l2_optimism_via_older_selector() -> None:
    """The older 0xa6df7b8c overload routes through the same decoder."""
    calldata = _build_hop_send_to_l2_calldata(
        method_id="a6df7b8c",
        chain_id=10,                       # Optimism
        recipient="d" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="hop",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "optimism"
    assert out.destination_address == "0x" + "d" * 40
    assert out.confidence == "high"


def test_hop_unknown_chain_id_medium_confidence() -> None:
    """Unknown chain ID → no chain mapping, address still extractable → medium."""
    calldata = _build_hop_send_to_l2_calldata(
        chain_id=999_999,                  # Not in _EVM_CHAIN_BY_ID
        recipient="e" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Hop",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain is None
    assert out.destination_address == "0x" + "e" * 40
    assert out.confidence == "medium"


def test_hop_truncated_calldata_returns_low() -> None:
    """Calldata < 7 full slots → low confidence, no crash."""
    short = "0xdeace8f5" + "00" * 64       # only 2 slots
    out = decode_bridge_calldata(
        bridge_protocol="Hop",
        input_data=short,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"
    assert out.destination_chain is None
    assert out.destination_address is None


def test_hop_unknown_method_returns_none() -> None:
    """0xdeadbeef is not a Hop selector → dispatcher returns None."""
    out = decode_bridge_calldata(
        bridge_protocol="Hop",
        input_data="0xdeadbeef" + "00" * 224,
    )
    assert out is None


def test_hop_case_insensitive_protocol_dispatch() -> None:
    """Mixed-case 'HOP' / 'Hop' / 'hop' all reach the decoder."""
    calldata = _build_hop_send_to_l2_calldata(
        chain_id=10,
        recipient="9" * 40,
    )
    for label in ("HOP", "Hop", "hop", "HoP Protocol"):
        out = decode_bridge_calldata(
            bridge_protocol=label,
            input_data=calldata,
        )
        assert isinstance(out, BridgeDecodeResult), f"label={label!r}"
        assert out.destination_chain == "optimism"


def test_hop_hopr_protocol_NOT_routed_to_hop() -> None:
    """'HOPR' (the privacy network) must NOT dispatch through the Hop
    decoder — it's an unrelated protocol whose name starts with 'hop'.
    """
    calldata = _build_hop_send_to_l2_calldata(
        chain_id=42161,
        recipient="a" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="HOPR Net",
        input_data=calldata,
    )
    # Dispatcher must not recognize HOPR → no decoder → None
    assert out is None


# ─────────────────────────────────────────────────────────────────────────────
# Squid bridgeCall / callBridgeCall decoder
# ─────────────────────────────────────────────────────────────────────────────


def _build_squid_bridge_call_calldata(
    *,
    method_id: str = "84d2bb4d",
    destination_chain: str = "Polygon",
    destination_address: str = "0x" + "1" * 40,
) -> str:
    """Build a synthetic Squid bridgeCall calldata blob.

    bridgeCall(string destinationChain, string destinationAddress, ...)
    Encoded as two dynamic-string args in the head slots, then tails.
    To make the test calldata realistic but minimal, we pad the head
    region out to at least 128 bytes (4 slots — what the dispatcher
    requires to attempt decode) by adding two zero placeholder slots
    after the two offset slots.
    """
    chain_tail = _encode_string_tail(destination_chain)
    addr_tail = _encode_string_tail(destination_address)

    # 4-slot head: 2 offsets + 2 zero placeholders to satisfy the
    # 128-byte minimum the decoder enforces before attempting parse.
    head_size = 4 * 32
    off_chain = head_size
    off_addr = off_chain + (len(chain_tail) // 2)
    head = (
        _pad_uint(off_chain, 1)
        + _pad_uint(off_addr, 1)
        + _pad_uint(0, 1)
        + _pad_uint(0, 1)
    )
    return "0x" + method_id + head + chain_tail + addr_tail


def test_squid_bridge_call_polygon_evm_destination() -> None:
    """Mapped chain name + EVM 0x address → high confidence."""
    calldata = _build_squid_bridge_call_calldata(
        destination_chain="Polygon",
        destination_address="0x" + "1" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Squid",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "polygon"
    assert out.destination_address == "0x" + "1" * 40
    assert out.confidence == "high"
    assert out.bridge_method == "bridgeCall"


def test_squid_call_bridge_call_avalanche() -> None:
    """The callBridgeCall selector (0x32fb1360) routes through same decoder."""
    calldata = _build_squid_bridge_call_calldata(
        method_id="32fb1360",
        destination_chain="avalanche",
        destination_address="0x" + "2" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Squid Router",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "avalanche"
    assert out.destination_address == "0x" + "2" * 40
    assert out.confidence == "high"
    assert out.bridge_method == "callBridgeCall"


def test_squid_cosmos_bech32_address_accepted() -> None:
    """Squid bridges into Cosmos via Axelar — bech32 addresses are
    forwarded verbatim."""
    bech32 = "osmo1abc123def456ghi789jkl0mnp345qrs678tuv"
    calldata = _build_squid_bridge_call_calldata(
        destination_chain="osmosis",
        destination_address=bech32,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Squid",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "cosmos"   # osmosis → cosmos via _AXELAR_CHAIN_NAMES
    assert out.destination_address == bech32


def test_squid_unknown_chain_name_preserved_lowercase() -> None:
    """A chain not in the Axelar table is kept verbatim (lowercased)."""
    calldata = _build_squid_bridge_call_calldata(
        destination_chain="Crescent",
        destination_address="0x" + "3" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Squid",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "crescent"
    assert out.destination_address == "0x" + "3" * 40
    # Both fields populated → high
    assert out.confidence == "high"


def test_squid_truncated_calldata_returns_low() -> None:
    """Less than 4 full head slots → low confidence."""
    short = "0x84d2bb4d" + "00" * 64
    out = decode_bridge_calldata(
        bridge_protocol="Squid",
        input_data=short,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"
    assert out.destination_chain is None
    assert out.destination_address is None


def test_squid_unknown_method_returns_none() -> None:
    """0xdeadbeef is not a Squid selector → dispatcher returns None."""
    out = decode_bridge_calldata(
        bridge_protocol="Squid",
        input_data="0xdeadbeef" + "00" * 224,
    )
    assert out is None


def test_squid_case_insensitive_protocol_dispatch() -> None:
    """Mixed-case 'SQUID' / 'Squid' / 'squid' all reach the decoder."""
    calldata = _build_squid_bridge_call_calldata(
        destination_chain="Polygon",
        destination_address="0x" + "4" * 40,
    )
    for label in ("SQUID", "Squid", "squid", "Squid Router"):
        out = decode_bridge_calldata(
            bridge_protocol=label,
            input_data=calldata,
        )
        assert isinstance(out, BridgeDecodeResult), f"label={label!r}"
        assert out.destination_chain == "polygon"
        assert out.destination_address == "0x" + "4" * 40


def test_squid_malformed_offset_does_not_crash() -> None:
    """Garbage offsets pointing past EOB → low-confidence, no raise."""
    method_id = "84d2bb4d"
    head = (
        _pad_uint(0xffffffff, 1)
        + _pad_uint(0xffffffff, 1)
        + _pad_uint(0, 1)
        + _pad_uint(0, 1)
    )
    out = decode_bridge_calldata(
        bridge_protocol="Squid",
        input_data="0x" + method_id + head,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"
    assert out.destination_chain is None
    assert out.destination_address is None


# ─────────────────────────────────────────────────────────────────────────────
# Cross-decoder dispatch sanity
# ─────────────────────────────────────────────────────────────────────────────


def test_dispatch_hop_calldata_under_squid_protocol_returns_none() -> None:
    """A Hop selector under bridge_protocol='Squid' is not in
    _SQUID_METHODS → decoder returns None (graceful)."""
    calldata = _build_hop_send_to_l2_calldata()
    out = decode_bridge_calldata(
        bridge_protocol="Squid",
        input_data=calldata,
    )
    assert out is None


def test_dispatch_squid_calldata_under_hop_protocol_returns_none() -> None:
    """A Squid selector under bridge_protocol='Hop' is not in
    _HOP_METHODS → decoder returns None."""
    calldata = _build_squid_bridge_call_calldata()
    out = decode_bridge_calldata(
        bridge_protocol="Hop",
        input_data=calldata,
    )
    assert out is None


def test_both_new_protocols_never_swallow_valid_selectors_on_truncation() -> None:
    """Smoke: valid selectors on truncated input still return a result
    (not None) — recognition + handoff surfacing must survive."""
    truncated_hop = "0xdeace8f5" + "00" * 32
    truncated_squid = "0x84d2bb4d" + "00" * 32

    r_hop = decode_bridge_calldata(bridge_protocol="Hop", input_data=truncated_hop)
    r_squid = decode_bridge_calldata(bridge_protocol="Squid", input_data=truncated_squid)

    for r in (r_hop, r_squid):
        assert isinstance(r, BridgeDecodeResult)
        assert r.confidence == "low"
        assert r.destination_chain is None
        assert r.destination_address is None
