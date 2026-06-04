"""v0.31.4 — Punishing tests for the 6 remaining bridge decoders.

Six protocols had seed entries in bridges.json but no destination-
extraction code path pre-v0.31.4:

  * DeBridge DLN — createSaleOrder / createOrder / send. OrderCreation
    tuple carries takeChainId (uint256, EVM chainID) + receiverDst
    (bytes, variable length so EVM + non-EVM both fit).
  * LayerZero raw OApp Endpoint — send_v1 (uint16 dstChainId) and
    send_v2 (MessagingParams with uint32 dstEid). LZ uses its own
    chain-ID namespace; v2 endpoints live in the 30000-series.
  * Chainlink CCIP Router — ccipSend(uint64 destChainSelector,
    EVM2AnyMessage). CCIP uses its own uint64 selector namespace
    (NOT EVM chainIDs / NOT LZ EIDs / NOT Wormhole).
  * Multichain (Anyswap legacy) — anySwapOutUnderlying / anySwapOut.
    Defunct since July 2023 but transit traffic still hits legacy
    routers; decoding lets the trace continue past those handoffs.
  * Stargate v2 — Pool.sendToken(SendParam, MessagingFee, address).
    Reuses LZ v2 EIDs in the dstEid field.
  * Symbiosis MetaRouter — already had a heuristic scan-16 decoder;
    v0.31.4 tightens the scan window to 8 slots to reduce false
    positives, but the existing test fixtures (slot 0/1/3) still
    decode cleanly.

Each decoder gets the standard punishment grid: happy path, truncated
calldata, unknown method ID, unknown chain selector, adversarial
1MB blob, case-insensitive protocol dispatch.
"""

from __future__ import annotations

from recupero.trace.bridge_calldata import (
    BridgeDecodeResult,
    decode_bridge_calldata,
)

# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers — copied verbatim from the v0.31.x test files so this file
# stays self-contained (no cross-test imports).
# ─────────────────────────────────────────────────────────────────────────────


def _pad_uint(value: int, slot_count: int = 1) -> str:
    """Right-align an integer into ``slot_count`` 32-byte slots."""
    return f"{value:0{64 * slot_count}x}"


def _pad_address(addr_hex_no_prefix: str) -> str:
    """Right-pad a 20-byte address to a 32-byte slot."""
    assert len(addr_hex_no_prefix) == 40, f"need 40 hex chars, got {len(addr_hex_no_prefix)}"
    return "0" * 24 + addr_hex_no_prefix.lower()


def _bytes_tail(b: bytes) -> str:
    """ABI dynamic-bytes tail: 32-byte length + body padded to 32-byte multiple."""
    pad = ((len(b) + 31) // 32) * 32
    return _pad_uint(len(b), 1) + b.hex() + "00" * (pad - len(b))


# ═════════════════════════════════════════════════════════════════════════════
# 1. DeBridge DLN decoder
# ═════════════════════════════════════════════════════════════════════════════


def _build_debridge_create_sale_order(
    *,
    method_id: str = "fb96b66e",
    take_chain_id: int = 137,           # Polygon
    receiver_dst: str = "b" * 40,       # 20-byte EVM address (40 hex chars)
    give_token: str = "1" * 40,
    give_amount: int = 1_000_000_000,
    take_amount: int = 990_000_000,
) -> str:
    """Build a synthetic DeBridge DLN createSaleOrder calldata blob.

    OrderCreation struct layout (head slots, then dynamic tails):
      slot 0: giveTokenAddress (address)
      slot 1: giveAmount (uint256)
      slot 2: offset to takeTokenAddress (bytes)
      slot 3: takeAmount (uint256)
      slot 4: takeChainId (uint256)        <-- target
      slot 5: offset to receiverDst (bytes) <-- target
      slot 6: givePatchAuthoritySrc (address)
      slot 7: offset to orderAuthorityAddressDst (bytes)
      slot 8: offset to allowedTakerDst (bytes)
      slot 9: offset to externalCall (bytes)
      slot 10: offset to allowedCancelBeneficiarySrc (bytes)
    """
    receiver_bytes = bytes.fromhex(receiver_dst)
    take_token_tail = _bytes_tail(b"\xff" * 20)        # 20-byte EVM token
    receiver_tail = _bytes_tail(receiver_bytes)
    # 5 extra dynamic fields (empty bytes) for slots 7..10 + take_token_tail (slot 2)
    empty_tail = _bytes_tail(b"")

    head_slots = 11
    head_len = head_slots * 32

    off_take_token = head_len
    off_receiver = off_take_token + (len(take_token_tail) // 2)
    off_authority = off_receiver + (len(receiver_tail) // 2)
    off_allowed_taker = off_authority + (len(empty_tail) // 2)
    off_external = off_allowed_taker + (len(empty_tail) // 2)
    off_cancel = off_external + (len(empty_tail) // 2)

    tuple_head = (
        _pad_address(give_token)              # slot 0
        + _pad_uint(give_amount, 1)           # slot 1
        + _pad_uint(off_take_token, 1)        # slot 2 (offset)
        + _pad_uint(take_amount, 1)           # slot 3
        + _pad_uint(take_chain_id, 1)         # slot 4 (chain)
        + _pad_uint(off_receiver, 1)          # slot 5 (offset)
        + _pad_address("0" * 40)              # slot 6 (authority)
        + _pad_uint(off_authority, 1)         # slot 7 (offset)
        + _pad_uint(off_allowed_taker, 1)     # slot 8 (offset)
        + _pad_uint(off_external, 1)          # slot 9 (offset)
        + _pad_uint(off_cancel, 1)            # slot 10 (offset)
    )

    outer = _pad_uint(32, 1)
    return (
        "0x"
        + method_id
        + outer
        + tuple_head
        + take_token_tail
        + receiver_tail
        + empty_tail   # authority
        + empty_tail   # allowed taker
        + empty_tail   # external
        + empty_tail   # cancel
    )


def test_debridge_create_sale_order_polygon_high_confidence() -> None:
    """Happy path: chain 137 + valid receiver → high."""
    calldata = _build_debridge_create_sale_order(
        take_chain_id=137,
        receiver_dst="b" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="DeBridge",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "polygon"
    assert out.destination_address == "0x" + "b" * 40
    assert out.confidence == "medium"  # v0.36: calldata decode is never 'high'
    assert out.bridge_method == "createSaleOrder"


def test_debridge_truncated_calldata_returns_low() -> None:
    """Calldata too short for OrderCreation struct → low, no crash."""
    short = "0xfb96b66e" + "00" * 64    # only 2 slots
    out = decode_bridge_calldata(
        bridge_protocol="DeBridge",
        input_data=short,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"
    assert out.destination_chain is None
    assert out.destination_address is None


def test_debridge_unknown_method_returns_none() -> None:
    """Unknown selector → dispatcher returns None."""
    out = decode_bridge_calldata(
        bridge_protocol="DeBridge",
        input_data="0xdeadbeef" + "00" * 400,
    )
    assert out is None


def test_debridge_unknown_chain_id_medium_confidence() -> None:
    """Unknown chain ID — receiver still extractable → medium."""
    calldata = _build_debridge_create_sale_order(
        take_chain_id=9999999,        # Not in _EVM_CHAIN_BY_ID
        receiver_dst="c" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="DeBridge",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    # Decoder scans slots 2..7 for a known EVM chain; with no match,
    # confidence drops to low or medium depending on whether receiver
    # was salvaged.
    assert out.confidence in ("low", "medium")
    assert out.destination_chain is None


def test_debridge_1mb_calldata_does_not_crash() -> None:
    """Adversarial 1MB blob must not crash."""
    base = _build_debridge_create_sale_order(
        take_chain_id=42161,        # Arbitrum
        receiver_dst="a" * 40,
    )
    junk = "00" * 1_048_576
    big_calldata = base + junk
    out = decode_bridge_calldata(
        bridge_protocol="DeBridge",
        input_data=big_calldata,
    )
    assert isinstance(out, BridgeDecodeResult)


def test_debridge_case_insensitive_protocol_dispatch() -> None:
    """All case variants of 'DeBridge' must reach the decoder."""
    calldata = _build_debridge_create_sale_order(
        take_chain_id=10,           # Optimism
        receiver_dst="9" * 40,
    )
    for label in (
        "DeBridge",
        "debridge",
        "DEBRIDGE",
        "deBridgeGate (DLN)",
        "deBridge DLN Source",
    ):
        out = decode_bridge_calldata(
            bridge_protocol=label,
            input_data=calldata,
        )
        assert isinstance(out, BridgeDecodeResult), f"{label} did not dispatch"
        assert out.bridge_method == "createSaleOrder"


# ═════════════════════════════════════════════════════════════════════════════
# 2. LayerZero raw OApp Endpoint decoder
# ═════════════════════════════════════════════════════════════════════════════


def _build_layerzero_v1_send(
    *,
    method_id: str = "c5803100",
    dst_chain_id: int = 110,             # Arbitrum (LZ v1 chain id)
    destination_addr: str = "b" * 40,
    payload: bytes = b"",
    refund: str = "1" * 40,
    zro_payment: str = "0" * 40,
    adapter_params: bytes = b"",
) -> str:
    """Build a synthetic LayerZero v1 Endpoint.send calldata blob.

    send(uint16 _dstChainId, bytes _destination, bytes _payload,
         address payable _refundAddress, address _zroPaymentAddress,
         bytes _adapterParams)
    """
    # Destination bytes: just the 20-byte address (no encoded suffix).
    dest_bytes = bytes.fromhex(destination_addr)
    dest_tail = _bytes_tail(dest_bytes)
    payload_tail = _bytes_tail(payload)
    adapter_tail = _bytes_tail(adapter_params)

    head_len = 6 * 32   # 6 static head slots
    off_dest = head_len
    off_payload = off_dest + (len(dest_tail) // 2)
    off_adapter = off_payload + (len(payload_tail) // 2)

    head = (
        _pad_uint(dst_chain_id, 1)        # slot 0: uint16 right-aligned
        + _pad_uint(off_dest, 1)          # slot 1: offset
        + _pad_uint(off_payload, 1)       # slot 2: offset
        + _pad_address(refund)            # slot 3: address
        + _pad_address(zro_payment)       # slot 4: address
        + _pad_uint(off_adapter, 1)       # slot 5: offset
    )
    return "0x" + method_id + head + dest_tail + payload_tail + adapter_tail


def _build_layerzero_v2_send(
    *,
    method_id: str = "1bb3a8fd",
    dst_eid: int = 30110,                # Arbitrum (LZ v2 EID)
    receiver_addr: str = "b" * 40,
    message: bytes = b"",
    options: bytes = b"",
    pay_in_lz_token: bool = False,
    refund: str = "1" * 40,
) -> str:
    """Build a synthetic LayerZero v2 Endpoint.send calldata blob.

    send(MessagingParams calldata _params, address _refundAddress)
    where MessagingParams = (uint32 dstEid, bytes32 receiver, bytes message,
                             bytes options, bool payInLzToken)
    """
    receiver_bytes32 = "0" * 24 + receiver_addr.lower()
    message_tail = _bytes_tail(message)
    options_tail = _bytes_tail(options)

    head_len = 5 * 32   # 5 static head slots for MessagingParams head
    off_message = head_len
    off_options = off_message + (len(message_tail) // 2)

    tuple_body = (
        _pad_uint(dst_eid, 1)               # slot 0: dstEid (uint32 right-aligned)
        + receiver_bytes32                  # slot 1: receiver (bytes32)
        + _pad_uint(off_message, 1)         # slot 2: offset
        + _pad_uint(off_options, 1)         # slot 3: offset
        + _pad_uint(1 if pay_in_lz_token else 0, 1)  # slot 4
        + message_tail
        + options_tail
    )
    outer_off = 64    # 2 head slots before tuple body (offset + refund)
    # Outer head: [0..32] offset to tuple, [32..64] refundAddress
    outer_head = _pad_uint(outer_off, 1) + _pad_address(refund)
    return "0x" + method_id + outer_head + tuple_body


def test_layerzero_v1_send_arbitrum_high_confidence() -> None:
    """LZ v1 send with chainID=110 (Arbitrum) + destination → high."""
    calldata = _build_layerzero_v1_send(
        dst_chain_id=110,             # Arbitrum
        destination_addr="b" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="LayerZero",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "arbitrum"
    assert out.destination_address == "0x" + "b" * 40
    assert out.confidence == "medium"  # v0.36: calldata decode is never 'high'
    assert out.bridge_method == "send_v1"


def test_layerzero_v2_send_polygon_high_confidence() -> None:
    """LZ v2 send with EID=30109 (Polygon) + receiver → high."""
    calldata = _build_layerzero_v2_send(
        dst_eid=30109,                # Polygon (LZ v2)
        receiver_addr="c" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="LayerZero",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "polygon"
    assert out.destination_address == "0x" + "c" * 40
    assert out.confidence == "medium"  # v0.36: calldata decode is never 'high'
    assert out.bridge_method == "send_v2"


def test_layerzero_truncated_calldata_returns_low() -> None:
    """Truncated v1 send → low, no crash."""
    short = "0xc5803100" + "00" * 64    # only 2 slots
    out = decode_bridge_calldata(
        bridge_protocol="LayerZero",
        input_data=short,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"


def test_layerzero_unknown_method_returns_none() -> None:
    """Unknown selector → None."""
    out = decode_bridge_calldata(
        bridge_protocol="LayerZero",
        input_data="0xdeadbeef" + "00" * 400,
    )
    assert out is None


def test_layerzero_unknown_chain_id_medium_confidence() -> None:
    """Unknown LZ chain ID — receiver still extractable → medium."""
    calldata = _build_layerzero_v1_send(
        dst_chain_id=65535,            # Not in _LZ_CHAIN_IDS
        destination_addr="d" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="LayerZero",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain is None
    assert out.destination_address == "0x" + "d" * 40
    assert out.confidence == "medium"


def test_layerzero_1mb_calldata_does_not_crash() -> None:
    """Adversarial 1MB blob must not crash."""
    base = _build_layerzero_v1_send(
        dst_chain_id=101,         # Ethereum
        destination_addr="a" * 40,
    )
    big_calldata = base + "00" * 1_048_576
    out = decode_bridge_calldata(
        bridge_protocol="LayerZero",
        input_data=big_calldata,
    )
    assert isinstance(out, BridgeDecodeResult)


def test_layerzero_case_insensitive_protocol_dispatch() -> None:
    """All case variants of 'LayerZero' route to the decoder.

    Crucially: 'LayerZero' must NOT route through the Stargate
    decoder even though the dispatch chain checks startswith('stargate')
    first — the LZ branch is gated by 'stargate not in proto_lc'.
    """
    calldata = _build_layerzero_v1_send(
        dst_chain_id=109,         # Polygon
        destination_addr="e" * 40,
    )
    for label in (
        "LayerZero",
        "layerzero",
        "LAYERZERO",
        "LayerZero: Endpoint v1",
        "LayerZero: Endpoint v2 on Arbitrum",
    ):
        out = decode_bridge_calldata(
            bridge_protocol=label,
            input_data=calldata,
        )
        assert isinstance(out, BridgeDecodeResult), f"{label} did not dispatch"
        assert out.destination_chain == "polygon"


# ═════════════════════════════════════════════════════════════════════════════
# 3. Chainlink CCIP decoder
# ═════════════════════════════════════════════════════════════════════════════


def _build_ccip_send(
    *,
    method_id: str = "96f4e9f9",
    chain_selector: int = 4949039107694359620,    # Arbitrum
    receiver_addr: str = "b" * 40,
    data: bytes = b"",
    fee_token: str = "0" * 40,
    extra_args: bytes = b"",
) -> str:
    """Build a synthetic Chainlink CCIP ccipSend calldata blob.

    ccipSend(uint64 destinationChainSelector, EVM2AnyMessage message)
    where EVM2AnyMessage = (bytes receiver, bytes data,
                            EVMTokenAmount[] tokenAmounts, address feeToken,
                            bytes extraArgs).

    Outer layout:
      [0..32]  chainSelector (uint64 right-aligned)
      [32..64] offset to EVM2AnyMessage tuple (= 0x40 = 64)
      then tuple body.

    Inside the tuple:
      slot 0: offset to receiver (bytes)
      slot 1: offset to data (bytes)
      slot 2: offset to tokenAmounts (array)
      slot 3: feeToken (address)
      slot 4: offset to extraArgs (bytes)
    """
    # Receiver bytes are typically a 32-byte right-padded address for
    # EVM destinations; CCIP wraps EVM addresses as 32-byte bytes.
    receiver_padded = bytes.fromhex("00" * 12 + receiver_addr)
    receiver_tail = _bytes_tail(receiver_padded)
    data_tail = _bytes_tail(data)
    extra_tail = _bytes_tail(extra_args)
    # tokenAmounts: empty array (length 0)
    token_amounts_tail = _pad_uint(0, 1)

    head_slots = 5
    head_len = head_slots * 32

    off_receiver = head_len
    off_data = off_receiver + (len(receiver_tail) // 2)
    off_tokens = off_data + (len(data_tail) // 2)
    off_extra = off_tokens + (len(token_amounts_tail) // 2)

    tuple_body = (
        _pad_uint(off_receiver, 1)          # slot 0
        + _pad_uint(off_data, 1)            # slot 1
        + _pad_uint(off_tokens, 1)          # slot 2
        + _pad_address(fee_token)           # slot 3
        + _pad_uint(off_extra, 1)           # slot 4
        + receiver_tail
        + data_tail
        + token_amounts_tail
        + extra_tail
    )

    outer_head = (
        _pad_uint(chain_selector, 1)        # [0..32] selector
        + _pad_uint(64, 1)                  # [32..64] offset to tuple
    )
    return "0x" + method_id + outer_head + tuple_body


def test_ccip_send_arbitrum_high_confidence() -> None:
    """CCIP send with Arbitrum selector + receiver → high."""
    calldata = _build_ccip_send(
        chain_selector=4949039107694359620,    # Arbitrum
        receiver_addr="b" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="CCIP",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "arbitrum"
    assert out.destination_address == "0x" + "b" * 40
    assert out.confidence == "medium"  # v0.36: calldata decode is never 'high'
    assert out.bridge_method == "ccipSend"


def test_ccip_truncated_calldata_returns_low() -> None:
    """Truncated ccipSend → low."""
    short = "0x96f4e9f9" + "00" * 32
    out = decode_bridge_calldata(
        bridge_protocol="CCIP",
        input_data=short,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"


def test_ccip_unknown_method_returns_none() -> None:
    """Unknown selector → None."""
    out = decode_bridge_calldata(
        bridge_protocol="CCIP",
        input_data="0xdeadbeef" + "00" * 400,
    )
    assert out is None


def test_ccip_unknown_chain_selector_medium_confidence() -> None:
    """Unknown chain selector — receiver still extractable → medium."""
    calldata = _build_ccip_send(
        chain_selector=99999999,        # Not in _CCIP_CHAIN_SELECTORS
        receiver_addr="c" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="CCIP",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain is None
    assert out.destination_address == "0x" + "c" * 40
    assert out.confidence == "medium"


def test_ccip_1mb_calldata_does_not_crash() -> None:
    """Adversarial 1MB blob must not crash."""
    base = _build_ccip_send(
        chain_selector=5009297550715157269,    # Ethereum
        receiver_addr="a" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="CCIP",
        input_data=base + "00" * 1_048_576,
    )
    assert isinstance(out, BridgeDecodeResult)


def test_ccip_case_insensitive_protocol_dispatch() -> None:
    """All case variants route to the CCIP decoder."""
    calldata = _build_ccip_send(
        chain_selector=15971525489660198786,    # Base
        receiver_addr="f" * 40,
    )
    for label in (
        "CCIP",
        "ccip",
        "Chainlink CCIP",
        "Chainlink CCIP: Router (Ethereum)",
        "ccip-router",
    ):
        out = decode_bridge_calldata(
            bridge_protocol=label,
            input_data=calldata,
        )
        assert isinstance(out, BridgeDecodeResult), f"{label} did not dispatch"
        assert out.destination_chain == "base"


# ═════════════════════════════════════════════════════════════════════════════
# 4. Multichain (Anyswap legacy) decoder
# ═════════════════════════════════════════════════════════════════════════════


def _build_multichain_any_swap_out_underlying(
    *,
    method_id: str = "a5e56571",
    token: str = "1" * 40,
    to_addr: str = "b" * 40,
    amount: int = 1_000_000_000,
    to_chain_id: int = 56,        # BSC
) -> str:
    """Build a synthetic Multichain anySwapOutUnderlying calldata blob.

    anySwapOutUnderlying(address token, address to, uint256 amount, uint256 toChainID)
    """
    head = (
        _pad_address(token)
        + _pad_address(to_addr)
        + _pad_uint(amount, 1)
        + _pad_uint(to_chain_id, 1)
    )
    return "0x" + method_id + head


def test_multichain_any_swap_out_underlying_bsc_high() -> None:
    """Multichain anySwapOutUnderlying with chain=56 (BSC) → high."""
    calldata = _build_multichain_any_swap_out_underlying(
        to_addr="b" * 40,
        to_chain_id=56,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Multichain",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "bsc"
    assert out.destination_address == "0x" + "b" * 40
    assert out.confidence == "medium"  # v0.36: calldata decode is never 'high'
    assert out.bridge_method == "anySwapOutUnderlying"


def test_multichain_any_swap_out_avalanche_high() -> None:
    """Multichain anySwapOut (no underlying) → high."""
    calldata = _build_multichain_any_swap_out_underlying(
        method_id="a5e3deeb",
        to_addr="c" * 40,
        to_chain_id=43114,        # Avalanche
    )
    out = decode_bridge_calldata(
        bridge_protocol="Anyswap",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "avalanche"
    assert out.destination_address == "0x" + "c" * 40
    assert out.confidence == "medium"  # v0.36: calldata decode is never 'high'
    assert out.bridge_method == "anySwapOut"


def test_multichain_truncated_calldata_returns_low() -> None:
    """Truncated calldata → low."""
    short = "0xa5e56571" + "00" * 64
    out = decode_bridge_calldata(
        bridge_protocol="Multichain",
        input_data=short,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"


def test_multichain_unknown_method_returns_none() -> None:
    """Unknown selector → None."""
    out = decode_bridge_calldata(
        bridge_protocol="Multichain",
        input_data="0xdeadbeef" + "00" * 200,
    )
    assert out is None


def test_multichain_unknown_chain_id_medium_confidence() -> None:
    """Unknown chain ID — receiver still salvageable → medium."""
    calldata = _build_multichain_any_swap_out_underlying(
        to_addr="d" * 40,
        to_chain_id=9999,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Multichain",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain is None
    assert out.destination_address == "0x" + "d" * 40
    assert out.confidence == "medium"


def test_multichain_1mb_calldata_does_not_crash() -> None:
    """1MB blob must not crash."""
    base = _build_multichain_any_swap_out_underlying(
        to_addr="a" * 40,
        to_chain_id=137,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Multichain",
        input_data=base + "00" * 1_048_576,
    )
    assert isinstance(out, BridgeDecodeResult)


def test_multichain_case_insensitive_protocol_dispatch() -> None:
    """Multichain + Anyswap + case variants all route here."""
    calldata = _build_multichain_any_swap_out_underlying(
        to_addr="9" * 40,
        to_chain_id=10,
    )
    for label in (
        "Multichain",
        "multichain",
        "MULTICHAIN",
        "Anyswap",
        "anyswap",
        "Multichain / Anyswap (defunct)",
    ):
        out = decode_bridge_calldata(
            bridge_protocol=label,
            input_data=calldata,
        )
        assert isinstance(out, BridgeDecodeResult), f"{label} did not dispatch"
        assert out.destination_chain == "optimism"


# ═════════════════════════════════════════════════════════════════════════════
# 5. Stargate v2 decoder
# ═════════════════════════════════════════════════════════════════════════════


def _build_stargate_v2_send_token(
    *,
    method_id: str = "cbef2aa9",
    dst_eid: int = 30110,         # Arbitrum (LZ v2)
    to_addr: str = "b" * 40,
    amount_ld: int = 1_000_000_000,
    min_amount_ld: int = 990_000_000,
    extra_options: bytes = b"",
    compose_msg: bytes = b"",
    oft_cmd: bytes = b"",
    native_fee: int = 0,
    lz_token_fee: int = 0,
    refund: str = "1" * 40,
) -> str:
    """Build a synthetic Stargate v2 Pool.sendToken calldata blob.

    sendToken(SendParam, MessagingFee, address) where
    SendParam = (uint32 dstEid, bytes32 to, uint256 amountLD,
                 uint256 minAmountLD, bytes extraOptions, bytes composeMsg,
                 bytes oftCmd).

    Outer layout:
      [0..32]   offset to SendParam tuple (= 0x80 = 128)
      [32..64]  MessagingFee.nativeFee
      [64..96]  MessagingFee.lzTokenFee
      [96..128] refundAddress
      [128..)   SendParam tuple body
    """
    to_bytes32 = "0" * 24 + to_addr.lower()
    extra_tail = _bytes_tail(extra_options)
    compose_tail = _bytes_tail(compose_msg)
    oft_tail = _bytes_tail(oft_cmd)

    head_len = 7 * 32   # 7 static head slots in SendParam tuple body
    off_extra = head_len
    off_compose = off_extra + (len(extra_tail) // 2)
    off_oft = off_compose + (len(compose_tail) // 2)

    tuple_body = (
        _pad_uint(dst_eid, 1)             # slot 0: dstEid
        + to_bytes32                      # slot 1: to (bytes32)
        + _pad_uint(amount_ld, 1)         # slot 2: amountLD
        + _pad_uint(min_amount_ld, 1)     # slot 3: minAmountLD
        + _pad_uint(off_extra, 1)         # slot 4: offset
        + _pad_uint(off_compose, 1)       # slot 5: offset
        + _pad_uint(off_oft, 1)           # slot 6: offset
        + extra_tail
        + compose_tail
        + oft_tail
    )

    outer_head = (
        _pad_uint(128, 1)                 # [0..32] offset to SendParam
        + _pad_uint(native_fee, 1)        # [32..64] nativeFee
        + _pad_uint(lz_token_fee, 1)      # [64..96] lzTokenFee
        + _pad_address(refund)            # [96..128] refundAddress
    )
    return "0x" + method_id + outer_head + tuple_body


def test_stargate_v2_send_token_arbitrum_high() -> None:
    """Stargate v2 with dstEid=30110 (Arbitrum LZ v2) → high."""
    calldata = _build_stargate_v2_send_token(
        dst_eid=30110,
        to_addr="b" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Stargate v2",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "arbitrum"
    assert out.destination_address == "0x" + "b" * 40
    assert out.confidence == "medium"  # v0.36: calldata decode is never 'high'
    assert out.bridge_method == "sendToken_v2"


def test_stargate_v2_rejects_non_evm_to_slot() -> None:
    """v0.34 (no fake wallets): SendParam.to is bytes32. A slot whose top 12
    bytes are NON-zero is a non-EVM address (Solana/Aptos pubkey) or a
    misaligned read, NOT an EVM address. The decoder must NOT surface its low
    20 bytes as a high-confidence EVM destination — that would fabricate a
    wallet. The chain still decodes from the intact dstEid."""
    valid = _build_stargate_v2_send_token(dst_eid=30110, to_addr="b" * 40)
    addr_slot = "0" * 24 + "b" * 40            # right-aligned EVM address
    corrupt_slot = "ff" * 12 + "b" * 40         # non-EVM/uint256: nonzero top
    assert addr_slot in valid
    corrupted = valid.replace(addr_slot, corrupt_slot, 1)
    out = decode_bridge_calldata(bridge_protocol="Stargate v2", input_data=corrupted)
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "arbitrum"          # dstEid intact
    assert out.destination_address != "0x" + "b" * 40    # bogus addr NOT surfaced
    assert out.destination_address is None


def test_stargate_v2_truncated_calldata_returns_low() -> None:
    """Truncated Stargate v2 calldata → low.

    Falls through Stargate v1 decoder first (which returns low),
    so v1's low result is returned (not v2's).
    """
    short = "0xcbef2aa9" + "00" * 32
    out = decode_bridge_calldata(
        bridge_protocol="Stargate v2",
        input_data=short,
    )
    # v1 doesn't recognize 0xcbef2aa9 so returns None; falls through
    # to v2 decoder which returns low for the truncated args.
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"


def test_stargate_v2_unknown_method_returns_none() -> None:
    """Unknown selector → None (after trying both v1 and v2 tables)."""
    out = decode_bridge_calldata(
        bridge_protocol="Stargate v2",
        input_data="0xdeadbeef" + "00" * 400,
    )
    assert out is None


def test_stargate_v2_unknown_eid_medium_confidence() -> None:
    """Unknown EID — receiver still salvageable → medium."""
    calldata = _build_stargate_v2_send_token(
        dst_eid=99999,            # Not in either LZ table
        to_addr="d" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Stargate v2",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain is None
    assert out.destination_address == "0x" + "d" * 40
    assert out.confidence == "medium"


def test_stargate_v2_1mb_calldata_does_not_crash() -> None:
    """1MB blob must not crash."""
    base = _build_stargate_v2_send_token(
        dst_eid=30101,            # Ethereum
        to_addr="a" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Stargate v2",
        input_data=base + "00" * 1_048_576,
    )
    assert isinstance(out, BridgeDecodeResult)


def test_stargate_v2_case_insensitive_protocol_dispatch() -> None:
    """'Stargate v2' / 'stargate v2' / 'Stargate v2: USDC Pool' all route."""
    calldata = _build_stargate_v2_send_token(
        dst_eid=30109,            # Polygon
        to_addr="e" * 40,
    )
    for label in (
        "Stargate v2",
        "stargate v2",
        "STARGATE v2",
        "Stargate v2: USDC Pool",
        "Stargate: Router on Arbitrum",     # falls through v1 then v2
    ):
        out = decode_bridge_calldata(
            bridge_protocol=label,
            input_data=calldata,
        )
        assert isinstance(out, BridgeDecodeResult), f"{label} did not dispatch"
        assert out.destination_chain == "polygon"


def test_stargate_v1_v2_dispatch_chain() -> None:
    """When the calldata has a v1 selector (0x9fbf10fc) but protocol
    string is 'Stargate v2', the v1 decoder fires first and returns a
    valid v1 result — the dispatcher does NOT fall through to v2."""
    # Use the existing v1 swap selector (which the v1 decoder owns).
    # Build enough args for the v1 min-length check (≥ 32 bytes).
    v1_calldata = "0x9fbf10fc" + _pad_uint(101, 1)   # dstChainId = 101 = ethereum
    out = decode_bridge_calldata(
        bridge_protocol="Stargate v2",
        input_data=v1_calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.bridge_method == "swap"     # v1 method, not sendToken_v2


# ═════════════════════════════════════════════════════════════════════════════
# 6. Symbiosis MetaRouter — re-test the existing decoder under the v0.31.4
#    narrowed scan window. The pre-existing fixtures (slots 0, 1, 3) all sit
#    inside the new 0..7 window, so they continue to decode high. The new
#    coverage below stress-tests the boundary (slot 7) and slot 8 (now
#    just outside the window).
# ═════════════════════════════════════════════════════════════════════════════


def _build_symbiosis_for_v031_4(
    *,
    method_id: str = "a11b1198",
    relay_recipient: str = "b" * 40,
    nested_chain_id: int = 137,
    nested_chain_id_slot: int = 1,
    nested_extra_slots: int = 5,
    first_dex_router: str = "1" * 40,
    second_dex_router: str = "2" * 40,
    amount: int = 1_000_000_000,
) -> str:
    """Build a Symbiosis metaRoute calldata blob — same shape as
    test_v031_2_symbiosis_decoder.py but kept local to avoid cross-test
    imports."""
    approved_tokens = [first_dex_router, second_dex_router]

    first_tail = _bytes_tail(b"")
    second_tail = _bytes_tail(b"")

    approved_tail = _pad_uint(len(approved_tokens), 1) + "".join(
        _pad_address(addr) for addr in approved_tokens
    )

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
        + _pad_uint(0, 1)
        + _pad_address(relay_recipient)
        + _pad_uint(off_other, 1)
    )
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


def test_symbiosis_slot_7_boundary_decodes() -> None:
    """ChainID at slot 7 (last slot in the v0.31.4 narrowed window) → high."""
    calldata = _build_symbiosis_for_v031_4(
        relay_recipient="b" * 40,
        nested_chain_id=137,
        nested_chain_id_slot=7,
        nested_extra_slots=8,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "polygon"
    assert out.confidence == "medium"  # v0.36: calldata decode is never 'high'


def test_symbiosis_slot_10_outside_window_falls_to_medium() -> None:
    """ChainID at slot 10 (outside the v0.31.4 narrowed window) →
    chain not extracted; recipient still salvageable → medium.

    Documents the v0.31.4 trade-off: narrower scan rejects late-slot
    chain IDs that might be amount-field collisions.
    """
    calldata = _build_symbiosis_for_v031_4(
        relay_recipient="c" * 40,
        nested_chain_id=137,
        nested_chain_id_slot=10,
        nested_extra_slots=12,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain is None
    assert out.destination_address == "0x" + "c" * 40
    assert out.confidence == "medium"


def test_symbiosis_unknown_method_returns_none() -> None:
    """Unknown selector → None (sanity for the symbiosis dispatch path)."""
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data="0xdeadbeef" + "00" * 400,
    )
    assert out is None


def test_symbiosis_truncated_returns_low() -> None:
    """Truncated → low (no crash)."""
    short = "0xa11b1198" + "00" * 32
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data=short,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"


def test_symbiosis_unknown_chain_id_medium_confidence() -> None:
    """Unknown chain ID — recipient still extractable → medium."""
    calldata = _build_symbiosis_for_v031_4(
        relay_recipient="d" * 40,
        nested_chain_id=12345678,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain is None
    assert out.destination_address == "0x" + "d" * 40
    assert out.confidence == "medium"


def test_symbiosis_1mb_calldata_does_not_crash() -> None:
    """1MB tail must not crash; valid prefix still decodes."""
    base = _build_symbiosis_for_v031_4(
        relay_recipient="a" * 40,
        nested_chain_id=10,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Symbiosis",
        input_data=base + "00" * 1_048_576,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "optimism"
    assert out.confidence == "medium"  # v0.36: calldata decode is never 'high'


def test_symbiosis_case_insensitive_protocol_dispatch() -> None:
    """Symbiosis case variants all route — covers v0.31.4 paranoia."""
    calldata = _build_symbiosis_for_v031_4(
        relay_recipient="e" * 40,
        nested_chain_id=42161,
    )
    for label in (
        "Symbiosis",
        "symbiosis",
        "SYMBIOSIS",
        "Symbiosis: MetaRouter (Ethereum)",
    ):
        out = decode_bridge_calldata(
            bridge_protocol=label,
            input_data=calldata,
        )
        assert isinstance(out, BridgeDecodeResult), f"{label} did not dispatch"
        assert out.destination_chain == "arbitrum"


# ═════════════════════════════════════════════════════════════════════════════
# Cross-cutting: dispatcher boundary between LayerZero + Stargate.
# 'LayerZero' must NOT be routed to the Stargate decoder even though both
# names share LZ infrastructure under the hood. Conversely, 'Stargate' must
# NOT be routed to the LayerZero decoder.
# ═════════════════════════════════════════════════════════════════════════════


def test_layerzero_is_not_routed_through_stargate_decoder() -> None:
    """A 'LayerZero' protocol name must NOT hit the Stargate decoder
    even though Stargate uses LZ internally. The dispatch guard is
    `'stargate' not in proto_lc` on the LayerZero branch.
    """
    calldata = _build_layerzero_v1_send(
        dst_chain_id=109,
        destination_addr="b" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="LayerZero",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    # LayerZero decoder's bridge_method is "send_v1"/"send_v2"; Stargate
    # decoder would return "swap"/"swapETH" — confirm we got LZ's method.
    assert out.bridge_method == "send_v1"


def test_stargate_is_not_routed_through_layerzero_decoder() -> None:
    """A 'Stargate' protocol name with a valid v1 swap selector must
    hit the Stargate v1 decoder, NOT the LayerZero decoder.
    """
    # Use the Stargate v1 swap selector.
    calldata = "0x9fbf10fc" + _pad_uint(110, 1)   # dstChainId = 110 (LZ id)
    out = decode_bridge_calldata(
        bridge_protocol="Stargate",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    # Stargate v1 decoder returns "swap"; LZ decoder would return "send_v1".
    assert out.bridge_method == "swap"
