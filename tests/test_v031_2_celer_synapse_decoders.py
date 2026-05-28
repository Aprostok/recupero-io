"""v0.31.2 — Punishing tests for the Celer cBridge + Synapse decoders.

Two more bridges promoted out of recognition-only (gap #2 continuation):
  * Celer cBridge — `send(address,address,uint256,uint64,uint64,uint32)`
    and `sendNative(address,uint256,uint64,uint64,uint32)`. EVM
    chainID dispatch (real chain IDs, not Wormhole or LayerZero).
  * Synapse Protocol — `bridge(address,uint256,address,uint256)` and
    `swapAndRedeem(...)`. Both put (to, chainId) in the first two
    static slots, so a single reader handles either selector.

Each decoder is probed with:
  * Happy path — known EVM chain ID → confidence='high', chain +
    recipient extracted.
  * Truncated calldata → confidence='low', no fields, no crash.
  * Unknown method id → None (dispatcher falls back).
  * Case-insensitive protocol dispatch (cBridge / celer / CELER /
    Synapse / SYNAPSE) → routed to the right decoder.
"""

from __future__ import annotations

from recupero.trace.bridge_calldata import (
    BridgeDecodeResult,
    decode_bridge_calldata,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — same ABI-encoding shape as test_v031_decoders.py. Copied
# locally so this test file is self-contained (no cross-test imports).
# ─────────────────────────────────────────────────────────────────────────────


def _pad_uint(value: int, slot_count: int = 1) -> str:
    """Right-align an integer into `slot_count` 32-byte slots."""
    return f"{value:0{64 * slot_count}x}"


def _pad_address(addr_hex_no_prefix: str) -> str:
    """Right-pad a 20-byte address to a 32-byte slot."""
    assert len(addr_hex_no_prefix) == 40, f"need 40 hex chars, got {len(addr_hex_no_prefix)}"
    return "0" * 24 + addr_hex_no_prefix.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Celer cBridge decoder
# ─────────────────────────────────────────────────────────────────────────────


def _build_celer_send_calldata(
    *,
    receiver: str = "b" * 40,
    token: str = "c" * 40,
    amount: int = 1_000_000_000,        # 1 USDC (6 decimals)
    dst_chain_id: int = 137,            # Polygon
    nonce: int = 42,
    max_slippage: int = 50_000,         # bps × 100
) -> str:
    """Build a synthetic Celer `send` calldata blob.

    send(address receiver, address token, uint256 amount,
         uint64 dstChainId, uint64 nonce, uint32 maxSlippage)
    """
    method_id = "a5977fbb"
    head = (
        _pad_address(receiver)              # [0..32]    receiver
        + _pad_address(token)               # [32..64]   token
        + _pad_uint(amount, 1)              # [64..96]   amount
        + _pad_uint(dst_chain_id, 1)        # [96..128]  dstChainId (uint64 right-aligned)
        + _pad_uint(nonce, 1)               # [128..160] nonce
        + _pad_uint(max_slippage, 1)        # [160..192] maxSlippage
    )
    return "0x" + method_id + head


def _build_celer_send_native_calldata(
    *,
    receiver: str = "b" * 40,
    amount: int = 1_000_000_000_000_000_000,   # 1 ETH (18 decimals)
    dst_chain_id: int = 42161,                 # Arbitrum
    nonce: int = 7,
    max_slippage: int = 50_000,
) -> str:
    """Build a synthetic Celer `sendNative` calldata blob.

    sendNative(address receiver, uint256 amount,
               uint64 dstChainId, uint64 nonce, uint32 maxSlippage)
    """
    method_id = "e957bf91"
    head = (
        _pad_address(receiver)              # [0..32]    receiver
        + _pad_uint(amount, 1)              # [32..64]   amount
        + _pad_uint(dst_chain_id, 1)        # [64..96]   dstChainId (uint64 right-aligned)
        + _pad_uint(nonce, 1)               # [96..128]  nonce
        + _pad_uint(max_slippage, 1)        # [128..160] maxSlippage
    )
    return "0x" + method_id + head


def test_celer_send_decodes_polygon() -> None:
    """High-confidence path: known EVM chain ID + valid recipient."""
    calldata = _build_celer_send_calldata(
        receiver="b" * 40,
        dst_chain_id=137,    # Polygon
    )
    out = decode_bridge_calldata(
        bridge_protocol="Celer",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "polygon"
    assert out.destination_address == "0x" + "b" * 40
    assert out.confidence == "high"
    assert out.bridge_method == "send"


def test_celer_send_native_decodes_arbitrum() -> None:
    """sendNative variant — recipient + chain still extractable."""
    calldata = _build_celer_send_native_calldata(
        receiver="f" * 40,
        dst_chain_id=42161,   # Arbitrum
    )
    out = decode_bridge_calldata(
        bridge_protocol="cBridge",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "arbitrum"
    assert out.destination_address == "0x" + "f" * 40
    assert out.confidence == "high"
    assert out.bridge_method == "sendNative"


def test_celer_truncated_calldata_returns_low() -> None:
    """Calldata < 5 full slots → low confidence, no fields, no crash."""
    short = "0xa5977fbb" + "00" * 64   # only 2 slots
    out = decode_bridge_calldata(
        bridge_protocol="Celer",
        input_data=short,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"
    assert out.destination_chain is None
    assert out.destination_address is None


def test_celer_unknown_method_returns_none() -> None:
    """0xdeadbeef is not a Celer selector → dispatcher returns None."""
    out = decode_bridge_calldata(
        bridge_protocol="Celer",
        input_data="0xdeadbeef" + "00" * 200,
    )
    assert out is None


def test_celer_case_insensitive_protocol_dispatch() -> None:
    """Both 'cBridge' / 'celer' / 'CELER' route to the Celer decoder."""
    calldata = _build_celer_send_calldata(
        receiver="a" * 40,
        dst_chain_id=1,   # Ethereum
    )
    for protocol_name in ("cBridge", "celer", "CELER", "Celer Network"):
        out = decode_bridge_calldata(
            bridge_protocol=protocol_name,
            input_data=calldata,
        )
        assert isinstance(out, BridgeDecodeResult), f"{protocol_name} did not dispatch"
        assert out.destination_chain == "ethereum"
        assert out.destination_address == "0x" + "a" * 40


# ─────────────────────────────────────────────────────────────────────────────
# Synapse Protocol decoder
# ─────────────────────────────────────────────────────────────────────────────


def _build_synapse_bridge_calldata(
    *,
    to: str = "9" * 40,
    chain_id: int = 42161,            # Arbitrum
    token: str = "e" * 40,
    amount: int = 5_000_000,          # 5 USDC
) -> str:
    """Build a synthetic Synapse `bridge` calldata blob.

    bridge(address to, uint256 chainId, IERC20 token, uint256 amount)
    """
    method_id = "fa9d8e22"
    head = (
        _pad_address(to)               # [0..32]   to
        + _pad_uint(chain_id, 1)       # [32..64]  chainId (uint256)
        + _pad_address(token)          # [64..96]  token
        + _pad_uint(amount, 1)         # [96..128] amount
    )
    return "0x" + method_id + head


def _build_synapse_swap_and_redeem_calldata(
    *,
    to: str = "9" * 40,
    chain_id: int = 8453,             # Base
    token: str = "e" * 40,
    token_index_from: int = 0,
    token_index_to: int = 1,
    dx: int = 5_000_000,
    min_dy: int = 4_950_000,
    deadline: int = 9_999_999_999,
) -> str:
    """Build a synthetic Synapse `swapAndRedeem` calldata blob.

    swapAndRedeem(address to, uint256 chainId, IERC20 token,
                  uint8 tokenIndexFrom, uint8 tokenIndexTo,
                  uint256 dx, uint256 minDy, uint256 deadline)
    """
    method_id = "f1a64348"
    head = (
        _pad_address(to)                       # [0..32]    to
        + _pad_uint(chain_id, 1)               # [32..64]   chainId
        + _pad_address(token)                  # [64..96]   token
        + _pad_uint(token_index_from, 1)       # [96..128]  tokenIndexFrom
        + _pad_uint(token_index_to, 1)         # [128..160] tokenIndexTo
        + _pad_uint(dx, 1)                     # [160..192] dx
        + _pad_uint(min_dy, 1)                 # [192..224] minDy
        + _pad_uint(deadline, 1)               # [224..256] deadline
    )
    return "0x" + method_id + head


def test_synapse_bridge_decodes_arbitrum() -> None:
    """High-confidence path: known EVM chain ID + valid recipient."""
    calldata = _build_synapse_bridge_calldata(
        to="9" * 40,
        chain_id=42161,   # Arbitrum
    )
    out = decode_bridge_calldata(
        bridge_protocol="Synapse",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "arbitrum"
    assert out.destination_address == "0x" + "9" * 40
    assert out.confidence == "high"
    assert out.bridge_method == "bridge"


def test_synapse_swap_and_redeem_decodes_base() -> None:
    """swapAndRedeem variant shares the (to, chainId) prefix."""
    calldata = _build_synapse_swap_and_redeem_calldata(
        to="3" * 40,
        chain_id=8453,    # Base
    )
    out = decode_bridge_calldata(
        bridge_protocol="Synapse",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "base"
    assert out.destination_address == "0x" + "3" * 40
    assert out.confidence == "high"
    assert out.bridge_method == "swapAndRedeem"


def test_synapse_truncated_calldata_returns_low() -> None:
    """Calldata < 2 full slots → low confidence, no fields, no crash."""
    short = "0xfa9d8e22" + "00" * 32   # only 1 slot
    out = decode_bridge_calldata(
        bridge_protocol="Synapse",
        input_data=short,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"
    assert out.destination_chain is None
    assert out.destination_address is None


def test_synapse_unknown_method_returns_none() -> None:
    """0xdeadbeef is not a Synapse selector → dispatcher returns None."""
    out = decode_bridge_calldata(
        bridge_protocol="Synapse",
        input_data="0xdeadbeef" + "00" * 128,
    )
    assert out is None


def test_synapse_case_insensitive_protocol_dispatch() -> None:
    """'Synapse' / 'synapse' / 'SYNAPSE' all route to the Synapse decoder."""
    calldata = _build_synapse_bridge_calldata(
        to="c" * 40,
        chain_id=10,   # Optimism
    )
    for protocol_name in ("Synapse", "synapse", "SYNAPSE", "Synapse Protocol"):
        out = decode_bridge_calldata(
            bridge_protocol=protocol_name,
            input_data=calldata,
        )
        assert isinstance(out, BridgeDecodeResult), f"{protocol_name} did not dispatch"
        assert out.destination_chain == "optimism"
        assert out.destination_address == "0x" + "c" * 40


# ─────────────────────────────────────────────────────────────────────────────
# Cross-decoder sanity — verify the dispatch table doesn't conflate
# protocols and that unknown-chain-id paths degrade gracefully.
# ─────────────────────────────────────────────────────────────────────────────


def test_celer_unknown_chain_id_medium_confidence() -> None:
    """Unknown EVM chain ID → no chain mapping, but recipient extractable."""
    calldata = _build_celer_send_calldata(
        receiver="e" * 40,
        dst_chain_id=999_999_999,   # Not in _EVM_CHAIN_BY_ID
    )
    out = decode_bridge_calldata(
        bridge_protocol="Celer",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain is None
    assert out.destination_address == "0x" + "e" * 40
    assert out.confidence == "medium"


def test_synapse_unknown_chain_id_medium_confidence() -> None:
    """Unknown EVM chain ID — recipient salvaged → medium."""
    calldata = _build_synapse_bridge_calldata(
        to="d" * 40,
        chain_id=12345,   # Not in _EVM_CHAIN_BY_ID
    )
    out = decode_bridge_calldata(
        bridge_protocol="Synapse",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain is None
    assert out.destination_address == "0x" + "d" * 40
    assert out.confidence == "medium"
