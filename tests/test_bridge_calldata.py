"""Tests for v0.9.5 bridge calldata parsing.

Each test uses a real-shape calldata blob (constructed from
documented ABI encodings) to verify the decoder extracts the
right destination chain + address.

These are pure functions — no network, no DB. The full integration
(fetch input_data → decode → enrich CrossChainHandoff) is wired
into the brief assembly in a follow-up.
"""

from __future__ import annotations

from recupero.trace.bridge_calldata import (
    decode_bridge_calldata,
)

# ---- Empty / malformed input ---- #


def test_empty_input_returns_none() -> None:
    assert decode_bridge_calldata(
        bridge_protocol="Wormhole", input_data="",
    ) is None
    assert decode_bridge_calldata(
        bridge_protocol="Wormhole", input_data=None,
    ) is None


def test_too_short_input_returns_none() -> None:
    """Less than 4 method-id bytes = not parseable."""
    assert decode_bridge_calldata(
        bridge_protocol="Wormhole", input_data="0x12",
    ) is None


def test_unknown_protocol_returns_none() -> None:
    """Bridge we don't have a parser for → return None,
    don't crash. cross_chain.py falls back to the existing
    destination_chain_candidates list."""
    assert decode_bridge_calldata(
        bridge_protocol="DummyBridge",
        input_data="0xdeadbeef0000",
    ) is None


def test_unknown_method_id_returns_none() -> None:
    """Method id is one we don't recognize → None."""
    # 0xdeadbeef is not a valid Wormhole method id
    out = decode_bridge_calldata(
        bridge_protocol="Wormhole",
        input_data="0xdeadbeef" + "00" * 200,
    )
    assert out is None


# ---- Wormhole decoder ---- #


def _build_wormhole_transfer_calldata(
    *,
    token_address: str = "a" * 40,
    amount_hex: str = "0" * 62 + "01",  # 1 unit
    recipient_chain: int = 1,           # Solana
    recipient_bytes32: str = "b" * 64,
    arbiter_fee_hex: str = "0" * 64,
    nonce_hex: str = "0" * 64,
) -> str:
    """Build a synthetic Wormhole transferTokens calldata blob."""
    method_id = "0f5287b0"
    # Each 32-byte slot is 64 hex chars
    token_padded = "0" * 24 + token_address  # right-pad address to 32 bytes
    recipient_chain_padded = "0" * 60 + f"{recipient_chain:04x}"
    return (
        "0x" + method_id
        + token_padded
        + amount_hex
        + recipient_chain_padded
        + recipient_bytes32
        + arbiter_fee_hex
        + nonce_hex
    )


def test_wormhole_decode_solana_recipient() -> None:
    """Wormhole TokenBridge.transferTokens with recipientChain=1
    (Solana) → destination_chain='solana', recipient = 32-byte
    pubkey encoded to **base58** (v0.17.5 forensic CRIT fix).

    Pre-v0.17.5 the decoder returned a 0x-hex form that the
    downstream Solana adapter couldn't lookup — cross-chain BFS
    continuation silently dropped every Wormhole→Solana handoff.
    Now we encode to base58 here so callers don't need to know
    the destination chain to interpret destination_address.
    """
    pubkey_hex = "c" * 64  # 32 bytes
    calldata = _build_wormhole_transfer_calldata(
        recipient_chain=1, recipient_bytes32=pubkey_hex,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Wormhole", input_data=calldata,
    )
    assert out is not None
    assert out.destination_chain == "solana"
    # base58 of 32 bytes of 0xcc — round-trip-check rather than
    # hardcode the literal so the test exercises the encoder.
    from recupero.trace.bridge_calldata import _b58encode_no_checksum
    assert out.destination_address == _b58encode_no_checksum(
        bytes.fromhex(pubkey_hex)
    )
    assert out.bridge_method == "transferTokens"
    assert out.confidence == "high"


def test_wormhole_decode_ethereum_recipient() -> None:
    """Wormhole transfer to chain id 2 (Ethereum). Recipient bytes32
    has the EVM address right-padded → extract last 20 bytes."""
    eth_addr = "1234567890" * 4   # 20 bytes = 40 hex
    recipient_padded = "0" * 24 + eth_addr  # bytes32 = 32 bytes
    calldata = _build_wormhole_transfer_calldata(
        recipient_chain=2, recipient_bytes32=recipient_padded,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Wormhole", input_data=calldata,
    )
    assert out is not None
    assert out.destination_chain == "ethereum"
    assert out.destination_address == "0x" + eth_addr


def test_wormhole_decode_unknown_chain_id() -> None:
    """Wormhole chain id we don't have in the map → destination_chain
    is None, confidence='medium' (we have the recipient bytes32 but
    can't translate the chain)."""
    calldata = _build_wormhole_transfer_calldata(
        recipient_chain=9999, recipient_bytes32="d" * 64,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Wormhole", input_data=calldata,
    )
    assert out is not None
    assert out.destination_chain is None
    assert out.confidence == "medium"


# ---- Across decoder ---- #


def _build_across_deposit_v3_calldata(
    *,
    depositor: str = "a" * 40,
    recipient: str = "b" * 40,
    input_token: str = "c" * 40,
    output_token: str = "d" * 40,
    input_amount: str = "0" * 60 + "1000",  # 0x1000 = 4096
    output_amount: str = "0" * 60 + "0fa0",  # 0xfa0 = 4000
    destination_chain_id: int = 42161,        # Arbitrum
) -> str:
    """Build a synthetic Across depositV3 calldata blob."""
    method_id = "7b939232"
    def pad_addr(a: str) -> str:
        return "0" * 24 + a
    def pad_uint(u: int) -> str:
        return f"{u:064x}"
    return (
        "0x" + method_id
        + pad_addr(depositor)
        + pad_addr(recipient)
        + pad_addr(input_token)
        + pad_addr(output_token)
        + input_amount
        + output_amount
        + pad_uint(destination_chain_id)
    )


def test_across_depositv3_arbitrum() -> None:
    """Across depositV3 with destinationChainId=42161 → arbitrum
    + the recipient address extracted from the second arg."""
    recipient = "feed" + "00" * 18  # exactly 40 hex = 20 bytes
    calldata = _build_across_deposit_v3_calldata(
        recipient=recipient,
        destination_chain_id=42161,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Across", input_data=calldata,
    )
    assert out is not None
    assert out.destination_chain == "arbitrum"
    assert out.destination_address == "0x" + recipient
    assert out.bridge_method == "depositV3"
    assert out.confidence == "high"


def test_across_depositv3_optimism() -> None:
    """chainId=10 → optimism."""
    recipient = "abcd" + "00" * 18
    calldata = _build_across_deposit_v3_calldata(
        recipient=recipient,
        destination_chain_id=10,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Across", input_data=calldata,
    )
    assert out is not None
    assert out.destination_chain == "optimism"


def test_across_depositv3_unknown_chain() -> None:
    """Unknown chain id → destination_chain=None, confidence='medium'
    (we still extracted the recipient)."""
    calldata = _build_across_deposit_v3_calldata(
        destination_chain_id=99999,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Across", input_data=calldata,
    )
    assert out is not None
    assert out.destination_chain is None
    assert out.destination_address is not None
    assert out.confidence == "medium"


def test_across_truncated_calldata_returns_low_confidence() -> None:
    """Calldata too short for full decode → low confidence,
    no destination extracted."""
    out = decode_bridge_calldata(
        bridge_protocol="Across",
        input_data="0x7b939232" + "ab" * 50,  # only ~50 bytes
    )
    assert out is not None
    assert out.confidence == "low"
    assert out.destination_chain is None
    assert out.destination_address is None


# ---- Stargate decoder ---- #


def test_stargate_swap_extracts_chain_id() -> None:
    """Stargate swap() with LayerZero dstChainId=110 → arbitrum.

    We construct a minimal blob — the 'to' bytes extraction
    requires the full dynamic-bytes layout; medium confidence
    if we get the chain but not the address."""
    method_id = "9fbf10fc"
    lz_chain_id = 110  # Arbitrum
    # Minimal layout: just enough to extract dstChainId from slot 0
    calldata = (
        "0x" + method_id
        + f"{lz_chain_id:064x}"           # dstChainId slot 0
        + "0" * 64                        # srcPoolId
        + "0" * 64                        # dstPoolId
        + "0" * 64                        # refundAddress
        + "0" * 64                        # amountLD
        + "0" * 64                        # minAmountLD
        + "0" * 192                       # lzTxObj (3 slots)
        + "0" * 64                        # offset to 'to'
        + "0" * 64                        # offset to 'payload'
    )
    out = decode_bridge_calldata(
        bridge_protocol="Stargate", input_data=calldata,
    )
    assert out is not None
    assert out.destination_chain == "arbitrum"
    assert out.bridge_method == "swap"


def test_stargate_unknown_lz_chain() -> None:
    """LayerZero chain id we don't recognize → chain=None,
    confidence='low'."""
    method_id = "9fbf10fc"
    calldata = "0x" + method_id + f"{9999:064x}" + "0" * 1000
    out = decode_bridge_calldata(
        bridge_protocol="Stargate", input_data=calldata,
    )
    assert out is not None
    assert out.destination_chain is None


# ---- Forensic record ---- #


def test_raw_calldata_excerpt_included() -> None:
    """Every result carries the first 200 chars of calldata as a
    forensic record. Lets the operator manually re-decode if
    suspicious about the automated parse."""
    calldata = _build_across_deposit_v3_calldata()
    out = decode_bridge_calldata(
        bridge_protocol="Across", input_data=calldata,
    )
    assert out is not None
    assert out.raw_calldata_excerpt.startswith("7b939232")  # method id (no 0x)
    assert len(out.raw_calldata_excerpt) <= 400
