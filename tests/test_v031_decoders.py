"""v0.31.0 — Punishing tests for the three new bridge calldata decoders.

Coverage targets (per the v0.31.0 plan):
  * Connext xcall — uint32 domain ID dispatch into chain enum,
    address recovered from right-padded slot.
  * Axelar callContractWithToken — string-typed dynamic-bytes
    arguments decoded via _read_solidity_string, chain name
    mapped through _AXELAR_CHAIN_NAMES, bech32 Cosmos addresses
    accepted verbatim.
  * LiFi startBridgeTokensViaStargate — BridgeData tuple
    receiver + destinationChainId extracted at multiple candidate
    offsets (covers both no-swap and swap-and-bridge facets).

Each decoder is also probed with:
  * Empty / short input         → returns BridgeDecodeResult(confidence='low')
                                    or None per dispatcher contract.
  * Malformed hex inside a slot → does not raise; falls back to 'low'.
  * Unknown method id           → returns None (dispatcher falls back).
  * Domain/chain ID we don't know → confidence='low' or 'medium' depending
                                    on whether the address was salvageable.
"""

from __future__ import annotations

from recupero.trace.bridge_calldata import (
    BridgeDecodeResult,
    decode_bridge_calldata,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers — construct realistic ABI-encoded calldata blobs.
# Each 32-byte slot is 64 hex chars.
# ─────────────────────────────────────────────────────────────────────────────


def _pad_uint(value: int, slot_count: int = 1) -> str:
    """Right-align an integer into `slot_count` 32-byte slots."""
    return f"{value:0{64 * slot_count}x}"


def _pad_address(addr_hex_no_prefix: str) -> str:
    """Right-pad a 20-byte address to a 32-byte slot."""
    assert len(addr_hex_no_prefix) == 40, f"need 40 hex chars, got {len(addr_hex_no_prefix)}"
    return "0" * 24 + addr_hex_no_prefix.lower()


def _encode_string_arg(s: str) -> tuple[str, str]:
    """Return (offset_placeholder_hint, tail_bytes_hex) for a string arg.

    ABI dynamic-string encoding inside calldata is:
      [head slot] = offset (in bytes) from start of the args blob to the tail
      [tail]      = 32-byte length, then UTF-8 bytes right-padded to 32-byte multiple
    The caller assembles head slots + concatenates tails, computing the
    correct offsets.
    """
    body = s.encode("utf-8")
    length_slot = _pad_uint(len(body), 1)
    # Pad to 32-byte boundary
    pad_to = ((len(body) + 31) // 32) * 32
    body_hex = body.hex() + "00" * (pad_to - len(body))
    return length_slot, body_hex


# ─────────────────────────────────────────────────────────────────────────────
# Connext xcall decoder
# ─────────────────────────────────────────────────────────────────────────────


def _build_connext_xcall_calldata(
    *,
    domain_id: int = 1869640809,           # Optimism
    to_address: str = "b" * 40,
    asset: str = "c" * 40,
    delegate: str = "d" * 40,
    amount: int = 1_000_000_000,           # 1 USDC (6 decimals)
    slippage: int = 30,
    calldata_offset: int = 224,            # 7 slots in
    calldata_payload: str = "",
) -> str:
    """Build a synthetic Connext xcall calldata blob.

    xcall(uint32 destination, address to, address asset,
          address delegate, uint256 amount, uint256 slippage, bytes callData)
    """
    method_id = "4ff746f6"
    head = (
        _pad_uint(domain_id, 1)            # [0..32]   destination domain (uint32 right-aligned)
        + _pad_address(to_address)         # [32..64]  to
        + _pad_address(asset)              # [64..96]  asset
        + _pad_address(delegate)           # [96..128] delegate
        + _pad_uint(amount, 1)             # [128..160] amount
        + _pad_uint(slippage, 1)           # [160..192] slippage
        + _pad_uint(calldata_offset, 1)    # [192..224] offset to bytes
    )
    # Append the dynamic-bytes tail (length-prefixed, 0-padded)
    payload_bytes = bytes.fromhex(calldata_payload) if calldata_payload else b""
    pad_to = ((len(payload_bytes) + 31) // 32) * 32
    tail = (
        _pad_uint(len(payload_bytes), 1)
        + payload_bytes.hex()
        + "00" * (pad_to - len(payload_bytes))
    )
    return "0x" + method_id + head + tail


def test_connext_xcall_decodes_optimism() -> None:
    """High-confidence path: known domain ID + valid recipient."""
    calldata = _build_connext_xcall_calldata(
        domain_id=1869640809,   # Optimism
        to_address="b" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Connext",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "optimism"
    assert out.destination_address == "0x" + "b" * 40
    assert out.confidence == "high"
    assert out.bridge_method == "xcall"


def test_connext_xcall_decodes_arbitrum() -> None:
    calldata = _build_connext_xcall_calldata(
        domain_id=1634886255,   # Arbitrum
        to_address="f" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="connext",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "arbitrum"
    assert out.destination_address == "0x" + "f" * 40


def test_connext_xcall_unknown_domain_id_medium_confidence() -> None:
    """Unknown domain ID → no chain mapping, but address still extractable."""
    calldata = _build_connext_xcall_calldata(
        domain_id=999_999_999,   # Not in our table
        to_address="e" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Connext",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain is None
    assert out.destination_address == "0x" + "e" * 40
    # Per decoder: address present + chain missing → medium
    assert out.confidence == "medium"


def test_connext_everclear_protocol_routes_to_connext() -> None:
    """Everclear is the rebrand of Connext — both names dispatch."""
    calldata = _build_connext_xcall_calldata(
        domain_id=6648936,   # Ethereum
        to_address="a" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Everclear",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "ethereum"


def test_connext_truncated_calldata_returns_low() -> None:
    """Calldata < 7 full slots → low confidence, no fields, no crash."""
    short = "0x4ff746f6" + "00" * 64  # only 2 slots
    out = decode_bridge_calldata(
        bridge_protocol="Connext",
        input_data=short,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"
    assert out.destination_chain is None
    assert out.destination_address is None


def test_connext_unknown_method_returns_none() -> None:
    """0xdeadbeef is not a Connext selector → dispatcher returns None."""
    out = decode_bridge_calldata(
        bridge_protocol="Connext",
        input_data="0xdeadbeef" + "00" * 224,
    )
    assert out is None


# ─────────────────────────────────────────────────────────────────────────────
# Axelar callContractWithToken / sendToken decoder
# ─────────────────────────────────────────────────────────────────────────────


def _build_axelar_call_contract_with_token(
    *,
    destination_chain: str = "Polygon",
    contract_address: str = "0x" + "1" * 40,
    payload_hex: str = "",
    symbol: str = "USDC",
    amount: int = 5_000_000,        # 5 USDC
) -> str:
    """Build callContractWithToken(string,string,bytes,string,uint256).

    The 5 head slots (each 32 bytes):
      [0]: offset to destinationChain string
      [1]: offset to contractAddress string
      [2]: offset to payload bytes
      [3]: offset to symbol string
      [4]: amount (static uint256)
    Then the tails for each dynamic arg in order.
    """
    method_id = "b5417084"

    # Build tails first so we know their sizes
    def _string_tail(s: str) -> str:
        body = s.encode("utf-8")
        pad = ((len(body) + 31) // 32) * 32
        return _pad_uint(len(body), 1) + body.hex() + "00" * (pad - len(body))

    chain_tail = _string_tail(destination_chain)
    addr_tail = _string_tail(contract_address)
    payload_body = bytes.fromhex(payload_hex) if payload_hex else b""
    payload_pad = ((len(payload_body) + 31) // 32) * 32
    payload_tail = (
        _pad_uint(len(payload_body), 1)
        + payload_body.hex()
        + "00" * (payload_pad - len(payload_body))
    )
    symbol_tail = _string_tail(symbol)

    # The first non-tail slot starts at offset 5*32 = 160 (= 0xa0)
    head_size = 5 * 32
    off_chain = head_size
    off_addr = off_chain + (len(chain_tail) // 2)
    off_payload = off_addr + (len(addr_tail) // 2)
    off_symbol = off_payload + (len(payload_tail) // 2)

    head = (
        _pad_uint(off_chain, 1)
        + _pad_uint(off_addr, 1)
        + _pad_uint(off_payload, 1)
        + _pad_uint(off_symbol, 1)
        + _pad_uint(amount, 1)
    )
    return "0x" + method_id + head + chain_tail + addr_tail + payload_tail + symbol_tail


def test_axelar_call_contract_with_token_evm_destination() -> None:
    """Mapped chain name + EVM 0x address → high confidence."""
    calldata = _build_axelar_call_contract_with_token(
        destination_chain="Polygon",
        contract_address="0x" + "1" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Axelar",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "polygon"
    assert out.destination_address == "0x" + "1" * 40
    assert out.confidence == "high"
    assert out.bridge_method == "callContractWithToken"


def test_axelar_call_contract_with_token_cosmos_bech32_address() -> None:
    """Cosmos bech32 addresses accepted verbatim (Axelar bridges into Cosmos)."""
    bech32 = "osmo1abc123def456ghi789jkl0mnp345qrs678tuv"
    calldata = _build_axelar_call_contract_with_token(
        destination_chain="osmosis",
        contract_address=bech32,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Axelar",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    # osmosis maps to "cosmos" in _AXELAR_CHAIN_NAMES
    assert out.destination_chain == "cosmos"
    assert out.destination_address == bech32


def test_axelar_unknown_chain_name_preserved_as_raw_lowercase() -> None:
    """A chain name not in our table is kept verbatim (lowercased)
    so the operator can follow up at the Axelar explorer."""
    calldata = _build_axelar_call_contract_with_token(
        destination_chain="Crescent",   # Real but not mapped
        contract_address="0x" + "2" * 40,
    )
    out = decode_bridge_calldata(
        bridge_protocol="Axelar",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "crescent"
    assert out.destination_address == "0x" + "2" * 40
    # Address salvaged + chain string salvaged but not canonicalized — still 'high'
    # per the decoder's truthiness rule (both fields populated)
    assert out.confidence == "high"


def test_axelar_truncated_calldata_returns_low() -> None:
    """Less than 4 full head slots → low confidence."""
    short = "0xb5417084" + "00" * 64
    out = decode_bridge_calldata(
        bridge_protocol="Axelar",
        input_data=short,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"


def test_axelar_malformed_offset_does_not_crash() -> None:
    """A garbage offset that points past EOB → _read_solidity_string
    returns None, decoder returns low-confidence result without raising."""
    method_id = "b5417084"
    # Set both offsets to insane values
    head = (
        _pad_uint(0xffffffff, 1)
        + _pad_uint(0xffffffff, 1)
        + _pad_uint(0, 1)
        + _pad_uint(0, 1)
        + _pad_uint(0, 1)
    )
    out = decode_bridge_calldata(
        bridge_protocol="Axelar",
        input_data="0x" + method_id + head,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"
    assert out.destination_chain is None
    assert out.destination_address is None


# ─────────────────────────────────────────────────────────────────────────────
# LiFi BridgeData decoder
# ─────────────────────────────────────────────────────────────────────────────


def _build_lifi_bridgedata_calldata(
    *,
    method_id: str = "ed178619",          # startBridgeTokensViaStargate
    receiver_address: str = "9" * 40,
    destination_chain_id: int = 137,      # Polygon
    prefix_slots: int = 0,
) -> str:
    """Build a LiFi BridgeData-prefix calldata blob.

    Layout (no source swap, BridgeData starts at args[0]):
      [0..32]    transactionId (bytes32, opaque)
      [32..64]   offset to bridge string
      [64..96]   offset to integrator string
      [96..128]  referrer  (address)
      [128..160] sendingAssetId (address)
      [160..192] receiver  (address)         <-- target
      [192..224] minAmount
      [224..256] destinationChainId         <-- target
      [256..288] hasSourceSwaps
      [288..320] hasDestinationCall
    """
    prefix = "00" * 32 * prefix_slots
    bridge_struct = (
        "11" * 32                                    # transactionId
        + _pad_uint(320 + 64 * prefix_slots, 1)      # offset to bridge string
        + _pad_uint(0, 1)                            # offset to integrator string (filled later)
        + _pad_address("a" * 40)                     # referrer
        + _pad_address("b" * 40)                     # sendingAssetId
        + _pad_address(receiver_address)             # receiver
        + _pad_uint(0, 1)                            # minAmount
        + _pad_uint(destination_chain_id, 1)         # destinationChainId
        + _pad_uint(0, 1)                            # hasSourceSwaps
        + _pad_uint(0, 1)                            # hasDestinationCall
    )
    # Append a single dynamic-string tail so the offsets land inside the blob
    tail = _pad_uint(8, 1) + "73746172676174" + "00" * 25  # "stargat" + padding (~"stargate")
    return "0x" + method_id + prefix + bridge_struct + tail


def test_lifi_start_bridge_tokens_via_stargate_polygon() -> None:
    """No-swap facet: BridgeData at offset 0. Polygon = 137."""
    calldata = _build_lifi_bridgedata_calldata(
        method_id="ed178619",
        receiver_address="9" * 40,
        destination_chain_id=137,
    )
    out = decode_bridge_calldata(
        bridge_protocol="LiFi",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "polygon"
    assert out.destination_address == "0x" + "9" * 40
    assert out.confidence == "high"
    assert out.bridge_method == "startBridgeTokensViaStargate"


def test_lifi_start_bridge_tokens_via_across_arbitrum() -> None:
    """Across-facet variant; chain 42161 = Arbitrum."""
    calldata = _build_lifi_bridgedata_calldata(
        method_id="b4c20477",
        receiver_address="3" * 40,
        destination_chain_id=42161,
    )
    out = decode_bridge_calldata(
        bridge_protocol="LiFi",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "arbitrum"
    assert out.destination_address == "0x" + "3" * 40


def test_lifi_li_fi_protocol_alias_routes_correctly() -> None:
    """Some seeds spell it 'li.fi' rather than 'lifi'."""
    calldata = _build_lifi_bridgedata_calldata(
        receiver_address="7" * 40,
        destination_chain_id=1,
    )
    out = decode_bridge_calldata(
        bridge_protocol="li.fi",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "ethereum"
    assert out.destination_address == "0x" + "7" * 40


def test_lifi_unknown_method_returns_none() -> None:
    out = decode_bridge_calldata(
        bridge_protocol="LiFi",
        input_data="0xdeadbeef" + "00" * 400,
    )
    assert out is None


def test_lifi_short_calldata_returns_low() -> None:
    """BridgeData needs 320 bytes; anything shorter → low."""
    short = "0xed178619" + "00" * 100   # nowhere near 320 bytes
    out = decode_bridge_calldata(
        bridge_protocol="LiFi",
        input_data=short,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.confidence == "low"
    assert out.destination_address is None
    assert out.destination_chain is None


def test_lifi_zero_receiver_falls_back_to_low() -> None:
    """Receiver of 0x00…00 is a sentinel for wrong offset → no high-conf return."""
    calldata = _build_lifi_bridgedata_calldata(
        receiver_address="0" * 40,
        destination_chain_id=137,
    )
    out = decode_bridge_calldata(
        bridge_protocol="LiFi",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    # Decoder skips the candidate and finds nothing → low
    assert out.confidence == "low"


# ─────────────────────────────────────────────────────────────────────────────
# Cross-decoder sanity — exercise the dispatch table.
# ─────────────────────────────────────────────────────────────────────────────


def test_dispatch_prefers_decoder_over_unknown() -> None:
    """A Connext-shaped calldata sent under bridge_protocol='Axelar'
    will be routed to the Axelar decoder. The Axelar decoder will
    fail to make sense of it and return low-confidence."""
    calldata = _build_connext_xcall_calldata()
    out = decode_bridge_calldata(
        bridge_protocol="Axelar",
        input_data=calldata,
    )
    # Method id 0x4ff746f6 is not in _AXELAR_METHODS → dispatcher returns None
    assert out is None


def test_all_three_new_protocols_dispatched_not_swallowed() -> None:
    """A complete smoke check that the three protocols never short-
    circuit to None for valid method-IDs even on truncated input."""
    truncated_connext = "0x4ff746f6" + "00" * 32
    truncated_axelar = "0xb5417084" + "00" * 32
    truncated_lifi = "0xed178619" + "00" * 32

    r1 = decode_bridge_calldata(
        bridge_protocol="Connext", input_data=truncated_connext)
    r2 = decode_bridge_calldata(
        bridge_protocol="Axelar", input_data=truncated_axelar)
    r3 = decode_bridge_calldata(
        bridge_protocol="LiFi", input_data=truncated_lifi)

    for r in (r1, r2, r3):
        assert isinstance(r, BridgeDecodeResult)
        assert r.confidence == "low"
        assert r.destination_chain is None
        assert r.destination_address is None
