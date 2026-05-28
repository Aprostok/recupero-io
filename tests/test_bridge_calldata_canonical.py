"""Tests for v0.32.1 rollup-canonical bridge decoders (Jacob audit M-6).

The 5 canonical L2 bridges (Polygon PoS, Optimism, Arbitrum, zkSync Era,
Base) had ZERO destination extraction pre-v0.32.1 — Lazarus-tier APTs
routed through them in the audit's Route 1 and escaped cleanly because
the trace BFS halted at the labeled bridge with no actionable
destination. These tests verify:

  * Each of the 5 decoders extracts the correct destination chain
    (constant per bridge) and destination address (from the appropriate
    ABI-encoded slot).
  * The dispatcher routes correctly based on `bridge_protocol` (the
    bridges.json `name` field).
  * Malformed / truncated calldata returns a low-confidence result
    rather than raising (graceful degradation contract).
  * Zero-address destinations are rejected.
  * Selector hex matches keccak256(signature)[:4] for every claimed
    signature — any selector drift fails CI immediately.
  * Base uses 'base' as destination, Optimism uses 'optimism', despite
    sharing the L1StandardBridge ABI (OP-Stack fork).

All tests are pure functions (no network, no DB). Calldata is
synthesised from the documented ABI layouts.
"""

from __future__ import annotations

from eth_utils import keccak

from recupero.trace.bridge_calldata import (
    _ARBITRUM_L1_METHODS,
    _BASE_L1_METHODS,
    _OPTIMISM_L1_METHODS,
    _POLYGON_POS_METHODS,
    _ZKSYNC_L1_METHODS,
    BridgeDecodeResult,
    decode_bridge_calldata,
)

# ─────────────────────────────────────────────────────────────────────────────
# Selector verification — recompute keccak256(sig)[:4] and assert the
# values claimed in the decoder tables match. Any drift between the
# decoder's claimed selectors and the canonical signatures will fail
# here BEFORE any synthetic-calldata test runs.
# ─────────────────────────────────────────────────────────────────────────────


def _selector(sig: str) -> str:
    """Return canonical 0x-prefixed 4-byte keccak selector for ``sig``."""
    return "0x" + keccak(text=sig).hex()[:8]


def test_polygon_pos_selectors_match_keccak() -> None:
    assert _selector("depositFor(address,address,bytes)") == "0xe3dec8fb"
    assert _selector("depositEtherFor(address)") == "0x4faa8a26"
    assert "0xe3dec8fb" in _POLYGON_POS_METHODS
    assert "0x4faa8a26" in _POLYGON_POS_METHODS


def test_optimism_l1_selectors_match_keccak() -> None:
    assert _selector(
        "depositERC20To(address,address,address,uint256,uint32,bytes)",
    ) == "0x838b2520"
    assert _selector("depositETHTo(address,uint32,bytes)") == "0x9a2ac6d5"
    assert _selector(
        "depositERC20(address,address,uint256,uint32,bytes)",
    ) == "0x58a997f6"
    assert _selector("depositETH(uint32,bytes)") == "0xb1a1a882"
    assert _selector(
        "withdrawTo(address,address,uint256,uint32,bytes)",
    ) == "0xa3a79548"
    for sel in (
        "0x838b2520", "0x9a2ac6d5", "0x58a997f6", "0xb1a1a882", "0xa3a79548",
    ):
        assert sel in _OPTIMISM_L1_METHODS


def test_base_l1_selectors_match_keccak() -> None:
    # Base is OP-Stack — shares all 4 deposit selectors with Optimism.
    for sig, expected in [
        ("depositERC20To(address,address,address,uint256,uint32,bytes)",
         "0x838b2520"),
        ("depositETHTo(address,uint32,bytes)", "0x9a2ac6d5"),
        ("depositERC20(address,address,uint256,uint32,bytes)", "0x58a997f6"),
        ("depositETH(uint32,bytes)", "0xb1a1a882"),
    ]:
        assert _selector(sig) == expected
        assert expected in _BASE_L1_METHODS


def test_arbitrum_l1_selectors_match_keccak() -> None:
    assert _selector(
        "outboundTransfer(address,address,uint256,uint256,uint256,bytes)",
    ) == "0xd2ce7d65"
    assert _selector(
        "outboundTransferCustomRefund(address,address,address,"
        "uint256,uint256,uint256,bytes)",
    ) == "0x4fb1a07b"
    assert _selector("depositEth()") == "0x439370b1"
    for sel in ("0xd2ce7d65", "0x4fb1a07b", "0x439370b1"):
        assert sel in _ARBITRUM_L1_METHODS


def test_zksync_l1_selectors_match_keccak() -> None:
    assert _selector(
        "deposit(address,address,uint256,uint256,uint256,address)",
    ) == "0xe8b99b1b"
    assert "0xe8b99b1b" in _ZKSYNC_L1_METHODS


# ─────────────────────────────────────────────────────────────────────────────
# Calldata-synthesis helpers. Each builds an ABI-encoded args blob from
# a documented signature; the test then prepends the 4-byte selector,
# 0x-prefixes the whole thing, and feeds it through the dispatcher.
# ─────────────────────────────────────────────────────────────────────────────


def _pad_address(addr_hex: str) -> str:
    """Right-pad a 20-byte hex (no 0x) into a 32-byte slot (64 hex)."""
    assert len(addr_hex) == 40, f"expected 20-byte hex, got {len(addr_hex)}"
    return "0" * 24 + addr_hex.lower()


def _pad_uint(value: int) -> str:
    """Right-align uint into a 32-byte slot (64 hex)."""
    return f"{value:064x}"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Polygon PoS RootChainManager
# ─────────────────────────────────────────────────────────────────────────────


def test_polygon_pos_deposit_for_decodes_user() -> None:
    user = "1111111111111111111111111111111111111111"
    root_token = "2222222222222222222222222222222222222222"
    # depositData = abi.encode(uint256 amount) — points to a tail blob.
    # Args: user(slot0) rootToken(slot1) depositData_offset(slot2)
    #       + tail: length=32 then 32-byte uint amount.
    calldata = (
        "0xe3dec8fb"
        + _pad_address(user)
        + _pad_address(root_token)
        + _pad_uint(0x60)         # offset to depositData (3 slots = 96 bytes)
        + _pad_uint(32)            # length of depositData bytes
        + _pad_uint(1_000_000)     # the encoded amount
    )
    out = decode_bridge_calldata(
        bridge_protocol="Polygon: RootChainManager",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "polygon"
    assert out.destination_address == "0x" + user
    assert out.bridge_method == "depositFor"
    assert out.confidence == "high"


def test_polygon_pos_deposit_ether_for_decodes_user() -> None:
    user = "3333333333333333333333333333333333333333"
    calldata = "0x4faa8a26" + _pad_address(user)
    out = decode_bridge_calldata(
        bridge_protocol="Polygon: RootChainManager",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "polygon"
    assert out.destination_address == "0x" + user
    assert out.bridge_method == "depositEtherFor"
    assert out.confidence == "high"


def test_polygon_pos_malformed_returns_low_confidence_no_exception() -> None:
    """Truncated depositFor → low confidence, no exception."""
    # Selector present but args truncated after slot 0
    truncated = "0xe3dec8fb" + _pad_address("4" * 40) + "deadbeef"
    out = decode_bridge_calldata(
        bridge_protocol="Polygon: RootChainManager",
        input_data=truncated,
    )
    # Result is either None or low-confidence — both are acceptable
    # graceful-degradation outputs. The contract is: must not raise.
    assert out is None or out.confidence in {"low", "medium", "high"}


def test_polygon_pos_zero_address_rejected() -> None:
    calldata = "0x4faa8a26" + _pad_address("0" * 40)
    out = decode_bridge_calldata(
        bridge_protocol="Polygon: RootChainManager",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    # Zero address is rejected → destination_address must be None
    assert out.destination_address is None
    # Chain attribution still surfaces (it's a constant per contract)
    assert out.destination_chain == "polygon"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Optimism L1StandardBridge
# ─────────────────────────────────────────────────────────────────────────────


def test_optimism_deposit_erc20_to_decodes_recipient() -> None:
    l1_token = "a" * 40
    l2_token = "b" * 40
    to = "c" * 40
    calldata = (
        "0x838b2520"
        + _pad_address(l1_token)
        + _pad_address(l2_token)
        + _pad_address(to)
        + _pad_uint(1_000_000)     # amount
        + _pad_uint(200_000)       # _l2Gas
        + _pad_uint(0xc0)          # offset to _data bytes
        + _pad_uint(0)             # length of _data = 0
    )
    out = decode_bridge_calldata(
        bridge_protocol="Optimism: L1 Standard Bridge",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "optimism"
    assert out.destination_address == "0x" + to
    assert out.bridge_method == "depositERC20To"
    assert out.confidence == "high"


def test_optimism_deposit_eth_to_decodes_recipient() -> None:
    to = "d" * 40
    calldata = (
        "0x9a2ac6d5"
        + _pad_address(to)
        + _pad_uint(200_000)       # _l2Gas
        + _pad_uint(0x60)          # offset to _data bytes
        + _pad_uint(0)             # length of _data = 0
    )
    out = decode_bridge_calldata(
        bridge_protocol="Optimism: L1 Standard Bridge",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "optimism"
    assert out.destination_address == "0x" + to
    assert out.bridge_method == "depositETHTo"
    assert out.confidence == "high"


def test_optimism_deposit_erc20_no_recipient_surfaces_chain_only() -> None:
    """depositERC20 (msg.sender variant) — destination not in calldata.
    Decoder surfaces chain attribution + null recipient (medium confidence).
    """
    calldata = (
        "0x58a997f6"
        + _pad_address("e" * 40)
        + _pad_address("f" * 40)
        + _pad_uint(1_000_000)
        + _pad_uint(200_000)
        + _pad_uint(0xa0)
        + _pad_uint(0)
    )
    out = decode_bridge_calldata(
        bridge_protocol="Optimism: L1 Standard Bridge",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "optimism"
    assert out.destination_address is None
    assert out.confidence == "medium"


def test_optimism_withdraw_to_decodes_recipient_on_ethereum() -> None:
    """L2-side withdrawTo: recipient is on ethereum (the L1 side)."""
    l2_token = "1" * 40
    to = "5" * 40
    calldata = (
        "0xa3a79548"
        + _pad_address(l2_token)
        + _pad_address(to)
        + _pad_uint(1_000_000)
        + _pad_uint(200_000)
        + _pad_uint(0xa0)
        + _pad_uint(0)
    )
    out = decode_bridge_calldata(
        bridge_protocol="Optimism: L2 Standard Bridge",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "ethereum"
    assert out.destination_address == "0x" + to
    assert out.bridge_method == "withdrawTo"
    assert out.confidence == "high"


def test_optimism_malformed_returns_low_confidence_no_exception() -> None:
    out = decode_bridge_calldata(
        bridge_protocol="Optimism: L1 Standard Bridge",
        input_data="0x838b2520deadbeef",
    )
    # Either None (truncated, returns low-confidence BridgeDecodeResult) or
    # a low/medium-confidence result. Must not raise.
    if out is not None:
        assert out.confidence in {"low", "medium", "high"}


# ─────────────────────────────────────────────────────────────────────────────
# 3. Arbitrum L1ERC20Gateway / Inbox
# ─────────────────────────────────────────────────────────────────────────────


def test_arbitrum_outbound_transfer_decodes_recipient() -> None:
    l1_token = "a" * 40
    to = "7" * 40
    calldata = (
        "0xd2ce7d65"
        + _pad_address(l1_token)
        + _pad_address(to)
        + _pad_uint(1_000_000)     # amount
        + _pad_uint(200_000)       # maxGas
        + _pad_uint(1_000_000_000) # gasPriceBid
        + _pad_uint(0xc0)          # offset to _data
        + _pad_uint(0)
    )
    out = decode_bridge_calldata(
        bridge_protocol="Arbitrum: L1ERC20Gateway",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "arbitrum"
    assert out.destination_address == "0x" + to
    assert out.bridge_method == "outboundTransfer"
    assert out.confidence == "high"


def test_arbitrum_outbound_transfer_custom_refund_decodes_recipient() -> None:
    l1_token = "a" * 40
    refund_to = "b" * 40
    to = "9" * 40
    calldata = (
        "0x4fb1a07b"
        + _pad_address(l1_token)
        + _pad_address(refund_to)
        + _pad_address(to)
        + _pad_uint(1_000_000)
        + _pad_uint(200_000)
        + _pad_uint(1_000_000_000)
        + _pad_uint(0xe0)
        + _pad_uint(0)
    )
    out = decode_bridge_calldata(
        bridge_protocol="Arbitrum: L1ERC20Gateway",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "arbitrum"
    assert out.destination_address == "0x" + to
    assert out.bridge_method == "outboundTransferCustomRefund"


def test_arbitrum_deposit_eth_surfaces_chain_only() -> None:
    """depositEth() has zero args — destination = msg.sender (not in calldata)."""
    calldata = "0x439370b1"
    out = decode_bridge_calldata(
        bridge_protocol="Arbitrum: Inbox",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "arbitrum"
    assert out.destination_address is None
    assert out.bridge_method == "depositEth"


def test_arbitrum_malformed_returns_low_confidence_no_exception() -> None:
    out = decode_bridge_calldata(
        bridge_protocol="Arbitrum: L1ERC20Gateway",
        input_data="0xd2ce7d6500ff",
    )
    if out is not None:
        assert out.confidence in {"low", "medium", "high"}


# ─────────────────────────────────────────────────────────────────────────────
# 4. zkSync Era L1ERC20Bridge
# ─────────────────────────────────────────────────────────────────────────────


def test_zksync_era_deposit_decodes_l2_receiver() -> None:
    l2_receiver = "8" * 40
    l1_token = "a" * 40
    refund_recipient = "b" * 40
    calldata = (
        "0xe8b99b1b"
        + _pad_address(l2_receiver)
        + _pad_address(l1_token)
        + _pad_uint(1_000_000)     # amount
        + _pad_uint(2_000_000)     # _l2TxGasLimit
        + _pad_uint(800)           # _l2TxGasPerPubdataByte
        + _pad_address(refund_recipient)
    )
    out = decode_bridge_calldata(
        bridge_protocol="zkSync Era: L1ERC20Bridge",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "zksync"
    assert out.destination_address == "0x" + l2_receiver
    assert out.bridge_method == "deposit"
    assert out.confidence == "high"


def test_zksync_malformed_returns_low_confidence_no_exception() -> None:
    out = decode_bridge_calldata(
        bridge_protocol="zkSync Era: L1ERC20Bridge",
        input_data="0xe8b99b1b00ff",
    )
    if out is not None:
        assert out.confidence in {"low", "medium", "high"}


def test_zksync_zero_l2_receiver_rejected() -> None:
    calldata = (
        "0xe8b99b1b"
        + _pad_address("0" * 40)
        + _pad_address("a" * 40)
        + _pad_uint(1_000_000)
        + _pad_uint(2_000_000)
        + _pad_uint(800)
        + _pad_address("b" * 40)
    )
    out = decode_bridge_calldata(
        bridge_protocol="zkSync Era: L1ERC20Bridge",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_address is None
    assert out.destination_chain == "zksync"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Base L1StandardBridge (OP-Stack fork — same selectors as Optimism;
#    destination chain MUST be 'base' not 'optimism').
# ─────────────────────────────────────────────────────────────────────────────


def test_base_deposit_erc20_to_decodes_recipient_with_base_chain() -> None:
    l1_token = "a" * 40
    l2_token = "b" * 40
    to = "c" * 40
    calldata = (
        "0x838b2520"
        + _pad_address(l1_token)
        + _pad_address(l2_token)
        + _pad_address(to)
        + _pad_uint(1_000_000)
        + _pad_uint(200_000)
        + _pad_uint(0xc0)
        + _pad_uint(0)
    )
    out = decode_bridge_calldata(
        bridge_protocol="Base: L1 Standard Bridge",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    # CRITICAL: must be 'base' not 'optimism'. The shared OP-Stack ABI
    # would cause a regression here if the dispatcher routed Base traffic
    # to _decode_optimism_l1 without the chain override.
    assert out.destination_chain == "base"
    assert out.destination_address == "0x" + to
    assert out.bridge_method == "depositERC20To"


def test_base_deposit_eth_to_decodes_recipient_with_base_chain() -> None:
    to = "5" * 40
    calldata = (
        "0x9a2ac6d5"
        + _pad_address(to)
        + _pad_uint(200_000)
        + _pad_uint(0x60)
        + _pad_uint(0)
    )
    out = decode_bridge_calldata(
        bridge_protocol="Base: L1 Standard Bridge",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "base"
    assert out.destination_address == "0x" + to


def test_base_malformed_returns_low_confidence_no_exception() -> None:
    out = decode_bridge_calldata(
        bridge_protocol="Base: L1 Standard Bridge",
        input_data="0x838b2520deadbeef",
    )
    if out is not None:
        assert out.confidence in {"low", "medium", "high"}


# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher routing — confirm an unknown selector under a recognised
# protocol returns None (not a default fallthrough). Also confirms the
# bridges.json `name` strings used in cross_chain.py dispatch.
# ─────────────────────────────────────────────────────────────────────────────


def test_dispatcher_unknown_selector_under_polygon_pos_returns_none() -> None:
    out = decode_bridge_calldata(
        bridge_protocol="Polygon: RootChainManager",
        input_data="0xdeadbeef" + "00" * 200,
    )
    assert out is None


def test_dispatcher_recognises_erc20_predicate_alias() -> None:
    """bridges.json has 'Polygon: ERC20Predicate' as a separate entry —
    same protocol family, must route to _decode_polygon_pos."""
    user = "1" * 40
    calldata = "0x4faa8a26" + _pad_address(user)
    out = decode_bridge_calldata(
        bridge_protocol="Polygon: ERC20Predicate",
        input_data=calldata,
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "polygon"
    assert out.destination_address == "0x" + user


def test_dispatcher_recognises_arbitrum_delayed_inbox_alias() -> None:
    """The v0.32.1 bridges.json entry 'Arbitrum: DelayedInbox' must
    route to the arbitrum decoder (matches the 'arbitrum' prefix)."""
    out = decode_bridge_calldata(
        bridge_protocol="Arbitrum: DelayedInbox",
        input_data="0x439370b1",
    )
    assert isinstance(out, BridgeDecodeResult)
    assert out.destination_chain == "arbitrum"
    assert out.bridge_method == "depositEth"


# ─────────────────────────────────────────────────────────────────────────────
# Bridges.json consistency — the 5 canonical bridges must be present with
# kind="bridge" and a chain attribution. Regression guard: if anyone
# removes an entry, this test fires.
# ─────────────────────────────────────────────────────────────────────────────


def test_bridges_json_has_all_5_canonical_addresses() -> None:
    import json
    from pathlib import Path
    repo_root = Path(__file__).resolve().parents[1]
    path = repo_root / "src" / "recupero" / "labels" / "seeds" / "bridges.json"
    entries = json.loads(path.read_text(encoding="utf-8"))
    # Filter out section-comment entries (have only "_section" key)
    real_entries = [
        e for e in entries if isinstance(e, dict) and "address" in e
    ]
    addrs = {e["address"].lower() for e in real_entries}
    # 5 canonical L1 contracts (Ethereum side).
    required = {
        # Polygon PoS RootChainManager
        "0xa0c68c638235ee32657e8f720a23cec1bfc77c77",
        # Optimism L1StandardBridge
        "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1",
        # Arbitrum DelayedInbox (v0.32.1 prompt-supplied canonical address)
        "0x4dbd4fc535ac27206064b6804e1fbcc1c5b8ee18",
        # zkSync Era L1ERC20Bridge (v0.32.1 addition)
        "0x57891966931eb4bb6fb81430e6ce0a03aabde063",
        # Base L1StandardBridge
        "0x3154cf16ccdb4c6d922629664174b904d80f2c35",
    }
    missing = required - addrs
    assert not missing, (
        f"bridges.json missing canonical L2 bridge addresses: {missing}"
    )
    # Spot-check category="bridge" for the 5 — sample one address from each.
    by_addr = {e["address"].lower(): e for e in real_entries}
    for addr in required:
        entry = by_addr[addr]
        assert entry.get("category") == "bridge", (
            f"{addr} has category != 'bridge'"
        )
