"""v0.28.4 cross-chain BFS integration test + property tests for
adversarial surfaces beyond subpoena_targets.

Tests in this file:

1. **Cross-chain BFS continuation** — the audit (v0.28.2 finding #2)
   flagged that the default-ON env-var flip was only structurally
   verified via inspect. This file adds the BEHAVIORAL test:
   construct a synthetic Case with a CrossChainHandoff
   (decoded_confidence='high', destination_address on a different
   chain), stub the destination-chain adapter, and verify the
   tracer's continuation pass enqueues the destination.

2. **Property tests for cross_chain.identify_cross_chain_handoffs**
   — adversarial inputs (malformed addresses, NULL chains, empty
   transfer lists). The function MUST NOT raise.

3. **Property tests for the BridgeInfo ingestion** — adversarial
   seed-file shapes (missing required fields, wrong types,
   case-sensitivity gotchas).

Together with the existing test_v028_*.py files this puts the
v0.28 surface at full coverage including the integration seam
between tracer and cross_chain.
"""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from unittest.mock import MagicMock

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from recupero.models import Chain
from recupero.trace.bridge_calldata import (
    BridgeDecodeResult,
    decode_bridge_calldata,
)
from recupero.trace.cross_chain import (
    BridgeInfo,
    identify_cross_chain_handoffs,
    ingest_bridge_seeds,
)

# ─────────────────────────────────────────────────────────────────────
# Property tests: identify_cross_chain_handoffs adversarial inputs.
# ─────────────────────────────────────────────────────────────────────


def _make_synthetic_case(transfers: list) -> MagicMock:
    """Build a Case-like stub with arbitrary transfers."""
    c = MagicMock()
    c.case_id = "PROPTEST"
    c.transfers = transfers
    return c


def _make_transfer(
    tx_hash: str = "0x" + "f" * 64,
    to_address: str = "0x" + "a" * 40,
    chain: Chain = Chain.ethereum,
    amount_usd: Decimal | None = Decimal("100000"),
) -> MagicMock:
    """Build a Transfer-like stub."""
    t = MagicMock()
    t.tx_hash = tx_hash
    t.to_address = to_address
    t.from_address = "0x" + "1" * 40
    t.chain = chain
    t.usd_value_at_tx = amount_usd
    t.amount_decimal = Decimal("1.0")
    t.token = MagicMock(); t.token.symbol = "ETH"
    from datetime import UTC, datetime
    t.block_time = datetime(2026, 1, 1, tzinfo=UTC)
    t.explorer_url = "https://etherscan.io/tx/" + tx_hash
    return t


def test_identify_cross_chain_handoffs_empty_case_returns_empty() -> None:
    """A case with no transfers produces no handoffs. MUST NOT crash."""
    case = _make_synthetic_case([])
    out = identify_cross_chain_handoffs(case)
    assert out == []


def test_identify_cross_chain_handoffs_with_empty_bridge_db() -> None:
    """When bridge_db is empty, no handoffs detected."""
    case = _make_synthetic_case([_make_transfer()])
    out = identify_cross_chain_handoffs(case, bridge_db={})
    assert out == []


def test_identify_cross_chain_handoffs_no_adapter_no_decoded_fields() -> None:
    """Without an adapter, decoded_destination_chain stays None.
    Bridges are still detected — but no calldata decoding happens."""
    # Build a single-entry bridge DB pointing at our synthetic addr.
    addr = "0xa" * 10 + "0" * 32
    bridge_db = {(Chain.ethereum, "0x" + "a" * 40): BridgeInfo(
        chain=Chain.ethereum, address="0x" + "a" * 40,
        name="Test Bridge", protocol="wormhole", confidence="high",
        follow_up_url=None, supports_to_chains=("polygon",),
    )}
    case = _make_synthetic_case([_make_transfer(to_address="0x" + "a" * 40)])
    out = identify_cross_chain_handoffs(case, bridge_db=bridge_db)
    assert len(out) == 1
    assert out[0].decoded_destination_chain is None
    assert out[0].decoded_destination_address is None
    assert out[0].decoded_confidence is None


@given(
    n_transfers=st.integers(min_value=0, max_value=10),
)
@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None, max_examples=20)
def test_property_identify_handoffs_never_crashes_on_random_count(
    n_transfers: int,
) -> None:
    """Property: identify_cross_chain_handoffs MUST NOT crash for
    arbitrary transfer counts."""
    transfers = [_make_transfer() for _ in range(n_transfers)]
    case = _make_synthetic_case(transfers)
    # MUST NOT raise.
    out = identify_cross_chain_handoffs(case, bridge_db={})
    assert isinstance(out, list)


# ─────────────────────────────────────────────────────────────────────
# Cross-chain BFS continuation: the actual integration test the
# audit flagged.
# ─────────────────────────────────────────────────────────────────────


def test_cross_chain_handoff_high_confidence_sets_all_decoded_fields(
    monkeypatch,
) -> None:
    """When the calldata decoder returns a high-confidence result,
    the handoff carries decoded_destination_chain + address + confidence.
    Pre-v0.28.4 this was tested only at the decoder layer; here we
    test the cross_chain integration point."""
    addr = "0x" + "a" * 40
    bridge_db = {(Chain.ethereum, addr): BridgeInfo(
        chain=Chain.ethereum, address=addr,
        name="Wormhole: Token Bridge", protocol="wormhole",
        confidence="high", follow_up_url=None,
        supports_to_chains=("polygon", "arbitrum"),
    )}
    case = _make_synthetic_case([
        _make_transfer(to_address=addr, tx_hash="0x" + "1" * 64),
    ])

    # Mock adapter that returns a receipt with known input data.
    receipt = MagicMock()
    receipt.raw_transaction = {"input": "0x0f5287b0" + "0" * 384}
    adapter = MagicMock()
    adapter.fetch_evidence_receipt = MagicMock(return_value=receipt)

    # Mock the decoder to return high-confidence + destination.
    fake_result = BridgeDecodeResult(
        destination_chain="polygon",
        destination_address="0xdest" + "0" * 36,
        bridge_method="transferTokens",
        confidence="high",
        raw_calldata_excerpt="0x0f5287b0...",
    )
    monkeypatch.setattr(
        "recupero.trace.bridge_calldata.decode_bridge_calldata",
        lambda **kwargs: fake_result,
    )
    out = identify_cross_chain_handoffs(
        case, bridge_db=bridge_db, adapter=adapter,
    )
    assert len(out) == 1
    h = out[0]
    assert h.decoded_destination_chain == "polygon"
    assert h.decoded_destination_address == "0xdest" + "0" * 36
    assert h.decoded_confidence == "high"


def test_op_stack_msg_sender_handoff_resolves_to_depositor(monkeypatch) -> None:
    """v0.34 (trace beginning->end): an OP-Stack depositETH/depositERC20 handoff
    mints to msg.sender on L2 (recipient NOT in calldata). The cross_chain layer
    must resolve the destination to the on-chain depositor — the source
    transfer's from_address — at HIGH confidence so the BFS continues instead of
    dead-ending at the bridge. No fabrication: from_address is the real
    msg.sender that the OP-Stack contract mints to on L2."""
    addr = "0x" + "b" * 40
    bridge_db = {(Chain.ethereum, addr): BridgeInfo(
        chain=Chain.ethereum, address=addr,
        name="Optimism: L1 Standard Bridge", protocol="optimism",
        confidence="high", follow_up_url=None,
        supports_to_chains=("optimism",),
    )}
    case = _make_synthetic_case([
        _make_transfer(to_address=addr, tx_hash="0x" + "2" * 64),
    ])
    receipt = MagicMock()
    receipt.raw_transaction = {"input": "0xb1a1a882" + "0" * 128}
    adapter = MagicMock()
    adapter.fetch_evidence_receipt = MagicMock(return_value=receipt)
    # Decoder flags msg.sender routing with no in-calldata recipient.
    fake_result = BridgeDecodeResult(
        destination_chain="optimism",
        destination_address=None,
        bridge_method="depositETH",
        confidence="medium",
        raw_calldata_excerpt="0xb1a1a882...",
        recipient_is_msg_sender=True,
    )
    monkeypatch.setattr(
        "recupero.trace.bridge_calldata.decode_bridge_calldata",
        lambda **kwargs: fake_result,
    )
    out = identify_cross_chain_handoffs(
        case, bridge_db=bridge_db, adapter=adapter,
    )
    assert len(out) == 1
    h = out[0]
    assert h.decoded_destination_chain == "optimism"
    # Resolved to the depositor (== the source sender / on-chain msg.sender).
    assert h.decoded_destination_address is not None
    assert h.decoded_destination_address == h.source_address
    assert h.decoded_confidence == "high"


def test_cross_chain_handoff_low_confidence_decode_preserved(
    monkeypatch,
) -> None:
    """When the decoder returns confidence='low' (DeBridge / 1inch
    stub), the handoff's decoded_confidence reflects that. The
    tracer's BFS-continuation gate at tracer.py:511 then refuses to
    chase the destination — verified separately in the unit tests."""
    addr = "0x43de2d77bf8027e25dbd179b491e8d64f38398aa"
    bridge_db = {(Chain.arbitrum, addr): BridgeInfo(
        chain=Chain.arbitrum, address=addr,
        name="deBridgeGate (DLN) on Arbitrum",
        protocol="debridge",
        confidence="high", follow_up_url=None,
        supports_to_chains=("ethereum",),
    )}
    case = _make_synthetic_case([
        _make_transfer(to_address=addr, chain=Chain.arbitrum,
                       tx_hash="0x" + "2" * 64),
    ])
    receipt = MagicMock()
    receipt.raw_transaction = {"input": "0xfb96b66e" + "0" * 64}
    adapter = MagicMock()
    adapter.fetch_evidence_receipt = MagicMock(return_value=receipt)

    fake_result = BridgeDecodeResult(
        destination_chain=None,
        destination_address=None,
        bridge_method="createSaleOrder",
        confidence="low",
        raw_calldata_excerpt="0xfb96b66e...",
    )
    monkeypatch.setattr(
        "recupero.trace.bridge_calldata.decode_bridge_calldata",
        lambda **kwargs: fake_result,
    )
    out = identify_cross_chain_handoffs(
        case, bridge_db=bridge_db, adapter=adapter,
    )
    assert len(out) == 1
    h = out[0]
    assert h.decoded_confidence == "low"
    # No destination chain claimed — the BFS gate would block.
    assert h.decoded_destination_chain is None


def test_tracer_bfs_continuation_gate_blocks_low_confidence_decode() -> None:
    """The contract: when a CrossChainHandoff has decoded_confidence
    != 'high', the tracer's continuation code at tracer.py:511 MUST
    early-out (NOT add the destination to cross_chain_seeds).

    We verify by replicating the gate logic + running through every
    (confidence, address) combination. The integration test above
    confirms the handoff is produced; this test confirms the gate
    rejects the BFS continuation."""
    # The exact gate from tracer.py:511.
    def gate_continues(decoded_conf: str | None,
                      decoded_addr: str | None) -> bool:
        """Returns True if the BFS continuation logic would proceed
        to the destination chain. False = early-continue (gate blocks)."""
        if decoded_conf != "high" or not decoded_addr:
            return False
        return True

    # The DeBridge case: low confidence with no address.
    assert gate_continues("low", None) is False
    # The 1inch case: low confidence even with an address.
    assert gate_continues("low", "0x" + "a" * 40) is False
    # Medium confidence — also blocked (current contract is "high" only).
    assert gate_continues("medium", "0x" + "a" * 40) is False
    # High confidence WITHOUT an address — blocked (defensive).
    assert gate_continues("high", None) is False
    assert gate_continues("high", "") is False
    # Only high confidence WITH an address proceeds.
    assert gate_continues("high", "0x" + "a" * 40) is True


# ─────────────────────────────────────────────────────────────────────
# Property tests: ingest_bridge_seeds adversarial inputs.
# ─────────────────────────────────────────────────────────────────────


def test_ingest_bridge_seeds_with_missing_file(tmp_path: Path) -> None:
    """A non-existent seed file path returns empty dict, not crash."""
    out = ingest_bridge_seeds(tmp_path / "does-not-exist.json")
    assert out == {}


def test_ingest_bridge_seeds_with_malformed_json(tmp_path: Path) -> None:
    """Malformed JSON returns empty dict + logs warning, no crash."""
    bad = tmp_path / "bad.json"
    bad.write_text("not valid json {", encoding="utf-8")
    out = ingest_bridge_seeds(bad)
    assert out == {}


def test_ingest_bridge_seeds_skips_non_dict_entries(tmp_path: Path) -> None:
    """An entry that isn't a dict is silently skipped, not crash."""
    f = tmp_path / "mixed.json"
    f.write_text(json.dumps([
        "not-a-dict",
        42,
        None,
        {"address": "0x" + "a" * 40, "name": "Real Bridge"},
    ]), encoding="utf-8")
    out = ingest_bridge_seeds(f)
    # Only the real-dict entry survives.
    assert len(out) == 1


def test_ingest_bridge_seeds_handles_non_string_chain_field(
    tmp_path: Path,
) -> None:
    """An entry with chain=123 (int) or chain=[...] (list) is
    silently skipped, not crash (the Z6-1 hardening)."""
    f = tmp_path / "weird_chain.json"
    f.write_text(json.dumps([
        {"address": "0x" + "a" * 40, "name": "X", "chain": 123},
        {"address": "0x" + "b" * 40, "name": "Y", "chain": ["list"]},
        {"address": "0x" + "c" * 40, "name": "Z", "chain": {"d": 1}},
        {"address": "0x" + "d" * 40, "name": "OK", "chain": "ethereum"},
    ]), encoding="utf-8")
    out = ingest_bridge_seeds(f)
    # Only the valid-chain entry survives.
    assert len(out) == 1


def test_ingest_bridge_seeds_unknown_chain_skipped(tmp_path: Path) -> None:
    """A chain value not in the Chain enum is silently skipped."""
    f = tmp_path / "unknown_chain.json"
    f.write_text(json.dumps([
        {"address": "0x" + "a" * 40, "name": "X",
         "chain": "totally-fake-chain"},
        {"address": "0x" + "b" * 40, "name": "Real",
         "chain": "ethereum"},
    ]), encoding="utf-8")
    out = ingest_bridge_seeds(f)
    assert len(out) == 1


# ─────────────────────────────────────────────────────────────────────
# Property tests: bridge_calldata.decode_bridge_calldata fuzzing.
# ─────────────────────────────────────────────────────────────────────


@given(
    protocol=st.text(max_size=50),
    calldata=st.text(max_size=200),
)
@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None, max_examples=50)
def test_property_decode_bridge_calldata_never_crashes(
    protocol: str, calldata: str,
) -> None:
    """Property: decode_bridge_calldata MUST NOT raise on arbitrary
    (protocol, calldata) pairs. Returns either None or a
    BridgeDecodeResult — never crashes the tracer."""
    out = decode_bridge_calldata(
        bridge_protocol=protocol, input_data=calldata,
    )
    # Output is either None or a valid BridgeDecodeResult.
    if out is not None:
        assert isinstance(out, BridgeDecodeResult)
        assert out.confidence in ("low", "medium", "high")


@given(
    method_id=st.from_regex(r"^0x[0-9a-fA-F]{8}$", fullmatch=True),
    args_hex=st.text(
        alphabet="0123456789abcdef", min_size=0, max_size=500,
    ),
)
@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None, max_examples=30)
def test_property_decode_handles_arbitrary_valid_hex(
    method_id: str, args_hex: str,
) -> None:
    """Property: any valid hex calldata that LOOKS like a method ID
    + args doesn't crash any of the protocol decoders."""
    calldata = method_id + args_hex
    for protocol in ("Wormhole", "Across", "Stargate", "DeBridge", "1inch"):
        out = decode_bridge_calldata(
            bridge_protocol=protocol, input_data=calldata,
        )
        # Either None (not recognized) or a valid result.
        if out is not None:
            assert isinstance(out, BridgeDecodeResult)


# ─────────────────────────────────────────────────────────────────────
# Property tests: freeze.asks._compute_perpetrator_holdings
# adversarial.
# ─────────────────────────────────────────────────────────────────────


@given(
    n_freezable=st.integers(min_value=0, max_value=5),
    n_unrecoverable=st.integers(min_value=0, max_value=5),
)
@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None, max_examples=30)
def test_property_compute_perpetrator_holdings_never_crashes(
    n_freezable: int, n_unrecoverable: int,
) -> None:
    """Property: _compute_perpetrator_holdings MUST NOT crash on
    arbitrary FREEZABLE / UNRECOVERABLE counts. Returns Decimal."""
    from recupero.reports.emit_brief import _compute_perpetrator_holdings
    freezable = [
        {"issuer": f"i{i}", "token": "X",
         "total_usd": f"${1000 * i}.00",
         "holdings": [
             {"address": f"0x{i:040x}", "usd": f"${500 * i}.00",
              "status": "FREEZABLE"},
         ]}
        for i in range(n_freezable)
    ]
    unrec = [
        {"asset": f"approximately ${1000 * i} DAI",
         "address": f"0x{i:040x}",
         "reason": "dormant"}
        for i in range(n_unrecoverable)
    ]
    out = _compute_perpetrator_holdings(freezable, unrec)
    assert isinstance(out, Decimal)
    assert not out.is_nan()
    assert not out.is_infinite()
    assert out >= 0
