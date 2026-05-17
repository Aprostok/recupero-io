"""Tests for v0.8.1 cross-chain handoff detection.

The trace today can't follow funds past a bridge contract
(different chain, different RPC). What we CAN do is detect the
handoff at the bridge entry-point and surface it as an
investigator-actionable item.

Contracts under test:
  * ingest_bridge_seeds — schema flexibility (flat array,
    wrapped object), defensive against malformed entries
  * identify_cross_chain_handoffs — finds transfers to bridges,
    dedups on (tx, bridge), sorts by amount desc
  * handoffs_to_brief_section — produces the JSON shape
    consumed by the brief template + AI editorial prompt
  * _build_investigator_note — the one-line action item
    visible to government / operator analysts
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.trace.cross_chain import (
    BridgeInfo,
    CrossChainHandoff,
    handoffs_to_brief_section,
    identify_cross_chain_handoffs,
    ingest_bridge_seeds,
)


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    usd: Decimal | None = Decimal("1000"),
    chain: Chain = Chain.ethereum,
    tx_suffix: str = "1",
    block: int = 1,
) -> Transfer:
    tx_hash = "0x" + tx_suffix * 64
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return Transfer(
        transfer_id=f"{chain.value}:{tx_hash}:{block}",
        chain=chain,
        tx_hash=tx_hash,
        block_number=block,
        block_time=ts,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=True),
        token=TokenRef(
            chain=chain, contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol="USDC", decimals=6, coingecko_id="usd-coin",
        ),
        amount_raw="1000000000",
        amount_decimal=Decimal("1000"),
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=ts,
    )


def _mk_case(transfers: list[Transfer]) -> Case:
    return Case(
        case_id="test",
        seed_address="0x" + "a" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        software_version="test",
        config_used={},
    )


# ---- ingest_bridge_seeds ---- #


def test_ingest_handles_flat_array_schema() -> None:
    """The existing seed file is a flat array. Loader must
    accept it (vs requiring the wrapped 'bridges' key shape)."""
    db = ingest_bridge_seeds()
    assert len(db) > 0
    # Wormhole, Stargate, Hop should all be present.
    addresses = {addr for (_chain, addr) in db.keys()}
    # Wormhole token bridge — lowercased
    assert any("3ee18b2214aff97000d974cf647e54347ae7c7e4" in addr
               for addr in addresses)


def test_ingest_handles_wrapped_object_schema() -> None:
    """Future schema bump: {bridges: [...]} wrapper. Both shapes
    must load identically."""
    payload = {
        "_meta": {"description": "test"},
        "bridges": [
            {
                "address": "0xfeedface00000000000000000000000000000001",
                "name": "TestBridge",
                "category": "bridge",
                "chain": "ethereum",
                "supports_to_chains": ["arbitrum"],
            },
        ],
    }
    with TemporaryDirectory() as tmp:
        p = Path(tmp) / "bridges.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        db = ingest_bridge_seeds(p)
    assert len(db) == 1
    info = next(iter(db.values()))
    assert info.name == "TestBridge"
    assert info.supports_to_chains == ("arbitrum",)


def test_ingest_skips_malformed_entries() -> None:
    """Entry without address → skipped. Entry with unknown chain
    → skipped. Loader logs at debug; never raises."""
    payload = [
        {"name": "no-address-here", "category": "bridge"},
        {"address": "0xabc", "name": "bad-chain",
         "chain": "neptune"},
        {"address": "0xfeedface00000000000000000000000000000099",
         "name": "valid-one", "chain": "ethereum"},
    ]
    with TemporaryDirectory() as tmp:
        p = Path(tmp) / "bridges.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        db = ingest_bridge_seeds(p)
    assert len(db) == 1
    assert next(iter(db.values())).name == "valid-one"


def test_ingest_returns_empty_on_missing_file() -> None:
    """Missing file → empty dict, NOT crash. The trace pipeline
    must degrade gracefully when the seed file isn't shipped."""
    db = ingest_bridge_seeds(Path("/does/not/exist/bridges.json"))
    assert db == {}


# ---- identify_cross_chain_handoffs ---- #


def test_identify_no_transfers_returns_empty() -> None:
    case = _mk_case([])
    assert identify_cross_chain_handoffs(case) == []


def test_identify_no_bridge_destinations_returns_empty() -> None:
    """All transfers go to non-bridge addresses → no handoffs."""
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr="0x" + "b" * 40,
        ),
    ])
    assert identify_cross_chain_handoffs(case) == []


def test_identify_detects_wormhole_handoff() -> None:
    """A transfer landing at the Wormhole Token Bridge gets
    surfaced as a CrossChainHandoff."""
    # Wormhole Token Bridge address from the seed file.
    wormhole = "0x3ee18b2214aff97000d974cf647e54347ae7c7e4"
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=wormhole,
            usd=Decimal("120000"),  # the V-CFI01 Solana bridge amount
        ),
    ])
    out = identify_cross_chain_handoffs(case)
    assert len(out) == 1
    h = out[0]
    assert h.bridge_protocol.lower().startswith("wormhole") or (
        "Wormhole" in h.bridge_name
    )
    assert h.bridge_address == wormhole
    assert h.amount_usd == Decimal("120000")
    assert h.token_symbol == "USDC"


def test_identify_dedups_multiple_transfers_to_same_bridge() -> None:
    """A single tx may emit multiple ERC-20 Transfer events to
    the same bridge — dedup on (tx, bridge) so the brief shows
    one handoff per transaction, not one per Transfer event."""
    wormhole = "0x3ee18b2214aff97000d974cf647e54347ae7c7e4"
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=wormhole,
            tx_suffix="1", block=1,
        ),
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=wormhole,
            tx_suffix="1", block=1,  # same tx
        ),
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=wormhole,
            tx_suffix="2", block=2,  # different tx, same bridge
        ),
    ])
    out = identify_cross_chain_handoffs(case)
    # Two distinct transactions, both bridging to Wormhole.
    assert len(out) == 2


def test_identify_sorts_by_amount_desc() -> None:
    """Largest handoff first — investigator workflow priority.
    Big amounts get attention before small ones."""
    wormhole = "0x3ee18b2214aff97000d974cf647e54347ae7c7e4"
    stargate = "0x8731d54e9d02c286767d56ac03e8037c07e01e98"
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=wormhole,
            usd=Decimal("1000"), tx_suffix="1",
        ),
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=stargate,
            usd=Decimal("500000"), tx_suffix="2",
        ),
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=wormhole,
            usd=Decimal("50000"), tx_suffix="3",
        ),
    ])
    out = identify_cross_chain_handoffs(case)
    assert len(out) == 3
    assert out[0].amount_usd == Decimal("500000")  # largest first
    assert out[1].amount_usd == Decimal("50000")
    assert out[2].amount_usd == Decimal("1000")


def test_identify_handles_null_usd_value() -> None:
    """Transfer with no usd_value_at_tx (pricing failed) still
    surfaces as a handoff — just sorts last. Failing-to-price
    a bridge transfer shouldn't make us miss the bridge."""
    wormhole = "0x3ee18b2214aff97000d974cf647e54347ae7c7e4"
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=wormhole, usd=None,
        ),
    ])
    out = identify_cross_chain_handoffs(case)
    assert len(out) == 1
    assert out[0].amount_usd is None


# ---- handoffs_to_brief_section ---- #


def test_brief_section_shape() -> None:
    """Locked: each handoff in the brief JSON has the keys
    downstream consumers (AI editorial prompt + brief template)
    bind to."""
    wormhole = "0x3ee18b2214aff97000d974cf647e54347ae7c7e4"
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=wormhole,
            usd=Decimal("120000"),
        ),
    ])
    out = identify_cross_chain_handoffs(case)
    section = handoffs_to_brief_section(out)
    assert len(section) == 1
    entry = section[0]
    # Required keys — the brief / AI prompt bind against these.
    for key in (
        "source_chain", "source_address", "tx_hash",
        "tx_explorer_url", "bridge_name", "bridge_protocol",
        "bridge_address", "amount_decimal", "amount_usd",
        "token_symbol", "block_time", "follow_up_url",
        "destination_chain_candidates", "investigator_note",
    ):
        assert key in entry, f"missing required key: {key}"

    # Format checks
    assert entry["source_chain"] == "ethereum"
    assert entry["amount_usd"] == "$120,000.00"
    assert isinstance(entry["destination_chain_candidates"], list)
    assert isinstance(entry["investigator_note"], str)
    assert "Bridged" in entry["investigator_note"]


def test_brief_section_empty_list_returns_empty() -> None:
    """No handoffs → empty array, not None. JSON-friendly."""
    assert handoffs_to_brief_section([]) == []


# ---- investigator note content ---- #


def test_investigator_note_includes_actionable_info() -> None:
    """The note is what an FBI / IRS-CI analyst reads first.
    Must include: amount + token, bridge name, tx hash prefix,
    destination chain candidates, follow-up URL, block time
    range. Lock the content so a future 'let's reword' doesn't
    accidentally drop the actionable bits."""
    wormhole = "0x3ee18b2214aff97000d974cf647e54347ae7c7e4"
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=wormhole,
            usd=Decimal("250000"),
        ),
    ])
    out = identify_cross_chain_handoffs(case)
    section = handoffs_to_brief_section(out)
    note = section[0]["investigator_note"]

    assert "$250,000" in note
    assert "USDC" in note
    assert "Wormhole" in note
    assert "Investigator:" in note
    # Tx hash prefix surfaced (first ~14 chars to be readable)
    assert "0x1111111" in note  # tx_suffix="1" pattern
    # Block time / "near" guidance for cross-chain correlation
    assert "2026-01-01" in note
