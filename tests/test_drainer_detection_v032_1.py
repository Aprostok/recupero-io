"""Tests for v0.32.1 CRIT-4: approval-pull drainer detection un-gated.

Pre-v0.32.1 the second drainer-detection signal (approval-pull
forwarding) was hard-gated behind ``if False``. The most common
2024-2026 attack vector (drainer kit signs ``approve(MAX_UINT256,
drainerContract)`` then ``transferFrom``s out) was detected ONLY
when the drainer's contract address was already labeled in
``high_risk.json``. Any new drainer (Inferno, Pink, Angel, MS,
Monkey, etc.) emerges, lands a victim, and the brief showed nothing
in the DRAINER_ATTRIBUTION column.

v0.32.1 reopens the branch with a tight forwarding-pattern test
that distinguishes drainer-pull from DEX/protocol use without
requiring raw Approval-event ingestion:

  1. Victim sends funds to a contract C.
  2. Contract C forwards ≥80% of those funds to a DIFFERENT EOA E
     within ≤5 blocks.
  3. Victim does NOT receive anything back from C or E in the
     window (no swap output, no LP receipt).

These tests cover positive detection across ERC-20 / ERC-721 /
ERC-1155 / native paths, plus the critical negative case (DEX
swap with output back to victim must NOT fire).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.trace.drainer_detection import (
    APPROVAL_TOPIC0,
    ApprovalEvent,
    DrainerEvent,
    detect_drainer_pattern,
    drainer_findings_to_brief_section,
)


VICTIM = "0x" + "a" * 40
DRAINER_CONTRACT = "0x" + "d" * 40
ATTACKER_EOA = "0x" + "9" * 40
USDC_CONTRACT = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
NFT_CONTRACT = "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d"  # BAYC


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    amount_decimal: Decimal = Decimal("1000"),
    amount_raw: str = "1000000000",
    tx_hash: str | None = None,
    block_number: int = 100,
    is_contract: bool = False,
    token_symbol: str = "USDC",
    token_contract: str | None = USDC_CONTRACT,
    token_decimals: int = 6,
    chain: Chain = Chain.ethereum,
) -> Transfer:
    ts = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=block_number * 12)
    if tx_hash is None:
        tx_hash = "0x" + str(block_number).zfill(64)
    return Transfer(
        transfer_id=f"{chain.value}:{tx_hash}:1",
        chain=chain,
        tx_hash=tx_hash,
        block_number=block_number,
        block_time=ts,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(
            address=to_addr, label=None, is_contract=is_contract,
        ),
        token=TokenRef(
            chain=chain,
            contract=token_contract,
            symbol=token_symbol,
            decimals=token_decimals,
            coingecko_id="usd-coin",
        ),
        amount_raw=amount_raw,
        amount_decimal=amount_decimal,
        usd_value_at_tx=Decimal("1000"),
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=ts,
    )


def _mk_case(transfers: list[Transfer], seed: str = VICTIM) -> Case:
    return Case(
        case_id="test",
        seed_address=seed,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        software_version="test",
        config_used={},
    )


# ---- 1: ERC-20 approval-pull (the canonical case) ---- #


def test_erc20_approval_pull_drainer_pattern_detected() -> None:
    """Victim → DrainerContract (USDC, 1000) → AttackerEOA (USDC,
    1000) within 1 block. No return flow to victim. Must fire as
    drainer-pattern with confidence='medium' and emit a
    DrainerEvent + approval_to_unknown_contract signal."""
    transfers = [
        _mk_transfer(
            from_addr=VICTIM, to_addr=DRAINER_CONTRACT,
            amount_decimal=Decimal("1000"), amount_raw="1000000000",
            block_number=100, is_contract=True,
            token_symbol="USDC",
        ),
        _mk_transfer(
            from_addr=DRAINER_CONTRACT, to_addr=ATTACKER_EOA,
            amount_decimal=Decimal("950"), amount_raw="950000000",
            block_number=100,  # same block — instant pull
            is_contract=False,
            token_symbol="USDC",
        ),
    ]
    case = _mk_case(transfers)
    findings = detect_drainer_pattern(case, high_risk_db={})

    assert findings.is_drainer_case is True
    assert findings.classification_confidence == "medium"
    assert any(
        s.signal_type == "approval_to_unknown_contract"
        for s in findings.signals
    )
    assert any(
        s.signal_type == "transfer_from_pattern" and s.counterparty == ATTACKER_EOA.lower()
        for s in findings.signals
    )
    # Exactly one DrainerEvent for the ERC-20 drain.
    assert len(findings.events) == 1
    event = findings.events[0]
    assert isinstance(event, DrainerEvent)
    assert event.victim_address == VICTIM.lower()
    assert event.attacker_address == ATTACKER_EOA.lower()
    assert event.signing_contract == DRAINER_CONTRACT.lower()
    assert event.asset_type == "erc20"
    assert event.asset_symbol == "USDC"
    assert event.pattern == "approve+transferFrom"


# ---- 2: Negative — DEX swap must NOT fire (return flow to victim) ---- #


def test_dex_swap_with_return_to_victim_does_not_fire() -> None:
    """The critical negative case: victim → DEX router → router →
    victim (output token). The return flow to the victim is the
    differentiating signal that distinguishes legitimate DeFi
    from a drainer-pull. Must NOT fire as a drainer."""
    transfers = [
        # Victim sends USDC to router
        _mk_transfer(
            from_addr=VICTIM, to_addr=DRAINER_CONTRACT,  # acts as router here
            amount_decimal=Decimal("1000"), amount_raw="1000000000",
            block_number=100, is_contract=True,
            token_symbol="USDC",
        ),
        # Router forwards USDC to attacker — same as drainer shape...
        _mk_transfer(
            from_addr=DRAINER_CONTRACT, to_addr=ATTACKER_EOA,
            amount_decimal=Decimal("950"), amount_raw="950000000",
            block_number=100, is_contract=False,
            token_symbol="USDC",
        ),
        # ...BUT: router returns USDT to victim. Legitimate swap.
        _mk_transfer(
            from_addr=DRAINER_CONTRACT, to_addr=VICTIM,
            amount_decimal=Decimal("948"), amount_raw="948000000",
            block_number=100, is_contract=False,
            token_symbol="USDT",
        ),
    ]
    case = _mk_case(transfers)
    findings = detect_drainer_pattern(case, high_risk_db={})

    assert findings.is_drainer_case is False
    assert findings.events == []
    assert not any(
        s.signal_type == "approval_to_unknown_contract"
        for s in findings.signals
    )


# ---- 3: Forwarding outside the block window must NOT fire ---- #


def test_forward_outside_window_does_not_fire() -> None:
    """The drainer pattern requires the forwarding tx within ≤5
    blocks. A forwarding tx 100 blocks later is NOT a drainer-
    pull (could be a custody contract sweeping balances on a
    scheduled job; absent further evidence we don't flag it)."""
    transfers = [
        _mk_transfer(
            from_addr=VICTIM, to_addr=DRAINER_CONTRACT,
            amount_decimal=Decimal("1000"), amount_raw="1000000000",
            block_number=100, is_contract=True,
        ),
        _mk_transfer(
            from_addr=DRAINER_CONTRACT, to_addr=ATTACKER_EOA,
            amount_decimal=Decimal("950"), amount_raw="950000000",
            block_number=200,   # 100 blocks later
            is_contract=False,
        ),
    ]
    case = _mk_case(transfers)
    findings = detect_drainer_pattern(case, high_risk_db={})
    assert findings.is_drainer_case is False
    assert findings.events == []


# ---- 4: Forwarded amount too small (< 80%) does NOT fire ---- #


def test_forward_below_threshold_does_not_fire() -> None:
    """Drainers can take a small commission (5-20%) but they don't
    leave the bulk of funds in the contract — that's just
    custody/escrow. If only 50% is forwarded, it's more likely a
    legitimate split / fee + refund pattern; don't flag."""
    transfers = [
        _mk_transfer(
            from_addr=VICTIM, to_addr=DRAINER_CONTRACT,
            amount_decimal=Decimal("1000"), amount_raw="1000000000",
            block_number=100, is_contract=True,
        ),
        _mk_transfer(
            from_addr=DRAINER_CONTRACT, to_addr=ATTACKER_EOA,
            amount_decimal=Decimal("500"), amount_raw="500000000",
            block_number=100, is_contract=False,
        ),
    ]
    case = _mk_case(transfers)
    findings = detect_drainer_pattern(case, high_risk_db={})
    assert findings.is_drainer_case is False
    assert findings.events == []


# ---- 5: ERC-721 (NFT) drainer-pull ---- #


def test_erc721_setapprovalforall_drainer_pattern() -> None:
    """NFT drainers use setApprovalForAll + safeTransferFrom. The
    amount_raw=1 + decimals=0 signature identifies ERC-721;
    DrainerEvent.asset_type == 'erc721', pattern ==
    'setApprovalForAll+safeTransferFrom'."""
    transfers = [
        _mk_transfer(
            from_addr=VICTIM, to_addr=DRAINER_CONTRACT,
            amount_decimal=Decimal("1"), amount_raw="1",
            block_number=100, is_contract=True,
            token_symbol="BAYC",
            token_contract=NFT_CONTRACT,
            token_decimals=0,
        ),
        _mk_transfer(
            from_addr=DRAINER_CONTRACT, to_addr=ATTACKER_EOA,
            amount_decimal=Decimal("1"), amount_raw="1",
            block_number=100, is_contract=False,
            token_symbol="BAYC",
            token_contract=NFT_CONTRACT,
            token_decimals=0,
        ),
    ]
    case = _mk_case(transfers)
    findings = detect_drainer_pattern(case, high_risk_db={})

    assert findings.is_drainer_case is True
    assert len(findings.events) == 1
    e = findings.events[0]
    assert e.asset_type == "erc721"
    assert e.asset_symbol == "BAYC"
    assert e.pattern == "setApprovalForAll+safeTransferFrom"


def test_erc1155_multi_asset_drainer_pattern() -> None:
    """ERC-1155 drains carry decimals=0 + amount_raw > 1. The
    pattern label is also setApprovalForAll-style (ERC-1155 uses
    setApprovalForAll for the spender contract)."""
    transfers = [
        _mk_transfer(
            from_addr=VICTIM, to_addr=DRAINER_CONTRACT,
            amount_decimal=Decimal("50"), amount_raw="50",
            block_number=100, is_contract=True,
            token_symbol="GAMETOKEN",
            token_contract=NFT_CONTRACT,
            token_decimals=0,
        ),
        _mk_transfer(
            from_addr=DRAINER_CONTRACT, to_addr=ATTACKER_EOA,
            amount_decimal=Decimal("50"), amount_raw="50",
            block_number=100, is_contract=False,
            token_symbol="GAMETOKEN",
            token_contract=NFT_CONTRACT,
            token_decimals=0,
        ),
    ]
    case = _mk_case(transfers)
    findings = detect_drainer_pattern(case, high_risk_db={})

    assert findings.is_drainer_case is True
    assert len(findings.events) == 1
    assert findings.events[0].asset_type == "erc1155"


# ---- 6: Brief section includes events ---- #


def test_brief_section_includes_drainer_events_array() -> None:
    """The brief renderer needs the events array to populate the
    'Approval-pull exploit' timeline section. Verify the JSON
    shape carries the events key with the expected fields."""
    transfers = [
        _mk_transfer(
            from_addr=VICTIM, to_addr=DRAINER_CONTRACT,
            amount_decimal=Decimal("1000"), amount_raw="1000000000",
            block_number=100, is_contract=True,
            token_symbol="USDC",
        ),
        _mk_transfer(
            from_addr=DRAINER_CONTRACT, to_addr=ATTACKER_EOA,
            amount_decimal=Decimal("950"), amount_raw="950000000",
            block_number=100, is_contract=False,
            token_symbol="USDC",
        ),
    ]
    case = _mk_case(transfers)
    findings = detect_drainer_pattern(case, high_risk_db={})
    section = drainer_findings_to_brief_section(findings)

    assert "events" in section
    assert len(section["events"]) == 1
    event_dict = section["events"][0]
    for key in (
        "victim_address", "attacker_address", "signing_contract",
        "asset_type", "asset_symbol", "amount", "tx_hash",
        "block_number", "pattern",
    ):
        assert key in event_dict, f"missing key: {key}"
    assert event_dict["asset_type"] == "erc20"
    assert event_dict["pattern"] == "approve+transferFrom"


# ---- 7: Public exports (ApprovalEvent + APPROVAL_TOPIC0) ---- #


def test_approval_topic0_is_canonical_keccak() -> None:
    """The APPROVAL_TOPIC0 constant should equal keccak256 of
    "Approval(address,address,uint256)" so any downstream EVM-log
    matcher can compare without re-derivation."""
    assert APPROVAL_TOPIC0 == (
        "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
    )


def test_approval_event_dataclass_constructs_cleanly() -> None:
    """ApprovalEvent must be constructable with all required fields
    so downstream Approval-event ingestion can build them without
    surprises at runtime."""
    ev = ApprovalEvent(
        owner=VICTIM,
        spender=DRAINER_CONTRACT,
        token_contract=USDC_CONTRACT,
        amount_raw="115792089237316195423570985008687907853269984665640564039457584007913129639935",
        tx_hash="0x" + "f" * 64,
        block_number=100,
        block_time=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert ev.spender == DRAINER_CONTRACT
    # frozen dataclass — assignment raises.
    import dataclasses
    assert dataclasses.is_dataclass(ApprovalEvent)
