"""Tests for v0.10.1 (drainer detection) + v0.10.2 (DEX swap
unwrapping).

Both modules expand the trace's understanding of how funds
move post-incident: drainer signals classify the case shape,
DEX swap unwrapping continues the trace past router contracts.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.trace.dex_swaps import (
    detect_dex_swaps,
    dex_swaps_to_brief_section,
    load_dex_routers,
)
from recupero.trace.drainer_detection import (
    detect_drainer_pattern,
    drainer_findings_to_brief_section,
)
from recupero.trace.risk_scoring import HighRiskEntry


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    usd: Decimal = Decimal("1000"),
    tx_hash: str = "0x" + "1" * 64,
    is_contract: bool = False,
    token_symbol: str = "USDC",
    amount: Decimal = Decimal("1000"),
    chain: Chain = Chain.ethereum,
) -> Transfer:
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    return Transfer(
        transfer_id=f"{chain.value}:{tx_hash}:1",
        chain=chain,
        tx_hash=tx_hash,
        block_number=1,
        block_time=ts,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(
            address=to_addr, label=None, is_contract=is_contract,
        ),
        token=TokenRef(
            chain=chain, contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol=token_symbol, decimals=6, coingecko_id="usd-coin",
        ),
        amount_raw="1000000000",
        amount_decimal=amount,
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=ts,
    )


def _mk_case(transfers: list[Transfer], seed: str = "0x" + "a" * 40) -> Case:
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


# ---- Drainer detection ---- #


def test_drainer_no_transfers_no_classification() -> None:
    case = _mk_case([])
    findings = detect_drainer_pattern(case)
    assert findings.is_drainer_case is False
    assert findings.signals == []


def test_drainer_direct_outflow_to_known_drainer_is_critical() -> None:
    """Victim → Pink Drainer → critical signal + drainer
    classification with high confidence + attribution."""
    pink_drainer = "0x" + "d" * 40
    db = {pink_drainer: HighRiskEntry(
        address=pink_drainer, name="Pink Drainer",
        risk_category="scam_drainer", severity=3,
    )}
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=pink_drainer,
            usd=Decimal("50000"),
        ),
    ])
    findings = detect_drainer_pattern(case, high_risk_db=db)
    assert findings.is_drainer_case is True
    assert findings.drainer_attribution == "Pink Drainer"
    assert findings.classification_confidence == "high"
    assert any(s.severity == "critical" for s in findings.signals)


def test_drainer_outflow_to_unknown_contract_no_classification_without_approval() -> None:
    """v0.18.0 (round-11 forensic CRIT-003): pre-v0.18.0 Signal-2
    fired for ANY transfer to any contract not in the high-risk
    DB. Result: every victim who had used a DEX before the theft
    got mis-classified as drainer-attribution. New behavior: a
    bare contract-destination is NOT enough — we require actual
    approval evidence (setApprovalForAll / permit signature) before
    flagging. Until approval-event data lands in case shape, this
    signal is gated off.
    """
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40,
            to_addr="0x" + "1" * 40,  # not in high_risk_db
            usd=Decimal("50000"),
            is_contract=True,
        ),
    ])
    findings = detect_drainer_pattern(case, high_risk_db={})
    # Contract-destination alone no longer triggers drainer classification.
    assert findings.is_drainer_case is False
    # And no signal is emitted for the unknown-contract case.
    assert not any(
        s.signal_type == "approval_to_unknown_contract"
        for s in findings.signals
    )


def test_drainer_outflow_to_normal_wallet_no_classification() -> None:
    """Victim → normal EOA (not a contract, not in DB) →
    no drainer signal. Could be operator error / phishing /
    custodial mistake — not a drainer-pattern case."""
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr="0x" + "2" * 40,
            usd=Decimal("50000"), is_contract=False,
        ),
    ])
    findings = detect_drainer_pattern(case, high_risk_db={})
    assert findings.is_drainer_case is False
    assert findings.signals == []


def test_drainer_known_overrides_unknown_contract_classification() -> None:
    """If a victim sent to BOTH a known drainer AND unknown
    contracts, the attribution + confidence should reflect the
    known one (more authoritative)."""
    pink = "0x" + "d" * 40
    db = {pink: HighRiskEntry(
        address=pink, name="Pink Drainer",
        risk_category="scam_drainer", severity=3,
    )}
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr="0x" + "1" * 40,
            usd=Decimal("10000"), is_contract=True, tx_hash="0x" + "1" * 64,
        ),
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=pink,
            usd=Decimal("40000"), tx_hash="0x" + "2" * 64,
        ),
    ])
    findings = detect_drainer_pattern(case, high_risk_db=db)
    assert findings.classification_confidence == "high"
    assert findings.drainer_attribution == "Pink Drainer"


def test_drainer_brief_section_shape() -> None:
    pink = "0x" + "d" * 40
    db = {pink: HighRiskEntry(
        address=pink, name="Pink Drainer",
        risk_category="scam_drainer", severity=3,
    )}
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr=pink,
            usd=Decimal("50000"),
        ),
    ])
    findings = detect_drainer_pattern(case, high_risk_db=db)
    section = drainer_findings_to_brief_section(findings)

    assert section["is_drainer_case"] is True
    assert section["drainer_attribution"] == "Pink Drainer"
    assert section["classification_confidence"] == "high"
    assert len(section["signals"]) >= 1
    s = section["signals"][0]
    for key in (
        "type", "address", "counterparty", "counterparty_name",
        "severity", "description", "confidence",
    ):
        assert key in s


# ---- DEX swap detection ---- #


def test_load_dex_routers_includes_known_aggregators() -> None:
    """The DEX router loader should pull 1inch / Uniswap /
    CoW Protocol / ParaSwap from defi_protocols.json based on
    the subcategory field (added in v0.9.3)."""
    routers = load_dex_routers()
    # 1inch v5 — known address from defi_protocols.json
    oneinch_v5 = "0x1111111254eeb25477b68fb85ed929f73a960582"
    assert oneinch_v5 in routers
    assert "1inch" in routers[oneinch_v5]["name"]


def test_detect_no_swaps_when_no_routers_involved() -> None:
    """A case with no transfers to DEX router addresses → no swaps."""
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "a" * 40, to_addr="0x" + "b" * 40,
            usd=Decimal("1000"),
        ),
    ])
    assert detect_dex_swaps(case) == []


def test_detect_swap_with_input_only_medium_confidence() -> None:
    """Transfer to a router, no matching output in the trace →
    medium-confidence DEXSwap (input identified, output
    inference uncertain)."""
    oneinch = "0x1111111254eeb25477b68fb85ed929f73a960582"
    case = _mk_case([
        _mk_transfer(
            from_addr="0x" + "1" * 40, to_addr=oneinch,
            usd=Decimal("48200"),
            token_symbol="USDC",
        ),
    ])
    swaps = detect_dex_swaps(case)
    assert len(swaps) == 1
    s = swaps[0]
    assert s.confidence == "medium"
    assert "1inch" in s.router_name
    assert s.input_amount_usd == Decimal("48200")
    assert s.input_token_symbol == "USDC"


def test_detect_swap_with_paired_output_high_confidence() -> None:
    """Two transfers in the same tx: one IN to the router,
    one OUT from the router to a new address → high-
    confidence swap with output recipient identified."""
    swapper = "0x" + "1" * 40
    oneinch = "0x1111111254eeb25477b68fb85ed929f73a960582"
    perp_wallet = "0x" + "9" * 40
    tx = "0x" + "f" * 64
    case = _mk_case([
        # Input: swapper → router (USDC)
        _mk_transfer(
            from_addr=swapper, to_addr=oneinch,
            usd=Decimal("48200"),
            tx_hash=tx,
            token_symbol="USDC",
        ),
        # Output: router → perpetrator wallet (USDT)
        _mk_transfer(
            from_addr=oneinch, to_addr=perp_wallet,
            usd=Decimal("48100"),
            tx_hash=tx,  # same tx
            token_symbol="USDT",
        ),
    ])
    swaps = detect_dex_swaps(case)
    assert len(swaps) == 1
    s = swaps[0]
    assert s.confidence == "high"
    assert s.swapper == swapper
    assert s.input_token_symbol == "USDC"
    assert s.input_amount_usd == Decimal("48200")
    assert s.output_token_symbol == "USDT"
    assert s.output_amount_usd == Decimal("48100")
    assert s.output_recipient == perp_wallet


def test_detect_swap_unpriced_single_output_still_followed() -> None:
    """v0.32.1 (trace-depth #3): a swap whose OUTPUT token CoinGecko can't
    price (usd=None) must still identify the output recipient. Pre-fix the
    best-output selection was USD-only — an unpriced output defaulted to $0,
    never won, best_output stayed None, and the tracer dead-ended at the
    router (a launderer swapping into a low-liquidity / self-issued token
    broke the trail). The router→address transfer is an on-chain fact, so a
    SOLE output is unambiguous → high confidence, recipient identified."""
    swapper = "0x" + "1" * 40
    oneinch = "0x1111111254eeb25477b68fb85ed929f73a960582"
    perp_wallet = "0x" + "9" * 40
    tx = "0x" + "e" * 64
    case = _mk_case([
        _mk_transfer(
            from_addr=swapper, to_addr=oneinch,
            usd=Decimal("48200"), tx_hash=tx, token_symbol="USDC",
        ),
        # Output: router → perp, but the output token is UNPRICED.
        _mk_transfer(
            from_addr=oneinch, to_addr=perp_wallet,
            usd=None, tx_hash=tx, token_symbol="NEWCOIN",
            amount=Decimal("12345"),
        ),
    ])
    swaps = detect_dex_swaps(case)
    assert len(swaps) == 1
    s = swaps[0]
    assert s.confidence == "high"
    assert s.output_recipient == perp_wallet, (
        "unpriced sole swap output must still be followed"
    )
    assert s.output_token_symbol == "NEWCOIN"


def test_detect_swap_unpriced_multi_same_token_picks_largest() -> None:
    """Multiple unpriced outputs of the SAME token: the largest amount is
    the main swap output (smaller ones are fee/dust). Pick it."""
    swapper = "0x" + "2" * 40
    oneinch = "0x1111111254eeb25477b68fb85ed929f73a960582"
    perp_wallet = "0x" + "8" * 40
    fee_wallet = "0x" + "7" * 40
    tx = "0x" + "d" * 64
    case = _mk_case([
        _mk_transfer(from_addr=swapper, to_addr=oneinch,
                     usd=Decimal("90000"), tx_hash=tx, token_symbol="USDC"),
        # Main output (large, unpriced).
        _mk_transfer(from_addr=oneinch, to_addr=perp_wallet,
                     usd=None, tx_hash=tx, token_symbol="NEWCOIN",
                     amount=Decimal("100000")),
        # Fee output (small, unpriced, same token).
        _mk_transfer(from_addr=oneinch, to_addr=fee_wallet,
                     usd=None, tx_hash=tx, token_symbol="NEWCOIN",
                     amount=Decimal("250")),
    ])
    swaps = detect_dex_swaps(case)
    assert len(swaps) == 1
    assert swaps[0].confidence == "high"
    assert swaps[0].output_recipient == perp_wallet


def test_detect_swap_unpriced_mixed_tokens_stays_medium() -> None:
    """Multiple unpriced outputs of DIFFERENT tokens: amounts aren't
    comparable across tokens, so we can't tell the main output from a fee.
    Leave the recipient unidentified (medium) — the brief still surfaces
    the swap for manual follow-up rather than guessing a wrong recipient."""
    swapper = "0x" + "3" * 40
    oneinch = "0x1111111254eeb25477b68fb85ed929f73a960582"
    a = "0x" + "6" * 40
    b = "0x" + "5" * 40
    tx = "0x" + "c" * 64
    case = _mk_case([
        _mk_transfer(from_addr=swapper, to_addr=oneinch,
                     usd=Decimal("90000"), tx_hash=tx, token_symbol="USDC"),
        _mk_transfer(from_addr=oneinch, to_addr=a, usd=None, tx_hash=tx,
                     token_symbol="TOKENA", amount=Decimal("100")),
        _mk_transfer(from_addr=oneinch, to_addr=b, usd=None, tx_hash=tx,
                     token_symbol="TOKENB", amount=Decimal("9999")),
    ])
    swaps = detect_dex_swaps(case)
    assert len(swaps) == 1
    assert swaps[0].confidence == "medium"
    assert swaps[0].output_recipient is None


def test_detect_swaps_sorted_by_amount_desc() -> None:
    """Multiple swaps → largest first, investigator workflow
    priority."""
    swapper = "0x" + "1" * 40
    oneinch = "0x1111111254eeb25477b68fb85ed929f73a960582"
    case = _mk_case([
        _mk_transfer(
            from_addr=swapper, to_addr=oneinch,
            usd=Decimal("1000"), tx_hash="0x" + "1" * 64,
        ),
        _mk_transfer(
            from_addr=swapper, to_addr=oneinch,
            usd=Decimal("100000"), tx_hash="0x" + "2" * 64,
        ),
        _mk_transfer(
            from_addr=swapper, to_addr=oneinch,
            usd=Decimal("5000"), tx_hash="0x" + "3" * 64,
        ),
    ])
    swaps = detect_dex_swaps(case)
    assert len(swaps) == 3
    assert swaps[0].input_amount_usd == Decimal("100000")
    assert swaps[1].input_amount_usd == Decimal("5000")
    assert swaps[2].input_amount_usd == Decimal("1000")


def test_swap_excludes_router_to_router_as_output() -> None:
    """When the 'output' transfer goes from one router to
    ANOTHER router (multi-router aggregator path), we don't
    treat the second router as the swap output — it's still
    a routing step. The output recipient remains None until
    we see a non-router destination."""
    swapper = "0x" + "1" * 40
    oneinch = "0x1111111254eeb25477b68fb85ed929f73a960582"
    paraswap = "0x216b4b4ba9f3e719726886d34a177484278bfcae"
    tx = "0x" + "f" * 64
    case = _mk_case([
        _mk_transfer(
            from_addr=swapper, to_addr=oneinch,
            usd=Decimal("1000"), tx_hash=tx,
        ),
        # Router-to-router (1inch routing through ParaSwap)
        _mk_transfer(
            from_addr=oneinch, to_addr=paraswap,
            usd=Decimal("999"), tx_hash=tx,
        ),
    ])
    swaps = detect_dex_swaps(case)
    # We get one swap for the 1inch input; the paraswap leg
    # isn't surfaced as the "output" because it's another
    # router (which we'd want to keep tracing past, not stop at).
    assert len(swaps) >= 1
    # The 1inch swap should NOT have paraswap as its output
    # recipient (we filter router-to-router).
    one_inch_swap = next(s for s in swaps if s.router_address == oneinch)
    assert one_inch_swap.output_recipient != paraswap


def test_dex_swap_brief_section_shape() -> None:
    """Locked: keys the brief renderer + investigator CSV
    consume from each DEXSwap entry."""
    swapper = "0x" + "1" * 40
    oneinch = "0x1111111254eeb25477b68fb85ed929f73a960582"
    perp = "0x" + "9" * 40
    tx = "0x" + "f" * 64
    case = _mk_case([
        _mk_transfer(
            from_addr=swapper, to_addr=oneinch,
            usd=Decimal("48200"), tx_hash=tx,
            token_symbol="USDC",
        ),
        _mk_transfer(
            from_addr=oneinch, to_addr=perp,
            usd=Decimal("48100"), tx_hash=tx,
            token_symbol="USDT",
        ),
    ])
    swaps = detect_dex_swaps(case)
    section = dex_swaps_to_brief_section(swaps)
    assert len(section) == 1
    entry = section[0]
    for key in (
        "tx_hash", "explorer_url", "block_time", "swapper",
        "router_address", "router_name", "router_protocol",
        "input_token", "input_amount", "input_amount_usd",
        "output_token", "output_amount", "output_amount_usd",
        "output_recipient", "confidence", "investigator_note",
    ):
        assert key in entry, f"missing key: {key}"
    assert entry["confidence"] == "high"
    assert entry["output_recipient"] == perp
    assert "Continue tracing" in entry["investigator_note"]
