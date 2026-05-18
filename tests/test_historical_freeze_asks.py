"""Tests for v0.14.8 historical-inflow freeze-ask synthesis.

The case that prompted this: Jacob's V-CFI01 re-run on May 18, 2026
against an October 9, 2025 incident — 7+ months later. Funds had
moved on by then; the dormant detector returned empty; freeze_asks
was empty; no freeze letters got produced.

These tests pin the behavior: when the trace shows freezable-token
inflows above threshold, synthesize_historical_freeze_asks() emits
FreezeAsk records regardless of current balance.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

from recupero.freeze.asks import (
    FreezeAsk,
    IssuerEntry,
    synthesize_historical_freeze_asks,
)
from recupero.models import (
    Case,
    Chain,
    Counterparty,
    TokenRef,
    Transfer,
)


# ---- Real mainnet contract addresses for the test fixtures ---- #

# Real USDT-ERC20 contract.
USDT_CONTRACT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
# Real USDC.
USDC_CONTRACT = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
# Real cbBTC (Coinbase Wrapped BTC).
CBBTC_CONTRACT = "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf"
# Made-up DAI contract for the test (Sky Protocol, NOT freezable).
DAI_CONTRACT = "0x6b175474e89094c44da98b954eedeac495271d0f"


VICTIM = "0x" + "a" * 40
PERP_HUB = "0x" + "b" * 40
USDT_DEST = "0x00000688768803Bbd44095770895ad27ad6b0d95"  # Jacob's case shape
USDC_DEST = "0x6482E8fB42130B3Cce53096BB035Ebe79435e2D4"
DAI_DEST = "0xd2b37aDE14708bf18904047b1E31F8166d39612b"


def _mk_token(*, contract: str, symbol: str, decimals: int = 6) -> TokenRef:
    return TokenRef(
        chain=Chain.ethereum,
        contract=contract,
        symbol=symbol,
        decimals=decimals,
        coingecko_id={
            USDT_CONTRACT: "tether",
            USDC_CONTRACT: "usd-coin",
            CBBTC_CONTRACT: "coinbase-wrapped-btc",
            DAI_CONTRACT: "dai",
        }.get(contract),
    )


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    token: TokenRef,
    usd: Decimal,
    amount: Decimal = Decimal("1000"),
    tx_hash: str = "0x" + "1" * 64,
    block_time: datetime | None = None,
) -> Transfer:
    block_time = block_time or datetime(2025, 10, 9, 0, 29, tzinfo=timezone.utc)
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:1",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=1,
        block_time=block_time,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(
            address=to_addr, label=None, is_contract=False,
        ),
        token=token,
        amount_raw="1000000000",
        amount_decimal=amount,
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=block_time,
    )


def _mk_case(transfers: list[Transfer]) -> Case:
    return Case(
        case_id="V-CFI01-test",
        seed_address=VICTIM,
        chain=Chain.ethereum,
        incident_time=datetime(2025, 10, 9, 0, 29, tzinfo=timezone.utc),
        transfers=transfers,
        trace_started_at=datetime(2026, 5, 18, tzinfo=timezone.utc),  # 7 months later
        software_version="test",
        config_used={},
    )


def _mk_issuer_db() -> dict:
    """Real-shape issuer entries for Tether, Circle, Coinbase, Sky."""
    return {
        (Chain.ethereum, USDT_CONTRACT.lower()): IssuerEntry(
            chain=Chain.ethereum, contract=USDT_CONTRACT.lower(),
            symbol="USDT", issuer="Tether",
            freeze_capability="yes",
            freeze_notes="Tether responds within 24h on LE-backed freeze requests.",
            primary_contact="compliance@tether.to",
            secondary_contact=None,
            jurisdiction="British Virgin Islands",
        ),
        (Chain.ethereum, USDC_CONTRACT.lower()): IssuerEntry(
            chain=Chain.ethereum, contract=USDC_CONTRACT.lower(),
            symbol="USDC", issuer="Circle",
            freeze_capability="yes",
            freeze_notes="Circle's compliance team is the fastest in stablecoin freezes.",
            primary_contact="compliance@circle.com",
            secondary_contact=None,
            jurisdiction="USA",
        ),
        (Chain.ethereum, CBBTC_CONTRACT.lower()): IssuerEntry(
            chain=Chain.ethereum, contract=CBBTC_CONTRACT.lower(),
            symbol="cbBTC", issuer="Coinbase",
            freeze_capability="limited",
            freeze_notes="cbBTC backing held at Coinbase; freeze pathway via exchange compliance.",
            primary_contact="compliance@coinbase.com",
            secondary_contact=None,
            jurisdiction="USA",
        ),
        (Chain.ethereum, DAI_CONTRACT.lower()): IssuerEntry(
            chain=Chain.ethereum, contract=DAI_CONTRACT.lower(),
            symbol="DAI", issuer="Sky Protocol",
            freeze_capability="no",  # permissionless — no freeze pathway
            freeze_notes="DAI is permissionless; no issuer freeze authority.",
            primary_contact=None,
            secondary_contact=None,
            jurisdiction="(decentralized)",
        ),
    }


# ---- The headline test: Jacob's case shape should produce asks ---- #


def test_jacobs_v_cfi01_case_shape_produces_historical_freeze_asks() -> None:
    """V-CFI01: victim → hub → USDT/USDC/cbBTC destinations. Current
    balances are zero (perp moved funds). The dormant-detector path
    yields nothing. The historical-inflow path MUST yield freeze asks
    for USDT, USDC, cbBTC. NOT for DAI (Sky Protocol, freeze_capability=no)."""
    transfers = [
        # Victim → hub
        _mk_transfer(
            from_addr=VICTIM, to_addr=PERP_HUB,
            token=_mk_token(contract=USDT_CONTRACT, symbol="USDT"),
            usd=Decimal("3120000"),
            tx_hash="0xhub",
        ),
        # Hub → USDT destination (Jacob's $171K case)
        _mk_transfer(
            from_addr=PERP_HUB, to_addr=USDT_DEST,
            token=_mk_token(contract=USDT_CONTRACT, symbol="USDT"),
            usd=Decimal("171000"),
            tx_hash="0xusdt1",
        ),
        # Hub → USDC destination
        _mk_transfer(
            from_addr=PERP_HUB, to_addr=USDC_DEST,
            token=_mk_token(contract=USDC_CONTRACT, symbol="USDC"),
            usd=Decimal("8881"),
            tx_hash="0xusdc1",
        ),
        # Hub → DAI destination (should NOT produce a freeze ask —
        # Sky Protocol can't freeze).
        _mk_transfer(
            from_addr=PERP_HUB, to_addr=DAI_DEST,
            token=_mk_token(contract=DAI_CONTRACT, symbol="DAI", decimals=18),
            usd=Decimal("100000"),
            tx_hash="0xdai1",
        ),
    ]
    case = _mk_case(transfers)
    issuer_db = _mk_issuer_db()
    asks = synthesize_historical_freeze_asks(
        case, issuer_db=issuer_db, min_inflow_usd=Decimal("1000"),
    )
    # Expected: at least 2 asks — Tether (for USDT_DEST), Circle (for USDC_DEST).
    # The hub itself received USDT; it's also in the ask list (separate entry).
    # The DAI destination is filtered (freeze_capability='no').
    issuers = {a.issuer.issuer for a in asks}
    assert "Tether" in issuers, (
        f"Tether ask must be produced for USDT_DEST receipt. Got issuers: {issuers}"
    )
    assert "Circle" in issuers, (
        f"Circle ask must be produced for USDC_DEST receipt. Got issuers: {issuers}"
    )
    assert "Sky Protocol" not in issuers, (
        "Sky Protocol must NOT receive a freeze ask — DAI is permissionless "
        "and a freeze letter would waste the operator's time."
    )
    # All emitted asks must carry evidence_type='historical_inflow'.
    assert all(a.evidence_type == "historical_inflow" for a in asks)
    # And observed_at_iso should be populated.
    assert all(a.observed_at_iso for a in asks)


def test_below_threshold_inflows_skipped() -> None:
    """A $500 receipt is below the $1000 min_inflow_usd → no ask."""
    transfers = [
        _mk_transfer(
            from_addr=VICTIM, to_addr=USDT_DEST,
            token=_mk_token(contract=USDT_CONTRACT, symbol="USDT"),
            usd=Decimal("500"),  # below $1K threshold
        ),
    ]
    case = _mk_case(transfers)
    asks = synthesize_historical_freeze_asks(
        case, issuer_db=_mk_issuer_db(),
        min_inflow_usd=Decimal("1000"),
    )
    assert asks == []


def test_aggregates_multiple_transfers_to_same_address() -> None:
    """Two $200 transfers to the same address (USDT) aggregate to $400.
    Still below threshold. Three $400 transfers aggregate to $1200 →
    above threshold → ONE ask (aggregated)."""
    transfers = [
        _mk_transfer(
            from_addr=VICTIM, to_addr=USDT_DEST,
            token=_mk_token(contract=USDT_CONTRACT, symbol="USDT"),
            usd=Decimal("400"),
            tx_hash="0xtx" + str(i),
        )
        for i in range(3)
    ]
    case = _mk_case(transfers)
    asks = synthesize_historical_freeze_asks(
        case, issuer_db=_mk_issuer_db(),
        min_inflow_usd=Decimal("1000"),
    )
    assert len(asks) == 1
    assert asks[0].holding_usd_value == Decimal("1200")
    # Transfer count is observed_transfer_count, used by the letter.
    assert asks[0].observed_transfer_count == 3


def test_freeze_capability_no_issuers_filtered() -> None:
    """Sky Protocol / DAI: freeze_capability='no'. Even a $1M DAI
    inflow must NOT produce an ask — the freeze letter would be
    pointless and embarrassing."""
    transfers = [
        _mk_transfer(
            from_addr=VICTIM, to_addr=DAI_DEST,
            token=_mk_token(contract=DAI_CONTRACT, symbol="DAI", decimals=18),
            usd=Decimal("1000000"),
        ),
    ]
    case = _mk_case(transfers)
    asks = synthesize_historical_freeze_asks(
        case, issuer_db=_mk_issuer_db(),
    )
    assert asks == []


def test_unknown_contracts_skipped() -> None:
    """A contract not in the issuer DB → no ask (no issuer to contact)."""
    unknown_token = TokenRef(
        chain=Chain.ethereum,
        contract="0x" + "f" * 40,
        symbol="UNKNOWN",
        decimals=18,
    )
    transfers = [
        _mk_transfer(
            from_addr=VICTIM, to_addr="0x" + "c" * 40,
            token=unknown_token,
            usd=Decimal("50000"),
        ),
    ]
    case = _mk_case(transfers)
    asks = synthesize_historical_freeze_asks(
        case, issuer_db=_mk_issuer_db(),
    )
    assert asks == []


def test_native_eth_skipped() -> None:
    """A native ETH transfer (contract=None) has no issuer to contact;
    skip silently."""
    native_eth = TokenRef(
        chain=Chain.ethereum, contract=None, symbol="ETH",
        decimals=18, coingecko_id="ethereum",
    )
    transfers = [
        _mk_transfer(
            from_addr=VICTIM, to_addr="0x" + "c" * 40,
            token=native_eth, usd=Decimal("100000"),
        ),
    ]
    case = _mk_case(transfers)
    asks = synthesize_historical_freeze_asks(
        case, issuer_db=_mk_issuer_db(),
    )
    assert asks == []


def test_seed_address_excluded() -> None:
    """The victim's seed address must NEVER appear as a freeze target,
    even if a perpetrator dust-attacks it with USDT."""
    transfers = [
        # Perp sends $5K USDT BACK to the victim (rare — dust attack
        # / refund / etc.). This must not produce a freeze ask
        # targeting the victim's own wallet.
        _mk_transfer(
            from_addr=PERP_HUB, to_addr=VICTIM,
            token=_mk_token(contract=USDT_CONTRACT, symbol="USDT"),
            usd=Decimal("5000"),
        ),
    ]
    case = _mk_case(transfers)
    asks = synthesize_historical_freeze_asks(
        case, issuer_db=_mk_issuer_db(),
    )
    addrs = {a.candidate_address for a in asks}
    assert VICTIM.lower() not in addrs


def test_exclude_addresses_parameter() -> None:
    """The exclude_addresses kwarg lets the caller skip addresses
    already covered by current-balance freeze asks. Avoids duplicates
    when the synthesizer is run alongside the dormant-detector path."""
    transfers = [
        _mk_transfer(
            from_addr=VICTIM, to_addr=USDT_DEST,
            token=_mk_token(contract=USDT_CONTRACT, symbol="USDT"),
            usd=Decimal("50000"),
        ),
        _mk_transfer(
            from_addr=VICTIM, to_addr=USDC_DEST,
            token=_mk_token(contract=USDC_CONTRACT, symbol="USDC"),
            usd=Decimal("50000"),
            tx_hash="0xusdc",
        ),
    ]
    case = _mk_case(transfers)
    asks = synthesize_historical_freeze_asks(
        case, issuer_db=_mk_issuer_db(),
        exclude_addresses={USDT_DEST},  # already covered by dormant
    )
    addrs = {a.candidate_address for a in asks}
    assert USDT_DEST.lower() not in addrs
    # USDC dest is still surfaced.
    assert USDC_DEST.lower() in addrs


def test_sorted_by_usd_value_descending() -> None:
    """Highest-USD asks first — operator sees the most important
    target at the top of the letter list."""
    transfers = [
        _mk_transfer(
            from_addr=VICTIM, to_addr=USDT_DEST,
            token=_mk_token(contract=USDT_CONTRACT, symbol="USDT"),
            usd=Decimal("5000"),
        ),
        _mk_transfer(
            from_addr=VICTIM, to_addr=USDC_DEST,
            token=_mk_token(contract=USDC_CONTRACT, symbol="USDC"),
            usd=Decimal("50000"),
            tx_hash="0xusdc",
        ),
    ]
    case = _mk_case(transfers)
    asks = synthesize_historical_freeze_asks(
        case, issuer_db=_mk_issuer_db(),
    )
    assert len(asks) == 2
    assert asks[0].holding_usd_value == Decimal("50000")  # USDC first
    assert asks[1].holding_usd_value == Decimal("5000")   # USDT second


def test_explorer_url_is_address_page_not_tx() -> None:
    """The historical ask's explorer_url should point at the
    ADDRESS page (which the operator can inspect at any time),
    not at a single representative tx (which is also fine but less
    useful for the operator's review)."""
    transfers = [
        _mk_transfer(
            from_addr=VICTIM, to_addr=USDT_DEST,
            token=_mk_token(contract=USDT_CONTRACT, symbol="USDT"),
            usd=Decimal("50000"),
        ),
    ]
    case = _mk_case(transfers)
    asks = synthesize_historical_freeze_asks(
        case, issuer_db=_mk_issuer_db(),
    )
    assert asks[0].explorer_url == f"https://etherscan.io/address/{USDT_DEST.lower()}"


# ---- short_summary uses evidence_type ---- #


def test_short_summary_marks_historical_evidence() -> None:
    """The operator-facing one-liner must distinguish historical
    from current-balance asks. Cron logs / dashboard see this."""
    transfers = [
        _mk_transfer(
            from_addr=VICTIM, to_addr=USDT_DEST,
            token=_mk_token(contract=USDT_CONTRACT, symbol="USDT"),
            usd=Decimal("50000"),
        ),
    ]
    case = _mk_case(transfers)
    asks = synthesize_historical_freeze_asks(
        case, issuer_db=_mk_issuer_db(),
    )
    summary = asks[0].short_summary()
    assert "HISTORICAL" in summary
    assert "Tether" in summary
    assert "USDT" in summary


def test_freezeask_default_evidence_type_is_current_balance() -> None:
    """Backward compat: existing call sites that construct FreezeAsk
    without evidence_type get the previous 'current_balance' semantics."""
    from recupero.freeze.asks import FreezeAsk, IssuerEntry
    issuer = IssuerEntry(
        chain=Chain.ethereum, contract=USDT_CONTRACT,
        symbol="USDT", issuer="Tether",
        freeze_capability="yes", freeze_notes="",
        primary_contact="compliance@tether.to",
        secondary_contact=None, jurisdiction="BVI",
    )
    ask = FreezeAsk(
        candidate_address="0xabc",
        chain=Chain.ethereum,
        holding_symbol="USDT",
        holding_decimal_amount=Decimal("100"),
        holding_usd_value=Decimal("100"),
        issuer=issuer,
        explorer_url="",
    )
    assert ask.evidence_type == "current_balance"
    assert ask.observed_at_iso is None
    assert ask.observed_transfer_count == 1
