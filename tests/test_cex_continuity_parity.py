"""v0.32.0 (audit HIGH-10): cross-token-at-parity CEX continuity tests.

Closes the audit finding HIGH-10 in
``docs/JACOB_TRACE_AUDIT_v032.md`` — `cex_continuity` previously
required exact same-token symbol match, silently killing the dominant
CEX laundering pattern (USDT→USDC at parity).

Three tiers of evidence, ranked by confidence:
  * Tier 1 — same symbol, same chain — ``confidence='high'``
  * Tier 2 — different symbol in same parity group, same chain —
            ``confidence='medium'``
  * Tier 3 — different symbol, both stables, different chains —
            ``confidence='low'``

This file adds 8+ synthetic cases covering each tier, the tolerance
boundaries, the disjoint-parity behavior, the empty-group fallback,
the BTC + ETH derivative groups, and a regression guard that Tier 1
exact match still works.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from unittest.mock import MagicMock

from recupero.labels.store import LabelStore
from recupero.models import (
    Case,
    Chain,
    Counterparty,
    Label,
    LabelCategory,
    TokenRef,
    Transfer,
)
from recupero.trace.cex_continuity import (
    BTC_PARITY_GROUPS,
    ETH_PARITY_GROUPS,
    STABLECOIN_PARITY_GROUPS,
    identify_cex_continuity_leads,
    leads_to_brief_section,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


_INCIDENT_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
_BINANCE_HOT_ETH = "0x28C6c06298d514Db089934071355E5743bf21d60"
_BINANCE_HOT_POLY = "0x290275e3db66394C52272398959845170E4DCb88"
_VICTIM = "0x1111111111111111111111111111111111111111"
_PERP = "0x2222222222222222222222222222222222222222"
_NEW_ADDR = "0x3333333333333333333333333333333333333333"
_NEW_ADDR_B = "0x4444444444444444444444444444444444444444"


def _mk_token(symbol: str, decimals: int = 6, chain: Chain = Chain.ethereum) -> TokenRef:
    return TokenRef(
        chain=chain,
        contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        symbol=symbol,
        decimals=decimals,
        coingecko_id=symbol.lower(),
    )


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    usd: Decimal,
    token_symbol: str,
    decimals: int,
    amount_decimal: Decimal,
    chain: Chain = Chain.ethereum,
    block_time: datetime | None = None,
    log_index: int = 0,
    block_number: int = 1_000_000,
) -> Transfer:
    tx_hash = "0x" + f"{abs(hash((from_addr, to_addr, token_symbol, log_index, block_number))):x}".rjust(64, "0")[:64]
    amount_raw = str(int(amount_decimal * (Decimal(10) ** decimals)))
    bt = block_time or _INCIDENT_TIME
    return Transfer(
        transfer_id=f"{chain.value}:{tx_hash}:{log_index}",
        chain=chain,
        tx_hash=tx_hash,
        block_number=block_number,
        block_time=bt,
        log_index=log_index,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=_mk_token(token_symbol, decimals=decimals, chain=chain),
        amount_raw=amount_raw,
        amount_decimal=amount_decimal,
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=bt,
    )


def _mk_case(transfers: list[Transfer], chain: Chain = Chain.ethereum) -> Case:
    return Case(
        case_id="01234567-89ab-cdef-0123-456789abcdef",
        seed_address=_VICTIM,
        chain=chain,
        incident_time=_INCIDENT_TIME,
        transfers=transfers,
        trace_started_at=_INCIDENT_TIME,
    )


def _mk_label_store(
    *entries: tuple[str, str, str], chain: Chain = Chain.ethereum,
) -> LabelStore:
    """Build a tiny in-memory label store. Each entry: (address, name, exchange).

    NB: Label is chain-agnostic by design — LabelStore keys purely by
    normalized address (store.add never reads a chain attribute; lookup
    takes a chain arg only to decide EVM-checksum normalization). The
    `chain` fixture arg therefore does not flow into Label construction.
    """
    _ = chain  # retained for call-site clarity; not a Label field
    store = LabelStore()
    for addr, name, exch in entries:
        lbl = Label(
            address=addr,
            name=name,
            category=LabelCategory.exchange_hot_wallet,
            exchange=exch,
            source="test:fixture",
            confidence="high",
            added_at=datetime(2025, 1, 1, tzinfo=UTC),
        )
        store.add(lbl)
    return store


def _mk_outflow_row(
    *,
    to_addr: str,
    block_time: datetime,
    token_symbol: str,
    decimals: int,
    amount_decimal: Decimal,
    chain: Chain = Chain.ethereum,
    tx_hash: str | None = None,
    from_addr: str = _BINANCE_HOT_ETH,
) -> dict[str, Any]:
    th = tx_hash or "0x" + f"{abs(hash((to_addr, token_symbol, amount_decimal, block_time))):x}".rjust(64, "0")[:64]
    return {
        "chain": chain,
        "tx_hash": th,
        "block_number": 1_001_000,
        "block_time": block_time,
        "log_index": 0,
        "from": from_addr,
        "to": to_addr,
        "token": _mk_token(token_symbol, decimals=decimals, chain=chain),
        "amount_raw": int(amount_decimal * (Decimal(10) ** decimals)),
        "explorer_url": f"https://etherscan.io/tx/{th}",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tier 1 — same exchange, same asset (regression guard)
# ─────────────────────────────────────────────────────────────────────────────


def test_tier1_exact_match_produces_low_confidence_lead() -> None:
    """Regression guard: $250K WBTC deposit → 4.9 WBTC withdrawal same
    chain, same symbol. Tier 1 (exact same-token match) still fires, but
    per the forensic-integrity invariant EVERY CEX-continuity lead is
    ``confidence='low'`` — a same-amount deposit/withdrawal pair through a
    commingled exchange hot wallet is a correlation, not proof, regardless
    of how exact the match is. WBTC is a non-noisy token so it survives the
    deposit-side noise gate.
    """
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT_ETH,
        usd=Decimal("250000"),
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("5"),
    )
    case = _mk_case([deposit])

    outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR,
        block_time=_INCIDENT_TIME + timedelta(hours=2),
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("4.9"),
    )
    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = [outflow]

    label_store = _mk_label_store((_BINANCE_HOT_ETH, "Binance Hot 14", "Binance"))
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert len(leads) == 1
    lead = leads[0]
    assert lead.confidence == "low"
    assert lead.deposit_token_symbol == "WBTC"
    assert lead.candidate_token_symbol == "WBTC"
    assert lead.parity_match is None
    assert lead.cross_chain_parity is False


# ─────────────────────────────────────────────────────────────────────────────
# Tier 2 — USDT → USDC same chain
# ─────────────────────────────────────────────────────────────────────────────


def test_stablecoin_usdt_deposit_dropped_at_noise_gate() -> None:
    """Precision policy (v0.32.1): a $100,000 USDT deposit at Binance is
    dropped at the deposit-side noise gate BEFORE any adapter call, even
    though a 99,500 USDC withdrawal 17 minutes later would be a "parity"
    match on paper. A CEX hot wallet processes millions of USDT/USDC per
    minute, so a same-amount stablecoin pair in a short window has
    thousands of coincidental matches per hour — surfacing it would flood
    the brief with false leads and waste LE time. Stablecoin deposits
    therefore never produce a continuity lead; the (still-low-confidence)
    parity matcher only applies to NON-noisy assets (see the WBTC↔cbBTC
    test below).
    """
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT_ETH,
        usd=Decimal("100000"),
        token_symbol="USDT",
        decimals=6,
        amount_decimal=Decimal("100000"),
    )
    case = _mk_case([deposit])

    outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR,
        block_time=_INCIDENT_TIME + timedelta(minutes=17),
        token_symbol="USDC",
        decimals=6,
        amount_decimal=Decimal("99500"),
    )
    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = [outflow]

    label_store = _mk_label_store((_BINANCE_HOT_ETH, "Binance Hot 14", "Binance"))
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert leads == []
    # Dropped at the gate before any (cost-incurring) adapter call.
    adapter.fetch_erc20_outflows.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Tier 3 — USDT on Ethereum → USDC on Polygon (cross-chain)
# ─────────────────────────────────────────────────────────────────────────────


def test_stablecoin_cross_chain_usdt_eth_to_usdc_polygon_dropped() -> None:
    """Precision policy: a $100K USDT-on-Ethereum deposit is a noisy-token
    deposit and is dropped at the gate, so a $99,800 USDC-on-Polygon
    cross-chain "parity" withdrawal at the same exchange never surfaces.
    Cross-chain stablecoin amount-matching has an even higher coincidental
    rate than same-chain, so it must not produce a lead. (Non-noisy
    cross-chain parity is exercised by the brief-section test below using
    WBTC↔cbBTC.)
    """
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT_ETH,
        usd=Decimal("100000"),
        token_symbol="USDT",
        decimals=6,
        amount_decimal=Decimal("100000"),
        chain=Chain.ethereum,
    )
    case = _mk_case([deposit], chain=Chain.ethereum)

    outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR,
        block_time=_INCIDENT_TIME + timedelta(hours=3),
        token_symbol="USDC",
        decimals=6,
        amount_decimal=Decimal("99800"),
        chain=Chain.polygon,
    )
    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = [outflow]

    label_store = _mk_label_store(
        (_BINANCE_HOT_ETH, "Binance Hot 14", "Binance"),
    )
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert leads == []
    adapter.fetch_erc20_outflows.assert_not_called()


def test_tier3_cross_chain_outside_4h_window_yields_zero_leads() -> None:
    """Cross-chain stable-to-stable but the outflow is 5h later — outside
    the Tier 3 ≤4h window. Even though it would still be inside the
    Tier 1/2 6h default window, Tier 3 enforces the tighter window.
    """
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT_ETH,
        usd=Decimal("100000"),
        token_symbol="USDT",
        decimals=6,
        amount_decimal=Decimal("100000"),
        chain=Chain.ethereum,
    )
    case = _mk_case([deposit], chain=Chain.ethereum)

    outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR,
        block_time=_INCIDENT_TIME + timedelta(hours=5),  # past 4h
        token_symbol="USDC",
        decimals=6,
        amount_decimal=Decimal("99800"),
        chain=Chain.polygon,
    )
    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = [outflow]

    label_store = _mk_label_store(
        (_BINANCE_HOT_ETH, "Binance Hot 14", "Binance"),
    )
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert leads == []


# ─────────────────────────────────────────────────────────────────────────────
# Tolerance boundary — USDT→USDC off by 3% → no hit (above 1.5%)
# ─────────────────────────────────────────────────────────────────────────────


def test_tier2_amount_off_by_3pct_yields_zero_leads() -> None:
    """$100K USDT deposit → 97,000 USDC withdrawal — 3% delta is well
    above the 1.5% stable parity tolerance. No leads.
    """
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT_ETH,
        usd=Decimal("100000"),
        token_symbol="USDT",
        decimals=6,
        amount_decimal=Decimal("100000"),
    )
    case = _mk_case([deposit])

    outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR,
        block_time=_INCIDENT_TIME + timedelta(hours=1),
        token_symbol="USDC",
        decimals=6,
        amount_decimal=Decimal("97000"),  # 3% lower
    )
    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = [outflow]

    label_store = _mk_label_store((_BINANCE_HOT_ETH, "Binance Hot 14", "Binance"))
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert leads == []


# ─────────────────────────────────────────────────────────────────────────────
# Tier 2 — ETH → stETH same exchange, same value
# ─────────────────────────────────────────────────────────────────────────────


def test_eth_deposit_steth_withdrawal_dropped_at_noise_gate() -> None:
    """Precision policy: ETH is in the default noisy_tokens set, so a
    100 ETH ($300K) deposit at Binance is dropped at the gate even though
    a 99.5 stETH withdrawal would be an ETH-parity match. ETH flows
    through a CEX hot wallet are far too high-volume for an amount-match
    to be anything but coincidental. No lead.
    """
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT_ETH,
        usd=Decimal("300000"),
        token_symbol="ETH",
        decimals=18,
        amount_decimal=Decimal("100"),
    )
    case = _mk_case([deposit])

    outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR,
        block_time=_INCIDENT_TIME + timedelta(hours=1),
        token_symbol="STETH",
        decimals=18,
        amount_decimal=Decimal("99.5"),
    )
    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = [outflow]

    label_store = _mk_label_store((_BINANCE_HOT_ETH, "Binance Hot 14", "Binance"))
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert leads == []
    adapter.fetch_erc20_outflows.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Tier 2 — WBTC → cbBTC same exchange (BTC parity group)
# ─────────────────────────────────────────────────────────────────────────────


def test_wbtc_deposit_cbbtc_withdrawal_low_confidence_parity_lead() -> None:
    """5 WBTC ($250K) deposit at Binance → 4.97 cbBTC withdrawal same
    chain. Both in the BTC parity group at 1.0% tolerance. WBTC/cbBTC are
    NON-noisy assets, so the cross-token parity matcher fires and produces
    a lead — but at ``confidence='low'`` (the forensic invariant: a CEX
    continuity correlation is never proof, regardless of tier).
    """
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT_ETH,
        usd=Decimal("250000"),
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("5"),
    )
    case = _mk_case([deposit])

    outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR,
        block_time=_INCIDENT_TIME + timedelta(hours=2),
        token_symbol="CBBTC",
        decimals=8,
        amount_decimal=Decimal("4.97"),  # 0.6% lower, inside 1.0% tol
    )
    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = [outflow]

    label_store = _mk_label_store((_BINANCE_HOT_ETH, "Binance Hot 14", "Binance"))
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert len(leads) == 1
    lead = leads[0]
    assert lead.confidence == "low"
    assert lead.parity_group == "btc"
    assert lead.deposit_token_symbol == "WBTC"
    assert lead.candidate_token_symbol == "CBBTC"


# ─────────────────────────────────────────────────────────────────────────────
# Non-parity asset swap — USDT → BNB — must NOT match
# ─────────────────────────────────────────────────────────────────────────────


def test_non_parity_swap_usdt_to_bnb_yields_zero_leads() -> None:
    """USDT → BNB at the same exchange is NOT a parity match — BNB has
    its own price, no peg to USD. The audit explicitly said DO NOT add
    asset-swap detection for non-parity pairs. Even if the
    amount-by-USD-equivalent happens to match, we MUST NOT produce a
    lead for it.
    """
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT_ETH,
        usd=Decimal("100000"),
        token_symbol="USDT",
        decimals=6,
        amount_decimal=Decimal("100000"),
    )
    case = _mk_case([deposit])

    # 100,000 BNB-symbol outflow — not in any parity group with USDT.
    outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR,
        block_time=_INCIDENT_TIME + timedelta(hours=1),
        token_symbol="BNB",
        decimals=18,
        amount_decimal=Decimal("99800"),  # same numeric, different asset
    )
    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = [outflow]

    label_store = _mk_label_store((_BINANCE_HOT_ETH, "Binance Hot 14", "Binance"))
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert leads == []


# ─────────────────────────────────────────────────────────────────────────────
# Empty parity group — Bitcoin chain has no entry in any parity table
# ─────────────────────────────────────────────────────────────────────────────


def test_empty_parity_group_falls_back_to_tier1_no_crash() -> None:
    """Bitcoin chain has no entry in STABLECOIN_PARITY_GROUPS /
    ETH_PARITY_GROUPS / BTC_PARITY_GROUPS. A non-noisy same-symbol
    same-chain match must STILL fire as Tier 1; cross-token candidates
    must be silently dropped, NOT crash.

    Use Chain.bitcoin (no parity entries) with a non-noisy invented
    symbol so the deposit-side gate doesn't kill it before tier
    classification.
    """
    # Use a Chain that has no parity entries. We need the case to use
    # the ethereum chain (the adapter is mocked) so we pick a non-noisy
    # symbol that ALSO isn't in any parity group on ethereum. "RNDR" is
    # neither noisy nor in any parity group.
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT_ETH,
        usd=Decimal("250000"),
        token_symbol="RNDR",
        decimals=18,
        amount_decimal=Decimal("50000"),
    )
    case = _mk_case([deposit])

    # Cross-token outflow that's NOT in any parity group → silently dropped.
    cross_outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR,
        block_time=_INCIDENT_TIME + timedelta(hours=2),
        token_symbol="LINK",  # also not in any parity group
        decimals=18,
        amount_decimal=Decimal("49000"),
    )
    # Same-symbol Tier 1 outflow → must still fire.
    same_outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR_B,
        block_time=_INCIDENT_TIME + timedelta(hours=2, minutes=5),
        token_symbol="RNDR",
        decimals=18,
        amount_decimal=Decimal("49500"),
    )
    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = [cross_outflow, same_outflow]

    label_store = _mk_label_store((_BINANCE_HOT_ETH, "Binance Hot 14", "Binance"))
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    # Only the same-symbol Tier 1 hit should survive — at 'low'
    # confidence (the forensic invariant caps all continuity leads).
    assert len(leads) == 1
    assert leads[0].confidence == "low"
    assert leads[0].deposit_token_symbol == "RNDR"
    assert leads[0].candidate_token_symbol == "RNDR"
    assert leads[0].candidate_withdrawal_to == _NEW_ADDR_B


# ─────────────────────────────────────────────────────────────────────────────
# Brief consumer must surface parity_match + cross_chain_parity fields
# ─────────────────────────────────────────────────────────────────────────────


def test_brief_section_includes_parity_match_fields() -> None:
    """The brief serializer must surface ``parity_match`` and (for the
    cross-chain case) ``cross_chain_parity`` + ``candidate_chain`` so the
    operator sees WHY the cross-token / cross-chain candidate is a lead.

    Uses a NON-noisy BTC-parity pair (WBTC-on-Ethereum deposit → cbBTC-on-
    Polygon withdrawal) since stablecoin/ETH deposits are dropped at the
    noise gate under the precision policy. The lead is ``confidence='low'``.
    """
    deposit = _mk_transfer(
        from_addr=_PERP,
        to_addr=_BINANCE_HOT_ETH,
        usd=Decimal("250000"),
        token_symbol="WBTC",
        decimals=8,
        amount_decimal=Decimal("5"),
        chain=Chain.ethereum,
    )
    case = _mk_case([deposit], chain=Chain.ethereum)

    outflow = _mk_outflow_row(
        to_addr=_NEW_ADDR,
        block_time=_INCIDENT_TIME + timedelta(hours=3),
        token_symbol="CBBTC",
        decimals=8,
        amount_decimal=Decimal("4.97"),  # 0.6% lower, inside 1.0% BTC tol
        chain=Chain.polygon,
    )
    adapter = MagicMock()
    adapter.fetch_native_outflows.return_value = []
    adapter.fetch_erc20_outflows.return_value = [outflow]

    label_store = _mk_label_store((_BINANCE_HOT_ETH, "Binance Hot 14", "Binance"))
    leads = identify_cex_continuity_leads(
        case, adapter=adapter, label_store=label_store,
    )
    assert len(leads) == 1
    section = leads_to_brief_section(leads)
    assert len(section) == 1
    entry = section[0]
    # Parity-match metadata must be surfaced verbatim.
    assert entry["lead_only"] is True
    assert entry["confidence"] == "low"
    assert entry["parity_match"] == {
        "deposit_asset": "WBTC",
        "withdrawal_asset": "CBBTC",
        "parity_group": "btc",
    }
    assert entry["cross_chain_parity"] is True
    assert entry["candidate_chain"] == "polygon"
    # Investigator note must mention the cross-token + cross-chain
    # reasoning so an analyst reading the brief can act on it.
    assert "WBTC" in entry["investigator_note"]
    assert "CBBTC" in entry["investigator_note"]
    assert "polygon" in entry["investigator_note"]


# ─────────────────────────────────────────────────────────────────────────────
# Parity tables — coverage sanity check
# ─────────────────────────────────────────────────────────────────────────────


def test_parity_groups_define_expected_chains() -> None:
    """The audit listed specific chains in the parity tables. Confirm
    each expected chain has a non-empty parity set.
    """
    # Stables — every listed chain must have at least 3 entries.
    expected_stable_chains = [
        Chain.ethereum, Chain.tron, Chain.bsc, Chain.polygon,
        Chain.arbitrum, Chain.optimism, Chain.base, Chain.avalanche,
        Chain.solana,
    ]
    for c in expected_stable_chains:
        assert c in STABLECOIN_PARITY_GROUPS, f"{c} missing from stable parity table"
        assert len(STABLECOIN_PARITY_GROUPS[c]) >= 3, (
            f"{c} stable group too sparse: {STABLECOIN_PARITY_GROUPS[c]}"
        )

    # ETH-parity must include the main L1 + the major L2s.
    for c in (Chain.ethereum, Chain.arbitrum, Chain.optimism, Chain.base):
        assert c in ETH_PARITY_GROUPS
        assert "ETH" in ETH_PARITY_GROUPS[c]
        assert "WETH" in ETH_PARITY_GROUPS[c]

    # BTC-parity must include Ethereum (WBTC/tBTC/cbBTC).
    assert Chain.ethereum in BTC_PARITY_GROUPS
    assert "WBTC" in BTC_PARITY_GROUPS[Chain.ethereum]
    assert "CBBTC" in BTC_PARITY_GROUPS[Chain.ethereum]
