"""Tests for v15 — issuer database + freeze-ask matching."""

from __future__ import annotations

from decimal import Decimal

from recupero.dormant.finder import DormantCandidate, TokenHolding
from recupero.freeze.asks import (
    FreezeAsk,
    IssuerEntry,
    group_by_issuer,
    load_issuer_db,
    match_freeze_asks,
)
from recupero.models import Chain, TokenRef


def _holding(symbol: str, contract: str | None, usd: Decimal, decimal_amount: Decimal) -> TokenHolding:
    return TokenHolding(
        token=TokenRef(
            chain=Chain.ethereum, contract=contract, symbol=symbol,
            decimals=18 if symbol != "USDC" else 6,
        ),
        raw_amount=int(decimal_amount * Decimal(10**18)),
        decimal_amount=decimal_amount,
        usd_value=usd,
    )


def _candidate(address: str, holdings: list[TokenHolding]) -> DormantCandidate:
    total = sum((h.usd_value for h in holdings if h.usd_value), start=Decimal("0"))
    return DormantCandidate(
        address=address, chain=Chain.ethereum,
        total_usd=total, holdings=holdings,
        explorer_url=f"https://etherscan.io/address/{address}",
    )


class TestLoadIssuerDB:
    def test_loads_seed_database(self):
        db = load_issuer_db()
        # Sanity: known issuers must exist
        usdc_eth = (Chain.ethereum, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
        assert usdc_eth in db
        assert db[usdc_eth].issuer == "Circle"
        assert db[usdc_eth].freeze_capability == "yes"
        assert db[usdc_eth].primary_contact == "compliance@circle.com"

    def test_dai_loaded_with_no_freeze(self):
        """v0.7.5 corrected DAI from 'limited' to 'no'. The prior
        'limited' tag overstated reality — DAI is permissionless
        at the contract level and Sky governance has no individual-
        address freeze. Recovery path for DAI is perpetrator
        identification + court order, not issuer freeze."""
        db = load_issuer_db()
        dai = (Chain.ethereum, "0x6b175474e89094c44da98b954eedeac495271d0f")
        assert dai in db
        assert db[dai].issuer.startswith("Sky")
        assert db[dai].freeze_capability == "no"

    def test_midas_msyrupusdp_loaded(self):
        db = load_issuer_db()
        msyrup = (Chain.ethereum, "0x2fe058ccf29f123f9dd2aec0418aa66a877d8e50")
        assert msyrup in db
        assert db[msyrup].issuer == "Midas"
        assert db[msyrup].primary_contact == "compliance@midas.app"

    def test_arbitrum_usdc_loaded_separately(self):
        db = load_issuer_db()
        arb_usdc = (Chain.arbitrum, "0xaf88d065e77c8cc2239327c5edb3a432268e5831")
        assert arb_usdc in db
        # Different chain, same issuer
        assert db[arb_usdc].issuer == "Circle"


class TestMatchFreezeAsks:
    def test_matches_known_token_to_issuer(self):
        candidate = _candidate(
            "0x3e2E66af967075120fa8bE27C659d0803DfF4436",
            [_holding("msyrupUSDp",
                     "0x2fe058ccf29f123f9dd2aec0418aa66a877d8e50",
                     Decimal("3120000"), Decimal("3109862"))],
        )
        matched, unmatched = match_freeze_asks([candidate])
        assert len(matched) == 1
        assert matched[0].issuer.issuer == "Midas"
        assert matched[0].holding_usd_value == Decimal("3120000")
        assert unmatched == []

    def test_unknown_token_goes_to_unmatched(self):
        random_token_contract = "0x1234567890abcdef1234567890abcdef12345678"
        candidate = _candidate(
            "0xabc",
            [_holding("WHATEVER", random_token_contract,
                     Decimal("50000"), Decimal("100"))],
        )
        matched, unmatched = match_freeze_asks([candidate])
        assert matched == []
        assert len(unmatched) == 1

    def test_native_eth_goes_to_unmatched(self):
        """Native ETH has no contract → cannot have an issuer to freeze."""
        candidate = _candidate(
            "0xabc",
            [_holding("ETH", None, Decimal("100000"), Decimal("22"))],
        )
        matched, unmatched = match_freeze_asks([candidate])
        assert matched == []
        assert len(unmatched) == 1

    def test_below_threshold_dropped(self):
        candidate = _candidate(
            "0xabc",
            [_holding("USDC",
                     "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                     Decimal("500"), Decimal("500"))],  # only $500
        )
        matched, unmatched = match_freeze_asks(
            [candidate], min_holding_usd=Decimal("1000"),
        )
        assert matched == []
        assert unmatched == []  # also not in unmatched (below threshold)

    def test_sorted_by_usd_descending(self):
        c1 = _candidate(
            "0xa",
            [_holding("DAI", "0x6b175474e89094c44da98b954eedeac495271d0f",
                     Decimal("9980000"), Decimal("9980000"))],
        )
        c2 = _candidate(
            "0xb",
            [_holding("msyrupUSDp",
                     "0x2fe058ccf29f123f9dd2aec0418aa66a877d8e50",
                     Decimal("3120000"), Decimal("3109862"))],
        )
        c3 = _candidate(
            "0xc",
            [_holding("USDC", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                     Decimal("100000"), Decimal("100000"))],
        )
        # v0.20.2 (audit-round-2 finding #5): the v0.20.1 filter that
        # routed freeze_capability="no" holdings to `unmatched` was
        # REVERTED — `_compute_perpetrator_holdings` reads ONLY the
        # freezable list when computing the perpetrator-holdings
        # headline, so dropping DAI here silently zeroed an $18M
        # headline on Jacob's V-CFI01 case. DAI now flows through to
        # `matched`; downstream `capability_blocks_freeze` (in
        # _extract_freezable) tags it UNRECOVERABLE for letter
        # generation. Sorted DESC by USD: DAI ($9.98M) > Midas
        # ($3.12M) > USDC ($100K).
        matched, _unmatched = match_freeze_asks([c1, c2, c3])
        assert len(matched) == 3
        assert matched[0].holding_symbol == "DAI"
        assert matched[1].holding_symbol == "msyrupUSDp"
        assert matched[2].holding_symbol == "USDC"

    def test_multi_holding_per_candidate_split_into_separate_asks(self):
        """One address holding USDC + USDT should produce two FreezeAsks.

        v0.20.1 (Jacob V-CFI01 residual #4): the prior fixture used
        DAI (Sky Protocol, freeze_capability=no) which now routes to
        `unmatched`. Replaced with USDT to preserve the original test
        intent (two-holdings-one-candidate → two-asks-same-candidate).
        """
        candidate = _candidate(
            "0xmulti",
            [
                _holding("USDC", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                        Decimal("100000"), Decimal("100000")),
                _holding("USDT", "0xdac17f958d2ee523a2206206994597c13d831ec7",
                        Decimal("50000"), Decimal("50000")),
            ],
        )
        matched, _ = match_freeze_asks([candidate])
        assert len(matched) == 2
        # Both reference the same underlying address
        assert all(a.candidate_address == "0xmulti" for a in matched)
        symbols = {a.holding_symbol for a in matched}
        assert symbols == {"USDC", "USDT"}


class TestGroupByIssuer:
    def test_groups_multiple_asks_to_same_issuer(self):
        """Two USDC holdings at different addresses → one Circle group."""
        c1 = _candidate(
            "0xa",
            [_holding("USDC", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                     Decimal("100000"), Decimal("100000"))],
        )
        c2 = _candidate(
            "0xb",
            [_holding("USDC", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                     Decimal("250000"), Decimal("250000"))],
        )
        matched, _ = match_freeze_asks([c1, c2])
        grouped = group_by_issuer(matched)
        assert "Circle" in grouped
        assert len(grouped["Circle"]) == 2

    def test_zigha_scenario_freezable_targets_grouped_by_issuer(self):
        """Verify the actual Zigha case shape produces correct issuer groups.

        v0.20.1 (Jacob V-CFI01 residual #4): the prior version of this
        test asserted Sky DAI holdings would land in matched. The
        v0.20.1 fix routes freeze_capability='no' issuers to unmatched,
        which is the correct behavior — Sky DAI freeze letters are a
        waste of time (no protocol authority to freeze). Test now asserts
        Midas + USDT shape (both freeze_capability='yes' issuers).
        """
        midas_target = _candidate(
            "0x3e2E66af967075120fa8bE27C659d0803DfF4436",
            [_holding("msyrupUSDp",
                     "0x2fe058ccf29f123f9dd2aec0418aa66a877d8e50",
                     Decimal("3120000"), Decimal("3109862"))],
        )
        tether_target_1 = _candidate(
            "0x00000688768803Bbd44095770895ad27ad6b0d95",
            [_holding("USDT", "0xdac17f958d2ee523a2206206994597c13d831ec7",
                     Decimal("170687"), Decimal("170687"))],
        )
        tether_target_2 = _candidate(
            "0x5141B82f5fFDa4c6fE1E372978F1C5427640a190",
            [_holding("USDT", "0xdac17f958d2ee523a2206206994597c13d831ec7",
                     Decimal("73151"), Decimal("73151"))],
        )
        matched, _ = match_freeze_asks(
            [midas_target, tether_target_1, tether_target_2],
        )
        grouped = group_by_issuer(matched)
        assert len(grouped) == 2
        assert len(grouped["Tether"]) == 2
        assert len(grouped["Midas"]) == 1
        tether_total = sum(a.holding_usd_value for a in grouped["Tether"])
        assert tether_total == Decimal("243838")
