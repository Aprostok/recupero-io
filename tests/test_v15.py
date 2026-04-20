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

    def test_dai_loaded_with_limited_freeze(self):
        db = load_issuer_db()
        dai = (Chain.ethereum, "0x6b175474e89094c44da98b954eedeac495271d0f")
        assert dai in db
        assert db[dai].issuer.startswith("Sky")
        assert db[dai].freeze_capability == "limited"

    def test_midas_msyrupusdp_loaded(self):
        db = load_issuer_db()
        msyrup = (Chain.ethereum, "0x2fe058cc73f7e2eecaaa17ed8c11c389a35cd5cb")
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
                     "0x2fe058cc73f7e2eecaaa17ed8c11c389a35cd5cb",
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
                     "0x2fe058cc73f7e2eecaaa17ed8c11c389a35cd5cb",
                     Decimal("3120000"), Decimal("3109862"))],
        )
        c3 = _candidate(
            "0xc",
            [_holding("USDC", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                     Decimal("100000"), Decimal("100000"))],
        )
        matched, _ = match_freeze_asks([c1, c2, c3])
        assert len(matched) == 3
        # DAI ($9.98M) > Midas ($3.12M) > USDC ($100K)
        assert matched[0].holding_symbol == "DAI"
        assert matched[1].holding_symbol == "msyrupUSDp"
        assert matched[2].holding_symbol == "USDC"

    def test_multi_holding_per_candidate_split_into_separate_asks(self):
        """One address holding USDC + DAI should produce two FreezeAsks."""
        candidate = _candidate(
            "0xmulti",
            [
                _holding("USDC", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                        Decimal("100000"), Decimal("100000")),
                _holding("DAI", "0x6b175474e89094c44da98b954eedeac495271d0f",
                        Decimal("50000"), Decimal("50000")),
            ],
        )
        matched, _ = match_freeze_asks([candidate])
        assert len(matched) == 2
        # Both reference the same underlying address
        assert all(a.candidate_address == "0xmulti" for a in matched)
        symbols = {a.holding_symbol for a in matched}
        assert symbols == {"USDC", "DAI"}


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

    def test_zigha_scenario_three_freeze_targets_two_issuers(self):
        """Verify the actual Zigha case shape produces 2 issuer groups."""
        midas_target = _candidate(
            "0x3e2E66af967075120fa8bE27C659d0803DfF4436",
            [_holding("msyrupUSDp",
                     "0x2fe058cc73f7e2eecaaa17ed8c11c389a35cd5cb",
                     Decimal("3120000"), Decimal("3109862"))],
        )
        sky_target_1 = _candidate(
            "0x3daFC6a860334d4feB0467a3D58C3687E9E921B6",
            [_holding("DAI", "0x6b175474e89094c44da98b954eedeac495271d0f",
                     Decimal("9980000"), Decimal("9980000"))],
        )
        sky_target_2 = _candidate(
            "0x415D8D075CAcB5A61Ae854A8e5ea53DF3A76F688",
            [_holding("DAI", "0x6b175474e89094c44da98b954eedeac495271d0f",
                     Decimal("6910000"), Decimal("6910000"))],
        )
        matched, _ = match_freeze_asks([midas_target, sky_target_1, sky_target_2])
        grouped = group_by_issuer(matched)
        # Two distinct issuers
        assert len(grouped) == 2
        # Sky group has 2 asks ($16.89M total), Midas has 1 ($3.12M)
        sky_key = [k for k in grouped if k.startswith("Sky")][0]
        assert len(grouped[sky_key]) == 2
        assert len(grouped["Midas"]) == 1
        sky_total = sum(a.holding_usd_value for a in grouped[sky_key])
        assert sky_total == Decimal("16890000")
