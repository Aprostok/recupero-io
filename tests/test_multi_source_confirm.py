"""Tests for the multi-source label-confirmation gate.

Closes JACOB_ADVERSARY_AUDIT_v032 M-1. Pins:

* Tronscan-only "Binance Hot Wallet" on attacker EOA → REJECT.
* DeFiLlama + Etherscan-contract-source on the same bridge → ACCEPT.
* Single high-trust source for high-impact category → HOLD (needs
  second independent source).
* Non-high-impact category (dex_pool, lp_token) → single source OK.
* Two low-trust sources (Tronscan + Solscan) → REJECT, do not count
  as independent corroboration.
"""

from __future__ import annotations

from recupero.labels.multi_source_confirm import (
    HIGH_IMPACT_CATEGORIES,
    ConfirmationResult,
    confirm_via_secondary_sources,
    requires_multi_source_confirm,
)

# ---------------------------------------------------------------------
# requires_multi_source_confirm gate
# ---------------------------------------------------------------------


def test_requires_confirm_true_for_high_impact_categories():
    for cat in ["exchange_hot_wallet", "mixer", "bridge", "sanctioned"]:
        assert requires_multi_source_confirm({"proposed_category": cat}) is True


def test_requires_confirm_false_for_low_impact_categories():
    for cat in ["dex_pool", "lp_token", "stablecoin_issuer", "service_wallet"]:
        assert requires_multi_source_confirm({"proposed_category": cat}) is False


def test_requires_confirm_accepts_legacy_category_key():
    """The seed-file key is ``category``; the candidate key is
    ``proposed_category``. The gate accepts either."""
    assert requires_multi_source_confirm({"category": "mixer"}) is True
    assert requires_multi_source_confirm({"category": "lp_token"}) is False


def test_requires_confirm_handles_garbage_input():
    assert requires_multi_source_confirm(None) is False  # type: ignore[arg-type]
    assert requires_multi_source_confirm({}) is False
    assert requires_multi_source_confirm({"proposed_category": ""}) is False


# ---------------------------------------------------------------------
# The core attack: Tronscan-only "Binance Hot Wallet" → REJECT
# ---------------------------------------------------------------------


def test_tronscan_only_binance_hot_wallet_rejected():
    """The exact P3 attack from the audit. Tron + low-trust only → reject."""
    res = confirm_via_secondary_sources(
        address="TXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        claimed_category="exchange_hot_wallet",
        claimed_name="Binance Hot Wallet",
        sources_seen=["tronscan_tag"],
        chain="tron",
    )
    assert isinstance(res, ConfirmationResult)
    assert res.accepted is False
    assert res.confidence == "low"
    # Reason mentions Tron + low_trust + the attack reference.
    assert "Tron" in res.reason
    assert "JACOB_ADVERSARY_AUDIT" in res.reason or "P3" in res.reason


def test_tronscan_plus_solscan_still_rejected_for_tron_high_impact():
    """Two low_trust sources are NOT independent corroboration."""
    res = confirm_via_secondary_sources(
        address="TYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
        claimed_category="exchange_hot_wallet",
        claimed_name="Binance Hot Wallet",
        sources_seen=["tronscan_tag", "solscan_tag", "etherscan_public_tag"],
        chain="tron",
    )
    assert res.accepted is False, (
        "5 low_trust sources should not constitute corroboration"
    )


# ---------------------------------------------------------------------
# Acceptance cases
# ---------------------------------------------------------------------


def test_defillama_plus_etherscan_contract_source_accepted_for_bridge():
    """Two high_trust sources from different tiers → confidence='high'."""
    res = confirm_via_secondary_sources(
        address="0xabc1234567890abcdef1234567890abcdef12345",
        claimed_category="bridge",
        claimed_name="Across V3 SpokePool",
        # both 'high_trust' tier; that's 2 in the same tier — accept.
        sources_seen=["defillama_new_protocol", "etherscan_contract_source"],
        chain="ethereum",
    )
    assert res.accepted is True
    assert res.confidence == "high"
    assert "defillama_new_protocol" in res.supporting_sources
    assert "etherscan_contract_source" in res.supporting_sources


def test_high_trust_plus_low_trust_accepted_via_distinct_tiers():
    """One DeFiLlama (high) + one Tronscan (low) on a non-Tron chain →
    accepted because two DISTINCT tiers are present."""
    res = confirm_via_secondary_sources(
        address="0xfeed1234567890abcdef1234567890abcdef1234",
        claimed_category="bridge",
        claimed_name="Wormhole Token Bridge",
        sources_seen=["defillama_new_protocol", "etherscan_public_tag"],
        chain="ethereum",
    )
    assert res.accepted is True
    assert res.confidence == "high"


def test_single_high_trust_source_held_for_high_impact():
    """One DeFiLlama hit, nothing else → operator must wait."""
    res = confirm_via_secondary_sources(
        address="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        claimed_category="mixer",
        claimed_name="Tornado Cash",
        sources_seen=["defillama_new_protocol"],
        chain="ethereum",
    )
    assert res.accepted is False
    assert res.confidence == "medium"
    assert "Need 1 more" in res.reason or "Hold" in res.reason


def test_non_high_impact_single_source_accepted():
    """dex_pool / lp_token can be promoted from a single source."""
    res = confirm_via_secondary_sources(
        address="0xpoolpoolpoolpoolpoolpoolpoolpoolpoolpool",
        claimed_category="dex_pool",
        claimed_name="Uniswap V3 USDC/ETH 0.05%",
        sources_seen=["tronscan_tag"],  # even low_trust is fine
        chain="ethereum",
    )
    assert res.accepted is True


def test_manual_source_treated_as_high_trust():
    """A code-reviewed manual seed PR is high-trust by definition."""
    res = confirm_via_secondary_sources(
        address="0xmanualmanualmanualmanualmanualmanualmanual",
        claimed_category="bridge",
        claimed_name="Stargate Router",
        sources_seen=["manual", "defillama_new_protocol"],
        chain="ethereum",
    )
    assert res.accepted is True
    assert res.confidence == "high"


def test_empty_sources_rejected():
    res = confirm_via_secondary_sources(
        address="0xemptyemptyemptyemptyemptyemptyemptyempty",
        claimed_category="bridge",
        claimed_name="empty",
        sources_seen=[],
        chain="ethereum",
    )
    assert res.accepted is False
    assert "No sources" in res.reason


def test_unknown_source_treated_as_low_trust_fail_closed():
    """An attacker who can spin up 'mybridge_org_tags' should not get a
    high-trust promotion. Unknown sources default to low_trust."""
    res = confirm_via_secondary_sources(
        address="0xattackerattackerattackerattackerattackerattacker",
        claimed_category="bridge",
        claimed_name="Attacker Bridge",
        sources_seen=["mybridge_org_tags", "another_unknown_source"],
        chain="ethereum",
    )
    assert res.accepted is False
    assert res.confidence == "low"


def test_high_impact_categories_set_is_frozen():
    """The set must be a frozenset so callers can't mutate it."""
    assert isinstance(HIGH_IMPACT_CATEGORIES, frozenset)
    assert "bridge" in HIGH_IMPACT_CATEGORIES
    assert "exchange_hot_wallet" in HIGH_IMPACT_CATEGORIES
    assert "dex_pool" not in HIGH_IMPACT_CATEGORIES


def test_supporting_sources_sorted_deduplicated():
    """Returned source list is stable for brief rendering."""
    res = confirm_via_secondary_sources(
        address="0xstablestablestablestablestablestablestable",
        claimed_category="bridge",
        claimed_name="x",
        sources_seen=["etherscan_contract_source", "defillama_new_protocol",
                       "etherscan_contract_source", "defillama_new_protocol"],
        chain="ethereum",
    )
    # Sorted and deduplicated.
    assert res.supporting_sources == [
        "defillama_new_protocol", "etherscan_contract_source"
    ]
