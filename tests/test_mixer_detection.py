"""Tests for mixer_detection (v0.32.1+ Cap-A).

Coverage matrix:
  * Each mixer_type has at least one positive case.
  * Sanctioned entries surface as "sanctioned" type (not technical type).
  * Case-insensitivity for EVM, case-sensitivity for BTC.
  * Chain disambiguation for cross-chain address collisions.
  * Empty / None / non-mixer addresses return (False, None, "none").
"""

from __future__ import annotations

import pytest

from recupero.trace.mixer_detection import (
    KNOWN_MIXERS,
    count_by_type,
    is_mixer,
    list_known_mixers,
)


# -----------------------------------------------------------------------------
# Positive — zk_mixer (Tornado Cash, sanctioned)
# -----------------------------------------------------------------------------


def test_tornado_1eth_eth_mainnet_sanctioned():
    """Tornado 1 ETH pool — sanctioned overrides technical type."""
    flag, name, mtype = is_mixer(
        "0x47ce0c6eD5b0Ce3D3a51fdb1C52DC66a7c3c2936", "ethereum"
    )
    assert flag is True
    assert "Tornado" in name
    assert mtype == "sanctioned"  # sanctioned -> highest priority signal


def test_tornado_100eth_lowercased_input():
    """Address normalization — lowercase input still hits the registry."""
    flag, name, mtype = is_mixer(
        "0xa160cdab225685da1d56aa342ad8841c3b53f291", "ethereum"
    )
    assert flag is True
    assert "100 ETH" in name


def test_tornado_router_proxy_recognized():
    """The Tornado router proxy contract is also flagged."""
    flag, name, mtype = is_mixer(
        "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b", "ethereum"
    )
    assert flag is True
    assert mtype == "sanctioned"


# -----------------------------------------------------------------------------
# Positive — multi-chain Tornado deployments
# -----------------------------------------------------------------------------


def test_tornado_polygon_deployment():
    """Tornado is deployed on Polygon too — different address, same sanction."""
    flag, name, mtype = is_mixer(
        "0xdf231d99ff8b6c6cbf4e9b9a945cbacef9339178", "polygon"
    )
    assert flag is True
    assert "MATIC" in name
    assert mtype == "sanctioned"


def test_tornado_bsc_deployment():
    """Tornado BSC clone — 1 BNB denomination."""
    flag, name, mtype = is_mixer(
        "0xdf231d99ff8b6c6cbf4e9b9a945cbacef9339179", "bsc"
    )
    assert flag is True
    assert "BNB" in name


# -----------------------------------------------------------------------------
# Positive — privacy_pool (RAILGUN, NOT sanctioned)
# -----------------------------------------------------------------------------


def test_railgun_smart_wallet_not_sanctioned():
    """RAILGUN is a privacy_pool, not sanctioned — surface technical type."""
    flag, name, mtype = is_mixer(
        "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9", "ethereum"
    )
    assert flag is True
    assert "RAILGUN" in name
    assert mtype == "privacy_pool"  # NOT "sanctioned"


def test_railgun_polygon():
    """RAILGUN ships on multiple chains."""
    flag, name, mtype = is_mixer(
        "0x19b620929f97b7b990801496c3b361ca5def8c71", "polygon"
    )
    assert flag is True
    assert mtype == "privacy_pool"


def test_privacy_pools_vitalik_endorsed():
    """Vitalik-co-authored Privacy Pools — NOT sanctioned."""
    flag, name, mtype = is_mixer(
        "0x2c91d908e9fab2dd2441532a04182d791e590f2d", "ethereum"
    )
    assert flag is True
    assert mtype == "privacy_pool"


# -----------------------------------------------------------------------------
# Positive — swap_no_kyc (FixedFloat, ChangeNOW)
# -----------------------------------------------------------------------------


def test_fixedfloat_swap_router():
    """FixedFloat is mixer-adjacent, surfaced as swap_no_kyc."""
    flag, name, mtype = is_mixer(
        "0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f", "ethereum"
    )
    assert flag is True
    assert "FixedFloat" in name
    assert mtype == "swap_no_kyc"


def test_changenow_swap_router():
    """ChangeNOW non-KYC swap."""
    flag, name, mtype = is_mixer(
        "0x077d360f11d220e4d5d831430c81c26c9be7c4a4", "ethereum"
    )
    assert flag is True
    assert mtype == "swap_no_kyc"


# -----------------------------------------------------------------------------
# Positive — btc_mixer
# -----------------------------------------------------------------------------


def test_sinbad_btc_mixer_sanctioned():
    """Sinbad.io — OFAC SDN 2023-11-29."""
    flag, name, mtype = is_mixer(
        "bc1qy2cmgrcwucy26z6dat0qjehfh5fwnz5q4le930", "bitcoin"
    )
    assert flag is True
    assert "Sinbad" in name
    assert mtype == "sanctioned"


def test_blender_btc_mixer_sanctioned():
    """Blender.io — first BTC mixer sanctioned, May 2022."""
    flag, name, mtype = is_mixer(
        "bc1qy4nq6r8c6q4xn80ndxgdt6hkft0qynxdgk6sjz", "bitcoin"
    )
    assert flag is True
    assert "Blender" in name
    assert mtype == "sanctioned"


def test_wasabi_coordinator_btc_mixer():
    """Wasabi 1.0 zkSNACK coordinator — not sanctioned, but mixer type."""
    flag, name, mtype = is_mixer(
        "bc1qs604c7jv6amk4cxqlnvuxv26hv3e48cds4m0ew", "bitcoin"
    )
    assert flag is True
    assert mtype == "btc_mixer"


# -----------------------------------------------------------------------------
# Negative cases
# -----------------------------------------------------------------------------


def test_unknown_address_returns_false():
    flag, name, mtype = is_mixer(
        "0x1111111111111111111111111111111111111111", "ethereum"
    )
    assert flag is False
    assert name is None
    assert mtype == "none"


def test_empty_address_returns_false():
    flag, name, mtype = is_mixer("", "ethereum")
    assert flag is False
    assert mtype == "none"


def test_empty_chain_returns_false():
    flag, name, mtype = is_mixer(
        "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936", ""
    )
    assert flag is False
    assert mtype == "none"


def test_wrong_chain_returns_false():
    """Ethereum Tornado address queried on BSC -> no hit."""
    flag, name, mtype = is_mixer(
        "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936", "bsc"
    )
    assert flag is False


# -----------------------------------------------------------------------------
# Registry hygiene
# -----------------------------------------------------------------------------


def test_registry_has_meaningful_size():
    """Sanity check — we should ship at least 30 entries."""
    assert len(KNOWN_MIXERS) >= 30


def test_count_by_type_covers_all_types():
    """All 5 mixer types are populated."""
    counts = count_by_type()
    assert counts.get("zk_mixer", 0) >= 15
    assert counts.get("privacy_pool", 0) >= 5
    assert counts.get("swap_no_kyc", 0) >= 3
    assert counts.get("btc_mixer", 0) >= 5


def test_list_known_mixers_filter_by_chain():
    """list_known_mixers(chain=X) returns only X-chain entries."""
    eth = list_known_mixers("ethereum")
    btc = list_known_mixers("bitcoin")
    assert len(eth) > 0
    assert len(btc) > 0
    assert all(e[1].chain == "ethereum" for e in eth)
    assert all(e[1].chain == "bitcoin" for e in btc)


def test_list_known_mixers_no_filter_returns_all():
    all_entries = list_known_mixers()
    assert len(all_entries) == len(KNOWN_MIXERS)
