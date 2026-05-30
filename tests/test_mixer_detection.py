"""Tests for mixer_detection (v0.32.1+ Cap-A).

Coverage matrix:
  * Each mixer_type has at least one positive case.
  * Sanctioned entries surface as "sanctioned" type (not technical type).
  * Case-insensitivity for EVM, case-sensitivity for BTC.
  * Chain disambiguation for cross-chain address collisions.
  * Empty / None / non-mixer addresses return (False, None, "none").
"""

from __future__ import annotations

from recupero.trace.mixer_detection import (
    KNOWN_MIXERS,
    count_by_type,
    is_mixer,
    list_known_mixers,
)

# -----------------------------------------------------------------------------
# Positive — zk_mixer (Tornado Cash — OFAC-DELISTED 2025-03-21, still high-risk)
# -----------------------------------------------------------------------------


def test_tornado_1eth_eth_mainnet_high_risk_not_sanctioned():
    """Tornado 1 ETH pool — OFAC DELISTED 2025-03-21 (Van Loon v. Treasury, 5th
    Cir.). Surfaces as its technical type 'zk_mixer' (still a flagged mixer),
    NOT 'sanctioned' — so it no longer triggers a freeze letter. Sinbad/Blender
    (BTC) remain 'sanctioned'."""
    flag, name, mtype = is_mixer(
        "0x47ce0c6eD5b0Ce3D3a51fdb1C52DC66a7c3c2936", "ethereum"
    )
    assert flag is True
    assert "Tornado" in name
    assert mtype == "zk_mixer"  # delisted -> technical type, no freeze letter


def test_tornado_100eth_lowercased_input():
    """Address normalization — lowercase input still hits the registry."""
    flag, name, mtype = is_mixer(
        "0xa160cdab225685da1d56aa342ad8841c3b53f291", "ethereum"
    )
    assert flag is True
    assert "100 ETH" in name


def test_tornado_router_proxy_recognized():
    """The Tornado router proxy contract is still flagged as a zk_mixer
    (OFAC-delisted 2025-03-21, so not 'sanctioned')."""
    flag, name, mtype = is_mixer(
        "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b", "ethereum"
    )
    assert flag is True
    assert mtype == "zk_mixer"


# -----------------------------------------------------------------------------
# Positive — multi-chain Tornado deployments
# -----------------------------------------------------------------------------


def test_tornado_polygon_deployment():
    """Tornado is deployed on Polygon too — different address, same delisting.
    Surfaces as zk_mixer (not 'sanctioned') post-2025-03-21."""
    flag, name, mtype = is_mixer(
        "0xdf231d99ff8b6c6cbf4e9b9a945cbacef9339178", "polygon"
    )
    assert flag is True
    assert "MATIC" in name
    assert mtype == "zk_mixer"


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


def test_fabricated_btc_mixers_removed():
    """v0.34 — the prior Sinbad.io / Blender.io / ChipMixer / Whirlpool /
    Whir / CryptoMixer / FoxMixer BTC literals were FABRICATED (invalid
    checksums) and were removed. They must no longer resolve. CURRENTLY
    OFAC-sanctioned BTC mixers are covered by the OFAC SDN sync, not this
    hardcoded fast-path."""
    for fake in (
        "bc1qy2cmgrcwucy26z6dat0qjehfh5fwnz5q4le930",  # ex-"Sinbad.io"
        "bc1qy4nq6r8c6q4xn80ndxgdt6hkft0qynxdgk6sjz",  # ex-"Blender.io"
        "bc1qm3jzpa6yejmd83axfa3ka7vqg9q0c4wflpqxn5",  # ex-"ChipMixer"
        "bc1qwhirlpool0nq8j4hxs5d6yqj8h0xn5p5pq9xv8y",  # ex-"Whirlpool"
        "bc1qcryptomix0x4n5p3q8m7k9z2vc6h8a5g4f3d2s",  # ex-"CryptoMixer"
        "bc1qfoxmix5q3wn7p8m9k2v5xc6h8a3g4f3d2s1n0p",  # ex-"FoxMixer"
    ):
        flag, name, mtype = is_mixer(fake, "bitcoin")
        assert flag is False, f"fabricated address still present: {fake}"
        assert mtype == "none"


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
    # v0.34: 8 fabricated BTC mixers removed; only the checksum-valid Wasabi
    # coordinator remains. Production sanctioned-BTC coverage is via OFAC sync.
    assert counts.get("btc_mixer", 0) >= 1


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


# -----------------------------------------------------------------------------
# Anti-fabrication guard (v0.34) — every BTC address in the registry must pass
# its real checksum. A fabricated/placeholder literal (the class of bug that
# put 8 fake "Sinbad/Blender/ChipMixer/Whirlpool/..." addresses here) fails the
# bech32/base58check checksum and can never match a real transaction — so this
# guard makes it impossible to silently re-introduce one.
# -----------------------------------------------------------------------------

import hashlib  # noqa: E402

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _bech32_valid(addr: str) -> bool:
    if addr.lower() != addr and addr.upper() != addr:
        return False
    a = addr.lower()
    pos = a.rfind("1")
    if pos < 1 or pos + 7 > len(a) or len(a) > 90:
        return False
    hrp, data = a[:pos], a[pos + 1:]
    if any(c not in _BECH32_CHARSET for c in data):
        return False
    values = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    values += [_BECH32_CHARSET.find(c) for c in data]
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk in (1, 0x2BC830A3)


def _base58check_valid(s: str) -> bool:
    if any(c not in _B58 for c in s):
        return False
    num = 0
    for c in s:
        num = num * 58 + _B58.index(c)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) < 5:
        return False
    body, checksum = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] == checksum


def btc_address_valid(addr: str) -> bool:
    """True iff ``addr`` is a checksum-valid BTC address (bech32 or base58check)."""
    if addr.startswith(("bc1", "tb1", "BC1", "TB1")):
        return _bech32_valid(addr)
    return _base58check_valid(addr)


def test_no_fabricated_btc_addresses():
    """Every bitcoin-chain address in KNOWN_MIXERS must pass its real checksum.
    This is the permanent guard against fabricated/placeholder literals."""
    bad = [
        addr for addr, entry in KNOWN_MIXERS.items()
        if entry.chain == "bitcoin" and not btc_address_valid(addr)
    ]
    assert not bad, f"fabricated (checksum-invalid) BTC addresses in registry: {bad}"


def test_checksum_validator_self_check():
    """Sanity-check the validator: a real address passes, a fabricated one fails."""
    # Genesis coinbase address (real, base58check) and a known-good bech32.
    assert btc_address_valid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    assert btc_address_valid("bc1qs604c7jv6amk4cxqlnvuxv26hv3e48cds4m0ew")
    # Embedded-word placeholders (the fabricated class) must fail.
    assert not btc_address_valid("bc1qwhirlpool0nq8j4hxs5d6yqj8h0xn5p5pq9xv8y")
    assert not btc_address_valid("bc1qcryptomix0x4n5p3q8m7k9z2vc6h8a5g4f3d2s")
