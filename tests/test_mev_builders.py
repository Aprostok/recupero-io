"""Tests for MEV builder list (v0.32.1 trace gap D)."""

from __future__ import annotations

from recupero.trace.mev_builders import (
    BUILDER_VERIFIED,
    KNOWN_MEV_BUILDERS,
    is_mev_builder,
    is_verified_builder,
)

# ---- Positive cases (12+) ---- #


def test_flashbots_builder_1() -> None:
    ok, name = is_mev_builder("0xdAFEA492D9c6733ae3d56b7Ed1ADB60692c98Bc5")
    assert ok is True
    assert name is not None
    assert "Flashbots" in name


def test_flashbots_builder_2() -> None:
    ok, name = is_mev_builder("0xf573d99385c05c23b24ed33de616ad16a43a0919")
    assert ok is True
    assert name is not None and "Flashbots" in name


def test_beaverbuild_recognized() -> None:
    ok, name = is_mev_builder("0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5")
    assert ok is True
    assert name == "beaverbuild"


def test_titan_recognized() -> None:
    ok, name = is_mev_builder("0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97")
    assert ok is True
    assert name == "Titan Builder"


def test_rsync_recognized() -> None:
    ok, name = is_mev_builder("0x1f9090aae28b8a3dceadf281b0f12828e676c326")
    assert ok is True


def test_builder0x69_recognized() -> None:
    ok, _ = is_mev_builder("0x690b9a9e9aa1c9db991c7721a92d351db4fac990")
    assert ok is True


def test_bloxroute_regulated() -> None:
    ok, name = is_mev_builder("0x199d5ed7f45f4ee35960cf22eade2076e95b253f")
    assert ok is True
    assert name is not None and "bloXroute" in name


def test_bloxroute_ethical() -> None:
    ok, _ = is_mev_builder("0x9534ed1c8c2c54d4ed873c5d8a4f47fec38625fa")
    assert ok is True


def test_bloxroute_max_profit() -> None:
    ok, _ = is_mev_builder("0x3b64216ad1a58f61538b4fa1b27327675ab7ed67")
    assert ok is True


def test_eth_builder_dot_com() -> None:
    ok, name = is_mev_builder("0xfeebabe6b0418ec13b30aadf129f5dcdd4f70cea")
    assert ok is True
    assert name is not None


def test_payload_de_recognized() -> None:
    ok, _ = is_mev_builder("0xaab27b150451726ec7738aa1d0a94505c8729bd1")
    assert ok is True


def test_manifold_recognized() -> None:
    ok, _ = is_mev_builder("0x3b9c01dc46b6f51e9e8e8d0c30b6e6dbc54e8c2c")
    assert ok is True


def test_penguinbuild_recognized() -> None:
    ok, _ = is_mev_builder("0x4675c7e5baafbffbca748158becba61ef3b0a263")
    assert ok is True


def test_lightspeedbuilder_recognized() -> None:
    ok, _ = is_mev_builder("0xe688b84b23f322a994a53dbf8e15fa82cdb71127")
    assert ok is True


# ---- Negative cases (5) ---- #


def test_unknown_address_returns_false() -> None:
    ok, name = is_mev_builder("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    assert ok is False
    assert name is None


def test_zero_address_not_builder() -> None:
    ok, _ = is_mev_builder("0x0000000000000000000000000000000000000000")
    assert ok is False


def test_empty_input() -> None:
    assert is_mev_builder("") == (False, None)


def test_none_input() -> None:
    assert is_mev_builder(None) == (False, None)


def test_non_ethereum_chain_returns_false() -> None:
    """Even a real Flashbots address on Arbitrum → (False, None)."""
    ok, _ = is_mev_builder(
        "0xdafea492d9c6733ae3d56b7ed1adb60692c98bc5", chain="arbitrum"
    )
    assert ok is False


# ---- Case-insensitivity ---- #


def test_case_insensitive_match() -> None:
    lower = is_mev_builder("0xdafea492d9c6733ae3d56b7ed1adb60692c98bc5")
    upper = is_mev_builder("0xDAFEA492D9C6733AE3D56B7ED1ADB60692C98BC5")
    mixed = is_mev_builder("0xDaFeA492d9c6733aE3d56B7Ed1ADb60692c98Bc5")
    assert lower == upper == mixed
    assert lower[0] is True


# ---- Coverage assertions (canary tests) ---- #


def test_at_least_12_builders_listed() -> None:
    """Reactor parity floor: ≥ 12 distinct builders."""
    assert len(KNOWN_MEV_BUILDERS) >= 12


def test_verified_dict_parallel_to_known() -> None:
    """Every BUILDER_VERIFIED key must be a KNOWN_MEV_BUILDERS key."""
    assert set(BUILDER_VERIFIED).issubset(set(KNOWN_MEV_BUILDERS))


def test_is_verified_builder_basic() -> None:
    """Flashbots has verified=True; Manifold has verified=False."""
    assert is_verified_builder("0xdafea492d9c6733ae3d56b7ed1adb60692c98bc5") is True
    assert is_verified_builder("0x3b9c01dc46b6f51e9e8e8d0c30b6e6dbc54e8c2c") is False
    assert is_verified_builder("0xunknown") is False
