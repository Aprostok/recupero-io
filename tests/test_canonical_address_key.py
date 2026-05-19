"""Direct tests for `recupero._common.canonical_address_key`.

v0.18.8 (round-11 tests-CRIT-001): the canonical-key sweep across
v0.17.5–v0.17.10 touched 18+ modules but had ZERO direct
regression tests. Reverting the sweep passed all 1407 tests. This
file pins the function's contract so a regression is caught
immediately.

The contract:
* EVM (0x + 40 hex) → lower-cased canonical form.
* Base58 (Solana / Tron / Bitcoin) → preserved as-given.
* Empty / None / whitespace-only → empty string.
"""

from __future__ import annotations

from recupero._common import canonical_address_key as _ck


# ---- EVM lowercase ---- #


def test_evm_checksum_lowercased() -> None:
    """EIP-55 checksum-cased EVM address gets lowercased canonical form."""
    assert _ck("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48") == (
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
    )


def test_evm_already_lowercase_unchanged() -> None:
    assert _ck("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") == (
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
    )


def test_evm_uppercase_prefix_unchanged() -> None:
    """0X prefix is uncommon but should NOT be canonicalized as EVM —
    the heuristic is strict-0x + exactly 42 chars."""
    out = _ck("0XA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    # The strict prefix check means this falls through as base58-shape;
    # case preserved. Documented behavior; operators paste 0x.
    assert out == "0XA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"


def test_evm_wrong_length_preserved() -> None:
    """A 40-char hex without 0x or a 44-char form isn't EVM-canonical;
    pass through as-given (base58/other case-sensitive form)."""
    assert _ck("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") == (
        "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
    )


# ---- Base58 case preservation ---- #


def test_solana_mint_case_preserved() -> None:
    """Solana USDC mint must round-trip with mixed case intact."""
    canon = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    assert _ck(canon) == canon


def test_solana_lowercased_form_preserved_separately() -> None:
    """A lowercased Solana mint is NOT the canonical address (Solana
    base58 is case-sensitive), but `_ck` preserves whatever the
    caller gave. The risk_scoring etc. callers protect against the
    spoof by comparing canonical-vs-canonical."""
    canon = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    lowercase = canon.lower()
    assert _ck(canon) == canon
    assert _ck(lowercase) == lowercase
    # Most importantly: the two are DISTINCT under canonical keying.
    assert _ck(canon) != _ck(lowercase)


def test_tron_mainnet_case_preserved() -> None:
    """Tron USDT TRC-20 contract — case-sensitive base58check."""
    canon = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    assert _ck(canon) == canon


def test_tron_usdd_case_preserved() -> None:
    """v0.18.0 (round-11) regression: USDD's canonical form has both
    uppercase R and lowercase p in chars 9-10. Pre-v0.18.0 the
    pricing.coingecko.py had it backwards (rR → rr, p → P)."""
    canon = "TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR"
    assert _ck(canon) == canon


def test_bitcoin_p2pkh_case_preserved() -> None:
    """Bitcoin legacy P2PKH address — base58check, case-sensitive."""
    canon = "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s"
    assert _ck(canon) == canon


def test_bitcoin_bech32_unchanged() -> None:
    """bech32 (bc1...) is canonical-lowercase per BIP173. Either
    case-preservation strategy works because the input is already
    lowercase by spec. `_ck` just passes through."""
    canon = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    assert _ck(canon) == canon


# ---- Empty / None edge cases ---- #


def test_none_returns_empty() -> None:
    assert _ck(None) == ""


def test_empty_string_returns_empty() -> None:
    assert _ck("") == ""


def test_whitespace_only_returns_empty() -> None:
    assert _ck("   ") == ""


def test_strips_outer_whitespace() -> None:
    """Common operator-paste artifact: trailing newline / spaces."""
    assert _ck(" 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 ") == (
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
    )


def test_non_string_input_returns_empty() -> None:
    """Defensive: int / list / dict input must return empty, not crash."""
    assert _ck(123) == ""  # type: ignore[arg-type]
    assert _ck(["0xabc"]) == ""  # type: ignore[arg-type]
    assert _ck({"addr": "0xabc"}) == ""  # type: ignore[arg-type]
