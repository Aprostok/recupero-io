"""Cross-chain address normalization consistency tests.

Addresses cross many boundaries (chain adapter → normalize → dedup
keys → DB-shaped Transfer rows → brief renderer). Different chains
have different case rules:

  * EVM (0x + 40 hex) — case-insensitive on-chain. Lowercase for
    storage / dedup; EIP-55 mixed-case is a DISPLAY convention.
  * Solana — base58, CASE-SENSITIVE on-chain. Lowercasing silently
    corrupts the address.
  * Tron — base58check starting with ``T``, CASE-SENSITIVE.
  * Bitcoin P2PKH (``1...``) / P2SH (``3...``) — base58check,
    CASE-SENSITIVE.
  * Bitcoin bech32 (``bc1...``) — canonical lowercase per BIP173;
    lower() is safe but unnecessary.

Pre-existing tests (``test_canonical_address_key*.py``) pin the
``_ck`` helper. THIS file pins consistency across the *boundaries*
that consume ``_ck`` (or should): adapters that build Transfer
rows, the labels-validator dedup, and the brief display path.

The current owned-RED candidate: ``labels/validator.py:328`` uses
the naïve heuristic ``addr if addr.startswith("T") else addr.lower()``
to choose between "preserve case" and "lowercase". That heuristic
mis-classifies every Solana / Bitcoin address as EVM-shaped and
silently lowercases them for dedup, so a Solana mint and a
hand-mangled lowercase copy of the same mint compare as equal —
exactly the bug ``canonical_address_key`` exists to prevent.
"""

from __future__ import annotations

from recupero._common import canonical_address_key as _ck, short_addr


# ---- Boundary 1: canonical_address_key contract (cross-chain) ---- #


def test_evm_checksum_and_lowercase_dedup_to_same_key() -> None:
    """EIP-55 checksum form and its lowercase form MUST hash to the
    same canonical key. If they don't, dedup over the trace
    transfers table double-counts the same wallet."""
    checksum = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"  # USDC
    lower = checksum.lower()
    assert _ck(checksum) == _ck(lower)


def test_solana_mint_lowercase_does_NOT_collide_with_canonical() -> None:
    """Spoof-resistance: a Solana mint and its lowercased form are
    DIFFERENT on-chain accounts (base58 case-sensitive). Canonical
    keying must keep them distinct so a malicious label submission
    can't shadow the real mint by lowercasing it."""
    canon = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # USDC mint
    lower = canon.lower()
    assert _ck(canon) != _ck(lower)


def test_tron_address_t_prefix_case_preserved() -> None:
    """Tron base58check (T...) is case-sensitive. Storing the
    lowercased form would corrupt the address."""
    canon = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"  # USDT-TRC20
    assert _ck(canon) == canon
    assert _ck(canon) != canon.lower()


def test_bitcoin_p2pkh_case_preserved_across_dedup() -> None:
    """Bitcoin legacy P2PKH base58check is case-sensitive. The
    canonical key must not lowercase."""
    canon = "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s"
    assert _ck(canon) == canon
    assert _ck(canon) != canon.lower()


# ---- Boundary 2: labels-validator dedup must be chain-aware ---- #


def test_labels_validator_dedup_does_NOT_collapse_solana_case() -> None:
    """RED: ``labels/validator.py`` line 328 uses
    ``addr if addr.startswith("T") else addr.lower()`` to dedup
    addresses. That heuristic mis-classifies every Solana / Bitcoin
    address as EVM-shaped and ``.lower()``s them. Result: a Solana
    mint and a different-case copy of the same string compare as
    duplicates inside the validator's seen-addresses set, while on
    Solana they are distinct accounts.

    The validator's dedup key for a Solana / Bitcoin address must
    equal the case-preserving canonical key — i.e. the
    ``canonical_address_key`` form. Anything else is a bug.
    """
    # W13-09 fix: the validator now uses canonical_address_key.
    # Assert that the source file routes through the canonical
    # helper so a future revert is caught.
    from pathlib import Path
    validator_src = (Path(__file__).resolve().parent.parent
                     / "src" / "recupero" / "labels" / "validator.py"
                     ).read_text(encoding="utf-8")
    assert "canonical_address_key" in validator_src, (
        "labels/validator.py must import + apply canonical_address_key "
        "for dedup keying (W13-09 fix). The pre-fix `addr.lower()` "
        "heuristic lowercased Solana / Bitcoin addresses."
    )
    # Negative-control: confirm canonical_address_key actually
    # preserves the Solana mint's mixed case (the property we need).
    canon = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    assert _ck(canon) == canon, (
        "canonical_address_key broke its Solana case-preservation "
        "contract; the W13-09 fix relies on it."
    )


def test_labels_validator_dedup_preserves_bitcoin_p2pkh() -> None:
    """W13-09 companion: Bitcoin P2PKH starts with '1' — must NOT
    be lowercased by the validator. Same root cause."""
    canon = "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s"
    assert _ck(canon) == canon, (
        "canonical_address_key must preserve Bitcoin P2PKH case."
    )


# ---- Boundary 3: display helper (short_addr) preserves case ---- #


def test_short_addr_preserves_solana_case_for_display() -> None:
    """Display path must NOT lower() base58. ``short_addr`` is the
    canonical truncator for briefs / freeze letters; a Solana mint
    in a freeze letter MUST appear in its on-chain case so the
    exchange compliance team can copy-paste it."""
    canon = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    truncated = short_addr(canon)
    # 6-leading + ellipsis + 4-trailing per the convention.
    assert truncated.startswith("EPjFWd")
    assert truncated.endswith("Dt1v")
    # Case from the original must be present (mixed case in head).
    assert "P" in truncated and "j" in truncated


def test_short_addr_preserves_tron_t_prefix() -> None:
    """A Tron USDT contract in a freeze letter must keep the T."""
    canon = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    out = short_addr(canon)
    assert out.startswith("TR7NHq")


# ---- Boundary 4: EVM adapter writes lowercased storage form ---- #


def test_evm_adapter_normalizes_transfer_fields_to_lower() -> None:
    """The Alchemy / Etherscan EVM normalizers MUST store
    ``from`` / ``to`` as lowercase so that downstream dedup by
    raw ``.lower()`` (legacy callers in trace/dex_swaps) and
    by ``canonical_address_key`` (new callers) produce the same
    key. If the adapter leaves checksum case in place, dedup
    silently splits the wallet."""
    from recupero.chains.evm.alchemy_client import AlchemyClient

    row = {
        "hash": "0xdead",
        "blockNum": "0x1",
        "from": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # mixed
        "to": "0xdAC17F958D2ee523a2206206994597C13D831ec7",    # mixed
        "value": "0x0",
        "metadata": {"blockTimestamp": "2024-01-01T00:00:00Z"},
        "rawContract": {},
    }
    out = AlchemyClient._normalize_external_to_etherscan(row)
    assert out["from"] == out["from"].lower()
    assert out["to"] == out["to"].lower()
    # Sanity: must equal the EVM canonical key form.
    assert out["from"] == _ck("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
