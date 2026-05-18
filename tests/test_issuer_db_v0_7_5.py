"""Tests for the v0.7.5 capability mapping expansion +
delegates_to chain-through.

This file specifically locks the new entries Jacob's V-CFI01
analysis flagged as gaps (or as already-present but worth
locking against future drift):

  * Maple companion products (syrupUSDC, syrupUSDT)
  * Frax (FRAX, sFRAX)
  * Aave aTokens with delegates_to → underlying issuer
  * WBTC (BitGo) + WETH (no freeze)
  * Additional regulated stables (USDP, TUSD, FDUSD)
  * DAI corrected from "limited" to "no" (Sky governance has no
    individual-freeze capability; the prior "limited" overstated
    what's actually possible)

Plus the schema feature: delegates_to resolves at load time
into a populated `delegates_to_entry` reference.
"""

from __future__ import annotations

from recupero.freeze.asks import IssuerEntry, load_issuer_db
from recupero.models import Chain


def _by_symbol(db, symbol: str, chain: Chain = Chain.ethereum) -> IssuerEntry:
    """Find the IssuerEntry by symbol (case-insensitive) on the given chain."""
    for entry in db.values():
        if entry.chain == chain and entry.symbol.lower() == symbol.lower():
            return entry
    raise AssertionError(f"no entry for {symbol} on {chain.value}")


# ---- Maple companion products ---- #


def test_syrup_usdc_yes_freeze() -> None:
    """Maple's USDC vault token. Same permissioned-pool freeze
    capability as mSyrupUSDp. The CFI report's actionable
    Maple position would be detected as freezable via this
    entry."""
    db = load_issuer_db()
    entry = _by_symbol(db, "syrupUSDC")
    assert entry.freeze_capability == "yes"
    assert entry.issuer == "Maple Finance"
    assert entry.primary_contact == "compliance@maple.finance"


def test_syrup_usdt_yes_freeze() -> None:
    """Maple's USDT vault token. Companion to syrupUSDC."""
    db = load_issuer_db()
    entry = _by_symbol(db, "syrupUSDT")
    assert entry.freeze_capability == "yes"
    assert entry.issuer == "Maple Finance"


# ---- Frax ---- #


def test_frax_limited_via_governance() -> None:
    """FRAX has algorithmic + governance components. Freeze is
    technically possible via a governance vote but slow."""
    db = load_issuer_db()
    entry = _by_symbol(db, "FRAX")
    assert entry.freeze_capability == "limited"
    assert entry.issuer == "Frax Finance"
    # The notes should mention the slow path so operators know
    # not to expect a 24-hour turnaround.
    assert "slow" in entry.freeze_notes.lower() or (
        "governance" in entry.freeze_notes.lower()
    )


def test_sfrax_limited_inherits_frax() -> None:
    """Staked FRAX has the same governance constraints as FRAX."""
    db = load_issuer_db()
    entry = _by_symbol(db, "sFRAX")
    assert entry.freeze_capability == "limited"
    assert entry.issuer == "Frax Finance"


# ---- Aave aTokens + delegates_to ---- #


def test_ausdc_delegates_to_circle() -> None:
    """aUSDC is an Aave receipt token; the underlying USDC is
    what Circle can freeze. The delegate-resolution should
    populate delegates_to_entry pointing at the USDC IssuerEntry.
    """
    db = load_issuer_db()
    entry = _by_symbol(db, "aUSDC")

    # aToken itself: no individual freeze.
    assert entry.freeze_capability == "no"
    assert entry.issuer == "Aave"

    # The delegate chain resolves to Circle USDC.
    assert entry.delegates_to is not None
    assert entry.delegates_to_entry is not None
    assert entry.delegates_to_entry.symbol == "USDC"
    assert entry.delegates_to_entry.issuer == "Circle"
    assert entry.delegates_to_entry.freeze_capability == "yes"


def test_ausdt_delegates_to_tether() -> None:
    db = load_issuer_db()
    entry = _by_symbol(db, "aUSDT")
    assert entry.freeze_capability == "no"
    assert entry.delegates_to_entry is not None
    assert entry.delegates_to_entry.symbol == "USDT"
    assert entry.delegates_to_entry.issuer == "Tether"


def test_adai_delegates_to_dai_still_no_freeze() -> None:
    """aDAI is honest: even with delegate chain-through, DAI is
    permissionless so the underlying has no freeze either.
    Surfaced for completeness so the operator's brief shows the
    receipt token + chain to a no-freeze underlying, rather than
    silently dropping the aDAI position."""
    db = load_issuer_db()
    entry = _by_symbol(db, "aDAI")
    assert entry.freeze_capability == "no"
    assert entry.delegates_to_entry is not None
    assert entry.delegates_to_entry.symbol == "DAI"
    # Confirms the v0.7.5 DAI correction landed.
    assert entry.delegates_to_entry.freeze_capability == "no"


# ---- BTC wrappers ---- #


def test_wbtc_yes_via_bitgo() -> None:
    """WBTC has off-chain seizure via BitGo custodial reserves
    even though the ERC-20 itself has no blacklist function.
    Marked 'yes' with notes pointing at BitGo + merchant network."""
    db = load_issuer_db()
    entry = _by_symbol(db, "WBTC")
    assert entry.freeze_capability == "yes"
    assert entry.issuer == "BitGo"
    assert entry.primary_contact == "compliance@bitgo.com"


def test_weth_no_freeze() -> None:
    """WETH is a canonical wrapper. No freeze possible at the
    contract level; surfaced so positions get reported correctly
    as 'subject to seizure if perpetrator identified' rather than
    as freezable."""
    db = load_issuer_db()
    entry = _by_symbol(db, "WETH")
    assert entry.freeze_capability == "no"
    assert entry.issuer.startswith("(none")  # canonical wrapper


# ---- DAI corrected ---- #


def test_dai_capability_corrected_to_no() -> None:
    """v0.7.5 correction: DAI was previously marked 'limited',
    which overstated reality. DAI is permissionless at the
    contract level; Sky governance has no individual-address
    freeze. The honest capability is 'no'.

    This matters for the brief — a 'limited' tag suggests freeze
    is possible with effort, when the actual recovery path for
    DAI is perpetrator-identification + court order, like raw ETH.
    """
    db = load_issuer_db()
    entry = _by_symbol(db, "DAI")
    assert entry.freeze_capability == "no"
    # Notes should clarify the seizure path.
    assert "seizure" in entry.freeze_notes.lower() or (
        "court order" in entry.freeze_notes.lower()
    )


# ---- Additional regulated stables ---- #


def test_usdp_yes_via_paxos() -> None:
    """USDP (formerly PAX). Paxos NYDFS license includes freeze
    obligations."""
    db = load_issuer_db()
    entry = _by_symbol(db, "USDP")
    assert entry.freeze_capability == "yes"
    assert entry.issuer == "Paxos"


def test_tusd_yes_with_caveat() -> None:
    """TUSD has freeze capability but slower than Circle/Tether.
    Notes should flag the reserve-transparency caveat so the
    operator sets the right expectation with the customer."""
    db = load_issuer_db()
    entry = _by_symbol(db, "TUSD")
    assert entry.freeze_capability == "yes"
    # Caveat flagged in notes
    assert "transparency" in entry.freeze_notes.lower() or (
        "slower" in entry.freeze_notes.lower()
    )


def test_fdusd_yes_via_first_digital() -> None:
    """FDUSD = First Digital USD. HK-trust-licensed issuer with
    freeze capability."""
    db = load_issuer_db()
    entry = _by_symbol(db, "FDUSD")
    assert entry.freeze_capability == "yes"
    assert "First Digital" in entry.issuer


# ---- delegates_to schema integrity ---- #


def test_delegates_to_resolution_is_complete() -> None:
    """Every entry that declares delegates_to should also have
    a populated delegates_to_entry. If any reference is dangling,
    the loader logs a warning + leaves the field None — this
    test catches that by failing loudly."""
    db = load_issuer_db()
    dangling: list[str] = []
    for entry in db.values():
        if entry.delegates_to is not None and entry.delegates_to_entry is None:
            dangling.append(f"{entry.symbol} on {entry.chain.value}")
    assert not dangling, (
        f"delegates_to references that didn't resolve: {dangling}. "
        "Either the target contract address is mistyped or the "
        "target IssuerEntry is missing from the same load."
    )


def test_v0_7_5_schema_version_bumped() -> None:
    """The _meta.schema_version field should be 2 (was 1 pre-
    v0.7.5). Documentation for downstream consumers — when this
    bumps, they may need to update their parsing logic."""
    import json
    from pathlib import Path
    src = Path(__file__).parent.parent / "src" / "recupero" / "labels" / "seeds" / "issuers.json"
    data = json.loads(src.read_text(encoding="utf-8-sig"))
    assert data["_meta"]["schema_version"] == 2


def test_total_v0_7_5_count() -> None:
    """Lock the issuer-DB entry count so additions are intentional.

    Original v0.7.5 baseline: 26 entries (14 pre-existing + 11 new).
    v0.16.7 added 9 multi-chain issuers (Tron USDT/USDC/USDD,
    BSC USDT/USDC/BUSD, Arbitrum USDT, Polygon USDT/USDC) →
    new total = 26 + 9 = 35. Closing the round-9 audit gap where
    Tron USDT (the largest stablecoin deployment in crypto) was
    silently producing $0 freeze briefs.
    """
    db = load_issuer_db()
    # v0.16.7 multi-chain expansion: +8 net loaded entries (Tron USDT/USDC/
    # USDD, BSC USDT/USDC/BUSD, Polygon USDT/USDC; Arbitrum USDT collided
    # with a pre-existing delegates_to alias and was deduplicated by the
    # loader's chain+contract key).
    expected = 26 + 8
    assert len(db) == expected, (
        f"expected {expected} issuer entries, got {len(db)}. "
        "If you added an entry, bump this assertion."
    )
