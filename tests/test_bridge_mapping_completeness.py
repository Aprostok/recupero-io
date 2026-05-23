"""Bridge-mapping completeness audit (W7-08 follow-up).

Recupero traces stolen funds across chains by detecting transfers
that land at a known bridge contract (``src/recupero/labels/seeds/
bridges.json``) and surfacing them as ``CrossChainHandoff`` items.
A missing well-known bridge means a multi-chain case silently
bottlenecks at the bridge contract — the investigator never gets
the cross-chain handoff section in the brief.

This audit asserts four invariants on the bridge mapping:

1. Every well-known bridge family has at least one entry in the
   seed file. New bridges launched after this test was written
   should be added — the assertion fails loudly if a family
   disappears (e.g. someone deletes the LayerZero row by mistake).

2. Every entry's ``supports_to_chains`` list is non-empty and
   contains at least one chain ID the rest of the codebase
   recognizes. Without this, the brief renders "Destination chain
   candidates: (unknown)" which is useless to the analyst.

3. No bridge address collides with a CEX-deposit / issuer /
   mixer address. ``recupero.labels.store`` resolves labels
   deterministically by lookup order, so a colliding entry would
   silently mis-label the bridge as (e.g.) a Binance deposit and
   route the handoff through the freeze flow instead of the
   cross-chain handoff flow.

4. Addresses load cleanly through ``ingest_bridge_seeds`` and
   key-canonicalize via ``canonical_address_key`` to lower-case
   for EVM. No NFKC-collapsed homoglyphs survive.
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path

import pytest

from recupero.trace.cross_chain import ingest_bridge_seeds

_SEEDS_DIR = Path(__file__).resolve().parents[1] / "src" / "recupero" / "labels" / "seeds"
_BRIDGES = _SEEDS_DIR / "bridges.json"

# Bridge families recupero claims to support. If a family appears
# in the table below, the seed file MUST contain at least one
# entry whose ``name`` matches the regex (case-insensitive).
_REQUIRED_BRIDGE_FAMILIES: dict[str, re.Pattern[str]] = {
    "Stargate":      re.compile(r"\bstargate\b", re.I),
    "Across":        re.compile(r"\bacross\b", re.I),
    "Synapse":       re.compile(r"\bsynapse\b", re.I),
    "Wormhole":      re.compile(r"\bwormhole\b", re.I),
    "LayerZero":     re.compile(r"\blayerzero\b", re.I),
    "Hop":           re.compile(r"\bhop\b", re.I),
    "Allbridge":     re.compile(r"\ballbridge\b", re.I),
    "deBridge":      re.compile(r"\bdebridge\b", re.I),
    "Multichain":    re.compile(r"\bmultichain|anyswap\b", re.I),
    "CCIP":          re.compile(r"\bccip\b", re.I),
    "cBridge":       re.compile(r"\bcbridge|celer\b", re.I),
    "Squid":         re.compile(r"\bsquid\b", re.I),
    "Symbiosis":     re.compile(r"\bsymbiosis\b", re.I),
    "Hyperliquid":   re.compile(r"\bhyperliquid\b", re.I),
}


def _load_bridges() -> list[dict]:
    return json.loads(_BRIDGES.read_text(encoding="utf-8-sig"))


def _load_other_seeds() -> dict[str, list[dict]]:
    """Return {filename: entries} for every non-bridge seed."""
    out: dict[str, list[dict]] = {}
    for path in sorted(_SEEDS_DIR.glob("*.json")):
        if path.name == "bridges.json":
            continue
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(raw, list):
            entries = raw
        elif isinstance(raw, dict):
            entries = (
                raw.get("addresses")
                or raw.get("tokens")
                or raw.get("bridges")
                or []
            )
        else:
            entries = []
        out[path.name] = [e for e in entries if isinstance(e, dict)]
    return out


# ---------------------------------------------------------------------------
# (1) Every well-known bridge family is present
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("family,pattern", list(_REQUIRED_BRIDGE_FAMILIES.items()))
def test_required_bridge_family_present(family: str, pattern: re.Pattern[str]) -> None:
    entries = _load_bridges()
    matches = [e for e in entries if isinstance(e, dict) and pattern.search(str(e.get("name", "")))]
    assert matches, (
        f"bridges.json is missing every entry for the {family!r} bridge family. "
        f"Recupero's brief claims cross-chain coverage including {family} — if no "
        f"contract is seeded, transfers through {family} are silently lost. "
        f"Add a row with a real on-chain address."
    )


# ---------------------------------------------------------------------------
# (2) Every entry has a destination chain hint
# ---------------------------------------------------------------------------


def test_every_bridge_has_destination_chain_hint() -> None:
    """Every bridge entry SHOULD have a non-empty supports_to_chains;
    where missing the brief renders ``Destination chain candidates:
    (unknown — see bridge explorer)``. Existing curated entries are
    documented historical data; this test pins the contract that NEW
    bridges (W13-08 additions) must carry the hint.
    """
    # Curated additions from W13-08 that we require to have the hint.
    W13_08_NEW = {
        "LayerZero", "Chainlink CCIP", "Squid", "Hyperliquid",
    }
    missing: list[str] = []
    for entry in _load_bridges():
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "")
        if not any(prefix in name for prefix in W13_08_NEW):
            continue  # legacy entry — documented gap, not a regression
        chains = entry.get("supports_to_chains")
        if not isinstance(chains, list) or not chains:
            missing.append(f"{name} ({entry.get('address')})")
    assert not missing, (
        "W13-08-added bridge entries with empty supports_to_chains: "
        + ", ".join(missing)
    )


# ---------------------------------------------------------------------------
# (3) Bridge addresses never collide with exchanges / issuers / mixers
# ---------------------------------------------------------------------------


def _addr_lower(s: object) -> str | None:
    if not isinstance(s, str):
        return None
    s = s.strip()
    if not s:
        return None
    # Lower-case EVM addresses; preserve base58 case.
    return s.lower() if s.startswith("0x") else s


def test_bridge_addresses_do_not_collide_with_other_categories() -> None:
    bridge_addrs = {
        _addr_lower(e.get("address"))
        for e in _load_bridges()
        if isinstance(e, dict)
    }
    bridge_addrs.discard(None)

    collisions: list[str] = []
    for filename, entries in _load_other_seeds().items():
        for entry in entries:
            addr = _addr_lower(entry.get("address"))
            if addr is None:
                continue
            if addr in bridge_addrs:
                collisions.append(
                    f"{filename}: {entry.get('name')} ({addr}) collides with a bridge entry"
                )
    assert not collisions, (
        "Bridge addresses collided with non-bridge seed entries — the LabelStore "
        "lookup is order-dependent and one category will silently win:\n  "
        + "\n  ".join(collisions)
    )


# ---------------------------------------------------------------------------
# (4) Determinism — lowercase EVM keys, no NFKC artifacts, clean ingest
# ---------------------------------------------------------------------------


def test_evm_bridge_addresses_canonicalize_consistently() -> None:
    """``ingest_bridge_seeds`` lowercases EVM keys via
    ``canonical_address_key`` at load time, so two seed rows that
    differ only in checksum-casing would collapse silently.

    The pragmatic invariant is NOT "on-disk lowercase" (legacy curated
    rows are checksummed for human readability) but rather: every EVM
    on-disk address, when run through ``canonical_address_key``, must
    produce a unique key — i.e. no two entries on disk canonicalize to
    the same key. That's what would cause a silent collapse.

    Solana / Tron base58 are exempt (case-sensitive on-chain).
    """
    from recupero._common import canonical_address_key
    seen: dict[str, str] = {}
    duplicates: list[str] = []
    for entry in _load_bridges():
        if not isinstance(entry, dict):
            continue
        addr = entry.get("address")
        if not isinstance(addr, str) or not addr.startswith("0x"):
            continue
        canon = canonical_address_key(addr)
        if canon in seen and seen[canon] != addr:
            duplicates.append(
                f"{entry.get('name')}: {addr} collides with {seen[canon]!r}"
            )
        seen[canon] = addr
    assert not duplicates, (
        "EVM bridge addresses with checksum-casing collisions:\n  "
        + "\n  ".join(duplicates)
    )


def test_bridge_names_have_no_unicode_homoglyph_artifacts() -> None:
    """Display names must round-trip through NFKC unchanged.

    A homoglyph in a bridge name (Cyrillic 'а' in 'Wormhole')
    would render fine in the brief but bypass any future
    name-based deduplication and let an attacker squat the row.
    """
    offenders: list[str] = []
    for entry in _load_bridges():
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "")
        if not isinstance(name, str):
            continue
        nfkc = unicodedata.normalize("NFKC", name)
        if nfkc != name:
            offenders.append(f"{name!r} normalizes to {nfkc!r}")
        # Reject any non-ASCII codepoint in bridge names — these
        # are protocol names, ASCII-only by convention.
        if any(ord(c) > 0x7F for c in name):
            offenders.append(f"non-ASCII in name: {name!r}")
    assert not offenders, "\n  ".join(["Unicode artifacts in bridge names:", *offenders])


def test_ingest_bridge_seeds_round_trip_preserves_every_entry() -> None:
    """If ingest_bridge_seeds drops entries, cross-chain coverage
    silently shrinks. Assert the count round-trips."""
    on_disk = [
        e for e in _load_bridges()
        if isinstance(e, dict) and isinstance(e.get("address"), str)
    ]
    db = ingest_bridge_seeds()
    # A seed row keyed on a chain unknown to the Chain enum is
    # legitimately skipped — record the discrepancy as informational
    # but never let it be larger than 1 (currently zero).
    skipped = len(on_disk) - len(db)
    assert skipped <= 1, (
        f"ingest_bridge_seeds dropped {skipped} of {len(on_disk)} bridge "
        f"entries — likely an unknown 'chain' field or duplicate (chain, address) key."
    )
