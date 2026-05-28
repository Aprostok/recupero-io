"""v0.29 (protocol × chain) bridge coverage matrix — structural
fix for the diagnostic finding "completeness test only checks family
presence, not chain coverage" (docs/LABEL_DB_GAPS_DIAGNOSTIC.md).

The pre-v0.29 completeness test (`test_required_bridge_family_present`)
asserts that at least one entry exists with a name matching
`\bstargate\b`, `\bdebridge\b`, etc. The Ethereum-side Stargate Router
on its own satisfies that assertion. That's how the Zigha case
slipped through — Stargate was "present" because of one Ethereum row,
even though zero of its Arbitrum / Optimism / Base / Polygon
deployments were seeded.

This file adds the two-dimensional contract: for each (protocol,
chain) pair in a curated matrix, an entry MUST exist. A Zigha-shape
cross-chain handoff that touches Stargate on Arbitrum (the exact
shape we just shipped a fix for) is now caught at test time, not
case-discovery time.

The matrix is curated to match commercial-grade label-DB coverage
(TRM Labs / Chainalysis / Crystal). It's not exhaustive — we
deliberately scope to the protocols most relevant to recovery
forensics (high cross-chain volume, well-documented bridge
behavior). Operators add rows as new protocols hit production
volume thresholds.

When a row in the matrix has zero seed entries, this test fails LOUD.
Adding a new protocol requires either: (a) a corresponding seed
entry, or (b) explicit removal from the matrix (which is a deliberate
operator decision, not silent drift).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

_BRIDGES_PATH = (
    Path(__file__).parent.parent
    / "src" / "recupero" / "labels" / "seeds" / "bridges.json"
)


def _load_entries() -> list[dict]:
    """Load real bridge entries from the seed (skip _section markers)."""
    data = json.loads(_BRIDGES_PATH.read_text(encoding="utf-8"))
    return [
        e for e in data
        if isinstance(e, dict) and "address" in e
    ]


# ──────────────────────────────────────────────────────────────────────
# The matrix. Each entry: (protocol_family, chain) — a row IS REQUIRED
# in bridges.json. If you intentionally drop a row, remove the line
# from this matrix in the same commit so the change is visible.
# ──────────────────────────────────────────────────────────────────────
#
# Sourcing: each (family, chain) pair was selected based on:
#   1. Protocol has a documented mainnet deployment on the chain
#   2. The chain is a meaningful cross-chain destination for
#      recovery cases (theft-volume > $1M aggregate per recent
#      Chainalysis / TRM / PeckShield reporting)
#   3. The protocol's calldata is decodable OR the handoff
#      identification surfaces the bridge via the address label
#
# A future "bridge-sync" cron will diff this matrix against
# DefiLlama's /bridges + L2Beat's directory and emit warnings on
# new (family, chain) pairs we should add.

# Each test gets a separate parametrize entry so pytest gives one
# pass/fail per (family, chain) pair — when it fails the operator
# sees EXACTLY which pair needs a seed row.
COVERAGE_MATRIX: list[tuple[str, str]] = [
    # Stargate (LayerZero stablecoin bridge — high case-relevance).
    ("stargate",   "ethereum"),
    ("stargate",   "arbitrum"),
    ("stargate",   "optimism"),
    ("stargate",   "base"),
    ("stargate",   "polygon"),
    ("stargate",   "bsc"),
    ("stargate",   "avalanche"),
    # Wormhole (cross-ecosystem — supports Solana, BTC).
    ("wormhole",   "ethereum"),
    ("wormhole",   "arbitrum"),
    ("wormhole",   "optimism"),
    ("wormhole",   "base"),
    ("wormhole",   "polygon"),
    ("wormhole",   "bsc"),
    ("wormhole",   "avalanche"),
    # Across V3 (optimistic L2 bridge — frequent in 2024-2025 cases).
    ("across",     "ethereum"),
    ("across",     "arbitrum"),
    ("across",     "optimism"),
    ("across",     "base"),
    ("across",     "polygon"),
    # Hop (L2-focused, token-specific bridges).
    ("hop",        "ethereum"),
    ("hop",        "arbitrum"),
    ("hop",        "optimism"),
    ("hop",        "base"),
    ("hop",        "polygon"),
    # DeBridge (Zigha-relevant — original Jacob v0.27.1 case).
    ("debridge",   "ethereum"),
    ("debridge",   "arbitrum"),
    ("debridge",   "optimism"),
    ("debridge",   "base"),
    ("debridge",   "polygon"),
    # LayerZero (generic messaging — many OFTs / aggregators route here).
    ("layerzero",  "ethereum"),
    ("layerzero",  "arbitrum"),
    ("layerzero",  "optimism"),
    ("layerzero",  "base"),
    ("layerzero",  "polygon"),
    # Native L2 canonical bridges — these are the official L1→L2 entry
    # gateways. Operators trace funds INTO an L2 via these.
    ("arbitrum.+inbox",        "ethereum"),
    ("optimism.+(standard|l1)",  "ethereum"),
    ("base.+(standard|l1)",      "ethereum"),
    ("zksync.+bridge",           "ethereum"),
    ("polygon.+(rootchainmanager|erc20predicate)", "ethereum"),
    # Synapse (cross-chain swap router).
    ("synapse",    "ethereum"),
    # Hyperliquid (used in the original Zigha case).
    ("hyperliquid", "arbitrum"),
    # Chainlink CCIP (Arbitrum coverage — high-volume destination).
    ("chainlink.+ccip", "ethereum"),
    ("chainlink.+ccip", "arbitrum"),
    # v0.29.1 additions — additional protocol families added in the
    # TRM-parity push. Each (family, chain) cell pinned by the
    # corresponding _v029_1_expand_more_bridges.py source.
    # Connext / Everclear — hub-and-spoke fast-finality.
    ("connext",    "ethereum"),
    ("connext",    "arbitrum"),
    ("connext",    "optimism"),
    ("connext",    "base"),
    ("connext",    "polygon"),
    ("connext",    "bsc"),
    # Axelar Gateway — GMP + token bridge, deterministic deploys.
    ("axelar",     "ethereum"),
    ("axelar",     "arbitrum"),
    ("axelar",     "optimism"),
    ("axelar",     "base"),
    ("axelar",     "polygon"),
    ("axelar",     "bsc"),
    ("axelar",     "avalanche"),
    ("axelar",     "fantom"),
    # LiFi Diamond — aggregator. Single deterministic address across
    # most EVM chains; forensically important because LiFi-routed
    # transfers land at the diamond first.
    ("lifi",       "ethereum"),
    ("lifi",       "arbitrum"),
    ("lifi",       "optimism"),
    ("lifi",       "base"),
    ("lifi",       "polygon"),
    ("lifi",       "bsc"),
    # Celer cBridge — liquidity-network bridge.
    ("celer|cbridge", "ethereum"),
    ("celer|cbridge", "arbitrum"),
    ("celer|cbridge", "optimism"),
    ("celer|cbridge", "polygon"),
    ("celer|cbridge", "bsc"),
    # Symbiosis — permissionless cross-chain swap.
    ("symbiosis",  "ethereum"),
    ("symbiosis",  "arbitrum"),
    ("symbiosis",  "polygon"),
    ("symbiosis",  "bsc"),
    # Squid Router (Axelar-based) — broader chain coverage.
    ("squid",      "ethereum"),
    ("squid",      "arbitrum"),
    ("squid",      "polygon"),
    # Synapse — expanded beyond Ethereum.
    ("synapse",    "arbitrum"),
    ("synapse",    "optimism"),
    ("synapse",    "polygon"),
    ("synapse",    "bsc"),
]


def _entry_matches_family(entry: dict, family_pattern: str) -> bool:
    """Match an entry's name against the family pattern.

    Pattern can be a simple substring (matched case-insensitively)
    OR a regex (recognized by presence of '.+' / '|' / '\\b' etc.).
    """
    import re

    name = entry.get("name", "")
    if not isinstance(name, str):
        return False
    name_l = name.lower()
    if any(c in family_pattern for c in ".|+\\(["):
        # Treat as regex.
        try:
            return bool(re.search(family_pattern, name_l, re.IGNORECASE))
        except re.error:
            return False
    # Plain substring.
    return family_pattern.lower() in name_l


@pytest.mark.parametrize("family,chain", COVERAGE_MATRIX, ids=[
    f"{family}-{chain}" for family, chain in COVERAGE_MATRIX
])
def test_coverage_matrix_row_has_seed_entry(family: str, chain: str) -> None:
    """For each curated (family, chain) pair, an entry MUST exist
    in bridges.json. Catches the Zigha-shape gap — pre-v0.28 the
    Stargate-on-Arbitrum row was MISSING, but the single-axis
    "family present" check passed because Stargate-on-Ethereum
    existed."""
    entries = _load_entries()
    matches = [
        e for e in entries
        if e.get("chain") == chain
        and _entry_matches_family(e, family)
    ]
    assert matches, (
        f"COVERAGE MATRIX GAP: no bridges.json entry for "
        f"(family={family!r}, chain={chain!r}). This is the "
        f"Zigha-shape coverage failure the v0.28+v0.29 work was "
        f"meant to prevent. Either add the entry (with external "
        f"source verification) OR delete this row from the "
        f"COVERAGE_MATRIX in tests/test_v029_bridge_coverage_"
        f"matrix.py if the gap is intentional."
    )


def test_coverage_matrix_minimum_size() -> None:
    """The matrix itself must not shrink silently.

    v0.29.0 shipped with ~40 entries; v0.29.1 added Connext / Axelar /
    LiFi / Celer / Symbiosis / Squid / Synapse rows, pushing the
    floor to ~75. Pin the new floor."""
    PINNED_MIN = 75
    assert len(COVERAGE_MATRIX) >= PINNED_MIN, (
        f"COVERAGE_MATRIX has {len(COVERAGE_MATRIX)} entries; "
        f"pin requires at least {PINNED_MIN}. If you intentionally "
        f"shrunk it, bump PINNED_MIN with a comment explaining why."
    )


# ──────────────────────────────────────────────────────────────────────
# Schema validators per the diagnostic recommendations.
# ──────────────────────────────────────────────────────────────────────


def test_every_bridge_entry_has_chain_field() -> None:
    """v0.29 diagnostic Recommendation #2 (CRITICAL): require
    `chain` field on every bridge row. Pre-v0.28 the seed file had
    rows without `chain` (defaulting to ethereum), which made
    coverage gaps invisible to ad-hoc queries.

    Backfill is in the same commit as this test landing.
    """
    missing: list[str] = []
    for e in _load_entries():
        if not isinstance(e.get("chain"), str) or not e["chain"].strip():
            missing.append(f"{e.get('name', '(no name)')} ({e.get('address')})")
    assert not missing, (
        "Bridge entries missing explicit `chain` field — these would "
        "default to 'ethereum' in ingest_bridge_seeds, hiding "
        "potential coverage gaps:\n  " + "\n  ".join(missing)
    )


def test_high_confidence_entries_have_source_url() -> None:
    """v0.29 diagnostic Recommendation #4 (HIGH): provenance gate
    at write time. Every entry with `confidence: high` must have
    `source` populated. The v0.28.4 retrofit proved we can do this
    with WebFetch — formalize it as the entry barrier.

    'externally_verified_v0284' / 'externally_verified_v029'
    audit-status markers are also accepted as proof of provenance.
    """
    missing_provenance: list[str] = []
    for e in _load_entries():
        if e.get("confidence") != "high":
            continue
        # Accept either a non-empty `source` field OR a v0.28.4+
        # `_audit_status` marker proving external verification.
        source = (e.get("source") or "").strip()
        audit_status = (e.get("_audit_status") or "")
        if not source and "externally_verified" not in audit_status:
            missing_provenance.append(
                f"{e.get('name')} ({e.get('address')}): "
                f"confidence=high but source field is empty AND "
                f"no externally_verified audit_status"
            )
    assert not missing_provenance, (
        "High-confidence bridge entries without provenance — pin "
        "the source field at write time (audit Recommendation "
        "#4):\n  " + "\n  ".join(missing_provenance)
    )


def test_v029_addition_count_reasonable() -> None:
    """v0.29.0 added Stargate Pool routers + Wormhole TokenBridges +
    Hop L2 bridges. v0.29.1 added Connext / Axelar / LiFi / Celer /
    Symbiosis / Squid / Synapse. Pin BOTH expansion counts so a
    regression in either expansion script trips a test."""
    v029_entries = [e for e in _load_entries() if e.get("_v029_addition")]
    v029_1_entries = [e for e in _load_entries() if e.get("_v029_1_addition")]
    PINNED_MIN_V029 = 40
    PINNED_MIN_V029_1 = 50
    assert len(v029_entries) >= PINNED_MIN_V029, (
        f"Expected at least {PINNED_MIN_V029} v0.29.0 additions; got "
        f"{len(v029_entries)}. Likely a silent regression in "
        f"scripts/_v029_expand_bridges.py."
    )
    assert len(v029_1_entries) >= PINNED_MIN_V029_1, (
        f"Expected at least {PINNED_MIN_V029_1} v0.29.1 additions; got "
        f"{len(v029_1_entries)}. Likely a silent regression in "
        f"scripts/_v029_1_expand_more_bridges.py."
    )


def test_v029_additions_carry_externally_verified_audit_status() -> None:
    """Every v0.29 addition was WebFetched against the protocol's
    docs at write time. The _audit_status field should reflect
    that — if it doesn't, the provenance gate (Recommendation #4)
    isn't enforced for the v0.29 batch."""
    v029_entries = [
        e for e in _load_entries()
        if e.get("_v029_addition")
    ]
    for e in v029_entries:
        audit_status = e.get("_audit_status") or ""
        assert "externally_verified" in audit_status, (
            f"v0.29 entry {e.get('name')!r} missing externally_"
            f"verified audit_status (got: {audit_status!r}). "
            f"Provenance gate not enforced."
        )
