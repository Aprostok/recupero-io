"""Tests for scripts.measure_trace_coverage + an Orbiter decoder lock.

Two unrelated-but-co-located concerns, both pure/offline:

  1. ``coverage_report`` (scripts/measure_trace_coverage.py) — the
     quantitative companion to the ``destinations_superset_of_ground_truth``
     validator. The validator gives pass/fail; this gives a recall number
     plus the gap list. These tests use SYNTHETIC briefs + ground-truth
     dicts (no fixtures, no DB, no network):
       * full match → recall_pct == 100.0, missing == [].
       * partial (1 of 2) → recall_pct == 50.0, gap surfaced with
         role + source.
       * a match via PERP_HUB (not DESTINATIONS) still counts as found.
       * EVM case-insensitivity (lowercase ground truth vs checksum-case
         brief) still matches.
       * empty expected → recall_pct == 100.0 (vacuously complete),
         missing == [].

  2. An Orbiter decoder-accuracy REGRESSION LOCK. The trace pipeline
     relies on ``decode_orbiter_destination`` mapping the real observed
     high-volume Orbiter identification codes to the right chains. A
     future edit to ``ORBITER_CODE_TO_CHAIN`` that silently drops or
     remaps a high-volume code (Base=21 is the single highest-volume
     destination) would degrade live cross-chain continuation without any
     other test noticing. This pins the (code → our_chain) pairs that are
     justified by orbiter.py's own map + the module-docstring provenance.

Every assertion here is derivable from the source — no fabricated
mappings or addresses.
"""

from __future__ import annotations

from recupero.trace.orbiter import (
    ORBITER_CODE_TO_CHAIN,
    decode_orbiter_destination,
)
from scripts.measure_trace_coverage import coverage_report

# ─────────────────────────────────────────────────────────────────────
# Synthetic addresses. EVM hex (0x + 40 hex). The checksum-case variant
# of ADDR_A is used to prove case-insensitive matching.
# ─────────────────────────────────────────────────────────────────────

ADDR_A = "0xf4be227b268e191b79097daad0acccd9a7a7fad2"
ADDR_A_CHECKSUM = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"
ADDR_B = "0x3dafc6a860334d4feb0467a3d58c3687e9e921b6"
ADDR_C = "0x415d8d075cacb5a61ae854a8e5ea53df3a76f688"


def _gt(*entries: dict) -> dict:
    """Build a ground-truth dict from expected-destination entries."""
    return {"case_id": "SYNTH", "expected_destinations": list(entries)}


def _expected(address: str, role: str, source: str) -> dict:
    return {"address": address, "role": role, "source": source}


# ─────────────────────────────────────────────────────────────────────
# coverage_report — full match.
# ─────────────────────────────────────────────────────────────────────


def test_full_match_is_100_pct_no_gaps() -> None:
    """Every expected destination present in DESTINATIONS → 100.0 recall,
    empty gap list."""
    brief = {
        "DESTINATIONS": [
            {"address": ADDR_A},
            {"address": ADDR_B},
        ],
    }
    gt = _gt(
        _expected(ADDR_A, "hub", "src-a"),
        _expected(ADDR_B, "dormant", "src-b"),
    )
    report = coverage_report(brief, gt)
    assert report["expected"] == 2
    assert report["found"] == 2
    assert report["recall_pct"] == 100.0
    assert report["missing"] == []


# ─────────────────────────────────────────────────────────────────────
# coverage_report — partial match (1 of 2).
# ─────────────────────────────────────────────────────────────────────


def test_partial_match_is_50_pct_and_lists_the_gap() -> None:
    """One of two expected found → 50.0 recall, the missing one surfaced
    with its curated role + source for triage."""
    brief = {"DESTINATIONS": [{"address": ADDR_A}]}
    gt = _gt(
        _expected(ADDR_A, "hub", "src-a"),
        _expected(ADDR_B, "dormant DAI holder", "journal.txt"),
    )
    report = coverage_report(brief, gt)
    assert report["expected"] == 2
    assert report["found"] == 1
    assert report["recall_pct"] == 50.0
    assert len(report["missing"]) == 1
    gap = report["missing"][0]
    assert gap["address"] == ADDR_B
    assert gap["role"] == "dormant DAI holder"
    assert gap["source"] == "journal.txt"


# ─────────────────────────────────────────────────────────────────────
# coverage_report — match via a non-DESTINATIONS surface (PERP_HUB).
# ─────────────────────────────────────────────────────────────────────


def test_match_via_perp_hub_only_still_counts_as_found() -> None:
    """An address present only in PERP_HUB (single-dict surface) and NOT
    in DESTINATIONS still counts as found — PERP_HUB is one of the six
    identified-address surfaces the validator gathers."""
    brief = {
        "DESTINATIONS": [],
        "PERP_HUB": {"address": ADDR_A, "chain": "arbitrum"},
    }
    gt = _gt(_expected(ADDR_A, "consolidation hub", "test"))
    report = coverage_report(brief, gt)
    assert report["expected"] == 1
    assert report["found"] == 1
    assert report["recall_pct"] == 100.0
    assert report["missing"] == []


def test_match_via_freezable_holding_and_unrecoverable() -> None:
    """Coverage across two more surfaces: a FREEZABLE[].holdings address
    and an UNRECOVERABLE address. Both count as found, proving the
    gatherer reads the full surface set, not just DESTINATIONS."""
    brief = {
        "DESTINATIONS": [],
        "FREEZABLE": [
            {"issuer": "Midas", "holdings": [{"address": ADDR_B}]},
        ],
        "UNRECOVERABLE": [{"address": ADDR_C, "asset": "DAI"}],
    }
    gt = _gt(
        _expected(ADDR_B, "freezable", "midas"),
        _expected(ADDR_C, "dormant DAI", "journal"),
    )
    report = coverage_report(brief, gt)
    assert report["found"] == 2
    assert report["recall_pct"] == 100.0
    assert report["missing"] == []


# ─────────────────────────────────────────────────────────────────────
# coverage_report — EVM case-insensitivity.
# ─────────────────────────────────────────────────────────────────────


def test_evm_case_insensitive_match() -> None:
    """Ground truth carries the lowercase canonical form; the brief
    carries the EIP-55 checksummed form. EVM addresses are
    case-insensitive at the identity layer, so this is a match."""
    brief = {"DESTINATIONS": [{"address": ADDR_A_CHECKSUM}]}
    gt = _gt(_expected(ADDR_A, "hub", "test"))  # lowercase
    report = coverage_report(brief, gt)
    assert report["found"] == 1
    assert report["recall_pct"] == 100.0
    assert report["missing"] == []


# ─────────────────────────────────────────────────────────────────────
# coverage_report — empty expected list (documented sentinel).
# ─────────────────────────────────────────────────────────────────────


def test_empty_expected_is_vacuously_100_pct() -> None:
    """No expected destinations → recall is 100.0 (vacuously complete:
    the trace was required to find nothing, so it missed nothing). This
    mirrors the validator, which treats an empty expected_destinations
    list as a trivially-satisfied invariant. ``missing`` is []."""
    report = coverage_report({"DESTINATIONS": []}, _gt())
    assert report["expected"] == 0
    assert report["found"] == 0
    assert report["recall_pct"] == 100.0
    assert report["missing"] == []


# ─────────────────────────────────────────────────────────────────────
# coverage_report — rounding (1 of 3 → 33.3, 1 decimal place).
# ─────────────────────────────────────────────────────────────────────


def test_recall_pct_is_one_decimal_place() -> None:
    """1 of 3 found rounds to a single decimal place (33.3, not
    33.33333...). Pins the contract's stated precision."""
    brief = {"DESTINATIONS": [{"address": ADDR_A}]}
    gt = _gt(
        _expected(ADDR_A, "r", "s"),
        _expected(ADDR_B, "r", "s"),
        _expected(ADDR_C, "r", "s"),
    )
    report = coverage_report(brief, gt)
    assert report["found"] == 1
    assert report["expected"] == 3
    assert report["recall_pct"] == 33.3


# ─────────────────────────────────────────────────────────────────────
# Orbiter decoder-accuracy regression lock.
#
# Build the smallest-unit amount as ("1000000000000" + "9{0NN}") where NN
# is the internalId, exactly the (9000 + internalId) marker the decoder
# requires. Assert (.code, .our_chain) maps to the documented chain.
#
# Every pair below is justified by orbiter.py's ORBITER_CODE_TO_CHAIN +
# the module docstring (real-data provenance: 454 inbound deposits to the
# highest-volume Maker, where 21→Base is the single highest-volume code).
# We never assert a pair not present in the map.
# ─────────────────────────────────────────────────────────────────────

# (internalId, expected our_chain). Sourced verbatim from
# ORBITER_CODE_TO_CHAIN. Base=21 is the highest-volume destination, so it
# anchors the guard against a future map edit silently dropping it.
_REAL_HIGH_VOLUME_CODES: list[tuple[int, str]] = [
    (2, "arbitrum"),
    (21, "base"),
    (7, "optimism"),
    (19, "scroll"),
    (23, "linea"),
    (14, "zksync"),
    (15, "bsc"),
    (6, "polygon"),
    (1, "ethereum"),
]


def _amount_for_code(code: int) -> str:
    """Smallest-unit amount carrying the (9000 + code) Orbiter marker in
    its trailing four digits, prefixed with a fixed high-order magnitude
    so the string is > 4 digits long."""
    return "1000000000000" + f"{9000 + code:04d}"


def test_orbiter_decoder_maps_real_high_volume_codes() -> None:
    """Regression lock: each real observed high-volume Orbiter code
    decodes to its documented (.code, .our_chain). A map edit that drops
    or remaps any of these — especially Base (21), the single
    highest-volume destination — trips this test."""
    for code, expected_chain in _REAL_HIGH_VOLUME_CODES:
        amount = _amount_for_code(code)
        dest = decode_orbiter_destination(amount)
        assert dest is not None, (
            f"code {code} (amount {amount}) decoded to None; expected an "
            f"OrbiterDestination for chain {expected_chain}"
        )
        assert dest.code == code, (
            f"expected decoded code {code}, got {dest.code} "
            f"(amount {amount})"
        )
        assert dest.our_chain == expected_chain, (
            f"code {code} expected our_chain {expected_chain!r}, got "
            f"{dest.our_chain!r}"
        )
        # Confidence is a forensic LEAD — never "high".
        assert dest.confidence != "high"


def test_orbiter_lock_pairs_are_self_consistent_with_the_map() -> None:
    """Defence-in-depth: every pair in the regression-lock table must
    actually be present in ORBITER_CODE_TO_CHAIN with the asserted
    our_chain. This guards against the lock table itself drifting away
    from the source map (e.g. a copy-paste typo that would let the
    decoder test pass against a stale expectation)."""
    for code, expected_chain in _REAL_HIGH_VOLUME_CODES:
        assert code in ORBITER_CODE_TO_CHAIN, (
            f"regression-lock code {code} not present in "
            "ORBITER_CODE_TO_CHAIN"
        )
        _orbiter_name, our_chain = ORBITER_CODE_TO_CHAIN[code]
        assert our_chain == expected_chain, (
            f"map disagrees with lock for code {code}: map says "
            f"{our_chain!r}, lock says {expected_chain!r}"
        )
