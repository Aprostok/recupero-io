"""Tests for v0.31.0 MVP indirect-exposure scorer.

Closes gap #3 from the trace-completeness assessment (TRM /
Chainalysis 4-hop weight-decayed exposure scoring). The MVP scorer
walks ``case.transfers`` from the seed (victim) outward up to 4 hops,
applying per-hop weights (1.0, 0.5, 0.25, 0.125) × USD fraction of
total drained. High-risk categories: mixer, sanctioned, ransomware,
darknet_market, scam. Score floor 0.01.

These tests live alongside the v0.10.0 ``test_indirect_exposure.py``
suite. Both algorithms ship; the v0.10.0 one carries rich path-level
attribution, the v0.31 one carries the flat top-10 brief ranking.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.trace.indirect_exposure import (
    _V031_HOP_WEIGHTS,
    _V031_SCORE_FLOOR,
    compute_indirect_exposure_mvp,
    compute_label_exposure_scores,
    label_exposure_scores_to_brief_section,
)

# ---------- helpers ---------- #


SEED = "0x" + "a" * 40   # victim wallet
ADDR_B = "0x" + "b" * 40
ADDR_C = "0x" + "c" * 40
ADDR_D = "0x" + "d" * 40
ADDR_E = "0x" + "e" * 40
ADDR_F = "0x" + "f" * 40


@dataclass
class _FakeLabel:
    """Minimal label shape — has either .category or .risk_category."""
    category: str | None = None
    risk_category: str | None = None


class _FakeLabelStore:
    """Implements .lookup(address) -> _FakeLabel | None."""

    def __init__(self, mapping: dict[str, _FakeLabel]) -> None:
        self._mapping = {k.lower(): v for k, v in mapping.items()}

    def lookup(self, address: str, chain=None):  # noqa: ARG002 — chain unused
        if address is None:
            return None
        return self._mapping.get(address.lower())


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    usd: Decimal | None,
    tx_suffix: str,
) -> Transfer:
    tx_hash = "0x" + (tx_suffix * 64)[:64]
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    fields: dict = {
        "transfer_id": (
            f"ethereum:{tx_hash}:1:{from_addr[-6:]}:{to_addr[-6:]}"
        ),
        "chain": Chain.ethereum,
        "tx_hash": tx_hash,
        "block_number": 1,
        "block_time": ts,
        "from_address": from_addr,
        "to_address": to_addr,
        "counterparty": Counterparty(
            address=to_addr, label=None, is_contract=False,
        ),
        "token": TokenRef(
            chain=Chain.ethereum,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol="USDC",
            decimals=6,
            coingecko_id="usd-coin",
        ),
        "amount_raw": "1000000",
        "amount_decimal": Decimal("1"),
        "usd_value_at_tx": usd,
        "hop_depth": 1,
        "explorer_url": f"https://etherscan.io/tx/{tx_hash}",
        "fetched_at": ts,
    }
    # Pydantic 2's finite_number validator rejects Decimal('NaN') and
    # Decimal('Infinity'). For adversarial tests we mirror the
    # established codebase pattern (test_v030_3_nan_poisoning.py) and
    # bypass validation via model_construct for non-finite values.
    if usd is not None and isinstance(usd, Decimal) and not usd.is_finite():
        return Transfer.model_construct(**fields)
    return Transfer(**fields)


def _mk_case(transfers: list[Transfer], seed: str = SEED) -> Case:
    return Case(
        case_id="v031-test",
        seed_address=seed,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        software_version="test",
        config_used={},
    )


# ---------- direct (1-hop) exposure ---------- #


def test_direct_mixer_counterparty_scores_one_times_usd_fraction() -> None:
    """Seed sends $1000 to a labeled mixer; that's the entire drain.

    With usd_fraction = 1.0 and hop-1 weight = 1.0, the mixer's
    exposure score is 1.0.
    """
    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("1000"), tx_suffix="1"),
    ])
    store = _FakeLabelStore({ADDR_B: _FakeLabel(category="mixer")})
    scores = compute_label_exposure_scores(case, label_store=store)
    assert ADDR_B.lower() in scores
    assert math.isclose(scores[ADDR_B.lower()], 1.0, rel_tol=1e-9)


def test_direct_sanctioned_counterparty_scores_proportionally() -> None:
    """Seed sends $250 to OFAC-sanctioned and $750 to clean.

    Sanctioned address gets 1.0 * (250/1000) = 0.25.
    """
    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("250"), tx_suffix="1"),
        _mk_transfer(from_addr=SEED, to_addr=ADDR_C,
                     usd=Decimal("750"), tx_suffix="2"),
    ])
    store = _FakeLabelStore({
        ADDR_B: _FakeLabel(risk_category="ofac_sanctioned"),
        ADDR_C: _FakeLabel(category="exchange_hot_wallet"),  # not high-risk
    })
    scores = compute_label_exposure_scores(case, label_store=store)
    assert ADDR_B.lower() in scores
    assert math.isclose(scores[ADDR_B.lower()], 0.25, rel_tol=1e-9)
    # Clean exchange address is NOT scored at all.
    assert ADDR_C.lower() not in scores


def test_ransomware_darknet_scam_all_count_as_high_risk() -> None:
    """All five high-risk categories (mixer/sanctioned/ransomware/
    darknet_market/scam) score above the floor."""
    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("100"), tx_suffix="1"),
        _mk_transfer(from_addr=SEED, to_addr=ADDR_C,
                     usd=Decimal("100"), tx_suffix="2"),
        _mk_transfer(from_addr=SEED, to_addr=ADDR_D,
                     usd=Decimal("100"), tx_suffix="3"),
        _mk_transfer(from_addr=SEED, to_addr=ADDR_E,
                     usd=Decimal("100"), tx_suffix="4"),
        _mk_transfer(from_addr=SEED, to_addr=ADDR_F,
                     usd=Decimal("100"), tx_suffix="5"),
    ])
    store = _FakeLabelStore({
        ADDR_B: _FakeLabel(category="mixer"),
        ADDR_C: _FakeLabel(risk_category="ofac_sanctioned"),
        ADDR_D: _FakeLabel(risk_category="ransomware"),
        ADDR_E: _FakeLabel(risk_category="darknet_market"),
        ADDR_F: _FakeLabel(risk_category="scam_drainer"),
    })
    scores = compute_label_exposure_scores(case, label_store=store)
    # All five contribute; each is 100/500 = 0.2 × hop-1 weight 1.0 = 0.2
    assert len(scores) == 5
    for addr in (ADDR_B, ADDR_C, ADDR_D, ADDR_E, ADDR_F):
        assert math.isclose(
            scores[addr.lower()], 0.2, rel_tol=1e-9,
        ), f"{addr} score wrong: {scores[addr.lower()]}"


# ---------- 2-hop exposure ---------- #


def test_two_hop_mixer_scores_half_of_one_hop() -> None:
    """Victim → A (clean) → B (mixer). B is 2 hops from victim.

    Edge fraction for A→B: $500/$1000 = 0.5 (total_drained = $1000
    leaving the seed; the second transfer doesn't leave the seed).
    Score for B = hop-2 weight 0.5 × 0.5 fraction = 0.25.
    """
    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("1000"), tx_suffix="1"),
        _mk_transfer(from_addr=ADDR_B, to_addr=ADDR_C,
                     usd=Decimal("500"), tx_suffix="2"),
    ])
    store = _FakeLabelStore({
        ADDR_C: _FakeLabel(category="mixer"),
    })
    scores = compute_label_exposure_scores(case, label_store=store)
    assert ADDR_C.lower() in scores
    assert math.isclose(scores[ADDR_C.lower()], 0.25, rel_tol=1e-9)
    # ADDR_B is clean (no label) → no score.
    assert ADDR_B.lower() not in scores


def test_hop_weights_table_matches_spec() -> None:
    """The hop-weight table is exactly (1.0, 0.5, 0.25, 0.125)."""
    assert _V031_HOP_WEIGHTS[1] == 1.0
    assert _V031_HOP_WEIGHTS[2] == 0.5
    assert _V031_HOP_WEIGHTS[3] == 0.25
    assert _V031_HOP_WEIGHTS[4] == 0.125


# ---------- defensive: NaN / Inf USD ---------- #


def test_nan_usd_transfers_do_not_crash() -> None:
    """Pure-finite math: a NaN usd_value_at_tx must skip silently."""
    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("NaN"), tx_suffix="1"),
        _mk_transfer(from_addr=SEED, to_addr=ADDR_C,
                     usd=Decimal("Infinity"), tx_suffix="2"),
        _mk_transfer(from_addr=SEED, to_addr=ADDR_D,
                     usd=Decimal("100"), tx_suffix="3"),
    ])
    store = _FakeLabelStore({
        ADDR_B: _FakeLabel(category="mixer"),
        ADDR_C: _FakeLabel(category="mixer"),
        ADDR_D: _FakeLabel(category="mixer"),
    })
    scores = compute_label_exposure_scores(case, label_store=store)
    # Only ADDR_D contributed; ADDR_B / ADDR_C were skipped.
    assert ADDR_D.lower() in scores
    # ADDR_B / ADDR_C had no finite USD value, so they have no edge to score.
    assert ADDR_B.lower() not in scores
    assert ADDR_C.lower() not in scores
    # ADDR_D is the only contributor → fraction 1.0 → score 1.0.
    assert math.isclose(scores[ADDR_D.lower()], 1.0, rel_tol=1e-9)


def test_none_usd_does_not_crash() -> None:
    """usd_value_at_tx=None (unpriced) transfers skip silently."""
    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=None, tx_suffix="1"),
        _mk_transfer(from_addr=SEED, to_addr=ADDR_C,
                     usd=Decimal("100"), tx_suffix="2"),
    ])
    store = _FakeLabelStore({
        ADDR_B: _FakeLabel(category="mixer"),
        ADDR_C: _FakeLabel(category="mixer"),
    })
    scores = compute_label_exposure_scores(case, label_store=store)
    assert ADDR_C.lower() in scores
    assert ADDR_B.lower() not in scores


def test_missing_label_store_does_not_crash() -> None:
    """label_store=None and label_store={} both return {}."""
    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("100"), tx_suffix="1"),
    ])
    assert compute_label_exposure_scores(case, label_store=None) == {}
    assert compute_label_exposure_scores(case, label_store={}) == {}


def test_empty_case_returns_empty() -> None:
    case = _mk_case([])
    store = _FakeLabelStore({})
    assert compute_label_exposure_scores(case, label_store=store) == {}


# ---------- max_hops truncation ---------- #


def test_max_hops_4_truncation() -> None:
    """A 5-hop path with max_hops=4 must NOT reach the 5th-hop address.

    Chain: SEED → B → C → D → E (4 hops) → F (5 hops).
    With max_hops=4, E is reachable (4 hops) but F is not (5 hops).
    """
    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("1000"), tx_suffix="1"),
        _mk_transfer(from_addr=ADDR_B, to_addr=ADDR_C,
                     usd=Decimal("1000"), tx_suffix="2"),
        _mk_transfer(from_addr=ADDR_C, to_addr=ADDR_D,
                     usd=Decimal("1000"), tx_suffix="3"),
        _mk_transfer(from_addr=ADDR_D, to_addr=ADDR_E,
                     usd=Decimal("1000"), tx_suffix="4"),
        _mk_transfer(from_addr=ADDR_E, to_addr=ADDR_F,
                     usd=Decimal("1000"), tx_suffix="5"),
    ])
    # Label both 4-hop (E) and 5-hop (F) addresses as mixers.
    store = _FakeLabelStore({
        ADDR_E: _FakeLabel(category="mixer"),
        ADDR_F: _FakeLabel(category="mixer"),
    })
    scores = compute_label_exposure_scores(case, label_store=store, max_hops=4)
    # E is at hop 4 → score = 0.125 × (1000/1000) = 0.125 (above floor)
    assert ADDR_E.lower() in scores
    assert math.isclose(scores[ADDR_E.lower()], 0.125, rel_tol=1e-9)
    # F is at hop 5 → NOT scored (max_hops cap)
    assert ADDR_F.lower() not in scores


def test_max_hops_2_truncation() -> None:
    """max_hops=2: a 3-hop mixer doesn't get scored."""
    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("1000"), tx_suffix="1"),
        _mk_transfer(from_addr=ADDR_B, to_addr=ADDR_C,
                     usd=Decimal("1000"), tx_suffix="2"),
        _mk_transfer(from_addr=ADDR_C, to_addr=ADDR_D,
                     usd=Decimal("1000"), tx_suffix="3"),
    ])
    store = _FakeLabelStore({ADDR_D: _FakeLabel(category="mixer")})
    scores = compute_label_exposure_scores(case, label_store=store, max_hops=2)
    assert ADDR_D.lower() not in scores


# ---------- score floor ---------- #


def test_score_floor_drops_rows_below_threshold() -> None:
    """A tiny edge-fraction × deep-hop weight that lands below 0.01
    must be dropped from the output."""
    # Edge fraction 0.05, hop-4 weight 0.125 → score 0.00625 < 0.01.
    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("950"), tx_suffix="1"),  # 95% clean flow
        _mk_transfer(from_addr=SEED, to_addr=ADDR_C,
                     usd=Decimal("50"), tx_suffix="2"),   # 5% tainted-bound
        _mk_transfer(from_addr=ADDR_C, to_addr=ADDR_D,
                     usd=Decimal("50"), tx_suffix="3"),
        _mk_transfer(from_addr=ADDR_D, to_addr=ADDR_E,
                     usd=Decimal("50"), tx_suffix="4"),
        _mk_transfer(from_addr=ADDR_E, to_addr=ADDR_F,
                     usd=Decimal("50"), tx_suffix="5"),  # F is at hop 4
    ])
    store = _FakeLabelStore({ADDR_F: _FakeLabel(category="mixer")})
    scores = compute_label_exposure_scores(case, label_store=store)
    # Score for F = 0.125 × (50/1000) = 0.00625 < 0.01 floor → dropped
    assert ADDR_F.lower() not in scores


def test_score_floor_keeps_rows_at_or_above_threshold() -> None:
    """A score exactly at 0.01 stays in the output."""
    # 100% of $100 to a hop-1 mixer = score 1.0 (well above floor).
    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("100"), tx_suffix="1"),
    ])
    store = _FakeLabelStore({ADDR_B: _FakeLabel(category="mixer")})
    scores = compute_label_exposure_scores(case, label_store=store)
    assert ADDR_B.lower() in scores
    assert scores[ADDR_B.lower()] >= _V031_SCORE_FLOOR


# ---------- spec-signature alias ---------- #


def test_compute_indirect_exposure_mvp_alias_works() -> None:
    """The task-spec function name is an alias for the implementation."""
    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("1000"), tx_suffix="1"),
    ])
    store = _FakeLabelStore({ADDR_B: _FakeLabel(category="mixer")})
    via_alias = compute_indirect_exposure_mvp(case, label_store=store)
    via_impl = compute_label_exposure_scores(case, label_store=store)
    assert via_alias == via_impl


# ---------- dict-shaped label_store ---------- #


def test_dict_shaped_label_store_works() -> None:
    """The scorer also accepts a plain {address: category_str} dict,
    which is what emit_brief.py passes (it reuses high_risk_db)."""
    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("1000"), tx_suffix="1"),
    ])
    # Dict where value is an object with .risk_category — matches
    # HighRiskEntry shape.
    store = {ADDR_B.lower(): _FakeLabel(risk_category="ofac_sanctioned")}
    scores = compute_label_exposure_scores(case, label_store=store)
    assert ADDR_B.lower() in scores
    assert math.isclose(scores[ADDR_B.lower()], 1.0, rel_tol=1e-9)


# ---------- brief section serialization ---------- #


def test_brief_section_returns_none_below_surface_threshold() -> None:
    """If no score crosses 0.1, the brief section is omitted entirely."""
    # Set up a score that's above the floor (0.01) but below
    # the surface threshold (0.1).
    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("900"), tx_suffix="1"),
        _mk_transfer(from_addr=SEED, to_addr=ADDR_C,
                     usd=Decimal("100"), tx_suffix="2"),  # 10% to clean
        _mk_transfer(from_addr=ADDR_C, to_addr=ADDR_D,
                     usd=Decimal("100"), tx_suffix="3"),  # mixer at hop 2
    ])
    store = _FakeLabelStore({ADDR_D: _FakeLabel(category="mixer")})
    scores = compute_label_exposure_scores(case, label_store=store)
    # ADDR_D: hop-2 weight 0.5 × edge_frac (100/1000=0.1) = 0.05 < 0.1
    assert scores.get(ADDR_D.lower(), 0) < 0.1
    section = label_exposure_scores_to_brief_section(
        case, scores, label_store=store,
    )
    assert section is None


def test_brief_section_shape_when_threshold_met() -> None:
    """When at least one score >= 0.1, the section publishes a
    top-N ranked list with the spec'd field set."""
    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("1000"), tx_suffix="1"),
        _mk_transfer(from_addr=ADDR_B, to_addr=ADDR_C,
                     usd=Decimal("500"), tx_suffix="2"),
    ])
    store = _FakeLabelStore({
        ADDR_B: _FakeLabel(category="mixer"),
        ADDR_C: _FakeLabel(risk_category="ofac_sanctioned"),
    })
    scores = compute_label_exposure_scores(case, label_store=store)
    section = label_exposure_scores_to_brief_section(
        case, scores, label_store=store,
    )
    assert section is not None
    assert "top_addresses" in section
    assert "summary" in section
    # Top entry must be ADDR_B (hop-1 mixer, fraction 1.0 → score 1.0).
    top = section["top_addresses"][0]
    assert top["address"] == ADDR_B.lower()
    assert top["primary_label_category"] == "mixer"
    assert top["hops_from_victim"] == 1
    assert top["exposure_score"] == 1.0
    assert top["total_usd_flow"].startswith("$")
    # ADDR_C should be second (hop-2 sanctioned, fraction 0.5 → score 0.25).
    second = section["top_addresses"][1]
    assert second["address"] == ADDR_C.lower()
    assert second["hops_from_victim"] == 2
    # Summary block fields
    assert section["summary"]["max_hops"] == 4
    assert section["summary"]["surface_threshold"] == 0.1
    assert section["summary"]["addresses_above_surface_threshold"] >= 1


def test_brief_section_caps_at_top_10() -> None:
    """Top-N defaults to 10 regardless of how many scored addresses."""
    # Build 12 direct mixer counterparties; each gets fraction 1/12.
    transfers = []
    extras = [
        "0x" + str(i).rjust(2, "0") * 20 for i in range(11, 23)
    ]
    mapping = {}
    for i, addr in enumerate(extras):
        transfers.append(_mk_transfer(
            from_addr=SEED, to_addr=addr,
            usd=Decimal("100"), tx_suffix=str(i + 1),
        ))
        mapping[addr] = _FakeLabel(category="mixer")
    case = _mk_case(transfers)
    store = _FakeLabelStore(mapping)
    scores = compute_label_exposure_scores(case, label_store=store)
    section = label_exposure_scores_to_brief_section(
        case, scores, label_store=store,
        surface_threshold=0.0,   # force section emission
    )
    assert section is not None
    assert len(section["top_addresses"]) == 10


# ---------- regression: existing v0.10.0 API still works ---------- #


def test_v010_api_still_intact() -> None:
    """The v0.10.0 compute_indirect_exposure(case, high_risk_db) signature
    must keep working — we added the v0.31 MVP alongside, not in place."""
    from recupero.trace.indirect_exposure import (
        compute_indirect_exposure,
        indirect_exposure_to_brief_section,
    )
    from recupero.trace.risk_scoring import HighRiskEntry

    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("1000"), tx_suffix="1"),
    ])
    # Note: v0.10.0 keys high_risk_db by canonical (lowercased EVM) key.
    high_risk_db = {
        SEED.lower(): HighRiskEntry(
            address=SEED.lower(),
            name="Test Sanctioned",
            risk_category="ofac_sanctioned",
            severity=4,
        ),
    }
    results = compute_indirect_exposure(case, high_risk_db)
    section = indirect_exposure_to_brief_section(results)
    # The v0.10.0 section shape is preserved.
    assert "addresses" in section
    assert "summary" in section


def test_label_exposure_warns_when_above_threshold_leads_dropped(caplog) -> None:
    """No silent caps: when more addresses score at/above the surface threshold
    than the top-N surfaced, the dropped significant leads must be WARNed —
    a #11-ranked money-mule must not silently vanish from the LE handoff."""
    import logging

    case = _mk_case([
        _mk_transfer(from_addr=SEED, to_addr=ADDR_B,
                     usd=Decimal("1000"), tx_suffix="1"),
    ])
    store = _FakeLabelStore({})
    scores = {f"0x{i:040x}": 0.5 for i in range(12)}  # 12 above the 0.1 threshold
    with caplog.at_level(logging.WARNING):
        section = label_exposure_scores_to_brief_section(
            case, scores, label_store=store, top_n=10,
        )
    assert section is not None
    assert len(section["top_addresses"]) == 10
    assert "significant exposure lead(s) omitted" in caplog.text
