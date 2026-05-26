"""INVARIANT B (v0.27.2, Jacob 0x52Aa bleed fix item B): trace
coverage regression canary.

Background. The v0.27.1 Zigha smoke test surfaced two issues. Item
A (the 0x52Aa bleed) was a bug visible inside the generated
artifacts — fixed by INVARIANT A and the per-issuer-target / freeze-
ask filtering work pinned in tests/test_jacob_zigha_v0271_residuals.py.
Item B is structurally different: the worker found 1 of 7 known
Zigha destinations. The artifacts that DID generate were fine; the
problem was what wasn't in them. No artifact-only validator can
catch this — the validator has no idea what the worker SHOULD have
found.

INVARIANT B's premise: pin known cases with operator-curated
``ground_truth.json`` files at the case-directory root. Every
expected address in that fixture must appear in the brief's
identified-address set (DESTINATIONS / PERP_HUB /
FREEZABLE.holdings / EXCHANGES / UNRECOVERABLE /
ALL_ISSUER_HOLDINGS). Missing addresses → critical violations
listing each gap with the operator-curated role + source for
actionable triage.

These tests pin the contract for the
``destinations_superset_of_ground_truth`` check in
src/recupero/validators/output_integrity.py. The actual fixture for
the Zigha case lives at ``tests/fixtures/zigha_ground_truth.json``.

Tests:
  1. No ground_truth.json → silent no-op (most cases don't have one).
  2. Empty expected_destinations → silent pass (curated case marker
     with no enforcement yet).
  3. Full match → no violations.
  4. Single missing destination → one critical violation with role
     + source surfaced.
  5. Multiple missing → one violation per missing address.
  6. Brief missing entirely while ground_truth is present →
     critical (can't verify the superset property).
  7. Malformed ground_truth (parse error, wrong root type, missing
     key) → high-severity violations describing the malformation.
  8. Malformed entry (non-EVM-hex address, non-dict item) → high.
  9. Brief identifies the expected address inside PERP_HUB only
     (not DESTINATIONS) — still satisfies the invariant. Same for
     UNRECOVERABLE / EXCHANGES / FREEZABLE.holdings /
     ALL_ISSUER_HOLDINGS surfaces.
 10. The committed tests/fixtures/zigha_ground_truth.json parses
     successfully and contains the three confirmed Zigha addresses.

Tests run synthetic — no DB, no network, fast.
"""

from __future__ import annotations

import json
from pathlib import Path

from recupero.validators.output_integrity import (
    _check_destinations_superset_of_ground_truth,
    validate_case_output,
)

# ─────────────────────────────────────────────────────────────────────
# Known Zigha addresses (canonical lower-case).
# ─────────────────────────────────────────────────────────────────────

ZIGHA_ARB_HUB = "0xf4be227b268e191b79097daad0acccd9a7a7fad2"
ZIGHA_ETH_DORMANT_DAI_1 = "0x3dafc6a860334d4feb0467a3d58c3687e9e921b6"
ZIGHA_ETH_DORMANT_DAI_2 = "0x415d8d075cacb5a61ae854a8e5ea53df3a76f688"

# ─────────────────────────────────────────────────────────────────────
# Helpers.
# ─────────────────────────────────────────────────────────────────────


def _write_gt(case_dir: Path, payload: object) -> None:
    """Drop a ground_truth.json into the case directory. ``payload``
    is JSON-serializable (dict for valid shapes, str/list for the
    malformed-shape tests)."""
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "ground_truth.json").write_text(
        json.dumps(payload) if not isinstance(payload, str) else payload,
        encoding="utf-8",
    )


def _zigha_gt_minimal(addrs: list[str] | None = None) -> dict:
    """Synthetic ground-truth fixture mirroring the on-disk
    ZIGHA-VERIFY pin. ``addrs`` overrides the expected list (defaults
    to the three confirmed addresses)."""
    if addrs is None:
        addrs = [ZIGHA_ARB_HUB, ZIGHA_ETH_DORMANT_DAI_1, ZIGHA_ETH_DORMANT_DAI_2]
    return {
        "case_id": "ZIGHA-TEST",
        "_curated_by": "test",
        "expected_destinations": [
            {
                "address": a,
                "chain": "ethereum" if "dafc" in a or "415d" in a else "arbitrum",
                "role": "test role",
                "source": "test source",
                "approx_usd": 1_000_000,
            }
            for a in addrs
        ],
    }


# ─────────────────────────────────────────────────────────────────────
# 1. No ground_truth.json → silent no-op.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_b_noop_when_no_ground_truth_file(tmp_path: Path) -> None:
    """Most operator cases don't have a ground-truth file. The
    invariant must silently pass when the file is absent — it's
    opt-in, not a default requirement."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    # No ground_truth.json written. Brief is also absent — doesn't
    # matter, the check should short-circuit on file-not-found.
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief=None,
    )
    assert violations == []


# ─────────────────────────────────────────────────────────────────────
# 2. Empty expected_destinations → silent pass.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_b_silent_pass_on_empty_expected_list(tmp_path: Path) -> None:
    """Operator-curated case marker without enforcement: the file
    is present, but expected_destinations is []. The invariant
    passes trivially (no addresses to compare against).

    Common shape for a case being onboarded into the ground-truth
    pipeline — operators stage the marker before populating
    addresses so the file's presence is tracked in git."""
    case_dir = tmp_path / "case"
    _write_gt(case_dir, {
        "case_id": "EMPTY",
        "expected_destinations": [],
    })
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief={"DESTINATIONS": []},
    )
    assert violations == []


# ─────────────────────────────────────────────────────────────────────
# 3. Full match → no violations.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_b_full_match_no_violations(tmp_path: Path) -> None:
    """All three Zigha addresses present in the brief's DESTINATIONS
    list. The invariant must pass cleanly — zero violations.

    This is the steady-state we want post-v0.28: bridge-following
    fix lands, BFS reaches the Ethereum side, dormant detector finds
    the DAI positions, brief.DESTINATIONS now contains all three."""
    case_dir = tmp_path / "case"
    _write_gt(case_dir, _zigha_gt_minimal())
    freeze_brief = {
        "DESTINATIONS": [
            {"address": ZIGHA_ARB_HUB, "chain": "arbitrum"},
            {"address": ZIGHA_ETH_DORMANT_DAI_1, "chain": "ethereum"},
            {"address": ZIGHA_ETH_DORMANT_DAI_2, "chain": "ethereum"},
        ],
    }
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief,
    )
    assert violations == [], (
        f"expected zero violations on full match, got {violations}"
    )


# ─────────────────────────────────────────────────────────────────────
# 4. Single missing destination → one critical violation.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_b_single_missing_yields_critical(tmp_path: Path) -> None:
    """The Zigha v0.27.1 shape: ARB hub found, ETH dormant DAI not
    found. INVARIANT B must produce one critical violation per
    missing address, with role + source surfaced for triage."""
    case_dir = tmp_path / "case"
    _write_gt(case_dir, _zigha_gt_minimal())
    freeze_brief = {
        # The v0.27.1 worker found only the ARB hub.
        "DESTINATIONS": [
            {"address": ZIGHA_ARB_HUB, "chain": "arbitrum"},
        ],
    }
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief,
    )
    # Two missing → two critical violations.
    crits = [v for v in violations if v.severity == "critical"]
    assert len(crits) == 2, (
        f"expected 2 critical violations on 2 missing addrs; got "
        f"{[(v.severity, v.detail) for v in violations]}"
    )
    # Verify the missing addresses are surfaced in the detail.
    details = " ".join(v.detail for v in crits)
    # The validator's detail prints addresses in input case (we used
    # lowercase in the fixture above), so check case-insensitively.
    assert ZIGHA_ETH_DORMANT_DAI_1.lower() in details.lower()
    assert ZIGHA_ETH_DORMANT_DAI_2.lower() in details.lower()
    # Role + source threading.
    for v in crits:
        assert "role" in v.detail.lower()
        assert "source" in v.detail.lower()


# ─────────────────────────────────────────────────────────────────────
# 5. Multiple missing → one violation per missing address.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_b_all_missing_yields_critical_per_address(tmp_path: Path) -> None:
    """Worst case: the worker found NONE of the expected addresses.
    Every entry in expected_destinations should generate its own
    critical violation so the operator can see the full gap."""
    case_dir = tmp_path / "case"
    _write_gt(case_dir, _zigha_gt_minimal())
    freeze_brief: dict = {
        "DESTINATIONS": [],  # Worker found nothing.
    }
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief,
    )
    crits = [v for v in violations if v.severity == "critical"]
    assert len(crits) == 3, (
        f"expected 3 critical violations (one per missing); got "
        f"{len(crits)}"
    )


# ─────────────────────────────────────────────────────────────────────
# 6. Brief missing while ground_truth is present → critical.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_b_critical_when_brief_missing(tmp_path: Path) -> None:
    """The validator cannot verify the superset property without a
    brief. Returning a clean pass would be a silent failure mode —
    instead surface the gap as critical so operators investigate."""
    case_dir = tmp_path / "case"
    _write_gt(case_dir, _zigha_gt_minimal())
    # freeze_brief=None mimics _safe_load_json on a missing file.
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief=None,
    )
    crits = [v for v in violations if v.severity == "critical"]
    assert len(crits) == 1
    assert "freeze_brief" in crits[0].detail.lower()


# ─────────────────────────────────────────────────────────────────────
# 7. Malformed ground_truth.json → high severity (not critical).
# ─────────────────────────────────────────────────────────────────────


def test_invariant_b_unparseable_ground_truth_is_high(tmp_path: Path) -> None:
    """Operator-error mode: the JSON is malformed. We don't want
    this masquerading as a trace-coverage regression — surface it as
    high (file/configuration issue) with a clear remediation hint."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "ground_truth.json").write_text("not-json{", encoding="utf-8")
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief={"DESTINATIONS": []},
    )
    highs = [v for v in violations if v.severity == "high"]
    crits = [v for v in violations if v.severity == "critical"]
    assert len(highs) == 1
    assert len(crits) == 0  # not a coverage gap, an operator-fix
    assert "could not be parsed" in highs[0].detail.lower()


def test_invariant_b_non_object_root_is_high(tmp_path: Path) -> None:
    """JSON list (or scalar) at the root is malformed for this
    fixture. High-severity, not critical."""
    case_dir = tmp_path / "case"
    _write_gt(case_dir, ["not", "an", "object"])
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief={"DESTINATIONS": []},
    )
    assert len(violations) == 1
    assert violations[0].severity == "high"


def test_invariant_b_missing_expected_destinations_key_is_high(
    tmp_path: Path,
) -> None:
    """Forgetting the expected_destinations key is a fixture-author
    mistake — high, not critical."""
    case_dir = tmp_path / "case"
    _write_gt(case_dir, {"case_id": "X"})  # no expected_destinations
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief={"DESTINATIONS": []},
    )
    assert len(violations) == 1
    assert violations[0].severity == "high"
    assert "expected_destinations" in violations[0].detail


# ─────────────────────────────────────────────────────────────────────
# 8. Malformed entry → high.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_b_non_dict_entry_is_high(tmp_path: Path) -> None:
    """A list entry that isn't a JSON object is malformed."""
    case_dir = tmp_path / "case"
    _write_gt(case_dir, {
        "expected_destinations": ["not-an-object"],
    })
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief={"DESTINATIONS": []},
    )
    assert len(violations) == 1
    assert violations[0].severity == "high"


def test_invariant_b_non_evm_address_is_high(tmp_path: Path) -> None:
    """Non-EVM-hex addresses (Solana base58, partial hex prefixes)
    are not supported yet. Surface as high so the operator fixes the
    fixture or waits for non-EVM support."""
    case_dir = tmp_path / "case"
    _write_gt(case_dir, {
        "expected_destinations": [
            {"address": "not-a-real-address", "chain": "ethereum",
             "role": "x", "source": "y"},
        ],
    })
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief={"DESTINATIONS": []},
    )
    assert len(violations) == 1
    assert violations[0].severity == "high"
    assert "invalid address" in violations[0].detail.lower()


# ─────────────────────────────────────────────────────────────────────
# 9. Brief identifies the expected address via non-DESTINATIONS surface.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_b_match_via_perp_hub_satisfies(tmp_path: Path) -> None:
    """The brief has the address in PERP_HUB (a single-dict
    field) rather than DESTINATIONS. INVARIANT B must still pass —
    PERP_HUB IS an identified address, just a structurally distinct
    surface."""
    case_dir = tmp_path / "case"
    _write_gt(case_dir, _zigha_gt_minimal([ZIGHA_ARB_HUB]))
    freeze_brief = {
        "PERP_HUB": {"address": ZIGHA_ARB_HUB, "chain": "arbitrum"},
        "DESTINATIONS": [],
    }
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief,
    )
    assert violations == []


def test_invariant_b_match_via_unrecoverable_satisfies(tmp_path: Path) -> None:
    """The dormant DAI addresses land in the UNRECOVERABLE bucket
    (DAI is permissionless, no issuer freeze). INVARIANT B should
    accept that as a match."""
    case_dir = tmp_path / "case"
    _write_gt(case_dir, _zigha_gt_minimal([ZIGHA_ETH_DORMANT_DAI_1]))
    freeze_brief = {
        "DESTINATIONS": [],
        "UNRECOVERABLE": [
            {"address": ZIGHA_ETH_DORMANT_DAI_1,
             "asset": "approximately 9.98M DAI", "chain": "ethereum"},
        ],
    }
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief,
    )
    assert violations == []


def test_invariant_b_match_via_freezable_holding_satisfies(tmp_path: Path) -> None:
    """When an issuer's per-holding row carries the expected
    address (e.g. Midas' mSyrupUSDp position on Zigha), the
    invariant should accept it."""
    case_dir = tmp_path / "case"
    _write_gt(case_dir, _zigha_gt_minimal([ZIGHA_ETH_DORMANT_DAI_1]))
    freeze_brief = {
        "DESTINATIONS": [],
        "FREEZABLE": [
            {
                "issuer": "Midas",
                "token": "mSyrupUSDp",
                "holdings": [
                    {"address": ZIGHA_ETH_DORMANT_DAI_1,
                     "status": "FREEZABLE"},
                ],
            },
        ],
    }
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief,
    )
    assert violations == []


def test_invariant_b_case_insensitive_match(tmp_path: Path) -> None:
    """The expected-destinations canonical form (lowercase) matches a
    brief surface that carries the EIP-55 checksummed form. EVM
    addresses are case-insensitive at the identity layer; the
    canonical_address_key normalizer handles the conversion."""
    case_dir = tmp_path / "case"
    # ground-truth: lowercase
    _write_gt(case_dir, {
        "expected_destinations": [
            {"address": ZIGHA_ARB_HUB, "chain": "arbitrum",
             "role": "hub", "source": "test"},
        ],
    })
    # brief: EIP-55 checksum form
    freeze_brief = {
        "DESTINATIONS": [
            {"address": "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"},
        ],
    }
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief,
    )
    assert violations == []


# ─────────────────────────────────────────────────────────────────────
# 10. End-to-end via validate_case_output.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_b_wired_into_validate_case_output(tmp_path: Path) -> None:
    """The check is registered with the top-level validator runner.
    Verify it appears in checks_run and that its critical violations
    sink result.ok to False."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    # Minimal artifacts the validator needs to not crash.
    (case_dir / "freeze_brief.json").write_text(
        json.dumps({"DESTINATIONS": []}), encoding="utf-8",
    )
    (case_dir / "freeze_asks.json").write_text(
        json.dumps({"by_issuer": {}}), encoding="utf-8",
    )
    (case_dir / "briefs").mkdir()
    _write_gt(case_dir, _zigha_gt_minimal())

    result = validate_case_output(case_dir)
    assert "destinations_superset_of_ground_truth" in result.checks_run
    crits = [
        v for v in result.violations
        if v.check == "destinations_superset_of_ground_truth"
        and v.severity == "critical"
    ]
    # 3 expected addresses, none in the (empty) brief → 3 critical.
    assert len(crits) == 3
    assert result.ok is False


# ─────────────────────────────────────────────────────────────────────
# 11. Committed fixture parses and contains the three confirmed addrs.
# ─────────────────────────────────────────────────────────────────────


def test_zigha_ground_truth_fixture_well_formed() -> None:
    """The tests/fixtures/zigha_ground_truth.json file must remain
    valid + contain the three currently-confirmed addresses. A
    silent edit that drops or corrupts the file is caught here."""
    fixture_path = (
        Path(__file__).parent / "fixtures" / "zigha_ground_truth.json"
    )
    assert fixture_path.is_file(), (
        f"missing canonical Zigha ground-truth fixture at {fixture_path}"
    )
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert payload.get("case_id") == "ZIGHA-VERIFY"
    expected = payload.get("expected_destinations")
    assert isinstance(expected, list)
    addrs = {e["address"].lower() for e in expected}
    # Three confirmed Zigha addresses with full hex strings.
    assert ZIGHA_ARB_HUB in addrs, (
        "Arbitrum-side consolidation hub (0xF4bE…FAD2) missing"
    )
    assert ZIGHA_ETH_DORMANT_DAI_1 in addrs, (
        "Ethereum dormant DAI #1 (0x3daFC6…) missing"
    )
    assert ZIGHA_ETH_DORMANT_DAI_2 in addrs, (
        "Ethereum dormant DAI #2 (0x415D8D…) missing"
    )


def test_zigha_ground_truth_fixture_runs_through_validator(
    tmp_path: Path,
) -> None:
    """Drop the canonical Zigha fixture into a fresh case_dir, run
    the validator with an EMPTY brief, and verify INVARIANT B
    surfaces exactly the three confirmed addresses as missing. This
    is the canary that proves the fixture is actually load-bearing
    once a brief is generated against ZIGHA-VERIFY."""
    fixture_path = (
        Path(__file__).parent / "fixtures" / "zigha_ground_truth.json"
    )
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "ground_truth.json").write_text(
        fixture_path.read_text(encoding="utf-8"), encoding="utf-8",
    )
    violations = _check_destinations_superset_of_ground_truth(
        case_dir, freeze_brief={"DESTINATIONS": []},
    )
    crits = [v for v in violations if v.severity == "critical"]
    assert len(crits) == 3, (
        f"expected 3 critical violations from the 3-address Zigha "
        f"fixture; got {len(crits)}: {[v.detail for v in crits]}"
    )
