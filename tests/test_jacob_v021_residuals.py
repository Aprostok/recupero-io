"""Lock Jacob's v0.21.x signoff residuals.

Jacob signed off on the v0.21.x bundle on 2026-05-23 with two cosmetic
items flagged as non-blocking. They're fixed in this commit and pinned
here so they cannot silently regress:

  1. ``freeze_brief.json TOTAL_UNRECOVERABLE_USD`` returned $0 when the
     editorial UNRECOVERABLE_ITEMS list was empty but the freeze_asks
     held a Sky-Protocol-shape entry with ``freeze_capability='no'``.
     Sky DAI at $655,751.45 was the load-bearing example.

  2. The perp hub's role text said "Holds DAI — freezable" even though
     its ``status`` / ``risk_category`` correctly classified it as
     UNRECOVERABLE — display vs classification disagreement.

  3. A new validator invariant
     (``unrecoverable_total_matches_holdings``) catches future drift:
     ``TOTAL_UNRECOVERABLE_USD`` must equal the sum of UNRECOVERABLE-
     status holdings in ``ALL_ISSUER_HOLDINGS`` (±$1 rounding).
"""

from __future__ import annotations

from decimal import Decimal


def _v_cfi01_brief():
    """Build the V-CFI01 brief via the same fixture path Jacob uses."""
    from recupero.reports.emit_brief import emit_brief
    from recupero.reports.victim import VictimInfo
    from tests.test_v_cfi01_production_path import (  # type: ignore
        VICTIM,
        _build_editorial,
        _build_freeze_asks_dict,
        _build_issuer_metadata,
        _build_v_cfi01_case,
    )

    return emit_brief(
        case=_build_v_cfi01_case(),
        victim=VictimInfo(
            name="V-CFI01 Test Victim",
            wallet_address=VICTIM,
            state="NY", country="US",
            email="victim@test.com",
        ),
        editorial=_build_editorial(),
        freeze_asks=_build_freeze_asks_dict(),
        issuer_metadata=_build_issuer_metadata(),
    )


def _parse_dollars(s: str) -> Decimal:
    """Strip ``$`` and ``,`` from a brief-format USD string."""
    return Decimal(s.lstrip("$").replace(",", "").strip())


def test_total_unrecoverable_rolls_up_sky_dai_holding():
    """Jacob residual #1: Sky Protocol's $655,751.45 DAI must appear
    in ``TOTAL_UNRECOVERABLE_USD`` even when the editorial list is
    empty. Pre-fix this returned $0."""
    brief = _v_cfi01_brief()
    total_unrecoverable = _parse_dollars(brief["TOTAL_UNRECOVERABLE_USD"])
    # Sky DAI is the only UNRECOVERABLE holding in V-CFI01.
    assert total_unrecoverable == Decimal("655751.45"), (
        f"TOTAL_UNRECOVERABLE_USD={brief['TOTAL_UNRECOVERABLE_USD']!r}; "
        f"expected $655,751.45 (Sky DAI). Rollup dropped the holding."
    )


def test_perp_hub_role_text_says_unrecoverable_when_capability_blocks_freeze():
    """Jacob residual #2: the Sky Protocol perp hub's role text must
    agree with its status field. Pre-fix said "Holds DAI — freezable"
    on a row whose status was UNRECOVERABLE."""
    brief = _v_cfi01_brief()
    sky_dest = next(
        (d for d in brief["DESTINATIONS"]
         if d.get("status") == "UNRECOVERABLE"
         and "DAI" in d.get("role", "")),
        None,
    )
    assert sky_dest is not None, (
        "no DAI-holding UNRECOVERABLE destination found in DESTINATIONS; "
        "V-CFI01 fixture shape changed?"
    )
    role = sky_dest["role"]
    assert "freezable" not in role.lower(), (
        f"role text {role!r} still claims freezable despite "
        f"status=UNRECOVERABLE — display contradicts classification."
    )
    assert "UNRECOVERABLE" in role, (
        f"role text {role!r} should explicitly say UNRECOVERABLE."
    )


def test_freezable_destinations_role_text_still_says_freezable():
    """The fix must not over-correct: every actually-freezable
    destination should keep "freezable" in its role text. Catches a
    sloppy fix that flips every "freezable" → "UNRECOVERABLE"."""
    brief = _v_cfi01_brief()
    freezable_dests = [
        d for d in brief["DESTINATIONS"]
        if d.get("status") == "FREEZABLE" and "Holds" in d.get("role", "")
    ]
    assert freezable_dests, "no FREEZABLE Holds-* destinations found"
    for d in freezable_dests:
        assert "freezable" in d["role"].lower(), (
            f"FREEZABLE destination {d['short']!r} role={d['role']!r} "
            "lost the 'freezable' marker after the residual fix."
        )
        assert "UNRECOVERABLE" not in d["role"], (
            f"FREEZABLE destination {d['short']!r} role={d['role']!r} "
            "incorrectly labeled UNRECOVERABLE."
        )


def test_validator_invariant_catches_rollup_mismatch():
    """The new ``unrecoverable_total_matches_holdings`` validator
    invariant must fire when ``TOTAL_UNRECOVERABLE_USD`` is wrong."""
    from recupero.validators.output_integrity import (
        _check_unrecoverable_total_matches_holdings,
    )
    # Healthy shape: matched
    healthy = {
        "TOTAL_UNRECOVERABLE_USD": "$655,751.45",
        "ALL_ISSUER_HOLDINGS": [{
            "issuer": "Sky Protocol",
            "holdings": [{
                "address": "0xF4bE...",
                "status": "UNRECOVERABLE",
                "usd": "$655,751.45",
            }],
        }],
    }
    assert _check_unrecoverable_total_matches_holdings(healthy) == []
    # Broken shape: declared $0, holdings sum to $655K
    broken = {**healthy, "TOTAL_UNRECOVERABLE_USD": "$0"}
    violations = _check_unrecoverable_total_matches_holdings(broken)
    assert len(violations) == 1
    assert violations[0].severity == "high"
    assert "TOTAL_UNRECOVERABLE_USD" in violations[0].detail


def test_v_cfi01_full_validator_passes_with_new_invariant():
    """End-to-end: a fresh V-CFI01 build should pass every validator
    check INCLUDING the new unrecoverable_total invariant. Belt-and-
    suspenders for the upstream fix."""
    import json
    import tempfile
    from pathlib import Path

    from recupero.reports.brief import InvestigatorInfo
    from recupero.reports.emit_brief import emit_brief
    from recupero.reports.victim import VictimInfo
    from recupero.validators.output_integrity import validate_case_output
    from recupero.worker._deliverables import build_all_deliverables
    from tests.test_v_cfi01_production_path import (  # type: ignore
        VICTIM,
        _build_editorial,
        _build_freeze_asks_dict,
        _build_issuer_metadata,
        _build_v_cfi01_case,
    )

    case = _build_v_cfi01_case()
    victim = VictimInfo(
        name="V-CFI01 Test Victim",
        wallet_address=VICTIM, state="NY", country="US",
        email="victim@test.com",
    )
    investigator = InvestigatorInfo(
        name="Test Investigator",
        organization="Recupero Forensics Ltd.",
        email="investigator@test.com",
    )
    brief = emit_brief(
        case=case, victim=victim,
        editorial=_build_editorial(),
        freeze_asks=_build_freeze_asks_dict(),
        issuer_metadata=_build_issuer_metadata(),
    )
    case_dir = Path(tempfile.mkdtemp(prefix="jacob_residual_v021_"))
    build_all_deliverables(
        case=case, victim=victim, freeze_brief=brief,
        case_dir=case_dir, investigator=investigator,
        skip_freeze_briefs=False,
    )
    asks = _build_freeze_asks_dict()
    (case_dir / "freeze_brief.json").write_text(
        json.dumps(brief, default=str), encoding="utf-8",
    )
    (case_dir / "freeze_asks.json").write_text(
        json.dumps(asks, default=str), encoding="utf-8",
    )
    result = validate_case_output(case_dir)
    high_or_crit = [
        v for v in result.violations
        if v.severity in ("critical", "high")
    ]
    assert not high_or_crit, (
        f"validator reports {len(high_or_crit)} critical/high "
        f"violation(s):\n  "
        + "\n  ".join(f"[{v.severity}] {v.check}: {v.detail}" for v in high_or_crit)
    )
