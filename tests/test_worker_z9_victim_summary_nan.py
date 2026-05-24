"""RIGOR-Jacob Z9: worker/_victim_summary.py adversarial-input hardening.

Bug Z9-1: ``worker/_victim_summary._parse_usd_string`` accepts the
literal strings ``"$NaN"`` / ``"$Infinity"`` / ``"$-Infinity"`` and
returns ``Decimal('NaN')`` / ``Decimal('Infinity')`` — Python's
``Decimal("NaN")`` parses successfully. That non-finite Decimal then
propagates into:

  1. ``classify_recovery_prospects``: ``total_freezable >= floor_usd``
     raises ``decimal.InvalidOperation`` on NaN. The outer caller in
     ``_deliverables.py`` swallows the exception via try/except and
     defaults the case to (is_recoverable=False, totals=0). Result:
     a case with one poisoned per-issuer entry silently routes to the
     UNRECOVERABLE branch — operator never sees the engagement letter
     or the recoverable victim summary even though other entries
     contain real freezable USD.

  2. ``_build_context`` line ``suspected_usd > 0`` also raises
     ``InvalidOperation`` on NaN. ``render_victim_summary`` then
     catches the exception and returns ``None`` — the entire victim
     summary deliverable is skipped on a case where one issuer entry
     happened to carry NaN.

Same shape as Z5-2 (pipeline._parse_usd) but a SEPARATE copy of the
parser. Z5-2 fixed pipeline; Z9-1 fixes _victim_summary.
"""

from __future__ import annotations

from decimal import Decimal

import pytest


def test_z9_parse_usd_string_rejects_nan() -> None:
    """Z9-1 RED → GREEN: ``_parse_usd_string("$NaN")`` must NOT return a
    non-finite Decimal. Returning Decimal(0) is the safe sentinel —
    matches the existing behavior for empty / malformed input."""
    from recupero.worker._victim_summary import _parse_usd_string

    nan_result = _parse_usd_string("$NaN")
    assert nan_result.is_finite(), (
        f"Expected finite Decimal for poisoned NaN input, got {nan_result!r} "
        "(non-finite Decimals corrupt every downstream comparison + sum)"
    )
    # Specifically should be zero — the canonical "couldn't parse" return.
    assert nan_result == Decimal(0)


def test_z9_parse_usd_string_rejects_infinity() -> None:
    """Z9-1 RED → GREEN: ``$Infinity`` / ``$-Infinity`` must also map to 0,
    not propagate as ``Decimal('Infinity')``."""
    from recupero.worker._victim_summary import _parse_usd_string

    for poisoned in ("$Infinity", "$-Infinity", "$inf", "$-inf"):
        result = _parse_usd_string(poisoned)
        assert result.is_finite(), (
            f"Expected finite Decimal for {poisoned!r}, got {result!r} "
            "(non-finite Decimals corrupt every downstream comparison + sum)"
        )
        assert result == Decimal(0), poisoned


def test_z9_classify_recovery_prospects_survives_nan_entry() -> None:
    """Z9-1 RED → GREEN: a freeze_brief that contains ONE poisoned
    entry (total_usd='$NaN') must not silently misclassify the whole
    case as unrecoverable. Other entries with real recoverable USD
    must still be summed and trigger the recoverable branch.

    Pre-fix: ``total_freezable >= floor_usd`` raises InvalidOperation
    inside classify_recovery_prospects → caller's try/except returns
    (False, 0, 0). Engagement letter + recoverable victim summary are
    then both silently suppressed even though the case has $50K of
    legitimately freezable USDC.
    """
    from recupero.worker._victim_summary import classify_recovery_prospects

    freeze_brief = {
        "FREEZABLE": [
            # Real entry with $50K freezable USDC — should drive
            # recoverable=True on its own (well above the $40K floor).
            {
                "issuer": "Circle",
                "token": "USDC",
                "total_usd": "$50,000.00",
                "total_suspected_usd": "$0",
                "freeze_capability": "yes",
                "holdings": [
                    {"status": "FREEZABLE", "usd": "$50,000.00"},
                ],
            },
            # Poisoned entry from upstream pricing bug — NaN must be
            # treated as zero, not propagate through the sum.
            {
                "issuer": "TetherCorrupted",
                "token": "USDT",
                "total_usd": "$NaN",
                "total_suspected_usd": "$Infinity",
                "freeze_capability": "yes",
                "holdings": [
                    {"status": "FREEZABLE", "usd": "$NaN"},
                ],
            },
        ],
    }

    is_recoverable, total_freezable, total_suspected = (
        classify_recovery_prospects(freeze_brief)
    )

    # All three returned Decimals must be finite — non-finite values
    # corrupt every downstream metric.
    assert total_freezable.is_finite(), total_freezable
    assert total_suspected.is_finite(), total_suspected
    # The Circle entry alone is well above the floor — the case must
    # classify as recoverable despite the poisoned Tether entry.
    assert is_recoverable, (
        f"Case with $50K real freezable + 1 NaN entry must still classify "
        f"as recoverable; got (is_recoverable={is_recoverable}, "
        f"total_freezable={total_freezable}, total_suspected={total_suspected})"
    )
    # The good entry's $50K must be preserved.
    assert total_freezable == Decimal("50000.00"), total_freezable


def test_z9_freeze_followup_renders_finite_amount_for_poisoned_decimal() -> None:
    """Z9-2 RED → GREEN: ``_render_followup_html`` formats
    ``requested_freeze_usd`` via ``float(...)`` directly. Postgres
    NUMERIC supports NaN/Infinity, so a poisoned freeze_letters_sent
    row carrying ``Decimal('NaN')`` flows into the rendered email body
    as the literal string ``"$nan"`` — an embarrassing artifact going
    out to compliance teams in a freeze-request follow-up.

    The render must produce a finite USD amount (zero-fallback is
    acceptable) regardless of poisoned Decimal input.
    """
    from datetime import UTC, datetime, timedelta
    from uuid import uuid4

    from recupero.worker._freeze_followup import (
        FreezeFollowupCandidate,
        _render_followup_html,
    )

    for poison in (Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")):
        sent = datetime.now(UTC) - timedelta(hours=80)
        cand = FreezeFollowupCandidate(
            letter_id=uuid4(),
            case_id=uuid4(),
            investigation_id=uuid4(),
            issuer="Circle",
            target_address="0xdeadbeef",
            chain="ethereum",
            asset_symbol="USDC",
            requested_freeze_usd=poison,
            letter_subject="Freeze request",
            letter_tier="standard",
            contact_email="compliance@circle.com",
            sent_at=sent,
            last_followup_sent_at=None,
            followup_stage="initial",
            next_stage="nudge_72h",
            template_name="freeze_followup_nudge.html.j2",
            investigator_email="inv@recupero.io",
            ic3_case_id=None,
            jurisdiction=None,
        )
        html = _render_followup_html(
            cand,
            investigator_name="Test Investigator",
            investigator_entity="Recupero",
        )
        lower = html.lower()
        # The rendered HTML must not contain the literal strings 'nan'
        # or 'inf' as the requested-freeze-amount value. These leak out
        # of ``f"{float(poisoned):,.2f}"`` when poisoned isn't pre-
        # sanitized. The nudge template renders the amount as
        # ``USD {{ requested_freeze_usd_human }}``, so the poisoned
        # value appears verbatim in the issuer-facing email body.
        # Look for the rendered formatter output: 'nan' / 'inf'.
        for needle in ("nan", "inf"):
            assert f"usd {needle}" not in lower, (
                f"Poisoned Decimal {poison!r} produced literal "
                f"'USD {needle}' in rendered freeze-followup email "
                f"(would go out to compliance teams)."
            )
