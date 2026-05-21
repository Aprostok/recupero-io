"""Trace-report UNRECOVERABLE labeling contract — locked.

The trace_report destinations table now flags DAI / USDS positions
with an UNRECOVERABLE badge. This was added in response to the
validator's dai_sky_consistency check firing a warning on V-CFI01:
a $655,751.45 DAI position appeared in the destinations table with
no context, which Jacob would flag during a real review.

These tests lock the contract:

  * `_build_destinations_table` annotates each row with
    `is_unrecoverable: bool`.
  * The annotation is True for symbols in the documented
    UNRECOVERABLE set (DAI / USDS).
  * Rendered HTML carries the UNRECOVERABLE badge text for
    flagged rows.
  * The validator's dai_sky_consistency check accepts the output.

A future refactor that drops the badge or the row-level flag
breaks these tests immediately.
"""

from __future__ import annotations

import json
import tempfile
from decimal import Decimal
from pathlib import Path

import pytest


def _make_minimal_case_with_dai():
    """Build a Case object whose destinations include a DAI position.
    Reuses the V-CFI01 fixture machinery — the V-CFI01 case includes
    a $655K DAI position via the Sky Protocol leg of the trace."""
    from tests.test_v_cfi01_production_path import _build_v_cfi01_case
    return _build_v_cfi01_case()


def test_destinations_table_flags_dai_as_unrecoverable():
    """Every row whose asset is DAI must carry is_unrecoverable=True."""
    from recupero.worker._trace_report import _build_destinations_table

    case = _make_minimal_case_with_dai()
    rows = _build_destinations_table(case)
    dai_rows = [r for r in rows if (r.get("symbol") or "").upper() == "DAI"]
    assert dai_rows, "test fixture has no DAI destinations — fixture changed"
    for r in dai_rows:
        assert r["is_unrecoverable"] is True, (
            f"DAI row {r['address_short']!r} not flagged is_unrecoverable: {r}"
        )


def test_destinations_table_does_not_flag_usdt_as_unrecoverable():
    """USDT IS freezable by Tether — must NOT be flagged
    UNRECOVERABLE. Catches the inverse mistake (over-flagging)."""
    from recupero.worker._trace_report import _build_destinations_table

    case = _make_minimal_case_with_dai()
    rows = _build_destinations_table(case)
    usdt_rows = [r for r in rows if (r.get("symbol") or "").upper() == "USDT"]
    if not usdt_rows:
        pytest.skip("fixture has no USDT destinations")
    for r in usdt_rows:
        assert r["is_unrecoverable"] is False, (
            f"USDT row {r['address_short']!r} INCORRECTLY flagged "
            f"is_unrecoverable: {r}"
        )


def test_rendered_trace_report_carries_unrecoverable_badge():
    """End-to-end: generate V-CFI01, open the rendered trace_report
    HTML, and assert it contains both the UNRECOVERABLE badge text
    AND the Sky Protocol explanation subtitle.

    A mutation that removes the badge from the template would fail
    this test."""
    from recupero.reports.brief import InvestigatorInfo
    from recupero.reports.emit_brief import emit_brief
    from recupero.reports.victim import VictimInfo
    from recupero.worker._deliverables import build_all_deliverables
    from tests.test_v_cfi01_production_path import (
        VICTIM, _build_editorial, _build_freeze_asks_dict,
        _build_issuer_metadata, _build_v_cfi01_case,
    )

    case = _build_v_cfi01_case()
    brief = emit_brief(
        case=case,
        victim=VictimInfo(
            name="UNRECOVERABLE Test", wallet_address=VICTIM,
            state="NY", country="US", email="v@test.x",
        ),
        editorial=_build_editorial(),
        freeze_asks=_build_freeze_asks_dict(),
        issuer_metadata=_build_issuer_metadata(),
    )
    tmp = Path(tempfile.mkdtemp(prefix="unrecov_test_"))
    (tmp / "freeze_brief.json").write_text(
        json.dumps(brief, default=str), encoding="utf-8",
    )
    (tmp / "freeze_asks.json").write_text(
        json.dumps(_build_freeze_asks_dict(), default=str), encoding="utf-8",
    )
    build_all_deliverables(
        case=case,
        victim=VictimInfo(
            name="UNRECOVERABLE Test", wallet_address=VICTIM,
            state="NY", country="US", email="v@test.x",
        ),
        freeze_brief=brief, case_dir=tmp,
        investigator=InvestigatorInfo(
            name="I", organization="R", email="i@x.y",
        ),
        skip_freeze_briefs=False,
    )

    trace_paths = list((tmp / "briefs").glob("trace_report_*.html"))
    assert trace_paths, "no trace_report_*.html found in output"
    html = trace_paths[0].read_text(encoding="utf-8")

    assert "UNRECOVERABLE" in html, (
        "trace_report HTML missing the UNRECOVERABLE badge — Jacob "
        "would see the $655K DAI position with no context."
    )
    assert "Sky Protocol" in html, (
        "trace_report HTML missing the 'Sky Protocol — no admin freeze "
        "pathway' explanation subtitle."
    )
    # Inline check on a DAI row specifically: the row containing DAI
    # must be in the same vicinity as 'UNRECOVERABLE'.
    dai_idx = html.find(">DAI<")
    if dai_idx < 0:
        # Pyright lookup fallback
        dai_idx = html.find("DAI")
    assert dai_idx > 0, "no DAI mention in HTML"
    # Within 2000 chars after the DAI mention (the table row is bounded
    # by closing </tr>) we should see UNRECOVERABLE.
    window = html[dai_idx:dai_idx + 2000]
    assert "UNRECOVERABLE" in window, (
        f"DAI mention at offset {dai_idx} not followed by UNRECOVERABLE "
        f"badge within 2000 chars. The badge is rendered in a separate "
        f"row from the asset → likely a template-column ordering bug."
    )


def test_validator_dai_sky_check_accepts_labeled_trace_report():
    """The validator's check 12 (dai_sky_consistency) must accept
    the V-CFI01 trace_report. Pre-fix it fired a warning; post-fix
    must return zero violations of that check."""
    from recupero.reports.brief import InvestigatorInfo
    from recupero.reports.emit_brief import emit_brief
    from recupero.reports.victim import VictimInfo
    from recupero.validators.output_integrity import validate_case_output
    from recupero.worker._deliverables import build_all_deliverables
    from tests.test_v_cfi01_production_path import (
        VICTIM, _build_editorial, _build_freeze_asks_dict,
        _build_issuer_metadata, _build_v_cfi01_case,
    )

    case = _build_v_cfi01_case()
    brief = emit_brief(
        case=case,
        victim=VictimInfo(
            name="V", wallet_address=VICTIM,
            state="NY", country="US", email="v@x.y",
        ),
        editorial=_build_editorial(),
        freeze_asks=_build_freeze_asks_dict(),
        issuer_metadata=_build_issuer_metadata(),
    )
    tmp = Path(tempfile.mkdtemp(prefix="dai_validator_"))
    (tmp / "freeze_brief.json").write_text(
        json.dumps(brief, default=str), encoding="utf-8",
    )
    (tmp / "freeze_asks.json").write_text(
        json.dumps(_build_freeze_asks_dict(), default=str), encoding="utf-8",
    )
    build_all_deliverables(
        case=case,
        victim=VictimInfo(
            name="V", wallet_address=VICTIM,
            state="NY", country="US", email="v@x.y",
        ),
        freeze_brief=brief, case_dir=tmp,
        investigator=InvestigatorInfo(
            name="I", organization="R", email="i@x.y",
        ),
        skip_freeze_briefs=False,
    )

    result = validate_case_output(tmp)
    dai_violations = [
        v for v in result.violations
        if v.check == "dai_sky_consistency"
    ]
    assert not dai_violations, (
        f"validator's dai_sky_consistency still fires after the "
        f"UNRECOVERABLE labeling: {dai_violations!r}"
    )
