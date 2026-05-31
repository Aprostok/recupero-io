"""v0.34 coverage-honesty (operator-requested).

A trace that ran with reduced parameters — a per-address fetch cap that
truncated a chatty/poisoned address, or address-poisoning that inflated the
transfer graph — may have DROPPED a real onward hop. The LE / freeze
deliverables must NEVER imply completeness in that case: ``emit_brief`` surfaces
a ``COVERAGE_NOTICE`` (recommending a recall-complete re-run) whenever the
trace's ``coverage.complete`` flag is False, and must NOT add the key when the
trace was complete (so clean briefs stay byte-identical).

These tests run synthetic — no DB, no network.
"""

from __future__ import annotations

from recupero.reports.emit_brief import emit_brief
from recupero.reports.victim import VictimInfo
from tests.test_v_cfi01_full_render import (
    VICTIM,
    _build_editorial,
    _build_freeze_asks_dict,
    _build_issuer_metadata,
    _build_v_cfi01_case,
)


def _emit(case) -> dict:
    victim = VictimInfo(
        name="Coverage Test Victim",
        wallet_address=VICTIM,
        state="NY",
        country="US",
        email="cov@example.com",
    )
    return emit_brief(
        case=case,
        victim=victim,
        editorial=_build_editorial(),
        freeze_asks=_build_freeze_asks_dict(),
        issuer_metadata=_build_issuer_metadata(),
    )


def test_incomplete_coverage_surfaces_notice_in_brief() -> None:
    """A poisoned / per-address-capped trace surfaces COVERAGE_NOTICE with the
    recall-complete recommendation so an operator can never mistake a reduced
    trace for a complete one."""
    case = _build_v_cfi01_case()
    case.config_used = {
        **(case.config_used or {}),
        "trace_status": "complete",  # the OLD silent-complete shape...
        "coverage": {
            "complete": False,  # ...but coverage knows it was reduced.
            "poisoning_detected": True,
            "poisoning_event_count": 3,
            "per_address_cap_truncations": [
                {"address": "0xabc", "kind": "per_address_fetch_cap",
                 "raw_outflows": 3754, "kept": 2500, "dropped": 1254},
            ],
            "reduced_parameters": {
                "max_depth": 3,
                "dust_threshold_usd": 1000.0,
                "max_transfers_per_address": 2500,
            },
            "recommendation": (
                "Coverage may be INCOMPLETE: re-run recall-complete "
                "(--max-depth 8 --dust-threshold-usd 50, uncapped)."
            ),
        },
    }
    brief = _emit(case)
    assert "COVERAGE_NOTICE" in brief, (
        "a reduced-parameter trace MUST surface COVERAGE_NOTICE in the brief"
    )
    notice = brief["COVERAGE_NOTICE"]
    assert notice["complete"] is False
    assert notice["poisoning_detected"] is True
    assert notice["per_address_cap_truncations"][0]["dropped"] == 1254
    assert "recall-complete" in notice["recommendation"]


def test_complete_coverage_adds_no_notice() -> None:
    """A clean, full-coverage trace must NOT add COVERAGE_NOTICE — otherwise
    every brief would carry a scary banner and existing golden artifacts would
    churn."""
    case = _build_v_cfi01_case()
    case.config_used = {
        **(case.config_used or {}),
        "trace_status": "complete",
        "coverage": {"complete": True, "poisoning_detected": False},
    }
    brief = _emit(case)
    assert "COVERAGE_NOTICE" not in brief


def test_missing_coverage_key_adds_no_notice() -> None:
    """Back-compat: a case with no ``coverage`` key (older trace / hand-built
    fixture) must not crash and must not add the notice."""
    case = _build_v_cfi01_case()
    # Ensure no coverage key present.
    cu = dict(case.config_used or {})
    cu.pop("coverage", None)
    case.config_used = cu
    brief = _emit(case)
    assert "COVERAGE_NOTICE" not in brief
