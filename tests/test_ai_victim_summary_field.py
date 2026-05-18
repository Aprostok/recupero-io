"""Tests for v0.15.0 VICTIM_SUMMARY AI-editorial field threading.

The AI editorial pipeline gets a new top-level required key:
VICTIM_SUMMARY (plain-English paragraph for the victim's eyes).
Distinct from the existing tests/test_victim_summary.py which
covers the separate customer-letter renderer artifact.

We verify integration without calling Claude:

  * VICTIM_SUMMARY is in AI_DRAFTED_KEYS so build_editorial_dict
    copies it through.
  * _validate_ai_output requires VICTIM_SUMMARY + its
    _AI_CONFIDENCE sibling.
  * EDITORIAL_TEMPLATE (the manual-edit fallback) includes a
    TODO placeholder.
  * The few-shot example output includes VICTIM_SUMMARY for the
    AI to calibrate against.
  * emit_brief surfaces VICTIM_SUMMARY in the assembled brief.
"""

from __future__ import annotations

from recupero.reports.ai_editorial import (
    AI_DRAFTED_KEYS,
    FEW_SHOT_EXAMPLE,
    _validate_ai_output,
)


def _valid_ai_output() -> dict:
    """Minimum-viable AI output covering every required key."""
    return {
        "INCIDENT_TYPE": "test",
        "INCIDENT_TYPE_AI_CONFIDENCE": "high",
        "INCIDENT_NARRATIVE_RECUPERO": "x",
        "INCIDENT_NARRATIVE_RECUPERO_AI_CONFIDENCE": "high",
        "INCIDENT_NARRATIVE_FIRST_PERSON": "y",
        "INCIDENT_NARRATIVE_FIRST_PERSON_AI_CONFIDENCE": "high",
        "VICTIM_JURISDICTION": "USA",
        "VICTIM_JURISDICTION_AI_CONFIDENCE": "high",
        "DESTINATION_NOTES": {},
        "DESTINATION_NOTES_AI_CONFIDENCE": "high",
        "UNRECOVERABLE_ITEMS": [],
        "UNRECOVERABLE_ITEMS_AI_CONFIDENCE": "high",
        "VICTIM_SUMMARY": "Plain English summary.",
        "VICTIM_SUMMARY_AI_CONFIDENCE": "high",
    }


# ---- AI_DRAFTED_KEYS / validator ---- #


def test_victim_summary_in_ai_drafted_keys() -> None:
    """build_editorial_dict copies AI_DRAFTED_KEYS through. If
    VICTIM_SUMMARY isn't in this list, the brief loses it even when
    the AI drafts it."""
    assert "VICTIM_SUMMARY" in AI_DRAFTED_KEYS


def test_validator_accepts_valid_output() -> None:
    problems = _validate_ai_output(_valid_ai_output())
    assert problems == []


def test_validator_flags_missing_victim_summary() -> None:
    """If the AI returns output without VICTIM_SUMMARY, validation
    must flag it so the retry loop catches the issue."""
    ai_out = _valid_ai_output()
    del ai_out["VICTIM_SUMMARY"]
    del ai_out["VICTIM_SUMMARY_AI_CONFIDENCE"]
    problems = _validate_ai_output(ai_out)
    assert any("VICTIM_SUMMARY" in p for p in problems)


def test_validator_flags_missing_confidence_sibling() -> None:
    """Every drafted field has an _AI_CONFIDENCE sibling. Forgetting
    one breaks the UI's review-confidence gating."""
    ai_out = _valid_ai_output()
    del ai_out["VICTIM_SUMMARY_AI_CONFIDENCE"]
    problems = _validate_ai_output(ai_out)
    assert any("VICTIM_SUMMARY_AI_CONFIDENCE" in p for p in problems)


def test_validator_flags_bad_confidence_value() -> None:
    """Confidence values must be low/medium/high."""
    ai_out = _valid_ai_output()
    ai_out["VICTIM_SUMMARY_AI_CONFIDENCE"] = "expert"  # invalid
    problems = _validate_ai_output(ai_out)
    assert any(
        "VICTIM_SUMMARY_AI_CONFIDENCE" in p and "expected one of" in p
        for p in problems
    )


# ---- Few-shot example calibration ---- #


def test_few_shot_example_includes_victim_summary() -> None:
    """The example output the AI sees in the prompt must include
    VICTIM_SUMMARY so the model has a calibration sample."""
    output = FEW_SHOT_EXAMPLE.get("output") or {}
    assert "VICTIM_SUMMARY" in output
    summary = output["VICTIM_SUMMARY"]
    assert isinstance(summary, str)
    # Length sanity: 4-6 sentences should be at least ~200 chars.
    assert len(summary) > 200


def test_few_shot_summary_uses_plain_language() -> None:
    """The example must NOT use jargon — it's the calibration the
    AI uses to set its own tone. Check for some forbidden terms."""
    output = FEW_SHOT_EXAMPLE.get("output") or {}
    summary = output["VICTIM_SUMMARY"].lower()
    # These would all be jargon-y / promise-y / hedge-y.
    # Note: the example uses "freeze" which is correct domain language
    # to keep; we're only filtering for legalese the victim doesn't need.
    for forbidden in ("subpoena", "mlat", "compelled disclosure",
                       "guaranteed recovery",
                       "definitely will recover"):
        assert forbidden not in summary, (
            f"Few-shot VICTIM_SUMMARY contains forbidden term "
            f"{forbidden!r} — the AI will copy that tone."
        )


# ---- Editorial template ---- #


def test_editorial_template_has_victim_summary_placeholder() -> None:
    """Operators who edit brief_editorial.json by hand should see a
    TODO placeholder for VICTIM_SUMMARY, not silently get a missing
    field at emit-brief time."""
    from recupero.reports.emit_brief import EDITORIAL_TEMPLATE
    assert "VICTIM_SUMMARY" in EDITORIAL_TEMPLATE
    template_value = EDITORIAL_TEMPLATE["VICTIM_SUMMARY"]
    assert "TODO" in template_value


# ---- emit_brief surfaces VICTIM_SUMMARY ---- #


def test_emit_brief_threads_victim_summary_through_assembly() -> None:
    """emit_brief() must include VICTIM_SUMMARY in the assembled
    brief dict so downstream renderers (Triage Report, customer
    portal) can display it."""
    from pathlib import Path
    src = (
        Path(__file__).parent.parent / "src" / "recupero" / "reports"
        / "emit_brief.py"
    ).read_text(encoding="utf-8")
    assert '"VICTIM_SUMMARY"' in src
    # Defaults to empty string when editorial doesn't carry it
    # (back-compat with pre-v0.15.0 editorial files).
    assert 'editorial.get("VICTIM_SUMMARY"' in src
