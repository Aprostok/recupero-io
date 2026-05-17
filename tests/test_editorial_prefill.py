"""Tests for the case-row pre-fill applied to build_editorial_dict.

The motivation: PR #12 added postal-address + jurisdiction + IC3
columns to public.cases. Without pre-fill, the AI editorial step
keeps emitting TODO: placeholders for these fields and the
operator has to re-type the data that's already in the database
before approving.

The pre-fill replaces those TODOs with the cases-row values when
non-empty, while falling back to existing TODO behavior on rows
where the columns are still null (pre-PR-#12 backfill state).

Contracts under test:

  * Non-empty pre-fill values override the AI's TODO output.
  * Empty / None / whitespace-only values leave the existing
    TODO placeholder intact so the review form still prompts.
  * The override is the LAST step in build_editorial_dict so
    nothing downstream can re-introduce the TODO.
  * Pre-fill marks _AI_CONFIDENCE as "high" since the value
    came from operator-curated intake, not AI inference.
  * No pre-fill (None or empty dict) behaves identically to
    pre-PR-#12 — the function is fully backward-compatible.
"""

from __future__ import annotations

from typing import Any

from recupero.reports.ai_editorial import build_editorial_dict


def _mk_ai_output(**overrides: Any) -> dict[str, Any]:
    """Minimal valid AI output. Each key matches the validator's
    required-key list; values default to TODO: placeholders so the
    pre-fill behavior is observable."""
    base: dict[str, Any] = {
        "INCIDENT_TYPE": "Wallet drainer",
        "INCIDENT_TYPE_AI_CONFIDENCE": "medium",
        "INCIDENT_NARRATIVE_RECUPERO": "Victim signed a malicious approval.",
        "INCIDENT_NARRATIVE_RECUPERO_AI_CONFIDENCE": "medium",
        "INCIDENT_NARRATIVE_FIRST_PERSON": "I signed a transaction I didn't realize was an approval.",
        "INCIDENT_NARRATIVE_FIRST_PERSON_AI_CONFIDENCE": "medium",
        "VICTIM_JURISDICTION": "TODO: confirm victim's state/country",
        "VICTIM_JURISDICTION_AI_CONFIDENCE": "low",
        "DESTINATION_NOTES": {},
        "DESTINATION_NOTES_AI_CONFIDENCE": "medium",
        "UNRECOVERABLE_ITEMS": [],
        "UNRECOVERABLE_ITEMS_AI_CONFIDENCE": "medium",
    }
    base.update(overrides)
    return base


def _mk_case_summary(**overrides: Any) -> dict[str, Any]:
    """Minimal case_summary the editorial dict needs.

    The address heuristic reads victim.address; defaulting to empty
    string means VICTIM_ADDRESS_LINE1/2 start as TODO placeholders
    (matching the worst-case pre-PR-#12 state). Tests then layer
    case_row_prefill on top and assert that the TODOs go away."""
    base: dict[str, Any] = {
        "incident_date_human": "April 12, 2026",
        "primary_chain": "ethereum",
        "victim": {
            "address": "",       # empty → TODO placeholders for LINE1/2
            "citizenship": "",
        },
    }
    base.update(overrides)
    return base


# ---- Backward compatibility (no pre-fill) ---- #


def test_no_prefill_preserves_todo_behavior() -> None:
    """case_row_prefill=None → behaves exactly like pre-v0.5.2. The
    TODO placeholders for address + jurisdiction stay put because no
    case-row values were provided to override them."""
    out = build_editorial_dict(_mk_ai_output(), _mk_case_summary())
    assert out["VICTIM_ADDRESS_LINE1"].startswith("TODO")
    assert out["VICTIM_ADDRESS_LINE2"].startswith("TODO")
    assert out["VICTIM_JURISDICTION"].startswith("TODO")


def test_empty_prefill_preserves_todo_behavior() -> None:
    """Empty dict → identical to None. Cheaper to construct in
    callers that always build the dict but sometimes have nothing
    to put in it."""
    out = build_editorial_dict(
        _mk_ai_output(), _mk_case_summary(), case_row_prefill={},
    )
    assert out["VICTIM_ADDRESS_LINE1"].startswith("TODO")
    assert out["VICTIM_JURISDICTION"].startswith("TODO")


# ---- Address pre-fill ---- #


def test_prefill_overrides_address_line1() -> None:
    """A populated address_line1 in the cases row → editorial gets
    the real value, no TODO. Same for line 2."""
    out = build_editorial_dict(
        _mk_ai_output(), _mk_case_summary(),
        case_row_prefill={
            "VICTIM_ADDRESS_LINE1": "99 Test Boulevard",
            "VICTIM_ADDRESS_LINE2": "Suite 200, Paris 75001, France",
        },
    )
    assert out["VICTIM_ADDRESS_LINE1"] == "99 Test Boulevard"
    assert out["VICTIM_ADDRESS_LINE2"] == "Suite 200, Paris 75001, France"
    assert "TODO" not in out["VICTIM_ADDRESS_LINE1"]


def test_prefill_partial_address() -> None:
    """Only line 1 populated → line 2 still TODO. Realistic case:
    international addresses that don't split cleanly into two lines."""
    out = build_editorial_dict(
        _mk_ai_output(), _mk_case_summary(),
        case_row_prefill={"VICTIM_ADDRESS_LINE1": "Karl-Marx-Allee 12"},
    )
    assert out["VICTIM_ADDRESS_LINE1"] == "Karl-Marx-Allee 12"
    # LINE2 was NOT in the pre-fill → existing TODO behavior preserved
    assert out["VICTIM_ADDRESS_LINE2"].startswith("TODO")


def test_prefill_overrides_heuristic_address_split() -> None:
    """When victim.address has a comma-split value AND the cases row
    also has address_line1/2, the case-row value wins. This is the
    key property — the pre-fill is the LAST step, so heuristic-
    derived placeholders from victim.json get replaced."""
    out = build_editorial_dict(
        _mk_ai_output(),
        _mk_case_summary(victim={
            "address": "1 Heuristic Lane, Old City",
            "citizenship": "",
        }),
        case_row_prefill={"VICTIM_ADDRESS_LINE1": "2 Canonical Way"},
    )
    assert out["VICTIM_ADDRESS_LINE1"] == "2 Canonical Way"


# ---- Jurisdiction pre-fill ---- #


def test_prefill_overrides_ai_jurisdiction_todo() -> None:
    """The AI emits 'TODO: confirm victim's state/country' for
    VICTIM_JURISDICTION. The cases-row value replaces it cleanly."""
    out = build_editorial_dict(
        _mk_ai_output(), _mk_case_summary(),
        case_row_prefill={"VICTIM_JURISDICTION": "Paris, France"},
    )
    assert out["VICTIM_JURISDICTION"] == "Paris, France"
    assert out["VICTIM_JURISDICTION_AI_CONFIDENCE"] == "high"


def test_prefill_jurisdiction_beats_victim_citizenship() -> None:
    """An earlier step copies victim.citizenship into
    VICTIM_JURISDICTION if the AI emitted a TODO. The case-row
    pre-fill must run AFTER that step so a populated jurisdiction
    on the cases row wins over a stale citizenship value."""
    out = build_editorial_dict(
        _mk_ai_output(),
        _mk_case_summary(victim={
            "address": "",
            "citizenship": "USA",         # → would be copied first
        }),
        case_row_prefill={"VICTIM_JURISDICTION": "Berlin, Germany"},
    )
    assert out["VICTIM_JURISDICTION"] == "Berlin, Germany"


# ---- IC3 pre-fill (new key in editorial) ---- #


def test_prefill_adds_ic3_case_id() -> None:
    """IC3_CASE_ID is a new key added in v0.5.2. It only appears in
    the editorial dict when the cases row provided one — there's no
    AI / heuristic / static fallback."""
    out = build_editorial_dict(
        _mk_ai_output(), _mk_case_summary(),
        case_row_prefill={"IC3_CASE_ID": "I3-TEST-ZIGHA-001"},
    )
    assert out["IC3_CASE_ID"] == "I3-TEST-ZIGHA-001"
    assert out["IC3_CASE_ID_AI_CONFIDENCE"] == "high"


def test_no_ic3_prefill_means_no_ic3_key() -> None:
    """No IC3_CASE_ID in the pre-fill → key isn't in the editorial
    dict at all. Downstream consumers (emit_brief.IC3_CASE_ID =
    editorial.get('IC3_CASE_ID')) get None, which is what they
    expect for the pre-PR-#12 era."""
    out = build_editorial_dict(_mk_ai_output(), _mk_case_summary())
    assert "IC3_CASE_ID" not in out


# ---- Empty-string / whitespace handling ---- #


def test_prefill_skips_empty_string() -> None:
    """An empty-string value in the pre-fill → ignored. The TODO
    placeholder stays. Defensive against callers that pass through
    DB NULLs as empty strings."""
    out = build_editorial_dict(
        _mk_ai_output(), _mk_case_summary(),
        case_row_prefill={"VICTIM_JURISDICTION": ""},
    )
    assert out["VICTIM_JURISDICTION"].startswith("TODO")


def test_prefill_skips_whitespace_only() -> None:
    """Whitespace-only ≈ empty. Don't replace a TODO with three
    spaces — that would slip past the emit-time TODO check."""
    out = build_editorial_dict(
        _mk_ai_output(), _mk_case_summary(),
        case_row_prefill={"VICTIM_JURISDICTION": "   "},
    )
    assert out["VICTIM_JURISDICTION"].startswith("TODO")


def test_prefill_skips_persisted_todo_strings() -> None:
    """Defensive guard for the bug found during live-verify against
    V-ZTST01: the literal string 'TODO: victim city/state/zip' had
    been persisted into cases.address_line2 during smoke testing.
    Without this guard, the pre-fill would replace the AI's TODO
    with that DB-persisted TODO — same outcome from the operator's
    perspective (re-typing required) but harder to debug because
    the failure is one layer deeper."""
    out = build_editorial_dict(
        _mk_ai_output(), _mk_case_summary(),
        case_row_prefill={
            "VICTIM_ADDRESS_LINE1": "99 Test Boulevard",
            "VICTIM_ADDRESS_LINE2": "TODO: victim city/state/zip",
            "VICTIM_JURISDICTION": "TODO: confirm jurisdiction",
            "IC3_CASE_ID": "TODO-PLACEHOLDER",
        },
    )
    # Good values pass through
    assert out["VICTIM_ADDRESS_LINE1"] == "99 Test Boulevard"
    # TODO-prefixed values get rejected — existing TODO placeholder
    # / absent key is preserved so the review form prompts cleanly.
    assert out["VICTIM_ADDRESS_LINE2"].startswith("TODO")
    assert out["VICTIM_JURISDICTION"].startswith("TODO")
    assert "IC3_CASE_ID" not in out


def test_prefill_skips_case_insensitive_todo() -> None:
    """The check is case-insensitive: 'todo:', 'Todo:', and 'TODO:'
    are all rejected. Defensive against operators who type the
    placeholder in various casings."""
    for variant in ("todo: city", "Todo: City", "TODO: City", "tOdO: x"):
        out = build_editorial_dict(
            _mk_ai_output(), _mk_case_summary(),
            case_row_prefill={"VICTIM_JURISDICTION": variant},
        )
        assert out["VICTIM_JURISDICTION"].startswith("TODO"), (
            f"variant {variant!r} should have been rejected"
        )


# ---- Idempotency / determinism ---- #


def test_prefill_is_deterministic_across_calls() -> None:
    """Calling build_editorial_dict twice with the same inputs
    produces the same editorial. Locks against hidden mutable
    state in the function or its helpers."""
    args = (_mk_ai_output(), _mk_case_summary())
    kwargs = {"case_row_prefill": {
        "VICTIM_ADDRESS_LINE1": "1 Test St",
        "VICTIM_JURISDICTION": "USA (TX)",
        "IC3_CASE_ID": "I3-AAA-001",
    }}
    a = build_editorial_dict(*args, **kwargs)
    b = build_editorial_dict(*args, **kwargs)
    # Compare the three pre-filled keys specifically — REPORT_DATE
    # uses the current date so the full dict won't equal.
    for key in ("VICTIM_ADDRESS_LINE1", "VICTIM_JURISDICTION", "IC3_CASE_ID"):
        assert a[key] == b[key]
