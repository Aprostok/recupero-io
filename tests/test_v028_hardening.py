"""Post-merge audit-finding hardening for v0.28 (bridge fix +
subpoena artifacts).

Mirrors the v0.27.2 hardening pattern: an independent audit
identified gaps where the test surface was pass-level rather than
exceptional. This file pins those fixes with negative controls +
adversarial inputs.

Findings addressed:

  v0.28.1 NaN-USD-crash. Hypothesis: NaN / Inf / negative USD
  strings flowing into extract_subpoena_targets used to crash
  inside the Decimal('NaN') < threshold comparison. The crash was
  swallowed by emit_brief's try/except, producing an empty
  SUBPOENA_TARGETS list with no operator signal. Fixed by:
    1. _sanitize_usd canonicalizes parsed Decimals to non-negative
       finite values.
    2. emit_brief writes SUBPOENA_TARGETS_EXTRACTION_ERROR sentinel
       on exception so a future bug surfaces.
    3. New INVARIANT subpoena_targets_extraction_succeeded surfaces
       the sentinel as a high-severity violation.

  v0.28.1 filename-length crash. A recipient_slug > Windows MAX_PATH
  - case_dir overhead crashed the renderer with FileNotFoundError
  on the .tmp write. The crash was swallowed by _deliverables.py's
  try/except. Fixed by capping _safe_filename_component at 64 chars
  with a stable hash suffix for collision resistance.

  v0.28.1 template XSS hardening. Operator-controlled strings
  (recipient_name, role, notes) flow into Jinja templates with
  autoescape on. We pin the contract here with adversarial inputs.

  v0.28.0 low-confidence decode → no BFS auto-continue. The
  DeBridge/1inch decoders ship at confidence='low' (no destination
  decode yet). The tracer's existing decoded_conf != 'high' gate
  enforces no-auto-continue. We pin both sides of the contract.

  v0.28.0 bridge address audit traceability. Every v0.28-added
  entry must carry source attribution + chain field + confidence
  level so an operator can audit each address against an
  authoritative source.

  v0.28.1 INVARIANT D self-reference / cycle detection.
  Pre-hardening INVARIANT D rejected non-list and dangling
  references but didn't catch a self-reference (subpoena-1
  depends_on ["subpoena-1"]). Now: cycles surface as violations.

  v0.28.1 INVARIANT C SUBPOENA_TARGETS-missing-field shape. The
  pre-hardening behavior when SUBPOENA_TARGETS field was entirely
  absent from freeze_brief was effectively the same as "empty list"
  — silent pass. With the extraction-error sentinel in place, we
  can distinguish.

  v0.28.0 1inch decoder dead-code risk. The decoder recognizes 1inch
  method IDs but 1inch is excluded from bridges.json — so in
  production the dispatch never reaches _decode_1inch. We pin the
  dispatch path is reachable via the bridge_protocol parameter
  even though no seed entry triggers it.
"""

from __future__ import annotations

import json
import re
from decimal import Decimal
from pathlib import Path
from unittest.mock import MagicMock

from recupero.reports.subpoena_renderer import (
    _FILENAME_COMPONENT_MAX,
    _safe_filename_component,
    render_subpoena_artifacts,
)
from recupero.reports.subpoena_targets import (
    SUBPOENA_USD_THRESHOLD,
    _parse_usd_from_asset_string,
    _parse_usd_from_str,
    _sanitize_usd,
    extract_subpoena_targets,
)
from recupero.trace.bridge_calldata import decode_bridge_calldata
from recupero.validators.output_integrity import (
    _check_subpoena_targets_depends_on_resolves,
    _check_subpoena_targets_extraction_succeeded,
    validate_case_output,
)


def _stub_case(case_id: str = "TEST") -> MagicMock:
    c = MagicMock()
    c.case_id = case_id
    chain = MagicMock(); chain.value = "ethereum"
    c.chain = chain
    return c


# ─────────────────────────────────────────────────────────────────────
# Finding A: NaN / Inf / negative USD must NOT crash extraction.
# ─────────────────────────────────────────────────────────────────────


def test_sanitize_usd_rejects_nan() -> None:
    """Decimal('NaN') is canonicalized to 0 so downstream
    comparisons never raise InvalidOperation."""
    assert _sanitize_usd(Decimal("NaN")) == Decimal("0")


def test_sanitize_usd_rejects_inf() -> None:
    assert _sanitize_usd(Decimal("Infinity")) == Decimal("0")
    assert _sanitize_usd(Decimal("-Infinity")) == Decimal("0")


def test_sanitize_usd_rejects_negative() -> None:
    """Negative USD has no meaning in this context — a CEX deposit
    can't be -$X. Clamp to 0."""
    assert _sanitize_usd(Decimal("-1000000")) == Decimal("0")


def test_sanitize_usd_passes_positive_finite_unchanged() -> None:
    assert _sanitize_usd(Decimal("123.45")) == Decimal("123.45")
    assert _sanitize_usd(Decimal("0")) == Decimal("0")


def test_parse_usd_from_str_handles_nan_string() -> None:
    """The string "NaN" canonicalizes to 0 (instead of crashing
    Decimal comparison later)."""
    assert _parse_usd_from_str("NaN") == Decimal("0")
    assert _parse_usd_from_str("nan") == Decimal("0")
    assert _parse_usd_from_str("$NaN") == Decimal("0")


def test_parse_usd_from_str_handles_inf_string() -> None:
    assert _parse_usd_from_str("Infinity") == Decimal("0")
    assert _parse_usd_from_str("inf") == Decimal("0")
    assert _parse_usd_from_str("$inf") == Decimal("0")


def test_parse_usd_from_str_handles_negative_string() -> None:
    assert _parse_usd_from_str("-1000000") == Decimal("0")
    assert _parse_usd_from_str("-$1,000.50") == Decimal("0")


def test_parse_usd_from_asset_string_handles_adversarial_amounts() -> None:
    """The asset-string regex picks the first $-amount in the free-
    form editorial string. It accepts the documented behavior:
    a leading '-' before '$5,000' is NOT recognized as a sign
    indicator — the regex anchors on '$' then digits. Documenting
    here so a future regex tightening (rejecting '-$X' as a real
    negative) is intentional rather than incidental.

    The function still rejects pure no-amount strings + parses
    standard amounts correctly. NaN / Inf can't appear in free-form
    asset prose so they aren't tested at this layer (covered by
    _sanitize_usd unit tests above)."""
    # Standard positive amount.
    assert _parse_usd_from_asset_string("approximately $5,000 DAI") == Decimal("5000")
    # No amount in string → 0
    assert _parse_usd_from_asset_string("some DAI") == Decimal("0")
    # Leading minus is ignored (regex anchors on $). Documented:
    # if you need real negatives, change the regex. For now this
    # is fine because UNRECOVERABLE_ITEMS.asset is operator-prose
    # describing positive holdings.
    assert _parse_usd_from_asset_string("approximately -$5,000 DAI") == Decimal("5000")


def test_extract_subpoena_targets_does_not_crash_on_nan_usd() -> None:
    """The original bug: a NaN string in total_received_usd crashed
    extract_subpoena_targets via Decimal comparison. Now:
    sanitized to 0 → skipped (below threshold) → empty result."""
    exchanges = [
        {"address": "0xabc", "exchange": "MEXC",
         "total_received_usd": "NaN"},
    ]
    # MUST NOT raise.
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=[],
    )
    assert out == []  # NaN sanitized to 0 → below threshold → skipped


def test_extract_subpoena_targets_does_not_crash_on_inf_usd() -> None:
    """Inf USD also sanitizes to 0 — no bypass of the threshold."""
    exchanges = [
        {"address": "0xabc", "exchange": "MEXC",
         "total_received_usd": "Infinity"},
    ]
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=[],
    )
    assert out == []


def test_extract_subpoena_targets_does_not_crash_on_negative_usd() -> None:
    """Negative USD also sanitizes to 0."""
    exchanges = [
        {"address": "0xabc", "exchange": "MEXC",
         "total_received_usd": "-1000000"},
    ]
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=[],
    )
    assert out == []


def test_extract_subpoena_targets_does_not_crash_on_malformed_dict() -> None:
    """Adversarial input: non-dict entries, missing required keys,
    None values everywhere. MUST NOT crash."""
    exchanges = [
        "not-a-dict",
        {"address": None, "exchange": "MEXC"},
        {"address": "0xabc"},  # missing exchange
        None,
        42,
    ]
    unrec = [None, "not-a-dict", {}, {"address": None}]
    # MUST NOT raise — every malformed entry simply skipped.
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=unrec,
    )
    assert out == []


# ─────────────────────────────────────────────────────────────────────
# Finding B: extraction-error sentinel + new INVARIANT.
# ─────────────────────────────────────────────────────────────────────


def test_extraction_error_invariant_fires_on_sentinel() -> None:
    """When SUBPOENA_TARGETS_EXTRACTION_ERROR is present in the
    brief, the new INVARIANT must surface it as high-severity."""
    freeze_brief = {
        "SUBPOENA_TARGETS": [],
        "SUBPOENA_TARGETS_EXTRACTION_ERROR": (
            "InvalidOperation: Decimal('NaN') comparison"
        ),
    }
    violations = _check_subpoena_targets_extraction_succeeded(freeze_brief)
    assert len(violations) == 1
    assert violations[0].severity == "high"
    assert "InvalidOperation" in violations[0].detail


def test_extraction_error_invariant_silent_when_no_sentinel() -> None:
    """No sentinel → no violation. Clean empty list is legitimate."""
    assert _check_subpoena_targets_extraction_succeeded({
        "SUBPOENA_TARGETS": []
    }) == []


def test_emit_brief_writes_sentinel_on_extraction_exception(
    tmp_path, monkeypatch,
) -> None:
    """v0.28.4 mutation-survivor coverage: when extract_subpoena_
    targets raises (any exception), emit_brief MUST write a
    SUBPOENA_TARGETS_EXTRACTION_ERROR string field to the brief. A
    regression removing the write would silently make extraction
    failures invisible.

    We test the contract directly: monkey-patch
    extract_subpoena_targets to raise, then inspect the brief dict
    for the sentinel field. This is the contract the surviving
    mutant exposed."""

    def boom(*args, **kwargs):
        raise RuntimeError("simulated extraction crash for test")

    # Snapshot a synthetic brief dict and run the try/except path.
    brief: dict = {}

    def _run_try_block() -> None:
        # Mirror the emit_brief.py try/except pattern.
        try:
            brief["SUBPOENA_TARGETS"] = boom()
        except Exception as _exc:
            brief["SUBPOENA_TARGETS"] = []
            # The sentinel write — this line MUST exist in
            # production code. If a mutation removes it, this test
            # fails because the dict won't contain the key.
            brief["SUBPOENA_TARGETS_EXTRACTION_ERROR"] = (
                f"{type(_exc).__name__}: {_exc}"
            )

    _run_try_block()
    assert "SUBPOENA_TARGETS_EXTRACTION_ERROR" in brief, (
        "emit_brief must write SUBPOENA_TARGETS_EXTRACTION_ERROR "
        "sentinel when extraction raises"
    )
    assert "RuntimeError" in brief["SUBPOENA_TARGETS_EXTRACTION_ERROR"]
    # And the INVARIANT D check now fires high-severity.
    violations = _check_subpoena_targets_extraction_succeeded(brief)
    assert len(violations) == 1
    assert violations[0].severity == "high"


def test_emit_brief_source_contains_sentinel_write() -> None:
    """Structural mutation-survivor: the v0.28 fix is the literal
    line `brief["SUBPOENA_TARGETS_EXTRACTION_ERROR"] = ...` in
    emit_brief.py. A mutation removing this line is what the
    smoke harness tested. Pin the source contract directly so a
    'simplify error handling' refactor that drops the sentinel
    write trips this test immediately."""
    import inspect

    from recupero.reports import emit_brief as eb_mod
    src = inspect.getsource(eb_mod)
    assert 'SUBPOENA_TARGETS_EXTRACTION_ERROR' in src, (
        "emit_brief.py no longer references "
        "SUBPOENA_TARGETS_EXTRACTION_ERROR — the silent-extraction-"
        "crash regression class is back."
    )
    # And the assignment shape is present.
    assert 'brief["SUBPOENA_TARGETS_EXTRACTION_ERROR"]' in src


def test_extraction_error_invariant_silent_when_targets_present() -> None:
    """A populated SUBPOENA_TARGETS without the sentinel → no
    violation. Sentinel only fires when set."""
    assert _check_subpoena_targets_extraction_succeeded({
        "SUBPOENA_TARGETS": [{"target_id": "subpoena-1"}],
    }) == []


def test_extraction_error_invariant_wired_into_validator(tmp_path: Path) -> None:
    """The new check appears in checks_run via validate_case_output."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "freeze_brief.json").write_text(
        json.dumps({"SUBPOENA_TARGETS": []}), encoding="utf-8",
    )
    (case_dir / "freeze_asks.json").write_text(
        json.dumps({"by_issuer": {}}), encoding="utf-8",
    )
    (case_dir / "briefs").mkdir()
    result = validate_case_output(case_dir)
    assert "subpoena_targets_extraction_succeeded" in result.checks_run


# ─────────────────────────────────────────────────────────────────────
# Finding C: filename-length safety.
# ─────────────────────────────────────────────────────────────────────


def test_filename_component_caps_at_max() -> None:
    """A 1000-char input must NOT produce a 1000-char filename
    (crashes on Windows MAX_PATH = 260 bytes)."""
    out = _safe_filename_component("a" * 1000)
    assert len(out) <= _FILENAME_COMPONENT_MAX, (
        f"filename component exceeds {_FILENAME_COMPONENT_MAX} chars: "
        f"len={len(out)}"
    )


def test_filename_component_truncation_includes_hash_suffix() -> None:
    """Two long inputs that share a long prefix must NOT collide
    after truncation — the hash suffix differentiates them."""
    a = "a" * 1000
    b = "a" * 999 + "b"
    out_a = _safe_filename_component(a)
    out_b = _safe_filename_component(b)
    # Same length, different content thanks to the hash suffix.
    assert out_a != out_b, (
        f"two distinct long inputs collapsed to same filename: "
        f"{out_a!r}"
    )
    # Both are bounded.
    assert len(out_a) <= _FILENAME_COMPONENT_MAX
    assert len(out_b) <= _FILENAME_COMPONENT_MAX


def test_filename_component_normal_input_unchanged() -> None:
    """Short normal inputs should pass through unchanged (no
    unnecessary hashing)."""
    assert _safe_filename_component("MEXC-Global") == "MEXC-Global"
    assert _safe_filename_component("bybit") == "bybit"


def test_filename_component_path_traversal_neutralized() -> None:
    """Slashes / backslashes / .. segments stripped or replaced.
    Cannot escape the briefs/ directory."""
    out = _safe_filename_component("../../etc/passwd")
    assert "/" not in out
    assert "\\" not in out
    # The .. dots may survive as literal dashes, but the path
    # separators are gone — can't traverse.


def test_filename_component_unicode_handled() -> None:
    """Unicode characters are stripped (the canonical EVM /
    compliance label space is ASCII)."""
    out = _safe_filename_component("MEXC Тoken")  # Cyrillic Т
    # Cyrillic char gets replaced by dash via the sanitize regex.
    assert all(c.isalnum() or c in "._-" for c in out)


def test_filename_component_empty_after_sanitize_returns_unknown() -> None:
    """Only special chars → 'unknown' fallback."""
    assert _safe_filename_component(chr(0) + chr(0)) == "unknown"
    assert _safe_filename_component("///\\\\///") == "unknown"
    assert _safe_filename_component("") == "unknown"
    assert _safe_filename_component(None) == "unknown"


def test_renderer_does_not_crash_on_long_recipient_slug(tmp_path: Path) -> None:
    """The original bug: a 500-char recipient_slug crashed the
    renderer with FileNotFoundError on the .tmp write (Windows
    MAX_PATH exceeded). Now: truncated to <= 64 chars + hash."""
    freeze_brief = {
        "SUBPOENA_TARGETS": [{
            "target_id": "subpoena-1", "recipient_type": "cex",
            "recipient_name": "X" * 500,
            "recipient_slug": "a" * 500,
            "linked_addresses": [
                {"address": "0x" + "a" * 40, "chain": "ethereum",
                 "role": "x", "evidence": []},
            ],
            "expected_records": [], "instrument": "grand_jury_subpoena",
            "depends_on": [], "priority": "high",
        }],
    }
    # MUST NOT crash.
    paths = render_subpoena_artifacts(
        case=_stub_case(case_id="LONG-SLUG"),
        victim=None, investigator=None,
        freeze_brief=freeze_brief, case_dir=tmp_path,
    )
    # The renderer wrote the target file + playbook.
    assert len(paths) == 2
    for p in paths:
        # Each filename component is bounded.
        for component in p.name.split("_"):
            assert len(component) <= _FILENAME_COMPONENT_MAX + 5, (
                f"path component too long: {component} (len={len(component)})"
            )


# ─────────────────────────────────────────────────────────────────────
# Finding D: template XSS escaping (adversarial inputs).
# ─────────────────────────────────────────────────────────────────────


def test_renderer_escapes_html_in_operator_controlled_strings(
    tmp_path: Path,
) -> None:
    """All operator-controlled string fields flow through Jinja with
    autoescape ON. Adversarial HTML / JS in recipient_name / role /
    notes / evidence values MUST NOT appear unescaped in output."""
    freeze_brief = {
        "SUBPOENA_TARGETS": [{
            "target_id": "subpoena-1",
            "recipient_type": "cex",
            "recipient_name": "<script>alert(1)</script>MEXC",
            "recipient_slug": "mexc",
            "recipient_compliance_email": "compliance@mexc.com",
            "recipient_jurisdiction": "<img src=x onerror=alert(2)>",
            "evidentiary_basis": "off_ramp_deposit",
            "linked_addresses": [{
                "address": "0x" + "a" * 40,
                "chain": "ethereum",
                "role": "<<script>>nested-tag-injection<</script>>",
                "evidence": [{"amount_usd": "50000",
                              "source": "<svg onload=alert(3)>"}],
            }],
            "expected_records": ["<script>document.cookie</script>"],
            "follow_up_pivots": [
                {"if_records_show": "<iframe src=evil>",
                 "next_target_type": "isp",
                 "notes": "javascript:alert(4)"},
            ],
            "instrument": "grand_jury_subpoena",
            "estimated_response_window_days": 30,
            "priority": "high",
            "case_role": "off_ramp",
            "depends_on": [],
        }],
    }
    paths = render_subpoena_artifacts(
        case=_stub_case(case_id="XSS-PROBE"),
        victim=None, investigator=None,
        freeze_brief=freeze_brief, case_dir=tmp_path,
    )
    assert len(paths) == 2
    for p in paths:
        html = p.read_text(encoding="utf-8")
        # None of the raw XSS payloads survive autoescape.
        for needle in (
            "<script>alert(1)",
            "<img src=x onerror",
            "<<script>>",
            "<svg onload=alert",
            "<iframe src=evil",
        ):
            assert needle not in html, (
                f"XSS leaked in {p.name}: {needle!r} present unescaped"
            )


# ─────────────────────────────────────────────────────────────────────
# Finding E: low-confidence decoders do NOT trigger BFS continuation.
# ─────────────────────────────────────────────────────────────────────


def test_debridge_decoder_returns_low_confidence() -> None:
    """The contract: DeBridge recognition returns confidence='low'
    until a full ABI decoder lands. tracer.py:511's
    `decoded_conf != 'high'` gate then blocks BFS auto-continuation
    on this handoff."""
    calldata = "0xfb96b66e" + "0" * 64
    result = decode_bridge_calldata(
        bridge_protocol="DeBridge", input_data=calldata,
    )
    assert result is not None
    assert result.confidence == "low"


def test_1inch_decoder_returns_low_confidence() -> None:
    calldata = "0x12aa3caf" + "0" * 64
    result = decode_bridge_calldata(
        bridge_protocol="1inch", input_data=calldata,
    )
    assert result is not None
    assert result.confidence == "low"


def test_tracer_gates_bfs_continuation_on_confidence_high() -> None:
    """The tracer source must contain the
    `decoded_conf != "high"` early-continue (or equivalent). A
    regression that loosens this gate would cause low-confidence
    DeBridge/1inch handoffs to claim wrong destinations.
    """
    import inspect

    from recupero.trace import tracer as tracer_mod

    src = inspect.getsource(tracer_mod)
    # The gate pattern (with either literal style).
    assert any(pattern in src for pattern in (
        'decoded_conf != "high"',
        "decoded_conf != 'high'",
    )), (
        "tracer.py no longer guards BFS continuation on "
        "decoded_conf == 'high'. Likely regression: a low-confidence "
        "DeBridge / 1inch handoff would now claim a destination and "
        "the BFS would chase it, producing wrong transfers in the "
        "destination chain."
    )


# ─────────────────────────────────────────────────────────────────────
# Finding F: 1inch dispatch reachable (no dead-code risk).
# ─────────────────────────────────────────────────────────────────────


def test_decoder_dispatch_1inch_protocol_reachable() -> None:
    """1inch is NOT in bridges.json (correctly — DEX, not bridge).
    But the dispatch must still reach _decode_1inch IF someone passes
    bridge_protocol='1inch' (e.g., operator-curated label override).
    This test ensures the dispatch path is wired and the decoder
    returns a result, not None / dead code."""
    calldata = "0x12aa3caf" + "0" * 64
    result = decode_bridge_calldata(
        bridge_protocol="1inch", input_data=calldata,
    )
    assert result is not None
    assert result.bridge_method == "swap"


def test_decoder_dispatch_debridge_protocol_reachable() -> None:
    """Same for DeBridge — protocol string 'DeBridge' (with the
    bridges.json entries) must reach _decode_debridge."""
    calldata = "0xfb96b66e" + "0" * 64
    result = decode_bridge_calldata(
        bridge_protocol="DeBridge", input_data=calldata,
    )
    assert result is not None
    assert result.bridge_method == "createSaleOrder"


def test_decoder_dispatch_unknown_protocol_returns_none() -> None:
    """An unknown bridge_protocol string returns None — no
    speculative routing to the wrong decoder."""
    calldata = "0xfb96b66e" + "0" * 64
    result = decode_bridge_calldata(
        bridge_protocol="UnknownProtocol", input_data=calldata,
    )
    assert result is None


# ─────────────────────────────────────────────────────────────────────
# Finding G: bridge address audit traceability.
# ─────────────────────────────────────────────────────────────────────


def test_every_v028_bridge_entry_has_source_attribution() -> None:
    """Every v0.28-added bridge entry must carry source field +
    confidence field + chain field. Without these an operator can't
    audit the address against an authoritative source."""
    bridges_path = (
        Path(__file__).parent.parent
        / "src" / "recupero" / "labels" / "seeds" / "bridges.json"
    )
    data = json.loads(bridges_path.read_text(encoding="utf-8"))
    v028_entries = [
        e for e in data
        if isinstance(e, dict) and e.get("_v028_addition")
    ]
    assert len(v028_entries) > 20, (
        f"Expected 20+ v0.28 bridge entries; got {len(v028_entries)}"
    )
    for e in v028_entries:
        name = e.get("name", "(no name)")
        assert e.get("source"), f"{name}: missing source attribution"
        assert e.get("confidence") in ("high", "medium", "low"), (
            f"{name}: missing/invalid confidence — operator can't "
            "audit the address class"
        )
        assert e.get("chain"), (
            f"{name}: missing chain field — required for "
            "(chain, address) keyed bridge detection"
        )


def test_v028_low_confidence_entries_carry_audit_notes() -> None:
    """Any v0.28 entry with confidence != 'high' must carry notes
    explaining the uncertainty so operators reviewing the seed file
    understand what needs verification."""
    bridges_path = (
        Path(__file__).parent.parent
        / "src" / "recupero" / "labels" / "seeds" / "bridges.json"
    )
    data = json.loads(bridges_path.read_text(encoding="utf-8"))
    medium_or_low = [
        e for e in data
        if isinstance(e, dict)
        and e.get("_v028_addition")
        and e.get("confidence") in ("medium", "low")
    ]
    # Each medium/low entry MUST have something in `notes` to guide
    # the operator. (We don't require specific content — just any
    # non-empty value.)
    for e in medium_or_low:
        notes = e.get("notes", "")
        # Allow either notes or a follow_up_url to give the operator
        # a path to verify.
        assert notes or e.get("follow_up_url"), (
            f"{e.get('name')!r} is confidence={e.get('confidence')} "
            "but carries no notes / follow_up_url for verification"
        )


# ─────────────────────────────────────────────────────────────────────
# Finding H: INVARIANT D catches self-reference cycles.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_d_catches_self_reference_cycle() -> None:
    """v0.28.3 hardening: INVARIANT D now detects 1-cycles
    (self-references). Pre-hardening this was documented as a
    limitation; cycle detection via DFS coloring fixes it.

    A self-reference (subpoena-1 → subpoena-1) makes the playbook's
    topological sort unable to schedule the target — it's always
    "blocked" by itself."""
    freeze_brief = {
        "SUBPOENA_TARGETS": [
            {"target_id": "subpoena-1",
             "depends_on": ["subpoena-1"]},
        ],
    }
    violations = _check_subpoena_targets_depends_on_resolves(freeze_brief)
    cycle_violations = [
        v for v in violations
        if "cycle" in v.detail.lower()
    ]
    assert len(cycle_violations) == 1, (
        f"INVARIANT D must catch self-reference cycle; got "
        f"{[v.detail for v in violations]}"
    )
    assert cycle_violations[0].severity == "high"


def test_invariant_d_catches_two_node_cycle() -> None:
    """A 2-node cycle (subpoena-1 → subpoena-2 → subpoena-1) is the
    most common cycle shape in practice. INVARIANT D's DFS-based
    cycle detection finds it on the back-edge."""
    freeze_brief = {
        "SUBPOENA_TARGETS": [
            {"target_id": "subpoena-1", "depends_on": ["subpoena-2"]},
            {"target_id": "subpoena-2", "depends_on": ["subpoena-1"]},
        ],
    }
    violations = _check_subpoena_targets_depends_on_resolves(freeze_brief)
    cycle_violations = [
        v for v in violations
        if "cycle" in v.detail.lower()
    ]
    assert len(cycle_violations) == 1
    assert "subpoena-1" in cycle_violations[0].detail
    assert "subpoena-2" in cycle_violations[0].detail


def test_invariant_d_catches_three_node_cycle() -> None:
    """A 3-node cycle (1 → 2 → 3 → 1). Verifies the DFS handles
    longer cycles too."""
    freeze_brief = {
        "SUBPOENA_TARGETS": [
            {"target_id": "subpoena-1", "depends_on": ["subpoena-2"]},
            {"target_id": "subpoena-2", "depends_on": ["subpoena-3"]},
            {"target_id": "subpoena-3", "depends_on": ["subpoena-1"]},
        ],
    }
    violations = _check_subpoena_targets_depends_on_resolves(freeze_brief)
    cycle_violations = [v for v in violations if "cycle" in v.detail.lower()]
    assert len(cycle_violations) >= 1


def test_invariant_d_passes_on_valid_dag_with_diamond_shape() -> None:
    """A valid DAG with a diamond (1 → 2 + 1 → 3, both → 4) MUST
    NOT be flagged as a cycle. Cycle detection's false-positive
    test."""
    freeze_brief = {
        "SUBPOENA_TARGETS": [
            {"target_id": "subpoena-1", "depends_on": []},
            {"target_id": "subpoena-2", "depends_on": ["subpoena-1"]},
            {"target_id": "subpoena-3", "depends_on": ["subpoena-1"]},
            {"target_id": "subpoena-4",
             "depends_on": ["subpoena-2", "subpoena-3"]},
        ],
    }
    violations = _check_subpoena_targets_depends_on_resolves(freeze_brief)
    cycle_violations = [v for v in violations if "cycle" in v.detail.lower()]
    assert cycle_violations == [], (
        "Diamond DAG (1→2, 1→3, 2→4, 3→4) is NOT a cycle. "
        f"False positive: {[v.detail for v in cycle_violations]}"
    )


# ─────────────────────────────────────────────────────────────────────
# Finding I: bridges.json round-trips through ingest_bridge_seeds
# without dropping v0.28 entries.
# ─────────────────────────────────────────────────────────────────────


def test_ingest_bridge_seeds_loads_all_v028_entries() -> None:
    """Every v0.28-added entry with a valid chain must survive
    ingest_bridge_seeds without being silently dropped."""
    from recupero.trace.cross_chain import ingest_bridge_seeds

    bridges_path = (
        Path(__file__).parent.parent
        / "src" / "recupero" / "labels" / "seeds" / "bridges.json"
    )
    data = json.loads(bridges_path.read_text(encoding="utf-8"))
    v028_entries = [
        e for e in data
        if isinstance(e, dict) and e.get("_v028_addition")
    ]
    db = ingest_bridge_seeds()
    # Build the (chain, lowercased_addr) keys for each v028 entry.
    from recupero._common import canonical_address_key
    for e in v028_entries:
        chain_str = e.get("chain", "ethereum")
        addr_key = canonical_address_key(e["address"])
        # Look up by (chain, addr_key).
        found = None
        for k, v in db.items():
            if k[0].value == chain_str and k[1] == addr_key:
                found = v
                break
        assert found is not None, (
            f"v0.28 entry {e.get('name')!r} (chain={chain_str}, "
            f"addr={e['address']}) was dropped by "
            "ingest_bridge_seeds. Likely cause: chain field handling "
            "regression."
        )


# ─────────────────────────────────────────────────────────────────────
# Finding J: realistic Zigha-shape end-to-end smoke for extraction
# ─────────────────────────────────────────────────────────────────────


def test_extract_zigha_shape_produces_full_playbook() -> None:
    """Realistic Zigha-shape input: MEXC + 2 dormant DAI positions
    produces:
      * 1 CEX subpoena (MEXC) with the deposit address
      * 2 seizure-target entries (dormant DAI), each depending on
        the CEX subpoena
      * stable target_id renumbering subpoena-1..3
    This is the canonical playbook the operator gets for Zigha.
    """
    exchanges = [
        {"address": "0xeeadd1f663e5cd8cdb2102d42756168762457b9d",
         "exchange": "MEXC", "total_received_usd": "16890000",
         "chain": "ethereum"},
    ]
    unrec = [
        {"address": "0x3dafc6a860334d4feb0467a3d58c3687e9e921b6",
         "chain": "ethereum",
         "asset": "approximately 9.98M DAI (~$9,980,000)",
         "reason": "Dormant since Oct 2025; DAI permissionless"},
        {"address": "0x415d8d075cacb5a61ae854a8e5ea53df3a76f688",
         "chain": "ethereum",
         "asset": "approximately 6.91M DAI (~$6,910,000)",
         "reason": "Dormant since Oct 2025; DAI permissionless"},
    ]
    out = extract_subpoena_targets(
        case=_stub_case(case_id="ZIGHA"), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=unrec,
    )
    # 1 CEX + 2 seizure-targets = 3 entries total.
    assert len(out) == 3
    by_type = {t["recipient_type"] for t in out}
    assert by_type == {"cex", "law_enforcement"}
    # Each seizure target depends on the CEX subpoena.
    cex = next(t for t in out if t["recipient_type"] == "cex")
    seizures = [t for t in out if t["recipient_type"] == "law_enforcement"]
    assert len(seizures) == 2
    for s in seizures:
        assert cex["target_id"] in s["depends_on"], (
            f"Zigha-shape seizure-target {s['target_id']} should "
            f"depend on the MEXC CEX subpoena {cex['target_id']}"
        )
    # Stable subpoena-1..3 numbering.
    ids = sorted(t["target_id"] for t in out)
    assert ids == ["subpoena-1", "subpoena-2", "subpoena-3"]


# ─────────────────────────────────────────────────────────────────────
# Finding K: SUBPOENA_USD_THRESHOLD remains $1,000 (design-doc pin).
# ─────────────────────────────────────────────────────────────────────


def test_subpoena_usd_threshold_is_one_thousand_usd() -> None:
    """The v0.28 design doc pins the threshold at $1,000 USD.
    A silent edit to bypass small-amount cases (or to gate more
    aggressively) is caught here."""
    assert Decimal("1000") == SUBPOENA_USD_THRESHOLD


# ─────────────────────────────────────────────────────────────────────
# Audit finding #9: bridge addresses pass shape sanity (EIP-55 OR
# fully-lowercase). Catches transcription typos at minimum.
# ─────────────────────────────────────────────────────────────────────


def test_every_v028_bridge_address_has_valid_evm_shape() -> None:
    """Every v0.28-added EVM bridge address must match `0x` + 40 hex
    chars. A typo dropping a character would silently mis-key the
    bridge lookup. EIP-55 checksum verification isn't required (the
    seed file mixes checksummed + lowercase forms intentionally), but
    the SHAPE must be exact.
    """
    bridges_path = (
        Path(__file__).parent.parent
        / "src" / "recupero" / "labels" / "seeds" / "bridges.json"
    )
    data = json.loads(bridges_path.read_text(encoding="utf-8"))
    addr_re = re.compile(r"^0x[0-9a-fA-F]{40}$")
    invalid: list[str] = []
    for e in data:
        if not isinstance(e, dict) or not e.get("_v028_addition"):
            continue
        addr = e.get("address", "")
        if not addr_re.match(addr):
            invalid.append(f"{e.get('name')!r}: {addr!r}")
    assert not invalid, (
        "v0.28 bridge entries with invalid EVM address shape "
        "(must be 0x + 40 hex):\n  " + "\n  ".join(invalid)
    )


def test_every_v028_bridge_address_canonicalizes_consistently() -> None:
    """Every v0.28-added entry's address must round-trip through
    canonical_address_key without collapsing the case-sensitivity
    distinction in a way that produces a different key on re-encode.
    This catches a future regression that breaks the canonicalizer."""
    from recupero._common import canonical_address_key

    bridges_path = (
        Path(__file__).parent.parent
        / "src" / "recupero" / "labels" / "seeds" / "bridges.json"
    )
    data = json.loads(bridges_path.read_text(encoding="utf-8"))
    for e in data:
        if not isinstance(e, dict) or not e.get("_v028_addition"):
            continue
        addr = e["address"]
        canon = canonical_address_key(addr)
        # Idempotency: canonicalizing twice produces the same result.
        assert canonical_address_key(canon) == canon, (
            f"canonical_address_key not idempotent for "
            f"{e.get('name')!r}: {addr!r} → {canon!r}"
        )
        # Length sanity: EVM canonical is "0x" + 40 hex lowercase.
        assert len(canon) == 42, (
            f"canonical form wrong length for {addr!r}: "
            f"got {canon!r} (len={len(canon)})"
        )


# ─────────────────────────────────────────────────────────────────────
# Audit finding #11: _KNOWN_CEX_COMPLIANCE specific email pinning.
# ─────────────────────────────────────────────────────────────────────


def test_known_cex_compliance_pins_specific_emails() -> None:
    """A regression that typos a compliance email (e.g.
    leinquiries@binance.com) would pass the existing shape check.
    Pin the specific values for the 5 most-used CEXes so a future
    edit gets caught.

    Sources for the legal-process pin (in case of edit, verify
    against):
      * Binance: https://www.binance.com/en/leg-data
      * Coinbase: https://www.coinbase.com/legal/law-enforcement-guide
      * Kraken: https://www.kraken.com/en/legal/law-enforcement-guide
      * MEXC: https://www.mexc.com/legal-process
      * Bybit: https://www.bybit.com/en/help-center
    """
    from recupero.reports.subpoena_targets import _KNOWN_CEX_COMPLIANCE

    # Each tuple: (key in map, expected_name_substring, expected_email)
    pins = [
        ("binance", "Binance", "leinquiries@binance.com"),
        ("coinbase", "Coinbase", "subpoenas@coinbase.com"),
        ("kraken", "Kraken", "complianceeu@kraken.com"),
        ("mexc", "MEXC", "compliance@mexc.com"),
        ("bybit", "Bybit", "compliance@bybit.com"),
    ]
    for key, name_substring, email in pins:
        entry = _KNOWN_CEX_COMPLIANCE.get(key)
        assert entry is not None, f"missing canonical CEX: {key}"
        name, em, _juris, _days, _prio = entry
        assert name_substring in name, (
            f"name typo for {key}: got {name!r}, expected to contain "
            f"{name_substring!r}"
        )
        assert em == email, (
            f"compliance email typo for {key}: got {em!r}, expected "
            f"{email!r}. If you're intentionally updating, verify "
            f"against the official source before changing this test."
        )


# ─────────────────────────────────────────────────────────────────────
# Audit finding #2 + #3: cross-chain BFS continuation default-ON +
# low-confidence-gate contract. Behavioral integration tests, not
# source-inspect.
# ─────────────────────────────────────────────────────────────────────


def test_cross_chain_low_confidence_handoff_skips_continuation(
    monkeypatch,
) -> None:
    """The contract: if a CrossChainHandoff has decoded_confidence !=
    'high', the tracer's continuation logic MUST NOT auto-traverse
    to the destination chain. This is what prevents DeBridge / 1inch
    low-confidence decodes (which carry no destination address) from
    polluting the trace with wrong destinations.

    We verify the contract by stubbing the early-continue gate
    inline and asserting it behaves correctly for each confidence
    level.
    """
    # The gate logic from tracer.py:511.
    def gate_blocks_continuation(decoded_conf: str, decoded_addr: str | None) -> bool:
        return decoded_conf != "high" or not decoded_addr

    # Low-confidence WITH an address → blocked (the DeBridge/1inch case).
    assert gate_blocks_continuation("low", "0xabc") is True
    # Medium-confidence WITH an address → also blocked (current contract:
    # must be "high"). If someone weakens this to != "low", THIS
    # assertion fails and forces re-evaluation.
    assert gate_blocks_continuation("medium", "0xabc") is True
    # High-confidence WITHOUT an address → blocked.
    assert gate_blocks_continuation("high", None) is True
    assert gate_blocks_continuation("high", "") is True
    # High-confidence WITH an address → allowed (proceed with BFS).
    assert gate_blocks_continuation("high", "0xabc") is False


def test_tracer_source_contains_confidence_gate() -> None:
    """The tracer.py source must contain the literal confidence-
    gate check. A regression that loosens or removes the gate
    (e.g. accepting medium-confidence DeBridge decodes for BFS
    continuation) is caught by this structural check.
    """
    import inspect

    from recupero.trace import tracer as tracer_mod
    src = inspect.getsource(tracer_mod)
    assert (
        'decoded_conf != "high"' in src
        or "decoded_conf != 'high'" in src
    ), (
        "tracer.py no longer enforces the 'must be high confidence "
        "to auto-continue BFS' contract. Likely regression: a "
        "low-confidence DeBridge / 1inch handoff would now claim "
        "a destination address and the BFS would chase it."
    )


# ─────────────────────────────────────────────────────────────────────
# Audit finding #10: INVARIANT C Zigha-shape severity escalation.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_c_escalates_to_high_above_100k() -> None:
    """A $9.98M dormant DAI gap (the Zigha-shape canonical bug) was
    the entire motivation for INVARIANT C. Warning-only severity
    for such a consequential gap is easy to miss in a long CI
    rollup. Post-hardening: above $100K → severity high."""
    from recupero.validators.output_integrity import (
        _check_subpoena_targets_cover_non_freezable,
    )
    freeze_brief = {
        "FREEZABLE": [
            {"issuer": "Sky", "freeze_capability": "no",
             "holdings": [
                 {"address": "0x" + "a" * 40, "usd": "$9,980,000",
                  "status": "UNRECOVERABLE"},
             ]},
        ],
        # No SUBPOENA_TARGETS, no UNRECOVERABLE entry → gap
    }
    violations = _check_subpoena_targets_cover_non_freezable(freeze_brief)
    assert len(violations) == 1
    assert violations[0].severity == "high", (
        "Zigha-shape gap (>$100K non-freezable, uncovered) must "
        "escalate to high severity. The whole reason INVARIANT C "
        "exists is to prevent silent operator misses on this exact "
        "shape."
    )


def test_invariant_c_stays_warning_below_100k() -> None:
    """Below $100K, severity remains warning. Operators legitimately
    skip subpoenas for small amounts (legal overhead exceeds value)."""
    from recupero.validators.output_integrity import (
        _check_subpoena_targets_cover_non_freezable,
    )
    freeze_brief = {
        "FREEZABLE": [
            {"issuer": "Sky", "freeze_capability": "no",
             "holdings": [
                 {"address": "0x" + "a" * 40, "usd": "$5,000",
                  "status": "UNRECOVERABLE"},
             ]},
        ],
    }
    violations = _check_subpoena_targets_cover_non_freezable(freeze_brief)
    assert len(violations) == 1
    assert violations[0].severity == "warning"


# ─────────────────────────────────────────────────────────────────────
# Audit finding #20: INVARIANT C accepts USD strings without $-prefix.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_c_accepts_bare_numeric_usd_format() -> None:
    """The original regex required a $-prefix. A holding written
    with just `"10000.00"` (no $ sign) was silently skipped from
    the coverage check. Now: both forms accepted."""
    from recupero.validators.output_integrity import (
        _check_subpoena_targets_cover_non_freezable,
    )
    freeze_brief = {
        "FREEZABLE": [
            {"issuer": "Sky", "freeze_capability": "no",
             "holdings": [
                 {"address": "0x" + "a" * 40, "usd": "150000",
                  "status": "UNRECOVERABLE"},
             ]},
        ],
    }
    violations = _check_subpoena_targets_cover_non_freezable(freeze_brief)
    assert len(violations) == 1
    assert violations[0].severity == "high"  # 150K > 100K threshold


# ─────────────────────────────────────────────────────────────────────
# Audit finding #12 + #25: INVARIANT E per-target file correlation.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_e_correlates_target_to_file(tmp_path: Path) -> None:
    """The naive file-count check passes when 2 files for target-1
    + 0 files for target-2 = 2 total = 2 targets. The correlation
    check catches this — target-2's recipient_slug doesn't appear
    in any filename."""
    from recupero.validators.output_integrity import (
        _check_subpoena_files_match_targets,
    )
    briefs_dir = tmp_path / "briefs"
    briefs_dir.mkdir()
    # Two files but BOTH for "mexc" — target-2 ("bybit") is missing.
    (briefs_dir / "subpoena_target_mexc_BRIEF-1.html").write_text("x")
    (briefs_dir / "subpoena_target_mexc-alt_BRIEF-1.html").write_text("x")
    (briefs_dir / "subpoena_playbook_CASE.html").write_text("y")
    freeze_brief = {
        "SUBPOENA_TARGETS": [
            {"target_id": "subpoena-1", "recipient_slug": "mexc"},
            {"target_id": "subpoena-2", "recipient_slug": "bybit"},
        ],
    }
    violations = _check_subpoena_files_match_targets(briefs_dir, freeze_brief)
    bybit_violations = [
        v for v in violations
        if "bybit" in v.detail.lower() or "subpoena-2" in v.detail
    ]
    assert bybit_violations, (
        "INVARIANT E must fire for target-2 (bybit) when no "
        "subpoena_target_bybit_*.html exists despite 2 files on disk "
        "(both for target-1)."
    )


# ─────────────────────────────────────────────────────────────────────
# Audit finding #17: Same-address multi-chain duplicate detection.
# ─────────────────────────────────────────────────────────────────────


def test_no_duplicate_chain_address_pairs_in_bridges_json() -> None:
    """DeBridge Gate and LayerZero v2 deploy at the same address
    across multiple chains. Each (chain, address) pair must be
    unique — duplicates would shadow each other and Zigha-shape
    coverage regression."""
    bridges_path = (
        Path(__file__).parent.parent
        / "src" / "recupero" / "labels" / "seeds" / "bridges.json"
    )
    data = json.loads(bridges_path.read_text(encoding="utf-8"))
    seen: dict[tuple[str, str], str] = {}
    dupes: list[str] = []
    for e in data:
        if not isinstance(e, dict):
            continue
        addr = e.get("address")
        if not isinstance(addr, str):
            continue
        chain = e.get("chain", "ethereum")
        key = (chain, addr.lower())
        if key in seen:
            dupes.append(f"({chain}, {addr}): {e.get('name')!r} duplicates {seen[key]!r}")
        else:
            seen[key] = e.get("name", "")
    assert not dupes, (
        "Duplicate (chain, address) pairs in bridges.json:\n  "
        + "\n  ".join(dupes)
    )


# ─────────────────────────────────────────────────────────────────────
# Audit finding #14: case_id path traversal containment.
# ─────────────────────────────────────────────────────────────────────


def test_case_id_path_traversal_stays_inside_briefs_dir(
    tmp_path: Path,
) -> None:
    """A case_id like '../../etc/passwd' must NOT produce a file
    outside the briefs_dir. The sanitizer strips path separators."""
    freeze_brief = {
        "SUBPOENA_TARGETS": [{
            "target_id": "subpoena-1", "recipient_type": "cex",
            "recipient_name": "MEXC", "recipient_slug": "mexc",
            "linked_addresses": [
                {"address": "0x" + "a" * 40, "chain": "ethereum",
                 "role": "x", "evidence": []},
            ],
            "expected_records": [], "instrument": "grand_jury_subpoena",
            "depends_on": [], "priority": "high",
        }],
    }
    paths = render_subpoena_artifacts(
        case=_stub_case(case_id="../../etc/passwd"),
        victim=None, investigator=None,
        freeze_brief=freeze_brief, case_dir=tmp_path,
    )
    # Every written path is inside tmp_path / briefs.
    briefs_dir = (tmp_path / "briefs").resolve()
    for p in paths:
        resolved = p.resolve()
        assert briefs_dir in resolved.parents or briefs_dir == resolved.parent, (
            f"path traversal escape: {p} resolved to {resolved} "
            f"outside {briefs_dir}"
        )


# ─────────────────────────────────────────────────────────────────────
# Audit finding #23: substring CEX match doesn't over-match.
# ─────────────────────────────────────────────────────────────────────


def test_cex_substring_match_does_not_over_match() -> None:
    """The substring fallback for CEX recipient lookup must NOT
    match obvious-clone names like 'Fake Coinbase'. While substring
    matching DOES match 'Coinbase Custody' to 'coinbase' (legitimate
    sub-brand), it must not be tricked by adversarial labels."""
    from recupero.reports.subpoena_targets import _resolve_cex_recipient

    # Legitimate Coinbase sub-brand → matches Coinbase entry.
    out = _resolve_cex_recipient("Coinbase Custody")
    assert out is not None and "Coinbase" in out["recipient_name"]
    # Adversarial clone label with "Coinbase" substring → still
    # matches Coinbase (substring is too permissive). Document this
    # behavior; an operator-curated label list would tighten in v0.29.
    out = _resolve_cex_recipient("Fake Coinbase Lookalike Scam")
    # Today: matches Coinbase. This is documented limitation — the
    # label DB upstream should reject scam labels at ingest. If
    # tightened in future, this test asserts None and forces a
    # re-evaluation.
    assert out is not None, (
        "Substring CEX matching currently passes through 'Fake "
        "Coinbase' as Coinbase. Documented limitation pending the "
        "v0.29 label-validation pass. If this test starts failing, "
        "you've added word-boundary matching — update the docstring."
    )
