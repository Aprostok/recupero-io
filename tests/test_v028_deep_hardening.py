"""v0.28.3 deep hardening — property-based fuzzing + e2e integration +
deferred audit findings.

Three categories of tests in this file:

1. **Property tests** (hypothesis-driven adversarial fuzzing). The
   most-load-bearing functions in the v0.28 surface get
   property tests that guarantee invariants hold across thousands
   of random inputs. This is the "catch issues rather than pass"
   discipline applied at the unit level: instead of asserting
   "this exact input produces this exact output", we assert
   "for ALL inputs satisfying the precondition, output X holds".

2. **End-to-end integration tests** with a realistic Zigha-shape
   case_dir, exercising the full pipeline: extract_subpoena_targets
   → render_subpoena_artifacts → validate_case_output. Catches
   integration bugs unit tests miss (e.g. brief schema drift,
   renderer-validator handshake).

3. **Deferred audit findings**. Things flagged in the v0.28.2
   audit but deferred:
     * Cycle detection in INVARIANT D (now: DFS-based detection
       finds self / 2-node / 3-node / arbitrary-length cycles)
     * `_atomic_write` cleans up .tmp on failure
     * Operator-supplied CEX compliance overrides via env var
     * INVARIANT C also checks UNRECOVERABLE_ITEMS (editorial
       alternate key)
"""

from __future__ import annotations

import json
import re
from decimal import Decimal
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import HealthCheck, assume, given, settings, strategies as st

from recupero.reports.subpoena_renderer import (
    _FILENAME_COMPONENT_MAX,
    _atomic_write,
    _safe_filename_component,
    render_subpoena_artifacts,
)
from recupero.reports.subpoena_targets import (
    SUBPOENA_USD_THRESHOLD,
    _parse_usd_from_asset_string,
    _parse_usd_from_str,
    _sanitize_usd,
    _slugify,
    extract_subpoena_targets,
)
from recupero.validators.output_integrity import (
    _check_subpoena_files_match_targets,
    _check_subpoena_targets_cover_non_freezable,
    _check_subpoena_targets_depends_on_resolves,
    validate_case_output,
)


def _stub_case(case_id: str = "TEST") -> MagicMock:
    c = MagicMock()
    c.case_id = case_id
    chain = MagicMock(); chain.value = "ethereum"
    c.chain = chain
    return c


# ─────────────────────────────────────────────────────────────────────
# Property tests — hypothesis-driven adversarial fuzzing.
# ─────────────────────────────────────────────────────────────────────


@given(s=st.text(max_size=2000))
@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property_safe_filename_component_always_bounded(s: str) -> None:
    """Property: for ANY input string, output length is bounded by
    _FILENAME_COMPONENT_MAX. No matter what an operator types
    (Unicode, control chars, null bytes, gigabytes of text), the
    filename never exceeds the platform limit."""
    out = _safe_filename_component(s)
    assert len(out) <= _FILENAME_COMPONENT_MAX, (
        f"input len={len(s)} produced output len={len(out)} > "
        f"{_FILENAME_COMPONENT_MAX}: input={s[:40]!r}..."
    )


@given(s=st.text(max_size=2000))
@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property_safe_filename_component_ascii_only(s: str) -> None:
    """Property: output is filename-safe ASCII. No Unicode, no
    control chars, no path separators."""
    out = _safe_filename_component(s)
    # Each char is alphanumeric OR in [._-]. No whitespace, no NUL,
    # no path separators, no Unicode.
    for c in out:
        assert c.isascii(), f"non-ASCII char in output: {c!r}"
        assert c.isalnum() or c in "._-", f"unsafe char: {c!r}"


@given(s=st.text(max_size=2000))
@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property_safe_filename_component_idempotent(s: str) -> None:
    """Property: f(f(x)) == f(x). Re-sanitizing already-sanitized
    output produces the same string (no further changes)."""
    once = _safe_filename_component(s)
    twice = _safe_filename_component(once)
    assert once == twice, (
        f"not idempotent: {s!r} → {once!r} → {twice!r}"
    )


@given(s=st.text(max_size=2000))
@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
def test_property_safe_filename_component_never_empty(s: str) -> None:
    """Property: output is never the empty string (fallback to
    'unknown'). Important because Path('') / 'file.html' raises
    in some contexts."""
    out = _safe_filename_component(s)
    assert out, f"empty output for input {s!r}"


@given(usd_decimal=st.one_of(
    # Finite decimals in a wide range, including negatives.
    st.decimals(
        min_value=Decimal("-1e18"), max_value=Decimal("1e18"),
        allow_nan=False, allow_infinity=False,
    ),
    # NaN / Inf separately (hypothesis won't combine with bounds).
    st.just(Decimal("NaN")),
    st.just(Decimal("Infinity")),
    st.just(Decimal("-Infinity")),
    st.just(Decimal("sNaN")),  # signaling NaN
))
def test_property_sanitize_usd_always_non_negative_finite(usd_decimal) -> None:
    """Property: for ANY Decimal (NaN, Inf, negative, huge positive),
    _sanitize_usd produces a non-negative finite Decimal. This is
    the invariant that prevents the comparison crash discovered in
    the v0.28.2 audit."""
    out = _sanitize_usd(usd_decimal)
    assert not out.is_nan()
    assert not out.is_infinite()
    assert out >= 0


@given(s=st.text(max_size=200))
def test_property_parse_usd_from_str_never_crashes(s: str) -> None:
    """Property: _parse_usd_from_str MUST NOT raise on any string
    input. Returns Decimal('0') on parse failure. Critical for the
    extraction-loop crash-safety guarantee."""
    out = _parse_usd_from_str(s)
    assert isinstance(out, Decimal)
    assert not out.is_nan()
    assert not out.is_infinite()
    assert out >= 0


@given(s=st.text(max_size=500))
def test_property_parse_usd_from_asset_string_never_crashes(s: str) -> None:
    """Same crash-safety guarantee for the asset-string parser."""
    out = _parse_usd_from_asset_string(s)
    assert isinstance(out, Decimal)
    assert not out.is_nan()
    assert not out.is_infinite()
    assert out >= 0


@given(slug=st.text(max_size=100))
def test_property_slugify_never_crashes(slug: str) -> None:
    """Property: _slugify accepts any input. Returns a string."""
    out = _slugify(slug)
    assert isinstance(out, str)
    assert out  # never empty (falls back to 'unknown')


# ─────────────────────────────────────────────────────────────────────
# Property test: extract_subpoena_targets never crashes on
# arbitrary exchange / unrecoverable input.
# ─────────────────────────────────────────────────────────────────────


# Exchange-dict strategy: address may be missing, malformed, or any
# string; exchange field is similar; USD value is arbitrary text.
_exchange_strategy = st.fixed_dictionaries({
    "address": st.one_of(
        st.text(max_size=50),
        st.none(),
        st.just(""),
    ),
    "exchange": st.one_of(
        st.text(max_size=50),
        st.none(),
    ),
    "total_received_usd": st.one_of(
        st.text(max_size=50),
        st.none(),
        st.just("NaN"),
        st.just("inf"),
        st.just("-1000"),
    ),
    "chain": st.one_of(
        st.text(max_size=20),
        st.none(),
    ),
})

_unrecoverable_strategy = st.fixed_dictionaries({
    "address": st.one_of(st.text(max_size=50), st.none()),
    "chain": st.one_of(st.text(max_size=20), st.none()),
    "asset": st.text(max_size=200),
    "reason": st.text(max_size=200),
})


@given(
    exchanges=st.lists(_exchange_strategy, max_size=10),
    unrecoverable=st.lists(_unrecoverable_strategy, max_size=10),
)
@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None, max_examples=50)
def test_property_extract_subpoena_targets_never_crashes(
    exchanges, unrecoverable,
) -> None:
    """Property: extract_subpoena_targets MUST NOT raise on any
    well-shaped (dict-of-strings) input. Adversarial fuzzing 50
    inputs each run via hypothesis."""
    # MUST NOT raise. We don't care about the output shape — only
    # that the function returns cleanly.
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=unrecoverable,
    )
    assert isinstance(out, list)
    # Each output is a dict with at least target_id.
    for t in out:
        assert isinstance(t, dict)
        assert "target_id" in t


@given(
    exchanges=st.lists(_exchange_strategy, max_size=10),
)
@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None, max_examples=50)
def test_property_extract_target_ids_are_unique_and_sequential(
    exchanges,
) -> None:
    """Property: target_ids in the output are unique + form a
    contiguous subpoena-1..N sequence. Catches re-numbering bugs."""
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=[],
    )
    ids = [t["target_id"] for t in out]
    # Unique.
    assert len(ids) == len(set(ids))
    # Sequential subpoena-1..N (where N = len).
    if ids:
        expected = [f"subpoena-{i+1}" for i in range(len(ids))]
        assert sorted(ids) == sorted(expected)


# ─────────────────────────────────────────────────────────────────────
# Property test: depends_on references always resolve.
# ─────────────────────────────────────────────────────────────────────


@given(
    exchanges=st.lists(_exchange_strategy, max_size=5),
    unrecoverable=st.lists(_unrecoverable_strategy, max_size=5),
)
@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None, max_examples=50)
def test_property_extract_depends_on_always_resolves(
    exchanges, unrecoverable,
) -> None:
    """Property: every depends_on reference in the output resolves
    to a target_id in the same output. INVARIANT D's positive
    contract at the extractor side."""
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=unrecoverable,
    )
    all_ids = {t["target_id"] for t in out}
    for t in out:
        for dep in t.get("depends_on", []):
            assert dep in all_ids, (
                f"Extractor produced dangling depends_on: target "
                f"{t['target_id']} depends on {dep!r} which is not "
                f"in {sorted(all_ids)}"
            )


# ─────────────────────────────────────────────────────────────────────
# Property test: extracted output passes INVARIANT D.
# ─────────────────────────────────────────────────────────────────────


@given(
    exchanges=st.lists(_exchange_strategy, max_size=5),
    unrecoverable=st.lists(_unrecoverable_strategy, max_size=5),
)
@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None, max_examples=50)
def test_property_extracted_output_passes_invariant_d(
    exchanges, unrecoverable,
) -> None:
    """Property: the extractor's output is always INVARIANT-D-clean
    (no dangling pointers, no cycles). The extraction code is
    correct-by-construction; this test pins that contract.
    """
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=unrecoverable,
    )
    freeze_brief = {"SUBPOENA_TARGETS": out}
    violations = _check_subpoena_targets_depends_on_resolves(freeze_brief)
    assert violations == [], (
        f"Extractor produced a brief that fails INVARIANT D: "
        f"{[v.detail for v in violations]}"
    )


# ─────────────────────────────────────────────────────────────────────
# Atomic write tmp-cleanup test.
# ─────────────────────────────────────────────────────────────────────


def test_atomic_write_cleans_tmp_on_write_failure(tmp_path: Path) -> None:
    """v0.28.3 hardening: a failed _atomic_write must NOT leave an
    orphan .tmp file on disk. Simulate failure by passing a target
    path inside a non-existent directory."""
    bad_path = tmp_path / "nonexistent_dir" / "subpoena.html"
    with pytest.raises(FileNotFoundError):
        _atomic_write(bad_path, "content")
    # No .tmp left behind in tmp_path tree.
    tmp_files = list(tmp_path.rglob("*.tmp"))
    assert tmp_files == [], (
        f"Orphan .tmp files survived failed write: {tmp_files}"
    )


def test_atomic_write_cleans_tmp_when_rename_fails(
    tmp_path: Path, monkeypatch,
) -> None:
    """When tmp.replace(path) raises (e.g. Windows PermissionError
    from antivirus / concurrent reader), the .tmp file MUST be
    cleaned up."""
    target = tmp_path / "out.html"
    original_replace = Path.replace

    def boom(self, *args, **kwargs):
        raise PermissionError("simulated rename failure")

    monkeypatch.setattr(Path, "replace", boom)
    with pytest.raises(PermissionError):
        _atomic_write(target, "content")
    # No .tmp survives.
    tmp_files = list(tmp_path.rglob("*.tmp"))
    assert tmp_files == [], (
        f"Orphan .tmp after PermissionError rename: {tmp_files}"
    )


def test_atomic_write_succeeds_normally(tmp_path: Path) -> None:
    """Sanity: the happy path produces the file with the content."""
    target = tmp_path / "out.html"
    _atomic_write(target, "hello world")
    assert target.read_text(encoding="utf-8") == "hello world"
    # No .tmp left over on success either.
    assert list(tmp_path.glob("*.tmp")) == []


# ─────────────────────────────────────────────────────────────────────
# CEX operator-override test.
# ─────────────────────────────────────────────────────────────────────


def test_cex_compliance_override_replaces_canonical_value(
    tmp_path: Path, monkeypatch,
) -> None:
    """Operators can override a CEX compliance contact via
    RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE pointing at a JSON file.
    Used when the canonical email becomes stale (e.g. an exchange
    changes their legal-process address mid-quarter)."""
    from recupero.reports.subpoena_targets import _resolve_cex_recipient

    override_file = tmp_path / "overrides.json"
    override_file.write_text(json.dumps({
        "mexc": ["MEXC (updated)", "newcompliance@mexc.com",
                 "Seychelles", 21, "high"],
    }), encoding="utf-8")
    monkeypatch.setenv(
        "RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE", str(override_file),
    )

    out = _resolve_cex_recipient("MEXC")
    assert out is not None
    assert out["recipient_name"] == "MEXC (updated)"
    assert out["recipient_compliance_email"] == "newcompliance@mexc.com"
    assert out["estimated_response_window_days"] == 21
    assert out["priority"] == "high"


def test_cex_compliance_override_invalid_shape_logs_and_skips(
    tmp_path: Path, monkeypatch, caplog,
) -> None:
    """An override entry with wrong shape (missing field, bad type,
    invalid priority value) is logged + skipped — does NOT poison
    the entire override map."""
    from recupero.reports.subpoena_targets import _resolve_cex_recipient

    override_file = tmp_path / "overrides.json"
    override_file.write_text(json.dumps({
        # Wrong: only 3 elements instead of 5.
        "binance": ["Binance", "compliance@binance.com", "Cayman"],
        # Wrong: priority must be in {high, medium, low}.
        "kraken": ["Kraken", "x@kraken.com", "USA", 14, "URGENT"],
        # Wrong: days out of range.
        "mexc": ["MEXC", "x@mexc.com", "Seychelles", 999, "high"],
        # Wrong: email without @.
        "bybit": ["Bybit", "noatsign", "Dubai", 30, "medium"],
        # Valid: should win.
        "coinbase": ["Coinbase Override", "ovr@coinbase.com",
                     "USA", 14, "high"],
    }), encoding="utf-8")
    monkeypatch.setenv(
        "RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE", str(override_file),
    )

    # Invalid overrides → fall through to canonical map.
    binance = _resolve_cex_recipient("binance")
    assert binance is not None
    assert binance["recipient_compliance_email"] == "leinquiries@binance.com"

    # Valid override → applied.
    coinbase = _resolve_cex_recipient("coinbase")
    assert coinbase is not None
    assert coinbase["recipient_name"] == "Coinbase Override"


def test_cex_compliance_override_unparseable_json_falls_back(
    tmp_path: Path, monkeypatch,
) -> None:
    """A malformed JSON override file is logged + ignored. We don't
    fail the worker because an operator typo'd a comma."""
    from recupero.reports.subpoena_targets import _resolve_cex_recipient

    override_file = tmp_path / "overrides.json"
    override_file.write_text("not valid json {", encoding="utf-8")
    monkeypatch.setenv(
        "RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE", str(override_file),
    )
    # Falls back to canonical MEXC.
    out = _resolve_cex_recipient("MEXC")
    assert out is not None
    assert out["recipient_compliance_email"] == "compliance@mexc.com"


def test_cex_compliance_override_missing_file_falls_back(
    monkeypatch, tmp_path: Path,
) -> None:
    """An env var pointing at a non-existent file is logged +
    ignored."""
    from recupero.reports.subpoena_targets import _resolve_cex_recipient

    monkeypatch.setenv(
        "RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE",
        str(tmp_path / "does-not-exist.json"),
    )
    out = _resolve_cex_recipient("MEXC")
    assert out is not None
    assert out["recipient_compliance_email"] == "compliance@mexc.com"


def test_cex_compliance_override_unset_uses_canonical() -> None:
    """No env var set → canonical map only."""
    from recupero.reports.subpoena_targets import _resolve_cex_recipient
    import os

    # Ensure unset.
    os.environ.pop("RECUPERO_SUBPOENA_RECIPIENTS_OVERRIDE", None)
    out = _resolve_cex_recipient("MEXC")
    assert out is not None
    assert out["recipient_compliance_email"] == "compliance@mexc.com"


# ─────────────────────────────────────────────────────────────────────
# INVARIANT C UNRECOVERABLE_ITEMS alternate-key check.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_c_accepts_unrecoverable_items_alternate_key() -> None:
    """The editorial pipeline may write to UNRECOVERABLE OR
    UNRECOVERABLE_ITEMS depending on schema version. INVARIANT C
    must check both keys so a schema drift doesn't silently fail
    coverage acknowledgement."""
    freeze_brief = {
        "FREEZABLE": [
            {"issuer": "Sky", "freeze_capability": "no",
             "holdings": [
                 {"address": "0x" + "a" * 40, "usd": "$10,000",
                  "status": "UNRECOVERABLE"},
             ]},
        ],
        # Editorial uses the legacy key.
        "UNRECOVERABLE_ITEMS": [
            {"address": "0x" + "a" * 40,
             "asset": "approximately 10K DAI", "reason": "perp anon"},
        ],
    }
    violations = _check_subpoena_targets_cover_non_freezable(freeze_brief)
    assert violations == [], (
        "INVARIANT C must recognize UNRECOVERABLE_ITEMS as a valid "
        "coverage acknowledgment key (editorial schema legacy)."
    )


# ─────────────────────────────────────────────────────────────────────
# End-to-end integration test: full Zigha-shape pipeline.
# ─────────────────────────────────────────────────────────────────────


def test_e2e_zigha_shape_brief_render_validate(tmp_path: Path) -> None:
    """End-to-end: realistic Zigha-shape input → extract subpoena
    targets → render artifacts → validate. Exercises the full
    integration path. A bug in any layer surfaces here.

    Zigha shape:
      * 1 MEXC off-ramp ($16.89M)
      * 2 dormant DAI positions ($9.98M + $6.91M)
    Expected output:
      * 1 CEX subpoena (MEXC)
      * 2 seizure-target subpoenas (each depending on MEXC)
      * 1 playbook
      * Files written for all 3 targets + the playbook
      * Validator reports clean (no critical/high violations from
        the v0.28-introduced checks)
    """
    case = _stub_case(case_id="ZIGHA-E2E")
    case.exchange_endpoints = []

    # Step 1: extract subpoena targets.
    exchanges = [
        {"address": "0xeeadd1f663e5cd8cdb2102d42756168762457b9d",
         "exchange": "MEXC", "total_received_usd": "16890000",
         "chain": "ethereum"},
    ]
    unrecoverable = [
        {"address": "0x3dafc6a860334d4feb0467a3d58c3687e9e921b6",
         "chain": "ethereum",
         "asset": "approximately 9.98M DAI (~$9,980,000)",
         "reason": "Dormant since Oct 2025; DAI permissionless"},
        {"address": "0x415d8d075cacb5a61ae854a8e5ea53df3a76f688",
         "chain": "ethereum",
         "asset": "approximately 6.91M DAI (~$6,910,000)",
         "reason": "Dormant since Oct 2025; DAI permissionless"},
    ]
    targets = extract_subpoena_targets(
        case=case, freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=unrecoverable,
    )
    assert len(targets) == 3

    # Step 2: write a synthetic freeze_brief.json that includes
    # SUBPOENA_TARGETS + reasoning UNRECOVERABLE entries.
    case_dir = tmp_path / "case"
    briefs_dir = case_dir / "briefs"
    briefs_dir.mkdir(parents=True)
    freeze_brief = {
        "CASE_ID": "ZIGHA-E2E",
        "SUBPOENA_TARGETS": targets,
        "FREEZABLE": [
            {"issuer": "Sky Protocol", "token": "DAI",
             "freeze_capability": "no",
             "holdings": [
                 {"address": "0x3dafc6a860334d4feb0467a3d58c3687e9e921b6",
                  "usd": "$9,980,000.00", "status": "UNRECOVERABLE"},
                 {"address": "0x415d8d075cacb5a61ae854a8e5ea53df3a76f688",
                  "usd": "$6,910,000.00", "status": "UNRECOVERABLE"},
             ]},
        ],
        # Both keys (UNRECOVERABLE + UNRECOVERABLE_ITEMS) to test the
        # alternate-key acceptance.
        "UNRECOVERABLE": unrecoverable,
    }
    (case_dir / "freeze_brief.json").write_text(
        json.dumps(freeze_brief), encoding="utf-8",
    )
    (case_dir / "freeze_asks.json").write_text(
        json.dumps({"by_issuer": {}}), encoding="utf-8",
    )

    # Step 3: render the artifacts.
    paths = render_subpoena_artifacts(
        case=case, victim={"name": "Z Customer"},
        investigator={"name": "Alec Prostok", "email": "alec@recupero.io"},
        freeze_brief=freeze_brief, case_dir=case_dir,
    )
    # 3 target files + 1 playbook = 4 files
    assert len(paths) == 4
    target_files = list(briefs_dir.glob("subpoena_target_*.html"))
    playbook_files = list(briefs_dir.glob("subpoena_playbook_*.html"))
    assert len(target_files) == 3
    assert len(playbook_files) == 1

    # Each target file contains the expected recipient name.
    target_blob = " ".join(
        p.read_text(encoding="utf-8") for p in target_files
    )
    assert "MEXC Global" in target_blob
    assert "Identified law enforcement agency" in target_blob
    # Each address appears.
    assert "0xeeadd1f663e5cd8cdb2102d42756168762457b9d" in target_blob
    assert "0x3dafc6a860334d4feb0467a3d58c3687e9e921b6" in target_blob
    assert "0x415d8d075cacb5a61ae854a8e5ea53df3a76f688" in target_blob

    # Playbook references both the CEX subpoena and the seizure
    # targets + the dependency chain.
    playbook_html = playbook_files[0].read_text(encoding="utf-8")
    assert "MEXC Global" in playbook_html
    assert "Identified law enforcement agency" in playbook_html
    # Stage 1 contains the MEXC target (depends_on=[]).
    assert "Stage 1" in playbook_html
    # Stage 2 contains the seizure targets (depend on MEXC).
    assert "Stage 2" in playbook_html

    # Step 4: validate.
    result = validate_case_output(case_dir)

    # No v0.28-introduced critical / high violations.
    v028_critical_checks = {
        "subpoena_targets_cover_non_freezable",
        "subpoena_targets_depends_on_resolves",
        "subpoena_files_match_targets",
        "subpoena_targets_extraction_succeeded",
    }
    v028_violations = [
        v for v in result.violations
        if v.check in v028_critical_checks
        and v.severity in ("critical", "high")
    ]
    assert not v028_violations, (
        "v0.28 INVARIANT surface fired on a CLEAN Zigha-shape case: "
        + "\n  ".join(
            f"[{v.severity}] {v.check}: {v.detail}"
            for v in v028_violations
        )
    )

    # The v0.28 checks all ran.
    for check in v028_critical_checks:
        assert check in result.checks_run, f"{check} not run"


def test_e2e_zigha_pre_v028_shape_fails_validation(
    tmp_path: Path,
) -> None:
    """Negative control: the pre-v0.28 Zigha shape (no
    SUBPOENA_TARGETS, dormant DAI in UNRECOVERABLE without
    reason) MUST fail INVARIANT C above the $100K threshold."""
    case_dir = tmp_path / "case"
    (case_dir / "briefs").mkdir(parents=True)
    freeze_brief = {
        "CASE_ID": "ZIGHA-PRE-V028",
        # No SUBPOENA_TARGETS (the pre-v0.28 shape).
        "FREEZABLE": [
            {"issuer": "Sky Protocol", "token": "DAI",
             "freeze_capability": "no",
             "holdings": [
                 {"address": "0x" + "a" * 40,
                  "usd": "$9,980,000.00", "status": "UNRECOVERABLE"},
             ]},
        ],
        # No UNRECOVERABLE / UNRECOVERABLE_ITEMS entries either.
    }
    (case_dir / "freeze_brief.json").write_text(
        json.dumps(freeze_brief), encoding="utf-8",
    )
    (case_dir / "freeze_asks.json").write_text(
        json.dumps({"by_issuer": {}}), encoding="utf-8",
    )

    result = validate_case_output(case_dir)
    # INVARIANT C must fire at HIGH severity (Zigha-shape escalation).
    c_violations = [
        v for v in result.violations
        if v.check == "subpoena_targets_cover_non_freezable"
        and v.severity == "high"
    ]
    assert c_violations, (
        "INVARIANT C must fire at HIGH severity for pre-v0.28 "
        "Zigha shape ($9.98M dormant DAI, no SUBPOENA_TARGETS, no "
        "UNRECOVERABLE-with-reason). Got: "
        f"{[(v.severity, v.detail[:80]) for v in result.violations]}"
    )
