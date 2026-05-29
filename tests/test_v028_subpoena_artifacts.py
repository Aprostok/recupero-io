"""v0.28.0 subpoena artifact family — regression tests.

Pins the identified-but-non-freezable artifact family from Jacob's
v0.27.1 review item 3. See docs/v0.28_subpoena_targets_design.md.

The shape:
  * `_extract_subpoena_targets` walks the case's exchange endpoints +
    UNRECOVERABLE items, emits structured records keyed on recipient
    (CEX, ISP, law enforcement, etc.) with depends_on DAG edges.
  * `render_subpoena_artifacts` materializes per-recipient
    subpoena_target_*.html + a per-case subpoena_playbook_*.html.
  * INVARIANTS C/D/E in validators/output_integrity.py keep the
    artifact family in sync with the brief data:
      - C: every freeze_capability="no" destination above $1K USD
        is covered (subpoena target OR UNRECOVERABLE w/ reason).
      - D: depends_on references resolve inside the same case.
      - E: file count matches |SUBPOENA_TARGETS| + 1 playbook.

These tests cover:
  * data-layer extraction shapes (CEX, dormant DAI, no-targets
    happy paths)
  * recipient lookup fall-through behavior (known + unknown CEXes)
  * dependency-graph correctness (CEX → seizure-target chain)
  * template rendering (per-target HTML + playbook HTML)
  * filename safety
  * the three validator invariants positive + negative
"""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from unittest.mock import MagicMock

from recupero.reports.subpoena_targets import (
    _KNOWN_CEX_COMPLIANCE,
    SUBPOENA_USD_THRESHOLD,
    _resolve_cex_recipient,
    extract_subpoena_targets,
)
from recupero.validators.output_integrity import (
    _check_subpoena_files_match_targets,
    _check_subpoena_targets_cover_non_freezable,
    _check_subpoena_targets_depends_on_resolves,
    validate_case_output,
)


def _stub_case(case_id: str = "TEST-CASE", chain: str = "ethereum") -> MagicMock:
    """Build a minimal Case-like stub for extraction tests."""
    c = MagicMock()
    c.case_id = case_id
    chain_obj = MagicMock()
    chain_obj.value = chain
    c.chain = chain_obj
    c.exchange_endpoints = []
    return c


# ─────────────────────────────────────────────────────────────────────
# extract_subpoena_targets — data layer.
# ─────────────────────────────────────────────────────────────────────


def test_extract_emits_nothing_for_empty_case() -> None:
    """A case with no exchanges + no unrecoverable items has no
    qualifying subpoena targets. Output is empty list (not None)."""
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=[], unrecoverable=[],
    )
    assert out == []


def test_extract_emits_one_cex_subpoena_for_mexc_off_ramp() -> None:
    """Zigha-shape: a MEXC off-ramp deposit at $1.2M produces one
    CEX subpoena target. Recipient details come from the known-CEX
    compliance map."""
    exchanges = [
        {"address": "0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d",
         "exchange": "MEXC", "total_received_usd": "1234567",
         "chain": "ethereum"},
    ]
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=[],
    )
    assert len(out) == 1
    t = out[0]
    assert t["recipient_type"] == "cex"
    assert "MEXC" in t["recipient_name"]
    assert t["evidentiary_basis"] == "off_ramp_deposit"
    assert t["instrument"] == "grand_jury_subpoena"
    # Linked address surfaces in the entry.
    assert len(t["linked_addresses"]) == 1
    assert (
        t["linked_addresses"][0]["address"]
        == "0xeEaDd1F663E5Cd8cdB2102d42756168762457b9d"
    )
    # Compliance email from the known map.
    assert t["recipient_compliance_email"] == "compliance@mexc.com"


def test_extract_consolidates_same_exchange_multiple_addresses() -> None:
    """When the perpetrator off-ramped to multiple deposit addresses
    at the same exchange, emit ONE subpoena (recipient is the same)
    listing all addresses. Avoids spamming MEXC with N letters when
    one letter could ask for all the data."""
    exchanges = [
        {"address": "0x" + "a" * 40, "exchange": "MEXC",
         "total_received_usd": "500000"},
        {"address": "0x" + "b" * 40, "exchange": "MEXC",
         "total_received_usd": "300000"},
        {"address": "0x" + "c" * 40, "exchange": "MEXC",
         "total_received_usd": "200000"},
    ]
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=[],
    )
    cex_targets = [t for t in out if t["recipient_type"] == "cex"]
    assert len(cex_targets) == 1, (
        f"expected 1 consolidated MEXC subpoena; got {len(cex_targets)}"
    )
    assert len(cex_targets[0]["linked_addresses"]) == 3


def test_extract_skips_below_threshold() -> None:
    """A deposit under $1,000 USD is below the subpoena threshold
    (legal-process overhead exceeds expected recovery value)."""
    exchanges = [
        {"address": "0x" + "a" * 40, "exchange": "MEXC",
         "total_received_usd": "500"},  # below threshold
    ]
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=[],
    )
    assert out == []


def test_extract_threshold_boundary_includes_at_exact() -> None:
    """A deposit at exactly $1,000.00 is at the threshold and is
    included."""
    exchanges = [
        {"address": "0x" + "a" * 40, "exchange": "MEXC",
         "total_received_usd": "1000.00"},
    ]
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=[],
    )
    assert len(out) == 1


def test_extract_unknown_cex_uses_placeholder_recipient() -> None:
    """An exchange not in _KNOWN_CEX_COMPLIANCE still emits a
    subpoena target with placeholder fields the operator must
    research. Better than silent drop."""
    exchanges = [
        {"address": "0x" + "a" * 40,
         "exchange": "SomeObscureCEX",
         "total_received_usd": "50000"},
    ]
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=[],
    )
    assert len(out) == 1
    t = out[0]
    assert "SomeObscureCEX" in t["recipient_name"] or t["recipient_name"]
    assert t["recipient_compliance_email"] is None
    assert "unknown" in (t["recipient_jurisdiction"] or "").lower()


def test_extract_emits_seizure_target_for_dormant_dai() -> None:
    """Zigha-shape: UNRECOVERABLE_ITEMS with $9.98M dormant DAI
    produces a law_enforcement seizure-target entry."""
    unrec = [
        {"address": "0x3dafc6a860334d4feb0467a3d58c3687e9e921b6",
         "chain": "ethereum",
         "asset": "approximately 9.98M DAI (~$9,980,000)",
         "reason": "Dormant since Oct 2025; DAI permissionless"},
    ]
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=[], unrecoverable=unrec,
    )
    assert len(out) == 1
    t = out[0]
    assert t["recipient_type"] == "law_enforcement"
    assert t["instrument"] == "seizure_order"
    assert t["priority"] == "high"  # $9.98M ≥ $100K


def test_extract_seizure_target_depends_on_cex_subpoenas() -> None:
    """When both a CEX subpoena AND a dormant-DAI seizure target
    exist, the seizure target depends_on the CEX subpoena
    (identity must be established before seizure can be filed).
    This is the DAG core of the playbook."""
    exchanges = [
        {"address": "0x" + "a" * 40, "exchange": "MEXC",
         "total_received_usd": "100000"},
    ]
    unrec = [
        {"address": "0x" + "b" * 40, "chain": "ethereum",
         "asset": "approximately 5M DAI (~$5,000,000)",
         "reason": "Dormant"},
    ]
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=unrec,
    )
    cex = next(t for t in out if t["recipient_type"] == "cex")
    seizure = next(t for t in out if t["recipient_type"] == "law_enforcement")
    assert cex["target_id"] in seizure["depends_on"], (
        f"seizure-target {seizure['target_id']} should depend on CEX "
        f"target {cex['target_id']}; depends_on={seizure['depends_on']}"
    )
    # CEX target has no dependencies (file first).
    assert cex["depends_on"] == []


def test_extract_stable_target_id_renumbering() -> None:
    """target_ids are renumbered to a stable subpoena-1..N sequence
    after sort. The depends_on field follows the renumbering — no
    dangling references."""
    exchanges = [
        {"address": "0x" + "a" * 40, "exchange": "MEXC",
         "total_received_usd": "50000"},
    ]
    unrec = [
        {"address": "0x" + "b" * 40,
         "asset": "10M DAI (~$10,000,000)", "reason": "Dormant"},
        {"address": "0x" + "c" * 40,
         "asset": "5M DAI (~$5,000,000)", "reason": "Dormant"},
    ]
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=unrec,
    )
    target_ids = [t["target_id"] for t in out]
    # IDs are subpoena-1, subpoena-2, ...
    assert target_ids == ["subpoena-1", "subpoena-2", "subpoena-3"]
    # depends_on references resolve inside the list.
    for t in out:
        for d in t.get("depends_on", []):
            assert d in target_ids, (
                f"target {t['target_id']} depends_on {d!r} which is "
                f"not in the target_id set {target_ids}"
            )


def test_extract_sorts_by_descending_usd() -> None:
    """Higher-USD targets sort first so the playbook surfaces the
    most consequential subpoenas at the top."""
    exchanges = [
        {"address": "0x" + "a" * 40, "exchange": "Bitstamp",
         "total_received_usd": "10000"},  # smaller
        {"address": "0x" + "b" * 40, "exchange": "Binance",
         "total_received_usd": "500000"},  # larger
    ]
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=[],
    )
    # First target is the bigger one.
    assert "Binance" in out[0]["recipient_name"]


def test_extract_recipient_slug_is_filename_safe() -> None:
    """The recipient_slug field used by the renderer for filenames
    is alphanumeric + dashes only."""
    exchanges = [
        {"address": "0x" + "a" * 40, "exchange": "MEXC",
         "total_received_usd": "50000"},
    ]
    out = extract_subpoena_targets(
        case=_stub_case(), freeze_asks={}, editorial=None,
        exchanges=exchanges, unrecoverable=[],
    )
    for t in out:
        slug = t.get("recipient_slug", "")
        assert slug, "recipient_slug must be populated"
        # Alphanumeric + dashes only.
        assert all(c.isalnum() or c == "-" for c in slug), (
            f"recipient_slug {slug!r} contains non-filename-safe chars"
        )


# ─────────────────────────────────────────────────────────────────────
# _resolve_cex_recipient lookups.
# ─────────────────────────────────────────────────────────────────────


def test_resolve_cex_exact_match() -> None:
    info = _resolve_cex_recipient("MEXC")
    assert info is not None
    assert "MEXC" in info["recipient_name"]


def test_resolve_cex_case_insensitive() -> None:
    info_upper = _resolve_cex_recipient("BINANCE")
    info_lower = _resolve_cex_recipient("binance")
    assert info_upper == info_lower


def test_resolve_cex_substring_match() -> None:
    """A label like 'Binance Hot Wallet 14' matches 'binance' via
    substring fallback."""
    info = _resolve_cex_recipient("Binance Hot Wallet 14")
    assert info is not None
    assert "Binance" in info["recipient_name"]


def test_resolve_cex_unknown_returns_none() -> None:
    assert _resolve_cex_recipient("SomeUnknownExchange") is None


def test_resolve_cex_handles_empty_and_none() -> None:
    assert _resolve_cex_recipient("") is None
    assert _resolve_cex_recipient(None) is None


def test_known_cex_compliance_map_has_priority_jurisdiction_email() -> None:
    """Every entry in the compliance map must have all five fields
    populated (no None compliance email for known CEXes)."""
    for exchange_key, (name, email, jurisdiction, days, priority) in (
        _KNOWN_CEX_COMPLIANCE.items()
    ):
        assert name, f"empty name for {exchange_key}"
        assert email and "@" in email, f"invalid email for {exchange_key}: {email!r}"
        assert jurisdiction, f"empty jurisdiction for {exchange_key}"
        assert 7 <= days <= 90, f"unreasonable days for {exchange_key}: {days}"
        assert priority in ("high", "medium", "low"), (
            f"invalid priority for {exchange_key}: {priority!r}"
        )


# ─────────────────────────────────────────────────────────────────────
# Renderer (template + filename).
# ─────────────────────────────────────────────────────────────────────


def test_renderer_writes_per_target_files_and_playbook(tmp_path: Path) -> None:
    """End-to-end: render_subpoena_artifacts writes one
    subpoena_target_*.html per entry + one subpoena_playbook_*.html
    per case. Verified by inspecting the disk after rendering."""
    from recupero.reports.subpoena_renderer import render_subpoena_artifacts

    case = _stub_case(case_id="RENDER-TEST")
    freeze_brief = {
        "SUBPOENA_TARGETS": [
            {
                "target_id": "subpoena-1",
                "recipient_type": "cex",
                "recipient_name": "MEXC Global",
                "recipient_slug": "mexc-global",
                "recipient_compliance_email": "compliance@mexc.com",
                "recipient_jurisdiction": "Seychelles",
                "evidentiary_basis": "off_ramp_deposit",
                "linked_addresses": [
                    {"address": "0x" + "a" * 40, "chain": "ethereum",
                     "role": "off-ramp", "evidence": [{"amount_usd": "50000"}]},
                ],
                "expected_records": ["KYC", "IP log"],
                "follow_up_pivots": [],
                "instrument": "grand_jury_subpoena",
                "estimated_response_window_days": 30,
                "priority": "high",
                "case_role": "off_ramp",
                "depends_on": [],
            },
        ],
    }
    paths = render_subpoena_artifacts(
        case=case, victim=None, investigator=None,
        freeze_brief=freeze_brief, case_dir=tmp_path,
    )
    # Two files: 1 target + 1 playbook.
    assert len(paths) == 2
    target_files = list((tmp_path / "briefs").glob("subpoena_target_*.html"))
    playbook_files = list((tmp_path / "briefs").glob("subpoena_playbook_*.html"))
    assert len(target_files) == 1
    assert len(playbook_files) == 1
    # The target HTML carries the recipient name + the linked address.
    target_html = target_files[0].read_text(encoding="utf-8")
    assert "MEXC Global" in target_html
    assert "0x" + "a" * 40 in target_html
    assert "FREEZABLE" not in target_html  # not a freeze letter
    assert "compliance@mexc.com" in target_html


def test_renderer_empty_targets_writes_nothing(tmp_path: Path) -> None:
    """When SUBPOENA_TARGETS is empty the renderer skips both
    per-target files AND the playbook. An empty playbook would
    confuse operators."""
    from recupero.reports.subpoena_renderer import render_subpoena_artifacts

    paths = render_subpoena_artifacts(
        case=_stub_case(case_id="EMPTY-CASE"), victim=None, investigator=None,
        freeze_brief={"SUBPOENA_TARGETS": []},
        case_dir=tmp_path,
    )
    assert paths == []
    # No files written.
    briefs_dir = tmp_path / "briefs"
    if briefs_dir.is_dir():
        assert list(briefs_dir.glob("subpoena_*.html")) == []


def test_renderer_playbook_lists_all_targets(tmp_path: Path) -> None:
    """Playbook HTML must reference every target's target_id +
    recipient_name."""
    from recupero.reports.subpoena_renderer import render_subpoena_artifacts

    freeze_brief = {
        "SUBPOENA_TARGETS": [
            {"target_id": "subpoena-1", "recipient_type": "cex",
             "recipient_name": "MEXC Global", "recipient_slug": "mexc-global",
             "recipient_compliance_email": "compliance@mexc.com",
             "linked_addresses": [{"address": "0x" + "a" * 40,
                                   "chain": "ethereum", "role": "x", "evidence": []}],
             "expected_records": [], "instrument": "grand_jury_subpoena",
             "depends_on": [], "priority": "high"},
            {"target_id": "subpoena-2", "recipient_type": "cex",
             "recipient_name": "Bybit", "recipient_slug": "bybit",
             "recipient_compliance_email": "compliance@bybit.com",
             "linked_addresses": [{"address": "0x" + "b" * 40,
                                   "chain": "ethereum", "role": "x", "evidence": []}],
             "expected_records": [], "instrument": "grand_jury_subpoena",
             "depends_on": ["subpoena-1"], "priority": "medium"},
        ],
    }
    paths = render_subpoena_artifacts(
        case=_stub_case(case_id="MULTI-TEST"), victim=None, investigator=None,
        freeze_brief=freeze_brief, case_dir=tmp_path,
    )
    playbook = next(p for p in paths if "playbook" in p.name)
    html = playbook.read_text(encoding="utf-8")
    assert "subpoena-1" in html
    assert "subpoena-2" in html
    assert "MEXC Global" in html
    assert "Bybit" in html
    # Dependency note for subpoena-2.
    assert "subpoena-1" in html  # in the depends_on column


# ─────────────────────────────────────────────────────────────────────
# INVARIANT C: cover_non_freezable.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_c_passes_when_non_freezable_has_subpoena() -> None:
    """A freeze_capability='no' destination above $1K covered by a
    SUBPOENA_TARGETS entry produces zero violations."""
    freeze_brief = {
        "FREEZABLE": [
            {"issuer": "Sky", "freeze_capability": "no",
             "holdings": [
                 {"address": "0x" + "a" * 40, "usd": "$10,000",
                  "status": "UNRECOVERABLE"},
             ]},
        ],
        "SUBPOENA_TARGETS": [
            {"target_id": "subpoena-1",
             "linked_addresses": [{"address": "0x" + "a" * 40}]},
        ],
    }
    violations = _check_subpoena_targets_cover_non_freezable(freeze_brief)
    assert violations == []


def test_invariant_c_passes_when_non_freezable_has_unrecoverable_with_reason() -> None:
    """An UNRECOVERABLE entry with a `reason` field counts as
    covered too — operator-curated rationale."""
    freeze_brief = {
        "FREEZABLE": [
            {"issuer": "Sky", "freeze_capability": "no",
             "holdings": [
                 {"address": "0x" + "a" * 40, "usd": "$10,000",
                  "status": "UNRECOVERABLE"},
             ]},
        ],
        "UNRECOVERABLE": [
            {"address": "0x" + "a" * 40,
             "asset": "approximately 10K DAI", "reason": "perpetrator anon"},
        ],
    }
    violations = _check_subpoena_targets_cover_non_freezable(freeze_brief)
    assert violations == []


def test_invariant_c_fires_warning_when_uncovered() -> None:
    """A freeze_capability='no' destination above $1K with neither
    SUBPOENA_TARGETS nor UNRECOVERABLE-with-reason produces a
    warning."""
    freeze_brief = {
        "FREEZABLE": [
            {"issuer": "Sky", "freeze_capability": "no",
             "holdings": [
                 {"address": "0x" + "a" * 40, "usd": "$50,000",
                  "status": "UNRECOVERABLE"},
             ]},
        ],
        # No SUBPOENA_TARGETS entry, no UNRECOVERABLE entry → gap
    }
    violations = _check_subpoena_targets_cover_non_freezable(freeze_brief)
    assert len(violations) == 1
    assert violations[0].severity == "warning"


def test_invariant_c_skips_below_threshold() -> None:
    """A non-freezable holding below $1K doesn't need to be covered."""
    freeze_brief = {
        "FREEZABLE": [
            {"issuer": "Sky", "freeze_capability": "no",
             "holdings": [
                 {"address": "0x" + "a" * 40, "usd": "$500",
                  "status": "UNRECOVERABLE"},
             ]},
        ],
    }
    assert _check_subpoena_targets_cover_non_freezable(freeze_brief) == []


# ─────────────────────────────────────────────────────────────────────
# INVARIANT D: depends_on_resolves.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_d_passes_when_depends_on_resolves() -> None:
    freeze_brief = {
        "SUBPOENA_TARGETS": [
            {"target_id": "subpoena-1", "depends_on": []},
            {"target_id": "subpoena-2", "depends_on": ["subpoena-1"]},
        ],
    }
    assert _check_subpoena_targets_depends_on_resolves(freeze_brief) == []


def test_invariant_d_fires_on_dangling_reference() -> None:
    freeze_brief = {
        "SUBPOENA_TARGETS": [
            {"target_id": "subpoena-1",
             "depends_on": ["subpoena-99"]},  # doesn't exist
        ],
    }
    violations = _check_subpoena_targets_depends_on_resolves(freeze_brief)
    assert len(violations) == 1
    assert violations[0].severity == "high"
    assert "subpoena-99" in violations[0].detail


def test_invariant_d_fires_on_non_list_depends_on() -> None:
    freeze_brief = {
        "SUBPOENA_TARGETS": [
            {"target_id": "subpoena-1", "depends_on": "subpoena-2"},  # str not list
        ],
    }
    violations = _check_subpoena_targets_depends_on_resolves(freeze_brief)
    assert len(violations) == 1


# ─────────────────────────────────────────────────────────────────────
# INVARIANT E: files_match_targets.
# ─────────────────────────────────────────────────────────────────────


def test_invariant_e_passes_with_matching_files(tmp_path: Path) -> None:
    """One subpoena_target_*.html per entry + one playbook = pass."""
    briefs_dir = tmp_path / "briefs"
    briefs_dir.mkdir()
    (briefs_dir / "subpoena_target_mexc_BRIEF-1.html").write_text("x")
    (briefs_dir / "subpoena_playbook_CASE-1.html").write_text("y")
    freeze_brief = {
        "SUBPOENA_TARGETS": [{"target_id": "subpoena-1"}],
    }
    assert _check_subpoena_files_match_targets(briefs_dir, freeze_brief) == []


def test_invariant_e_passes_when_no_targets(tmp_path: Path) -> None:
    """Empty SUBPOENA_TARGETS → no files expected → no violations."""
    briefs_dir = tmp_path / "briefs"
    briefs_dir.mkdir()
    assert _check_subpoena_files_match_targets(
        briefs_dir, {"SUBPOENA_TARGETS": []},
    ) == []


def test_invariant_e_fires_when_target_file_missing(tmp_path: Path) -> None:
    """Two targets in JSON but only 1 file → high violation."""
    briefs_dir = tmp_path / "briefs"
    briefs_dir.mkdir()
    (briefs_dir / "subpoena_target_mexc_BRIEF-1.html").write_text("x")
    (briefs_dir / "subpoena_playbook_CASE-1.html").write_text("y")
    freeze_brief = {
        "SUBPOENA_TARGETS": [
            {"target_id": "subpoena-1"},
            {"target_id": "subpoena-2"},
        ],
    }
    violations = _check_subpoena_files_match_targets(briefs_dir, freeze_brief)
    file_count_violations = [
        v for v in violations if "subpoena_target_" in v.detail and "files were written" in v.detail
    ]
    assert len(file_count_violations) == 1
    assert file_count_violations[0].severity == "high"


def test_invariant_e_fires_when_playbook_missing(tmp_path: Path) -> None:
    """Targets exist but no playbook → high violation (operators
    can't sequence the subpoenas)."""
    briefs_dir = tmp_path / "briefs"
    briefs_dir.mkdir()
    (briefs_dir / "subpoena_target_mexc_BRIEF-1.html").write_text("x")
    freeze_brief = {
        "SUBPOENA_TARGETS": [{"target_id": "subpoena-1"}],
    }
    violations = _check_subpoena_files_match_targets(briefs_dir, freeze_brief)
    playbook_violations = [
        v for v in violations if "playbook" in v.detail.lower()
    ]
    assert len(playbook_violations) == 1
    assert playbook_violations[0].severity == "high"


# ─────────────────────────────────────────────────────────────────────
# End-to-end via validate_case_output.
# ─────────────────────────────────────────────────────────────────────


def test_invariants_wired_into_validator(tmp_path: Path) -> None:
    """The three new INVARIANTS appear in checks_run when
    validate_case_output is invoked."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "freeze_asks.json").write_text(
        json.dumps({"by_issuer": {}}), encoding="utf-8",
    )
    (case_dir / "freeze_brief.json").write_text(
        json.dumps({"SUBPOENA_TARGETS": []}), encoding="utf-8",
    )
    (case_dir / "briefs").mkdir()
    result = validate_case_output(case_dir)
    assert "subpoena_targets_cover_non_freezable" in result.checks_run
    assert "subpoena_targets_depends_on_resolves" in result.checks_run
    assert "subpoena_files_match_targets" in result.checks_run


def test_subpoena_usd_threshold_constant() -> None:
    """The threshold is documented as $1,000 USD in the design doc.
    Locking the constant value as a regression guard."""
    assert Decimal("1000") == SUBPOENA_USD_THRESHOLD


# ─────────────────────────────────────────────────────────────────────
# v0.32.1 (#209 step 1): emit_brief resolves endpoint transfer_ids into
# subpoena tx-level evidence. Pre-fix the exchange dicts dropped
# transfer_ids, so every off-ramp subpoena target shipped with NO tx_hash
# for the exchange compliance team to grep against.
# ─────────────────────────────────────────────────────────────────────


def test_subpoena_exchange_dicts_resolves_tx_evidence() -> None:
    """Each ExchangeEndpoint's transfer_ids resolve to deduped tx_hashes
    (+ chain + deposit window + count) via case.transfers."""
    from datetime import UTC, datetime
    from types import SimpleNamespace

    from recupero.reports.emit_brief import _subpoena_exchange_dicts

    eth = SimpleNamespace(value="ethereum")
    transfers = [
        SimpleNamespace(transfer_id="ethereum:0xaaa:0", tx_hash="0xaaa", chain=eth),
        SimpleNamespace(transfer_id="ethereum:0xbbb:1", tx_hash="0xbbb", chain=eth),
        # Same tx, different log index → must dedupe to one hash.
        SimpleNamespace(transfer_id="ethereum:0xaaa:2", tx_hash="0xaaa", chain=eth),
    ]
    ep = SimpleNamespace(
        address="0xDEPOSIT",
        exchange="MEXC",
        transfer_ids=["ethereum:0xaaa:0", "ethereum:0xbbb:1", "ethereum:0xaaa:2"],
        total_received_usd=Decimal("1234567"),
        first_deposit_at=datetime(2026, 1, 1, tzinfo=UTC),
        last_deposit_at=datetime(2026, 1, 2, tzinfo=UTC),
    )
    case = SimpleNamespace(transfers=transfers, exchange_endpoints=[ep])

    out = _subpoena_exchange_dicts(case)
    assert len(out) == 1
    d = out[0]
    assert d["address"] == "0xDEPOSIT"
    assert d["exchange"] == "MEXC"
    assert d["tx_hashes"] == ["0xaaa", "0xbbb"], "deduped, order-preserved"
    assert d["chain"] == "ethereum"
    assert d["transfer_count"] == 3
    assert d["first_deposit_at"] == "2026-01-01T00:00:00+00:00"
    assert d["last_deposit_at"] == "2026-01-02T00:00:00+00:00"
    assert d["source"] == "label_db"


def test_subpoena_exchange_dicts_falls_back_to_parsing_transfer_id() -> None:
    """When a transfer is absent from case.transfers, parse the canonical
    'chain:tx_hash:logidx' id form so evidence is still emitted."""
    from types import SimpleNamespace

    from recupero.reports.emit_brief import _subpoena_exchange_dicts

    ep = SimpleNamespace(
        address="TDeposit", exchange="Binance",
        transfer_ids=["tron:abc123:0"],
        total_received_usd=Decimal("5000"),
        first_deposit_at=None, last_deposit_at=None,
    )
    case = SimpleNamespace(transfers=[], exchange_endpoints=[ep])
    out = _subpoena_exchange_dicts(case)
    assert out[0]["tx_hashes"] == ["abc123"]
    assert out[0]["chain"] == "tron"
    assert out[0]["first_deposit_at"] is None


def test_subpoena_exchange_dicts_empty_case_is_empty_list() -> None:
    from types import SimpleNamespace

    from recupero.reports.emit_brief import _subpoena_exchange_dicts

    case = SimpleNamespace(transfers=[], exchange_endpoints=[])
    assert _subpoena_exchange_dicts(case) == []
