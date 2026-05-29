"""Tests for recupero.validators.output_integrity (JACOB-3).

Each invariant gets:
  * A positive test (a well-formed case directory passes the check)
  * A negative test (a deliberately-broken case directory triggers
    the check with a critical/high severity)

End-to-end test runs the full V-CFI01 build through the validator
and asserts result.ok == True.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from recupero.validators.output_integrity import (
    ValidationResult,
    Violation,
    validate_case_output,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers: build small synthetic case directories
# ─────────────────────────────────────────────────────────────────────────────


def _write_lf(path: Path, content: str) -> None:
    """Write content with LF-only line endings — matches the
    production atomic_write_text behavior so manifest SHAs computed
    in tests match the on-disk SHAs on Windows + POSIX alike."""
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(content)


def _build_minimal_good_case(tmp_path: Path) -> Path:
    """Create a small, well-formed case directory that passes every
    invariant. Used as the baseline that negative tests then mutate.

    The case is intentionally complete enough that every PUNISH-C
    invariant has positive markers to find: title/h1 contains the
    issuer name, Section 4.2 ALL_ISSUER_HOLDINGS exists, victim name
    appears in the LE handoff + victim summary + engagement letter,
    CASE_ID is identical across artifacts, asset symbol agrees, and
    TOTAL_LOSS_USD/TOTAL_FREEZABLE_USD figures cross-reference."""
    case_dir = tmp_path / "case"
    briefs = case_dir / "briefs"
    briefs.mkdir(parents=True)

    # Drivers. NOTE: write LF-only so the manifest's SHA hashes
    # (computed against the in-memory string) match the on-disk bytes
    # on Windows. atomic_write_text() in production does the same.
    _write_lf(case_dir / "freeze_asks.json", json.dumps({
        "by_issuer": {
            "Tether": [{"freeze_capability": "yes", "token": "USDT"}],
        }
    }))
    freeze_brief = {
        "CASE_ID": "TEST",
        "TOTAL_FREEZABLE_USD": "$1,000.00",
        "MAX_RECOVERABLE_USD": "$1,000.00",
        "TOTAL_LOSS_USD": "$1,000.00",
        "victim": {"name": "Alice Victim"},
        "asset": {
            "symbol": "USDT",
            "issuer": "Tether",
        },
        "FREEZABLE": [
            {
                "issuer": "Tether",
                "token": "USDT",
                "freeze_capability": "yes",
                "holdings": [
                    {"address": "0xaaa", "freeze_capability": "yes",
                     "status": "FREEZABLE"},
                ],
            },
        ],
        "ALL_ISSUER_HOLDINGS": [
            {"issuer": "Tether", "token": "USDT",
             "amount_usd": "$1,000.00", "status": "FREEZABLE"},
        ],
    }
    _write_lf(case_dir / "freeze_brief.json", json.dumps(freeze_brief))

    # Issuer-named freeze_request + le_handoff — both reference the
    # Tether compliance email so the filename/content check passes.
    #
    # v0.27.2 (Jacob 0x52Aa bleed fix, INVARIANT
    # issuer_letter_backed_by_freezable_row): the freeze request MUST
    # contain at least one FREEZABLE-tagged row in a <tbody>. A letter
    # with no FREEZABLE row is a letter with no ask — pre-fix Zigha
    # shipped four such letters. The minimal fixture now embeds a
    # primary-targets table with a single FREEZABLE row so this
    # validator-level check trips only on actual regressions, not on
    # the synthetic test baseline.
    freeze_html = (
        "<!DOCTYPE html>\n<html>"
        "<head><title>Compliance Freeze Request to Tether — Case TEST</title></head>"
        "<body>"
        "<h1>Freeze Request — Tether</h1>"
        "<p>To: compliance@tether.to</p>"
        "<p>USDT freeze request. CASE_ID: TEST. Amount: $1,000.00.</p>"
        "<table class=\"evidence\"><thead><tr><th>Status</th><th>Address</th>"
        "<th>Amount</th></tr></thead><tbody>"
        "<tr><td><span class=\"label-pill\">FREEZABLE</span></td>"
        "<td><a href=\"https://etherscan.io/address/0xaaa\">0xaaa</a></td>"
        "<td>$1,000.00</td></tr>"
        "</tbody></table>"
        "</body></html>"
    )
    _write_lf(briefs / "freeze_request_tether_BRIEF-TEST-1.html", freeze_html)

    le_html = (
        "<!DOCTYPE html>\n<html>"
        "<head><title>LE Handoff — Tether — Case TEST</title></head>"
        "<body>"
        "<h1>LE Handoff — Tether</h1>"
        "<p>Victim: Alice Victim. CASE_ID: TEST.</p>"
        "<h2>1. Executive Summary</h2>"
        "<div><p>USDT theft. The token is issued by Tether. "
        "Total loss: $1,000.00.</p></div>"
        "<h2>2. Asset</h2><p>Tether USDT</p>"
        "<h2>4.1 Recoverable Positions</h2>"
        "<table class=\"evidence\"><thead><tr><th>Status</th><th>Address</th>"
        "<th>Amount</th></tr></thead><tbody>"
        "<tr><td><span class=\"label-pill\">FREEZABLE</span></td>"
        "<td><a href=\"https://etherscan.io/address/0xaaa\">0xaaa</a></td>"
        "<td>$1,000.00</td></tr>"
        "</tbody></table>"
        "<h2>4.2 ALL_ISSUER_HOLDINGS</h2>"
        "<table><tr><td>Tether</td><td>USDT</td><td>$1,000.00</td>"
        "<td>FREEZABLE</td></tr></table>"
        "</body></html>"
    )
    _write_lf(briefs / "le_handoff_tether_BRIEF-TEST-1.html", le_html)

    # Manifest with valid SHA references.
    freeze_sha = hashlib.sha256(freeze_html.encode()).hexdigest()
    le_sha = hashlib.sha256(le_html.encode()).hexdigest()
    _write_lf(briefs / "manifest_BRIEF-TEST-1.json", json.dumps({
        "case_id": "TEST",
        "outputs": {
            "issuer_freeze_request": "freeze_request_tether_BRIEF-TEST-1.html",
            "le_handoff": "le_handoff_tether_BRIEF-TEST-1.html",
        },
        "output_sha256": {
            "issuer_freeze_request": freeze_sha,
            "le_handoff": le_sha,
        },
    }))

    # Other deliverables.
    _write_lf(briefs / "trace_report_abc123.html",
        "<!DOCTYPE html>\n<html><body>"
        "<h1>Internal Trace Report — Case TEST</h1>"
        "<p>Victim: Alice Victim. Asset: USDT. "
        "Total drained: $1,000.00.</p>"
        "</body></html>"
    )
    _write_lf(briefs / "victim_summary_recoverable_def456.html",
        "<!DOCTYPE html>\n<html><body>"
        "<h1>Case Summary — Alice Victim</h1>"
        "<p>CASE_ID: TEST. $1,000.00 freezable.</p>"
        "</body></html>"
    )
    _write_lf(briefs / "engagement_letter_ghi789.html",
        "<!DOCTYPE html>\n<html><body>"
        "<h1>Engagement Letter — Alice Victim</h1>"
        "<p>Engagement fee: $1,000.00. CASE_ID: TEST.</p>"
        "</body></html>"
    )
    return case_dir


# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────


def test_validation_result_ok_when_no_critical_or_high():
    r = ValidationResult(violations=[
        Violation("x", "warning", "ignore"),
    ])
    assert r.ok is True
    assert r.critical_count == 0


def test_validation_result_not_ok_on_critical():
    r = ValidationResult(violations=[
        Violation("x", "critical", "bad"),
    ])
    assert r.ok is False


def test_validation_result_summary_text():
    r = ValidationResult(
        violations=[Violation("x", "critical", "boom", file="f.html")],
        checks_run=["x"],
    )
    text = r.summary_text()
    assert "FAIL" in text
    assert "CRITICAL" in text
    assert "f.html" in text


# ─────────────────────────────────────────────────────────────────────────────
# Smoke + happy-path
# ─────────────────────────────────────────────────────────────────────────────


def test_missing_case_dir_critical(tmp_path):
    result = validate_case_output(tmp_path / "nonexistent")
    assert not result.ok
    assert any(v.check == "case_dir_exists" for v in result.violations)


def test_minimal_good_case_passes(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    result = validate_case_output(case_dir)
    # The minimal case may produce warnings (e.g., DAI not mentioned
    # at all → no DAI check trips). It must NOT produce critical or
    # high severity violations.
    crits = [v for v in result.violations if v.severity == "critical"]
    highs = [v for v in result.violations if v.severity == "high"]
    assert not crits, f"critical violations: {crits}"
    assert not highs, f"high violations: {highs}"
    assert result.ok


# ─────────────────────────────────────────────────────────────────────────────
# Check 1: filename / content consistency
# ─────────────────────────────────────────────────────────────────────────────


def test_freeze_request_with_wrong_issuer_content_fails(tmp_path):
    """The v0.20.15 routing bug: freeze_request_tether_*.html should
    contain the Tether letter but instead contains Circle content."""
    case_dir = _build_minimal_good_case(tmp_path)
    # Overwrite the Tether freeze letter with Circle content.
    bad_path = case_dir / "briefs" / "freeze_request_tether_BRIEF-TEST-1.html"
    _write_lf(bad_path,
        "<!DOCTYPE html>\n<html><body>"
        "<h1>Freeze Request - Circle</h1>"
        "<p>To: compliance@circle.com</p>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert not result.ok
    assert any(
        v.check == "filename_content_consistency" and v.severity == "critical"
        for v in result.violations
    )


# ─────────────────────────────────────────────────────────────────────────────
# Check 2: HTML files contain HTML
# ─────────────────────────────────────────────────────────────────────────────


def test_html_file_containing_json_fails(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "engagement_letter_ghi789.html"
    bad.write_text('{"this_is_json": true}')
    result = validate_case_output(case_dir)
    assert any(
        v.check == "html_files_contain_html" and v.severity == "critical"
        for v in result.violations
    )


def test_html_file_containing_svg_fails(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "trace_report_abc123.html"
    bad.write_text('<?xml version="1.0"?><svg></svg>')
    result = validate_case_output(case_dir)
    assert any(
        v.check == "html_files_contain_html" and v.severity == "critical"
        for v in result.violations
    )


# ─────────────────────────────────────────────────────────────────────────────
# Check 3: JSON files parse as JSON
# ─────────────────────────────────────────────────────────────────────────────


def test_json_file_containing_html_fails(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "manifest_BRIEF-TEST-1.json"
    bad.write_text("<!DOCTYPE html><html>not json</html>")
    result = validate_case_output(case_dir)
    assert any(
        v.check == "json_files_parse_as_json" and v.severity == "critical"
        for v in result.violations
    )


# ─────────────────────────────────────────────────────────────────────────────
# Check 4: no duplicate file contents
# ─────────────────────────────────────────────────────────────────────────────


def test_duplicate_file_contents_flagged(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    a = case_dir / "briefs" / "trace_report_abc123.html"
    b = case_dir / "briefs" / "victim_summary_recoverable_def456.html"
    a.write_text("<!DOCTYPE html><html>same content</html>")
    b.write_text("<!DOCTYPE html><html>same content</html>")
    result = validate_case_output(case_dir)
    assert any(
        v.check == "no_duplicate_file_contents"
        for v in result.violations
    )


# ─────────────────────────────────────────────────────────────────────────────
# Check 5: manifest SHA matches disk
# ─────────────────────────────────────────────────────────────────────────────


def test_stale_manifest_sha_flagged(tmp_path):
    """If the freeze_request file gets rewritten after the manifest
    was sealed, the recorded SHA no longer matches — the exact
    forensic Jacob suggested to localize the routing bug.

    RIGOR-3 tightening: the violation MUST be on the freeze_request
    file specifically (the one we modified). Pre-tightening the test
    accepted ANY manifest_sha_matches_disk violation, which let a
    mutation that inverted the SHA comparator pass — the inverted
    comparator fired the violation on the LE handoff (whose SHA still
    matched) instead of on the freeze_request (whose SHA didn't),
    masking the bug. Now we pin the FILE the violation is on."""
    case_dir = _build_minimal_good_case(tmp_path)
    bad_path = case_dir / "briefs" / "freeze_request_tether_BRIEF-TEST-1.html"
    bad_path.write_text(
        "<!DOCTYPE html>\n<html><body>"
        "<h1>Tether</h1>"
        "<p>To: compliance@tether.to (replaced after manifest sealed)</p>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    # The violation must reference the file we modified, with critical
    # severity. A mutation that inverts `actual_sha != declared_sha`
    # to `==` would fire the violation on a DIFFERENT file (LE
    # handoff, whose SHA still matches). The bad-content file's name
    # appears in the violation's `detail` (the validator stores the
    # MANIFEST filename in `.file` and the wrong-content target in
    # the detail string).
    relevant = [
        v for v in result.violations
        if v.check == "manifest_sha_matches_disk"
        and v.severity == "critical"
        and bad_path.name in (v.detail or "")
    ]
    assert relevant, (
        f"expected a manifest_sha_matches_disk critical violation "
        f"referencing {bad_path.name!r}; got: "
        f"{[(v.check, v.severity, v.detail[:80]) for v in result.violations]}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Check 6: every freezable issuer has letters
# ─────────────────────────────────────────────────────────────────────────────


def test_missing_freeze_request_for_freezable_issuer_flagged(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    # Add a Circle issuer to FREEZABLE without producing the letter.
    fb_path = case_dir / "freeze_brief.json"
    fb = json.loads(fb_path.read_text())
    fb["FREEZABLE"].append({
        "issuer": "Circle",
        "token": "USDC",
        "freeze_capability": "yes",
        "holdings": [{
            "address": "0xbbb", "freeze_capability": "yes",
            "status": "FREEZABLE",
        }],
    })
    fb_path.write_text(json.dumps(fb))
    result = validate_case_output(case_dir)
    assert any(
        v.check == "every_freezable_issuer_has_letters"
        and v.severity == "critical"
        and "Circle" in v.detail
        for v in result.violations
    )


# ─────────────────────────────────────────────────────────────────────────────
# Check 8: stolen-asset issuer vs freeze-target issuer
# ─────────────────────────────────────────────────────────────────────────────


def test_stolen_asset_issuer_conflation_flagged(tmp_path):
    """Section 1 ¶1 of a Circle LE handoff claiming USDT is 'issued by
    Circle' triggers the v0.19.3-residual / JACOB-2 check."""
    case_dir = _build_minimal_good_case(tmp_path)
    # Add a Circle handoff with the conflation.
    bad = case_dir / "briefs" / "le_handoff_circle_BRIEF-TEST-1.html"
    bad.write_text(
        "<!DOCTYPE html>\n<html><body>"
        "<h2>1. Executive Summary</h2>"
        "<div><p>USDT was removed. The token is issued by Circle.</p></div>"
        "</body></html>"
    )
    # Also need to add Circle to FREEZABLE so the resolver finds it.
    fb_path = case_dir / "freeze_brief.json"
    fb = json.loads(fb_path.read_text())
    fb["FREEZABLE"].append({
        "issuer": "Circle", "token": "USDC", "freeze_capability": "yes",
        "holdings": [{"address": "0xb", "freeze_capability": "yes",
                      "status": "FREEZABLE"}],
    })
    fb_path.write_text(json.dumps(fb))
    # Add the corresponding Circle freeze_request so check 6 is happy.
    (case_dir / "briefs" / "freeze_request_circle_BRIEF-TEST-1.html").write_text(
        "<!DOCTYPE html><html><body><p>compliance@circle.com</p></body></html>"
    )
    result = validate_case_output(case_dir)
    assert any(
        v.check == "stolen_vs_target_issuer_distinct"
        and v.severity == "critical"
        for v in result.violations
    )


# ─────────────────────────────────────────────────────────────────────────────
# Check 9: recoverable variant matches MAX_RECOVERABLE_USD
# ─────────────────────────────────────────────────────────────────────────────


def test_unrecoverable_variant_with_positive_max_recoverable_flagged(tmp_path):
    """v0.15.1 bug: case with $3.5M freezable shipped UNRECOVERABLE
    summary + auto-refund."""
    case_dir = _build_minimal_good_case(tmp_path)
    # Replace the recoverable variant with unrecoverable.
    (case_dir / "briefs" / "victim_summary_recoverable_def456.html").unlink()
    (case_dir / "briefs" / "victim_summary_unrecoverable_def456.html").write_text(
        "<!DOCTYPE html><html><body>No funds recoverable</body></html>"
    )
    # Brief still says $1,000 recoverable.
    result = validate_case_output(case_dir)
    assert any(
        v.check == "recoverable_variant_matches_state"
        and v.severity == "critical"
        for v in result.violations
    )


# ─────────────────────────────────────────────────────────────────────────────
# Check 10: no unrendered Jinja placeholders
# ─────────────────────────────────────────────────────────────────────────────


def test_unrendered_jinja_var_flagged(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "trace_report_abc123.html"
    _write_lf(bad,
        "<!DOCTYPE html><html><body>"
        "<p>Hello {{ victim.name }} - your case</p>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert any(
        v.check == "no_unrendered_jinja_placeholders"
        and v.severity == "high"
        for v in result.violations
    )


def test_unrendered_jinja_block_flagged(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "trace_report_abc123.html"
    bad.write_text(
        "<!DOCTYPE html><html><body>"
        "{% if foo %}<p>x</p>{% endif %}"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert any(
        v.check == "no_unrendered_jinja_placeholders"
        for v in result.violations
    )


def test_unrendered_jinja_in_legal_requests_flagged(tmp_path):
    """v0.32.1 output-MED: subpoena / 314(b) / MLAT drafts land in
    cases/<id>/legal_requests/, which the validator previously did NOT
    scan. A template bug there could ship an unrendered {{ courthouse }}
    to an attorney. The check now scans that subdir too."""
    case_dir = _build_minimal_good_case(tmp_path)
    legal_dir = case_dir / "legal_requests"
    legal_dir.mkdir(parents=True, exist_ok=True)
    _write_lf(legal_dir / "subpoena_Binance.html",
        "<!DOCTYPE html><html><body>"
        "<p>Produce records for {{ perpetrator.exchange_address }}</p>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert any(
        v.check == "no_unrendered_jinja_placeholders"
        and v.severity == "high"
        and v.file == "subpoena_Binance.html"
        for v in result.violations
    ), "unrendered Jinja in legal_requests/ must be flagged"


def test_todo_attorney_fill_in_not_flagged_as_unrendered(tmp_path):
    """The intentional [TODO: ...] attorney fill-ins a subpoena draft
    carries (judicial district, courthouse, return date — blanks recupero
    genuinely cannot populate) render via |default("[TODO: ...]") and are
    NOT unrendered Jinja. The check must NOT flag them, or it would break
    the legitimate subpoena-draft workflow with a false positive."""
    case_dir = _build_minimal_good_case(tmp_path)
    legal_dir = case_dir / "legal_requests"
    legal_dir.mkdir(parents=True, exist_ok=True)
    _write_lf(legal_dir / "subpoena_Kraken.html",
        "<!DOCTYPE html><html><body>"
        "<p>Sitting at [TODO: courthouse address] on or before "
        "[TODO: 30-day return date].</p>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert not any(
        v.check == "no_unrendered_jinja_placeholders"
        and v.file == "subpoena_Kraken.html"
        for v in result.violations
    ), "intentional [TODO:] attorney fill-ins must not be flagged"


# ─────────────────────────────────────────────────────────────────────────────
# End-to-end: run V-CFI01 production path through the validator
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def v_cfi01_case_dir() -> Path:
    """Build the V-CFI01 case end-to-end via build_all_deliverables
    and return the case_dir path. Shared across the e2e tests."""
    from recupero.reports.brief import InvestigatorInfo
    from recupero.reports.emit_brief import emit_brief
    from recupero.reports.victim import VictimInfo
    from recupero.worker._deliverables import build_all_deliverables
    from tests.test_v_cfi01_production_path import (  # type: ignore
        VICTIM,
        _build_editorial,
        _build_freeze_asks_dict,
        _build_issuer_metadata,
        _build_v_cfi01_case,
    )

    case = _build_v_cfi01_case()
    editorial = _build_editorial()
    freeze_asks = _build_freeze_asks_dict()
    metadata = _build_issuer_metadata()
    victim = VictimInfo(
        name="V-CFI01 Test Victim", wallet_address=VICTIM,
        state="NY", country="US", email="victim@test.com",
    )
    inv = InvestigatorInfo(
        name="Test Investigator",
        organization="Recupero Forensics Ltd.",
        email="investigator@test.com",
    )
    brief = emit_brief(
        case=case, victim=victim, editorial=editorial,
        freeze_asks=freeze_asks, issuer_metadata=metadata,
    )
    tmp = Path(tempfile.mkdtemp(prefix="validator_e2e_"))
    # Drop freeze_brief.json into the case_dir for the validator to
    # find — build_all_deliverables writes it into briefs/ in some
    # codepaths; we write the canonical location explicitly.
    (tmp / "freeze_brief.json").write_text(
        json.dumps(brief, default=str), encoding="utf-8",
    )
    (tmp / "freeze_asks.json").write_text(
        json.dumps(freeze_asks, default=str), encoding="utf-8",
    )
    build_all_deliverables(
        case=case, victim=victim, freeze_brief=brief,
        case_dir=tmp, investigator=inv, skip_freeze_briefs=False,
    )
    return tmp


# ─────────────────────────────────────────────────────────────────────────────
# PUNISH-C: Jacob's Part 5 audit — 15 new invariants
# ─────────────────────────────────────────────────────────────────────────────


# Check 13: freeze_request <title> tag contains the issuer name.
def test_freeze_request_title_missing_issuer_flagged(tmp_path):
    """If the freeze_request for Tether has a <title> that doesn't
    mention Tether (e.g., generic "Compliance Freeze Request") the
    routing bug is detectable at the title-tag layer too."""
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "freeze_request_tether_BRIEF-TEST-1.html"
    # Generic title that omits the issuer name — exactly the bug
    # Jacob caught in v0.20.15.
    _write_lf(bad,
        "<!DOCTYPE html>\n<html>"
        "<head><title>Compliance Freeze Request — Case TEST</title></head>"
        "<body>"
        "<p>To: compliance@tether.to</p>"
        "<p>USDT freeze request. CASE_ID: TEST. Amount: $1,000.00.</p>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert any(
        v.check == "freeze_request_title_contains_issuer"
        and v.severity == "high"
        for v in result.violations
    ), result.summary_text()


# Check 14: no foreign-issuer compliance emails leak into a letter.
def test_freeze_request_with_foreign_issuer_email_flagged(tmp_path):
    """Tether letter must NOT contain compliance@circle.com — a
    template-fill bug crossed two issuers' contacts."""
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "freeze_request_tether_BRIEF-TEST-1.html"
    _write_lf(bad,
        "<!DOCTYPE html>\n<html>"
        "<head><title>Compliance Freeze Request to Tether — Case TEST</title></head>"
        "<body>"
        "<h1>Freeze Request — Tether</h1>"
        "<p>To: compliance@tether.to</p>"
        "<p>cc: compliance@circle.com</p>"  # bug: Circle email in Tether letter
        "<p>USDT freeze request. CASE_ID: TEST. Amount: $1,000.00.</p>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert any(
        v.check == "freeze_request_no_other_issuer_emails"
        and v.severity == "critical"
        for v in result.violations
    ), result.summary_text()


# Check 15: LE handoff Section 4.2 lists every FREEZABLE issuer.
def test_le_handoff_section_42_missing_issuer_flagged(tmp_path):
    """If the brief lists 2 issuers (Tether + Circle) but Section 4.2
    only enumerates Tether, AUSA cannot serve the missing target."""
    case_dir = _build_minimal_good_case(tmp_path)
    fb_path = case_dir / "freeze_brief.json"
    fb = json.loads(fb_path.read_text())
    fb["FREEZABLE"].append({
        "issuer": "Circle", "token": "USDC", "freeze_capability": "yes",
        "holdings": [{"address": "0xbbb", "freeze_capability": "yes",
                      "status": "FREEZABLE"}],
    })
    fb["ALL_ISSUER_HOLDINGS"].append({
        "issuer": "Circle", "token": "USDC",
        "amount_usd": "$500.00", "status": "FREEZABLE",
    })
    fb_path.write_text(json.dumps(fb))
    # Add Circle letters so check 6 is satisfied.
    _write_lf(case_dir / "briefs" / "freeze_request_circle_BRIEF-TEST-1.html",
        "<!DOCTYPE html><html><head><title>Freeze Request to Circle — Case TEST</title></head>"
        "<body><h1>Circle</h1><p>compliance@circle.com</p><p>CASE_ID: TEST.</p></body></html>"
    )
    _write_lf(case_dir / "briefs" / "le_handoff_circle_BRIEF-TEST-1.html",
        "<!DOCTYPE html><html><head><title>LE Handoff — Circle — Case TEST</title></head>"
        "<body><h1>Circle</h1>"
        "<p>Victim: Alice Victim. CASE_ID: TEST.</p>"
        "<h2>1. Executive Summary</h2><p>USDC theft. Total loss: $1,000.00.</p>"
        "<h2>4.2 ALL_ISSUER_HOLDINGS</h2>"
        # Bug: Circle handoff omits Tether from its inventory.
        "<table><tr><td>Circle</td><td>USDC</td><td>$500.00</td><td>FREEZABLE</td></tr></table>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert any(
        v.check == "le_handoff_section_42_lists_all_issuers"
        and v.severity == "high"
        and "Tether" in v.detail
        for v in result.violations
    ), result.summary_text()


# Check 16: LE handoff cites TOTAL_LOSS_USD from the brief.
def test_le_handoff_missing_total_loss_flagged(tmp_path):
    """An LE handoff that does not reproduce the brief's TOTAL_LOSS_USD
    figure leaves AUSA without a quantified loss."""
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "le_handoff_tether_BRIEF-TEST-1.html"
    _write_lf(bad,
        "<!DOCTYPE html>\n<html>"
        "<head><title>LE Handoff — Tether — Case TEST</title></head>"
        "<body><h1>LE Handoff — Tether</h1>"
        "<p>Victim: Alice Victim. CASE_ID: TEST.</p>"
        "<h2>1. Executive Summary</h2>"
        # Bug: dollar figure missing.
        "<p>USDT theft. The token is issued by Tether.</p>"
        "<h2>4.2 ALL_ISSUER_HOLDINGS</h2>"
        "<table><tr><td>Tether</td><td>USDT</td><td>FREEZABLE</td></tr></table>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert any(
        v.check == "le_handoff_cites_total_loss"
        and v.severity == "high"
        for v in result.violations
    ), result.summary_text()


# Check 17: trace_report must not contain freeze-request language.
def test_trace_report_with_freeze_request_language_flagged(tmp_path):
    """trace_report_*.html is an internal investigative document. If
    it contains 'Attn: Compliance Department' / 'Compliance Freeze
    Request', a template was crossed."""
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "trace_report_abc123.html"
    _write_lf(bad,
        "<!DOCTYPE html>\n<html><body>"
        "<h1>Compliance Freeze Request</h1>"  # bug: freeze-request title in trace_report
        "<p>Attn: Compliance Department</p>"
        "<p>Trace details follow.</p>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert any(
        v.check == "trace_report_internal_marker"
        and v.severity == "critical"
        for v in result.violations
    ), result.summary_text()


# Check 18: engagement_letter exists iff MAX_RECOVERABLE_USD > 0.
def test_engagement_letter_with_zero_recoverable_flagged(tmp_path):
    """If MAX_RECOVERABLE_USD == 0 there is nothing to sign up for —
    engagement_letter must NOT exist. The v0.15.1 classifier-on-broken-
    input bug applies at this artifact too."""
    case_dir = _build_minimal_good_case(tmp_path)
    fb_path = case_dir / "freeze_brief.json"
    fb = json.loads(fb_path.read_text())
    fb["MAX_RECOVERABLE_USD"] = "$0.00"
    fb["TOTAL_FREEZABLE_USD"] = "$0.00"
    fb_path.write_text(json.dumps(fb))
    # Replace recoverable summary with unrecoverable to be consistent.
    (case_dir / "briefs" / "victim_summary_recoverable_def456.html").unlink()
    _write_lf(case_dir / "briefs" / "victim_summary_unrecoverable_def456.html",
        "<!DOCTYPE html><html><body>"
        "<h1>Case Summary — Alice Victim</h1>"
        "<p>CASE_ID: TEST. No funds recoverable.</p>"
        "</body></html>"
    )
    # engagement_letter_ghi789.html still exists — that's the bug.
    result = validate_case_output(case_dir)
    assert any(
        v.check == "engagement_letter_exists_iff_recoverable"
        and v.severity == "critical"
        for v in result.violations
    ), result.summary_text()


# Check 19: engagement_letter names the victim.
def test_engagement_letter_missing_victim_name_flagged(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "engagement_letter_ghi789.html"
    _write_lf(bad,
        "<!DOCTYPE html><html><body>"
        "<h1>Engagement Letter</h1>"  # bug: no victim name
        "<p>Engagement fee: $1,000.00. CASE_ID: TEST.</p>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert any(
        v.check == "engagement_letter_names_victim"
        and v.severity == "high"
        for v in result.violations
    ), result.summary_text()


# Check 20: victim_summary quotes the freezable / recoverable figure.
def test_victim_summary_missing_freezable_total_flagged(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "victim_summary_recoverable_def456.html"
    _write_lf(bad,
        "<!DOCTYPE html><html><body>"
        "<h1>Case Summary — Alice Victim</h1>"
        # Bug: dollar amount missing.
        "<p>CASE_ID: TEST. Funds freezable.</p>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert any(
        v.check == "victim_summary_quotes_freezable_total"
        and v.severity == "high"
        for v in result.violations
    ), result.summary_text()


# Check 21: victim_summary names the victim.
def test_victim_summary_missing_victim_name_flagged(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "victim_summary_recoverable_def456.html"
    _write_lf(bad,
        "<!DOCTYPE html><html><body>"
        "<h1>Case Summary</h1>"  # bug: no victim name
        "<p>CASE_ID: TEST. $1,000.00 freezable.</p>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert any(
        v.check == "victim_summary_names_victim"
        and v.severity == "high"
        for v in result.violations
    ), result.summary_text()


# Check 22: flow_*.svg files have a valid SVG/XML root.
def test_flow_svg_with_html_content_flagged(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "flow_diagram_abc.svg"
    # Write HTML into a .svg path — classic content/extension mismatch.
    _write_lf(bad, "<!DOCTYPE html><html><body>not an SVG</body></html>")
    result = validate_case_output(case_dir)
    assert any(
        v.check == "flow_svg_valid_root"
        and v.severity == "critical"
        for v in result.violations
    ), result.summary_text()


# Check 23: investigator_findings.csv well-formed (header + ≥1 row).
def test_investigator_findings_csv_missing_header_flagged(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "investigator_findings.csv"
    # Bug: just data rows, no recognizable header.
    _write_lf(bad, "0xaaa,1000,FREEZABLE\n0xbbb,500,FREEZABLE\n")
    result = validate_case_output(case_dir)
    assert any(
        v.check == "investigator_findings_csv_well_formed"
        and v.severity == "high"
        for v in result.violations
    ), result.summary_text()


def test_investigator_findings_csv_empty_flagged(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    # No data rows but FREEZABLE has 1 holding.
    bad = case_dir / "briefs" / "investigator_findings.csv"
    _write_lf(bad, "address,amount_usd,status\n")
    result = validate_case_output(case_dir)
    assert any(
        v.check == "investigator_findings_csv_well_formed"
        for v in result.violations
    ), result.summary_text()


# Check 24: CASE_ID consistent across artifacts.
def test_case_id_inconsistent_across_artifacts_flagged(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    # Re-write the LE handoff with the wrong case ID.
    bad = case_dir / "briefs" / "le_handoff_tether_BRIEF-TEST-1.html"
    _write_lf(bad,
        "<!DOCTYPE html>\n<html>"
        "<head><title>LE Handoff — Tether — Case TEST</title></head>"
        "<body><h1>LE Handoff — Tether</h1>"
        "<p>Victim: Alice Victim. CASE_ID: WRONG.</p>"  # bug
        "<h2>1. Executive Summary</h2><p>USDT theft. Total loss: $1,000.00.</p>"
        "<h2>4.2 ALL_ISSUER_HOLDINGS</h2>"
        "<table><tr><td>Tether</td><td>USDT</td><td>$1,000.00</td><td>FREEZABLE</td></tr></table>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert any(
        v.check == "case_id_consistent_across_artifacts"
        and v.severity == "high"
        for v in result.violations
    ), result.summary_text()


# Check 25: asset symbol consistent across LE handoff + trace_report.
def test_asset_symbol_mismatch_in_trace_report_flagged(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "trace_report_abc123.html"
    _write_lf(bad,
        "<!DOCTYPE html>\n<html><body>"
        "<h1>Internal Trace Report — Case TEST</h1>"
        # Bug: trace_report says USDC but brief says USDT.
        "<p>Victim: Alice Victim. Asset: USDC. "
        "Total drained: $1,000.00.</p>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert any(
        v.check == "asset_symbol_consistent_across_artifacts"
        and v.severity == "high"
        for v in result.violations
    ), result.summary_text()


# Check 26: victim name consistent across artifacts.
def test_victim_name_inconsistent_across_artifacts_flagged(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    bad = case_dir / "briefs" / "victim_summary_recoverable_def456.html"
    _write_lf(bad,
        "<!DOCTYPE html><html><body>"
        "<h1>Case Summary — Bob Other</h1>"  # bug: different victim
        "<p>CASE_ID: TEST. $1,000.00 freezable.</p>"
        "</body></html>"
    )
    result = validate_case_output(case_dir)
    assert any(
        v.check == "victim_name_consistent_across_artifacts"
        and v.severity == "high"
        for v in result.violations
    ), result.summary_text()


# Check 27: recovery_snapshot exists iff brief has positive recovery.
def test_recovery_snapshot_with_zero_recoverable_flagged(tmp_path):
    case_dir = _build_minimal_good_case(tmp_path)
    fb_path = case_dir / "freeze_brief.json"
    fb = json.loads(fb_path.read_text())
    fb["MAX_RECOVERABLE_USD"] = "$0.00"
    fb["TOTAL_FREEZABLE_USD"] = "$0.00"
    fb_path.write_text(json.dumps(fb))
    # Add recovery_snapshot for a $0-recovery case — bug.
    _write_lf(case_dir / "briefs" / "recovery_snapshot_xyz.html",
        "<!DOCTYPE html><html><body>"
        "<h1>Recovery Snapshot — Alice Victim</h1>"
        "<p>CASE_ID: TEST. Recovery: $0.00.</p>"
        "</body></html>"
    )
    # Replace recoverable summary with unrecoverable to stay consistent.
    (case_dir / "briefs" / "victim_summary_recoverable_def456.html").unlink()
    _write_lf(case_dir / "briefs" / "victim_summary_unrecoverable_def456.html",
        "<!DOCTYPE html><html><body>"
        "<h1>Case Summary — Alice Victim</h1>"
        "<p>CASE_ID: TEST. No funds recoverable.</p>"
        "</body></html>"
    )
    # And remove engagement_letter to satisfy check 18.
    (case_dir / "briefs" / "engagement_letter_ghi789.html").unlink()
    result = validate_case_output(case_dir)
    assert any(
        v.check == "recovery_snapshot_iff_recoverable"
        and v.severity == "high"
        for v in result.violations
    ), result.summary_text()


def test_v_cfi01_e2e_passes_validator(v_cfi01_case_dir):
    """The whole V-CFI01 production path must pass every structural
    invariant. If this fails, Jacob's eyeball check would also fail."""
    result = validate_case_output(v_cfi01_case_dir)
    # Print the summary on failure so the test output shows the
    # specific violation list — exactly what Jacob would want to see.
    if not result.ok:
        print("\n" + result.summary_text())
    assert result.ok, (
        f"validator found violations:\n{result.summary_text()}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# INVARIANT F (v0.32 Tier-0 gap #1): MANDATORY HUMAN REVIEW
# ─────────────────────────────────────────────────────────────────────────────


def test_invariant_f_skipped_when_dsn_unset(tmp_path, monkeypatch):
    """No DSN configured → INVARIANT F is a silent no-op so test
    suites + local-dev runs aren't blocked."""
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    case_dir = _build_minimal_good_case(tmp_path)
    result = validate_case_output(case_dir)
    # No violations from the review-gate check.
    review_violations = [
        v for v in result.violations
        if v.check == "review_gate_approvals_present"
    ]
    assert review_violations == []


def test_invariant_f_skipped_when_case_id_not_uuid(tmp_path, monkeypatch):
    """The minimal fixture uses CASE_ID='TEST' (not a UUID); INVARIANT
    F must skip rather than blow up, even with a DSN configured."""
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake/db")
    case_dir = _build_minimal_good_case(tmp_path)
    # Patch db_connect so the real driver isn't hit if the early-skip
    # in INVARIANT F somehow fails.
    monkeypatch.setattr(
        "recupero._common.db_connect",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("db_connect should not be called"),
        ),
    )
    result = validate_case_output(case_dir)
    review_violations = [
        v for v in result.violations
        if v.check == "review_gate_approvals_present"
    ]
    assert review_violations == []


def test_invariant_f_flags_missing_approval(tmp_path, monkeypatch):
    """With a UUID case_id + DSN configured + no DB rows → every
    customer-facing artifact trips a critical violation."""
    from uuid import uuid4
    monkeypatch.setenv("SUPABASE_DB_URL", "postgres://fake/db")
    case_dir = _build_minimal_good_case(tmp_path)
    # Swap CASE_ID for a real UUID so the validator actually queries.
    fb_path = case_dir / "freeze_brief.json"
    fb = json.loads(fb_path.read_text(encoding="utf-8"))
    fb["CASE_ID"] = str(uuid4())
    _write_lf(fb_path, json.dumps(fb))

    # Patch db_connect to return no matching rows (empty SELECT).
    class _NoRowsCursor:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def execute(self, *a, **k): pass
        def fetchone(self): return None
        def fetchall(self): return []

    class _NoRowsConn:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def cursor(self): return _NoRowsCursor()

    monkeypatch.setattr(
        "recupero._common.db_connect",
        lambda *a, **k: _NoRowsConn(),
    )
    result = validate_case_output(case_dir)
    review_violations = [
        v for v in result.violations
        if v.check == "review_gate_approvals_present"
    ]
    # Expect at least one critical for the trace_report / victim_summary /
    # engagement_letter / freeze_request / le_handoff files.
    assert review_violations, (
        "expected critical violations for missing review rows"
    )
    assert all(
        v.severity == "critical" for v in review_violations
    )
    # Case build is BLOCKED.
    assert not result.ok
