"""v0.35.10 (E3) — SAR/STR regulatory-filing draft generator.

Pins: jurisdiction labels switch (US FinCEN / UK NCA / EU goAML); subjects are
built ONLY from brief addresses (never fabricated) and deduped; the
suspicious-activity amount/date-range come from the case; placeholder sentinels
in victim fields don't leak; NaN/Inf subject amounts collapse to $0.00; the
rendered HTML carries the regulator + a prominent DRAFT/NOT-FILED disclaimer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from recupero.reports.regulatory_filing import (
    SAR_JURISDICTIONS,
    build_sar_context,
    render_sar_filing,
)

_EVM = "0x" + "ab" * 20
_EVM2 = "0x" + "cd" * 20


def _brief(**overrides):
    base = {
        "CASE_ID": "V-CFI01",
        "INCIDENT_DATE": "2026-01-04",
        "INCIDENT_TYPE": "an approval-phishing drainer attack",
        "TOTAL_LOSS_USD": "$56,040.00",
        "VICTIM_NAME": "Jane Q. Victim",
        "VICTIM_JURISDICTION": "United States",
        "INVESTIGATOR_NAME": "A. Investigator",
        "INVESTIGATOR_EMAIL": "investigator@recupero.io",
        "EXCHANGES": [
            {"exchange": "Binance", "address": _EVM,
             "total_received_usd": "$45,000.00", "chain": "ethereum"},
        ],
        "DESTINATIONS": [
            {"address": _EVM2, "label": "unknown wallet",
             "total_usd": "$11,040.00", "chain": "ethereum"},
        ],
        "CROSS_CHAIN_HANDOFFS": [
            {"tx_hash": "0x" + "1" * 64, "block_time": "2026-01-04T12:00:00Z",
             "amount_usd": "$45,000.00"},
            {"tx_hash": "0x" + "2" * 64, "block_time": "2026-01-05T08:30:00Z",
             "amount_usd": "$11,040.00"},
        ],
    }
    base.update(overrides)
    return base


def test_us_fincen_context():
    ctx = build_sar_context(_brief(), jurisdiction="us")
    assert ctx["jurisdiction_key"] == "us_fincen"
    assert "FinCEN" in ctx["labels"]["regulator"]
    assert "111" in ctx["labels"]["form_reference"]
    assert ctx["labels"]["report_acronym"] == "SAR"
    # Subjects built from EXCHANGES + DESTINATIONS.
    addrs = {s["address"] for s in ctx["subjects"]}
    assert _EVM in addrs and _EVM2 in addrs
    # Activity reflects the case.
    assert ctx["activity"]["amount_usd"] == "$56,040.00"
    assert ctx["activity"]["date_from"] == "2026-01-04T12:00:00"
    assert ctx["activity"]["date_to"] == "2026-01-05T08:30:00"
    assert "Jane Q. Victim" in ctx["sar_narrative"]
    assert "56,040" in ctx["sar_narrative"]


def test_jurisdiction_switch_uk_and_eu():
    uk = build_sar_context(_brief(), jurisdiction="uk")
    assert "NCA" in uk["labels"]["regulator"]
    assert "POCA" in uk["labels"]["statute"] or "Proceeds of Crime" in uk["labels"]["statute"]
    assert uk["labels"]["report_acronym"] == "SAR"

    eu = build_sar_context(_brief(), jurisdiction="eu")
    assert eu["labels"]["report_acronym"] == "STR"
    assert "goAML" in eu["labels"]["form_reference"]


def test_invalid_jurisdiction_raises():
    with pytest.raises(ValueError, match="not recognized"):
        build_sar_context(_brief(), jurisdiction="atlantis")


def test_subjects_deduped_across_sources():
    # Same address in EXCHANGES and DESTINATIONS → one subject row.
    b = _brief(DESTINATIONS=[{"address": _EVM, "total_usd": "$1.00", "chain": "ethereum"}])
    ctx = build_sar_context(b, jurisdiction="us")
    rows = [s for s in ctx["subjects"] if s["address"] == _EVM]
    assert len(rows) == 1
    assert "VASP deposit" in rows[0]["role"]   # first (EXCHANGES) role wins


def test_no_fabrication_on_empty_brief():
    ctx = build_sar_context(
        {"CASE_ID": "X", "TOTAL_LOSS_USD": "$0.00"}, jurisdiction="us",
    )
    assert ctx["subjects"] == []          # nothing invented
    assert ctx["sar_narrative"]           # still renders a narrative
    assert ctx["activity"]["amount_usd"] == "$0.00"


def test_placeholder_sentinel_not_leaked():
    b = _brief(VICTIM_NAME="TODO: confirm victim identity")
    ctx = build_sar_context(b, jurisdiction="us")
    assert "TODO" not in ctx["victim"]["name"]
    assert ctx["victim"]["name"] == "[victim name]"
    assert "TODO" not in ctx["sar_narrative"]


def test_subject_amount_nan_safe():
    b = _brief(EXCHANGES=[
        {"exchange": "X", "address": _EVM, "total_received_usd": "Infinity",
         "chain": "ethereum"},
    ])
    ctx = build_sar_context(b, jurisdiction="us")
    sub = next(s for s in ctx["subjects"] if s["address"] == _EVM)
    assert sub["amount_usd"] == "$0.00"   # Inf collapsed, no "$inf" leak


def test_render_writes_draft_html(tmp_path: Path):
    render = render_sar_filing(_brief(), jurisdiction="us", output_dir=tmp_path)
    assert render.output_path.exists()
    assert render.report_acronym == "SAR"
    assert render.subject_count == 2
    html = render.output_path.read_text(encoding="utf-8")
    assert "FinCEN" in html
    assert "DRAFT" in html and "NOT YET FILED" in html
    assert "56,040" in html
    assert _EVM in html                    # subject address present
    assert "BSA E-Filing" in html          # filing portal


def test_jurisdictions_constant_exposed():
    assert set(SAR_JURISDICTIONS) == {"us_fincen", "uk_nca", "eu_goaml"}
