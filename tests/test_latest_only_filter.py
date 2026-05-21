"""Tests for the latest_only filter on /investigations/<id>.

The filter collapses multiple brief sets per issuer (from re-runs
that pre-date the briefs/ auto-cleanup in commit a507f12) down to
the most-recent set per issuer. Investigations that already have
clean single-brief artifact lists (the post-cleanup steady state)
pass through unchanged.

Tests run in <50ms, zero network.
"""

from __future__ import annotations

from recupero.worker.investigations_api import (
    _extract_brief_timestamp,
    _filter_to_latest_briefs,
)


def _entry(issuer_slug: str, html_name: str, pdf_name: str | None = None) -> dict:
    """Build a freeze_letters[] entry shape matching what
    _build_artifacts_map produces."""
    out = {
        "issuer_slug": issuer_slug,
        "html": {"name": html_name, "size_bytes": 1000, "mimetype": "text/html",
                 "signed_url": "..."},
        "pdf": None,
        "le_handoff_html": None,
        "le_handoff_pdf": None,
    }
    if pdf_name:
        out["pdf"] = {"name": pdf_name, "size_bytes": 2000,
                      "mimetype": "application/pdf", "signed_url": "..."}
    return out


# ---- _extract_brief_timestamp ---- #


def test_extract_timestamp_from_html() -> None:
    """Recognize the BRIEF-YYYYMMDDTHHMMSS pattern in any of the
    filename fields."""
    entry = _entry("Circle", "freeze_request_circle_BRIEF-20260515T135939-abcd.html")
    assert _extract_brief_timestamp(entry) == "20260515T135939"


def test_extract_timestamp_from_pdf_when_html_missing() -> None:
    """Falls back to scanning the pdf filename if html is None
    (defensive — some intermediate runs may have PDF without HTML)."""
    entry = {
        "issuer_slug": "Tether",
        "html": None,
        "pdf": {"name": "freeze_request_tether_BRIEF-20260514T214844-xyz.pdf",
                "size_bytes": 100, "mimetype": "application/pdf",
                "signed_url": "..."},
        "le_handoff_html": None, "le_handoff_pdf": None,
    }
    assert _extract_brief_timestamp(entry) == "20260514T214844"


def test_extract_timestamp_from_le_handoff() -> None:
    """The fallback ordering also covers le_handoff fields — some
    early case-driven runs put the LE handoff on different cadence
    than the freeze letter."""
    entry = {
        "issuer_slug": "Sky",
        "html": None,
        "pdf": None,
        "le_handoff_html": {
            "name": "le_handoff_sky_BRIEF-20260514T182431-1f9d4b.html",
            "size_bytes": 100, "mimetype": "text/html", "signed_url": "..."
        },
        "le_handoff_pdf": None,
    }
    assert _extract_brief_timestamp(entry) == "20260514T182431"


def test_extract_timestamp_no_brief_pattern_returns_empty() -> None:
    """Entry without a BRIEF-<timestamp> filename returns empty
    string — caller treats this as "oldest" so a malformed entry
    never wins the latest comparison."""
    entry = _entry("Custom", "freeze_request_custom_no_timestamp.html")
    assert _extract_brief_timestamp(entry) == ""


def test_extract_timestamp_empty_entry() -> None:
    """Empty entry → empty timestamp, no crash."""
    assert _extract_brief_timestamp({}) == ""


# ---- _filter_to_latest_briefs ---- #


def test_filter_passes_single_brief_unchanged() -> None:
    """The common case after auto-cleanup: one brief per issuer,
    nothing to filter. Pass through verbatim."""
    artifacts = {
        "trace_report": {"html": None, "pdf": None},
        "flow_diagram": {"svg": None, "pdf": None},
        "raw": {},
        "freeze_letters": [
            _entry("Circle Brief-20260515T140000", "freeze_request_circle_BRIEF-20260515T140000-abc.html"),
        ],
    }
    out = _filter_to_latest_briefs(artifacts)
    assert len(out["freeze_letters"]) == 1
    assert out["freeze_letters"][0]["issuer_slug"].startswith("Circle")


def test_filter_collapses_multi_brief_to_latest() -> None:
    """The dry-run finding: 14 Circle briefs spanning multiple
    re-runs collapse to just the latest one."""
    artifacts = {
        "trace_report": {"html": None, "pdf": None},
        "flow_diagram": {"svg": None, "pdf": None},
        "raw": {},
        "freeze_letters": [
            _entry("Circle Brief-20260514T182431", "freeze_request_circle_BRIEF-20260514T182431-a.html"),
            _entry("Circle Brief-20260514T214844", "freeze_request_circle_BRIEF-20260514T214844-b.html"),
            _entry("Circle Brief-20260515T135939", "freeze_request_circle_BRIEF-20260515T135939-c.html"),
        ],
    }
    out = _filter_to_latest_briefs(artifacts)
    assert len(out["freeze_letters"]) == 1
    # Latest by timestamp wins
    assert "20260515T135939" in out["freeze_letters"][0]["html"]["name"]


def test_filter_preserves_separate_issuers() -> None:
    """Different issuers each get their own latest entry — they
    don't compete with each other."""
    artifacts = {
        "trace_report": {"html": None, "pdf": None},
        "flow_diagram": {"svg": None, "pdf": None},
        "raw": {},
        "freeze_letters": [
            _entry("Circle Brief-20260515T135939", "freeze_request_circle_BRIEF-20260515T135939-a.html"),
            _entry("Tether Brief-20260515T135939", "freeze_request_tether_BRIEF-20260515T135939-b.html"),
            _entry("Paxos Brief-20260515T135939",  "freeze_request_paxos_BRIEF-20260515T135939-c.html"),
            _entry("Sky Brief-20260515T135939",    "freeze_request_sky_BRIEF-20260515T135939-d.html"),
        ],
    }
    out = _filter_to_latest_briefs(artifacts)
    assert len(out["freeze_letters"]) == 4
    issuers = sorted(entry["issuer_slug"].split()[0] for entry in out["freeze_letters"])
    assert issuers == ["Circle", "Paxos", "Sky", "Tether"]


def test_filter_keeps_per_issuer_latest() -> None:
    """Mixed input: 3 Circle briefs + 2 Tether briefs → 1 of each,
    latest per issuer."""
    artifacts = {
        "trace_report": {"html": None, "pdf": None},
        "flow_diagram": {"svg": None, "pdf": None},
        "raw": {},
        "freeze_letters": [
            _entry("Circle Brief-20260514T182431", "freeze_request_circle_BRIEF-20260514T182431-a.html"),
            _entry("Circle Brief-20260515T135939", "freeze_request_circle_BRIEF-20260515T135939-b.html"),
            _entry("Circle Brief-20260514T214844", "freeze_request_circle_BRIEF-20260514T214844-c.html"),
            _entry("Tether Brief-20260514T230557", "freeze_request_tether_BRIEF-20260514T230557-d.html"),
            _entry("Tether Brief-20260515T123304", "freeze_request_tether_BRIEF-20260515T123304-e.html"),
        ],
    }
    out = _filter_to_latest_briefs(artifacts)
    assert len(out["freeze_letters"]) == 2
    by_issuer = {e["issuer_slug"].split()[0]: e for e in out["freeze_letters"]}
    assert "20260515T135939" in by_issuer["Circle"]["html"]["name"]
    assert "20260515T123304" in by_issuer["Tether"]["html"]["name"]


def test_filter_preserves_non_freeze_artifacts() -> None:
    """The filter operates on freeze_letters only — trace_report,
    flow_diagram, and raw artifacts pass through untouched."""
    artifacts = {
        "trace_report": {"html": {"name": "trace_report_abc.html"},
                         "pdf": {"name": "trace_report_abc.pdf"}},
        "flow_diagram": {"svg": {"name": "flow_xyz.svg"},
                         "pdf": {"name": "flow_xyz.pdf"}},
        "raw": {"case_json": {"name": "case.json"}},
        "freeze_letters": [
            _entry("Circle Brief-20260514T182431", "freeze_request_circle_BRIEF-20260514T182431-a.html"),
            _entry("Circle Brief-20260515T135939", "freeze_request_circle_BRIEF-20260515T135939-b.html"),
        ],
    }
    out = _filter_to_latest_briefs(artifacts)
    # Non-freeze sections unchanged
    assert out["trace_report"]["html"]["name"] == "trace_report_abc.html"
    assert out["flow_diagram"]["svg"]["name"] == "flow_xyz.svg"
    assert out["raw"]["case_json"]["name"] == "case.json"
    # freeze_letters filtered as expected
    assert len(out["freeze_letters"]) == 1


def test_filter_handles_empty_letters() -> None:
    """Wallet-trace investigations have freeze_letters=[]. The filter
    is a no-op on empty input."""
    artifacts = {
        "trace_report": {"html": None, "pdf": None},
        "flow_diagram": {"svg": None, "pdf": None},
        "raw": {},
        "freeze_letters": [],
    }
    out = _filter_to_latest_briefs(artifacts)
    assert out["freeze_letters"] == []


def test_filter_handles_entry_without_issuer_slug() -> None:
    """Defensive: an entry with no issuer_slug (malformed) gets a
    synthetic key per id() so it doesn't collide with real
    issuer-named entries and isn't silently dropped."""
    bad_entry = {
        "issuer_slug": "",
        "html": {"name": "weird_freeze.html", "size_bytes": 0,
                 "mimetype": "text/html", "signed_url": "..."},
        "pdf": None, "le_handoff_html": None, "le_handoff_pdf": None,
    }
    artifacts = {
        "trace_report": {"html": None, "pdf": None},
        "flow_diagram": {"svg": None, "pdf": None},
        "raw": {},
        "freeze_letters": [
            bad_entry,
            _entry("Circle Brief-20260515T135939", "freeze_request_circle_BRIEF-20260515T135939-a.html"),
        ],
    }
    out = _filter_to_latest_briefs(artifacts)
    # Both should survive — one under synthetic key, one under Circle
    assert len(out["freeze_letters"]) == 2
