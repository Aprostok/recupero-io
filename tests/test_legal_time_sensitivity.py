"""Legal time-sensitivity / statute-of-limitations advisory.

Covers the citable-info-with-counsel-referral posture:
  * jurisdiction normalization + limitation resolution (seeded baseline);
  * the override loader's safety rails (drop citation-less entries, downgrade
    sourceless "verified", skip doc keys);
  * the case-derived clocks (days since incident, per-exchange windows) and the
    approximate limitation runout + status math, pinned via ``as_of``;
  * the rendered advisory carries the NOT-LEGAL-ADVICE framing, real citations,
    and the confirm-with-counsel posture for unknown jurisdictions;
  * the committed seed file ships no un-cited periods.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from tempfile import TemporaryDirectory

from recupero.legal.limitations import (
    _OVERRIDES_PATH,
    load_limitation_overrides,
    normalize_jurisdiction,
    resolve_limitations,
)
from recupero.legal.time_sensitivity import build_time_sensitivity
from recupero.reports.time_sensitivity_report import render_time_sensitivity

_INCIDENT = "2026-05-01"


def _brief(*, jurisdiction: str = "US", flows: list[dict] | None = None) -> dict:
    return {
        "CASE_ID": "SOL-TEST-01",
        "VICTIM_NAME": "Acme Corp",
        "VICTIM_JURISDICTION": jurisdiction,
        "INCIDENT_DATE": _INCIDENT,
        "_freeze_asks": {"onward_cex_flows": flows or []},
    }


def _flow(exchange: str, first: str | None = "2026-05-02T12:00:00Z") -> dict:
    return {"exchange": exchange, "first_flow_at": first}


# --- jurisdiction + resolution -------------------------------------------

def test_normalize_jurisdiction_aliases() -> None:
    for alias in ("US", "usa", "United States", "u.s.a."):
        assert normalize_jurisdiction(alias) == "US"
    assert normalize_jurisdiction("United Kingdom") == "UK"
    assert normalize_jurisdiction("European Union") == "EU"
    assert normalize_jurisdiction("Atlantis") is None
    assert normalize_jurisdiction("") is None
    assert normalize_jurisdiction(None) is None


def test_resolve_us_returns_cited_seed() -> None:
    refs = resolve_limitations("United States")
    assert refs, "US must have seeded references"
    # Every shipped reference MUST carry a real citation (never fabricated).
    assert all(r.citation.strip() for r in refs)
    citations = {r.citation for r in refs}
    assert "18 U.S.C. § 3282(a)" in citations
    assert "18 U.S.C. § 3293(2)" in citations


def test_resolve_unknown_jurisdiction_is_empty() -> None:
    # Never guess a period for a jurisdiction we have no cited reference for.
    assert resolve_limitations("Atlantis") == []
    assert resolve_limitations(None) == []


# --- override loader safety rails ----------------------------------------

def test_override_drops_entry_without_citation(tmp_path) -> None:
    p = tmp_path / "ov.json"
    p.write_text(json.dumps({
        "US": [
            {"claim_kind": "civil", "label": "no citation", "period": "3 years"},
            {"claim_kind": "civil", "label": "ok", "period": "3 years",
             "citation": "Some Real Cite", "verified": True, "source": "src"},
        ],
    }), encoding="utf-8")
    out = load_limitation_overrides(p)
    assert "US" in out
    labels = [r.label for r in out["US"]]
    assert "no citation" not in labels  # dropped: no citation
    assert "ok" in labels


def test_override_downgrades_verified_without_source(tmp_path) -> None:
    p = tmp_path / "ov.json"
    p.write_text(json.dumps({
        "UK": [
            {"claim_kind": "civil", "label": "x", "period": "6 years",
             "citation": "Limitation Act 1980, s.2", "verified": True},
        ],
    }), encoding="utf-8")
    out = load_limitation_overrides(p)
    assert out["UK"][0].verified is False  # no source -> downgraded


def test_override_skips_doc_keys_and_bad_file(tmp_path) -> None:
    p = tmp_path / "ov.json"
    p.write_text(json.dumps({
        "_README": "docs", "_schema": {}, "_example": {"x": 1},
    }), encoding="utf-8")
    assert load_limitation_overrides(p) == {}
    missing = tmp_path / "nope.json"
    assert load_limitation_overrides(missing) == {}


def test_committed_seed_file_has_no_uncited_periods() -> None:
    # The shipped override file is documentation-only; it must never resolve to
    # a real period without a citation. Loading it yields no real entries.
    out = load_limitation_overrides(_OVERRIDES_PATH)
    for refs in out.values():
        assert all(r.citation.strip() for r in refs)


# --- time-sensitivity builder --------------------------------------------

def test_days_since_incident_and_exchange_clocks() -> None:
    ts = build_time_sensitivity(
        _brief(flows=[_flow("Binance", "2026-05-02T00:00:00Z"),
                      _flow("Kraken", "2026-05-10T00:00:00Z")]),
        as_of=date(2026, 6, 1),
    )
    assert ts.days_since_incident == 31  # 2026-05-01 -> 2026-06-01
    by_name = {c.exchange: c for c in ts.exchange_clocks}
    assert by_name["Binance"].days_since_first_flow == 30
    assert by_name["Kraken"].days_since_first_flow == 22


def test_limitation_clock_status_running_approaching_elapsed() -> None:
    # 18 U.S.C. § 3282(a) is 5 years -> runout 2031-05-01 from a 2026-05-01 incident.
    running = build_time_sensitivity(_brief(), as_of=date(2026, 6, 1))
    five_yr = [c for c in running.limitation_clocks
               if c.ref.citation == "18 U.S.C. § 3282(a)"][0]
    assert five_yr.approx_deadline == "2031-05-01"
    assert five_yr.status == "running"

    approaching = build_time_sensitivity(_brief(), as_of=date(2031, 1, 1))
    five_yr_a = [c for c in approaching.limitation_clocks
                 if c.ref.citation == "18 U.S.C. § 3282(a)"][0]
    assert five_yr_a.status == "approaching"

    elapsed = build_time_sensitivity(_brief(), as_of=date(2031, 6, 1))
    five_yr_e = [c for c in elapsed.limitation_clocks
                 if c.ref.citation == "18 U.S.C. § 3282(a)"][0]
    assert five_yr_e.status == "may_have_elapsed"
    assert five_yr_e.approx_days_remaining < 0


def test_illustrative_civil_entries_get_no_computed_deadline() -> None:
    ts = build_time_sensitivity(_brief(), as_of=date(2026, 6, 1))
    illus = [c for c in ts.limitation_clocks if c.ref.illustrative]
    assert illus, "expected illustrative civil examples for US"
    # Illustrative periods vary by state — we must NOT imply a concrete date.
    assert all(c.approx_deadline is None and c.status == "unknown" for c in illus)


def test_unknown_jurisdiction_sets_confirm_with_counsel() -> None:
    ts = build_time_sensitivity(_brief(jurisdiction="Atlantis"), as_of=date(2026, 6, 1))
    assert ts.jurisdiction_canonical is None
    assert ts.limitation_clocks == ()
    assert ts.confirm_with_counsel is True


def test_compound_period_not_date_computed() -> None:
    # "6 years, or 2 years from discovery" is the NY fraud example (illustrative);
    # even were it non-illustrative, a compound period yields no single date.
    ts = build_time_sensitivity(_brief(), as_of=date(2026, 6, 1))
    fraud = [c for c in ts.limitation_clocks
             if "213(8)" in c.ref.citation][0]
    assert fraud.approx_deadline is None


# --- renderer ------------------------------------------------------------

def test_render_writes_advisory_with_disclaimer_and_citation() -> None:
    with TemporaryDirectory() as tmp:
        out = render_time_sensitivity(
            _brief(flows=[_flow("Binance")]),
            output_dir=Path(tmp), as_of=date(2026, 6, 1),
        )
        assert out.name == "legal_time_sensitivity.html"
        html = out.read_text(encoding="utf-8")
        assert "NOT LEGAL ADVICE" in html
        assert "18 U.S.C. § 3282(a)" in html  # real citation surfaced
        assert "Binance" in html               # practical clock present
        assert "not legal advice" in html.lower()


def test_render_unknown_jurisdiction_shows_confirm_with_counsel() -> None:
    with TemporaryDirectory() as tmp:
        out = render_time_sensitivity(
            _brief(jurisdiction="Atlantis"),
            output_dir=Path(tmp), as_of=date(2026, 6, 1),
        )
        html = out.read_text(encoding="utf-8")
        assert "No verified limitation reference" in html
        assert "licensed counsel" in html.lower()
