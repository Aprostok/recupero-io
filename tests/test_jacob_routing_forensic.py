"""JACOB-1 forensic: does the v0.20.15 routing bug still exist?

Jacob's review of v0.20.15 found that build_all_deliverables wrote
content for issuer X to the file named for issuer Y. The existing
test_v_cfi01_production_path.py only checks COUNTS of output files,
not content-vs-filename consistency — which is exactly why the bug
shipped to Jacob unnoticed.

This file does what Jacob did manually:
  1. Run build_all_deliverables on V-CFI01.
  2. For each freeze_request_<issuer>_*.html, verify the content
     actually addresses that issuer (compliance@<issuer>.com or
     similar issuer-specific markers).
  3. For each le_handoff_<issuer>_*.html, verify the same.
  4. For every NON-issuer file (trace_report, victim_summary,
     engagement_letter, manifest, flow), verify the file type
     matches the filename extension.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

# Reuse the heavy fixture builder from the existing production-path test.
# This module is symlinked / colocated so the import works.
from tests.test_v_cfi01_production_path import (  # type: ignore[import-not-found]
    VICTIM,
    _build_editorial,
    _build_freeze_asks_dict,
    _build_issuer_metadata,
    _build_v_cfi01_case,
)


@pytest.fixture(scope="module")
def deliverables_dir() -> Path:
    """Run build_all_deliverables end-to-end and return the briefs/ dir."""
    from recupero.reports.brief import InvestigatorInfo
    from recupero.reports.emit_brief import emit_brief
    from recupero.reports.victim import VictimInfo
    from recupero.worker._deliverables import build_all_deliverables

    case = _build_v_cfi01_case()
    editorial = _build_editorial()
    freeze_asks = _build_freeze_asks_dict()
    issuer_metadata = _build_issuer_metadata()
    victim = VictimInfo(
        name="V-CFI01 Test Victim",
        wallet_address=VICTIM, state="NY", country="US",
        email="victim@test.com",
    )
    investigator = InvestigatorInfo(
        name="Test Investigator",
        organization="Recupero Forensics Ltd.",
        email="investigator@test.com",
    )
    brief_data = emit_brief(
        case=case, victim=victim, editorial=editorial,
        freeze_asks=freeze_asks, issuer_metadata=issuer_metadata,
    )
    tmp = tempfile.mkdtemp(prefix="jacob_forensic_")
    case_dir = Path(tmp)
    build_all_deliverables(
        case=case, victim=victim, freeze_brief=brief_data,
        case_dir=case_dir, investigator=investigator,
        skip_freeze_briefs=False,
    )
    return case_dir / "briefs"


# Each issuer's content-validation markers. compliance email is the
# strongest signal — it's a unique string per issuer that the
# template only emits when that issuer is the freeze-target.
_ISSUER_MARKERS = {
    "midas":    ["compliance@midas.app",     "Midas"],
    "tether":   ["compliance@tether.to",     "Tether"],
    "circle":   ["compliance@circle.com",    "Circle"],
    "coinbase": ["compliance@coinbase.com",  "Coinbase"],
}

# The OTHER issuers — any of these markers appearing in a freeze
# letter named for issuer X means the wrong content landed there.
_ISSUER_NEGATIVE_MARKERS = {
    "midas":    ["compliance@tether.to",     "compliance@circle.com",
                 "compliance@coinbase.com"],
    "tether":   ["compliance@midas.app",     "compliance@circle.com",
                 "compliance@coinbase.com"],
    "circle":   ["compliance@midas.app",     "compliance@tether.to",
                 "compliance@coinbase.com"],
    "coinbase": ["compliance@midas.app",     "compliance@tether.to",
                 "compliance@circle.com"],
}


def _find_issuer_files(briefs_dir: Path, prefix: str) -> dict[str, Path]:
    """Map issuer_slug -> path for every <prefix>_<issuer>_*.html."""
    result: dict[str, Path] = {}
    for path in briefs_dir.glob(f"{prefix}_*.html"):
        # Filename shape: freeze_request_<issuer>_BRIEF-V-CFI01-...html
        # or le_handoff_<issuer>_BRIEF-V-CFI01-...html
        stem = path.stem
        # Strip the prefix.
        if not stem.startswith(f"{prefix}_"):
            continue
        rest = stem[len(prefix) + 1:]
        # rest is e.g. "midas_BRIEF-V-CFI01-abc123"
        # The issuer slug is the first underscore-separated token.
        issuer_slug = rest.split("_", 1)[0]
        result[issuer_slug] = path
    return result


# ─────────────────────────────────────────────────────────────────────────────
# JACOB-1: routing — freeze_request_<X>_*.html contains content for X
# ─────────────────────────────────────────────────────────────────────────────


def test_freeze_request_content_matches_filename(deliverables_dir):
    """Per Jacob's review of v0.20.15: every freeze_request_<X>_*.html
    must contain content addressed to issuer X."""
    files = _find_issuer_files(deliverables_dir, "freeze_request")
    assert files, "No freeze_request_*.html files were produced"

    failures: list[str] = []
    for slug, path in files.items():
        content = path.read_text(encoding="utf-8")
        markers = _ISSUER_MARKERS.get(slug, [])
        negatives = _ISSUER_NEGATIVE_MARKERS.get(slug, [])
        # Positive check: the named issuer's markers must appear.
        for m in markers:
            if m not in content:
                failures.append(
                    f"{path.name}: expected marker {m!r} NOT FOUND. "
                    "Wrong issuer content routed to this path."
                )
        # Negative check: no OTHER issuer's compliance email may appear
        # (the email is a unique-per-issuer marker; appearing means
        # the wrong content was rendered).
        for n in negatives:
            if n in content:
                failures.append(
                    f"{path.name}: contains foreign marker {n!r}. "
                    "This is the v0.20.15 routing bug."
                )
    assert not failures, "\n".join(failures)


def test_le_handoff_content_matches_filename(deliverables_dir):
    """Same as above for LE handoff."""
    files = _find_issuer_files(deliverables_dir, "le_handoff")
    assert files, "No le_handoff_*.html files were produced"

    failures: list[str] = []
    for slug, path in files.items():
        content = path.read_text(encoding="utf-8")
        markers = _ISSUER_MARKERS.get(slug, [])
        # RIGOR-2 (F841): removed `negatives` lookup — Section 4.2 of
        # the LE handoff legitimately mentions every issuer in the
        # all_issuers_freezable inventory, so negative-marker
        # exclusion (which works on freeze_request letters) is wrong
        # here. Positive marker check is the right discipline. Pre-
        # cleanup the variable was assigned but never used.
        for m in markers:
            if m not in content:
                failures.append(
                    f"{path.name}: expected marker {m!r} NOT FOUND."
                )
    assert not failures, "\n".join(failures)


def test_non_issuer_files_have_correct_content_type(deliverables_dir):
    """Per Jacob's findings: trace_report_*.html should contain HTML,
    not LE Handoff or JSON. engagement_letter_*.html should be the
    engagement letter. manifest_*.json should be valid JSON."""
    failures: list[str] = []

    # 1. trace_report — should NOT have LE Handoff title.
    for path in deliverables_dir.glob("trace_report_*.html"):
        text = path.read_text(encoding="utf-8")
        if "<title>LE Handoff" in text:
            failures.append(
                f"{path.name}: title says LE Handoff — content "
                "scrambled across deliverable types"
            )
        if not text.lstrip().startswith("<"):
            failures.append(
                f"{path.name}: does not start with HTML — first 80 "
                f"chars: {text[:80]!r}"
            )

    # 2. engagement_letter — should be the engagement contract,
    # not freeze_brief.json structured data.
    for path in deliverables_dir.glob("engagement_letter_*.html"):
        text = path.read_text(encoding="utf-8")
        if text.lstrip().startswith("{"):
            failures.append(
                f"{path.name}: starts with JSON — freeze_brief.json "
                "got written here (cross-deliverable collision)"
            )

    # 3. manifest_*.json — should parse as JSON.
    for path in deliverables_dir.glob("manifest_*.json"):
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            failures.append(
                f"{path.name}: not valid JSON — HTML may have been "
                f"written here. parse error: {exc}"
            )

    # 4. victim_summary — should NOT contain manifest JSON.
    for path in deliverables_dir.glob("victim_summary_*.html"):
        text = path.read_text(encoding="utf-8")
        if text.lstrip().startswith("{") and '"outputs"' in text[:500]:
            failures.append(
                f"{path.name}: looks like the brief manifest JSON"
            )

    assert not failures, "\n".join(failures)


# ─────────────────────────────────────────────────────────────────────────────
# JACOB-2: STOLEN_ASSET_ISSUER vs FREEZE_TARGET_ISSUER conflation
# ─────────────────────────────────────────────────────────────────────────────


def test_le_handoff_does_not_conflate_stolen_asset_with_freeze_target(
    deliverables_dir,
):
    """Per Jacob's review: 'On 2025-10-09... 600,000 USDT was removed...
    The token is issued by Circle.' — USDT is Tether-issued. The
    template conflated STOLEN_ASSET_ISSUER (Tether) with
    FREEZE_TARGET_ISSUER (Circle).

    Check: the Section 1 Executive Summary paragraph (the one that
    narrates the original theft event) must name the STOLEN asset's
    real issuer.

    The OTHER paragraphs about how the perpetrator converted funds
    into the freeze-target's stablecoin (USDC for Circle, etc.) are
    legitimately about that stablecoin's issuer — not the bug we
    are checking for. We scope the check to Section 1 only.
    """
    import re
    files = _find_issuer_files(deliverables_dir, "le_handoff")
    failures: list[str] = []
    for slug, path in files.items():
        content = path.read_text(encoding="utf-8")
        if "USDT" not in content:
            continue
        # Extract the FIRST paragraph of Section 1 — the one that
        # narrates the original USDT theft event. Subsequent
        # paragraphs talk about the freeze-target's stablecoin
        # (USDC for Circle), where "issued by Circle" is correct.
        # The conflation bug specifically affects the FIRST paragraph.
        m = re.search(
            r"1\.\s*Executive Summary.*?<p[^>]*>(.*?)</p>",
            content, flags=re.DOTALL,
        )
        if not m:
            failures.append(
                f"{path.name}: could not locate Section 1 first paragraph"
            )
            continue
        first_para = m.group(1)
        # The first paragraph narrates the stolen USDT.
        # It MUST say "issued by Tether" and MUST NOT say
        # "issued by Circle/Coinbase/Midas".
        if "issued by Tether" not in first_para:
            failures.append(
                f"{path.name} Section 1 ¶1: missing 'issued by Tether' "
                "narration of the stolen USDT theft event."
            )
        for freeze_target in ["Circle", "Coinbase", "Midas"]:
            if f"issued by {freeze_target}" in first_para:
                failures.append(
                    f"{path.name} Section 1 ¶1: claims USDT is issued "
                    f"by {freeze_target}. USDT is Tether-issued; "
                    "STOLEN_ASSET_ISSUER and FREEZE_TARGET_ISSUER "
                    "are still conflated."
                )
    assert not failures, "\n".join(failures)
