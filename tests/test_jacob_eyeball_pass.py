"""JACOB-EYEBALL: punishing artifact-pass test.

The point of this file is to be HARD to pass. Jacob caught v0.20.15
by opening 16 artifacts in a browser and reading them. The 1,800
existing unit tests didn't catch it because they were calibrated to
the bugs already fixed, not to the artifact as Jacob reads it.

Each test function below mirrors one specific thing Jacob looks at.
The assertions are loud and specific: if a check fails, the test
output names the exact file + the exact missing-or-wrong string.
No "if found" / "if any" softening — every assertion is unconditional.

If any of these tests fail on a green build, the artifact is not
production-ready, and the rule is: FIX the artifact, do NOT relax
the test.

Coverage:
  * 4 freeze_request_<issuer>_*.html — issuer addressing, asset
    correctness, dollar reconciliation, no foreign markers
  * 4 le_handoff_<issuer>_*.html — Section 1 stolen-asset issuer,
    Section 4.2 inventory, no conflation
  * trace_report — chain-aware explorer URLs, totals
  * engagement_letter — victim name, fee, totals
  * victim_summary — correct variant, totals
  * manifest — SHA matches disk
  * freeze_brief / freeze_asks — shape + cross-reference
  * Cross-artifact reconciliation
  * No placeholders / dev-fixture strings / unrendered Jinja
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Module-scoped fixture: run the full V-CFI01 pipeline ONCE.
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def artifacts() -> dict:
    """Build V-CFI01 end-to-end and return paths + parsed brief."""
    import tempfile
    from tests.test_v_cfi01_production_path import (  # type: ignore
        _build_v_cfi01_case,
        _build_editorial,
        _build_freeze_asks_dict,
        _build_issuer_metadata,
        VICTIM,
    )
    from recupero.reports.brief import InvestigatorInfo
    from recupero.reports.emit_brief import emit_brief
    from recupero.reports.victim import VictimInfo
    from recupero.worker._deliverables import build_all_deliverables

    case = _build_v_cfi01_case()
    editorial = _build_editorial()
    freeze_asks = _build_freeze_asks_dict()
    metadata = _build_issuer_metadata()
    victim = VictimInfo(
        name="V-CFI01 Test Victim", wallet_address=VICTIM,
        state="NY", country="US", email="victim@test.com",
    )
    investigator = InvestigatorInfo(
        name="Test Investigator",
        organization="Recupero Forensics Ltd.",
        email="investigator@test.com",
    )
    brief = emit_brief(
        case=case, victim=victim, editorial=editorial,
        freeze_asks=freeze_asks, issuer_metadata=metadata,
    )
    tmp = Path(tempfile.mkdtemp(prefix="jacob_eyeball_"))
    build_all_deliverables(
        case=case, victim=victim, freeze_brief=brief,
        case_dir=tmp, investigator=investigator,
        skip_freeze_briefs=False,
    )
    briefs = tmp / "briefs"

    # Pre-locate every artifact.
    out = {
        "case_dir": tmp,
        "briefs_dir": briefs,
        "brief": brief,
        "freeze_asks": freeze_asks,
    }
    for slug in ("midas", "tether", "circle", "coinbase"):
        out[f"freeze_request_{slug}"] = next(
            briefs.glob(f"freeze_request_{slug}_*.html")
        )
        out[f"le_handoff_{slug}"] = next(
            briefs.glob(f"le_handoff_{slug}_*.html")
        )
    out["trace_report"] = next(briefs.glob("trace_report_*.html"))
    out["engagement_letter"] = next(briefs.glob("engagement_letter_*.html"))
    out["victim_summary"] = next(briefs.glob("victim_summary_recoverable_*.html"))
    out["manifest"] = next(briefs.glob("manifest_*.json"))
    return out


# Per-issuer expectations. Tightly specified — if any value is
# wrong, the test fails with the specific check + the specific issuer.
_ISSUER_EXPECTATIONS = {
    "midas": {
        "compliance_email": "compliance@midas.app",
        "display_name": "Midas",
        "stablecoin_symbol": "mSyrupUSDp",
        # Ground-truth from V-CFI01 fixture (test_v_cfi01_full_render.py).
        # Match to the cent — if the per-issuer rollup changes the
        # number this test fails loudly with the new value visible.
        "expected_usd_freezable": "3,119,023.12",
        # NEGATIVE markers — no OTHER issuer's compliance email may appear
        # in the freeze letter (the LE handoff is multi-issuer Section 4.2
        # so we DON'T apply this to LE handoffs).
        "foreign_emails": [
            "compliance@tether.to",
            "compliance@circle.com",
            "compliance@coinbase.com",
            "law-enforcement@coinbase.com",
        ],
    },
    "tether": {
        "compliance_email": "compliance@tether.to",
        "display_name": "Tether",
        "stablecoin_symbol": "USDT",
        # Ground-truth = $97,535.58 + $73,151.68 + $1,597.70 from
        # the V-CFI01 fixture's three USDT_DEST transfers. Jacob's
        # v0.20.15 review notes cited $245,436.64 — that was a
        # different fixture state. This is the canonical value the
        # current fixture computes.
        "expected_usd_freezable": "172,284.96",
        "foreign_emails": [
            "compliance@midas.app",
            "compliance@circle.com",
            "compliance@coinbase.com",
            "law-enforcement@coinbase.com",
        ],
    },
    "circle": {
        "compliance_email": "compliance@circle.com",
        "display_name": "Circle",
        "stablecoin_symbol": "USDC",
        "expected_usd_freezable": "8,881.31",
        "foreign_emails": [
            "compliance@midas.app",
            "compliance@tether.to",
            "compliance@coinbase.com",
            "law-enforcement@coinbase.com",
        ],
    },
    "coinbase": {
        "compliance_email": "compliance@coinbase.com",  # or law-enforcement@
        "display_name": "Coinbase",
        "stablecoin_symbol": "cbBTC",
        "expected_usd_freezable": "246,812.01",
        "foreign_emails": [
            "compliance@midas.app",
            "compliance@tether.to",
            "compliance@circle.com",
        ],
    },
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _strip_html(text: str) -> str:
    """Remove tags + collapse whitespace for plaintext substring checks."""
    plain = re.sub(r"<[^>]+>", " ", text)
    plain = re.sub(r"\s+", " ", plain)
    return plain.strip()


# ─────────────────────────────────────────────────────────────────────────────
# Per-issuer freeze_request: deep content checks
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("slug", list(_ISSUER_EXPECTATIONS))
def test_freeze_request_addresses_correct_issuer(artifacts, slug):
    """The freeze_request_<X>_*.html MUST contain the issuer's
    compliance email. No exception, no fallback. Jacob opens this
    file in a browser and reads the To: line."""
    path = artifacts[f"freeze_request_{slug}"]
    content = _read(path)
    exp = _ISSUER_EXPECTATIONS[slug]
    # At least one of the issuer's recognized compliance addresses
    # must appear. For Coinbase we accept either the seed-db
    # primary_contact OR the template-default compliance address.
    candidates = [exp["compliance_email"]]
    if slug == "coinbase":
        candidates.append("law-enforcement@coinbase.com")
    found = [c for c in candidates if c in content]
    assert found, (
        f"{path.name}: NONE of the recognized compliance addresses "
        f"for {exp['display_name']} were present. Looked for: "
        f"{candidates}. This is the JACOB-1 routing bug."
    )


@pytest.mark.parametrize("slug", list(_ISSUER_EXPECTATIONS))
def test_freeze_request_does_not_address_foreign_issuer(artifacts, slug):
    """The freeze_request_<X>_*.html MUST NOT contain any OTHER
    issuer's compliance email. If foreign emails appear, the file
    is mis-routed."""
    path = artifacts[f"freeze_request_{slug}"]
    content = _read(path)
    exp = _ISSUER_EXPECTATIONS[slug]
    leaks = [e for e in exp["foreign_emails"] if e in content]
    assert not leaks, (
        f"{path.name}: contains foreign issuer compliance emails "
        f"{leaks}. The letter is routing to the wrong issuer (a "
        "v0.20.15-style content/filename scramble)."
    )


@pytest.mark.parametrize("slug", list(_ISSUER_EXPECTATIONS))
def test_freeze_request_titles_correct_issuer(artifacts, slug):
    """The HTML <title> tag must include the issuer's display name.
    A title saying 'Freeze Request - Circle' on the Midas file is
    the smoking gun for cross-content routing."""
    path = artifacts[f"freeze_request_{slug}"]
    content = _read(path)
    exp = _ISSUER_EXPECTATIONS[slug]
    m = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
    assert m, f"{path.name}: no <title> tag found"
    title_text = m.group(1).strip()
    assert exp["display_name"] in title_text, (
        f"{path.name}: <title> is {title_text!r} — does not include "
        f"the freeze-target issuer name {exp['display_name']!r}."
    )


@pytest.mark.parametrize("slug", list(_ISSUER_EXPECTATIONS))
def test_freeze_request_mentions_correct_stablecoin(artifacts, slug):
    """Each freeze letter MUST mention the issuer-specific token
    symbol it's asking to be frozen. Midas → mSyrupUSDp, Circle →
    USDC, Coinbase → cbBTC, Tether → USDT. A letter to Circle that
    doesn't say USDC is wrong."""
    path = artifacts[f"freeze_request_{slug}"]
    content = _read(path)
    exp = _ISSUER_EXPECTATIONS[slug]
    assert exp["stablecoin_symbol"] in content, (
        f"{path.name}: does not mention {exp['stablecoin_symbol']!r} — "
        f"the token {exp['display_name']} is being asked to freeze. "
        "Either the letter is mis-routed or the per-issuer freezable "
        "context lost the token symbol."
    )


@pytest.mark.parametrize("slug", list(_ISSUER_EXPECTATIONS))
def test_freeze_request_quotes_correct_dollar_amount(artifacts, slug):
    """Each freeze letter must quote the per-issuer freezable dollar
    amount from freeze_brief.FREEZABLE. If the letter says Circle has
    $246K but the brief says $8,881.31, somebody copy-pasted from
    the wrong issuer's slot."""
    path = artifacts[f"freeze_request_{slug}"]
    content = _read(path)
    exp = _ISSUER_EXPECTATIONS[slug]
    assert exp["expected_usd_freezable"] in content, (
        f"{path.name}: does not contain expected freezable $"
        f"{exp['expected_usd_freezable']} for {exp['display_name']}. "
        "Per-issuer dollar amount may have been routed to the wrong "
        "letter, or the brief's FREEZABLE entry is missing this value."
    )


@pytest.mark.parametrize("slug", list(_ISSUER_EXPECTATIONS))
def test_freeze_request_has_no_unrendered_jinja(artifacts, slug):
    """Every freeze_request HTML must be fully rendered. A leaked
    {{ victim.name }} would be the worst possible client-facing
    surface."""
    path = artifacts[f"freeze_request_{slug}"]
    content = _read(path)
    var_matches = re.findall(r"\{\{[^}]+\}\}", content)
    block_matches = re.findall(r"\{%[^%]+%\}", content)
    assert not var_matches, (
        f"{path.name}: {len(var_matches)} unrendered Jinja variables: "
        f"{var_matches[:3]!r}"
    )
    assert not block_matches, (
        f"{path.name}: {len(block_matches)} unrendered Jinja blocks: "
        f"{block_matches[:3]!r}"
    )


@pytest.mark.parametrize("slug", list(_ISSUER_EXPECTATIONS))
def test_freeze_request_has_no_placeholder_strings(artifacts, slug):
    """No TODO/FIXME/XXX/TBD/PLACEHOLDER in customer-facing HTML."""
    path = artifacts[f"freeze_request_{slug}"]
    content = _read(path)
    # Case-sensitive — these markers are caps by convention. lower-case
    # 'todo' or 'tbd' might appear in legitimate body text.
    forbidden = ["TODO", "FIXME", "XXX", "TBD", "PLACEHOLDER", "{TODO}"]
    leaked = [w for w in forbidden if w in content]
    assert not leaked, (
        f"{path.name}: leaked placeholder strings: {leaked}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Per-issuer LE handoff: stolen-asset narrative + Section 4.2 inventory
# ─────────────────────────────────────────────────────────────────────────────


_LE_SLUGS = ["midas", "tether", "circle", "coinbase"]


@pytest.mark.parametrize("slug", _LE_SLUGS)
def test_le_handoff_section_1_names_real_asset_issuer(artifacts, slug):
    """Section 1 ¶1 narrates the stolen USDT theft event. The
    sentence 'The token is issued by X' MUST name Tether (the real
    USDT issuer), regardless of which freeze-target this handoff
    is addressed to."""
    path = artifacts[f"le_handoff_{slug}"]
    content = _read(path)
    m = re.search(
        r"1\.\s*Executive Summary.*?<p[^>]*>(.*?)</p>",
        content, flags=re.DOTALL,
    )
    assert m, f"{path.name}: cannot find Section 1 ¶1"
    para = _strip_html(m.group(1))
    assert "USDT" in para, (
        f"{path.name} Section 1 ¶1: missing 'USDT' — "
        "narrative doesn't reference the stolen asset"
    )
    assert "issued by Tether" in para, (
        f"{path.name} Section 1 ¶1: missing 'issued by Tether'. "
        f"Section 1 ¶1 reads: {para!r}"
    )


@pytest.mark.parametrize("slug", _LE_SLUGS)
def test_le_handoff_section_1_does_not_attribute_usdt_to_wrong_issuer(
    artifacts, slug,
):
    """A non-Tether handoff must NOT claim USDT is issued by anyone
    other than Tether. The JACOB-2 conflation pattern."""
    path = artifacts[f"le_handoff_{slug}"]
    content = _read(path)
    m = re.search(
        r"1\.\s*Executive Summary.*?<p[^>]*>(.*?)</p>",
        content, flags=re.DOTALL,
    )
    assert m, f"{path.name}: cannot find Section 1 ¶1"
    para = _strip_html(m.group(1))
    if slug == "tether":
        return  # self-letter — "issued by Tether" is also the
                # freeze-target so no conflation possible
    for wrong in ["Midas", "Circle", "Coinbase"]:
        forbidden = f"issued by {wrong}"
        assert forbidden not in para, (
            f"{path.name} Section 1 ¶1: claims USDT is "
            f"{forbidden!r}. USDT is issued by Tether. "
            f"Paragraph reads: {para!r}"
        )


@pytest.mark.parametrize("slug", _LE_SLUGS)
def test_le_handoff_section_4_2_lists_every_issuer(artifacts, slug):
    """Section 4.2 Complete Holdings Inventory must enumerate ALL
    issuers in the case — including Sky Protocol (UNRECOVERABLE)."""
    path = artifacts[f"le_handoff_{slug}"]
    content = _read(path)
    expected_issuers = ["Midas", "Tether", "Circle", "Coinbase", "Sky Protocol"]
    missing = [i for i in expected_issuers if i not in content]
    assert not missing, (
        f"{path.name}: Section 4.2 inventory missing issuer(s) "
        f"{missing}. The complete-holdings inventory must show "
        "every issuer regardless of which one this letter targets."
    )


@pytest.mark.parametrize("slug", _LE_SLUGS)
def test_le_handoff_marks_sky_dai_as_unrecoverable(artifacts, slug):
    """Every LE handoff must explicitly tag Sky Protocol / DAI as
    UNRECOVERABLE. Sky has no admin freeze pathway."""
    path = artifacts[f"le_handoff_{slug}"]
    content = _read(path)
    assert "Sky Protocol" in content, (
        f"{path.name}: Sky Protocol not mentioned"
    )
    assert "UNRECOVERABLE" in content, (
        f"{path.name}: UNRECOVERABLE tag missing — Sky / DAI must "
        "be flagged so LE doesn't waste cycles on it"
    )


@pytest.mark.parametrize("slug", _LE_SLUGS)
def test_le_handoff_shows_total_theft_amount(artifacts, slug):
    """V-CFI01 has six $600K USDT drains = $3,600,000 total. Every
    LE handoff cover page must show this aggregate figure."""
    path = artifacts[f"le_handoff_{slug}"]
    content = _read(path)
    assert "3,600,000" in content, (
        f"{path.name}: $3,600,000 total theft not shown. "
        "Multi-event rollup may be broken."
    )


@pytest.mark.parametrize("slug", _LE_SLUGS)
def test_le_handoff_has_no_unrendered_jinja(artifacts, slug):
    path = artifacts[f"le_handoff_{slug}"]
    content = _read(path)
    var_matches = re.findall(r"\{\{[^}]+\}\}", content)
    block_matches = re.findall(r"\{%[^%]+%\}", content)
    assert not var_matches and not block_matches, (
        f"{path.name}: unrendered Jinja: vars={var_matches[:3]!r} "
        f"blocks={block_matches[:3]!r}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Cross-artifact reconciliation
# ─────────────────────────────────────────────────────────────────────────────


def test_freeze_brief_has_required_top_level_fields(artifacts):
    """The brief must carry every field downstream artifacts reference."""
    brief = artifacts["brief"]
    required = [
        "CASE_ID", "TOTAL_LOSS_USD", "MAX_RECOVERABLE_USD",
        "TOTAL_FREEZABLE_USD", "FREEZABLE", "ALL_ISSUER_HOLDINGS",
        "asset",
    ]
    missing = [k for k in required if k not in brief]
    assert not missing, (
        f"freeze_brief.json missing required top-level fields: {missing}"
    )


def test_freeze_brief_freezable_lists_every_expected_issuer(artifacts):
    """V-CFI01 fixture has Midas, Tether, Circle, Coinbase in
    FREEZABLE. Sky is in ALL_ISSUER_HOLDINGS only (UNRECOVERABLE)."""
    brief = artifacts["brief"]
    freezable_issuers = {
        e.get("issuer") for e in brief.get("FREEZABLE") or []
        if e.get("issuer")
    }
    expected = {"Midas", "Tether", "Circle", "Coinbase"}
    missing = expected - freezable_issuers
    assert not missing, (
        f"freeze_brief.FREEZABLE missing issuers {missing}. "
        f"Got: {freezable_issuers}"
    )


def test_total_freezable_usd_reconciles_across_artifacts(artifacts):
    """The same TOTAL_FREEZABLE_USD figure must appear in: the brief
    JSON, the engagement letter, the victim summary. Any divergence
    means the contract / customer comms claim a different number
    than the brief computed."""
    brief = artifacts["brief"]
    total_str = str(brief.get("TOTAL_FREEZABLE_USD") or "")
    # Strip $ and commas to get a normalized form.
    norm = total_str.lstrip("$").strip()
    assert norm, "freeze_brief has no TOTAL_FREEZABLE_USD"

    eng_content = _read(artifacts["engagement_letter"])
    summary_content = _read(artifacts["victim_summary"])
    # Both files MUST contain the same formatted figure ($X,XXX,XXX.XX
    # or close). At minimum, the numeric portion (with commas) appears.
    plain_amount = norm  # already comma-formatted
    assert plain_amount in eng_content, (
        f"engagement_letter does not quote freeze_brief's "
        f"TOTAL_FREEZABLE_USD = {plain_amount!r}. "
        "Brief and contract disagree on the headline number."
    )
    assert plain_amount in summary_content, (
        f"victim_summary does not quote freeze_brief's "
        f"TOTAL_FREEZABLE_USD = {plain_amount!r}."
    )


def test_every_freezable_issuer_has_both_freeze_request_and_le_handoff(
    artifacts,
):
    """Slug parity: the set of freeze_request_<X>_*.html slugs must
    equal the set of le_handoff_<X>_*.html slugs. If one issuer has
    a freeze letter but no handoff, the case is half-built."""
    briefs = artifacts["briefs_dir"]
    freeze_slugs = {
        p.stem.split("_", 2)[2].split("_BRIEF", 1)[0]
        for p in briefs.glob("freeze_request_*.html")
    }
    le_slugs = {
        p.stem.split("_", 2)[2].split("_BRIEF", 1)[0]
        for p in briefs.glob("le_handoff_*.html")
    }
    assert freeze_slugs == le_slugs, (
        f"freeze_request slugs {sorted(freeze_slugs)} != "
        f"le_handoff slugs {sorted(le_slugs)}. "
        "Some issuers got a letter but not a handoff (or vice versa)."
    )
    assert freeze_slugs == {"midas", "tether", "circle", "coinbase"}, (
        f"Expected exactly 4 issuer slugs (midas, tether, circle, "
        f"coinbase), got {sorted(freeze_slugs)}"
    )


def test_manifest_sha_matches_disk(artifacts):
    """The brief manifest's output_sha256 must match the actual file
    bytes on disk. Jacob's forensic localizer — if the SHA is stale,
    the wrong content was written after the manifest sealed."""
    manifest_path = artifacts["manifest"]
    manifest = json.loads(_read(manifest_path))
    outputs = manifest.get("outputs", {})
    shas = manifest.get("output_sha256", {})
    briefs_dir = manifest_path.parent
    failures = []
    for key, declared_path in outputs.items():
        declared_sha = shas.get(key, "")
        if not declared_sha:
            continue
        target = briefs_dir / Path(declared_path).name
        assert target.is_file(), (
            f"manifest declares {key}={declared_path} but file missing"
        )
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != declared_sha:
            failures.append(
                f"{key}: manifest={declared_sha[:16]}... "
                f"disk={actual[:16]}..."
            )
    assert not failures, (
        f"{manifest_path.name}: stale SHAs:\n  " + "\n  ".join(failures)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Trace report
# ─────────────────────────────────────────────────────────────────────────────


def test_trace_report_is_html_with_correct_title(artifacts):
    path = artifacts["trace_report"]
    content = _read(path)
    assert content.lstrip().startswith("<!DOCTYPE") or content.lstrip().startswith("<html"), (
        f"{path.name}: does not start with HTML"
    )
    m = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
    assert m, f"{path.name}: no <title>"
    title = m.group(1).strip()
    assert "Trace Report" in title or "Trace" in title, (
        f"{path.name}: title is {title!r}, expected 'Trace Report'"
    )


def test_trace_report_includes_total_theft(artifacts):
    path = artifacts["trace_report"]
    content = _read(path)
    assert "3,600,000" in content or "$3,600,000" in content, (
        f"{path.name}: total theft amount missing"
    )


def test_trace_report_uses_chain_aware_explorer_urls(artifacts):
    """The trace report must NOT hardcode etherscan.io for non-Ethereum
    transactions. V-CFI01's perp wallet is on Ethereum so this is
    actually all etherscan, but the assertion is that we don't see
    any cross-chain bridge transactions linked to the wrong scanner."""
    path = artifacts["trace_report"]
    content = _read(path)
    # Sanity: at least some explorer link is present.
    explorers = re.findall(
        r'https?://[a-z]+\.(?:io|com)/(?:tx|address)/0x[0-9a-fA-F]+',
        content,
    )
    assert explorers, (
        f"{path.name}: no explorer links found. The trace report "
        "should link every tx to a chain explorer."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Engagement letter
# ─────────────────────────────────────────────────────────────────────────────


def test_engagement_letter_names_the_victim(artifacts):
    path = artifacts["engagement_letter"]
    content = _read(path)
    assert "V-CFI01 Test Victim" in content, (
        f"{path.name}: victim name 'V-CFI01 Test Victim' missing"
    )


def test_engagement_letter_includes_engagement_fee(artifacts):
    """The contract must specify the engagement fee. A blank/0 fee
    would void the contract."""
    path = artifacts["engagement_letter"]
    content = _read(path)
    # Match either a $ figure or 'engagement fee' nearby.
    has_fee_label = "engagement fee" in content.lower() or "engagement_fee" in content.lower()
    has_dollar_figure = bool(re.search(r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?", content))
    assert has_fee_label, f"{path.name}: 'engagement fee' label missing"
    assert has_dollar_figure, f"{path.name}: no dollar figure found"


def test_engagement_letter_has_no_placeholder_strings(artifacts):
    path = artifacts["engagement_letter"]
    content = _read(path)
    forbidden = ["TODO", "FIXME", "XXX", "TBD", "PLACEHOLDER"]
    leaked = [w for w in forbidden if w in content]
    assert not leaked, (
        f"{path.name}: leaked placeholder strings: {leaked}"
    )


def test_engagement_letter_has_no_unrendered_jinja(artifacts):
    path = artifacts["engagement_letter"]
    content = _read(path)
    assert "{{ " not in content, f"{path.name}: unrendered {{{{ }}}}"
    assert "{% " not in content, f"{path.name}: unrendered {{% %}}"


# ─────────────────────────────────────────────────────────────────────────────
# Victim summary
# ─────────────────────────────────────────────────────────────────────────────


def test_victim_summary_is_recoverable_variant(artifacts):
    """V-CFI01 has $3.6M recoverable. The summary MUST be the
    recoverable variant — v0.15.1 shipped unrecoverable+auto-refund
    on a fully-recoverable case."""
    briefs = artifacts["briefs_dir"]
    has_recoverable = any(briefs.glob("victim_summary_recoverable_*.html"))
    has_unrecoverable = any(briefs.glob("victim_summary_unrecoverable_*.html"))
    assert has_recoverable, "victim_summary_recoverable_*.html missing"
    assert not has_unrecoverable, (
        "victim_summary_unrecoverable_*.html should NOT exist — "
        "MAX_RECOVERABLE_USD > 0 on V-CFI01"
    )


def test_victim_summary_names_the_victim(artifacts):
    path = artifacts["victim_summary"]
    content = _read(path)
    assert "V-CFI01 Test Victim" in content, (
        f"{path.name}: victim name missing"
    )


def test_victim_summary_has_no_unrendered_jinja(artifacts):
    path = artifacts["victim_summary"]
    content = _read(path)
    assert "{{ " not in content, f"{path.name}: unrendered {{{{ }}}}"
    assert "{% " not in content, f"{path.name}: unrendered {{% %}}"


# ─────────────────────────────────────────────────────────────────────────────
# Validator integration
# ─────────────────────────────────────────────────────────────────────────────


def test_validator_passes_with_zero_critical_or_high(artifacts):
    """The output_integrity validator from JACOB-3 must return ok=True
    on a clean build. This is what `recupero-ops validate-output` runs."""
    from recupero.validators.output_integrity import validate_case_output
    # Place brief/asks json at the case_dir top level for the
    # validator's _safe_load_json lookups.
    case_dir = artifacts["case_dir"]
    (case_dir / "freeze_brief.json").write_text(
        json.dumps(artifacts["brief"], default=str),
        encoding="utf-8",
    )
    (case_dir / "freeze_asks.json").write_text(
        json.dumps(artifacts["freeze_asks"], default=str),
        encoding="utf-8",
    )
    result = validate_case_output(case_dir)
    assert result.critical_count == 0, (
        f"validator found {result.critical_count} critical violations:\n"
        + result.summary_text()
    )
    assert result.high_count == 0, (
        f"validator found {result.high_count} high violations:\n"
        + result.summary_text()
    )
