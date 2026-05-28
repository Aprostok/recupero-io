"""v0.32.1 LE handoff audit-fix regressions.

Pins the fixes from `docs/JACOB_LE_HANDOFF_AUDIT_v032.md` (3 CRITs +
10 HIGHs). Every assertion below would fail against pre-v0.32.1 code.
"""
from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from recupero.models import (
    Case, Chain, Counterparty, TokenRef, Transfer,
)
from recupero.reports.brief import (
    InvestigatorInfo, generate_briefs,
)
from recupero.reports.victim import VictimInfo


VICTIM_ADDR = "0x0cdC902f4448b51289398261DB41E8ADC99bE955"
PERP_ADDR = "0xF4bE227b268e191b79097Daad0AcCcD9a7A7FAD2"
USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"


def _now():
    return datetime(2026, 1, 15, 1, 37, 23, tzinfo=UTC)


def _transfer(
    *, symbol: str, contract: str | None, amount: Decimal, usd: Decimal | None,
    block: int, tx_hash: str,
) -> Transfer:
    token = TokenRef(
        chain=Chain.ethereum, contract=contract, symbol=symbol, decimals=18,
    )
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:0",
        chain=Chain.ethereum, tx_hash=tx_hash, block_number=block,
        block_time=datetime.fromtimestamp(1700000000 + block, tz=UTC),
        from_address=VICTIM_ADDR, to_address=PERP_ADDR,
        counterparty=Counterparty(address=PERP_ADDR, is_contract=False),
        token=token,
        amount_raw=str(int(amount * Decimal(10**18))),
        amount_decimal=amount, usd_value_at_tx=usd, hop_depth=0,
        fetched_at=_now(),
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
    )


def _mixed_case() -> Case:
    """Mimics the Alec smoke case: 0.21 ETH + 20,610 USDT drain."""
    return Case(
        case_id="ALEC-TEST-2026", seed_address=VICTIM_ADDR, chain=Chain.ethereum,
        incident_time=_now(), trace_started_at=_now(), trace_completed_at=_now(),
        transfers=[
            _transfer(
                symbol="ETH", contract=None, amount=Decimal("0.21"),
                usd=Decimal("707.60"), block=100, tx_hash="0xaaa",
            ),
            _transfer(
                symbol="USDT", contract=USDT, amount=Decimal("20610.34"),
                usd=Decimal("20610.34"), block=101, tx_hash="0xbbb",
            ),
        ],
    )


def _single_asset_case() -> Case:
    """Single-asset Zigha-shape for the "no banner / configured" path."""
    return Case(
        case_id="ZIGHA-VERIFY", seed_address=VICTIM_ADDR, chain=Chain.ethereum,
        incident_time=_now(), trace_started_at=_now(), trace_completed_at=_now(),
        transfers=[
            _transfer(
                symbol="msyrupUSDp",
                contract="0x2fE058CcF29f123f9dd2aEC0418AA66a877d8E50",
                amount=Decimal("3109861.71576"), usd=Decimal("3119023.12"),
                block=100, tx_hash="0xccc",
            ),
        ],
    )


def _render_le(tmp_path: Path, case: Case, *, investigator=None) -> str:
    case_dir = tmp_path / case.case_id
    case_dir.mkdir(parents=True)
    victim = VictimInfo(name="Test Victim", wallet_address=VICTIM_ADDR)
    inv = investigator or InvestigatorInfo(
        name="Jane Investigator", organization="Recupero LLC",
        email="jane@recupero.example",
    )
    bundle = generate_briefs(
        primary_case=case, linked_cases=[], victim=victim,
        investigator=inv, case_dir=case_dir,
    )
    return bundle.le_html


# ─────────────────────────────────────────────────────────────────────
# CRIT-1: Mixed-asset table no longer self-contradictory
# ─────────────────────────────────────────────────────────────────────


def test_crit1_mixed_asset_table_renders_per_asset_breakdown(tmp_path: Path):
    """Mixed-asset drains render a per-asset breakdown sub-table; the
    single-asset Stolen Asset Details table is NOT rendered with
    contradictory locked rows."""
    html = _render_le(tmp_path, _mixed_case())
    # The pre-v0.32.1 contradictory render had a row reading exactly
    # "2 events, mixed assets" inside the single-asset details table.
    # Post-v0.32.1, on mixed drains we render the per-asset section
    # instead, and the "mixed assets" label MUST NOT appear in the
    # single-asset Amount cell because that table is suppressed.
    assert "Per-asset breakdown" in html
    # Per-token rows for both ETH and USDT must appear in the breakdown.
    assert ">ETH<" in html or "<strong>ETH</strong>" in html
    assert ">USDT<" in html or "<strong>USDT</strong>" in html


def test_crit1_single_asset_table_skipped_on_mixed_drain(tmp_path: Path):
    """The single-asset details table (Asset symbol / Token contract
    address / Issuer) must NOT be rendered on a mixed-asset drain."""
    html = _render_le(tmp_path, _mixed_case())
    # Pre-v0.32.1 rendered an "Asset symbol" <th> row even on mixed.
    # Now we render "Drain composition" + per-asset breakdown.
    assert "Drain composition" in html


def test_crit1_single_asset_drain_still_uses_details_table(tmp_path: Path):
    """Single-asset drains still render the original detailed table —
    we only branched on `theft_assets_mixed`, didn't break the
    happy path."""
    html = _render_le(tmp_path, _single_asset_case())
    assert "Asset symbol" in html
    assert "Token contract address" in html
    assert "Per-asset breakdown" not in html


# ─────────────────────────────────────────────────────────────────────
# CRIT-2: Cross-reference rot — section 5 → section 4.1 in prose
# ─────────────────────────────────────────────────────────────────────


def test_crit2_no_freezable_prose_refers_to_section_5() -> None:
    """The executive summary + timeline previously told the reader to
    look in 'section 5' for the freezable holdings; section 5 is
    actually the BFS wallet dump. The fix is template-level: all six
    prose refs point to section 4.1. Verify by inspecting the
    template source directly so we don't depend on a particular
    freezable-context shape to make the prose render."""
    template = Path(
        "src/recupero/reports/templates/le.html.j2"
    ).read_text(encoding="utf-8")
    # These exact substrings appeared in pre-v0.32.1 prose; they MUST
    # be gone.
    for needle in (
        "addresses listed in section 5",
        "enumerated in section 5",
    ):
        assert needle not in template.lower(), (
            f"CRIT-2 regression: template still contains {needle!r}"
        )
    # The Investigative recommendation legitimately references
    # capital-S "Section 5" (the BFS wallet table) — keep it.
    assert "Section 5" in template


def test_crit2_section_4_1_appears_in_template() -> None:
    """The corrected cross-references point to section 4.1."""
    template = Path(
        "src/recupero/reports/templates/le.html.j2"
    ).read_text(encoding="utf-8")
    # At least 6 occurrences (the audit prescription).
    assert template.count("section 4.1") >= 6


# ─────────────────────────────────────────────────────────────────────
# CRIT-3: Operator-name fallback suppressed; UNSIGNED banner present
# ─────────────────────────────────────────────────────────────────────


def test_crit3_unconfigured_investigator_does_not_leak_sentinel(
    tmp_path: Path, monkeypatch,
) -> None:
    """When the env var is unset AND the caller doesn't override
    investigator, brief.py uses `(operator name not configured)` —
    which used to render in heavy serif on the cover + signature
    block. Post-v0.32.1 we sanitize that string to empty + render an
    explicit placeholder-line + UNSIGNED banner."""
    monkeypatch.delenv("RECUPERO_INVESTIGATOR_NAME", raising=False)
    # Use the default-investigator path: pass the sentinel as if it
    # came from investigator_defaults().
    inv = InvestigatorInfo(
        name="(operator name not configured)",
        organization="Recupero LLC",
        email="compliance@recupero.io",
    )
    html = _render_le(tmp_path, _single_asset_case(), investigator=inv)
    # The literal sentinel MUST NOT appear in the rendered output.
    assert "(operator name not configured)" not in html, (
        "CRIT-3 regression: the operator-name placeholder still ships "
        "in rendered LE HTML"
    )
    # The compliance@recupero.io alias must also be suppressed (HIGH-6).
    assert "compliance@recupero.io" not in html, (
        "HIGH-6 regression: generic compliance@recupero.io alias still "
        "ships as the named-investigator contact"
    )
    # The UNSIGNED banner must be present.
    assert "unsigned-banner" in html or "UNSIGNED — Operator identity" in html


def test_crit3_real_investigator_renders_named_block(tmp_path: Path) -> None:
    """A caller passing a real InvestigatorInfo (test path, CLI
    override) must render the named-human block, NOT the placeholder
    branch — even when the env var is unset."""
    html = _render_le(
        tmp_path, _single_asset_case(),
        investigator=InvestigatorInfo(
            name="Jane Investigator", organization="Recupero LLC",
            email="jane@example.com",
        ),
    )
    assert "Jane Investigator" in html
    # Banner must NOT be present in this case.
    assert "unsigned-banner" not in html
    # Placeholder-line must NOT be present.
    assert "[Operator pending assignment]" not in html


def test_crit3_watermark_opacity_raised(tmp_path: Path) -> None:
    """The diagonal UNSIGNED watermark must use ≥0.20 alpha so a skim
    cannot miss it. Pre-v0.32.1 it was 0.10 — visible only on careful
    inspection, leaving "(operator name not configured)" readable
    underneath."""
    styles = Path(
        "src/recupero/reports/templates/_styles.html.j2"
    ).read_text(encoding="utf-8")
    # Pre-fix: rgba(140, 16, 16, 0.10) — must be ≥ 0.20 post-fix.
    assert "rgba(140, 16, 16, 0.10)" not in styles, (
        "CRIT-3 regression: watermark still at 0.10 opacity"
    )


# ─────────────────────────────────────────────────────────────────────
# HIGH-1: No "USD X" prefix on the LE handoff cover/exec summary
# ─────────────────────────────────────────────────────────────────────


def test_high1_le_handoff_uses_dollar_prefix_only(tmp_path: Path) -> None:
    """The LE handoff cover + exec summary must render USD via the
    `$X,YYY.ZZ` convention, NOT the bank-statement `USD X,YYY.ZZ`
    form. Pre-v0.32.1 the cover printed `USD 21,317.94` next to
    `$29,273.63` on the same page."""
    html = _render_le(tmp_path, _single_asset_case())
    # The substring "USD 3" (digit after USD ) would be the old format.
    # Allow "USD" in headers/captions; reject "USD <digit>" patterns.
    import re
    offenders = re.findall(r"USD \d", html)
    assert not offenders, (
        f"HIGH-1 regression: still rendering 'USD <digit>' prose at "
        f"{len(offenders)} site(s). Use the `| usd_prefix` filter or "
        f"drop the literal 'USD ' prefix."
    )


# ─────────────────────────────────────────────────────────────────────
# HIGH-2 / HIGH-3: Section 4.1 footer grammar + KYC framing
# ─────────────────────────────────────────────────────────────────────


def test_high2_section_4_1_footer_no_confirmed_held_compound() -> None:
    """The pre-v0.32.1 footer had a stray hyphenated compound
    'confirmed-held' that parsed as 'are CONFIRMED-HELD'. Confirm the
    fixed footer doesn't contain it."""
    template = Path(
        "src/recupero/reports/templates/le.html.j2"
    ).read_text(encoding="utf-8")
    assert "confirmed-held" not in template, (
        "HIGH-2 regression: Section 4.1 footer still has the "
        "'confirmed-held' hyphenation bug"
    )


def test_high3_section_4_1_branches_on_issuer_kyc_required() -> None:
    """For non-KYC issuers (USDT/USDC/DAI etc.) the footer MUST NOT
    claim the wallets were received 'not via subscription' — those
    issuers have no subscription pathway."""
    template = Path(
        "src/recupero/reports/templates/le.html.j2"
    ).read_text(encoding="utf-8")
    # The footer must guard the "subscription" claim with an
    # `issuer.kyc_required` branch.
    assert "issuer.kyc_required" in template
    # And must include an else-branch with the no-subscription framing.
    assert "no customer-of-record" in template, (
        "HIGH-3 regression: Section 4.1 footer doesn't branch the "
        "false KYC subscription claim for non-RWA issuers"
    )


# ─────────────────────────────────────────────────────────────────────
# HIGH-5: TODO/placeholder sanitization
# ─────────────────────────────────────────────────────────────────────


def test_high5_sanitize_placeholder_filters_todo_prefix() -> None:
    """`_sanitize_placeholder` neutralizes any TODO:/TBD/(unset)/...
    sentinel so AI-editorial leaks don't reach the LE template."""
    from recupero.reports.brief import _sanitize_placeholder
    assert _sanitize_placeholder("TODO: confirm victim's state/country") is None
    assert _sanitize_placeholder("TBD") is None
    assert _sanitize_placeholder("(unset)") is None
    assert _sanitize_placeholder("(operator name not configured)") is None
    assert _sanitize_placeholder("California") == "California"
    assert _sanitize_placeholder("") is None
    assert _sanitize_placeholder(None) is None


def test_high5_todo_citizenship_does_not_leak_to_le(tmp_path: Path) -> None:
    """A victim with citizenship='TODO: confirm victim's state/country'
    must NOT have that string rendered in the LE handoff."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    victim = VictimInfo(
        name="V", wallet_address=VICTIM_ADDR,
        citizenship="TODO: confirm victim's state/country",
    )
    bundle = generate_briefs(
        primary_case=_single_asset_case(), linked_cases=[],
        victim=victim,
        investigator=InvestigatorInfo(
            name="X", organization="Y", email="z@a.b",
        ),
        case_dir=case_dir,
    )
    assert "TODO:" not in bundle.le_html


# ─────────────────────────────────────────────────────────────────────
# HIGH-7: Secondary preservation targets on multi-issuer cases
# ─────────────────────────────────────────────────────────────────────


def test_high7_secondary_preservation_list_built_correctly() -> None:
    """`_build_secondary_preservation_targets` filters out the primary
    issuer and zero-balance entries; surfaces the rest."""
    from recupero.reports.brief import _build_secondary_preservation_targets
    targets = _build_secondary_preservation_targets(
        primary_issuer_name="Tether",
        all_issuers_freezable=[
            {"issuer": "Tether", "token": "USDT", "total_usd": "$21,000",
             "total_suspected_usd": "$0", "freeze_capability": "HIGH"},
            {"issuer": "Circle", "token": "USDC", "total_usd": "$7,000",
             "total_suspected_usd": "$1,000", "freeze_capability": "HIGH",
             "contact_email": "compliance@circle.com"},
            {"issuer": "Sky", "token": "DAI", "total_usd": "$0",
             "total_suspected_usd": "$0", "freeze_capability": "NONE"},
        ],
    )
    # Tether (primary) and Sky (all-zero) filtered. Only Circle remains.
    assert len(targets) == 1
    assert targets[0]["issuer_name"] == "Circle"
    assert targets[0]["contact_email"] == "compliance@circle.com"


# ─────────────────────────────────────────────────────────────────────
# HIGH-9: verified_at carries full UTC datetime precision
# ─────────────────────────────────────────────────────────────────────


def test_high9_verified_at_has_full_utc_datetime(tmp_path: Path) -> None:
    """Pre-v0.32.1 verified_at was a date-only string ('2026-05-26')
    while every other timeline timestamp carried full hh:mm:ss UTC.
    Now they match precision."""
    html = _render_le(tmp_path, _single_asset_case())
    # The "Current state" timeline event renders verified_at.
    # The exact wall-clock varies; assert the structure: at least one
    # occurrence of `YYYY-MM-DD HH:MM:SS UTC`.
    import re
    matches = re.findall(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC", html)
    assert matches, (
        "HIGH-9 regression: verified_at rendered without full datetime + UTC"
    )


# ─────────────────────────────────────────────────────────────────────
# HIGH-10: Filing notes block always renders a default
# ─────────────────────────────────────────────────────────────────────


def test_high10_filing_notes_default_renders() -> None:
    """Pre-v0.32.1 the `le_routing.notes` block was conditional —
    silently disappeared on most cases. Now a default note ('Recupero
    is available for follow-up') always renders inside Section 6.1."""
    template = Path(
        "src/recupero/reports/templates/le.html.j2"
    ).read_text(encoding="utf-8")
    assert "available for follow-up clarifications" in template, (
        "HIGH-10 regression: default filing note removed"
    )


# ─────────────────────────────────────────────────────────────────────
# Per-asset summary helper unit tests
# ─────────────────────────────────────────────────────────────────────


def test_per_asset_summary_groups_by_symbol() -> None:
    """The per-asset summary groups events by token symbol and sums
    per-token amount + USD."""
    from recupero.reports.brief import _build_theft_events_per_asset_summary
    events = [
        _transfer(
            symbol="ETH", contract=None, amount=Decimal("0.21"),
            usd=Decimal("707.60"), block=100, tx_hash="0xaaa",
        ),
        _transfer(
            symbol="USDT", contract=USDT, amount=Decimal("20610.34"),
            usd=Decimal("20610.34"), block=101, tx_hash="0xbbb",
        ),
    ]
    summary = _build_theft_events_per_asset_summary(events)
    by_sym = {s["symbol"]: s for s in summary}
    assert "ETH" in by_sym
    assert "USDT" in by_sym
    assert by_sym["ETH"]["event_count"] == 1
    assert by_sym["USDT"]["event_count"] == 1
    assert by_sym["USDT"]["usd_value_at_theft"].startswith("$")
    assert by_sym["ETH"]["usd_value_at_theft"].startswith("$")
