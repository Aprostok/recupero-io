"""Tests for the Tier-2 engagement letter renderer.

The engagement letter is the legal contract the victim signs to
authorize active recovery (Option A from the victim summary).
Pre-generated for every recoverable case so the operator has it
ready to send.

The renderer is straightforward template-fill — these tests lock
the prose-critical fields, the fee math, and the legal language
that must be present.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory

from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.reports.brief import InvestigatorInfo
from recupero.reports.victim import VictimInfo
from recupero.worker._engagement_letter import render_engagement_letter


def _make_case() -> Case:
    return Case(
        case_id="test-engagement",
        seed_address="0x" + "a" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=[Transfer(
            transfer_id="ethereum:0xtheft:0",
            chain=Chain.ethereum,
            tx_hash="0x" + "f" * 64,
            block_number=12345,
            block_time=datetime(2026, 1, 2, tzinfo=UTC),
            from_address="0x" + "a" * 40,
            to_address="0x" + "b" * 40,
            counterparty=Counterparty(address="0x" + "b" * 40, label=None, is_contract=False),
            token=TokenRef(chain=Chain.ethereum, contract=None, symbol="ETH",
                          decimals=18, coingecko_id="ethereum"),
            amount_raw="1000000000000000000",
            amount_decimal=Decimal("1"),
            usd_value_at_tx=Decimal("3000"),
            hop_depth=0,
            fetched_at=datetime(2026, 1, 2, 0, 1, tzinfo=UTC),
            explorer_url="https://etherscan.io/tx/0xtheft",
        )],
        trace_started_at=datetime(2026, 1, 2, tzinfo=UTC),
        trace_completed_at=datetime(2026, 1, 2, 0, 5, tzinfo=UTC),
        software_version="test",
    )


def _victim() -> VictimInfo:
    return VictimInfo(
        name="Jane Doe",
        email="jane@example.com",
        wallet_address="0x" + "a" * 40,
        citizenship="USA",
        state="CA",
        address="123 Main St, San Francisco, CA 94102",
    )


def _investigator() -> InvestigatorInfo:
    return InvestigatorInfo(
        name="Alec Prostok",
        organization="Recupero LLC",
        email="alec@recupero.io",
    )


def _freeze_brief(total_usd: str = "$7,097.58") -> dict:
    return {"FREEZABLE": [{
        "issuer": "Circle", "token": "USDC",
        "total_usd": total_usd, "total_suspected_usd": "$50,000.00",
        "freeze_capability": "HIGH",
        "holdings": [{
            "address": "0x" + "c" * 40, "amount": "1000 USDC",
            "usd": total_usd, "status": "FREEZABLE",
        }],
    }]}


# ---- rendering happy path ---- #


def test_render_returns_path_on_success() -> None:
    with TemporaryDirectory() as tmp:
        path = render_engagement_letter(
            case=_make_case(), victim=_victim(),
            investigator=_investigator(),
            freeze_brief=_freeze_brief(),
            briefs_dir=Path(tmp),
            total_freezable_usd=Decimal("7097.58"),
            total_suspected_usd=Decimal("50000.00"),
        )
        assert path is not None
        assert path.exists()
        assert path.name.startswith("engagement_letter_")


def test_letter_includes_victim_name_and_org() -> None:
    """Both parties named correctly in the contract."""
    with TemporaryDirectory() as tmp:
        path = render_engagement_letter(
            case=_make_case(), victim=_victim(),
            investigator=_investigator(),
            freeze_brief=_freeze_brief(),
            briefs_dir=Path(tmp),
            total_freezable_usd=Decimal("7097.58"),
            total_suspected_usd=Decimal("50000.00"),
        )
        html = path.read_text(encoding="utf-8")

    assert "Jane Doe" in html
    assert "Recupero LLC" in html
    assert "Alec Prostok" in html
    # Affected wallet in the cover meta
    assert "0x" + "a" * 40 in html


def test_letter_includes_required_sections() -> None:
    """All 9 sections must be present — operator's professional
    quality bar."""
    with TemporaryDirectory() as tmp:
        path = render_engagement_letter(
            case=_make_case(), victim=_victim(),
            investigator=_investigator(),
            freeze_brief=_freeze_brief(),
            briefs_dir=Path(tmp),
            total_freezable_usd=Decimal("7097.58"),
            total_suspected_usd=Decimal("50000.00"),
        )
        html = path.read_text(encoding="utf-8")

    for section in [
        "1. Background",
        "2. Scope of services",
        "3. What this engagement does NOT include",
        "4. Fees",
        "5. Termination",
        "6. Authority",
        "7. Confidentiality",
        "8. Governing law",
        "9. Signature",
    ]:
        assert section in html, f"missing section: {section}"


def test_fee_math_with_default_engagement() -> None:
    """v0.7.0 decoupled the diagnostic from the engagement: the
    engagement fee is the published amount ($10,000) and the
    $499 diagnostic is a separate, already-paid charge that does
    NOT get credited. The letter shows both amounts as standalone
    fees."""
    with TemporaryDirectory() as tmp:
        path = render_engagement_letter(
            case=_make_case(), victim=_victim(),
            investigator=_investigator(),
            freeze_brief=_freeze_brief(),
            briefs_dir=Path(tmp),
            total_freezable_usd=Decimal("7097.58"),
            total_suspected_usd=Decimal("50000.00"),
        )
        html = path.read_text(encoding="utf-8")

    assert "$10,000.00" in html  # engagement fee
    assert "$499.00" in html      # diagnostic fee (referenced as
                                  # separately earned)
    # v0.7.0 decoupling: the template explicitly clarifies the
    # engagement is "not credited against" the diagnostic. The
    # negation phrase is intentional — but the old "incremental
    # amount due upon signing" language is gone.
    assert "not credited against" in html
    assert "incremental amount" not in html
    assert "incremental engagement" not in html


def test_fee_math_with_custom_engagement_amount() -> None:
    """Operator overrides to a custom engagement fee (e.g., for a
    bespoke premium-case quote). The letter renders the override
    cleanly with no credit math."""
    with TemporaryDirectory() as tmp:
        path = render_engagement_letter(
            case=_make_case(), victim=_victim(),
            investigator=_investigator(),
            freeze_brief=_freeze_brief(),
            briefs_dir=Path(tmp),
            total_freezable_usd=Decimal("7097.58"),
            total_suspected_usd=Decimal("50000.00"),
            engagement_fee_usd=Decimal("25000"),
        )
        html = path.read_text(encoding="utf-8")

    assert "$25,000.00" in html
    # No "incremental" math — the override is the standalone fee.
    assert "incremental amount" not in html


def test_contingency_pct_renders() -> None:
    """The contingency percentage appears in section 4."""
    with TemporaryDirectory() as tmp:
        path = render_engagement_letter(
            case=_make_case(), victim=_victim(),
            investigator=_investigator(),
            freeze_brief=_freeze_brief(),
            briefs_dir=Path(tmp),
            total_freezable_usd=Decimal("7097.58"),
            total_suspected_usd=Decimal("50000.00"),
            contingency_pct=12,
        )
        html = path.read_text(encoding="utf-8")

    assert "12%" in html


def test_recovered_total_appears_in_background() -> None:
    """The diagnostic finding (freezable + suspected) appears in
    section 1 so the client sees what they're engaging us to recover.

    v0.16.7 semantic clarification: `total_suspected_usd` from the brief
    is INVESTIGATE-only — NOT FREEZABLE+INVESTIGATE gross. The template
    now renders it directly as "under investigation" rather than doing
    a `suspected - freezable` subtraction that was silently producing
    $0/negative on every real case.
    """
    with TemporaryDirectory() as tmp:
        path = render_engagement_letter(
            case=_make_case(), victim=_victim(),
            investigator=_investigator(),
            freeze_brief=_freeze_brief(),
            briefs_dir=Path(tmp),
            total_freezable_usd=Decimal("7097.58"),
            total_suspected_usd=Decimal("42902.42"),  # INVESTIGATE-only
        )
        html = path.read_text(encoding="utf-8")

    assert "$7,097.58" in html  # confirmed-recoverable
    assert "$42,902.42" in html  # under-investigation (now passed in directly)


def test_jurisdiction_override() -> None:
    """Operator can override the governing-law jurisdiction. Default
    (None) → Delaware. Override → the specified state."""
    with TemporaryDirectory() as tmp:
        # Default (no override)
        path = render_engagement_letter(
            case=_make_case(), victim=_victim(),
            investigator=_investigator(),
            freeze_brief=_freeze_brief(),
            briefs_dir=Path(tmp),
            total_freezable_usd=Decimal("7097.58"),
            total_suspected_usd=Decimal("50000.00"),
        )
        html = path.read_text(encoding="utf-8")
        assert "Delaware" in html

    with TemporaryDirectory() as tmp:
        # Override to California
        path = render_engagement_letter(
            case=_make_case(), victim=_victim(),
            investigator=_investigator(),
            freeze_brief=_freeze_brief(),
            briefs_dir=Path(tmp),
            total_freezable_usd=Decimal("7097.58"),
            total_suspected_usd=Decimal("50000.00"),
            investigator_jurisdiction="California",
        )
        html = path.read_text(encoding="utf-8")
        assert "California" in html


# ---- legal-language critical phrases ---- #


def test_letter_includes_no_legal_advice_disclaimer() -> None:
    """The letter explicitly disclaims legal-advice — this protects
    Recupero from unauthorized-practice-of-law liability."""
    with TemporaryDirectory() as tmp:
        path = render_engagement_letter(
            case=_make_case(), victim=_victim(),
            investigator=_investigator(),
            freeze_brief=_freeze_brief(),
            briefs_dir=Path(tmp),
            total_freezable_usd=Decimal("7097.58"),
            total_suspected_usd=Decimal("50000.00"),
        )
        html = path.read_text(encoding="utf-8")

    # The "Recupero is not a law firm" language must be in the
    # letter (twice — once in scope, once in footer disclaimer).
    assert "not a law firm" in html


def test_letter_includes_no_recovery_guarantee() -> None:
    """The letter explicitly says recovery is not guaranteed —
    protects against breach-of-contract claims for non-recovery."""
    with TemporaryDirectory() as tmp:
        path = render_engagement_letter(
            case=_make_case(), victim=_victim(),
            investigator=_investigator(),
            freeze_brief=_freeze_brief(),
            briefs_dir=Path(tmp),
            total_freezable_usd=Decimal("7097.58"),
            total_suspected_usd=Decimal("50000.00"),
        )
        html = path.read_text(encoding="utf-8")

    # The "does NOT include" section must list the non-guarantees
    assert "does NOT include" in html
    assert "will actually be frozen" in html
    # The "Partial recovery is typical" disclaimer (may have line-break
    # between words from the template's indentation, so check for both
    # words appearing in the html — they may not be contiguous).
    assert "Partial" in html
    assert "recovery is the typical outcome" in html


def test_letter_includes_signature_blocks() -> None:
    """Both party signature blocks present in section 9."""
    with TemporaryDirectory() as tmp:
        path = render_engagement_letter(
            case=_make_case(), victim=_victim(),
            investigator=_investigator(),
            freeze_brief=_freeze_brief(),
            briefs_dir=Path(tmp),
            total_freezable_usd=Decimal("7097.58"),
            total_suspected_usd=Decimal("50000.00"),
        )
        html = path.read_text(encoding="utf-8")

    # Signature blocks for both parties
    assert html.count("signature-line") >= 2
    assert html.count("Date:") >= 2
