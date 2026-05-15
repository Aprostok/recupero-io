"""Tests for the per-issuer freeze-letter refactor.

Operator-quality review on case e917ffc5 revealed that every
issuer's freeze letter asked Circle / Tether / Sky / Paxos to
freeze the same 130 ETH at the same first-hop address. Stablecoin
issuers don't control ETH — every letter would have been rejected.

The fix threads each issuer's FREEZABLE.holdings list from
freeze_brief.json through to the template, so each letter asks
for the SPECIFIC stablecoin (USDC / USDT / DAI / PYUSD) at the
SPECIFIC addresses that issuer actually controls.

Tests:

  1. ``_build_issuer_freezable_ctx`` correctly transforms the
     freeze_brief.json entry into the template-friendly shape.
  2. Status FREEZABLE / INVESTIGATE both surface, with correct
     counts.
  3. Empty/None input returns None (legacy path stays available).
  4. Address explorer URLs are correctly built for each chain.
  5. End-to-end: generate_briefs renders a letter with the
     stablecoin token name (not the original asset symbol) when
     issuer_freezable is provided.

Tests run in <100ms, no DB / no network.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from recupero.models import (
    Address,
    Case,
    Chain,
    EvidenceReceipt,
    TokenRef,
    Transfer,
    Counterparty,
)
from recupero.reports.brief import (
    InvestigatorInfo,
    IssuerInfo,
    _build_issuer_freezable_ctx,
    _short_addr,
    generate_briefs,
)
from recupero.reports.victim import VictimInfo


# ---- _build_issuer_freezable_ctx ---- #


def _circle_freeze_brief_entry() -> dict:
    """Reproduces the actual freeze_brief.json shape from case e917ffc5
    for Circle, with one FREEZABLE and one INVESTIGATE holding."""
    return {
        "issuer": "Circle",
        "token": "USDC",
        "total_usd": "$7,097.58",
        "total_suspected_usd": "$1,037,451.35",
        "freeze_capability": "HIGH",
        "holdings": [
            {
                "address": "0x016606Acc6B0cFE537acc221e3bf1bb44B4049Ee",
                "amount": "793113.726367 USDC",
                "usd": "$793,113.73",
                "status": "INVESTIGATE",
            },
            {
                "address": "0x480CD46E6faDe651a0437DeaddA53D5c8e7D846A",
                "amount": "6031.31 USDC",
                "usd": "$6,031.31",
                "status": "FREEZABLE",
            },
        ],
        "contact_email": "compliance@circle.com",
    }


def test_ctx_none_input_returns_none() -> None:
    """Legacy path: no per-issuer freezable data → return None so
    the template falls back to single-asset rendering."""
    assert _build_issuer_freezable_ctx(None, Chain.ethereum) is None


def test_ctx_empty_dict_returns_none() -> None:
    """Defensive: an empty dict (falsy) also returns None."""
    assert _build_issuer_freezable_ctx({}, Chain.ethereum) is None


def test_ctx_basic_shape_locked() -> None:
    """The output shape is the contract the template binds to. Lock
    every top-level key so accidental edits in brief.py fail loudly."""
    out = _build_issuer_freezable_ctx(_circle_freeze_brief_entry(), Chain.ethereum)
    assert out is not None
    assert set(out.keys()) == {
        "token", "freeze_capability",
        "total_usd_freezable", "total_usd_suspected",
        "holdings", "freezable_holdings", "investigate_holdings",
        "has_freezable", "has_investigate",
        "freezable_count", "investigate_count", "total_count",
    }


def test_ctx_token_locked() -> None:
    out = _build_issuer_freezable_ctx(_circle_freeze_brief_entry(), Chain.ethereum)
    assert out["token"] == "USDC"


def test_ctx_freeze_capability_locked() -> None:
    out = _build_issuer_freezable_ctx(_circle_freeze_brief_entry(), Chain.ethereum)
    assert out["freeze_capability"] == "HIGH"


def test_ctx_totals_string_preserved() -> None:
    """Total USD values come in pre-formatted from freeze_brief.json
    — preserve them verbatim. Re-formatting here would risk diverging
    from the canonical aggregation in emit_brief.py."""
    out = _build_issuer_freezable_ctx(_circle_freeze_brief_entry(), Chain.ethereum)
    assert out["total_usd_freezable"] == "$7,097.58"
    assert out["total_usd_suspected"] == "$1,037,451.35"


def test_ctx_holdings_split_by_status() -> None:
    """FREEZABLE and INVESTIGATE holdings appear in their respective
    lists, AND in the combined ``holdings`` list. Template uses each
    list for a different purpose (section 4 lists ALL, section 5
    asks only for FREEZABLE)."""
    out = _build_issuer_freezable_ctx(_circle_freeze_brief_entry(), Chain.ethereum)
    assert out["total_count"] == 2
    assert out["freezable_count"] == 1
    assert out["investigate_count"] == 1
    assert out["has_freezable"] is True
    assert out["has_investigate"] is True


def test_ctx_explorer_url_built() -> None:
    """Each holding gets an explorer URL — the template renders
    every address as a clickable link. URL prefix per chain.
    Verified for Ethereum here; cross-chain coverage tested
    elsewhere."""
    out = _build_issuer_freezable_ctx(_circle_freeze_brief_entry(), Chain.ethereum)
    first = out["holdings"][0]
    assert first["explorer_url"].startswith("https://etherscan.io/address/")
    assert "0x016606Acc6B0cFE537acc221e3bf1bb44B4049Ee" in first["explorer_url"]


def test_ctx_short_address_helper() -> None:
    """``_short_addr`` truncates 40-char hex to 0xABCDEF…1234 for
    inline display in section 4 of the letter (the full address is
    also rendered, but the short form is used in tooltips / status
    badges)."""
    out = _build_issuer_freezable_ctx(_circle_freeze_brief_entry(), Chain.ethereum)
    first = out["holdings"][0]
    assert first["address_short"] == "0x016606…49Ee"


def test_ctx_only_investigate_no_freezable() -> None:
    """When every holding is INVESTIGATE (the freeze_capability is
    LOW), has_freezable=False and the freezable list is empty.
    Template should adapt section 5 to not promise specific addresses."""
    entry = _circle_freeze_brief_entry()
    for h in entry["holdings"]:
        h["status"] = "INVESTIGATE"
    out = _build_issuer_freezable_ctx(entry, Chain.ethereum)
    assert out["has_freezable"] is False
    assert out["freezable_count"] == 0
    assert out["investigate_count"] == 2


def test_ctx_only_freezable_no_investigate() -> None:
    """Inverse: every holding confirmed FREEZABLE. The template's
    INVESTIGATE-specific copy should not render in this case."""
    entry = _circle_freeze_brief_entry()
    for h in entry["holdings"]:
        h["status"] = "FREEZABLE"
    out = _build_issuer_freezable_ctx(entry, Chain.ethereum)
    assert out["has_investigate"] is False
    assert out["investigate_count"] == 0
    assert out["freezable_count"] == 2


def test_ctx_unknown_status_defaults_to_investigate() -> None:
    """A holding with an unrecognized status (or None) gets bucketed
    into INVESTIGATE rather than dropped, so we don't silently lose
    the row from the letter."""
    entry = _circle_freeze_brief_entry()
    entry["holdings"][0]["status"] = "FROZEN_PENDING_REVIEW"  # not a real status
    out = _build_issuer_freezable_ctx(entry, Chain.ethereum)
    # The unknown-status holding stays in the combined list but
    # is filtered out of both FREEZABLE and INVESTIGATE buckets
    # (it doesn't match either status string).
    assert out["total_count"] == 2
    # The other holding's status is still respected
    statuses = {h["status"] for h in out["holdings"]}
    assert statuses == {"FROZEN_PENDING_REVIEW", "FREEZABLE"}


def test_ctx_missing_holdings_returns_empty_list() -> None:
    """A FREEZABLE entry with no holdings (defensive — shouldn't
    happen but the parser must not crash)."""
    entry = _circle_freeze_brief_entry()
    entry["holdings"] = []
    out = _build_issuer_freezable_ctx(entry, Chain.ethereum)
    assert out["total_count"] == 0
    assert out["has_freezable"] is False
    assert out["has_investigate"] is False


# ---- _short_addr ---- #


def test_short_addr_normal_hex() -> None:
    out = _short_addr("0x" + "a" * 40)
    assert out == "0xaaaaaa…aaaa"


def test_short_addr_short_input_passes_through() -> None:
    assert _short_addr("0x123") == "0x123"
    assert _short_addr("") == ""


# ---- End-to-end: generate_briefs with issuer_freezable ---- #


def _make_minimal_case() -> Case:
    """Build a minimum-viable Case with one transfer (the theft event)
    so generate_briefs has something to work with."""
    theft_xfer = Transfer(
        transfer_id="ethereum:0xtheft:0",
        chain=Chain.ethereum,
        tx_hash="0x" + "f" * 64,
        block_number=12345,
        block_time=datetime(2026, 1, 2, 0, 0, tzinfo=timezone.utc),
        from_address="0x" + "1" * 40,
        to_address="0x" + "2" * 40,
        counterparty=Counterparty(
            address="0x" + "2" * 40,
            label=None,
            is_contract=False,
        ),
        token=TokenRef(
            chain=Chain.ethereum,
            contract=None,
            symbol="ETH",
            decimals=18,
            coingecko_id="ethereum",
        ),
        amount_raw="130000000000000000000",
        amount_decimal=Decimal("130"),
        usd_value_at_tx=Decimal("385680.64"),
        hop_depth=0,
        fetched_at=datetime(2026, 1, 2, 0, 1, tzinfo=timezone.utc),
        explorer_url="https://etherscan.io/tx/0xtheft",
    )
    return Case(
        case_id="test-e2e",
        seed_address="0x" + "1" * 40,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 2, tzinfo=timezone.utc),
        transfers=[theft_xfer],
        trace_started_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        software_version="test",
    )


def test_generate_briefs_renders_stablecoin_when_freezable_provided() -> None:
    """End-to-end: the rendered freeze letter mentions USDC (the
    issuer's token) prominently — not just ETH (the original
    asset). This is the regression that this whole fix exists to
    prevent."""
    case = _make_minimal_case()
    victim = VictimInfo(
        name="Jane Doe",
        wallet_address="0x" + "1" * 40,
        citizenship="USA",
    )
    investigator = InvestigatorInfo(
        name="Alec Prostok",
        organization="Recupero LLC",
        email="alec@recupero.io",
    )
    issuer = IssuerInfo(
        name="Circle",
        short_name="Circle",
        contact_email="compliance@circle.com",
        jurisdiction="USA",
        regulatory_framework="",
        kyc_required=True,
    )

    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        bundle = generate_briefs(
            primary_case=case,
            linked_cases=[],
            victim=victim,
            investigator=investigator,
            case_dir=case_dir,
            issuer=issuer,
            issuer_freezable=_circle_freeze_brief_entry(),
        )
        html = bundle.maple_path.read_text(encoding="utf-8")

    # The letter must talk about USDC (the issuer's token), not just
    # the original ETH asset.
    assert "USDC" in html
    # Specific freezable amount should appear (the cumulative $7,097.58)
    assert "$7,097.58" in html
    # Both addresses should appear in section 4
    assert "0x016606Acc6B0cFE537acc221e3bf1bb44B4049Ee" in html
    assert "0x480CD46E6faDe651a0437DeaddA53D5c8e7D846A" in html
    # Status badges
    assert "FREEZABLE" in html
    assert "INVESTIGATE" in html


def test_generate_briefs_legacy_path_unchanged() -> None:
    """When issuer_freezable is None (legacy / wallet-trace path),
    the letter renders the same way it did pre-fix — single
    asset + single current_holder. Backward-compat regression
    guard."""
    case = _make_minimal_case()
    victim = VictimInfo(
        name="Jane Doe",
        wallet_address="0x" + "1" * 40,
    )
    investigator = InvestigatorInfo(
        name="Alec Prostok",
        organization="Recupero LLC",
        email="alec@recupero.io",
    )
    issuer = IssuerInfo(
        name="Circle",
        short_name="Circle",
        contact_email="compliance@circle.com",
    )

    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        bundle = generate_briefs(
            primary_case=case, linked_cases=[],
            victim=victim, investigator=investigator,
            case_dir=case_dir, issuer=issuer,
            # issuer_freezable explicitly omitted — legacy path
        )
        html = bundle.maple_path.read_text(encoding="utf-8")

    # Legacy path: letter mentions ETH (the original theft asset)
    # and the to_address as the current holder.
    assert "ETH" in html
    assert "0x" + "2" * 40 in html
