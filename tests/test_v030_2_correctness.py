"""v0.30.2 regression tests for V030_2_CORRECTNESS_AUDIT Tier-1 findings.

Pins:
  T1-A: cross-token amount sum nonsense ("0.21 ETH + 20,610 USDT
        rendered as 20,610.55") corrected by per-symbol aggregation.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

import pytest

# ──────────────────────────────────────────────────────────────────────
# T1-A: cross-token amount sum
# ──────────────────────────────────────────────────────────────────────


@dataclass
class _Token:
    symbol: str


@dataclass
class _Transfer:
    amount_decimal: Decimal | None
    token: _Token


def test_theft_events_mixed_assets_detects_multi_symbol() -> None:
    from recupero.reports.brief import _theft_events_mixed_assets
    eth_event = _Transfer(amount_decimal=Decimal("0.210815"), token=_Token("ETH"))
    usdt_event = _Transfer(amount_decimal=Decimal("20610.336829"), token=_Token("USDT"))
    assert _theft_events_mixed_assets([eth_event, usdt_event]) is True


def test_theft_events_mixed_assets_same_symbol_returns_false() -> None:
    from recupero.reports.brief import _theft_events_mixed_assets
    a = _Transfer(amount_decimal=Decimal("100"), token=_Token("USDT"))
    b = _Transfer(amount_decimal=Decimal("200"), token=_Token("USDT"))
    assert _theft_events_mixed_assets([a, b]) is False


def test_theft_events_mixed_assets_case_insensitive() -> None:
    """Symbol normalization is case-insensitive — "ETH" and "eth"
    are the same asset for aggregation purposes."""
    from recupero.reports.brief import _theft_events_mixed_assets
    a = _Transfer(amount_decimal=Decimal("1"), token=_Token("eth"))
    b = _Transfer(amount_decimal=Decimal("2"), token=_Token("ETH"))
    assert _theft_events_mixed_assets([a, b]) is False


def test_theft_events_mixed_assets_empty_and_single() -> None:
    from recupero.reports.brief import _theft_events_mixed_assets
    assert _theft_events_mixed_assets([]) is False
    one = _Transfer(amount_decimal=Decimal("1"), token=_Token("ETH"))
    assert _theft_events_mixed_assets([one]) is False


def test_aggregate_theft_amount_refuses_cross_token_sum() -> None:
    """The actual T1-A bug: 0.21 ETH + 20,610 USDT MUST NOT render as
    "20,610.547644". A federal agent reading that loses trust in
    every number on the page."""
    from recupero.reports.brief import _aggregate_theft_amount_human
    eth_event = _Transfer(amount_decimal=Decimal("0.210815"), token=_Token("ETH"))
    usdt_event = _Transfer(amount_decimal=Decimal("20610.336829"), token=_Token("USDT"))
    out = _aggregate_theft_amount_human([eth_event, usdt_event], eth_event)
    # The pre-v0.30.2 bug: "20,610.547644" via cross-token addition.
    assert "20,610.547644" not in out
    assert "20610.547644" not in out
    # The correct render: a non-numeric label that signals breakdown.
    assert "mixed assets" in out.lower()
    assert "2 events" in out


def test_aggregate_theft_amount_sums_same_symbol() -> None:
    """When every event is the same token, addition is correct."""
    from recupero.reports.brief import _aggregate_theft_amount_human
    a = _Transfer(amount_decimal=Decimal("100"), token=_Token("USDT"))
    b = _Transfer(amount_decimal=Decimal("200"), token=_Token("USDT"))
    out = _aggregate_theft_amount_human([a, b], a)
    # Expect "300" rendered.
    assert "300" in out


def test_aggregate_theft_amount_single_event() -> None:
    """Single-event renders the event's amount, no aggregation."""
    from recupero.reports.brief import _aggregate_theft_amount_human
    a = _Transfer(amount_decimal=Decimal("20610.336829"), token=_Token("USDT"))
    out = _aggregate_theft_amount_human([a], a)
    # _fmt_decimal trims trailing zeros, so 20610.336829 renders as itself.
    assert "20,610.336829" in out or "20610.336829" in out


def test_aggregate_theft_amount_empty_falls_back_to_theft_transfer() -> None:
    """Empty events list — fall back to the primary theft_transfer's
    amount (defensive against test fixtures with no theft_events)."""
    from recupero.reports.brief import _aggregate_theft_amount_human
    primary = _Transfer(amount_decimal=Decimal("1500"), token=_Token("USDC"))
    out = _aggregate_theft_amount_human([], primary)
    assert "1,500" in out or "1500" in out


def test_smoke_brief_amount_row_does_not_show_nonsense_sum(tmp_path) -> None:
    """End-to-end: regenerate the ALEC smoke brief and confirm the
    Section 4 'Amount (total across N events)' row does NOT contain
    the pre-v0.30.2 nonsense sum '20,610.547644'."""
    from pathlib import Path
    brief_path = (
        Path("scripts/_smoke_deliverables_out/ALEC-TEST-2026/briefs/"
             "le_handoff_circle_BRIEF-ALEC-TES-356787.html")
    )
    if not brief_path.exists():
        pytest.skip("smoke deliverables output not present; run smoke_deliverables.py first")
    html = brief_path.read_text(encoding="utf-8")
    # The exact pre-v0.30.2 nonsense value:
    assert "20,610.547644" not in html, (
        "Section 4 Amount cell still renders cross-token sum "
        "'20,610.547644' — T1-A regression. "
        "The ALEC fixture has 2 theft events (ETH + USDT) and the "
        "fixed renderer should produce '2 events, mixed assets', "
        "not a single decimal."
    )
