"""v0.35.0 Watchlist / Watcher dashboard.

The operator-facing "show me everything we're watching, where it is, and whether
it MOVED" surface. Tests pin:
  * the pure summarizer's movement verdict (moved-by-delta, moved-by-tx,
    still-present, never-checked) and staleness;
  * status derivation (TRACKED / FREEZABLE / UNRECOVERABLE / EXCHANGE / FROZEN);
  * portfolio rollups (totals, by-status, by-chain) and moved-first sort order;
  * empty-state / DB-outage safety of the builder;
  * the renderer produces well-formed HTML with the right pills + badges.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from recupero.monitoring.watchlist_dashboard import (
    WatchlistOverview,
    build_watchlist_overview,
    summarize_watchlist,
)
from recupero.reports.watchlist_dashboard import render_watchlist_dashboard

NOW = datetime(2026, 6, 2, 12, 0, tzinfo=UTC)


def _row(
    address,
    *,
    chain="ethereum",
    is_freezeable=False,
    status="active",
    label_category=None,
    label_name=None,
    issuer=None,
    asset_symbol="ETH",
    last_balance_usd="0",
    last_tx_count=None,
    prior_tx_count=None,
    latest_delta_usd=None,
    flagged_days_ago=10,
    checked_hours_ago=2,
    priority="standard",
):
    flagged = NOW - timedelta(days=flagged_days_ago)
    checked = None if checked_hours_ago is None else NOW - timedelta(hours=checked_hours_ago)
    return {
        "address": address,
        "chain": chain,
        "role": "current_holder",
        "is_freezeable": is_freezeable,
        "issuer": issuer,
        "asset_symbol": asset_symbol,
        "asset_contract": None,
        "flagged_at": flagged,
        "status": status,
        "priority": priority,
        "label_category": label_category,
        "label_name": label_name,
        "investigation_id": None,
        "last_balance_usd": last_balance_usd,
        "last_native_balance": None,
        "last_tx_count": last_tx_count,
        "last_snapshot_at": checked,
        "latest_delta_usd": latest_delta_usd,
        "prior_tx_count": prior_tx_count,
    }


# ----------------------------- movement verdict ---------------------------- #


def test_movement_verdicts():
    rows = [
        _row("0xstill", last_balance_usd="1000", last_tx_count=5,
             prior_tx_count=5, latest_delta_usd="0"),
        _row("0xmoved_usd", last_balance_usd="2000", last_tx_count=5,
             prior_tx_count=5, latest_delta_usd="-500000"),
        _row("0xmoved_tx", last_balance_usd="3000", last_tx_count=10,
             prior_tx_count=8, latest_delta_usd="0"),
        _row("0xnew", last_balance_usd="4000", checked_hours_ago=None),
    ]
    ov = summarize_watchlist(rows, now=NOW)
    verdict = {it.address: it.movement for it in ov.items}
    assert verdict["0xstill"] == "still_present"
    assert verdict["0xmoved_usd"] == "moved"
    assert verdict["0xmoved_tx"] == "moved"
    assert verdict["0xnew"] == "never_checked"
    assert ov.n_moved == 2
    assert ov.n_still_present == 1
    assert ov.n_never_checked == 1


def test_moved_first_sort_then_usd_desc():
    rows = [
        _row("0xstill_big", last_balance_usd="9999", last_tx_count=1,
             prior_tx_count=1, latest_delta_usd="0"),
        _row("0xmoved_small", last_balance_usd="10", latest_delta_usd="-5000",
             last_tx_count=2, prior_tx_count=1),
        _row("0xmoved_big", last_balance_usd="8000", latest_delta_usd="-9000",
             last_tx_count=2, prior_tx_count=1),
    ]
    ov = summarize_watchlist(rows, now=NOW)
    order = [it.address for it in ov.items]
    # Both moved rows come before the still-present one; within moved, USD desc.
    assert order == ["0xmoved_big", "0xmoved_small", "0xstill_big"]


# ----------------------------- status derivation --------------------------- #


def test_status_derivation():
    rows = [
        _row("0xtracked"),  # not freezeable, no label → TRACKED
        _row("0xfreeze", is_freezeable=True),
        _row("0xmix", label_category="mixer", label_name="Tornado"),
        _row("0xcex", label_category="exchange_deposit", label_name="Binance"),
        _row("0xfrozen", status="frozen"),
        _row("0xrec", status="recovered"),
    ]
    ov = summarize_watchlist(rows, now=NOW)
    st = {it.address: it.status for it in ov.items}
    assert st["0xtracked"] == "TRACKED"
    assert st["0xfreeze"] == "FREEZABLE"
    assert st["0xmix"] == "UNRECOVERABLE"
    assert st["0xcex"] == "EXCHANGE"
    assert st["0xfrozen"] == "FROZEN"
    assert st["0xrec"] == "RECOVERED"
    assert ov.by_status["TRACKED"] == 1 and ov.by_status["FREEZABLE"] == 1


def test_staleness_and_days_watched():
    rows = [
        _row("0xfresh", checked_hours_ago=2, flagged_days_ago=30),
        _row("0xstale", checked_hours_ago=50, flagged_days_ago=5),
        _row("0xnever", checked_hours_ago=None),
    ]
    ov = summarize_watchlist(rows, now=NOW, stale_after_hours=24)
    by = {it.address: it for it in ov.items}
    assert by["0xfresh"].stale is False
    assert by["0xstale"].stale is True       # 50h > 24h
    assert by["0xnever"].stale is True       # never checked
    assert by["0xfresh"].days_watched == 30
    assert ov.n_stale == 2


def test_rollups_totals_and_by_chain():
    rows = [
        _row("0xa", chain="ethereum", last_balance_usd="1000000",
             last_tx_count=1, prior_tx_count=1, latest_delta_usd="0"),
        _row("0xb", chain="arbitrum", last_balance_usd="500000",
             latest_delta_usd="-250000", last_tx_count=2, prior_tx_count=1),
        _row("0xc", chain="ethereum", last_balance_usd="250000",
             checked_hours_ago=None),
    ]
    ov = summarize_watchlist(rows, now=NOW)
    assert ov.n_items == 3
    assert ov.total_watched_usd == Decimal("1750000")
    assert ov.total_moved_usd == Decimal("500000")        # 0xb
    assert ov.total_still_present_usd == Decimal("1000000")  # 0xa
    assert ov.by_chain["ethereum"]["n"] == 2
    assert ov.by_chain["ethereum"]["usd"] == Decimal("1250000")
    assert ov.by_chain["arbitrum"]["n"] == 1


def test_explorer_url_built_per_chain():
    ov = summarize_watchlist([_row("0xabc", chain="arbitrum")], now=NOW)
    assert ov.items[0].explorer_url == "https://arbiscan.io/address/0xabc"


def test_nan_and_none_balance_guarded():
    # A NaN/None balance must not crash or poison totals.
    rows = [
        _row("0xnan", last_balance_usd="NaN"),
        _row("0xnone", last_balance_usd=None),
        _row("0xok", last_balance_usd="100", last_tx_count=1,
             prior_tx_count=1, latest_delta_usd="0"),
    ]
    ov = summarize_watchlist(rows, now=NOW)
    assert ov.total_watched_usd == Decimal("100")  # NaN/None coerced to 0


# ----------------------------- builder safety ------------------------------ #


def test_build_overview_empty_when_dsn_none():
    ov = build_watchlist_overview(dsn=None, now=NOW)
    assert isinstance(ov, WatchlistOverview)
    assert ov.n_items == 0 and ov.items == []


def test_build_overview_empty_on_db_error():
    def _boom(*a, **kw):
        raise RuntimeError("simulated supabase outage")

    with patch("recupero._common.db_connect", side_effect=_boom):
        ov = build_watchlist_overview(dsn="postgres://x", now=NOW)
    assert ov.n_items == 0


# ----------------------------- renderer ------------------------------------ #


def test_render_produces_html(tmp_path: Path):
    rows = [
        _row("0xMixDeposit", label_category="mixer", label_name="Tornado Cash: 100 ETH",
             last_balance_usd="21629000", latest_delta_usd="0",
             last_tx_count=1, prior_tx_count=1),
        _row("0xMovedWhale", last_balance_usd="500000", latest_delta_usd="-500000",
             last_tx_count=3, prior_tx_count=1),
    ]
    ov = summarize_watchlist(rows, now=NOW)
    out = render_watchlist_dashboard(
        output_dir=tmp_path, dsn="postgres://x", overview=ov,
    )
    assert out is not None and out.exists()
    html = out.read_text(encoding="utf-8")
    assert "Watchlist" in html
    assert "MOVED" in html                       # movement badge
    assert "UNRECOVERABLE" in html               # mixer terminal pill
    assert "$21,629,000.00" in html              # aggregate balance rendered
    assert "0xMovedWhale" in html


def test_render_empty_state(tmp_path: Path):
    ov = summarize_watchlist([], now=NOW)
    out = render_watchlist_dashboard(
        output_dir=tmp_path, dsn="postgres://x", overview=ov,
    )
    assert out is not None and out.exists()
    assert "Nothing under watch yet" in out.read_text(encoding="utf-8")
