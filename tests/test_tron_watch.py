"""Roadmap-v4 Tier-2 #10: Tron settled-outbound freeze-race watcher.

The fixture row is the LIVE-VERIFIED TronGrid TRC-20 shape (2026-06): a real
Binance-hot-wallet outbound USDT transfer (from/to base58, value raw 6-dec,
token_info{symbol,address,decimals}, block_timestamp ms, transaction_id).
"""

from __future__ import annotations

from typing import Any

from recupero.monitoring.tron_watch import (
    USDT_TRC20_CONTRACT,
    alerts_to_json,
    classify_tron_outbound,
    iter_tron_outbound_alerts,
    scan_tron_outbound,
    tron_watch_enabled,
)

_WATCHED = "TJRabPrwbZy45sbavfcjinPJC18kjpRTv8"   # the watched (perp) wallet
_CEX_DEP = "TRGsjk84qAKfs6zPTgAMEaWXqpBuYCXsws"   # a (labeled) exchange deposit
_FRESH = "TFreshWalletXXXXXXXXXXXXXXXXXXXXXXX"


def _trc20(*, frm, to, value="80960000", symbol="USDT",
           contract=USDT_TRC20_CONTRACT, decimals=6, tx="0xabc",
           ts=1776179616000):
    # exact TronGrid /transactions/trc20 row shape (live-verified)
    return {
        "from": frm, "to": to, "value": value, "type": "Transfer",
        "transaction_id": tx, "block_timestamp": ts,
        "token_info": {"symbol": symbol, "address": contract, "decimals": decimals},
    }


def _cex_lookup(addr: str) -> str | None:
    return "Binance" if addr == _CEX_DEP else None


def test_outbound_to_cex_is_freezable_alert() -> None:
    a = classify_tron_outbound(
        _trc20(frm=_WATCHED, to=_CEX_DEP),
        watched={_WATCHED}, cex_lookup=_cex_lookup,
    )
    assert a is not None
    assert a.from_address == _WATCHED
    assert a.to_address == _CEX_DEP
    assert a.token_symbol == "USDT"
    assert a.amount_raw == "80960000"
    assert a.amount_human == "80.96"        # 6-dec scaled
    assert a.to_is_cex is True
    assert a.cex_name == "Binance"
    assert a.freezable is True
    assert a.settled is True
    assert "RACE A FREEZE" in a.recommended_action


def test_outbound_to_unknown_is_alert_but_not_freezable() -> None:
    a = classify_tron_outbound(
        _trc20(frm=_WATCHED, to=_FRESH),
        watched={_WATCHED}, cex_lookup=_cex_lookup,
    )
    assert a is not None
    assert a.to_is_cex is False
    assert a.cex_name is None
    assert a.freezable is False


def test_non_watched_sender_is_not_an_alert() -> None:
    # inbound (someone else -> watched) is not an outbound freeze-race signal
    assert classify_tron_outbound(
        _trc20(frm=_FRESH, to=_WATCHED),
        watched={_WATCHED}, cex_lookup=_cex_lookup,
    ) is None


def test_base58_is_case_sensitive_not_lowercased() -> None:
    # a case-variant of the watched address must NOT match (base58 is exact)
    a = classify_tron_outbound(
        _trc20(frm=_WATCHED.lower(), to=_CEX_DEP),
        watched={_WATCHED}, cex_lookup=_cex_lookup,
    )
    assert a is None


def test_usdt_only_filter_skips_other_trc20() -> None:
    other = _trc20(frm=_WATCHED, to=_CEX_DEP, symbol="USDD",
                   contract="TPYmHEhy5n8TCEfYGqW2rPxsghSfzghPDn")
    assert classify_tron_outbound(
        other, watched={_WATCHED}, cex_lookup=_cex_lookup, usdt_only=True) is None
    # with usdt_only off it IS surfaced
    assert classify_tron_outbound(
        other, watched={_WATCHED}, cex_lookup=_cex_lookup, usdt_only=False) is not None


def test_zero_value_skipped() -> None:
    assert classify_tron_outbound(
        _trc20(frm=_WATCHED, to=_CEX_DEP, value="0"),
        watched={_WATCHED}, cex_lookup=_cex_lookup) is None


class _StubClient:
    def __init__(self, rows_by_addr):
        self.rows_by_addr = rows_by_addr
        self.calls: list[dict[str, Any]] = []

    def get_trc20_transfers(self, address, *, only_from, min_timestamp,
                            limit, contract_address=None):
        self.calls.append({
            "address": address, "only_from": only_from,
            "min_timestamp": min_timestamp, "contract_address": contract_address,
        })
        return self.rows_by_addr.get(address, [])


def test_scan_uses_server_side_filters_and_classifies() -> None:
    client = _StubClient({_WATCHED: [
        _trc20(frm=_WATCHED, to=_CEX_DEP, tx="0x1"),
        _trc20(frm=_WATCHED, to=_FRESH, tx="0x2"),
    ]})
    alerts = scan_tron_outbound(
        addresses=[_WATCHED], client=client, since_ms=1776000000000,
        cex_lookup=_cex_lookup,
    )
    assert len(alerts) == 2
    # server-side outbound + USDT-contract + min_timestamp filters applied
    call = client.calls[0]
    assert call["only_from"] is True
    assert call["min_timestamp"] == 1776000000000
    assert call["contract_address"] == USDT_TRC20_CONTRACT
    freezable = [a for a in alerts if a.freezable]
    assert len(freezable) == 1 and freezable[0].cex_name == "Binance"


def test_alerts_to_json_shape() -> None:
    a = classify_tron_outbound(
        _trc20(frm=_WATCHED, to=_CEX_DEP), watched={_WATCHED}, cex_lookup=_cex_lookup)
    doc = alerts_to_json([a])
    assert doc["kind"] == "recupero_tron_outbound_alerts"
    assert doc["alert_count"] == 1
    assert doc["alerts"][0]["freezable"] is True
    assert "freeze race" in doc["disclaimer"].lower()


def test_iter_and_gate(monkeypatch) -> None:
    rows = [_trc20(frm=_WATCHED, to=_CEX_DEP), _trc20(frm=_FRESH, to=_WATCHED)]
    out = iter_tron_outbound_alerts(rows, watched={_WATCHED}, cex_lookup=_cex_lookup)
    assert len(out) == 1            # only the watched-outbound row
    monkeypatch.delenv("RECUPERO_TRON_WATCH", raising=False)
    assert tron_watch_enabled() is False
    monkeypatch.setenv("RECUPERO_TRON_WATCH", "on")
    assert tron_watch_enabled() is True
