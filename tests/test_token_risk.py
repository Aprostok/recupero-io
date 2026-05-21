"""Tests for v0.13.3 token honeypot / rug-pull risk scoring."""

from __future__ import annotations

from recupero.token_risk.scorer import (
    score_token,
)

# ---- Bytecode pattern detection ---- #


def test_clean_bytecode_produces_clean_verdict() -> None:
    """Random non-honeypot bytecode → no signals, verdict clean."""
    # USDC-style innocuous bytecode (synthetic).
    bc = "0x6080604052" + "ab" * 100
    out = score_token("0xtoken", bytecode=bc)
    assert out.verdict == "clean"
    assert out.signals == []
    assert out.risk_score == 0


def test_setBuyTax_selector_emits_signal() -> None:
    """A tax mutator selector in the bytecode produces a medium-
    severity signal."""
    bc = "0x6080604052" + "00" * 50 + "ed8e84e3" + "00" * 50
    out = score_token("0xtoken", bytecode=bc)
    assert any(s.kind == "bytecode_pattern" for s in out.signals)
    assert "setBuyTax" in out.signals[0].description


def test_multiple_mutator_selectors_produce_multiple_signals() -> None:
    """Both setBuyTax + setSellTax → 2 signals."""
    bc = "0x6080604052" + "ed8e84e3" + "31fb0ad7" + "00" * 20
    out = score_token("0xtoken", bytecode=bc)
    bytecode_signals = [s for s in out.signals if s.kind == "bytecode_pattern"]
    assert len(bytecode_signals) == 2


def test_bytecode_is_case_insensitive() -> None:
    """Bytecode selectors should match regardless of case."""
    upper = "0xED8E84E3" + "00" * 50
    out = score_token("0xtoken", bytecode=upper)
    assert any(s.kind == "bytecode_pattern" for s in out.signals)


# ---- Tx-history honeypot detection ---- #


def test_high_buy_no_sell_is_critical_honeypot() -> None:
    """20+ buys, zero successful sells → critical honeypot signal,
    verdict 'honeypot', score 10."""
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": 50,
        "sell_success_count": 0,
    })
    assert out.verdict == "honeypot"
    assert out.risk_score == 10
    assert any(s.kind == "high_buy_no_sell" for s in out.signals)
    assert any(s.severity == 4 for s in out.signals)
    assert "honeypot" in out.investigator_note.lower()


def test_moderate_buy_no_sell_is_high_risk() -> None:
    """5-19 buys with no sells is suggestive but not certain —
    severity=3, verdict medium."""
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": 10,
        "sell_success_count": 0,
    })
    assert any(s.kind == "high_buy_no_sell" and s.severity == 3 for s in out.signals)
    assert out.verdict == "medium_risk"


def test_low_buy_count_no_sell_no_signal() -> None:
    """Only 3 buys with no sells doesn't hit either threshold;
    too early to call."""
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": 3,
        "sell_success_count": 0,
    })
    assert all(s.kind != "high_buy_no_sell" for s in out.signals)


def test_buys_with_some_sells_no_honeypot() -> None:
    """20 buys + 5 successful sells → not a honeypot."""
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": 20,
        "sell_success_count": 5,
    })
    assert all(s.kind != "high_buy_no_sell" for s in out.signals)


# ---- Rug-pull detection ---- #


def test_lp_removed_within_24h_is_critical_rug() -> None:
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": 100,
        "sell_success_count": 50,
        "lp_removed_within_24h_of_launch": True,
        "launch_block": 19_000_000,
    })
    assert any(s.kind == "rug_lp_removal" for s in out.signals)
    assert out.verdict == "high_risk_rug"
    assert "rug" in out.investigator_note.lower() or "RUG" in out.investigator_note


# ---- GoPlus API integration ---- #


def test_goplus_honeypot_flag_emits_critical_signal() -> None:
    goplus = {"is_honeypot": "1"}
    out = score_token("0xtoken", goplus_result=goplus)
    assert out.verdict == "honeypot"
    assert any(s.kind == "goplus_honeypot" for s in out.signals)


def test_goplus_cannot_sell_emits_signal() -> None:
    goplus = {"cannot_sell_all": "1"}
    out = score_token("0xtoken", goplus_result=goplus)
    assert any(s.kind == "goplus_cannot_sell" for s in out.signals)
    assert out.verdict == "medium_risk"


def test_goplus_multiple_concerning_flags_compound() -> None:
    """transfer_pausable + hidden_owner + blacklist → multiple sev=3,
    cumulating to high_risk_rug."""
    goplus = {
        "transfer_pausable": "1",
        "hidden_owner": "1",
        "is_blacklisted": "1",
    }
    out = score_token("0xtoken", goplus_result=goplus)
    # 1 sev=2 + 2 sev=3 → 2 sev=3 triggers high_risk_rug.
    assert out.verdict == "high_risk_rug"


def test_goplus_clean_token_has_no_signals() -> None:
    goplus = {
        "is_honeypot": "0",
        "cannot_sell_all": "0",
        "transfer_pausable": "0",
        "is_blacklisted": "0",
    }
    out = score_token("0xtoken", goplus_result=goplus)
    assert out.signals == []
    assert out.verdict == "clean"


def test_goplus_wrapped_result_format() -> None:
    """GoPlus's actual API wraps the token dict under
    result.<contract_addr>. The scorer accepts both shapes."""
    wrapped = {
        "result": {
            "0xabc": {"is_honeypot": "1"},
        },
    }
    out = score_token("0xabc", goplus_result=wrapped)
    assert out.verdict == "honeypot"


# ---- Aggregation ladder ---- #


def test_aggregation_honeypot_beats_rug() -> None:
    """When both honeypot and rug signals fire, honeypot wins
    (it's the more dispositive verdict)."""
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": 50,
        "sell_success_count": 0,  # honeypot
        "lp_removed_within_24h_of_launch": True,  # rug
    })
    assert out.verdict == "honeypot"


def test_data_sources_used_reports_all_inputs() -> None:
    """The result tracks which signal sources were consulted."""
    out = score_token(
        "0xtoken",
        bytecode="0x" + "00" * 100,
        tx_history_stats={"buy_count": 0, "sell_success_count": 0},
        goplus_result={"is_honeypot": "0"},
    )
    assert "bytecode_heuristic" in out.data_sources_used
    assert "tx_history_heuristic" in out.data_sources_used
    assert "goplus_api" in out.data_sources_used


def test_no_data_sources_means_clean() -> None:
    """Called with no inputs → no signals, verdict clean (defensive
    default — the scorer doesn't fail if the caller has no data)."""
    out = score_token("0xtoken")
    assert out.verdict == "clean"
    assert out.data_sources_used == []


# ---- to_json_safe ---- #


def test_to_json_safe_is_serializable() -> None:
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": 50, "sell_success_count": 0,
    })
    import json
    json.dumps(out.to_json_safe())  # should not raise
