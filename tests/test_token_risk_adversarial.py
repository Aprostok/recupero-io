"""Adversarial-input hardening for token_risk.scorer (RIGOR-Jacob Z8).

Threat model: attacker controls `bytecode`, `tx_history_stats`, and
`goplus_result` via POST /v1/token-risk. They want to either crash
the scoring pipeline or get a false-clean verdict on a real honeypot.

These tests pin behaviour for malformed / hostile inputs.
"""

from __future__ import annotations

from recupero.token_risk.scorer import score_token

# ---- Bug Z8-A: non-dict tx_history_stats crashes with AttributeError ---- #


def test_non_dict_tx_history_stats_does_not_crash() -> None:
    """Attacker posts a string instead of a dict. Scorer must defensively
    treat non-dict tx_history_stats as 'no data', not crash."""
    out = score_token("0xtoken", tx_history_stats="malicious-string")  # type: ignore[arg-type]
    assert out.verdict == "clean"
    assert all(s.kind not in ("high_buy_no_sell", "rug_lp_removal") for s in out.signals)


def test_list_tx_history_stats_does_not_crash() -> None:
    out = score_token("0xtoken", tx_history_stats=["buy_count", 50])  # type: ignore[arg-type]
    assert out.verdict == "clean"


def test_int_tx_history_stats_does_not_crash() -> None:
    out = score_token("0xtoken", tx_history_stats=42)  # type: ignore[arg-type]
    assert out.verdict == "clean"


# ---- Bug Z8-B: NaN / Infinity in tx_history counts crash ---- #


def test_nan_buy_count_does_not_crash() -> None:
    """Attacker passes float('nan') as buy_count → int(nan) raises ValueError.
    Scorer must coerce safely."""
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": float("nan"),
        "sell_success_count": 0,
    })
    assert out.verdict == "clean"  # NaN treated as 0


def test_inf_buy_count_does_not_crash() -> None:
    """Attacker passes float('inf') as buy_count → int(inf) raises OverflowError."""
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": float("inf"),
        "sell_success_count": 0,
    })
    # inf should be treated as 'very large' — we'd expect either a clean
    # signal-free outcome OR the honeypot signal firing. Either is fine
    # as long as no crash.
    assert out.verdict in {"clean", "honeypot"}


def test_neg_inf_sell_count_does_not_crash() -> None:
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": 50,
        "sell_success_count": float("-inf"),
    })
    assert out.verdict in {"clean", "honeypot"}


def test_nan_sell_count_does_not_crash() -> None:
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": 50,
        "sell_success_count": float("nan"),
    })
    # NaN sell_success should be treated as 0 → trigger honeypot (50 buys, 0 sells)
    assert out.verdict == "honeypot"


def test_string_buy_count_does_not_crash() -> None:
    """Attacker passes 'fifty' as buy_count → int('fifty') raises."""
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": "fifty",
        "sell_success_count": 0,
    })
    assert out.verdict == "clean"


def test_empty_string_buy_count_treated_as_zero() -> None:
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": "",
        "sell_success_count": 0,
    })
    assert out.verdict == "clean"


# ---- Bug Z8-C: negative sell_success bypasses honeypot detection (FALSE-CLEAN) ---- #


def test_negative_sell_count_does_not_bypass_honeypot_detection() -> None:
    """CRITICAL: attacker passes sell_success_count=-1 with 50 buys.
    Original code used `sell_success == 0` so -1 silently bypassed the
    honeypot signal — a false-clean verdict on a real honeypot."""
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": 50,
        "sell_success_count": -1,
    })
    assert out.verdict == "honeypot", (
        f"FALSE-CLEAN: attacker bypassed honeypot detection with "
        f"sell_success_count=-1. Got verdict={out.verdict}"
    )
    assert any(s.kind == "high_buy_no_sell" for s in out.signals)


def test_negative_buy_count_treated_as_zero() -> None:
    """Negative buy counts are nonsense — treat as zero, no signal."""
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": -1_000_000,
        "sell_success_count": 0,
    })
    assert out.verdict == "clean"


def test_huge_negative_sell_count_does_not_bypass() -> None:
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": 100,
        "sell_success_count": -999_999_999,
    })
    assert out.verdict == "honeypot"


# ---- Bug Z8-D: non-string bytecode crashes ---- #


def test_int_bytecode_does_not_crash() -> None:
    """Attacker passes bytecode=123 (int, not str) → .lower() raises."""
    out = score_token("0xtoken", bytecode=123)  # type: ignore[arg-type]
    assert out.verdict == "clean"


def test_bytes_bytecode_does_not_crash() -> None:
    out = score_token("0xtoken", bytecode=b"\xed\x8e\x84\xe3")  # type: ignore[arg-type]
    assert out.verdict == "clean"


def test_list_bytecode_does_not_crash() -> None:
    out = score_token("0xtoken", bytecode=["0x", "ed8e84e3"])  # type: ignore[arg-type]
    assert out.verdict == "clean"


# ---- Bug Z8-E: non-dict goplus_result variants ---- #


def test_int_goplus_result_does_not_crash() -> None:
    """Attacker posts goplus_result=42 → `'result' in 42` raises TypeError."""
    out = score_token("0xtoken", goplus_result=42)  # type: ignore[arg-type]
    assert out.verdict == "clean"


def test_bytes_goplus_result_does_not_crash() -> None:
    out = score_token("0xtoken", goplus_result=b"is_honeypot=1")  # type: ignore[arg-type]
    assert out.verdict == "clean"


def test_string_goplus_result_does_not_crash() -> None:
    out = score_token("0xtoken", goplus_result="{}")  # type: ignore[arg-type]
    assert out.verdict == "clean"


def test_list_goplus_result_does_not_crash() -> None:
    out = score_token("0xtoken", goplus_result=[{"is_honeypot": "1"}])  # type: ignore[arg-type]
    assert out.verdict == "clean"


def test_none_goplus_result_is_clean() -> None:
    out = score_token("0xtoken", goplus_result=None)
    assert out.verdict == "clean"


# ---- Bug Z8-F: launch_block evidence sanitization ---- #


def test_launch_block_with_html_does_not_inject_into_evidence() -> None:
    """If launch_block is user-controlled HTML, the evidence string
    should not embed it verbatim — could leak through to PDF or LE
    reports if not bounded."""
    out = score_token("0xtoken", tx_history_stats={
        "buy_count": 100,
        "sell_success_count": 50,
        "lp_removed_within_24h_of_launch": True,
        "launch_block": "<script>alert(1)</script>",
    })
    rug = next((s for s in out.signals if s.kind == "rug_lp_removal"), None)
    assert rug is not None
    # evidence should be bounded (sanitized to int/None, or capped len)
    assert rug.evidence is not None
    assert "<script>" not in rug.evidence, (
        f"XSS payload leaked into evidence: {rug.evidence}"
    )


# ---- Bug Z8-G: combined adversarial payload survives ---- #


def test_combined_adversarial_payload_does_not_crash() -> None:
    """Worst-case caller hostile input: every field garbage."""
    out = score_token(
        "0xtoken",
        bytecode=object(),  # type: ignore[arg-type]
        tx_history_stats={
            "buy_count": float("nan"),
            "sell_success_count": float("inf"),
            "lp_removed_within_24h_of_launch": "yes",
            "launch_block": float("nan"),
        },
        goplus_result={"result": "not a dict"},
    )
    assert out.verdict in {"clean", "low_risk", "medium_risk", "high_risk_rug", "honeypot"}
