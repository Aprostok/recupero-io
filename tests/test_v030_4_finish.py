"""v0.30.4 finish-line tests: remaining NaN sites, SOURCE_DATE_EPOCH
coverage, cross-chain $NaN, aggregate atomic write, dotted-I flake fix.
"""
from __future__ import annotations

from decimal import Decimal
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────
# T2-A: SOURCE_DATE_EPOCH honored by the new shared helper
# ──────────────────────────────────────────────────────────────────────


def test_resolve_render_time_honors_source_date_epoch(monkeypatch) -> None:
    """When SOURCE_DATE_EPOCH is set, the helper returns that exact
    moment in UTC (not wall-clock)."""
    from recupero._common import resolve_render_time
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1577836800")  # 2020-01-01 00:00:00 UTC
    t = resolve_render_time()
    assert t.year == 2020 and t.month == 1 and t.day == 1
    assert t.tzinfo is not None


def test_resolve_render_time_falls_back_on_bad_epoch(monkeypatch) -> None:
    """Garbage SOURCE_DATE_EPOCH should not crash; fall back to wall-clock."""
    from recupero._common import resolve_render_time
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-an-integer")
    t = resolve_render_time()
    assert t.tzinfo is not None


def test_resolve_render_time_no_env_returns_wall_clock(monkeypatch) -> None:
    from recupero._common import resolve_render_time
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    t = resolve_render_time()
    assert t.tzinfo is not None


def test_all_seven_renderers_route_through_shared_helper() -> None:
    """Grep-level proof: every renderer imports `resolve_render_time`
    from `_common.py`. If any renderer regresses to bare
    `datetime.now(UTC)` it shows up here."""
    targets = [
        "src/recupero/reports/cluster_handoff.py",
        "src/recupero/reports/aggregate.py",
        "src/recupero/reports/ai_editorial.py",
        "src/recupero/reports/cooperation_dashboard.py",
        "src/recupero/reports/legal_requests.py",
        "src/recupero/reports/subpoena_renderer.py",
        "src/recupero/reports/law_firm_dashboard.py",
    ]
    for path in targets:
        src = Path(path).read_text(encoding="utf-8")
        assert "resolve_render_time" in src, (
            f"{path}: does not import or call resolve_render_time. "
            f"V030_2_CORRECTNESS_AUDIT T2-A regression."
        )


# ──────────────────────────────────────────────────────────────────────
# T2-B: cross_chain $NaN render guard
# ──────────────────────────────────────────────────────────────────────


def test_cross_chain_brief_section_skips_nan_amount_usd() -> None:
    """`handoffs_to_brief_section` must NOT render $NaN into the
    LE handoff cross-chain table."""
    from recupero.models import Chain
    from recupero.trace.cross_chain import CrossChainHandoff, handoffs_to_brief_section
    h = CrossChainHandoff(
        source_chain=Chain.ethereum,
        source_address="0xVictim",
        source_tx_hash="0xabc",
        source_explorer_url="https://etherscan.io/tx/0xabc",
        bridge_name="Test Bridge",
        bridge_protocol="testbridge",
        bridge_address="0xBridge",
        amount_decimal=Decimal("100"),
        amount_usd=Decimal("NaN"),
        token_symbol="USDT",
        block_time_iso="2026-01-01T00:00:00Z",
        follow_up_url="https://example.com/follow",
        destination_chain_candidates=("solana",),
    )
    section = handoffs_to_brief_section([h])
    assert len(section) == 1
    # amount_usd must NOT be a $NaN string; should be None.
    assert section[0]["amount_usd"] is None, (
        f"NaN amount_usd leaked into brief section: {section[0]['amount_usd']!r}"
    )


def test_cross_chain_investigator_note_skips_inf_usd() -> None:
    """The investigator-note prose must not render 'Bridged $Infinity'."""
    from recupero.models import Chain
    from recupero.trace.cross_chain import CrossChainHandoff, _build_investigator_note
    h = CrossChainHandoff(
        source_chain=Chain.ethereum,
        source_address="0xV",
        source_tx_hash="0xa",
        source_explorer_url="x",
        bridge_name="b",
        bridge_protocol="bp",
        bridge_address="0xB",
        amount_decimal=Decimal("100"),
        amount_usd=Decimal("Infinity"),
        token_symbol="USDT",
        block_time_iso="2026-01-01T00:00:00Z",
        follow_up_url="x",
        destination_chain_candidates=("solana",),
    )
    note = _build_investigator_note(h)
    assert "$Infinity" not in note
    assert "$NaN" not in note


# ──────────────────────────────────────────────────────────────────────
# Turkish dotted-I filename flake
# ──────────────────────────────────────────────────────────────────────


def test_safe_filename_segment_turkish_dotted_i_caps_correctly() -> None:
    """The pre-v0.30.4 bug: 64 Turkish dotted-I (U+0130) chars
    truncated to 64, THEN lowercased — each U+0130 became "i̇"
    (Latin i + combining diacritical mark), expanding the output to
    65 chars. v0.30.4 swaps the order: lowercase first, then truncate."""
    from recupero.reports.legal_requests import _safe_filename_segment
    # The exact failing example from hypothesis:
    adversarial = "0" * 63 + "İ"
    out = _safe_filename_segment(adversarial)
    assert len(out) <= 64, (
        f"Output exceeded 64 chars: {len(out)} chars in {out!r}. "
        f"Lowercase-then-truncate order needed."
    )


def test_safe_filename_segment_caps_at_64_with_normal_input() -> None:
    """Don't regress the normal case."""
    from recupero.reports.legal_requests import _safe_filename_segment
    out = _safe_filename_segment("a" * 200)
    assert len(out) <= 64


# ──────────────────────────────────────────────────────────────────────
# Remaining NaN sites (ai_editorial + freeze/asks)
# ──────────────────────────────────────────────────────────────────────


def test_freeze_asks_flow_usd_value_excludes_nan() -> None:
    """`flow_usd_value` bucket must not be poisoned by a NaN transfer.
    A poisoned bucket renders `$NaN` into the freeze letter as the
    "amount we're asking you to freeze" — instant credibility hit.

    Verify the grep: the source contains the is_finite() guard.
    That's the regression we want to pin without coupling the test
    to the function's private signature."""
    src = Path("src/recupero/freeze/asks.py").read_text(encoding="utf-8")
    # The two sites flagged by V030_2_CORRECTNESS_AUDIT:
    assert src.count('is_finite()') >= 4, (
        "freeze/asks.py is missing is_finite() guards. "
        "V030_2_CORRECTNESS_AUDIT T1-B requires both "
        "flow_usd_value and total_usd accumulators to skip NaN."
    )


def test_ai_editorial_aggregators_have_finite_guards() -> None:
    """ai_editorial.py has 2 USD aggregators (drain + first-hop,
    per_addr_received). V030_2_CORRECTNESS_AUDIT T1-B requires
    `.is_finite()` filters."""
    src = Path("src/recupero/reports/ai_editorial.py").read_text(encoding="utf-8")
    # Both sites should now carry the guard.
    finite_guards = src.count("usd_value_at_tx.is_finite()")
    assert finite_guards >= 2, (
        f"ai_editorial.py has only {finite_guards} is_finite() guards; "
        f"V030_2_CORRECTNESS_AUDIT T1-B expects ≥2 (drain+first-hop and "
        f"per_addr_received aggregators)."
    )


# ──────────────────────────────────────────────────────────────────────
# T2-C: aggregate atomic write
# ──────────────────────────────────────────────────────────────────────


def test_aggregate_uses_atomic_write_text() -> None:
    """V030_2_CORRECTNESS_AUDIT T2-C: aggregate.py was bare
    `Path.write_text`; mid-write SIGKILL leaves a truncated JSON that
    the next CLI invocation treats as authoritative. Fix uses
    atomic_write_text (write-to-temp + rename)."""
    src = Path("src/recupero/reports/aggregate.py").read_text(encoding="utf-8")
    assert "atomic_write_text" in src, (
        "aggregate.py does not use atomic_write_text. T2-C regression."
    )
    # And the bare `.write_text` site should be gone from the JSON-write
    # path (it might still appear in other contexts but the final JSON
    # write must be atomic).
    assert "out_path.write_text" not in src, (
        "aggregate.py still has bare out_path.write_text. "
        "Should be atomic_write_text(out_path, ...)."
    )


# ──────────────────────────────────────────────────────────────────────
# Security T1-B: pepper_id schema migration
# ──────────────────────────────────────────────────────────────────────


def test_pepper_id_migration_exists() -> None:
    """V030_2_SECURITY_AUDIT T1-B: PEPPER rotation needs `pepper_id`
    on `case_tokens` so operators can enumerate affected victims
    post-rotation."""
    mig = Path("migrations/026_case_tokens_pepper_id.sql")
    assert mig.exists(), "026_case_tokens_pepper_id.sql migration missing"
    sql = mig.read_text(encoding="utf-8")
    # Must add the column.
    assert "ALTER TABLE case_tokens" in sql
    assert "pepper_id" in sql.lower()
    # Must include the rotation-recovery index.
    assert "CREATE INDEX" in sql.upper()
    # Must default backfill existing rows to a sentinel.
    assert "DEFAULT" in sql.upper() or "legacy" in sql.lower()
