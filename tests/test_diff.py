"""Tests for material-change detection in the worker.

Covers compute_freeze_asks_diff (pure function, no I/O) and
build_summary_text (also pure). The integration glue in run_diff_stage
is exercised by passing a synthetic fetch_prior_complete callable —
no DB / bucket mocks needed.
"""

from __future__ import annotations

import uuid
from decimal import Decimal

import pytest

from recupero.worker.diff import (
    DELTA_PCT_THRESHOLD,
    DELTA_USD_THRESHOLD,
    DiffResult,
    build_summary_text,
    compute_freeze_asks_diff,
    run_diff_stage,
)


# ----- Synthetic freeze_asks fixtures ----- #


def _ask(issuer: str, address: str, symbol: str, usd: str) -> dict:
    return {
        "address": address,
        "chain": "ethereum",
        "symbol": symbol,
        "amount": "100",
        "usd_value": usd,
        "primary_contact": "test@example.com",
        "freeze_capability": "yes",
        "explorer_url": f"https://etherscan.io/address/{address}",
    }


def _freeze_asks(*asks_by_issuer: tuple[str, dict]) -> dict:
    by_issuer: dict[str, list[dict]] = {}
    for issuer, ask in asks_by_issuer:
        by_issuer.setdefault(issuer, []).append(ask)
    return {
        "case_id": "test-case",
        "total_asks": sum(len(v) for v in by_issuer.values()),
        "by_issuer": by_issuer,
        "exchange_deposits": [],
    }


ADDR_A = "0xe3478b0BB1A5084567C319096437924948Be1964"
ADDR_B = "0x004375Dff511095CC5A197A54140a24eFEF3A416"
ADDR_C = "0x9A84A1852bC7FB608794960960ADb04666A12B41"


# =============================================================================
# compute_freeze_asks_diff
# =============================================================================


class TestComputeDiff:
    def test_both_empty(self) -> None:
        diff = compute_freeze_asks_diff({}, {})
        assert diff["new_asks"] == []
        assert diff["removed_asks"] == []
        assert diff["changed_amounts"] == []
        assert diff["new_freezable_issuers"] == []
        assert diff["removed_freezable_issuers"] == []

    def test_none_inputs_treated_as_empty(self) -> None:
        # Edge case: prior investigation never produced a freeze_asks file
        diff = compute_freeze_asks_diff(None, None)
        assert diff["new_asks"] == []
        assert diff["removed_asks"] == []

    def test_new_ask_appears(self) -> None:
        prior = _freeze_asks()
        current = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "10000.00")))
        diff = compute_freeze_asks_diff(prior, current)
        assert len(diff["new_asks"]) == 1
        assert diff["new_asks"][0]["issuer"] == "Circle"
        assert diff["new_asks"][0]["address"] == ADDR_A
        assert diff["new_asks"][0]["symbol"] == "USDC"
        assert diff["new_asks"][0]["usd_value"] == "10000.00"
        assert diff["removed_asks"] == []
        assert diff["new_freezable_issuers"] == ["Circle"]

    def test_ask_removed(self) -> None:
        prior = _freeze_asks(("Tether", _ask("Tether", ADDR_A, "USDT", "5000.00")))
        current = _freeze_asks()
        diff = compute_freeze_asks_diff(prior, current)
        assert diff["new_asks"] == []
        assert len(diff["removed_asks"]) == 1
        assert diff["removed_asks"][0]["issuer"] == "Tether"
        assert diff["removed_freezable_issuers"] == ["Tether"]

    def test_same_ask_unchanged_value(self) -> None:
        ask = _ask("Circle", ADDR_A, "USDC", "10000.00")
        prior = _freeze_asks(("Circle", ask))
        current = _freeze_asks(("Circle", dict(ask)))
        diff = compute_freeze_asks_diff(prior, current)
        assert diff["new_asks"] == []
        assert diff["removed_asks"] == []
        assert diff["changed_amounts"] == []

    def test_same_ask_changed_value_above_dollar_threshold(self) -> None:
        prior = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "10000.00")))
        current = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "12500.00")))
        diff = compute_freeze_asks_diff(prior, current)
        assert len(diff["changed_amounts"]) == 1
        change = diff["changed_amounts"][0]
        assert change["delta_usd"] == "2500.00"
        assert change["prior_usd"] == "10000.00"
        assert change["current_usd"] == "12500.00"
        assert change["address"] == ADDR_A

    def test_same_ask_changed_value_below_thresholds(self) -> None:
        # $50 delta on $10K = 0.5% — below both thresholds
        prior = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "10000.00")))
        current = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "10050.00")))
        diff = compute_freeze_asks_diff(prior, current)
        # changed_amounts captures it (anything non-zero), but
        # _is_material decides whether to flag overall material_change.
        assert len(diff["changed_amounts"]) == 1

    def test_same_ask_value_decreased(self) -> None:
        # Funds moved OUT — also material
        prior = _freeze_asks(("Tether", _ask("Tether", ADDR_A, "USDT", "20000.00")))
        current = _freeze_asks(("Tether", _ask("Tether", ADDR_A, "USDT", "5000.00")))
        diff = compute_freeze_asks_diff(prior, current)
        assert len(diff["changed_amounts"]) == 1
        assert diff["changed_amounts"][0]["delta_usd"] == "-15000.00"

    def test_multiple_changes_at_once(self) -> None:
        prior = _freeze_asks(
            ("Circle", _ask("Circle", ADDR_A, "USDC", "10000.00")),
            ("Tether", _ask("Tether", ADDR_B, "USDT", "5000.00")),
        )
        current = _freeze_asks(
            ("Circle", _ask("Circle", ADDR_A, "USDC", "15000.00")),  # increased
            # Tether row removed
            ("Sky Protocol (formerly MakerDAO)", _ask("Sky Protocol (formerly MakerDAO)", ADDR_C, "DAI", "8000.00")),  # new
        )
        diff = compute_freeze_asks_diff(prior, current)
        assert len(diff["new_asks"]) == 1
        assert diff["new_asks"][0]["issuer"] == "Sky Protocol (formerly MakerDAO)"
        assert len(diff["removed_asks"]) == 1
        assert diff["removed_asks"][0]["issuer"] == "Tether"
        assert len(diff["changed_amounts"]) == 1
        assert diff["changed_amounts"][0]["delta_usd"] == "5000.00"

    def test_address_case_insensitive_match(self) -> None:
        # Etherscan may return different cases; comparison should normalize
        prior = _freeze_asks(("Circle", _ask("Circle", ADDR_A.lower(), "USDC", "10000.00")))
        current = _freeze_asks(("Circle", _ask("Circle", ADDR_A.upper(), "USDC", "12000.00")))
        diff = compute_freeze_asks_diff(prior, current)
        # Should be a CHANGED amount, not new + removed
        assert diff["new_asks"] == []
        assert diff["removed_asks"] == []
        assert len(diff["changed_amounts"]) == 1

    def test_output_is_deterministic(self) -> None:
        # Running the same diff twice should produce identical output
        # (matters for idempotency on stale-claim retry)
        prior = _freeze_asks(
            ("Circle", _ask("Circle", ADDR_A, "USDC", "10000.00")),
            ("Tether", _ask("Tether", ADDR_B, "USDT", "5000.00")),
        )
        current = _freeze_asks(
            ("Circle", _ask("Circle", ADDR_A, "USDC", "12000.00")),
        )
        d1 = compute_freeze_asks_diff(prior, current)
        d2 = compute_freeze_asks_diff(prior, current)
        assert d1 == d2

    def test_malformed_usd_value_treated_as_zero(self) -> None:
        prior = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "garbage")))
        current = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "10000.00")))
        diff = compute_freeze_asks_diff(prior, current)
        # prior=0, current=10000 → counts as changed
        assert len(diff["changed_amounts"]) == 1
        assert diff["changed_amounts"][0]["prior_usd"] == "0.00"

    def test_missing_address_or_symbol_skipped(self) -> None:
        prior = {"by_issuer": {"Circle": [{"symbol": "USDC", "usd_value": "100"}]}}  # no address
        current = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "100")))
        diff = compute_freeze_asks_diff(prior, current)
        # The malformed prior ask is silently dropped → looks like a new ask
        assert len(diff["new_asks"]) == 1


# =============================================================================
# build_summary_text
# =============================================================================


class TestBuildSummaryText:
    def test_empty_diff(self) -> None:
        diff = compute_freeze_asks_diff({}, {})
        assert build_summary_text(diff) == "No material change."

    def test_one_new_ask(self) -> None:
        prior = _freeze_asks()
        current = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "10000.00")))
        diff = compute_freeze_asks_diff(prior, current)
        text = build_summary_text(diff)
        assert "1 new freeze target" in text
        assert "Circle" in text
        assert text.endswith(".")

    def test_multiple_new_asks_different_issuers(self) -> None:
        prior = _freeze_asks()
        current = _freeze_asks(
            ("Circle", _ask("Circle", ADDR_A, "USDC", "10000.00")),
            ("Tether", _ask("Tether", ADDR_B, "USDT", "5000.00")),
        )
        diff = compute_freeze_asks_diff(prior, current)
        text = build_summary_text(diff)
        assert "2 new freeze targets" in text
        assert "Circle" in text and "Tether" in text

    def test_removed_ask(self) -> None:
        prior = _freeze_asks(("Tether", _ask("Tether", ADDR_A, "USDT", "5000.00")))
        current = _freeze_asks()
        text = build_summary_text(compute_freeze_asks_diff(prior, current))
        assert "1 freeze target removed" in text
        assert "moved out" in text

    def test_changed_amount_increase(self) -> None:
        prior = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "10000.00")))
        current = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "22500.00")))
        text = build_summary_text(compute_freeze_asks_diff(prior, current))
        assert "USDC" in text
        assert "increased" in text
        assert "$12,500" in text

    def test_changed_amount_decrease(self) -> None:
        prior = _freeze_asks(("Tether", _ask("Tether", ADDR_A, "USDT", "20000.00")))
        current = _freeze_asks(("Tether", _ask("Tether", ADDR_A, "USDT", "5000.00")))
        text = build_summary_text(compute_freeze_asks_diff(prior, current))
        assert "decreased" in text
        assert "$15,000" in text

    def test_below_threshold_change_not_in_summary(self) -> None:
        # $50 delta on $10K = 0.5%. Below both thresholds ($1K and 5%).
        # Should NOT appear in the summary text.
        prior = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "10000.00")))
        current = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "10050.00")))
        text = build_summary_text(compute_freeze_asks_diff(prior, current))
        assert text == "No material change."

    def test_summary_picks_largest_absolute_delta(self) -> None:
        # When multiple changes, summary should cite the biggest one
        prior = _freeze_asks(
            ("Circle", _ask("Circle", ADDR_A, "USDC", "10000.00")),
            ("Tether", _ask("Tether", ADDR_B, "USDT", "5000.00")),
        )
        current = _freeze_asks(
            ("Circle", _ask("Circle", ADDR_A, "USDC", "12000.00")),  # +$2K
            ("Tether", _ask("Tether", ADDR_B, "USDT", "55000.00")),  # +$50K (bigger)
        )
        text = build_summary_text(compute_freeze_asks_diff(prior, current))
        assert "USDT" in text
        assert "$50,000" in text


# =============================================================================
# run_diff_stage (integration with synthetic fetch_prior_complete)
# =============================================================================


class TestRunDiffStage:
    def test_no_prior_returns_first_run_result(self) -> None:
        inv_id = uuid.uuid4()
        case_id = uuid.uuid4()
        result = run_diff_stage(
            investigation_id=inv_id,
            case_id=case_id,
            current_freeze_asks=_freeze_asks(),
            fetch_prior_complete=lambda c, i: None,
        )
        assert result.is_followup is False
        assert result.prior_id is None
        assert result.material_change is False
        assert result.summary is None

    def test_prior_with_no_change_returns_no_material_change(self) -> None:
        inv_id = uuid.uuid4()
        prior_id = uuid.uuid4()
        case_id = uuid.uuid4()
        ask = _ask("Circle", ADDR_A, "USDC", "10000.00")
        prior_asks = _freeze_asks(("Circle", ask))
        current_asks = _freeze_asks(("Circle", dict(ask)))

        result = run_diff_stage(
            investigation_id=inv_id,
            case_id=case_id,
            current_freeze_asks=current_asks,
            fetch_prior_complete=lambda c, i: (prior_id, prior_asks),
        )
        assert result.is_followup is True
        assert result.prior_id == prior_id
        assert result.material_change is False
        # On no-change, summary is just the text
        assert result.summary == {"summary_text_for_ui": "No material change."}

    def test_prior_with_material_change_populates_full_summary(self) -> None:
        inv_id = uuid.uuid4()
        prior_id = uuid.uuid4()
        case_id = uuid.uuid4()
        prior_asks = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "10000.00")))
        current_asks = _freeze_asks(
            ("Circle", _ask("Circle", ADDR_A, "USDC", "10000.00")),
            ("Tether", _ask("Tether", ADDR_B, "USDT", "20000.00")),
        )

        result = run_diff_stage(
            investigation_id=inv_id,
            case_id=case_id,
            current_freeze_asks=current_asks,
            fetch_prior_complete=lambda c, i: (prior_id, prior_asks),
        )
        assert result.is_followup is True
        assert result.prior_id == prior_id
        assert result.material_change is True
        assert result.summary is not None
        assert len(result.summary["new_asks"]) == 1
        assert "summary_text_for_ui" in result.summary
        assert "Tether" in result.summary["summary_text_for_ui"]

    def test_self_comparison_raises(self) -> None:
        # If somehow the prior fetch returns the current row's id,
        # we should crash loudly rather than silently produce a no-op diff.
        inv_id = uuid.uuid4()
        case_id = uuid.uuid4()
        with pytest.raises(ValueError, match="self-comparison"):
            run_diff_stage(
                investigation_id=inv_id,
                case_id=case_id,
                current_freeze_asks=_freeze_asks(),
                fetch_prior_complete=lambda c, i: (inv_id, {}),
            )


# =============================================================================
# Threshold sanity checks
# =============================================================================


class TestThresholds:
    def test_dollar_threshold_just_above(self) -> None:
        # $1,001 delta — just above the $1K threshold
        prior = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "100000.00")))
        current = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "101001.00")))
        diff = compute_freeze_asks_diff(prior, current)
        text = build_summary_text(diff)
        assert "increased" in text  # crosses dollar threshold

    def test_dollar_threshold_just_below(self) -> None:
        # $999 delta — below the $1K threshold AND below 5% on $100K
        prior = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "100000.00")))
        current = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "100999.00")))
        diff = compute_freeze_asks_diff(prior, current)
        text = build_summary_text(diff)
        assert text == "No material change."

    def test_percent_threshold_catches_drift_on_smaller_wallet(self) -> None:
        # $300 delta on $5K = 6% — crosses pct threshold even though
        # absolute is below $1K
        prior = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "5000.00")))
        current = _freeze_asks(("Circle", _ask("Circle", ADDR_A, "USDC", "5300.00")))
        diff = compute_freeze_asks_diff(prior, current)
        text = build_summary_text(diff)
        assert "increased" in text

    def test_constants_have_sane_values(self) -> None:
        # Guard against accidental edits that would over-fire alerts
        assert DELTA_USD_THRESHOLD == Decimal("1000")
        assert DELTA_PCT_THRESHOLD == Decimal("5.0")
