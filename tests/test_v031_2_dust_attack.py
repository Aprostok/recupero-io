"""v0.31.2 — dust-attack pattern detection tests.

Covers `recupero.trace.dust_attack.identify_dust_attack_destinations`
and the env-var parsing wired into `tracer._apply_dust_attack_filter`.

The detector is intended to catch perpetrators flooding many distinct
addresses with sub-cent transfers to pollute Section 5 of the brief.
The existing per-transfer dust gate (`policy.dust_threshold_usd`) can
be evaded by a sophisticated attacker who stays just under threshold,
or simply doesn't help because the destination addresses still land
in `unlabeled_counterparties` for the brief renderer. This filter
operates POST-BFS on the destination ADDRESS level instead.
"""

from __future__ import annotations

import math
import os
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from recupero.models import (
    Chain,
    Counterparty,
    TokenRef,
    Transfer,
)
from recupero.trace.dust_attack import identify_dust_attack_destinations


# ─────────────────────────────────────────────────────────────────────────────
# Test helpers
# ─────────────────────────────────────────────────────────────────────────────


_BLOCK_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    usd: Decimal | None,
    log_index: int = 0,
    amount: Decimal = Decimal("1000"),
) -> Transfer:
    """Synthetic EVM transfer for unit tests. Carries no real on-chain
    semantics — only the fields the detector consults are meaningful."""
    tx_hash = "0x" + f"{abs(hash((from_addr, to_addr, log_index))):x}".rjust(64, "0")[:64]
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:{log_index}",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=1_000_000 + log_index,
        block_time=_BLOCK_TIME,
        log_index=log_index,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr, label=None, is_contract=False),
        token=TokenRef(
            chain=Chain.ethereum,
            contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            symbol="USDC",
            decimals=6,
            coingecko_id="usd-coin",
        ),
        amount_raw=str(int(amount * 10**6)),
        amount_decimal=amount,
        usd_value_at_tx=usd,
        hop_depth=1,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
        fetched_at=_BLOCK_TIME,
    )


def _addr(suffix: int) -> str:
    """Synthetic EVM-looking address derived from an int suffix."""
    return "0x" + f"{suffix:040x}"


# ─────────────────────────────────────────────────────────────────────────────
# Core pure-function semantics
# ─────────────────────────────────────────────────────────────────────────────


def test_empty_transfer_list_returns_empty_set() -> None:
    """No transfers → no signal → empty set. Pure-function call must
    not crash on the degenerate case."""
    assert identify_dust_attack_destinations([]) == set()


def test_classic_dust_shower_20_destinations_all_flagged() -> None:
    """1 perp seed sends 20 transfers of $0.001 to 20 distinct addresses.
    All 20 destinations must be flagged."""
    perp = _addr(0xDEAD)
    transfers = [
        _mk_transfer(
            from_addr=perp,
            to_addr=_addr(i),
            usd=Decimal("0.001"),
            log_index=i,
        )
        for i in range(1, 21)
    ]
    flagged = identify_dust_attack_destinations(transfers)
    assert len(flagged) == 20
    assert flagged == {_addr(i) for i in range(1, 21)}


def test_above_threshold_transfers_not_flagged() -> None:
    """1 perp seed sends 20 transfers of $5.00 to 20 distinct addresses.
    NONE flagged — all amounts above the $1 default threshold."""
    perp = _addr(0xCAFE)
    transfers = [
        _mk_transfer(
            from_addr=perp,
            to_addr=_addr(i),
            usd=Decimal("5.00"),
            log_index=i,
        )
        for i in range(100, 120)
    ]
    flagged = identify_dust_attack_destinations(transfers)
    assert flagged == set()


def test_below_min_fanout_not_flagged() -> None:
    """1 perp seed sends 5 transfers of $0.001 to 5 distinct addresses.
    NONE flagged — below the default min_fanout of 10."""
    perp = _addr(0xBEEF)
    transfers = [
        _mk_transfer(
            from_addr=perp,
            to_addr=_addr(i),
            usd=Decimal("0.001"),
            log_index=i,
        )
        for i in range(200, 205)
    ]
    flagged = identify_dust_attack_destinations(transfers)
    assert flagged == set()


def test_consolidation_hub_plus_dust_shower_only_dust_flagged() -> None:
    """1 perp seed sends $10M to a real consolidation hub + 30 dust
    transfers to 30 distinct shower destinations. Only the 30 dust
    destinations are flagged — the consolidation hub stays in the brief.

    This exercises the confidence guard: when dust dests (30) >=
    2x non-dust dests (1), the shower pattern fires AND the
    non-dust destinations are NOT swept up.
    """
    perp = _addr(0x1234)
    consolidation_hub = _addr(0xC0DE)
    transfers = [
        # One big real payment to a consolidation hub.
        _mk_transfer(
            from_addr=perp,
            to_addr=consolidation_hub,
            usd=Decimal("10000000.00"),
            log_index=0,
        ),
    ]
    # 30 dust transfers to 30 distinct shower destinations.
    for i in range(300, 330):
        transfers.append(
            _mk_transfer(
                from_addr=perp,
                to_addr=_addr(i),
                usd=Decimal("0.001"),
                log_index=i,
            )
        )
    flagged = identify_dust_attack_destinations(transfers)
    assert consolidation_hub not in flagged
    assert flagged == {_addr(i) for i in range(300, 330)}
    assert len(flagged) == 30


def test_confidence_guard_dust_not_dominating_non_dust() -> None:
    """If a source has 10 dust dests + 10 real-payment dests, the
    2x guard should SUPPRESS the shower signal — this is the
    legitimate "many small refunds + many real payments" pattern, not
    a dust attack."""
    perp = _addr(0xAA)
    transfers = []
    # 10 dust destinations.
    for i in range(400, 410):
        transfers.append(
            _mk_transfer(
                from_addr=perp,
                to_addr=_addr(i),
                usd=Decimal("0.50"),
                log_index=i,
            )
        )
    # 10 real-payment destinations.
    for i in range(500, 510):
        transfers.append(
            _mk_transfer(
                from_addr=perp,
                to_addr=_addr(i),
                usd=Decimal("250.00"),
                log_index=i,
            )
        )
    # 10 dust vs 10 non-dust → ratio 1.0 (< 2.0 guard) → suppressed.
    flagged = identify_dust_attack_destinations(transfers)
    assert flagged == set()


def test_confidence_guard_exactly_2x_fires() -> None:
    """The guard is `dust >= 2 * non_dust` (inclusive). 20 dust to
    10 non-dust = exactly 2x → should fire."""
    perp = _addr(0xBB)
    transfers = []
    for i in range(600, 620):
        transfers.append(_mk_transfer(
            from_addr=perp, to_addr=_addr(i),
            usd=Decimal("0.001"), log_index=i,
        ))
    for i in range(700, 710):
        transfers.append(_mk_transfer(
            from_addr=perp, to_addr=_addr(i),
            usd=Decimal("100.00"), log_index=i,
        ))
    flagged = identify_dust_attack_destinations(transfers)
    assert flagged == {_addr(i) for i in range(600, 620)}


# ─────────────────────────────────────────────────────────────────────────────
# Robustness against malformed inputs (NaN / Inf USD values)
# ─────────────────────────────────────────────────────────────────────────────


def _force_usd(transfer: Transfer, usd: Decimal) -> Transfer:
    """Bypass pydantic finite-number validation to inject a NaN/Inf
    `usd_value_at_tx`. Pydantic's `finite_number` constraint blocks the
    happy path (a hardening win from RIGOR-Jacob F) but the detector
    must STILL survive if a NaN somehow slips through (e.g., a future
    ingest path drops the constraint, or a model_validate bypass).
    Defense in depth: assert the detector handles the inputs the
    pydantic layer is supposed to reject.

    Uses object.__setattr__ to skirt pydantic's field assignment hook.
    """
    object.__setattr__(transfer, "usd_value_at_tx", usd)
    return transfer


def test_nan_usd_value_does_not_crash_no_dust_signal() -> None:
    """A transfer with Decimal('NaN') in usd_value_at_tx must not crash
    the detector AND must not be counted as dust signal (NaN is "we don't
    know" — neither dust nor non-dust).

    Pydantic blocks NaN at construction (since RIGOR-Jacob F), so we
    inject via object.__setattr__ to confirm the detector survives even
    if that hardening is bypassed by a future ingest seam."""
    perp = _addr(0xFF)
    transfers = []
    for i in range(20):
        t = _mk_transfer(
            from_addr=perp,
            to_addr=_addr(800 + i),
            usd=Decimal("0.001"),
            log_index=i,
        )
        transfers.append(_force_usd(t, Decimal("NaN")))
    # No-op — NaN doesn't count as dust signal.
    flagged = identify_dust_attack_destinations(transfers)
    assert flagged == set()


def test_inf_usd_value_does_not_crash_no_dust_signal() -> None:
    """+Infinity in usd_value_at_tx must be ignored, not treated as
    'definitely above threshold'. Inject via object.__setattr__ to
    bypass pydantic's finite-number constraint."""
    perp = _addr(0xEE)
    transfers = []
    for i in range(20):
        t = _mk_transfer(
            from_addr=perp,
            to_addr=_addr(900 + i),
            usd=Decimal("0.001"),
            log_index=i,
        )
        transfers.append(_force_usd(t, Decimal("Infinity")))
    flagged = identify_dust_attack_destinations(transfers)
    assert flagged == set()


def test_none_usd_value_does_not_crash_no_dust_signal() -> None:
    """`usd_value_at_tx is None` (unpriced token) is the most common
    real-world case where the dust signal is unknowable. The detector
    must skip these rather than treat them as either dust or non-dust."""
    perp = _addr(0xDD)
    transfers = [
        _mk_transfer(
            from_addr=perp,
            to_addr=_addr(1000 + i),
            usd=None,
            log_index=i,
        )
        for i in range(20)
    ]
    flagged = identify_dust_attack_destinations(transfers)
    assert flagged == set()


def test_mixed_nan_and_real_dust_only_real_dust_counts() -> None:
    """If a source has 10 NaN-priced + 15 real-dust transfers to distinct
    addresses, only the 15 real-dust ones should be counted toward
    fan-out. Threshold is met → the 15 real-dust addresses flagged.
    NaN-priced ones are skipped (carry no signal)."""
    perp = _addr(0xCC)
    transfers = []
    # 10 NaN-priced (carry no signal). Inject via object.__setattr__ to
    # bypass pydantic's finite-number validator.
    for i in range(1100, 1110):
        t = _mk_transfer(
            from_addr=perp, to_addr=_addr(i),
            usd=Decimal("0.001"), log_index=i,
        )
        transfers.append(_force_usd(t, Decimal("NaN")))
    # 15 real-dust to distinct addresses.
    for i in range(1200, 1215):
        transfers.append(_mk_transfer(
            from_addr=perp, to_addr=_addr(i),
            usd=Decimal("0.001"), log_index=i,
        ))
    flagged = identify_dust_attack_destinations(transfers)
    assert flagged == {_addr(i) for i in range(1200, 1215)}
    # NaN-priced addresses are not flagged.
    for i in range(1100, 1110):
        assert _addr(i) not in flagged


# ─────────────────────────────────────────────────────────────────────────────
# Multiple sources / interactions
# ─────────────────────────────────────────────────────────────────────────────


def test_multiple_sources_each_evaluated_independently() -> None:
    """Two distinct sources each running a shower → both flagged.
    Verifies the per-source grouping is correct."""
    perp_a = _addr(0xA000)
    perp_b = _addr(0xB000)
    transfers = []
    for i in range(2000, 2015):
        transfers.append(_mk_transfer(
            from_addr=perp_a, to_addr=_addr(i),
            usd=Decimal("0.001"), log_index=i,
        ))
    for i in range(2100, 2115):
        transfers.append(_mk_transfer(
            from_addr=perp_b, to_addr=_addr(i),
            usd=Decimal("0.001"), log_index=i,
        ))
    flagged = identify_dust_attack_destinations(transfers)
    expected = {_addr(i) for i in range(2000, 2015)} | {_addr(i) for i in range(2100, 2115)}
    assert flagged == expected


def test_duplicate_destinations_from_same_source_dedupe() -> None:
    """If the perp hits the SAME address 20 times with dust, that's
    only 1 distinct destination and should NOT trigger fan-out (it's
    a single noisy address, not a shower)."""
    perp = _addr(0xDED)
    same_dest = _addr(0xDEAD2)
    transfers = [
        _mk_transfer(
            from_addr=perp,
            to_addr=same_dest,
            usd=Decimal("0.001"),
            log_index=i,
        )
        for i in range(20)
    ]
    flagged = identify_dust_attack_destinations(transfers)
    assert flagged == set()


# ─────────────────────────────────────────────────────────────────────────────
# Custom threshold + min_fanout parameters
# ─────────────────────────────────────────────────────────────────────────────


def test_custom_threshold_catches_just_under() -> None:
    """With threshold=$10, transfers of $9.99 should be caught."""
    perp = _addr(0x999)
    transfers = [
        _mk_transfer(
            from_addr=perp, to_addr=_addr(i),
            usd=Decimal("9.99"), log_index=i,
        )
        for i in range(3000, 3015)
    ]
    flagged = identify_dust_attack_destinations(
        transfers, dust_threshold_usd=Decimal("10.00"),
    )
    assert flagged == {_addr(i) for i in range(3000, 3015)}


def test_custom_min_fanout_3_triggers_at_3() -> None:
    """With min_fanout=3, 3 distinct dust destinations trigger."""
    perp = _addr(0x333)
    transfers = [
        _mk_transfer(
            from_addr=perp, to_addr=_addr(i),
            usd=Decimal("0.001"), log_index=i,
        )
        for i in range(4000, 4003)
    ]
    flagged = identify_dust_attack_destinations(transfers, min_fanout=3)
    assert flagged == {_addr(i) for i in range(4000, 4003)}


def test_invalid_threshold_falls_back_to_default() -> None:
    """Pure-function defensive: a caller passing Decimal('NaN') as
    threshold should fall back to default $1.00 rather than crash."""
    perp = _addr(0x111)
    transfers = [
        _mk_transfer(
            from_addr=perp, to_addr=_addr(i),
            usd=Decimal("0.001"), log_index=i,
        )
        for i in range(5000, 5015)
    ]
    # NaN threshold falls back to $1.00 default → these all qualify.
    flagged = identify_dust_attack_destinations(
        transfers, dust_threshold_usd=Decimal("NaN"),
    )
    assert flagged == {_addr(i) for i in range(5000, 5015)}


def test_invalid_min_fanout_falls_back_to_default() -> None:
    """min_fanout=0 (nonsensical) → fall back to default 10."""
    perp = _addr(0x222)
    # Only 5 dust → below default 10 → nothing flagged after fallback.
    transfers = [
        _mk_transfer(
            from_addr=perp, to_addr=_addr(i),
            usd=Decimal("0.001"), log_index=i,
        )
        for i in range(6000, 6005)
    ]
    flagged = identify_dust_attack_destinations(transfers, min_fanout=0)
    assert flagged == set()


# ─────────────────────────────────────────────────────────────────────────────
# Env-var parsing — mirror the tracer.py _apply_dust_attack_filter logic.
# Sanity-checks the NaN/Inf-rejecting branch follows the same pattern
# as v0.31.1's RECUPERO_CROSSCHAIN_WINDOW_HOURS.
# ─────────────────────────────────────────────────────────────────────────────


def _parse_threshold_env(monkeypatch: pytest.MonkeyPatch, raw: str | None) -> Decimal:
    """Mirror the env-var threshold parser in tracer._apply_dust_attack_filter."""
    if raw is None:
        monkeypatch.delenv("RECUPERO_DUST_ATTACK_THRESHOLD_USD", raising=False)
    else:
        monkeypatch.setenv("RECUPERO_DUST_ATTACK_THRESHOLD_USD", raw)
    threshold_usd = Decimal("1.00")
    env_raw = os.environ.get("RECUPERO_DUST_ATTACK_THRESHOLD_USD")
    if env_raw is not None:
        try:
            env_thr = float(env_raw)
            if not math.isfinite(env_thr) or env_thr < 0:
                raise ValueError("non-finite or negative")
            clamped = max(0.0, min(100.0, env_thr))
            threshold_usd = Decimal(str(clamped))
        except (TypeError, ValueError):
            pass
    return threshold_usd


def _parse_min_fanout_env(monkeypatch: pytest.MonkeyPatch, raw: str | None) -> int:
    if raw is None:
        monkeypatch.delenv("RECUPERO_DUST_ATTACK_MIN_FANOUT", raising=False)
    else:
        monkeypatch.setenv("RECUPERO_DUST_ATTACK_MIN_FANOUT", raw)
    min_fanout = 10
    env_raw = os.environ.get("RECUPERO_DUST_ATTACK_MIN_FANOUT")
    if env_raw is not None:
        try:
            env_fan = int(env_raw)
            min_fanout = max(3, min(1000, env_fan))
        except (TypeError, ValueError):
            pass
    return min_fanout


def test_env_threshold_nan_rejected_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    """`RECUPERO_DUST_ATTACK_THRESHOLD_USD=NaN` must reject and fall
    back to the $1.00 default. NaN comparisons silently break filtering
    — this is the v0.31.1 RECUPERO_CROSSCHAIN_WINDOW_HOURS pattern."""
    assert _parse_threshold_env(monkeypatch, "NaN") == Decimal("1.00")
    assert _parse_threshold_env(monkeypatch, "nan") == Decimal("1.00")


def test_env_threshold_inf_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _parse_threshold_env(monkeypatch, "Infinity") == Decimal("1.00")
    assert _parse_threshold_env(monkeypatch, "inf") == Decimal("1.00")
    assert _parse_threshold_env(monkeypatch, "-inf") == Decimal("1.00")


def test_env_threshold_negative_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _parse_threshold_env(monkeypatch, "-1") == Decimal("1.00")


def test_env_threshold_clamped_to_100(monkeypatch: pytest.MonkeyPatch) -> None:
    """Values above $100 clamp to $100 — above that catches legitimate
    small payments."""
    assert _parse_threshold_env(monkeypatch, "1000") == Decimal("100.0")
    assert _parse_threshold_env(monkeypatch, "999999") == Decimal("100.0")


def test_env_threshold_garbage_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _parse_threshold_env(monkeypatch, "abc") == Decimal("1.00")
    assert _parse_threshold_env(monkeypatch, "") == Decimal("1.00")


def test_env_threshold_normal_value_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _parse_threshold_env(monkeypatch, "0.5") == Decimal("0.5")
    assert _parse_threshold_env(monkeypatch, "10") == Decimal("10.0")
    assert _parse_threshold_env(monkeypatch, "0") == Decimal("0.0")


def test_env_threshold_unset_uses_default(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _parse_threshold_env(monkeypatch, None) == Decimal("1.00")


def test_env_min_fanout_clamps_below_three(monkeypatch: pytest.MonkeyPatch) -> None:
    """min_fanout < 3 catches legitimate change-back patterns.
    Clamp UP to 3."""
    assert _parse_min_fanout_env(monkeypatch, "0") == 3
    assert _parse_min_fanout_env(monkeypatch, "-5") == 3
    assert _parse_min_fanout_env(monkeypatch, "1") == 3


def test_env_min_fanout_clamps_above_1000(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _parse_min_fanout_env(monkeypatch, "5000") == 1000
    assert _parse_min_fanout_env(monkeypatch, "999999999") == 1000


def test_env_min_fanout_garbage_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _parse_min_fanout_env(monkeypatch, "abc") == 10
    assert _parse_min_fanout_env(monkeypatch, "NaN") == 10
    assert _parse_min_fanout_env(monkeypatch, "") == 10


def test_env_min_fanout_unset_uses_default(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _parse_min_fanout_env(monkeypatch, None) == 10


def test_env_min_fanout_normal_value_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _parse_min_fanout_env(monkeypatch, "20") == 20
    assert _parse_min_fanout_env(monkeypatch, "500") == 500


# ─────────────────────────────────────────────────────────────────────────────
# Integration with case.unlabeled_counterparties — verify the filter
# only removes dust-attack destinations, leaving real counterparties.
# ─────────────────────────────────────────────────────────────────────────────


def test_filter_preserves_real_counterparties_drops_shower_dests() -> None:
    """End-to-end shape: if `unlabeled_counterparties` contains 1 real
    consolidation hub + 30 shower dests, after filtering with the
    dust-attack set the list should contain only the consolidation hub."""
    perp = _addr(0x7777)
    consolidation = _addr(0x7C7C)
    transfers = [
        _mk_transfer(
            from_addr=perp, to_addr=consolidation,
            usd=Decimal("100000.00"), log_index=0,
        ),
    ]
    for i in range(8000, 8030):
        transfers.append(_mk_transfer(
            from_addr=perp, to_addr=_addr(i),
            usd=Decimal("0.001"), log_index=i,
        ))
    flagged = identify_dust_attack_destinations(transfers)
    unlabeled_before = [consolidation] + [_addr(i) for i in range(8000, 8030)]
    unlabeled_after = [a for a in unlabeled_before if a not in flagged]
    assert unlabeled_after == [consolidation]
    assert len(unlabeled_after) == 1
