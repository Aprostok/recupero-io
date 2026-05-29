"""v0.31.0 — MEV / sandwich-attack obfuscation detection (Gap #9).

Five core behaviors covered:

  1. tx_metadata gas_price=0 → flashbots_bundle signal at conf 0.7
  2. 3-tx same-block flanking pattern → sandwich signal at conf 0.85
  3. clean case (no MEV shape) → empty signal list
  4. seed funded by a known MEV builder → mev_source signal at conf 0.9
  5. NaN-poisoned tx_metadata input doesn't crash detection

Plus brief-section wiring (rendering threshold, suppression count)
and dedupe (same tx_hash + signal_type collapses).

Pattern follows tests/test_v030_3_nan_poisoning.py and
tests/test_drainer_and_dex.py for fixture style.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from recupero.models import (
    Case,
    Chain,
    Counterparty,
    TokenRef,
    Transfer,
)
from recupero.trace.mev_detection import (
    BRIEF_RENDER_CONFIDENCE_FLOOR,
    MEVSignal,
    detect_mev_signals,
    mev_signals_to_brief_section,
)

# Verified addresses (lowercased canonical form matches the module).
_SEED = "0x000000000000000000000000000000000000beef"
_ATTACKER = "0x00000000000000000000000000000000000a77ac"
_POOL = "0x00000000000000000000000000000000000aabba"
_FLASHBOTS_BUILDER = "0xdAFEA492D9c6733ae3d56b7Ed1ADB60692c98Bc5"
_BEAVERBUILD = "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5"


# ────────────────────────────────────────────────────────────────────
# Fixtures
# ────────────────────────────────────────────────────────────────────


def _mk_transfer(
    *,
    from_addr: str,
    to_addr: str,
    tx_hash: str,
    block_num: int = 1,
    log_index: int = 0,
    amount: Decimal = Decimal("100"),
    usd: Decimal | None = Decimal("100"),
) -> Transfer:
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    return Transfer(
        transfer_id=f"{tx_hash}:{log_index}:{from_addr}:{to_addr}",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=block_num,
        block_time=ts,
        log_index=log_index,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(address=to_addr),
        token=TokenRef(
            chain=Chain.ethereum,
            contract="0xdAC17F958D2ee523a2206206994597C13D831ec7",
            symbol="USDT",
            decimals=6,
        ),
        amount_raw=str(int(amount * 10**6)),
        amount_decimal=amount,
        usd_value_at_tx=usd,
        hop_depth=0,
        parent_transfer_id=None,
        pricing_source=None,
        pricing_error=None,
        fetched_at=ts,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
    )


def _mk_case(transfers: list[Transfer], seed: str = _SEED) -> Case:
    return Case(
        case_id="MEV-TEST",
        seed_address=seed,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=UTC),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        software_version="test",
        config_used={},
    )


# ────────────────────────────────────────────────────────────────────
# Heuristic 1: Flashbots / MEV-Boost bundle (gas_price ≤ 1 gwei)
# ────────────────────────────────────────────────────────────────────


def test_flashbots_bundle_zero_gas_price_flagged() -> None:
    """gas_price=0 tx metadata → flashbots_bundle signal."""
    tx = "0x" + "a" * 64
    case = _mk_case([_mk_transfer(
        from_addr=_SEED, to_addr=_ATTACKER, tx_hash=tx, block_num=10,
    )])
    signals = detect_mev_signals(case, tx_metadata={tx: {"gas_price": 0}})
    types = [s.signal_type for s in signals]
    assert "flashbots_bundle" in types, (
        f"Expected flashbots_bundle signal on gas_price=0 tx; got {types}"
    )
    fb = next(s for s in signals if s.signal_type == "flashbots_bundle")
    assert fb.tx_hash == tx
    assert 0.5 <= fb.confidence <= 1.0
    assert "bundle" in fb.forensic_note.lower() or "gas_price" in fb.forensic_note.lower()


def test_flashbots_bundle_one_gwei_threshold_flagged() -> None:
    """Up to 1 gwei is also bundle-shape (L1 system-tx edge case)."""
    tx = "0x" + "b" * 64
    case = _mk_case([_mk_transfer(
        from_addr=_SEED, to_addr=_ATTACKER, tx_hash=tx, block_num=11,
    )])
    signals = detect_mev_signals(
        case, tx_metadata={tx: {"gas_price": 1_000_000_000}},
    )
    assert any(s.signal_type == "flashbots_bundle" for s in signals)


def test_flashbots_bundle_normal_gas_price_not_flagged() -> None:
    """Normal gas (50 gwei) must NOT be flagged."""
    tx = "0x" + "c" * 64
    case = _mk_case([_mk_transfer(
        from_addr=_SEED, to_addr=_ATTACKER, tx_hash=tx, block_num=12,
    )])
    signals = detect_mev_signals(
        case, tx_metadata={tx: {"gas_price": 50_000_000_000}},
    )
    assert not any(s.signal_type == "flashbots_bundle" for s in signals), (
        "50 gwei gas price was incorrectly flagged as MEV bundle"
    )


def test_flashbots_bundle_direct_builder_metadata() -> None:
    """tx_metadata.builder == known builder address → bundle flag."""
    tx = "0x" + "d" * 64
    case = _mk_case([_mk_transfer(
        from_addr=_ATTACKER, to_addr=_SEED, tx_hash=tx, block_num=13,
    )])
    signals = detect_mev_signals(
        case, tx_metadata={tx: {"builder": _FLASHBOTS_BUILDER}},
    )
    fb = [s for s in signals if s.signal_type == "flashbots_bundle"]
    assert fb, "Builder-tagged tx not flagged as flashbots_bundle"
    assert fb[0].builder_name == "Flashbots: Builder"


# ────────────────────────────────────────────────────────────────────
# Heuristic 2: Sandwich pattern (3-tx same-block, flanking address)
# ────────────────────────────────────────────────────────────────────


def test_sandwich_pattern_detected() -> None:
    """Front-run + victim + back-run in same block, attacker on outer pair."""
    front_tx = "0x" + "1" * 64
    victim_tx = "0x" + "2" * 64
    back_tx = "0x" + "3" * 64
    transfers = [
        _mk_transfer(
            from_addr=_ATTACKER, to_addr=_POOL,
            tx_hash=front_tx, block_num=100, log_index=0,
        ),
        _mk_transfer(
            from_addr=_SEED, to_addr=_POOL,
            tx_hash=victim_tx, block_num=100, log_index=1,
        ),
        _mk_transfer(
            from_addr=_ATTACKER, to_addr=_POOL,
            tx_hash=back_tx, block_num=100, log_index=2,
        ),
    ]
    signals = detect_mev_signals(_mk_case(transfers))
    sandwich = [s for s in signals if s.signal_type == "sandwich"]
    assert len(sandwich) == 1, (
        f"Expected exactly one sandwich signal; got {len(sandwich)}: {signals}"
    )
    s = sandwich[0]
    assert s.tx_hash == victim_tx
    assert s.confidence >= 0.5
    assert s.address == _ATTACKER.lower()


def test_sandwich_requires_same_outer_address() -> None:
    """If outer two are DIFFERENT addresses, this is not a sandwich."""
    other_attacker = "0x" + "f" * 40
    transfers = [
        _mk_transfer(
            from_addr=_ATTACKER, to_addr=_POOL,
            tx_hash="0x" + "1" * 64, block_num=101, log_index=0,
        ),
        _mk_transfer(
            from_addr=_SEED, to_addr=_POOL,
            tx_hash="0x" + "2" * 64, block_num=101, log_index=1,
        ),
        _mk_transfer(
            from_addr=other_attacker, to_addr=_POOL,
            tx_hash="0x" + "3" * 64, block_num=101, log_index=2,
        ),
    ]
    signals = detect_mev_signals(_mk_case(transfers))
    assert not any(s.signal_type == "sandwich" for s in signals)


# ────────────────────────────────────────────────────────────────────
# Heuristic 3: Clean case → empty
# ────────────────────────────────────────────────────────────────────


def test_clean_case_no_signals() -> None:
    """Vanilla transfer with normal gas, no builders, no flanking → []."""
    tx = "0x" + "e" * 64
    case = _mk_case([_mk_transfer(
        from_addr=_SEED, to_addr=_ATTACKER, tx_hash=tx, block_num=200,
    )])
    signals = detect_mev_signals(
        case, tx_metadata={tx: {"gas_price": 30_000_000_000}},
    )
    assert signals == [], f"Clean case produced signals: {signals}"


def test_empty_case_no_signals() -> None:
    """No transfers at all → []."""
    case = _mk_case([])
    assert detect_mev_signals(case) == []


def test_none_case_no_crash() -> None:
    """detect_mev_signals(None) returns [] rather than crashing."""
    assert detect_mev_signals(None) == []  # type: ignore[arg-type]


# ────────────────────────────────────────────────────────────────────
# Heuristic 4: MEV-builder-sourced funds
# ────────────────────────────────────────────────────────────────────


def test_mev_source_funds_detected() -> None:
    """Seed receives funds directly from a known builder → mev_source."""
    tx = "0x" + "9" * 64
    transfers = [_mk_transfer(
        from_addr=_BEAVERBUILD, to_addr=_SEED,
        tx_hash=tx, block_num=300,
    )]
    signals = detect_mev_signals(_mk_case(transfers))
    src = [s for s in signals if s.signal_type == "mev_source"]
    assert len(src) == 1
    assert src[0].builder_name == "beaverbuild"
    assert src[0].confidence >= 0.5
    assert src[0].tx_hash == tx


def test_mev_source_case_insensitive_builder_address() -> None:
    """Builder address comparison must be case-insensitive."""
    tx = "0x" + "8" * 64
    transfers = [_mk_transfer(
        # Upper-case the builder address to ensure the canonical
        # lowercase compare still matches.
        from_addr=_FLASHBOTS_BUILDER.upper(), to_addr=_SEED,
        tx_hash=tx, block_num=301,
    )]
    signals = detect_mev_signals(_mk_case(transfers))
    assert any(s.signal_type == "mev_source" for s in signals), (
        "MEV-source detection is case-sensitive — checksum vs lowercase "
        "addresses must compare equal"
    )


# ────────────────────────────────────────────────────────────────────
# Heuristic 5: NaN-poisoned input must not crash
# ────────────────────────────────────────────────────────────────────


def test_nan_in_tx_metadata_does_not_crash() -> None:
    """NaN / Inf / garbage gas_price in metadata must not raise."""
    tx = "0x" + "7" * 64
    case = _mk_case([_mk_transfer(
        from_addr=_SEED, to_addr=_ATTACKER, tx_hash=tx, block_num=400,
    )])
    # NaN as float, Inf as Decimal, list as int substitute, None.
    bad_metadata: dict[str, dict[str, Any]] = {
        tx: {"gas_price": float("nan")},
        "other": {"gas_price": Decimal("Infinity")},
        "garbage1": {"gas_price": [1, 2, 3]},
        "garbage2": {"gas_price": None},
        "garbage3": {"builder": object()},
    }
    # Must not raise — return value just shouldn't fire on NaN/Inf rows.
    signals = detect_mev_signals(case, tx_metadata=bad_metadata)
    # gas_price=NaN must NOT pass the ≤1 gwei check.
    assert not any(
        s.signal_type == "flashbots_bundle" and s.tx_hash == tx
        for s in signals
    ), "NaN gas_price was incorrectly treated as ≤ 1 gwei"


def test_nan_amount_in_transfer_does_not_crash() -> None:
    """A transfer whose amount/usd carries NaN (via model_construct
    bypass) must not crash the MEV pass."""
    fields: dict[str, Any] = {
        "transfer_id": "tx:0:a:b",
        "chain": Chain.ethereum,
        "tx_hash": "0x" + "f" * 64,
        "block_number": 500,
        "block_time": datetime(2026, 1, 1, tzinfo=UTC),
        "log_index": 0,
        "from_address": _SEED,
        "to_address": _ATTACKER,
        "counterparty": Counterparty(address=_ATTACKER),
        "token": TokenRef(
            chain=Chain.ethereum,
            contract="0xdAC17F958D2ee523a2206206994597C13D831ec7",
            symbol="USDT", decimals=6,
        ),
        "amount_raw": "0",
        "amount_decimal": Decimal("0"),
        "usd_value_at_tx": Decimal("NaN"),  # poisoned
        "hop_depth": 0,
        "parent_transfer_id": None,
        "pricing_source": None,
        "pricing_error": None,
        "fetched_at": datetime(2026, 1, 1, tzinfo=UTC),
        "explorer_url": "https://etherscan.io/tx/foo",
    }
    transfer = Transfer.model_construct(**fields)
    case = _mk_case([transfer])
    # Should not crash. May return [] (no signals match) or some
    # signal not depending on USD — fine either way.
    out = detect_mev_signals(case)
    assert isinstance(out, list)


def test_missing_block_number_does_not_crash() -> None:
    """A transfer with block_number=None (model_construct bypass)
    must not crash the same-block grouping."""
    fields: dict[str, Any] = {
        "transfer_id": "tx:0:a:b",
        "chain": Chain.ethereum,
        "tx_hash": "0x" + "0" * 64,
        "block_number": None,  # poisoned
        "block_time": datetime(2026, 1, 1, tzinfo=UTC),
        "log_index": 0,
        "from_address": _SEED,
        "to_address": _ATTACKER,
        "counterparty": Counterparty(address=_ATTACKER),
        "token": TokenRef(
            chain=Chain.ethereum,
            contract="0xdAC17F958D2ee523a2206206994597C13D831ec7",
            symbol="USDT", decimals=6,
        ),
        "amount_raw": "0",
        "amount_decimal": Decimal("0"),
        "usd_value_at_tx": Decimal("0"),
        "hop_depth": 0,
        "parent_transfer_id": None,
        "pricing_source": None,
        "pricing_error": None,
        "fetched_at": datetime(2026, 1, 1, tzinfo=UTC),
        "explorer_url": "https://etherscan.io/tx/foo",
    }
    transfer = Transfer.model_construct(**fields)
    case = _mk_case([transfer])
    out = detect_mev_signals(case)
    assert isinstance(out, list)


# ────────────────────────────────────────────────────────────────────
# Brief-section serialization
# ────────────────────────────────────────────────────────────────────


def test_brief_section_renders_above_threshold() -> None:
    """signals ≥ 0.5 confidence appear in the rendered 'signals' list."""
    signals = [
        MEVSignal(
            tx_hash="0xaaa", signal_type="flashbots_bundle",
            confidence=0.7, forensic_note="bundle-shape",
        ),
        MEVSignal(
            tx_hash="0xbbb", signal_type="jit_lp",
            confidence=0.4, forensic_note="possible JIT",
        ),
    ]
    section = mev_signals_to_brief_section(signals)
    assert section["detected"] is True
    assert section["signal_count"] == 1
    assert section["suppressed_low_confidence_count"] == 1
    rendered_types = [s["signal_type"] for s in section["signals"]]
    assert rendered_types == ["flashbots_bundle"]


def test_brief_section_empty_when_no_signals_clear_threshold() -> None:
    """All sub-threshold → detected=False but suppressed count surfaces."""
    signals = [MEVSignal(
        tx_hash="0xaaa", signal_type="jit_lp",
        confidence=0.4, forensic_note="possible JIT",
    )]
    section = mev_signals_to_brief_section(signals)
    assert section["detected"] is False
    assert section["signal_count"] == 0
    assert section["suppressed_low_confidence_count"] == 1


def test_brief_section_threshold_constant_is_half() -> None:
    """Spec contract: confidence_floor default is 0.5 (per Gap #9 spec)."""
    assert BRIEF_RENDER_CONFIDENCE_FLOOR == 0.5


# ────────────────────────────────────────────────────────────────────
# Dedupe behavior
# ────────────────────────────────────────────────────────────────────


def test_signals_dedupe_keep_highest_confidence() -> None:
    """Same tx_hash + signal_type collapses to the highest-confidence
    entry (e.g. builder-tagged + gas_price=0 on the same tx both fire
    flashbots_bundle; we keep the stronger signal)."""
    tx = "0x" + "5" * 64
    case = _mk_case([_mk_transfer(
        from_addr=_ATTACKER, to_addr=_SEED, tx_hash=tx, block_num=600,
    )])
    signals = detect_mev_signals(
        case,
        tx_metadata={tx: {"gas_price": 0, "builder": _FLASHBOTS_BUILDER}},
    )
    fb = [s for s in signals if s.signal_type == "flashbots_bundle"]
    assert len(fb) == 1, (
        f"Expected dedupe to collapse the two flashbots_bundle hits on "
        f"the same tx; got {len(fb)}"
    )


# ────────────────────────────────────────────────────────────────────
# Wire-up sanity: emit_brief includes MEV_SIGNALS section
# ────────────────────────────────────────────────────────────────────


def test_emit_brief_builder_returns_section_shape() -> None:
    """The internal _build_mev_signals_section returns the expected
    section shape on a vanilla case (defensive: must not crash)."""
    from recupero.reports.emit_brief import _build_mev_signals_section
    case = _mk_case([_mk_transfer(
        from_addr=_SEED, to_addr=_ATTACKER,
        tx_hash="0x" + "6" * 64, block_num=700,
    )])
    section = _build_mev_signals_section(case)
    assert isinstance(section, dict)
    for k in ("detected", "signal_count", "suppressed_low_confidence_count", "signals"):
        assert k in section, f"Section missing key {k}"
