"""v0.34 Phase 2 — answer-key-free cross-chain correctness framework.

Covers the pure conservation invariant + the self-audit validators that let a
produced case check its own cryptographically-confirmed bridge hops without a
human answer key:
  * bridge_conservation_ok — same-asset value-conservation bound,
  * validate_bridge_confirmations — no `high` without proof + conservation,
  * render_bridge_confirmation_report — the human-auditable proof artifact.
"""

from __future__ import annotations

from decimal import Decimal

from recupero.trace.bridge_pairings import bridge_conservation_ok
from recupero.validators.cross_chain_integrity import (
    render_bridge_confirmation_report,
    validate_bridge_confirmations,
)

# A real-shaped DLN order-id (cross-asset → conservation NOT checked).
ORDER_ID = "0x57825e7d05231475614b6156ca01b74c8743fd70fb73210da95f7413f4871f9b"


# ------------------------------- conservation (pure) ------------------------


def test_conservation_within_fee_bound_ok() -> None:
    # dst == src → conserved; dst just inside the 1% floor → conserved.
    assert bridge_conservation_ok(1_000_000, 1_000_000, Decimal("1.0"))[0] is True
    assert bridge_conservation_ok(1_000_000, 991_000, Decimal("1.0"))[0] is True


def test_conservation_dst_exceeds_src_is_violation() -> None:
    ok, reason = bridge_conservation_ok(1_000_000, 1_000_001, Decimal("1.0"))
    assert ok is False
    assert "exceeds source" in reason


def test_conservation_dst_below_floor_is_violation() -> None:
    # 2% drop with a 1% max fee → below floor.
    ok, reason = bridge_conservation_ok(1_000_000, 980_000, Decimal("1.0"))
    assert ok is False
    assert "below the conservation floor" in reason


def test_conservation_unknown_amounts_never_fabricate_violation() -> None:
    assert bridge_conservation_ok(None, 100, Decimal("1.0")) == (
        True, "unknown (missing/non-positive amount)",
    )
    assert bridge_conservation_ok(100, None, Decimal("1.0"))[0] is True
    assert bridge_conservation_ok(0, 100, Decimal("1.0"))[0] is True
    assert bridge_conservation_ok(100, -5, Decimal("1.0"))[0] is True


def test_conservation_bad_fee_pct_is_unknown_not_violation() -> None:
    assert bridge_conservation_ok(100, 100, Decimal("NaN"))[0] is True
    assert bridge_conservation_ok(100, 100, Decimal("-1"))[0] is True
    assert bridge_conservation_ok(100, 100, Decimal("200"))[0] is True


# --------------------------- validate_bridge_confirmations -------------------


def test_clean_cross_asset_confirmation_has_no_violations() -> None:
    """A confirmed DLN hop (cross-asset; high WITH proof) is clean — conservation
    is skipped for cross-asset and the proof is present."""
    confs = [{
        "protocol": "DeBridge", "order_id": ORDER_ID,
        "source_chain": "arbitrum", "source_tx": "0xsrc",
        "dst_chain": "ethereum", "dst_tx": "0xfill",
        "recipient": "0xc1ee32fac1d9a0ce63021467e34164df3078289b",
        "raw_amount": "2919869135947824800000000", "src_raw_amount": None,
        "same_asset": False, "confidence": "high", "basis": "cryptographic match",
    }]
    assert validate_bridge_confirmations(confs) == []


def test_high_without_order_id_is_critical() -> None:
    confs = [{
        "protocol": "DeBridge", "order_id": None,
        "source_chain": "arbitrum", "dst_chain": "ethereum", "dst_tx": "0xfill",
        "confidence": "high",
    }]
    out = validate_bridge_confirmations(confs)
    assert len(out) == 1
    assert out[0].check == "cross_chain_edge_confirmed"
    assert out[0].severity == "critical"
    assert "order_id" in out[0].detail


def test_high_without_dst_tx_is_critical() -> None:
    confs = [{
        "protocol": "DeBridge", "order_id": ORDER_ID,
        "source_chain": "arbitrum", "dst_chain": "ethereum", "dst_tx": "",
        "confidence": "high",
    }]
    out = validate_bridge_confirmations(confs)
    assert len(out) == 1
    assert out[0].severity == "critical"
    assert "destination tx" in out[0].detail


def test_same_asset_conservation_violation_is_high() -> None:
    """Across is same-asset → a destination amount exceeding the source deposit
    is a HIGH-severity conservation violation (likely mispairing)."""
    confs = [{
        "protocol": "Across", "order_id": ORDER_ID,
        "source_chain": "base", "source_tx": "0xdep",
        "dst_chain": "ethereum", "dst_tx": "0xfill",
        "src_raw_amount": "1000000", "raw_amount": "1000001",
        "confidence": "high",  # same_asset omitted → read from registry (True)
    }]
    out = validate_bridge_confirmations(confs)
    checks = {v.check for v in out}
    assert "cross_chain_value_conserved" in checks
    v = next(v for v in out if v.check == "cross_chain_value_conserved")
    assert v.severity == "high"


def test_same_asset_conserved_has_no_violation() -> None:
    confs = [{
        "protocol": "Across", "order_id": ORDER_ID,
        "source_chain": "base", "source_tx": "0xdep",
        "dst_chain": "ethereum", "dst_tx": "0xfill",
        "src_raw_amount": "1000000", "raw_amount": "999000",  # 0.1% fee, < 1% max
        "confidence": "high",
    }]
    assert validate_bridge_confirmations(confs) == []


def test_non_mapping_record_is_warning_not_crash() -> None:
    out = validate_bridge_confirmations(["not a dict", 42, None])
    assert all(v.check == "cross_chain_confirmation_shape" for v in out)
    assert all(v.severity == "warning" for v in out)
    # None is falsy-skipped by the iterator? No — it's iterated; ensure no crash.
    assert len(out) >= 2


def test_empty_confirmations_no_violations() -> None:
    assert validate_bridge_confirmations(None) == []
    assert validate_bridge_confirmations([]) == []


def test_injected_get_spec_unknown_protocol_skips_conservation() -> None:
    """An unknown protocol (no spec) → conservation can't be checked, but the
    no-high-without-proof rule still applies."""
    confs = [{
        "protocol": "MysteryBridge", "order_id": ORDER_ID,
        "dst_tx": "0xfill", "confidence": "high",
        "src_raw_amount": "1000000", "raw_amount": "9999999",
    }]
    out = validate_bridge_confirmations(confs, get_spec=lambda _p: None)
    assert out == []  # proof present; no spec → no conservation check


# --------------------------- report rendering --------------------------------


def test_report_empty_states_no_confirmations() -> None:
    txt = render_bridge_confirmation_report([])
    assert "No cryptographically-confirmed" in txt


def test_report_lists_each_confirmation() -> None:
    confs = [{
        "protocol": "DeBridge", "order_id": ORDER_ID,
        "source_chain": "arbitrum", "source_tx": "0xsrc",
        "dst_chain": "ethereum", "dst_tx": "0xfill",
        "recipient": "0xc1ee32fac1d9a0ce63021467e34164df3078289b",
        "raw_amount": "2919869135947824800000000",
        "confidence": "high", "basis": "cryptographic match",
    }]
    txt = render_bridge_confirmation_report(confs)
    assert "DeBridge" in txt
    assert ORDER_ID in txt
    assert "0xfill" in txt
    assert "0xc1ee32fac1d9a0ce63021467e34164df3078289b" in txt
    assert "1 cross-chain destination(s) CONFIRMED" in txt
