"""Unit tests for the D6 recovery-alerts persistence store (no DB required).

The full DB round-trip (persist -> list) is exercised in prod + by the watch
tick against a real Postgres; these tests pin the DB-FREE contract that must
hold in CI:

  * ``persist_alerts(dsn, [])`` returns 0 WITHOUT opening a connection — so a
    no-alert tick never touches the DB (and an empty batch can't error even
    with a bogus DSN).
  * ``_alert_to_row`` accepts both a real ``RecoveryAlert`` (via ``to_dict``)
    and an already-serialized dict, and the keys it produces are exactly the
    columns ``persist_alerts`` writes — guarding against a silent
    schema/serialization drift between D6 and the store.
"""

from __future__ import annotations

from recupero.monitoring.recovery_alerts import RecoveryAlert
from recupero.monitoring.recovery_alerts_store import (
    _alert_to_row,
    persist_alerts,
)

# The columns persist_alerts() reads off each row dict (everything except the
# DB-managed id / created_at / status / dedup_key).
_EXPECTED_KEYS = {
    "address", "chain", "severity", "kind", "delta_usd", "dormant_days",
    "role", "label_name", "message", "recommended_action",
}


def test_persist_empty_returns_zero_without_touching_db() -> None:
    # A deliberately unreachable DSN: if persist_alerts tried to connect this
    # would raise. Empty input must short-circuit to 0 before any connection.
    assert persist_alerts("postgresql://nope:nope@127.0.0.1:1/none", []) == 0


def test_alert_to_row_from_dataclass_has_all_persisted_keys() -> None:
    alert = RecoveryAlert(
        address="0xabc",
        chain="ethereum",
        severity="critical",
        kind="freezable_outflow",
        delta_usd="$1,234.00",
        dormant_days=None,
        role="perp_hub",
        label_name="Binance",
        message="Funds moved",
        recommended_action="File freeze now",
    )
    row = _alert_to_row(alert)
    # Every column persist_alerts writes must be present in the serialized row.
    assert set(row) >= _EXPECTED_KEYS
    assert row["address"] == "0xabc"
    assert row["severity"] == "critical"
    assert row["kind"] == "freezable_outflow"


def test_alert_to_row_passes_through_plain_dict() -> None:
    d = {"address": "0xdef", "chain": "tron", "severity": "high", "kind": "x"}
    assert _alert_to_row(d) == d
