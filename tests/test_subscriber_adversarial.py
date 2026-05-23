"""Adversarial audit of monitoring.subscriber (cranky-fermat).

Hunt list:
  1. Idempotency on repeated derive (same brief, same case)
  2. Address normalization across mixed-case duplicates
  3. CRLF / NUL injection in label
  4. Race-safety: ON CONFLICT clause is present in INSERT SQL
  5. Missing DSN — silent no-op vs crash
  6. Bulk-insert: 10k holdings do not silently truncate
"""

from __future__ import annotations

import re
from unittest.mock import patch
from uuid import UUID

from recupero.monitoring.subscriber import (
    SubscriptionSeed,
    auto_subscribe_from_brief,
    derive_subscriptions_from_brief,
    persist_subscriptions,
)

CASE_ID = "RCP-2026-ADV1"
INV_ID = UUID("99999999-9999-9999-9999-999999999999")
INVESTIGATOR = "investigator@example.com"


def _addr(prefix: str, n: int = 0) -> str:
    """Build a valid-shape 0x address with `prefix` as the first hex char."""
    suffix = format(n, "x").rjust(39, "0")
    return "0x" + prefix + suffix


def _brief_with(*holdings, perp_hub=None, primary_chain="ethereum"):
    """Construct a minimal brief whose only freezable issuer is 'Tether'."""
    return {
        "CASE_ID": CASE_ID,
        "PRIMARY_CHAIN": primary_chain,
        "PERP_HUB": perp_hub or {},
        "ALL_ISSUER_HOLDINGS": [
            {
                "issuer": "Tether",
                "freeze_capability": "HIGH",
                "holdings": list(holdings),
            },
        ],
        "RISK_ASSESSMENT": {"addresses": {}},
        "INDIRECT_EXPOSURE": {"addresses": {}},
    }


# ─── 1. Idempotency: repeated derive on same brief yields same seed set ─────

def test_repeat_derive_is_idempotent_per_address():
    """Re-running derive on the same brief must produce the same canonical
    seed set — no double-counting via stale internal state."""
    brief = _brief_with(
        {"address": _addr("a"), "chain": "ethereum"},
        {"address": _addr("b"), "chain": "ethereum"},
        perp_hub={"address": _addr("c"), "chain": "ethereum"},
    )
    seeds_1 = derive_subscriptions_from_brief(
        brief, case_id=CASE_ID, investigator_email=INVESTIGATOR,
    )
    seeds_2 = derive_subscriptions_from_brief(
        brief, case_id=CASE_ID, investigator_email=INVESTIGATOR,
    )
    key = lambda s: (s.address.lower(), s.chain, s.created_by)  # noqa: E731
    assert sorted(map(key, seeds_1)) == sorted(map(key, seeds_2))
    assert len({key(s) for s in seeds_1}) == len(seeds_1), (
        "derive produced duplicate (address, chain, created_by) tuples"
    )


# ─── 2. Address normalization — mixed-case duplicate must collapse ─────────

def test_mixed_case_duplicate_collapses_and_persists_canonical():
    """Same address appearing in mixed case across PERP_HUB + holdings
    must dedup to ONE seed, and the persisted address must be the
    canonical lowercase form so the DB unique constraint stays stable
    across reruns where the brief casing drifts.
    """
    base = "0x" + "Ab" * 20  # 0xAbAbAb... 42 chars, valid EVM shape
    upper = base.upper().replace("0X", "0x", 1)
    lower = base.lower()
    brief = _brief_with(
        {"address": upper, "chain": "ethereum"},
        {"address": lower, "chain": "Ethereum"},  # also exercise chain casing
        perp_hub={"address": base, "chain": "ethereum"},
    )
    seeds = derive_subscriptions_from_brief(
        brief, case_id=CASE_ID, investigator_email=INVESTIGATOR,
    )
    # Exactly one seed for this address across all three sources.
    matching = [s for s in seeds if s.address.lower() == lower]
    assert len(matching) == 1, (
        f"mixed-case duplicates did not collapse: {[s.address for s in matching]}"
    )
    # Persisted address must be canonical lower so it survives idempotency
    # across reruns where upstream casing changes.
    assert matching[0].address == lower, (
        f"persisted address is non-canonical {matching[0].address!r}; "
        "the unique-constraint guarantee depends on canonical storage"
    )


# ─── 3. CRLF / NUL in label ─────────────────────────────────────────────────

def test_label_strips_control_chars():
    """Issuer names flow into label= unsanitized. Postgres TEXT rejects
    NUL bytes (\\x00) outright; CRLF in audit labels breaks log parsing.
    """
    bad_issuer = "Tether\x00\r\n<injected>"
    brief = {
        "CASE_ID": CASE_ID,
        "PRIMARY_CHAIN": "ethereum",
        "PERP_HUB": {},
        "ALL_ISSUER_HOLDINGS": [
            {
                "issuer": bad_issuer,
                "freeze_capability": "HIGH",
                "holdings": [{"address": _addr("a"), "chain": "ethereum"}],
            },
        ],
        "RISK_ASSESSMENT": {"addresses": {}},
        "INDIRECT_EXPOSURE": {"addresses": {}},
    }
    seeds = derive_subscriptions_from_brief(
        brief, case_id=CASE_ID, investigator_email=INVESTIGATOR,
    )
    assert len(seeds) == 1
    label = seeds[0].label
    assert "\x00" not in label, "NUL byte in label will be rejected by Postgres"
    assert "\r" not in label and "\n" not in label, (
        f"CRLF leaked into audit label: {label!r}"
    )


# ─── 4. Race-safety: INSERT uses ON CONFLICT clause ─────────────────────────

def test_persist_sql_uses_on_conflict():
    """Without ON CONFLICT, two concurrent emit_briefs racing the same
    (address, chain, created_by) would both INSERT and the UNIQUE
    constraint would error on the loser — losing the brief tail.
    """
    captured_sql: list[str] = []

    class _FakeCursor:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=None):
            captured_sql.append(sql)
            self.rowcount = 1

    class _FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def cursor(self):
            return _FakeCursor()

    seed = SubscriptionSeed(
        address=_addr("a"), chain="ethereum",
        trigger_type="any_movement", alert_email=INVESTIGATOR,
        case_id=CASE_ID, investigation_id=None,
        label="Tether", created_by=f"emit_brief:{CASE_ID}",
    )
    with patch(
        "recupero._common.db_connect",
        return_value=_FakeConn(),
    ):
        inserted, skipped = persist_subscriptions([seed], dsn="postgres://fake")
    assert inserted == 1 and skipped == 0
    assert captured_sql, "persist_subscriptions did not execute any SQL"
    sql_blob = " ".join(captured_sql).upper()
    assert re.search(r"ON\s+CONFLICT", sql_blob), (
        "INSERT lacks ON CONFLICT — concurrent emit_briefs will race"
    )


# ─── 5. Missing DSN — degrade silently ──────────────────────────────────────

def test_persist_with_none_dsn_does_not_crash_loud():
    """A None DSN reaching persist_subscriptions directly (e.g. via a
    misconfigured caller) must be swallowed — emit_brief cannot raise
    just because DSN env var was unset.
    """
    seed = SubscriptionSeed(
        address=_addr("a"), chain="ethereum",
        trigger_type="any_movement", alert_email=INVESTIGATOR,
        case_id=CASE_ID, investigation_id=None,
        label="Tether", created_by=f"emit_brief:{CASE_ID}",
    )
    # Must not raise even with explicit dsn=None.
    inserted, skipped = persist_subscriptions([seed], dsn=None)  # type: ignore[arg-type]
    assert inserted == 0
    assert skipped >= 1, "missing DSN should mark the seed skipped, not lost"


# ─── 6. Bulk insert — large brief is fully derived (no silent truncation) ──

def test_large_brief_derives_all_holdings():
    """A brief with 10k freezable holdings must produce 10k seeds —
    no silent cap, no early break. Performance is a separate concern;
    correctness comes first.
    """
    N = 10_000
    holdings = [
        {"address": _addr("a", i), "chain": "ethereum"} for i in range(N)
    ]
    brief = _brief_with(*holdings)
    seeds = derive_subscriptions_from_brief(
        brief, case_id=CASE_ID, investigator_email=INVESTIGATOR,
    )
    assert len(seeds) == N, (
        f"large-brief truncation: expected {N} seeds, got {len(seeds)}"
    )
    # All unique by address.
    assert len({s.address.lower() for s in seeds}) == N
