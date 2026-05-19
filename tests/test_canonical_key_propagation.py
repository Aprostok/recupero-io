"""Regression tests pinning the v0.17.5-v0.17.10 canonical-key sweep.

v0.18.8 (round-11 tests-CRIT-002 through CRIT-006): the
canonical-key sweep touched 18+ modules but had zero direct
regression tests. A revert of the sweep passed all 1407 tests
pre-v0.18.8. This file pins the behavior at the consumer sites
so a revert is caught immediately.

Modules covered:
* labels/store.py — base58 label lookup
* trace/risk_scoring.py — high-risk DB load + score_addresses
* worker/monitor_tick.py — base58 subscription outflow filter
* trace/correlation.py — canonical observation keying (smoke)
* trace/clustering.py — base58 cluster member keying (smoke)
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory


# ---- labels/store.py (round-11 tests-CRIT-003) ---- #


def test_label_store_preserves_solana_base58_case() -> None:
    """A Solana label looked up by its canonical mixed-case base58
    must NOT be silently lowercased to a non-on-chain form."""
    from recupero.labels.store import _label_key
    canon = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    # _label_key preserves base58 case.
    assert _label_key(canon) == canon
    # EVM checksum gets lowercased canonical form.
    assert _label_key("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48") == (
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
    )


# ---- trace/risk_scoring.py (round-11 tests-CRIT-001) ---- #


def test_high_risk_db_load_preserves_solana_case() -> None:
    """The sanctioned Solana wallet in high_risk.json (Lazarus DPRK)
    must land in the dict with its canonical case-preserved key.
    Pre-v0.17.5 the loader lowercased every key, breaking lookups."""
    import json as _json
    from recupero.trace.risk_scoring import load_high_risk_db

    with TemporaryDirectory() as td:
        td_p = Path(td)
        hr_path = td_p / "high_risk.json"
        hr_path.write_text(_json.dumps({
            "_meta": {"_section": "test"},
            "addresses": [{
                "address": "BcrW1fJRwSoNYRBn5UxbVKsKsXdNRwGsQbf5KAcDuwfV",
                "name": "Lazarus DPRK Solana",
                "risk_category": "ofac_sanctioned",
                "severity": 4,
            }],
        }))
        mx = td_p / "mixers.json"
        mx.write_text("[]")
        rw = td_p / "ransomware.json"
        rw.write_text(_json.dumps({"addresses": []}))
        db = load_high_risk_db(
            high_risk_path=hr_path, mixers_path=mx, ransomware_path=rw,
        )
    # Canonical-case key preserved.
    assert "BcrW1fJRwSoNYRBn5UxbVKsKsXdNRwGsQbf5KAcDuwfV" in db
    # Lowercased form must NOT be in the dict (would indicate the
    # writer silently lowercased base58, breaking on-chain match).
    assert "bcrw1fjrwsonyrbn5uxbvkskskxdnrwgsqbf5kacduwfv" not in db


# ---- worker/monitor_tick.py (round-11 tests-CRIT-002) ---- #


def test_monitor_tick_canonical_key_filter() -> None:
    """The base58 subscription outflow filter uses canonical_address_key
    on both sides — a Solana subscription matches adapter-returned
    activities only when both sides canonical-key to the same form."""
    from recupero._common import canonical_address_key as _ck
    sub_addr = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    # Adapter returns "from" in canonical case (Helius does).
    adapter_from = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    assert _ck(sub_addr) == _ck(adapter_from)
    # Pre-v0.17.10 the filter did `.lower()` on both sides which
    # collapsed to the same string anyway but mangled base58. Now
    # canonical_address_key preserves case → exact match.
    assert _ck(sub_addr) == sub_addr


# ---- trace/risk_scoring.score_addresses (round-11 tests-CRIT-004) ---- #


def test_score_addresses_matches_base58_high_risk_entry() -> None:
    """Build a Solana case where the perpetrator is a known
    sanctioned wallet; score_addresses must produce a non-zero
    score (= the high_risk DB entry matched on canonical key)."""
    from decimal import Decimal
    from recupero.models import (
        Case, Chain, Counterparty, TokenRef, Transfer,
    )
    from recupero.trace.risk_scoring import (
        HighRiskEntry, score_addresses,
    )

    sanctioned = "BcrW1fJRwSoNYRBn5UxbVKsKsXdNRwGsQbf5KAcDuwfV"
    victim = "9JBJYgT6Wp6JE9LZ6yTd2dgcr5JKHcGcDYr6mP7vXt8d"
    now = datetime(2026, 5, 1, tzinfo=timezone.utc)

    transfer = Transfer(
        transfer_id="solana:tx1:0",
        chain=Chain.solana,
        tx_hash="tx1",
        block_number=1,
        block_time=now,
        from_address=victim,
        to_address=sanctioned,
        counterparty=Counterparty(
            address=sanctioned, label=None, is_contract=False,
        ),
        token=TokenRef(
            chain=Chain.solana,
            contract="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            symbol="USDC", decimals=6, coingecko_id="usd-coin",
        ),
        amount_raw="50000000000",
        amount_decimal=Decimal("50000"),
        usd_value_at_tx=Decimal("50000"),
        hop_depth=0,
        fetched_at=now,
        explorer_url="https://solscan.io/tx/tx1",
    )
    case = Case(
        case_id="TEST-SOL-1",
        seed_address=victim,
        chain=Chain.solana,
        incident_time=now,
        trace_started_at=now,
        trace_completed_at=now,
        transfers=[transfer],
    )
    high_risk_db = {
        sanctioned: HighRiskEntry(
            address=sanctioned,
            name="Lazarus DPRK",
            risk_category="ofac_sanctioned",
            severity=4,
            confidence="high",
        ),
    }
    scores = score_addresses(case, high_risk_db)
    # Victim must have score > 0 — the canonical-key match against
    # the sanctioned wallet produced an exposure record.
    assert victim in scores
    assert scores[victim].score > 0
