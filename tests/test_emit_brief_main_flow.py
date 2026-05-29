"""Top-level audit of run_emit_brief — the main brief-generation entry point.

These RED tests target the OUTER orchestration function (``run_emit_brief``)
rather than the internal ``emit_brief`` assembly helper or any
sub-extractor. Properties under test (audit-checklist mapping):

  1. ``case_dir`` shape validation — handled upstream by CaseStore's
     ``_validate_case_id`` (covered separately); the assembly path
     correctly fans out via ``case_store.case_dir(case_id)``.
  2. Partially-corrupted ``freeze_asks.json`` — pre-fix the bare
     ``json.loads`` raised JSONDecodeError; the brief never wrote.
     Now: a corrupted/truncated freeze_asks file is logged + treated
     as an empty dict so the brief still emits.
  3. NaN/Inf in USD aggregation — case-level totals (the top-level
     ``TOTAL_LOSS_USD`` from ``_compute_total_drained``) survive
     ``usd_value_at_tx=None`` transfers without crashing.
  4. Atomic write — verified by absence of stray ``.tmp`` siblings
     after a successful run (atomic_write_text guarantee).
  5. Idempotency under ``SOURCE_DATE_EPOCH`` — two consecutive runs
     of the same case with the env var pinned produce byte-identical
     freeze_brief.json. Pre-fix REPORT_TIME_UTC was
     ``datetime.now()`` and ignored the epoch.
  6. Auto-subscribe failure — when ``dsn`` is None, no subscriber is
     called; brief still emits cleanly (the with-dsn failure path is
     covered by test_emit_brief_subscriptions).
  7. Missing CoinGecko prices (None usd_value_at_tx) — brief totals
     fall back to ``$0`` rather than crashing; the JSON serializes
     cleanly under ``allow_nan=False``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from recupero.config import RecuperoConfig
from recupero.models import (
    Case,
    Chain,
    Counterparty,
    TokenRef,
    Transfer,
)
from recupero.reports.emit_brief import run_emit_brief
from recupero.reports.victim import VictimInfo, write_victim
from recupero.storage.case_store import CaseStore

CASE_ID = "AUDIT-MAIN-FLOW-001"
VICTIM_ADDR = "0x" + "a" * 40
PERP_HUB = "0x" + "b" * 40
DEST_ADDR = "0x" + "c" * 40
USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"

NOW = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)


# ─────────────────────────────────────────────────────────────────────────────
# Fixture helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_token(*, has_price: bool = True) -> TokenRef:
    return TokenRef(
        chain=Chain.ethereum,
        contract=USDT,
        symbol="USDT",
        decimals=6,
        coingecko_id="tether" if has_price else None,
    )


def _make_transfer(
    *, from_addr: str, to_addr: str, usd: Decimal | None, tx_hash: str,
) -> Transfer:
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:0",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=1,
        block_time=NOW,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(
            address=to_addr, label=None, is_contract=False,
        ),
        token=_make_token(has_price=usd is not None),
        amount_raw="100000000",
        amount_decimal=Decimal("100"),
        usd_value_at_tx=usd,
        hop_depth=0 if from_addr == VICTIM_ADDR else 1,
        fetched_at=NOW,
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
    )


def _make_case(*, priced: bool = True) -> Case:
    """Synthetic two-hop case: victim → perp hub → CEX deposit. When
    ``priced=False``, every transfer has ``usd_value_at_tx=None``
    (the missing-CoinGecko-prices condition)."""
    usd_val = Decimal("100000") if priced else None
    return Case(
        case_id=CASE_ID,
        seed_address=VICTIM_ADDR,
        chain=Chain.ethereum,
        incident_time=NOW,
        trace_started_at=NOW,
        trace_completed_at=NOW,
        transfers=[
            _make_transfer(
                from_addr=VICTIM_ADDR, to_addr=PERP_HUB,
                usd=usd_val, tx_hash="0x" + "1" * 64,
            ),
            _make_transfer(
                from_addr=PERP_HUB, to_addr=DEST_ADDR,
                usd=usd_val, tx_hash="0x" + "2" * 64,
            ),
        ],
    )


def _make_editorial() -> dict:
    """Minimal editorial dict with no TODO placeholders."""
    return {
        "CASE_ID": CASE_ID,
        "REPORT_DATE": "May 1, 2026",
        "INCIDENT_DATE": "May 1, 2026",
        "INCIDENT_TYPE": "Synthetic audit case",
        "PRIMARY_CHAIN": "Ethereum",
        "INCIDENT_NARRATIVE_RECUPERO": "Synthetic test narrative.",
        "INCIDENT_NARRATIVE_FIRST_PERSON": "Synthetic first-person narrative.",
        "VICTIM_SUMMARY": "Synthetic summary.",
        "VICTIM_ADDRESS_LINE1": "1 Test St",
        "VICTIM_ADDRESS_LINE2": "Anywhere, USA",
        "VICTIM_JURISDICTION": "USA",
        "DESTINATION_NOTES": {},
        "UNRECOVERABLE_ITEMS": [],
        "IC3_CASE_ID": None,
        "INVESTIGATOR_NAME": "Test Investigator",
        "INVESTIGATOR_EMAIL": "investigator@test.com",
        "INVESTIGATOR_ENTITY": "Recupero",
        "INVESTIGATOR_ENTITY_FULL": "Recupero Forensics Ltd.",
        "INVESTIGATOR_WEB": "https://recupero.io",
        "TEMPLATE_VERSION": "v1.0",
    }


def _bootstrap_case_dir(
    tmp_path: Path,
    *,
    priced: bool = True,
    freeze_asks_content: str | None = "{}",
) -> tuple[CaseStore, Path]:
    """Write case.json, victim.json, brief_editorial.json (and
    optionally freeze_asks.json) to a fresh case directory. Returns
    the configured CaseStore + case_dir."""
    cfg = RecuperoConfig()
    cfg.storage.data_dir = str(tmp_path)
    store = CaseStore(cfg)
    case = _make_case(priced=priced)
    store.write_case(case)
    case_dir = store.case_dir(CASE_ID)

    victim = VictimInfo(
        name="Audit Test Victim",
        wallet_address=VICTIM_ADDR,
        email="victim@test.com",
    )
    write_victim(case_dir, victim)

    (case_dir / "brief_editorial.json").write_text(
        json.dumps(_make_editorial(), indent=2),
        encoding="utf-8",
    )

    if freeze_asks_content is not None:
        (case_dir / "freeze_asks.json").write_text(
            freeze_asks_content, encoding="utf-8",
        )

    return store, case_dir


# ─────────────────────────────────────────────────────────────────────────────
# Audit #2 — partially-corrupted freeze_asks.json must not crash the brief
# ─────────────────────────────────────────────────────────────────────────────

def test_corrupted_freeze_asks_json_does_not_crash(tmp_path: Path) -> None:
    """A truncated / malformed freeze_asks.json must be tolerated:
    log + treat as empty so the brief still emits. Pre-fix the bare
    ``json.loads`` in run_emit_brief raised JSONDecodeError and the
    brief never reached disk."""
    truncated = '{"by_issuer": {"Tether": [{"address": "0xff'  # cut mid-string
    store, case_dir = _bootstrap_case_dir(
        tmp_path, freeze_asks_content=truncated,
    )
    out_path, brief = run_emit_brief(CASE_ID, store)
    assert out_path.exists(), (
        "freeze_brief.json must still land when freeze_asks.json is corrupt"
    )
    # Brief assembled with empty freezable / empty exchanges
    assert brief["FREEZABLE"] == []
    assert brief["EXCHANGES"] == []


# ─────────────────────────────────────────────────────────────────────────────
# Audit #5 — idempotency under SOURCE_DATE_EPOCH
# ─────────────────────────────────────────────────────────────────────────────

def test_idempotent_under_source_date_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two consecutive runs of the same case with ``SOURCE_DATE_EPOCH``
    pinned must produce byte-identical ``freeze_brief.json``.

    Pre-fix ``REPORT_TIME_UTC`` was ``datetime.now()``; the epoch env
    var was ignored — the byte hash drifted between every run."""
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1747785600")  # 2026-05-21 UTC
    # Defuse the DB-backed correlation pass — if SUPABASE_DB_URL points
    # at a reachable local Postgres, the first run writes an
    # address_observations row and the second run sees it in the
    # lookup, breaking the byte hash through CROSS_CASE_CORRELATION.
    # For this idempotency property we want the pure-Python path only.
    monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
    store, case_dir = _bootstrap_case_dir(tmp_path)

    out_path, _brief1 = run_emit_brief(CASE_ID, store)
    bytes_1 = out_path.read_bytes()

    out_path, _brief2 = run_emit_brief(CASE_ID, store)
    bytes_2 = out_path.read_bytes()

    assert bytes_1 == bytes_2, (
        "freeze_brief.json must be byte-identical across runs when "
        "SOURCE_DATE_EPOCH is pinned (reproducible-builds contract)"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Audit #4 — atomic write: no .tmp siblings left on disk
# ─────────────────────────────────────────────────────────────────────────────

def test_atomic_write_leaves_no_temp_siblings(tmp_path: Path) -> None:
    """``atomic_write_text`` writes to a sibling tempfile then
    ``os.replace``s. After a clean run, no ``.tmp`` artifact may
    remain in the case dir."""
    store, case_dir = _bootstrap_case_dir(tmp_path)
    out_path, _ = run_emit_brief(CASE_ID, store)
    assert out_path.exists()
    leftovers = [
        p.name for p in case_dir.iterdir()
        if p.name.startswith("freeze_brief") and p.name != "freeze_brief.json"
    ]
    assert leftovers == [], (
        f"atomic write must clean up temp siblings; found: {leftovers}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Audit #7 — missing CoinGecko prices must render as $0, not crash
# ─────────────────────────────────────────────────────────────────────────────

def test_missing_coingecko_prices_renders_zero(tmp_path: Path) -> None:
    """When every transfer carries ``usd_value_at_tx=None`` (no
    CoinGecko coverage), the brief must still emit; headline totals
    fall back to ``$0`` and the JSON serializes cleanly."""
    store, case_dir = _bootstrap_case_dir(tmp_path, priced=False)
    out_path, brief = run_emit_brief(CASE_ID, store)
    # The actual loss aggregation skips None transfers, lands at $0
    assert brief["TOTAL_LOSS_USD"] == "$0", brief["TOTAL_LOSS_USD"]
    # Round-trip the on-disk JSON to prove allow_nan=False didn't trip
    on_disk = json.loads(out_path.read_text(encoding="utf-8"))
    assert on_disk["TOTAL_LOSS_USD"] == "$0"


# ─────────────────────────────────────────────────────────────────────────────
# Audit #6 — no-dsn path: auto-subscribe is skipped, brief still lands
# ─────────────────────────────────────────────────────────────────────────────

def test_no_dsn_skips_subscriber_and_still_writes_brief(
    tmp_path: Path,
) -> None:
    """Local-CLI path (dsn=None): subscriber import isn't attempted,
    brief still writes. Confirms step 7's ``if dsn:`` gate."""
    store, case_dir = _bootstrap_case_dir(tmp_path)
    out_path, brief = run_emit_brief(CASE_ID, store, dsn=None)
    assert out_path.exists()
    # CLUSTER_MEMBERSHIP only populated when both dsn and investigation_id
    # are provided. Local path must not surface it.
    assert "CLUSTER_MEMBERSHIP" not in brief


# ─────────────────────────────────────────────────────────────────────────────
# Audit #3 — NaN-tolerance in the main USD aggregation
# ─────────────────────────────────────────────────────────────────────────────

def test_brief_serializes_under_allow_nan_false(tmp_path: Path) -> None:
    """``run_emit_brief`` writes with ``allow_nan=False``. If any
    aggregator leaked an Inf/NaN Decimal into a top-level USD field,
    json.dumps would raise ValueError. Confirm the priced + unpriced
    flows both yield JSON-clean output."""
    # Priced path
    store_p, _ = _bootstrap_case_dir(tmp_path / "priced")
    out_p, _ = run_emit_brief(CASE_ID, store_p)
    json.loads(out_p.read_text(encoding="utf-8"))  # must not raise

    # Unpriced (no CoinGecko coverage) path
    store_u, _ = _bootstrap_case_dir(tmp_path / "unpriced", priced=False)
    out_u, _ = run_emit_brief(CASE_ID, store_u)
    json.loads(out_u.read_text(encoding="utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# Audit #2 (variant) — freeze_asks.json totally absent is already supported
# ─────────────────────────────────────────────────────────────────────────────

def test_freeze_asks_absent_emits_brief_with_empty_lists(
    tmp_path: Path,
) -> None:
    """When freeze_asks.json is missing entirely (operator hasn't run
    list-freeze-targets), the brief still emits with empty FREEZABLE +
    EXCHANGES. Regression guard for the existing ``if exists()`` gate."""
    store, case_dir = _bootstrap_case_dir(
        tmp_path, freeze_asks_content=None,
    )
    out_path, brief = run_emit_brief(CASE_ID, store)
    assert out_path.exists()
    assert brief["FREEZABLE"] == []
    assert brief["EXCHANGES"] == []
