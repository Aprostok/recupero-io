"""v0.32 — auto-ingest pipeline + confidence-decay tests.

Closes Tier-1 gaps #1 + #2 from docs/WHY_RECUPERO_WOULD_FAIL.md
§1.1 + §1.2 (adversary out-runs label-DB updates + CEX hot-wallet
rotation makes labels stale).

NO LIVE HTTP CALLS — every upstream API is stubbed via respx. NO
LIVE DB CALLS — every persistence path is exercised through a stubbed
``db_connect`` context manager. The pipeline must be testable without
internet or Supabase.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from recupero.labels import auto_ingest
from recupero.labels.auto_ingest import (
    CandidateLabel,
    fetch_candidate_bridges,
    fetch_candidate_etherscan_label_dumps,
    fetch_candidate_ton_entities,
    persist_candidates,
)
from recupero.labels.confidence_decay import (
    apply_decay,
)

# ─────────────────────────────────────────────────────────────────────────────
# DB stub — a single MagicMock connection that records SQL + returns
# the canned `fetchone` / `fetchall` sequence the test feeds it.
# ─────────────────────────────────────────────────────────────────────────────


class _FakeCursor:
    """Records every execute() call and returns the next item from a
    queued list on fetchone() / fetchall().

    Tests assign ``rows_for_fetchone`` / ``rows_for_fetchall`` before
    invoking the code under test. Anything not assigned returns None
    (fetchone) or [] (fetchall).
    """

    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[Any, ...]]] = []
        self.rows_for_fetchone: list[Any] = []
        self.rows_for_fetchall: list[list[Any]] = []

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self.executed.append((sql, params))

    def fetchone(self) -> Any:
        if self.rows_for_fetchone:
            return self.rows_for_fetchone.pop(0)
        return None

    def fetchall(self) -> list[Any]:
        if self.rows_for_fetchall:
            return self.rows_for_fetchall.pop(0)
        return []

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *args: Any) -> None:
        return None


class _FakeConn:
    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor

    def cursor(self) -> _FakeCursor:
        return self._cursor

    def __enter__(self) -> _FakeConn:
        return self

    def __exit__(self, *args: Any) -> None:
        return None


@pytest.fixture
def fake_db(monkeypatch: pytest.MonkeyPatch) -> _FakeCursor:
    """Provide a fake `db_connect` that returns the same cursor across
    every call inside the test, so assertions can introspect the SQL
    and the test can pre-load fetchone/fetchall returns.
    """
    cur = _FakeCursor()
    conn = _FakeConn(cur)

    def _fake_db_connect(dsn: str, **kwargs: Any) -> _FakeConn:
        return conn

    monkeypatch.setattr(
        "recupero._common.db_connect", _fake_db_connect, raising=True,
    )
    # The auto_ingest module imports lazily; patch the module-level
    # entry too in case Python has already pulled the symbol.
    import recupero._common as _common
    monkeypatch.setattr(_common, "db_connect", _fake_db_connect, raising=True)
    # Pretend we have a DSN so the local-dev no-op branch doesn't fire.
    monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://test@localhost/x")
    return cur


# ─────────────────────────────────────────────────────────────────────────────
# Source-fetch tests (respx mocks)
# ─────────────────────────────────────────────────────────────────────────────


@respx.mock
def test_tronscan_response_parses_into_candidate_labels() -> None:
    """Mock Tronscan tag response → parsed into N CandidateLabel
    entries with chain='tron' and category='bridge'."""
    respx.get("https://api.llama.fi/protocols").mock(
        return_value=httpx.Response(200, json=[]),
    )
    respx.get(
        "https://apilist.tronscanapi.com/api/contracts?contract_type=bridge"
    ).mock(return_value=httpx.Response(200, json={
        "data": [
            {"address": "TXYZbridge111", "name": "Wormhole Tron"},
            {"address": "TXYZbridge222", "name": "Multichain Tron"},
            {"address": "TXYZbridge333", "name": "Allbridge Tron"},
        ],
    }))
    out = fetch_candidate_bridges()
    tron_only = [c for c in out if c.source == "tronscan_tag"]
    assert len(tron_only) == 3
    for c in tron_only:
        assert c.chain == "tron"
        assert c.proposed_category == "bridge"
        assert c.proposed_confidence == "low"
        assert c.address.startswith("T")


@respx.mock
def test_defillama_new_bridge_produces_bridge_candidate() -> None:
    """DeFiLlama row with category='Bridge' → CandidateLabel with
    proposed_category='bridge'."""
    respx.get("https://api.llama.fi/protocols").mock(
        return_value=httpx.Response(200, json=[
            {
                "id": "1", "name": "BrandNewBridge",
                "address": "0xabcdef0000000000000000000000000000000001",
                "category": "Bridge",
                "chains": ["Ethereum"],
                "slug": "brandnewbridge",
            },
            # CEX rows should NOT show up in the bridges feed.
            {
                "id": "2", "name": "SomeCEX",
                "address": "0xabcdef0000000000000000000000000000000002",
                "category": "CEX",
                "chains": ["Ethereum"],
                "slug": "somecex",
            },
        ]),
    )
    respx.get(
        "https://apilist.tronscanapi.com/api/contracts?contract_type=bridge"
    ).mock(return_value=httpx.Response(200, json={"data": []}))
    out = fetch_candidate_bridges()
    bridge_candidates = [c for c in out if c.proposed_category == "bridge"]
    assert len(bridge_candidates) == 1
    c = bridge_candidates[0]
    assert c.source == "defillama_new_protocol"
    assert c.proposed_name == "BrandNewBridge"
    assert c.chain == "ethereum"


@respx.mock
def test_etherscan_unreachable_skips_and_other_sources_still_process(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Etherscan / DeFiLlama unreachable → 0 candidates from that
    source + WARN log + other sources still process."""
    # DeFiLlama is down (5xx).
    respx.get("https://api.llama.fi/protocols").mock(
        return_value=httpx.Response(503),
    )
    # Tronscan returns valid data anyway.
    respx.get(
        "https://apilist.tronscanapi.com/api/contracts?contract_type=bridge"
    ).mock(return_value=httpx.Response(200, json={
        "data": [{"address": "TVALID", "name": "ValidTronBridge"}],
    }))
    caplog.set_level(logging.WARNING)
    out = fetch_candidate_bridges()
    # Exactly one survives (Tron); DeFiLlama contributed zero.
    assert len(out) == 1
    assert out[0].source == "tronscan_tag"
    # WARN was logged for the failed source.
    assert any(
        "label auto-ingest" in rec.message and "503" in rec.message
        for rec in caplog.records
    )


@respx.mock
def test_network_exception_does_not_propagate(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A transport-level error (ConnectError, timeout) is swallowed
    with WARN; the pipeline keeps going."""
    respx.get("https://api.llama.fi/protocols").mock(
        side_effect=httpx.ConnectError("connection refused"),
    )
    respx.get(
        "https://apilist.tronscanapi.com/api/contracts?contract_type=bridge"
    ).mock(return_value=httpx.Response(200, json={"data": []}))
    caplog.set_level(logging.WARNING)
    out = fetch_candidate_bridges()
    assert out == []
    assert any("unreachable" in rec.message for rec in caplog.records)


# ─────────────────────────────────────────────────────────────────────────────
# Persistence
# ─────────────────────────────────────────────────────────────────────────────


def test_candidates_persisted_with_status_pending_review(
    fake_db: _FakeCursor,
) -> None:
    """persist_candidates inserts with the expected SQL shape (status
    defaults to 'pending_review' via the DDL; we verify the INSERT
    columns and that the status column is NOT explicitly written by
    persist_candidates — defaulting at the DB layer keeps the
    pending_review invariant in one place).
    """
    cands = [
        CandidateLabel(
            address="0xA0",
            chain="ethereum",
            proposed_category="bridge",
            proposed_name="Test Bridge",
            source="defillama_new_protocol",
        ),
    ]
    # The INSERT ... RETURNING id returns one row per insert.
    fake_db.rows_for_fetchone = [(101,)]
    n = persist_candidates(cands)
    assert n == 1
    # Verify the SQL shape: INSERT into label_candidates, no `status`
    # column in the INSERT.
    assert any(
        "INSERT INTO public.label_candidates" in sql
        and "status" not in sql.split("VALUES")[0]
        for sql, _ in fake_db.executed
    )


def test_duplicate_detection_same_chain_address_single_row(
    fake_db: _FakeCursor,
) -> None:
    """Same (chain, address) twice → DB upsert returns no row for the
    second one; our counter reflects 1 insert."""
    cands = [
        CandidateLabel(
            address="0xA0", chain="ethereum",
            proposed_category="bridge",
            proposed_name="First",
            source="defillama_new_protocol",
        ),
        CandidateLabel(
            address="0xA0", chain="ethereum",
            proposed_category="bridge",
            proposed_name="Second",
            source="tronscan_tag",
        ),
    ]
    # First insert returns id, second is a no-op (ON CONFLICT DO NOTHING).
    fake_db.rows_for_fetchone = [(101,), None]
    n = persist_candidates(cands)
    assert n == 1


# ─────────────────────────────────────────────────────────────────────────────
# Promote / reject
# ─────────────────────────────────────────────────────────────────────────────


def test_promote_endpoint_writes_to_bridges_json(
    fake_db: _FakeCursor, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """promote_candidate appends a row to bridges.json AND updates the
    candidate row to status='promoted'."""
    # Seed a starter bridges.json so the test doesn't depend on the
    # production seed-file count.
    seeds_dir = tmp_path / "seeds"
    seeds_dir.mkdir()
    bridges_path = seeds_dir / "bridges.json"
    bridges_path.write_text(json.dumps([
        {"address": "0xEXISTING", "name": "Existing Bridge",
         "category": "bridge", "source": "manual",
         "confidence": "high",
         "added_at": "2025-01-01T00:00:00Z", "chain": "ethereum"},
    ]), encoding="utf-8")

    # _read_candidate (SELECT) returns the pending row.
    # promote_candidate UPDATE returns (id,)
    fake_db.rows_for_fetchone = [
        # First call is _read_candidate SELECT:
        (
            42, "0x000000000000000000000000000000000000dEaD", "ethereum",
            "bridge", "Newly Tagged",
            "low", "defillama_new_protocol",
            "https://defillama.com/...", {}, "pending_review",
        ),
        # Second call is the UPDATE ... RETURNING id:
        (42,),
    ]

    result = auto_ingest.promote_candidate(
        candidate_id=42,
        reviewer="ops@recupero.io",
        confidence="medium",
        seeds_dir=seeds_dir,
    )
    assert result["promoted_to"] == str(bridges_path)

    # File now has 2 rows.
    after = json.loads(bridges_path.read_text(encoding="utf-8"))
    assert len(after) == 2
    new_entry = after[-1]
    assert new_entry["address"] == "0x000000000000000000000000000000000000dEaD"
    assert new_entry["category"] == "bridge"
    assert new_entry["confidence"] == "medium"
    assert new_entry["_v032_auto_ingest"] is True

    # SQL UPDATE was issued.
    assert any(
        "UPDATE public.label_candidates" in sql and "status = 'promoted'" in sql
        for sql, _ in fake_db.executed
    )


def test_promote_refuses_already_promoted_row(
    fake_db: _FakeCursor, tmp_path: Path,
) -> None:
    """Promoting a row that's already 'promoted' raises ValueError."""
    fake_db.rows_for_fetchone = [
        (42, "0xX", "ethereum", "bridge", "Some Bridge",
         "low", "defillama_new_protocol", "", {}, "promoted"),
    ]
    with pytest.raises(ValueError, match="already 'promoted'"):
        auto_ingest.promote_candidate(
            candidate_id=42, reviewer="ops@recupero.io",
            seeds_dir=tmp_path,
        )


def test_reject_endpoint_requires_reason(fake_db: _FakeCursor) -> None:
    """reject_candidate with empty reason → ValueError."""
    with pytest.raises(ValueError, match="non-empty reason"):
        auto_ingest.reject_candidate(
            candidate_id=42, reviewer="ops@recupero.io", reason="",
        )
    with pytest.raises(ValueError, match="non-empty reason"):
        auto_ingest.reject_candidate(
            candidate_id=42, reviewer="ops@recupero.io", reason="   ",
        )


def test_reject_marks_status_and_records_reviewer(
    fake_db: _FakeCursor,
) -> None:
    """reject_candidate writes reviewer + reason."""
    fake_db.rows_for_fetchone = [
        # _read_candidate SELECT result:
        (43, "0xY", "ethereum", "bridge", "Spam",
         "low", "defillama_new_protocol", "", {}, "pending_review"),
        # UPDATE ... RETURNING id:
        (43,),
    ]
    auto_ingest.reject_candidate(
        candidate_id=43, reviewer="ops@recupero.io",
        reason="upstream tag is clearly a phishing copycat",
    )
    # The UPDATE row carries the reviewer + reason params.
    update_calls = [
        (sql, params) for sql, params in fake_db.executed
        if "status = 'rejected'" in sql
    ]
    assert len(update_calls) == 1
    _, params = update_calls[0]
    assert "ops@recupero.io" in params
    assert any("phishing copycat" in str(p) for p in params)


# ─────────────────────────────────────────────────────────────────────────────
# Confidence decay
# ─────────────────────────────────────────────────────────────────────────────


def test_decay_200_day_high_becomes_medium() -> None:
    """200 days un-refreshed, stored 'high' → effective 'medium'."""
    now = datetime(2026, 5, 28, tzinfo=UTC)
    added = now - timedelta(days=200)
    result = apply_decay("high", added_at=added, refreshed_at=None, now=now)
    assert result == "medium"


def test_decay_200_day_high_with_recent_refresh_stays_high() -> None:
    """200 days since added_at but refreshed yesterday → still
    effective 'high'."""
    now = datetime(2026, 5, 28, tzinfo=UTC)
    added = now - timedelta(days=200)
    refreshed = now - timedelta(days=1)
    result = apply_decay("high", added_at=added, refreshed_at=refreshed, now=now)
    assert result == "high"


def test_decay_400_day_high_becomes_low() -> None:
    """400 days un-refreshed crosses 2 decay windows: high → medium →
    low. Floor at low — no further decay."""
    now = datetime(2026, 5, 28, tzinfo=UTC)
    added = now - timedelta(days=400)
    result = apply_decay("high", added_at=added, refreshed_at=None, now=now)
    assert result == "low"


def test_decay_999_day_high_still_only_low() -> None:
    """Even 5 decay windows old, low is the floor."""
    now = datetime(2026, 5, 28, tzinfo=UTC)
    added = now - timedelta(days=999)
    result = apply_decay("high", added_at=added, refreshed_at=None, now=now)
    assert result == "low"


def test_decay_under_one_window_unchanged() -> None:
    """At 179 days < 180-day window, 'high' stays 'high'."""
    now = datetime(2026, 5, 28, tzinfo=UTC)
    added = now - timedelta(days=179)
    result = apply_decay("high", added_at=added, refreshed_at=None, now=now)
    assert result == "high"


def test_decay_medium_becomes_low_after_one_window() -> None:
    """Starting from medium, one window → low."""
    now = datetime(2026, 5, 28, tzinfo=UTC)
    added = now - timedelta(days=181)
    result = apply_decay("medium", added_at=added, refreshed_at=None, now=now)
    assert result == "low"


def test_decay_low_stays_low_always() -> None:
    """Low never decays."""
    now = datetime(2026, 5, 28, tzinfo=UTC)
    added = now - timedelta(days=999)
    result = apply_decay("low", added_at=added, refreshed_at=None, now=now)
    assert result == "low"


def test_decay_with_naive_datetime_does_not_crash() -> None:
    """A naive ``added_at`` (no tzinfo) coerces to UTC and decay still
    applies — common with seed-file rows that read as naive ISO
    strings."""
    now = datetime(2026, 5, 28, tzinfo=UTC)
    added_naive = datetime(2025, 11, 1)  # naive, before -180d window
    result = apply_decay("high", added_at=added_naive, refreshed_at=None, now=now)
    assert result == "medium"


def test_decay_respects_env_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RECUPERO_LABEL_DECAY_DAYS=90 → faster decay."""
    monkeypatch.setenv("RECUPERO_LABEL_DECAY_DAYS", "90")
    now = datetime(2026, 5, 28, tzinfo=UTC)
    added = now - timedelta(days=100)  # >90, <180
    result = apply_decay("high", added_at=added, refreshed_at=None, now=now)
    assert result == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# Daily cap
# ─────────────────────────────────────────────────────────────────────────────


def test_daily_cap_of_100_honored(
    fake_db: _FakeCursor, monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Persist 150 candidates → only 100 reach the DB (cap=100)."""
    # Force a deterministic cap.
    monkeypatch.delenv("RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP", raising=False)
    many = [
        CandidateLabel(
            address=f"0x{i:040x}", chain="ethereum",
            proposed_category="bridge",
            proposed_name=f"Bridge{i}",
            source="defillama_new_protocol",
        )
        for i in range(150)
    ]
    # Pretend every insert returns a row id.
    fake_db.rows_for_fetchone = [(i,) for i in range(100)]
    caplog.set_level(logging.WARNING)
    n = persist_candidates(many)
    assert n == 100
    # Only 100 inserts (each calls fetchone()).
    insert_calls = [
        c for c in fake_db.executed
        if "INSERT INTO public.label_candidates" in c[0]
    ]
    assert len(insert_calls) == 100
    # WARN about the cap being exceeded.
    assert any("daily cap" in rec.message for rec in caplog.records)


def test_daily_cap_env_override(
    fake_db: _FakeCursor, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP=5 → only 5 persisted."""
    monkeypatch.setenv("RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP", "5")
    many = [
        CandidateLabel(
            address=f"0x{i:040x}", chain="ethereum",
            proposed_category="bridge",
            proposed_name=f"Bridge{i}",
            source="defillama_new_protocol",
        )
        for i in range(20)
    ]
    fake_db.rows_for_fetchone = [(i,) for i in range(5)]
    n = persist_candidates(many)
    assert n == 5


# ─────────────────────────────────────────────────────────────────────────────
# No-op re-run
# ─────────────────────────────────────────────────────────────────────────────


@respx.mock
def test_rerunning_cron_with_no_new_data_is_a_noop(
    fake_db: _FakeCursor, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every upstream returns the same rows; second run inserts zero
    new rows because dedup catches them."""
    monkeypatch.setenv("RECUPERO_LABEL_AUTO_INGEST_DAILY_CAP", "100")
    respx.get("https://api.llama.fi/protocols").mock(
        return_value=httpx.Response(200, json=[
            {
                "id": "1", "name": "OneBridge",
                "address": "0xbeef" + "0" * 36,
                "category": "Bridge",
                "chains": ["Ethereum"],
                "slug": "onebridge",
            },
        ]),
    )
    respx.get(
        "https://apilist.tronscanapi.com/api/contracts?contract_type=bridge"
    ).mock(return_value=httpx.Response(200, json={"data": []}))
    respx.get(
        "https://apilist.tronscanapi.com/api/contracts?contract_type=exchange"
    ).mock(return_value=httpx.Response(200, json={"data": []}))
    respx.get(
        "https://public-api.solscan.io/account/labels?category=exchange"
    ).mock(return_value=httpx.Response(200, json=[]))
    # v0.38: TON entity harvest (tonapi) — empty so the no-op assertion holds.
    respx.get("https://tonapi.io/v2/accounts/search").mock(
        return_value=httpx.Response(200, json={"addresses": []}),
    )
    # v0.38: OSS label dumps (brianleect, 6 EVM chains) — empty so it's a no-op.
    respx.get(url__regex=r"https://raw\.githubusercontent\.com/brianleect/.*").mock(
        return_value=httpx.Response(200, json={}),
    )

    # First run — one INSERT returns a row.
    fake_db.rows_for_fetchone = [(1,)]
    first = auto_ingest.run_daily_pull()
    assert first["persisted"] == 1
    # Second run — ON CONFLICT DO NOTHING returns no row.
    fake_db.rows_for_fetchone = [None]
    second = auto_ingest.run_daily_pull()
    assert second["persisted"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Candidate dataclass validation
# ─────────────────────────────────────────────────────────────────────────────


def test_candidate_rejects_empty_address() -> None:
    with pytest.raises(ValueError, match="address"):
        CandidateLabel(
            address="", chain="ethereum",
            proposed_category="bridge",
            proposed_name="x",
            source="defillama_new_protocol",
        )


def test_candidate_rejects_unknown_category() -> None:
    with pytest.raises(ValueError, match="proposed_category"):
        CandidateLabel(
            address="0xA0", chain="ethereum",
            proposed_category="totally_made_up",
            proposed_name="x",
            source="defillama_new_protocol",
        )


def test_candidate_rejects_unknown_confidence() -> None:
    with pytest.raises(ValueError, match="proposed_confidence"):
        CandidateLabel(
            address="0xA0", chain="ethereum",
            proposed_category="bridge",
            proposed_name="x",
            source="defillama_new_protocol",
            proposed_confidence="super-high",
        )


# ─────────────────────────────────────────────────────────────────────────────
# LabelStore wiring — decay is visible at lookup time
# ─────────────────────────────────────────────────────────────────────────────


def test_label_store_lookup_returns_decayed_confidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: a label loaded from a seed file with a 200-day-old
    added_at → LabelStore.lookup returns confidence='medium'."""
    from recupero.config import RecuperoConfig
    from recupero.labels.store import LabelStore
    from recupero.models import Chain

    seeds_dir = tmp_path / "seeds"
    seeds_dir.mkdir()
    # 200 days ago from 2026-05-28 → 2025-11-09
    old = (datetime.now(UTC) - timedelta(days=200)).isoformat().replace("+00:00", "Z")
    (seeds_dir / "bridges.json").write_text(json.dumps([
        {
            "address": "0x" + "ab" * 20,
            "name": "Old Bridge",
            "category": "bridge",
            "confidence": "high",
            "source": "manual",
            "added_at": old,
            "chain": "ethereum",
        },
    ]), encoding="utf-8")

    # Monkeypatch SEEDS_DIR to point at our tmp seeds.
    import recupero.labels.store as store_mod
    monkeypatch.setattr(store_mod, "SEEDS_DIR", seeds_dir, raising=True)

    cfg = RecuperoConfig()
    # storage.data_dir doesn't need to exist for this test.
    store = LabelStore.load(cfg)

    result = store.lookup("0x" + "AB" * 20, chain=Chain.ethereum)
    assert result is not None
    # Stored was 'high'; effective is 'medium' after 200d decay.
    assert result.confidence == "medium"


# ─────────────────────────────────────────────────────────────────────────────
# TON entity harvest (tonapi.io) — v0.38 (#1, more-data/TON)
# ─────────────────────────────────────────────────────────────────────────────

_BINANCE_TON_RAW = "0:f99b14600ae44d2f12b178e8c6eabd78892ae82c5e45b6898f9deb7eb203f9c4"


@respx.mock
def test_tonapi_search_produces_ton_exchange_candidate() -> None:
    """tonapi name-search → TON exchange_hot_wallet candidate, address
    canonicalized to raw, low confidence, source tonapi_search."""
    # One route matches all per-query calls; returns a Binance-named TON addr.
    respx.get("https://tonapi.io/v2/accounts/search").mock(
        return_value=httpx.Response(200, json={"addresses": [
            {"address": _BINANCE_TON_RAW, "name": "Binance cold account"},
        ]}),
    )
    out = fetch_candidate_ton_entities()
    # Only the "Binance" query's results pass the name-precision filter; dedup
    # collapses the 8 identical responses to one candidate.
    assert len(out) == 1
    c = out[0]
    assert c.chain == "ton"
    assert c.proposed_category == "exchange_hot_wallet"
    assert c.proposed_confidence == "low"
    assert c.source == "tonapi_search"
    assert c.address == _BINANCE_TON_RAW  # canonical raw, lowercased
    assert "Binance" in c.proposed_name


@respx.mock
def test_tonapi_precision_filters_unrelated_names() -> None:
    """A result whose tonapi name doesn't contain the query term is dropped
    (precision guard against fuzzy matches reaching the review queue)."""
    respx.get("https://tonapi.io/v2/accounts/search").mock(
        return_value=httpx.Response(200, json={"addresses": [
            {"address": _BINANCE_TON_RAW, "name": "Some random wallet"},
        ]}),
    )
    assert fetch_candidate_ton_entities() == []


@respx.mock
def test_tonapi_skips_unnormalizable_address() -> None:
    respx.get("https://tonapi.io/v2/accounts/search").mock(
        return_value=httpx.Response(200, json={"addresses": [
            {"address": "not-a-ton-address", "name": "Binance"},
        ]}),
    )
    assert fetch_candidate_ton_entities() == []


# ─────────────────────────────────────────────────────────────────────────────
# OSS label-dump harvest (brianleect/etherscan-labels, 6 EVM chains) — v0.38
# ─────────────────────────────────────────────────────────────────────────────


def _empty_oss_dumps_except(explorer: str, payload: dict) -> None:
    """Mock all 6 brianleect dump URLs: `payload` for `explorer`, {} for rest."""
    for ex in ("etherscan", "bscscan", "polygonscan", "arbiscan", "optimism", "ftmscan"):
        url = (
            "https://raw.githubusercontent.com/brianleect/etherscan-labels/main/"
            f"data/{ex}/combined/combinedAllLabels.json"
        )
        respx.get(url).mock(return_value=httpx.Response(
            200, json=payload if ex == explorer else {}))


@respx.mock
def test_oss_dump_maps_exchange_and_bridge_labels() -> None:
    """An exchange-name label → exchange_hot_wallet; a 'deposit' name →
    exchange_deposit; an exact 'bridge' label → bridge. EVM addr lower-cased."""
    _empty_oss_dumps_except("etherscan", {
        "0xAAA0000000000000000000000000000000000001": {"name": "Binance 35", "labels": ["binance"]},
        "0xBBB0000000000000000000000000000000000002": {"name": "Huobi: Deposit", "labels": ["huobi"]},
        "0xCCC0000000000000000000000000000000000003": {"name": "Hop Protocol: WBTC Bridge", "labels": ["bridge", "hop-protocol"]},
        "0xDDD0000000000000000000000000000000000004": {"name": "Some Token", "labels": ["bridged-token"]},  # NOT a bridge
        "0xEEE0000000000000000000000000000000000005": {"name": "Sushi", "labels": ["sushiswap"]},  # skipped
    })
    out = fetch_candidate_etherscan_label_dumps()
    by_addr = {c.address: c for c in out}
    assert by_addr["0xaaa0000000000000000000000000000000000001"].proposed_category == "exchange_hot_wallet"
    assert by_addr["0xbbb0000000000000000000000000000000000002"].proposed_category == "exchange_deposit"
    assert by_addr["0xccc0000000000000000000000000000000000003"].proposed_category == "bridge"
    # bridged-token (not exact 'bridge') and sushiswap are skipped
    assert "0xddd0000000000000000000000000000000000004" not in by_addr
    assert "0xeee0000000000000000000000000000000000005" not in by_addr
    for c in out:
        assert c.chain == "ethereum"
        assert c.source == "etherscan_labels_oss"
        assert c.proposed_confidence == "low"


@respx.mock
def test_oss_dump_chain_mapping_for_non_eth() -> None:
    """A bscscan dump entry is emitted with chain='bsc'."""
    _empty_oss_dumps_except("bscscan", {
        "0xfff0000000000000000000000000000000000009": {"name": "Binance Hot", "labels": ["binance"]},
    })
    out = fetch_candidate_etherscan_label_dumps()
    assert len(out) == 1
    assert out[0].chain == "bsc"
    assert out[0].address == "0xfff0000000000000000000000000000000000009"


@respx.mock
def test_oss_dump_unreachable_degrades_to_empty() -> None:
    for ex in ("etherscan", "bscscan", "polygonscan", "arbiscan", "optimism", "ftmscan"):
        url = (
            "https://raw.githubusercontent.com/brianleect/etherscan-labels/main/"
            f"data/{ex}/combined/combinedAllLabels.json"
        )
        respx.get(url).mock(return_value=httpx.Response(503))
    assert fetch_candidate_etherscan_label_dumps() == []


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v", "--tb=short"])
