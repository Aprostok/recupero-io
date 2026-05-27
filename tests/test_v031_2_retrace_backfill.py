"""v0.31.2 (Gap #14): retrace backfill observability cron.

The cron walks every case under ``CaseStore.cases_root`` and produces
a JSON report listing cases whose ``trace_completed_at`` predates a
"trace-shape-changing" label (bridge / mixer / exchange_deposit /
exchange_hot_wallet / perpetrator) that now matches one of the
case's counterparties.

Lockdown coverage:

* Three-case scenario (30d / 60d / 90d old traces, with labels
  added 15d and 45d ago) — verifies the time predicate counts the
  RIGHT labels per case.
* Edge: case with no ``trace_completed_at`` skips gracefully.
* Edge: label with no ``added_at`` (epoch fallback) never triggers
  as "new since trace".
* Edge: empty case store → empty candidate list.
* Edge: garbage ``trace_completed_at`` on the model is rejected by
  Pydantic at load time, so the cron only sees None — covered by
  the no-trace-completed-at edge case. We additionally lock down
  the cron's own ``_coerce_aware_utc`` to assert it returns None on
  garbage so future Pydantic loosening can't crash the cron.
* Schema: write_retrace_report sorts DESC by new_label_matches +
  emits the v1 envelope (schema_version / generated_at /
  candidate_count / candidates).
* Categories: a "defi_protocol" or "unknown" label that's newer
  than the trace does NOT trigger — only the five
  RETRACE_TRIGGER_CATEGORIES are investigatively meaningful.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from recupero.config import RecuperoConfig, StorageParams
from recupero.labels.store import LabelStore
from recupero.models import (
    Case,
    Chain,
    Counterparty,
    Label,
    LabelCategory,
    TokenRef,
    Transfer,
)
from recupero.storage.case_store import CaseStore
from recupero.worker.retrace_backfill import (
    DEFAULT_OUT_RELATIVE,
    RETRACE_TRIGGER_CATEGORIES,
    _coerce_aware_utc,
    find_retrace_candidates,
    run_backfill_scan,
    write_retrace_report,
)


# Reference "now" — pinned so all relative-time math is deterministic
# regardless of when the test suite runs.
_NOW = datetime(2026, 5, 26, 12, 0, 0, tzinfo=UTC)


# Three EVM-shape addresses we'll re-use across cases. Each is a
# valid checksum address (hand-picked from the zero-prefix space so
# we don't collide with any real seed-list entry).
_ADDR_A = "0x000000000000000000000000000000000000A001"
_ADDR_B = "0x000000000000000000000000000000000000B002"
_ADDR_C = "0x000000000000000000000000000000000000C003"


def _seed_addr() -> str:
    """Constant seed wallet for every synthetic case — outside the
    counterparty set so it's not a target of label resolution."""
    return "0x000000000000000000000000000000000000DEAD"


def _make_transfer(
    *,
    to_address: str,
    when: datetime,
    tx_suffix: str = "abc",
) -> Transfer:
    """Build one outbound Transfer from the seed to ``to_address``.

    Used to populate Case.transfers — the retrace cron only reads
    ``to_address`` (counterparty) so the rest of the fields are
    plausible placeholders sufficient for Pydantic validation.
    """
    cp = Counterparty(address=to_address, label=None, is_contract=False)
    return Transfer(
        transfer_id=f"ethereum:0x{tx_suffix}:0",
        chain=Chain.ethereum,
        tx_hash=f"0x{tx_suffix}",
        block_number=19_000_000,
        block_time=when,
        log_index=None,
        from_address=_seed_addr(),
        to_address=to_address,
        counterparty=cp,
        token=TokenRef(
            chain=Chain.ethereum,
            contract=None,
            symbol="ETH",
            decimals=18,
            coingecko_id="ethereum",
        ),
        amount_raw="1000000000000000000",
        amount_decimal=Decimal("1.0"),
        usd_value_at_tx=Decimal("3000.00"),
        pricing_source="coingecko:ethereum:2026-05-26",
        pricing_error=None,
        hop_depth=0,
        parent_transfer_id=None,
        fetched_at=when,
        explorer_url=f"https://etherscan.io/tx/0x{tx_suffix}",
    )


def _make_case(
    *,
    case_id: str,
    counterparties: list[str],
    trace_completed_at: datetime | None,
) -> Case:
    """Build a synthetic Case wired to the supplied counterparties.

    The cron only consults ``case.case_id`` + ``case.transfers`` +
    ``case.trace_completed_at`` so the other fields are minimal
    Pydantic-valid placeholders.
    """
    transfers = [
        _make_transfer(
            to_address=addr,
            when=trace_completed_at or _NOW,
            tx_suffix=f"{case_id}_{i}",
        )
        for i, addr in enumerate(counterparties)
    ]
    return Case(
        case_id=case_id,
        seed_address=_seed_addr(),
        chain=Chain.ethereum,
        incident_time=_NOW - timedelta(days=120),
        transfers=transfers,
        exchange_endpoints=[],
        total_usd_out=Decimal("3000"),
        trace_started_at=(trace_completed_at or _NOW) - timedelta(minutes=5),
        trace_completed_at=trace_completed_at,
    )


def _make_label(
    *,
    address: str,
    category: LabelCategory,
    added_at: datetime | None,
    name: str = "Synthetic Label",
) -> Label:
    """Build a Label whose ``added_at`` may be None (we then patch the
    field after construction to mimic an on-disk label-DB entry that
    lost its provenance). Pydantic enforces non-None on construction,
    so we use the model_construct path for the None case."""
    if added_at is None:
        # ``Label.added_at`` is a required datetime field. Use
        # model_construct to bypass validation — this is how a
        # malformed-but-existing on-disk label could end up in memory
        # in production (e.g. if load_file got widened to tolerate
        # missing added_at). The cron's epoch-fallback semantics must
        # cover this shape.
        return Label.model_construct(
            address=address,
            name=name,
            category=category,
            exchange=None,
            source="test",
            confidence="high",
            notes=None,
            added_at=None,
            valid_from=None,
            valid_until=None,
        )
    return Label(
        address=address,
        name=name,
        category=category,
        exchange=None,
        source="test",
        confidence="high",
        notes=None,
        added_at=added_at,
    )


def _label_store_with(labels: list[Label]) -> LabelStore:
    """Build an in-memory LabelStore with the supplied labels.

    We use ``LabelStore.add`` (the public API the task brief
    explicitly allows) rather than rebuilding the seed dir, so the
    test doesn't depend on filesystem layout.
    """
    store = LabelStore()
    for label in labels:
        store.add(label)
    return store


def _case_store(tmp_path: Path) -> CaseStore:
    """Build a CaseStore rooted at tmp_path."""
    cfg = RecuperoConfig(storage=StorageParams(data_dir=str(tmp_path)))
    return CaseStore(cfg)


# --------------------------------------------------------------------- #
# Core three-case scenario from the task brief.
# --------------------------------------------------------------------- #


class TestThreeCaseScenario:
    """Case A (30d): one 15-day-old label matches → CANDIDATE.
    Case B (60d): both 15d + 45d labels match → CANDIDATE (2 matches).
    Case C (90d): no matches → NOT a candidate."""

    @pytest.fixture()
    def populated(self, tmp_path: Path) -> tuple[CaseStore, LabelStore]:
        case_store = _case_store(tmp_path)

        # Case A — traced 30 days ago, counterparty A only.
        case_a = _make_case(
            case_id="caseA30d",
            counterparties=[_ADDR_A],
            trace_completed_at=_NOW - timedelta(days=30),
        )
        case_store.write_case(case_a)

        # Case B — traced 60 days ago, counterparties A + B.
        case_b = _make_case(
            case_id="caseB60d",
            counterparties=[_ADDR_A, _ADDR_B],
            trace_completed_at=_NOW - timedelta(days=60),
        )
        case_store.write_case(case_b)

        # Case C — traced 90 days ago, counterparty C (no matching label).
        case_c = _make_case(
            case_id="caseC90d",
            counterparties=[_ADDR_C],
            trace_completed_at=_NOW - timedelta(days=90),
        )
        case_store.write_case(case_c)

        label_store = _label_store_with([
            # Label on A added 15 days ago — newer than the 30d, 60d
            # cases but not relevant to case C (C doesn't touch A).
            _make_label(
                address=_ADDR_A,
                category=LabelCategory.bridge,
                added_at=_NOW - timedelta(days=15),
                name="Bridge-on-A (15d old)",
            ),
            # Label on B added 45 days ago — newer than 60d trace
            # (case B), older than 30d trace (case A doesn't touch B
            # anyway), and case C doesn't touch B.
            _make_label(
                address=_ADDR_B,
                category=LabelCategory.mixer,
                added_at=_NOW - timedelta(days=45),
                name="Mixer-on-B (45d old)",
            ),
        ])
        return case_store, label_store

    def test_case_a_30d_has_one_match(
        self, populated: tuple[CaseStore, LabelStore],
    ) -> None:
        case_store, label_store = populated
        candidates = find_retrace_candidates(
            case_store=case_store, label_store=label_store,
        )
        by_id = {c["case_id"]: c for c in candidates}
        assert "caseA30d" in by_id, (
            "case A (30d old) should be a candidate because the bridge "
            "label on _ADDR_A was added 15 days ago — strictly newer "
            "than the trace_completed_at"
        )
        row = by_id["caseA30d"]
        assert row["new_label_matches"] == 1
        assert row["by_category"] == {"bridge": 1}
        assert len(row["top_counterparties"]) == 1
        assert row["top_counterparties"][0]["address"] == _ADDR_A
        assert row["top_counterparties"][0]["new_label_category"] == "bridge"

    def test_case_b_60d_has_two_matches(
        self, populated: tuple[CaseStore, LabelStore],
    ) -> None:
        case_store, label_store = populated
        candidates = find_retrace_candidates(
            case_store=case_store, label_store=label_store,
        )
        by_id = {c["case_id"]: c for c in candidates}
        assert "caseB60d" in by_id
        row = by_id["caseB60d"]
        assert row["new_label_matches"] == 2, (
            "case B (60d old) touches both _ADDR_A and _ADDR_B; both "
            "labels (15d and 45d) postdate the 60d trace"
        )
        # by_category should sum to 2 across bridge + mixer.
        assert row["by_category"] == {"bridge": 1, "mixer": 1}

    def test_case_c_90d_is_not_a_candidate(
        self, populated: tuple[CaseStore, LabelStore],
    ) -> None:
        case_store, label_store = populated
        candidates = find_retrace_candidates(
            case_store=case_store, label_store=label_store,
        )
        by_id = {c["case_id"]: c for c in candidates}
        # The 15d / 45d labels both apply to A and B, neither of which
        # is in case C's counterparty set, so case C must NOT appear.
        assert "caseC90d" not in by_id

    def test_report_envelope_and_sort_order(
        self, populated: tuple[CaseStore, LabelStore], tmp_path: Path,
    ) -> None:
        case_store, label_store = populated
        candidates = find_retrace_candidates(
            case_store=case_store, label_store=label_store,
        )
        out_path = tmp_path / "report.json"
        write_retrace_report(candidates, out_path)
        payload = json.loads(out_path.read_text(encoding="utf-8"))
        assert payload["schema_version"] == 1
        assert "generated_at" in payload
        assert payload["candidate_count"] == 2  # A + B, not C
        # Sort: case B (2 matches) before case A (1 match).
        ids_in_order = [c["case_id"] for c in payload["candidates"]]
        assert ids_in_order == ["caseB60d", "caseA30d"]


# --------------------------------------------------------------------- #
# Edge cases.
# --------------------------------------------------------------------- #


class TestEdgeCases:
    def test_empty_case_store_returns_empty_list(
        self, tmp_path: Path,
    ) -> None:
        case_store = _case_store(tmp_path)
        label_store = _label_store_with([
            _make_label(
                address=_ADDR_A,
                category=LabelCategory.bridge,
                added_at=_NOW - timedelta(days=1),
            ),
        ])
        candidates = find_retrace_candidates(
            case_store=case_store, label_store=label_store,
        )
        assert candidates == []

    def test_case_without_trace_completed_at_skipped_gracefully(
        self, tmp_path: Path,
    ) -> None:
        case_store = _case_store(tmp_path)
        # The trace never finished — trace_completed_at is None.
        # The cron must NOT crash and must NOT report this case.
        open_case = _make_case(
            case_id="open_case",
            counterparties=[_ADDR_A],
            trace_completed_at=None,
        )
        case_store.write_case(open_case)
        label_store = _label_store_with([
            _make_label(
                address=_ADDR_A,
                category=LabelCategory.bridge,
                added_at=_NOW - timedelta(days=1),
            ),
        ])
        candidates = find_retrace_candidates(
            case_store=case_store, label_store=label_store,
        )
        assert candidates == []

    def test_label_without_added_at_treated_as_ancient(
        self, tmp_path: Path,
    ) -> None:
        """A label whose ``added_at`` got lost (None) must NEVER
        trigger as "new since trace" — otherwise an undated label
        manufactures false positives the operator can't act on."""
        case_store = _case_store(tmp_path)
        case = _make_case(
            case_id="recent_case",
            counterparties=[_ADDR_A],
            trace_completed_at=_NOW - timedelta(days=30),
        )
        case_store.write_case(case)
        label_store = _label_store_with([
            _make_label(
                address=_ADDR_A,
                category=LabelCategory.bridge,
                added_at=None,  # Provenance lost.
                name="Undated bridge",
            ),
        ])
        candidates = find_retrace_candidates(
            case_store=case_store, label_store=label_store,
        )
        assert candidates == [], (
            "an undated label must be treated as epoch-old, so it "
            "never counts as 'new since trace' regardless of how "
            "recent the trace was"
        )

    def test_irrelevant_label_categories_dont_trigger(
        self, tmp_path: Path,
    ) -> None:
        """defi_protocol / staking / unknown / victim labels change
        the brief NAMES but not the trace SHAPE — they are NOT a
        re-trace trigger even when fresh."""
        case_store = _case_store(tmp_path)
        case = _make_case(
            case_id="case_with_unknown",
            counterparties=[_ADDR_A, _ADDR_B, _ADDR_C],
            trace_completed_at=_NOW - timedelta(days=30),
        )
        case_store.write_case(case)
        # Three labels, all FRESH (1 day old), all NOT in the trigger set.
        label_store = _label_store_with([
            _make_label(
                address=_ADDR_A,
                category=LabelCategory.defi_protocol,
                added_at=_NOW - timedelta(days=1),
            ),
            _make_label(
                address=_ADDR_B,
                category=LabelCategory.staking,
                added_at=_NOW - timedelta(days=1),
            ),
            _make_label(
                address=_ADDR_C,
                category=LabelCategory.unknown,
                added_at=_NOW - timedelta(days=1),
            ),
        ])
        candidates = find_retrace_candidates(
            case_store=case_store, label_store=label_store,
        )
        assert candidates == [], (
            "labels not in RETRACE_TRIGGER_CATEGORIES must never "
            "produce a candidate, even when freshly added"
        )

    def test_label_added_exactly_at_trace_time_doesnt_trigger(
        self, tmp_path: Path,
    ) -> None:
        """Boundary: a label added AT the same instant as
        trace_completed_at was visible to the trace and must NOT
        re-trigger. Only strictly-newer labels count."""
        case_store = _case_store(tmp_path)
        trace_at = _NOW - timedelta(days=30)
        case = _make_case(
            case_id="boundary_case",
            counterparties=[_ADDR_A],
            trace_completed_at=trace_at,
        )
        case_store.write_case(case)
        label_store = _label_store_with([
            _make_label(
                address=_ADDR_A,
                category=LabelCategory.bridge,
                added_at=trace_at,  # exactly equal
            ),
        ])
        candidates = find_retrace_candidates(
            case_store=case_store, label_store=label_store,
        )
        assert candidates == []

    def test_perpetrator_and_exchange_hot_wallet_trigger(
        self, tmp_path: Path,
    ) -> None:
        """Lockdown that the full trigger set is honored, not just
        bridge + mixer. Add one perpetrator label + one
        exchange_hot_wallet label, expect both to register."""
        case_store = _case_store(tmp_path)
        case = _make_case(
            case_id="perp_and_hot_wallet",
            counterparties=[_ADDR_A, _ADDR_B],
            trace_completed_at=_NOW - timedelta(days=30),
        )
        case_store.write_case(case)
        label_store = _label_store_with([
            _make_label(
                address=_ADDR_A,
                category=LabelCategory.perpetrator,
                added_at=_NOW - timedelta(days=5),
            ),
            _make_label(
                address=_ADDR_B,
                category=LabelCategory.exchange_hot_wallet,
                added_at=_NOW - timedelta(days=10),
            ),
        ])
        candidates = find_retrace_candidates(
            case_store=case_store, label_store=label_store,
        )
        assert len(candidates) == 1
        assert candidates[0]["new_label_matches"] == 2
        assert candidates[0]["by_category"] == {
            "perpetrator": 1, "exchange_hot_wallet": 1,
        }


# --------------------------------------------------------------------- #
# Coerce / robustness lockdown.
# --------------------------------------------------------------------- #


class TestCoerceHelpers:
    """The cron's robustness against garbage trace_completed_at depends
    on ``_coerce_aware_utc`` returning None on non-datetime input. Lock
    this down separately so a future refactor can't quietly break it."""

    def test_coerce_returns_none_for_none(self) -> None:
        assert _coerce_aware_utc(None) is None

    def test_coerce_returns_none_for_string(self) -> None:
        # A string "garbage" or "NaN" must NOT crash, must NOT silently
        # coerce — must return None so the case loop skips this row.
        assert _coerce_aware_utc("not-a-datetime") is None
        assert _coerce_aware_utc("NaN") is None

    def test_coerce_returns_none_for_int(self) -> None:
        # Integers are a common "stale schema" leak (someone wrote an
        # epoch int instead of an ISO string). Must skip, not crash.
        assert _coerce_aware_utc(1234567890) is None

    def test_coerce_returns_none_for_float_nan(self) -> None:
        # NaN from a JSON allow_nan loader. Must skip.
        assert _coerce_aware_utc(float("nan")) is None

    def test_coerce_promotes_naive_to_utc(self) -> None:
        naive = datetime(2026, 1, 1, 0, 0, 0)
        promoted = _coerce_aware_utc(naive)
        assert promoted is not None
        assert promoted.tzinfo is UTC

    def test_coerce_preserves_aware(self) -> None:
        aware = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
        assert _coerce_aware_utc(aware) == aware


# --------------------------------------------------------------------- #
# Constants + end-to-end driver smoke.
# --------------------------------------------------------------------- #


class TestModuleSurface:
    def test_trigger_categories_locked(self) -> None:
        """Lock the exact set of trigger categories. A future change
        that quietly adds (e.g.) defi_protocol would inflate every
        cron run's candidate count and surprise operators — force
        the change to update this assertion deliberately."""
        assert RETRACE_TRIGGER_CATEGORIES == frozenset({
            LabelCategory.bridge,
            LabelCategory.mixer,
            LabelCategory.exchange_deposit,
            LabelCategory.exchange_hot_wallet,
            LabelCategory.perpetrator,
        })

    def test_default_out_path_is_under_data_dir(self) -> None:
        assert DEFAULT_OUT_RELATIVE == "data/retrace_candidates.json"

    def test_run_backfill_scan_writes_report(self, tmp_path: Path) -> None:
        """End-to-end smoke: build a case + label store on disk, run
        the top-level driver, assert it wrote a parseable report."""
        cfg = RecuperoConfig(storage=StorageParams(data_dir=str(tmp_path)))
        case_store = CaseStore(cfg)
        case = _make_case(
            case_id="e2e_smoke",
            counterparties=[_ADDR_A],
            trace_completed_at=_NOW - timedelta(days=10),
        )
        case_store.write_case(case)

        # Drop a local_*.json so LabelStore.load picks it up.
        labels_dir = tmp_path / "labels"
        labels_dir.mkdir(parents=True, exist_ok=True)
        (labels_dir / "local_retrace_test.json").write_text(json.dumps([
            {
                "address": _ADDR_A,
                "name": "E2E Bridge",
                "category": "bridge",
                "source": "test",
                "confidence": "high",
                "added_at": (_NOW - timedelta(days=2)).isoformat(),
            },
        ]))

        out_path = tmp_path / "report.json"
        n = run_backfill_scan(config=cfg, out_path=out_path)
        assert n == 1
        payload = json.loads(out_path.read_text(encoding="utf-8"))
        assert payload["candidate_count"] == 1
        assert payload["candidates"][0]["case_id"] == "e2e_smoke"
        assert payload["candidates"][0]["new_label_matches"] == 1


def test_report_sorted_desc_with_id_tiebreak(tmp_path: Path) -> None:
    """Verify the explicit sort contract — DESC by new_label_matches,
    ascending case_id on tie. Important for stable cron output
    across runs (operators paging a sorted list shouldn't see rows
    juggle position between identical-count cases)."""
    candidates: list[dict[str, Any]] = [
        {"case_id": "zebra", "new_label_matches": 3, "by_category": {},
         "trace_completed_at": _NOW.isoformat(), "top_counterparties": []},
        {"case_id": "alpha", "new_label_matches": 3, "by_category": {},
         "trace_completed_at": _NOW.isoformat(), "top_counterparties": []},
        {"case_id": "beta", "new_label_matches": 5, "by_category": {},
         "trace_completed_at": _NOW.isoformat(), "top_counterparties": []},
    ]
    out_path = tmp_path / "sort.json"
    write_retrace_report(candidates, out_path)
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    ids = [c["case_id"] for c in payload["candidates"]]
    assert ids == ["beta", "alpha", "zebra"], (
        "expect beta (5 matches) first, then alpha + zebra (3 each, "
        "alpha < zebra alphabetically)"
    )
