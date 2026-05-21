"""Unit tests for the investigations_api module.

These cover the pure-Python rendering + classification helpers
(``_render_list_row``, ``_render_detail_row``, ``_raw_key_for``,
``_parse_freeze_filename``, ``_issuer_from_slug``,
``_compute_duration_secs``). The network-touching paths
(``_list_bucket``, ``_sign_storage_url``, ``_build_summary``) are
exercised by the end-to-end Railway canary and not unit-tested
here — mocking ``urllib.request.urlopen`` for those would lock in
implementation details we may want to swap (e.g. moving to the
``supabase`` Python SDK).

Tests run in <50ms total, zero network, zero DB.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

from recupero.worker.investigations_api import (
    _compute_duration_secs,
    _empty_artifacts,
    _issuer_from_slug,
    _parse_freeze_filename,
    _raw_key_for,
    _render_detail_row,
    _render_list_row,
)

# ---- _render_list_row ---- #


def _make_row(**overrides) -> dict:
    base = {
        "id": uuid4(),
        "case_id": None,
        "status": "complete",
        "chain": "ethereum",
        "seed_address": "0x" + "a" * 40,
        "label": "test-row",
        "triggered_by": "alec@recupero.io",
        "triggered_at": datetime(2026, 5, 15, 15, 0, tzinfo=UTC),
        "claimed_at": datetime(2026, 5, 15, 15, 0, 0, tzinfo=UTC),
        "completed_at": datetime(2026, 5, 15, 15, 0, 12, tzinfo=UTC),
        "failed_at": None,
        "max_depth": 2,
        "skip_editorial": True,
        "skip_freeze_briefs": True,
        "total_loss_usd": Decimal("0"),
        "max_recoverable_usd": Decimal("0"),
        "freezable_issuers": None,
    }
    base.update(overrides)
    return base


def test_list_row_wallet_trace_flag_computed() -> None:
    """case_id=None must surface as is_wallet_trace=True for the UI."""
    out = _render_list_row(_make_row(case_id=None))
    assert out["is_wallet_trace"] is True


def test_list_row_case_driven_flag_computed() -> None:
    """case_id set → is_wallet_trace=False."""
    out = _render_list_row(_make_row(case_id=uuid4()))
    assert out["is_wallet_trace"] is False
    assert out["case_id"] is not None


def test_list_row_decimal_stringified() -> None:
    """Decimals serialize as strings — json.dumps can't handle Decimal."""
    out = _render_list_row(_make_row(total_loss_usd=Decimal("123.45")))
    assert out["total_loss_usd"] == "123.45"
    assert isinstance(out["total_loss_usd"], str)


def test_list_row_datetimes_iso() -> None:
    """All datetimes render as ISO 8601 strings, not raw datetime objects."""
    out = _render_list_row(_make_row())
    assert isinstance(out["triggered_at"], str)
    assert out["triggered_at"].startswith("2026-05-15")
    assert out["completed_at"].startswith("2026-05-15")


def test_list_row_null_datetimes_stay_null() -> None:
    """Missing timestamps render as None, not empty strings."""
    out = _render_list_row(_make_row(completed_at=None, failed_at=None))
    assert out["completed_at"] is None
    assert out["failed_at"] is None


# ---- _render_detail_row ---- #


def test_detail_row_has_duration_for_completed() -> None:
    """A completed row has duration_seconds = completed_at - claimed_at."""
    row = _make_row(
        claimed_at=datetime(2026, 5, 15, 15, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 5, 15, 15, 0, 12, tzinfo=UTC),
    )
    out = _render_detail_row(row)
    assert out["duration_seconds"] == 12.0


def test_detail_row_has_duration_for_failed() -> None:
    """A failed row uses failed_at, not completed_at."""
    row = _make_row(
        claimed_at=datetime(2026, 5, 15, 15, 0, 0, tzinfo=UTC),
        completed_at=None,
        failed_at=datetime(2026, 5, 15, 15, 5, 8, tzinfo=UTC),
        status="failed",
    )
    out = _render_detail_row(row)
    assert out["duration_seconds"] == 308.0


def test_detail_row_pending_has_no_duration() -> None:
    """An un-claimed row has duration=None — there's no end time yet."""
    row = _make_row(claimed_at=None, completed_at=None, failed_at=None,
                    status="pending")
    out = _render_detail_row(row)
    assert out["duration_seconds"] is None


def test_detail_row_running_has_no_duration() -> None:
    """A claimed-but-not-terminal row has duration=None."""
    row = _make_row(
        claimed_at=datetime(2026, 5, 15, 15, 0, tzinfo=UTC),
        completed_at=None, failed_at=None, status="tracing",
    )
    out = _render_detail_row(row)
    assert out["duration_seconds"] is None


def test_detail_row_carries_error_context_on_failure() -> None:
    """Failure mode rows must include error_stage + error_message so
    the admin UI can render the failure reason without a separate fetch."""
    row = _make_row(
        status="failed",
        error_stage="claim_validation_failed",
        error_message="ValidationError: incident_time is required",
        completed_at=None,
        failed_at=datetime(2026, 5, 15, 15, 0, 10, tzinfo=UTC),
    )
    out = _render_detail_row(row)
    assert out["error_stage"] == "claim_validation_failed"
    assert "ValidationError" in out["error_message"]


# ---- _raw_key_for / _is_folder_entry ---- #


def test_raw_key_for_known_files() -> None:
    """All root-level files the worker writes have a canonical key."""
    assert _raw_key_for("case.json") == "case_json"
    assert _raw_key_for("manifest.json") == "manifest_json"
    assert _raw_key_for("freeze_asks.json") == "freeze_asks"
    assert _raw_key_for("freeze_brief.json") == "freeze_brief"
    assert _raw_key_for("transfers.csv") == "transfers_csv"


def test_raw_key_for_unknown_files_filtered() -> None:
    """Unknown files return None so random bucket detritus (operator
    test files, leftover scratch) doesn't surface in the UI."""
    assert _raw_key_for("random_test.json") is None
    assert _raw_key_for("not_a_real_file.bin") is None


# ---- _parse_freeze_filename / _issuer_from_slug ---- #


def test_parse_freeze_request_filename() -> None:
    slug, ext = _parse_freeze_filename("freeze_request_circle_a1b2c3d4.html")
    assert slug == "circle_a1b2c3d4"
    assert ext == ".html"


def test_parse_le_handoff_filename() -> None:
    slug, ext = _parse_freeze_filename("le_handoff_tether_a1b2c3d4.pdf")
    assert slug == "tether_a1b2c3d4"
    assert ext == ".pdf"


def test_parse_unknown_prefix_returns_raw() -> None:
    """Filename that doesn't start with a known prefix returns
    name + empty ext — caller is expected to ignore unknown shapes."""
    slug, ext = _parse_freeze_filename("random_file.txt")
    assert slug == "random_file.txt"
    assert ext == ""


def test_issuer_from_slug_simple() -> None:
    """``circle_<hash>`` → 'Circle'."""
    assert _issuer_from_slug("circle_a1b2c3d4") == "Circle"
    assert _issuer_from_slug("tether_deadbeef") == "Tether"


def test_issuer_from_slug_multiword() -> None:
    """``coinbase_us_<hash>`` → 'Coinbase Us'."""
    assert _issuer_from_slug("coinbase_us_a1b2c3d4") == "Coinbase Us"


def test_issuer_from_slug_no_hash_fallback() -> None:
    """If the hash suffix isn't recognized, return the slug as-is
    (title-cased). Defensive — better than crashing on unexpected
    filename shapes."""
    out = _issuer_from_slug("not_a_normal_slug")
    # Title case applied to whatever we get
    assert out == "Not A Normal Slug"


# ---- _compute_duration_secs (boundary cases) ---- #


def test_duration_for_failed_uses_failed_at() -> None:
    row = _make_row(
        claimed_at=datetime(2026, 5, 15, 15, 0, 0, tzinfo=UTC),
        completed_at=None,
        failed_at=datetime(2026, 5, 15, 15, 1, 30, tzinfo=UTC),
    )
    assert _compute_duration_secs(row) == 90.0


def test_duration_completed_overrides_failed() -> None:
    """If both completed_at and failed_at are set (shouldn't happen
    in practice but defensive), completed_at wins."""
    row = _make_row(
        claimed_at=datetime(2026, 5, 15, 15, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 5, 15, 15, 0, 5, tzinfo=UTC),
        failed_at=datetime(2026, 5, 15, 15, 1, 0, tzinfo=UTC),
    )
    assert _compute_duration_secs(row) == 5.0


def test_duration_subsecond_precision() -> None:
    """Sub-second durations round to 2 decimals so the UI can show
    'completed in 0.12s'."""
    row = _make_row(
        claimed_at=datetime(2026, 5, 15, 15, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 5, 15, 15, 0, 0, 123456, tzinfo=UTC),
    )
    assert _compute_duration_secs(row) == 0.12


# ---- artifacts shape ---- #


def test_empty_artifacts_shape() -> None:
    """The empty-artifacts default is the contract the UI builds
    against — locking the shape so changes are intentional."""
    out = _empty_artifacts()
    assert set(out.keys()) == {"trace_report", "flow_diagram", "raw", "freeze_letters"}
    assert out["trace_report"] == {"html": None, "pdf": None}
    assert out["flow_diagram"] == {"svg": None, "pdf": None}
    assert out["raw"] == {}
    assert out["freeze_letters"] == []
