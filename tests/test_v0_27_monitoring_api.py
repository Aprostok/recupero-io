"""v0.27.0 — Exchange/Compliance monitoring API tests.

Covers:
  * created_by_for_api_key — multi-tenant boundary identifier
  * Input validation (address/chain/trigger/threshold/webhook URL)
  * create_subscription happy path + DB error
  * list_subscriptions filters by created_by prefix
  * get_subscription returns None for foreign-key lookups (404 leak guard)
  * soft_delete_subscription enforces ownership
  * Bulk screen request shape + per-row error tolerance
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# created_by_for_api_key
# ─────────────────────────────────────────────────────────────────────────────


def test_created_by_uses_api_prefix():
    from recupero.api.monitoring_api import (
        API_CREATED_BY_PREFIX, created_by_for_api_key,
    )
    assert API_CREATED_BY_PREFIX == "api:"
    assert created_by_for_api_key("exchange-acme") == "api:exchange-acme"
    # Stripping
    assert created_by_for_api_key("  partner-x  ") == "api:partner-x"


def test_two_api_keys_get_distinct_created_by():
    """Multi-tenant boundary: distinct keys produce distinct
    created_by values."""
    from recupero.api.monitoring_api import created_by_for_api_key
    a = created_by_for_api_key("partner-a")
    b = created_by_for_api_key("partner-b")
    assert a != b


# ─────────────────────────────────────────────────────────────────────────────
# Input validation
# ─────────────────────────────────────────────────────────────────────────────


def test_validate_rejects_empty_address():
    from recupero.api.monitoring_api import (
        MonitoringApiError, _validate_subscription_input,
    )
    with pytest.raises(MonitoringApiError) as exc:
        _validate_subscription_input(
            address="", chain="ethereum", trigger_type="any_movement",
            threshold_usd=None,
            webhook_url="https://example.com/hook", label=None,
            webhook_secret=None,
        )
    assert exc.value.field == "address"


def test_validate_rejects_unknown_trigger():
    from recupero.api.monitoring_api import (
        MonitoringApiError, _validate_subscription_input,
    )
    with pytest.raises(MonitoringApiError) as exc:
        _validate_subscription_input(
            address="0x" + "a" * 40, chain="ethereum",
            trigger_type="invalid_trigger",
            threshold_usd=None,
            webhook_url="https://example.com/hook", label=None,
            webhook_secret=None,
        )
    assert exc.value.field == "trigger_type"


def test_validate_requires_threshold_for_movement_above_usd():
    from recupero.api.monitoring_api import (
        MonitoringApiError, _validate_subscription_input,
    )
    with pytest.raises(MonitoringApiError) as exc:
        _validate_subscription_input(
            address="0x" + "a" * 40, chain="ethereum",
            trigger_type="movement_above_usd",
            threshold_usd=None,
            webhook_url="https://example.com/hook", label=None,
            webhook_secret=None,
        )
    assert exc.value.field == "threshold_usd"


def test_validate_rejects_negative_threshold():
    from recupero.api.monitoring_api import (
        MonitoringApiError, _validate_subscription_input,
    )
    with pytest.raises(MonitoringApiError) as exc:
        _validate_subscription_input(
            address="0x" + "a" * 40, chain="ethereum",
            trigger_type="balance_drop",
            threshold_usd=Decimal("-100"),
            webhook_url="https://example.com/hook", label=None,
            webhook_secret=None,
        )
    assert exc.value.field == "threshold_usd"


def test_validate_rejects_non_http_webhook_url():
    from recupero.api.monitoring_api import (
        MonitoringApiError, _validate_subscription_input,
    )
    with pytest.raises(MonitoringApiError) as exc:
        _validate_subscription_input(
            address="0x" + "a" * 40, chain="ethereum",
            trigger_type="any_movement",
            threshold_usd=None,
            webhook_url="ftp://example.com/hook", label=None,
            webhook_secret=None,
        )
    assert exc.value.field == "webhook_url"


def test_validate_accepts_any_movement_without_threshold():
    """The threshold-less triggers must not require threshold_usd."""
    from recupero.api.monitoring_api import _validate_subscription_input
    # Should not raise.
    _validate_subscription_input(
        address="0x" + "a" * 40, chain="ethereum",
        trigger_type="any_movement",
        threshold_usd=None,
        webhook_url="https://example.com/hook", label="my label",
        webhook_secret="secret-xyz",
    )


# ─────────────────────────────────────────────────────────────────────────────
# create_subscription
# ─────────────────────────────────────────────────────────────────────────────


def _stub_db_with_row(row):
    cur = MagicMock()
    cur.fetchone.return_value = row
    cur.execute = MagicMock()
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
    conn = MagicMock()
    conn.cursor.return_value = cur
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)
    return conn, cur


SUB_ID = UUID("11111111-1111-1111-1111-111111111111")


def _fake_row(**overrides):
    base = {
        "id": str(SUB_ID),
        "address": "0x" + "a" * 40,
        "chain": "ethereum",
        "trigger_type": "any_movement",
        "threshold_usd": None,
        "webhook_url": "https://example.com/hook",
        "label": "(api)",
        "status": "active",
        "created_at": "2026-05-20T12:00:00",
        "last_alerted_at": None,
        "expires_at": None,
    }
    base.update(overrides)
    return base


def test_create_subscription_returns_record_on_success():
    from recupero.api.monitoring_api import create_subscription

    conn, cur = _stub_db_with_row(_fake_row())
    with patch("recupero._common.db_connect", return_value=conn):
        rec = create_subscription(
            api_key_name="exchange-acme",
            address="0x" + "a" * 40, chain="ethereum",
            trigger_type="any_movement", threshold_usd=None,
            webhook_url="https://example.com/hook",
            label=None, webhook_secret=None,
            dsn="postgres://fake",
        )
    assert rec.id == SUB_ID
    assert rec.address == "0x" + "a" * 40
    # The INSERT params dict should have used the API-prefixed created_by.
    args, kwargs = cur.execute.call_args
    params = args[1]
    assert params["created_by"] == "api:exchange-acme"


def test_create_subscription_db_error_raises_runtime_error_not_psycopg():
    """DB layer crash → RuntimeError with generic message (no DSN
    leak)."""
    from recupero.api.monitoring_api import create_subscription

    def _boom(*a, **kw):
        raise Exception("FATAL: password authentication failed for user 'postgres' at host 'db.x.supabase.co'")

    with patch("recupero._common.db_connect", side_effect=_boom):
        with pytest.raises(RuntimeError) as exc:
            create_subscription(
                api_key_name="x",
                address="0x" + "a" * 40, chain="ethereum",
                trigger_type="any_movement", threshold_usd=None,
                webhook_url="https://example.com/hook",
                label=None, webhook_secret=None,
                dsn="postgres://fake",
            )
    # Generic message; no DSN / password leak.
    assert "subscription create failed" in str(exc.value)
    assert "password" not in str(exc.value)
    assert "supabase" not in str(exc.value)


# ─────────────────────────────────────────────────────────────────────────────
# list_subscriptions / get_subscription — multi-tenant isolation
# ─────────────────────────────────────────────────────────────────────────────


def test_list_subscriptions_filters_by_api_key_created_by():
    """List MUST send the api-key-derived created_by as the SQL
    filter. We assert by inspecting the SQL param."""
    from recupero.api.monitoring_api import list_subscriptions

    conn, cur = _stub_db_with_row(None)
    cur.fetchall.return_value = []
    with patch("recupero._common.db_connect", return_value=conn):
        list_subscriptions(
            api_key_name="partner-acme",
            dsn="postgres://fake",
            limit=50,
        )
    args, kwargs = cur.execute.call_args
    sql_params = args[1]
    # First positional param = created_by; second = limit.
    assert sql_params[0] == "api:partner-acme"
    assert sql_params[1] == 50


def test_get_subscription_foreign_key_returns_none_not_404():
    """A partner probing for another partner's subscription must see
    None — the API layer turns that into 404. The function MUST NOT
    raise."""
    from recupero.api.monitoring_api import get_subscription

    conn, cur = _stub_db_with_row(None)  # row not found for this api_key.
    with patch("recupero._common.db_connect", return_value=conn):
        result = get_subscription(
            api_key_name="partner-b",
            subscription_id=SUB_ID,
            dsn="postgres://fake",
        )
    assert result is None
    # Verify the WHERE clause was scoped to this api_key.
    args, kwargs = cur.execute.call_args
    sql_params = args[1]
    assert sql_params[0] == str(SUB_ID)
    assert sql_params[1] == "api:partner-b"


def test_soft_delete_returns_false_when_not_owned():
    """Soft-delete on a foreign key returns False without raising
    or revealing existence."""
    from recupero.api.monitoring_api import soft_delete_subscription

    conn, cur = _stub_db_with_row(None)  # UPDATE matched 0 rows.
    with patch("recupero._common.db_connect", return_value=conn):
        ok = soft_delete_subscription(
            api_key_name="partner-b",
            subscription_id=SUB_ID,
            dsn="postgres://fake",
        )
    assert ok is False


def test_limit_clamped_to_500_max():
    """Caller-supplied limit > 500 is clamped to 500 to bound
    response size."""
    from recupero.api.monitoring_api import list_subscriptions

    conn, cur = _stub_db_with_row(None)
    cur.fetchall.return_value = []
    with patch("recupero._common.db_connect", return_value=conn):
        list_subscriptions(
            api_key_name="x", dsn="postgres://fake", limit=99999,
        )
    args, kwargs = cur.execute.call_args
    sql_params = args[1]
    assert sql_params[1] == 500


def test_subscription_record_to_json_safe_decimal_to_str():
    """Decimal threshold serializes to string (JSON-safe, no float
    rounding)."""
    from recupero.api.monitoring_api import SubscriptionRecord
    rec = SubscriptionRecord(
        id=SUB_ID,
        address="0x" + "a" * 40, chain="ethereum",
        trigger_type="movement_above_usd",
        threshold_usd=Decimal("1500.50"),
        webhook_url="https://example.com/hook",
        label="my label", status="active",
        created_at="2026-05-20T12:00:00",
        last_alerted_at=None, expires_at=None,
    )
    d = rec.to_json_safe()
    assert d["threshold_usd"] == "1500.50"
    assert d["id"] == str(SUB_ID)


# ─────────────────────────────────────────────────────────────────────────────
# Bulk screen request validation
# ─────────────────────────────────────────────────────────────────────────────


def test_bulk_screen_request_caps_at_100():
    """The Pydantic model enforces max 100 addresses per request."""
    from recupero.api.app import BulkScreenRequest
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        BulkScreenRequest(addresses=["0x" + "a" * 40] * 101)


def test_bulk_screen_request_requires_at_least_one():
    from recupero.api.app import BulkScreenRequest
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        BulkScreenRequest(addresses=[])
