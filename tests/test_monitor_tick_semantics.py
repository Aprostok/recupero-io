"""W-Z semantics audit for ``worker/monitor_tick.py``.

These tests audit the cron-driven subscription poller for six
real-world concerns that the v0.13.2 / v0.14.6 / v0.17.10 / v0.18.4
/ v0.21.0 evolutions left under-covered. The dispatcher (wave-4 +
Z19), subscriber (W8-01), and monitoring_api (Z12) hardenings are
out of scope here — this file targets monitor_tick's OWN code path.

Bugs caught (pre-fix):

  M-1: ``_row_to_subscription`` converts ``threshold_usd`` via
       ``Decimal(str(threshold))`` with no finite-ness check. A
       Postgres ``numeric`` column accepts NaN / Infinity (Z5-2
       called this out for the freeze-brief path). If a poisoned
       row reaches the dispatcher's TRIGGER_USD compare,
       ``activity.amount_usd >= NaN`` raises ``InvalidOperation``
       and the whole sub eval is logged as a generic failure —
       silently muting the alert.

  M-2: ``_fetch_evm_activities`` converts the adapter's
       ``usd_value_at_tx`` via ``Decimal(str(amount_usd))`` with
       no finite-ness check. A buggy / hostile chain adapter
       returning ``float('nan')`` or ``float('inf')`` produces an
       ObservedActivity whose ``amount_usd`` is NaN/Inf. That value
       then flows into the alert template, which renders
       ``"NaN"`` / ``"Infinity"`` to the webhook recipient and
       breaks any downstream numeric aggregation.

Non-bugs that we lock in as semantics:

  M-3: Mixed-case watched address vs lowercased chain return —
       ``canonical_address_key`` correctly normalizes both sides;
       outflow detection works regardless of case.

  M-4: ``update_sql`` post-dispatch carries ``AND status = 'active'``
       so a delete-mid-poll race does NOT rewrite the cursor of a
       just-deleted subscription.

  M-5: claim_sql filters ``status = 'active'`` so a disabled sub
       is never even handed to the activity fetcher.

  M-6: Two subscriptions for the same address are independent rows;
       both fire (read-side has no implicit dedupe — that's the
       subscriber's responsibility).
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from recupero.monitoring.poller import ObservedActivity
from recupero.worker.monitor_tick import (
    _fetch_evm_activities,
    _row_to_subscription,
    run_monitor_tick,
)


# ----------------------- helpers ----------------------- #


def _sub_row(
    *,
    sub_id=None,
    address="0xperp",
    chain="ethereum",
    trigger_type="movement_above_usd",
    threshold_usd=Decimal("1000"),
    last_observed_tx_hash="0xprev",
    status="active",
):
    return {
        "id": sub_id or uuid4(),
        "address": address,
        "chain": chain,
        "trigger_type": trigger_type,
        "threshold_usd": threshold_usd,
        "webhook_url": "https://hook.example/alert",
        "webhook_secret": None,
        "last_observed_tx_hash": last_observed_tx_hash,
        "last_polled_at": None,
        "alert_channels": ["webhook"],
        "alert_email": None,
        "case_id": None,
        "investigation_id": None,
        "status": status,
    }


# ----------------------- M-1: NaN/Inf threshold rejected on dispatch ----------------------- #


def test_m1_row_to_subscription_rejects_nan_threshold() -> None:
    """A DB row carrying threshold_usd = NaN must not surface a
    non-finite Decimal to the dispatcher path. Either rejected
    outright (None) or normalized — but never a NaN Decimal.
    """
    row = _sub_row(threshold_usd=Decimal("NaN"))
    sub = _row_to_subscription(row)
    assert sub.threshold_usd is None or sub.threshold_usd.is_finite(), (
        f"NaN threshold leaked through _row_to_subscription: "
        f"{sub.threshold_usd!r}. activity.amount_usd >= NaN raises "
        f"InvalidOperation and silently mutes the alert."
    )


def test_m1_row_to_subscription_rejects_infinity_threshold() -> None:
    row = _sub_row(threshold_usd=Decimal("Infinity"))
    sub = _row_to_subscription(row)
    assert sub.threshold_usd is None or sub.threshold_usd.is_finite(), (
        f"Infinity threshold leaked through _row_to_subscription: "
        f"{sub.threshold_usd!r}. Threshold compare becomes nonsense."
    )


def test_m1_row_to_subscription_accepts_finite_threshold_unchanged() -> None:
    """Defense doesn't regress the happy path."""
    row = _sub_row(threshold_usd=Decimal("50000.00"))
    sub = _row_to_subscription(row)
    assert sub.threshold_usd == Decimal("50000.00")


# ----------------------- M-2: Non-finite USD amount in adapter result ----------------------- #


def test_m2_fetch_evm_activities_rejects_non_finite_usd() -> None:
    """A chain adapter returning float('nan') for usd_value_at_tx
    must NOT produce an ObservedActivity with NaN amount_usd —
    that value flows into the alert template / webhook body and
    corrupts every downstream numeric aggregation.
    """
    # Use a valid 40-hex EVM address so canonical_address_key
    # actually lowercases it (mixed-case but valid hex).
    addr = "0xDeAdBeEf" + "00" * 16
    sub = _row_to_subscription(_sub_row(address=addr))

    fake_adapter = MagicMock()
    fake_adapter.fetch_erc20_outflows.return_value = [
        {
            "tx_hash": "0xnan",
            "from": sub.address.lower(),
            "to": "0xexch",
            "block_number": 100,
            "block_time": None,
            "usd_value_at_tx": float("nan"),
            "explorer_url": "https://etherscan.io/tx/0xnan",
        },
        {
            "tx_hash": "0xinf",
            "from": sub.address.lower(),
            "to": "0xexch",
            "block_number": 99,
            "block_time": None,
            "usd_value_at_tx": float("inf"),
            "explorer_url": "https://etherscan.io/tx/0xinf",
        },
    ]

    with patch(
        "recupero.worker.monitor_tick._get_cached_adapter",
        return_value=fake_adapter,
    ):
        out = _fetch_evm_activities(sub)

    assert len(out) == 2, "both outflows should still be emitted"
    for a in out:
        assert a.amount_usd is None or a.amount_usd.is_finite(), (
            f"non-finite amount_usd leaked from _fetch_evm_activities "
            f"for tx {a.tx_hash}: {a.amount_usd!r}"
        )


# ----------------------- M-3: Mixed-case outflow detection ----------------------- #


def test_m3_mixed_case_watched_address_matches_lowercased_chain_return() -> None:
    """Sub registered with EIP-55 checksum address (mixed case); the
    chain adapter returns the same address lowercased on the 'from'
    field. _fetch_evm_activities must still classify the tx as an
    outbound (i.e., NOT silently filter it away).
    """
    checksum = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"
    sub = _row_to_subscription(_sub_row(address=checksum))

    fake_adapter = MagicMock()
    fake_adapter.fetch_erc20_outflows.return_value = [
        {
            "tx_hash": "0xmix",
            "from": checksum.lower(),  # chain returns lowercased
            "to": "0xexch",
            "block_number": 1,
            "block_time": None,
            "usd_value_at_tx": Decimal("100"),
            "explorer_url": "https://etherscan.io/tx/0xmix",
        },
    ]
    with patch(
        "recupero.worker.monitor_tick._get_cached_adapter",
        return_value=fake_adapter,
    ):
        out = _fetch_evm_activities(sub)

    assert len(out) == 1, (
        "mixed-case watched address vs lowercased chain return — "
        "outflow was silently filtered out by case-mismatch"
    )
    assert out[0].direction == "outflow"


# ----------------------- M-4: Disabled subscription is excluded by claim SQL ----------------------- #


def test_m4_claim_sql_filters_only_active_subscriptions() -> None:
    """The claim_sql used by run_monitor_tick must filter on
    ``status = 'active'`` — otherwise disabling a sub via UPDATE
    status='paused' would NOT actually stop the cron from polling.
    """
    import inspect

    from recupero.worker import monitor_tick as mt

    src = inspect.getsource(mt.run_monitor_tick)
    # The claim SELECT and the post-dispatch UPDATE must both
    # carry the status filter.
    assert "status = 'active'" in src, (
        "monitor_tick.run_monitor_tick lost its status='active' filter — "
        "disabling/pausing a subscription would no longer stop the cron."
    )
    # Two occurrences: one in claim_sql, one in update_sql (M-5).
    assert src.count("status = 'active'") >= 2, (
        "the post-dispatch UPDATE must ALSO filter status='active' so "
        "a delete-mid-poll race doesn't rewrite a deleted sub's cursor."
    )


# ----------------------- M-5: Two duplicate subs are read independently ----------------------- #


def test_m5_duplicate_address_subscriptions_polled_independently() -> None:
    """Two subscription rows for the same address are independent
    rows. The read-side does NOT (and should not) silently dedupe —
    that's the subscriber's responsibility. Both rows get polled.
    """
    addr = "0xperp" + "0" * 35
    a = _sub_row(sub_id=uuid4(), address=addr)
    b = _sub_row(sub_id=uuid4(), address=addr)

    seen_sub_ids: list = []

    def _fake_fetch(sub, _chain):
        seen_sub_ids.append(sub.subscription_id)
        return []

    with patch("psycopg.connect") as mock_connect:
        conn = MagicMock()
        cur = MagicMock()
        cur.fetchall.return_value = [a, b]
        conn.__enter__.return_value = conn
        cur.__enter__.return_value = cur
        conn.cursor.return_value = cur
        mock_connect.return_value = conn

        result = run_monitor_tick(
            dsn="postgres://test",
            fetch_activities_fn=_fake_fetch,
        )

    assert result.subscriptions_polled == 2
    assert set(seen_sub_ids) == {a["id"], b["id"]}, (
        "duplicate-address subs must be polled independently — the "
        "read-side must not implicitly dedupe by address."
    )


# ----------------------- M-6: Non-finite USD never reaches the dispatch payload ----------------------- #


def test_m6_evm_fetch_threshold_compare_survives_poisoned_amount() -> None:
    """End-to-end-ish: an EVM adapter slipping ``float('nan')`` into
    usd_value_at_tx must NOT cause the trigger evaluator to raise
    ``InvalidOperation`` when it compares amount_usd against the
    movement_above_usd threshold (which would log a generic "sub eval
    failed" and silently mute the alert).
    """
    addr = "0xDeAdBeEf" + "00" * 16
    sub = _row_to_subscription(_sub_row(
        address=addr,
        trigger_type="movement_above_usd",
        threshold_usd=Decimal("1000"),
        last_observed_tx_hash="0xprev",
    ))

    fake_adapter = MagicMock()
    fake_adapter.fetch_erc20_outflows.return_value = [
        {
            "tx_hash": "0xnew",
            "from": addr.lower(),
            "to": "0xexch",
            "block_number": 2,
            "block_time": None,
            "usd_value_at_tx": float("nan"),
            "explorer_url": "https://etherscan.io/tx/0xnew",
        },
    ]

    with patch(
        "recupero.worker.monitor_tick._get_cached_adapter",
        return_value=fake_adapter,
    ):
        activities = _fetch_evm_activities(sub)

    assert len(activities) == 1
    a = activities[0]
    # If amount_usd had leaked through as NaN, the trigger compare
    # below would raise InvalidOperation.
    threshold = sub.threshold_usd or Decimal("0")
    if a.amount_usd is None:
        # Sanitized away — trigger compare is short-circuited; alert
        # would not fire (acceptable graceful-degrade).
        return
    # If we kept a Decimal at all, it must be finite so >= doesn't
    # blow up the evaluator.
    assert a.amount_usd.is_finite()
    _ = a.amount_usd >= threshold  # must not raise


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
