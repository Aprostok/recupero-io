"""Tests for multi-event theft detection.

The old ``_find_theft_transfer`` returned ONE transfer (the biggest
USD). For cases where a wallet was drained across multiple
transactions (phishing approvals + piece-meal draining over hours,
or slow draining to avoid exchange monitoring), this missed the
full story — the letter said "$X stolen on day Y" when the
reality was "$X stolen across N transactions on days Y through Y+2".

``_find_theft_events`` (new) returns the full cluster within a
configurable time window (default 7 days). Tests cover the
clustering logic, time-window boundary, fallback when no
outbound-from-victim transfers exist, and the backward-compat
``_find_theft_transfer`` wrapper.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from recupero.models import Case, Chain, Counterparty, TokenRef, Transfer
from recupero.reports.brief import (
    _find_theft_events,
    _find_theft_transfer,
)


def _xfer(
    *,
    tx_hash: str,
    from_addr: str,
    to_addr: str,
    amount: Decimal,
    usd: Decimal | None,
    block_time: datetime,
    block_number: int = 12345,
) -> Transfer:
    """Build one Transfer with sane defaults."""
    return Transfer(
        transfer_id=f"ethereum:{tx_hash}:0",
        chain=Chain.ethereum,
        tx_hash=tx_hash,
        block_number=block_number,
        block_time=block_time,
        from_address=from_addr,
        to_address=to_addr,
        counterparty=Counterparty(
            address=to_addr, label=None, is_contract=False,
        ),
        token=TokenRef(
            chain=Chain.ethereum, contract=None,
            symbol="ETH", decimals=18, coingecko_id="ethereum",
        ),
        amount_raw=str(int(amount * (10 ** 18))),
        amount_decimal=amount,
        usd_value_at_tx=usd,
        hop_depth=0,
        fetched_at=block_time + timedelta(minutes=1),
        explorer_url=f"https://etherscan.io/tx/{tx_hash}",
    )


def _case(transfers: list[Transfer], seed: str = "0x" + "a" * 40) -> Case:
    return Case(
        case_id="multi-event-test",
        seed_address=seed,
        chain=Chain.ethereum,
        incident_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        transfers=transfers,
        trace_started_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        software_version="test",
    )


# ---- Single-event cases (backward compat) ---- #


def test_single_event_returned_as_primary_only() -> None:
    """When there's only one transfer from the victim, the result
    is a single-item list."""
    victim = "0x" + "a" * 40
    perp = "0x" + "b" * 40
    transfers = [_xfer(
        tx_hash="0x" + "1" * 64,
        from_addr=victim, to_addr=perp,
        amount=Decimal("10"), usd=Decimal("30000"),
        block_time=datetime(2026, 1, 5, tzinfo=timezone.utc),
    )]
    events = _find_theft_events(_case(transfers, seed=victim))
    assert len(events) == 1
    assert events[0].tx_hash == "0x" + "1" * 64


def test_find_theft_transfer_backward_compat() -> None:
    """The legacy ``_find_theft_transfer`` wrapper still returns
    the primary (highest-USD) event."""
    victim = "0x" + "a" * 40
    perp = "0x" + "b" * 40
    transfers = [
        _xfer(tx_hash="0x" + "1" * 64, from_addr=victim, to_addr=perp,
              amount=Decimal("1"), usd=Decimal("3000"),
              block_time=datetime(2026, 1, 5, tzinfo=timezone.utc)),
        _xfer(tx_hash="0x" + "2" * 64, from_addr=victim, to_addr=perp,
              amount=Decimal("10"), usd=Decimal("30000"),
              block_time=datetime(2026, 1, 6, tzinfo=timezone.utc)),
    ]
    primary = _find_theft_transfer(_case(transfers, seed=victim))
    assert primary is not None
    # The $30k event is the primary
    assert primary.tx_hash == "0x" + "2" * 64


# ---- Multi-event clustering ---- #


def test_multi_event_within_window_clustered() -> None:
    """Three drain events within a 7-day window all return."""
    victim = "0x" + "a" * 40
    perp = "0x" + "b" * 40
    base_time = datetime(2026, 1, 5, tzinfo=timezone.utc)
    transfers = [
        # Day 1: $10k
        _xfer(tx_hash="0x" + "1" * 64, from_addr=victim, to_addr=perp,
              amount=Decimal("3"), usd=Decimal("10000"),
              block_time=base_time),
        # Day 2: $50k (the primary)
        _xfer(tx_hash="0x" + "2" * 64, from_addr=victim, to_addr=perp,
              amount=Decimal("16"), usd=Decimal("50000"),
              block_time=base_time + timedelta(days=1)),
        # Day 4: $5k
        _xfer(tx_hash="0x" + "3" * 64, from_addr=victim, to_addr=perp,
              amount=Decimal("1.6"), usd=Decimal("5000"),
              block_time=base_time + timedelta(days=3)),
    ]
    events = _find_theft_events(_case(transfers, seed=victim))
    assert len(events) == 3
    # Primary is the $50k event, first in returned list
    assert events[0].usd_value_at_tx == Decimal("50000")


def test_event_outside_window_excluded() -> None:
    """A transfer 30 days before the primary is OUTSIDE the
    7-day window and excluded from the cluster."""
    victim = "0x" + "a" * 40
    perp = "0x" + "b" * 40
    base_time = datetime(2026, 2, 1, tzinfo=timezone.utc)
    transfers = [
        # 30 days before — OUTSIDE the 7-day default window
        _xfer(tx_hash="0x" + "1" * 64, from_addr=victim, to_addr=perp,
              amount=Decimal("100"), usd=Decimal("300000"),
              block_time=base_time - timedelta(days=30)),
        # Primary event
        _xfer(tx_hash="0x" + "2" * 64, from_addr=victim, to_addr=perp,
              amount=Decimal("16"), usd=Decimal("50000"),
              block_time=base_time),
    ]
    # Note: the $300k transfer is OLDER but LARGER — but it's outside
    # the window. Algorithm picks the largest first, but the cluster
    # window centers on THAT event. So with $300k as primary, the
    # $50k is also outside its window. Let's verify:
    events = _find_theft_events(_case(transfers, seed=victim))
    # $300k is primary (largest), the cluster excludes the $50k
    # because it's 30 days from the $300k primary.
    assert len(events) == 1
    assert events[0].usd_value_at_tx == Decimal("300000")


def test_custom_window_includes_more_events() -> None:
    """A 30-day window catches the older event."""
    victim = "0x" + "a" * 40
    perp = "0x" + "b" * 40
    base_time = datetime(2026, 2, 1, tzinfo=timezone.utc)
    transfers = [
        _xfer(tx_hash="0x" + "1" * 64, from_addr=victim, to_addr=perp,
              amount=Decimal("100"), usd=Decimal("300000"),
              block_time=base_time - timedelta(days=30)),
        _xfer(tx_hash="0x" + "2" * 64, from_addr=victim, to_addr=perp,
              amount=Decimal("16"), usd=Decimal("50000"),
              block_time=base_time),
    ]
    events = _find_theft_events(
        _case(transfers, seed=victim),
        time_window_hours=24 * 35,  # 35 days
    )
    assert len(events) == 2


# ---- Defensive cases ---- #


def test_empty_transfers_returns_empty_list() -> None:
    """No transfers in the case → empty list. Backward-compat
    wrapper returns None."""
    events = _find_theft_events(_case([]))
    assert events == []
    primary = _find_theft_transfer(_case([]))
    assert primary is None


def test_no_outbound_from_victim_falls_back_to_all() -> None:
    """When no transfers have from_address == seed_address (could
    be a chain-normalization quirk), fall back to using all
    transfers. This preserves the legacy behavior — never returns
    empty just because the from_address didn't normalize."""
    other_a = "0x" + "c" * 40
    other_b = "0x" + "d" * 40
    transfers = [
        _xfer(tx_hash="0x" + "1" * 64, from_addr=other_a, to_addr=other_b,
              amount=Decimal("10"), usd=Decimal("30000"),
              block_time=datetime(2026, 1, 5, tzinfo=timezone.utc)),
    ]
    # seed_address doesn't appear as from_address in any transfer
    events = _find_theft_events(_case(transfers, seed="0x" + "a" * 40))
    # Fallback picks the transfer anyway (legacy behavior)
    assert len(events) == 1


def test_no_usd_pricing_falls_back_to_amount() -> None:
    """When no transfer has usd_value_at_tx, the primary is the
    largest amount_decimal (less reliable but better than None)."""
    victim = "0x" + "a" * 40
    perp = "0x" + "b" * 40
    transfers = [
        _xfer(tx_hash="0x" + "1" * 64, from_addr=victim, to_addr=perp,
              amount=Decimal("5"), usd=None,
              block_time=datetime(2026, 1, 5, tzinfo=timezone.utc)),
        _xfer(tx_hash="0x" + "2" * 64, from_addr=victim, to_addr=perp,
              amount=Decimal("20"), usd=None,
              block_time=datetime(2026, 1, 6, tzinfo=timezone.utc)),
    ]
    events = _find_theft_events(_case(transfers, seed=victim))
    assert len(events) == 2
    assert events[0].amount_decimal == Decimal("20")


def test_inbound_transfers_excluded() -> None:
    """Transfers TO the victim (not FROM) aren't theft events.
    Defensive — a wallet that received funds after being drained
    shouldn't have those incoming transfers counted."""
    victim = "0x" + "a" * 40
    perp = "0x" + "b" * 40
    other = "0x" + "c" * 40
    transfers = [
        # Outbound (theft)
        _xfer(tx_hash="0x" + "1" * 64, from_addr=victim, to_addr=perp,
              amount=Decimal("10"), usd=Decimal("30000"),
              block_time=datetime(2026, 1, 5, tzinfo=timezone.utc)),
        # Inbound — someone sent victim funds; not a theft
        _xfer(tx_hash="0x" + "2" * 64, from_addr=other, to_addr=victim,
              amount=Decimal("100"), usd=Decimal("300000"),
              block_time=datetime(2026, 1, 5, 1, tzinfo=timezone.utc)),
    ]
    events = _find_theft_events(_case(transfers, seed=victim))
    # Only the outbound counts
    assert len(events) == 1
    assert events[0].tx_hash == "0x" + "1" * 64


# ---- Realistic scenarios ---- #


def test_phishing_drain_5_transactions_3_days() -> None:
    """Realistic phishing-drain scenario: 5 outbound transactions
    over 3 days (perpetrator drains piece-meal to avoid triggering
    monitoring thresholds). All cluster as theft events."""
    victim = "0x" + "a" * 40
    perp = "0x" + "b" * 40
    base_time = datetime(2026, 3, 15, tzinfo=timezone.utc)
    transfers = []
    for i in range(5):
        transfers.append(_xfer(
            tx_hash=f"0x{i:064x}",
            from_addr=victim, to_addr=perp,
            amount=Decimal(str(2 + i)),
            usd=Decimal(str(6000 + i * 3000)),
            block_time=base_time + timedelta(hours=i * 16),
        ))
    events = _find_theft_events(_case(transfers, seed=victim))
    assert len(events) == 5
    # Primary is the largest by USD
    largest_usd = max(t.usd_value_at_tx for t in transfers)
    assert events[0].usd_value_at_tx == largest_usd


def test_slow_drain_over_12_days_excludes_oldest() -> None:
    """Slow drain over 12 days — with the 7-day default window,
    the cluster around the primary event excludes the oldest
    transfers (more than 7 days from primary)."""
    victim = "0x" + "a" * 40
    perp = "0x" + "b" * 40
    base_time = datetime(2026, 3, 1, tzinfo=timezone.utc)
    transfers = []
    # Day 0: small drain (will be far from primary)
    transfers.append(_xfer(
        tx_hash="0x" + "1" * 64, from_addr=victim, to_addr=perp,
        amount=Decimal("1"), usd=Decimal("3000"),
        block_time=base_time,
    ))
    # Day 12: BIG drain (primary)
    transfers.append(_xfer(
        tx_hash="0x" + "2" * 64, from_addr=victim, to_addr=perp,
        amount=Decimal("100"), usd=Decimal("300000"),
        block_time=base_time + timedelta(days=12),
    ))
    # Day 14: small drain (within 7 days of primary)
    transfers.append(_xfer(
        tx_hash="0x" + "3" * 64, from_addr=victim, to_addr=perp,
        amount=Decimal("1"), usd=Decimal("3000"),
        block_time=base_time + timedelta(days=14),
    ))
    events = _find_theft_events(_case(transfers, seed=victim))
    # Day 0 is 12 days before primary → outside window
    # Day 14 is 2 days after primary → inside window
    assert len(events) == 2
    tx_hashes = {e.tx_hash for e in events}
    assert "0x" + "2" * 64 in tx_hashes  # primary
    assert "0x" + "3" * 64 in tx_hashes  # within window
    assert "0x" + "1" * 64 not in tx_hashes  # outside window
