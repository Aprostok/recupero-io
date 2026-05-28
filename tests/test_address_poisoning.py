"""Tests for address_poisoning (v0.32.1+ Cap-B).

Covers:
  * Positive: classic prefix+suffix mimic with dust amount + new sender.
  * Negative: high-similarity but high-amount -> not poisoning.
  * Negative: high-amount but low-similarity -> not poisoning.
  * Negative: returning prior sender (not new) -> not poisoning.
  * Edge: empty victim address.
  * Edge: empty transfer list.
  * Dict transfer compatibility.
  * Visual similarity score boundaries.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from recupero.trace.address_poisoning import (
    detect_poisoning_attempts,
    visual_similarity,
)


# Helper — produce a dict-shaped transfer (we test both shapes).
def mk(
    frm: str, to: str, *, tx: str = "0xtx", usd: str = "0", **extra
) -> dict:
    return {
        "from_address": frm,
        "to_address": to,
        "tx_hash": tx,
        "value_usd": Decimal(usd),
        **extra,
    }


VICTIM = "0xABCDEF1234567890abcdef1234567890ABCDEF12"
EXCHANGE = "0x1111222233334444555566667777888899990000"
# Poisoner: same first-4 (1111) and same last-4 (0000) as EXCHANGE, different middle.
POISONER = "0x1111deadbeefcafebabe1337feedfaceabcd0000"


# -----------------------------------------------------------------------------
# Visual similarity
# -----------------------------------------------------------------------------


def test_visual_similarity_identical_returns_1():
    """Same address -> 1.0 (edge case)."""
    assert visual_similarity(EXCHANGE, EXCHANGE) == 1.0


def test_visual_similarity_prefix_and_suffix_match():
    """Prefix-4 + suffix-4 match -> at least 0.8."""
    s = visual_similarity(POISONER, EXCHANGE)
    assert s >= 0.80


def test_visual_similarity_only_prefix_match():
    """Prefix only -> 0.40 max."""
    a = "0x11119999999999999999999999999999deadbeef"
    b = "0x1111000000000000000000000000000012345678"
    s = visual_similarity(a, b)
    assert s < 0.60  # only prefix-4 match, suffix differs


def test_visual_similarity_no_overlap_returns_zero_ish():
    """Random addresses -> low score."""
    a = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    b = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    assert visual_similarity(a, b) < 0.30


def test_visual_similarity_non_evm_returns_zero():
    """Bitcoin-shape input -> 0 (we don't poison-detect BTC)."""
    assert visual_similarity("bc1qxyz...", "bc1qabc...") == 0.0


# -----------------------------------------------------------------------------
# Positive detection
# -----------------------------------------------------------------------------


def test_classic_poisoning_pattern_detected():
    """Victim pays exchange -> attacker sends dust mimicking exchange."""
    transfers = [
        # Step 1: victim pays the legitimate exchange address.
        mk(VICTIM, EXCHANGE, tx="0x1", usd="1000.00"),
        # Step 2: attacker sends $0 from a visually-similar address.
        mk(POISONER, VICTIM, tx="0x2", usd="0.00"),
    ]
    events = detect_poisoning_attempts(transfers, VICTIM)
    assert len(events) == 1
    assert events[0].poisoner_address.lower().endswith("0000")
    assert events[0].impersonated_address.lower().endswith("0000")
    assert events[0].similarity >= 0.95


def test_poisoning_with_dust_amount_under_one_usd():
    """A $0.50 transfer still triggers (it's under the $1 threshold)."""
    transfers = [
        mk(VICTIM, EXCHANGE, tx="0x1", usd="500.00"),
        mk(POISONER, VICTIM, tx="0x2", usd="0.50"),
    ]
    events = detect_poisoning_attempts(transfers, VICTIM)
    assert len(events) == 1


def test_basis_string_includes_prefix_and_suffix():
    """The basis string surfaces both matched anchors."""
    transfers = [
        mk(VICTIM, EXCHANGE, tx="0x1", usd="100.00"),
        mk(POISONER, VICTIM, tx="0x2", usd="0.00"),
    ]
    events = detect_poisoning_attempts(transfers, VICTIM)
    assert "prefix-4" in events[0].impersonation_basis
    assert "suffix-4" in events[0].impersonation_basis


# -----------------------------------------------------------------------------
# Negative cases
# -----------------------------------------------------------------------------


def test_high_amount_does_not_trigger():
    """A $100 transfer from a similar address is NOT poisoning."""
    transfers = [
        mk(VICTIM, EXCHANGE, tx="0x1", usd="1000.00"),
        mk(POISONER, VICTIM, tx="0x2", usd="100.00"),  # too large
    ]
    events = detect_poisoning_attempts(transfers, VICTIM)
    assert events == []


def test_dissimilar_sender_does_not_trigger():
    """A truly random sender sending dust is not poisoning."""
    random_addr = "0xfeed0000000000000000000000000000beefcafe"
    transfers = [
        mk(VICTIM, EXCHANGE, tx="0x1", usd="1000.00"),
        mk(random_addr, VICTIM, tx="0x2", usd="0.10"),
    ]
    events = detect_poisoning_attempts(transfers, VICTIM)
    assert events == []


def test_returning_sender_does_not_trigger():
    """If the sender appeared earlier in the case, they aren't 'new'."""
    transfers = [
        # POISONER appears in an earlier outgoing flow first
        # (they're some prior counterparty, not a new attacker).
        mk(VICTIM, POISONER, tx="0x0", usd="50.00"),
        mk(VICTIM, EXCHANGE, tx="0x1", usd="1000.00"),
        mk(POISONER, VICTIM, tx="0x2", usd="0.00"),
    ]
    events = detect_poisoning_attempts(transfers, VICTIM)
    assert events == []


def test_no_prior_outgoing_no_target_to_impersonate():
    """If the victim has no outgoing history, nothing to impersonate."""
    transfers = [
        mk(POISONER, VICTIM, tx="0x1", usd="0.00"),
    ]
    events = detect_poisoning_attempts(transfers, VICTIM)
    assert events == []


def test_empty_victim_address_returns_empty():
    events = detect_poisoning_attempts([], "")
    assert events == []


def test_empty_transfer_list_returns_empty():
    events = detect_poisoning_attempts([], VICTIM)
    assert events == []


def test_multiple_poisoning_attempts_all_detected():
    """If the attacker tries twice from different mimics, both fire."""
    poisoner2 = "0x1111cafef00ddeadbeef1337abadbabe11110000"
    transfers = [
        mk(VICTIM, EXCHANGE, tx="0x1", usd="1000.00"),
        mk(POISONER, VICTIM, tx="0x2", usd="0.00"),
        mk(poisoner2, VICTIM, tx="0x3", usd="0.001"),
    ]
    events = detect_poisoning_attempts(transfers, VICTIM)
    assert len(events) == 2
