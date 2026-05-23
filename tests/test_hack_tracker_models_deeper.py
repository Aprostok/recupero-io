"""Deeper adversarial-input tests for ``recupero.hack_tracker.models``.

Wave 5 added basic validators (NaN/Inf gates, NUL/bidi scrub, EVM
canonicalization, http(s) scheme guard). This file deepens the audit
along eight axes the threat model previously left soft:

  1. ``severity`` accepts only the declared enum values
  2. ``source_url`` host is allowlisted (twitter/x/gov press/rekt) —
     not just any http(s) URL
  3. Every surviving entry of ``addresses`` is canonical AFTER
     lowercasing (the validator must not preserve upper-case)
  4. ``tx_hashes`` accepts the 64-hex form with or without 0x prefix
  5. ``estimated_loss_usd`` rejects implausibly huge values (> $1e15)
  6. ``observed_at`` is always tz-aware after validation (naive
     datetimes get coerced to UTC rather than rejected, to keep the
     existing ranker contract intact)
  7. ``title`` / ``summary`` length caps + HTML/script-tag scrub
  8. JSON round-trip via ``model_dump_json`` / ``model_validate_json``
     equals the original model

All tests construct ``HackEvent`` directly and are RED before the
matching validator extensions in ``src/recupero/hack_tracker/models.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError


# ---- 1. severity enum gate ---- #


def test_severity_rejects_non_enum_string() -> None:
    """A free-form string like ``severity='nuke'`` must not be coerced
    or accepted — only the five declared bucket names are legal."""
    from recupero.hack_tracker.models import HackEvent, HackEventSource

    with pytest.raises((ValueError, ValidationError)):
        HackEvent(
            content_hash="a" * 64,
            source=HackEventSource.x_peckshield,
            source_url="https://x.com/x/status/1",
            observed_at=datetime.now(UTC),
            title="t", summary="s",
            severity="nuke",  # not a member of HackEventSeverity
        )


# ---- 2. source_url host allowlist ---- #


def test_source_url_rejects_arbitrary_host() -> None:
    """``https://evil.example.com/...`` must be rejected even though
    the scheme is https. The allowlist covers twitter/x/gov press
    domains + rekt.news only."""
    from recupero.hack_tracker.models import HackEvent, HackEventSource

    with pytest.raises((ValueError, ValidationError)):
        HackEvent(
            content_hash="a" * 64,
            source=HackEventSource.x_peckshield,
            source_url="https://evil.example.com/malware",
            observed_at=datetime.now(UTC),
            title="t", summary="s",
        )


def test_source_url_accepts_allowlisted_hosts() -> None:
    """All canonical host forms used by the offline fixtures + the
    real x_feed / government_feeds adapters must validate."""
    from recupero.hack_tracker.models import HackEvent, HackEventSource

    allow_hosts = [
        "https://x.com/PeckShieldAlert/status/1",
        "https://twitter.com/SlowMist_Team/status/2",
        "https://ofac.treasury.gov/recent-actions",
        "https://www.ic3.gov/PSA/PSARss",
        "https://www.cisa.gov/news.xml",
        "https://rekt.news/article/x",
    ]
    for url in allow_hosts:
        ev = HackEvent(
            content_hash="a" * 64,
            source=HackEventSource.x_peckshield,
            source_url=url,
            observed_at=datetime.now(UTC),
            title="t", summary="s",
        )
        assert ev.source_url == url


# ---- 3. addresses always lowercased ---- #


def test_addresses_lowercased_even_when_input_uppercase() -> None:
    """Checksum-case (mixed case) EVM addresses are valid input — the
    validator must store them lowercased so downstream eq-checks are
    canonical."""
    from recupero.hack_tracker.models import HackEvent, HackEventSource

    mixed = "0xAaBbCcDdEeFf" + "0" * 28  # 0x + 40 hex = 42 chars
    assert len(mixed) == 42
    ev = HackEvent(
        content_hash="a" * 64,
        source=HackEventSource.x_peckshield,
        source_url="https://x.com/x/status/1",
        observed_at=datetime.now(UTC),
        title="t", summary="s",
        addresses=[mixed],
    )
    assert ev.addresses == [mixed.lower()]


# ---- 4. tx_hashes accepts 0x-prefixed and bare 64-hex ---- #


def test_tx_hashes_accepts_bare_64hex_without_prefix() -> None:
    """Many fixture / regex extractors emit the 64-hex digest without
    the 0x prefix. The validator should accept both forms and store
    them canonically (with the 0x prefix)."""
    from recupero.hack_tracker.models import HackEvent, HackEventSource

    bare = "b" * 64
    ev = HackEvent(
        content_hash="a" * 64,
        source=HackEventSource.x_peckshield,
        source_url="https://x.com/x/status/1",
        observed_at=datetime.now(UTC),
        title="t", summary="s",
        tx_hashes=[bare],
    )
    assert ev.tx_hashes == ["0x" + bare]


# ---- 5. estimated_loss_usd implausibility cap ---- #


def test_estimated_loss_usd_rejects_absurd_upper_bound() -> None:
    """A loss of $1e16 ($10 quadrillion) exceeds global crypto market
    cap by orders of magnitude. Must be rejected as an obvious feed
    parse-error / hostile injection."""
    from recupero.hack_tracker.models import HackEvent, HackEventSource

    with pytest.raises((ValueError, ValidationError)):
        HackEvent(
            content_hash="a" * 64,
            source=HackEventSource.x_peckshield,
            source_url="https://x.com/x/status/1",
            observed_at=datetime.now(UTC),
            title="t", summary="s",
            estimated_loss_usd=Decimal("1e16"),
        )


# ---- 6. observed_at always tz-aware ---- #


def test_observed_at_naive_input_coerced_to_utc() -> None:
    """Existing fixtures sometimes hand us a naive datetime (utcnow()
    pre-tz-fix). The validator must coerce to UTC rather than reject,
    so the existing ranker contract (which expects HackEvent
    construction to succeed for naive inputs) keeps working."""
    from recupero.hack_tracker.models import HackEvent, HackEventSource

    naive = datetime(2026, 5, 22, 12, 0, 0)
    assert naive.tzinfo is None
    ev = HackEvent(
        content_hash="a" * 64,
        source=HackEventSource.x_peckshield,
        source_url="https://x.com/x/status/1",
        observed_at=naive,
        title="t", summary="s",
    )
    assert ev.observed_at.tzinfo is not None


# ---- 7a. title length cap ---- #


def test_title_rejects_overlong_input() -> None:
    """A 5_000-char title would blow the digest layout + signal a
    likely feed parse-error. Cap is 200."""
    from recupero.hack_tracker.models import HackEvent, HackEventSource

    with pytest.raises((ValueError, ValidationError)):
        HackEvent(
            content_hash="a" * 64,
            source=HackEventSource.x_peckshield,
            source_url="https://x.com/x/status/1",
            observed_at=datetime.now(UTC),
            title="x" * 5_000,
            summary="s",
        )


# ---- 7b. HTML / script-tag scrub ---- #


def test_title_strips_script_tags() -> None:
    """If an attacker smuggles ``<script>`` into a tweet body, the
    model must scrub it — operator digests render HTML."""
    from recupero.hack_tracker.models import HackEvent, HackEventSource

    hostile = "Bridge X lost <script>alert(1)</script> $50M"
    ev = HackEvent(
        content_hash="a" * 64,
        source=HackEventSource.x_peckshield,
        source_url="https://x.com/x/status/1",
        observed_at=datetime.now(UTC),
        title=hostile,
        summary="s",
    )
    assert "<script>" not in ev.title.lower()
    assert "</script>" not in ev.title.lower()


# ---- 8. JSON round-trip ---- #


def test_round_trip_json_serialization_equals_model() -> None:
    """``HackEvent.model_validate_json(ev.model_dump_json())`` must
    produce a model equal to the original. Any validator that mutates
    values asymmetrically (e.g., canonicalizes on dump but not load)
    would break this and corrupt persisted state on re-load."""
    from recupero.hack_tracker.models import (
        HackEvent,
        HackEventSeverity,
        HackEventSource,
    )

    ev1 = HackEvent(
        content_hash="a" * 64,
        source=HackEventSource.x_peckshield,
        source_url="https://x.com/PeckShieldAlert/status/1",
        observed_at=datetime(2026, 5, 22, 12, 0, 0, tzinfo=UTC),
        title="Bridge X hack",
        summary="A bridge was drained for $5M",
        severity=HackEventSeverity.high,
        chains_mentioned=["ethereum", "arbitrum"],
        addresses=["0x" + "a" * 40],
        tx_hashes=["0x" + "b" * 64],
        estimated_loss_usd=Decimal("5000000"),
        attributed_actor="Lazarus",
        has_identifiable_victim=True,
        victim_hint="DEX bridge",
        tags=["bridge_exploit", "dprk"],
    )
    blob = ev1.model_dump_json()
    ev2 = HackEvent.model_validate_json(blob)
    assert ev1 == ev2
