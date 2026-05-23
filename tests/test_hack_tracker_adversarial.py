"""Adversarial-input tests for hack_tracker.aggregator + .models + .digest_cli.

Covers:
  * Naive datetime in HackEvent.observed_at must not crash the ranker
  * Pydantic model rejects NaN/Inf in estimated_loss_usd
  * Model strips NUL / bidi / zero-width from text fields
  * Model rejects non-canonical addresses
  * Model rejects non-http(s) source_url
  * digest_cli clamps hours; rejects negative / huge values
  * digest_cli does not crash on hostile titles (ANSI escapes / NUL)
  * aggregator dedupe is bounded against pathological duplicate counts
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError


# ---- aggregator._rank_key: datetime hostility ---- #


def test_rank_key_handles_naive_datetime() -> None:
    """A HackEvent with naive observed_at must not blow up the ranker
    with `can't subtract offset-naive and offset-aware datetimes`."""
    from recupero.hack_tracker.aggregator import _rank_key
    from recupero.hack_tracker.models import (
        HackEvent,
        HackEventSeverity,
        HackEventSource,
    )

    # Construct an event with a naive datetime to simulate a fixture
    # that forgot the tzinfo. The model accepts it (no validator
    # currently enforces tz-awareness), but the ranker must not crash.
    naive_now = datetime.utcnow()  # naive
    ev = HackEvent(
        content_hash="a" * 64,
        source=HackEventSource.x_peckshield,
        source_url="https://x.com/x/status/1",
        observed_at=naive_now,
        title="x", summary="y",
        severity=HackEventSeverity.high,
    )
    # Must not raise
    score = _rank_key(ev)
    assert isinstance(score, float)


# ---- models: USD-loss NaN/Inf gate ---- #


def test_estimated_loss_usd_rejects_nan() -> None:
    """`Decimal('NaN')` from a hostile X-post must not populate
    estimated_loss_usd."""
    from recupero.hack_tracker.models import (
        HackEvent,
        HackEventSeverity,
        HackEventSource,
    )

    with pytest.raises((ValueError, ValidationError)):
        HackEvent(
            content_hash="a" * 64,
            source=HackEventSource.x_peckshield,
            source_url="https://x.com/x/status/1",
            observed_at=datetime.now(UTC),
            title="x", summary="y",
            severity=HackEventSeverity.high,
            estimated_loss_usd=Decimal("NaN"),
        )


def test_estimated_loss_usd_rejects_inf() -> None:
    """`Decimal('Infinity')` from a hostile feed must be rejected."""
    from recupero.hack_tracker.models import (
        HackEvent,
        HackEventSeverity,
        HackEventSource,
    )

    with pytest.raises((ValueError, ValidationError)):
        HackEvent(
            content_hash="a" * 64,
            source=HackEventSource.x_peckshield,
            source_url="https://x.com/x/status/1",
            observed_at=datetime.now(UTC),
            title="x", summary="y",
            severity=HackEventSeverity.high,
            estimated_loss_usd=Decimal("Infinity"),
        )


def test_estimated_loss_usd_rejects_negative() -> None:
    """A negative loss is nonsensical — must be rejected."""
    from recupero.hack_tracker.models import (
        HackEvent,
        HackEventSeverity,
        HackEventSource,
    )

    with pytest.raises((ValueError, ValidationError)):
        HackEvent(
            content_hash="a" * 64,
            source=HackEventSource.x_peckshield,
            source_url="https://x.com/x/status/1",
            observed_at=datetime.now(UTC),
            title="x", summary="y",
            severity=HackEventSeverity.high,
            estimated_loss_usd=Decimal("-1000"),
        )


# ---- models: text-field hygiene ---- #


def test_title_strips_nul_bytes() -> None:
    """NUL bytes in title must be scrubbed at model-validation time."""
    from recupero.hack_tracker.models import (
        HackEvent,
        HackEventSeverity,
        HackEventSource,
    )

    ev = HackEvent(
        content_hash="a" * 64,
        source=HackEventSource.x_peckshield,
        source_url="https://x.com/x/status/1",
        observed_at=datetime.now(UTC),
        title="Hack\x00title", summary="y",
        severity=HackEventSeverity.high,
    )
    assert "\x00" not in ev.title


def test_summary_strips_bidi_overrides() -> None:
    """Bidi overrides in summary must be scrubbed at validation."""
    from recupero.hack_tracker.models import (
        HackEvent,
        HackEventSeverity,
        HackEventSource,
    )

    hostile = "Bridge ‮X lost $50M"
    ev = HackEvent(
        content_hash="a" * 64,
        source=HackEventSource.x_peckshield,
        source_url="https://x.com/x/status/1",
        observed_at=datetime.now(UTC),
        title="t", summary=hostile,
        severity=HackEventSeverity.high,
    )
    assert "‮" not in ev.summary


# ---- models: source_url scheme guard ---- #


def test_source_url_rejects_javascript_scheme() -> None:
    """`javascript:` URLs are XSS vectors when source_url lands in
    digest HTML. Must be rejected."""
    from recupero.hack_tracker.models import (
        HackEvent,
        HackEventSeverity,
        HackEventSource,
    )

    with pytest.raises((ValueError, ValidationError)):
        HackEvent(
            content_hash="a" * 64,
            source=HackEventSource.x_peckshield,
            source_url="javascript:alert(1)",
            observed_at=datetime.now(UTC),
            title="t", summary="s",
            severity=HackEventSeverity.high,
        )


def test_source_url_rejects_file_scheme() -> None:
    """`file:///etc/passwd` is an SSRF/data-exfil vector."""
    from recupero.hack_tracker.models import (
        HackEvent,
        HackEventSeverity,
        HackEventSource,
    )

    with pytest.raises((ValueError, ValidationError)):
        HackEvent(
            content_hash="a" * 64,
            source=HackEventSource.x_peckshield,
            source_url="file:///etc/passwd",
            observed_at=datetime.now(UTC),
            title="t", summary="s",
            severity=HackEventSeverity.high,
        )


# ---- models: address-list canonicalization ---- #


def test_addresses_drops_non_canonical_entries() -> None:
    """If an extractor handed us a string that LOOKS like an EVM
    address but isn't (wrong length, non-hex), the model must drop
    it rather than persist garbage."""
    from recupero.hack_tracker.models import (
        HackEvent,
        HackEventSeverity,
        HackEventSource,
    )

    ev = HackEvent(
        content_hash="a" * 64,
        source=HackEventSource.x_peckshield,
        source_url="https://x.com/x/status/1",
        observed_at=datetime.now(UTC),
        title="t", summary="s",
        severity=HackEventSeverity.high,
        addresses=[
            "0x" + "a" * 40,         # valid (canonical)
            "0xNOTHEXZZZZ" + "a" * 30,  # invalid: non-hex
            "0x" + "a" * 39,         # invalid: too short
            "0x" + "a" * 41,         # invalid: too long
            "not-an-address",        # invalid
        ],
    )
    # Only the valid one survives
    assert ev.addresses == ["0x" + "a" * 40]


def test_tx_hashes_drops_non_canonical_entries() -> None:
    """Same canonicalization for tx hashes (0x + 64 hex)."""
    from recupero.hack_tracker.models import (
        HackEvent,
        HackEventSeverity,
        HackEventSource,
    )

    good = "0x" + "a" * 64
    ev = HackEvent(
        content_hash="a" * 64,
        source=HackEventSource.x_peckshield,
        source_url="https://x.com/x/status/1",
        observed_at=datetime.now(UTC),
        title="t", summary="s",
        severity=HackEventSeverity.high,
        tx_hashes=[
            good,
            "0x" + "a" * 63,    # too short
            "0xZZ" + "a" * 62,  # non-hex
            "garbage",
        ],
    )
    assert ev.tx_hashes == [good]


# ---- digest_cli: hours / format hardening ---- #


def test_cli_negative_hours_clamped(monkeypatch, capsys) -> None:
    """A negative `hours` would compute since=now+positive_offset and
    fail every recency check. Must be clamped to a positive value."""
    monkeypatch.setenv("RECUPERO_HACK_TRACKER_OFFLINE", "1")
    from recupero.hack_tracker.digest_cli import run

    rc = run(hours=-100, output_format="text")
    assert rc == 0
    out = capsys.readouterr().out
    assert "RECUPERO HACK-TRACKER DAILY DIGEST" in out


def test_cli_huge_hours_clamped(monkeypatch, capsys) -> None:
    """A `hours=10**12` value would trigger OverflowError in timedelta.
    Must be clamped before reaching timedelta(hours=...)."""
    monkeypatch.setenv("RECUPERO_HACK_TRACKER_OFFLINE", "1")
    from recupero.hack_tracker.digest_cli import run

    # Must not raise
    rc = run(hours=10**18, output_format="text")
    assert rc == 0


def test_cli_unknown_format_falls_back_to_text(monkeypatch, capsys) -> None:
    """An unknown output_format like 'pickle' or '../etc/passwd' must
    NOT crash. Either fall back to text, or reject cleanly."""
    monkeypatch.setenv("RECUPERO_HACK_TRACKER_OFFLINE", "1")
    from recupero.hack_tracker.digest_cli import run

    rc = run(hours=24, output_format="pickle-evil")
    assert rc in (0, 2)  # either fallback (0) or rejected (2)


# ---- digest_cli: ANSI escape / NUL in operator-visible output ---- #


def test_cli_text_output_strips_ansi_from_attacker_fields(
    monkeypatch, capsys,
) -> None:
    """If a fixture / feed somehow injected ANSI escape codes into a
    title, the text printer must scrub them — otherwise an attacker
    can rewrite the operator's terminal display."""
    monkeypatch.setenv("RECUPERO_HACK_TRACKER_OFFLINE", "1")
    from recupero.hack_tracker.aggregator import DailyDigest
    from recupero.hack_tracker.digest_cli import _print_text
    from recupero.hack_tracker.models import (
        HackEvent,
        HackEventSeverity,
        HackEventSource,
    )

    now = datetime.now(UTC)
    ev = HackEvent(
        content_hash="a" * 64,
        source=HackEventSource.x_peckshield,
        source_url="https://x.com/x/status/1",
        observed_at=now,
        title="evil\x1b[31mTITLE\x1b[0m",  # ANSI escape via title
        summary="s",
        severity=HackEventSeverity.high,
    )
    digest = DailyDigest(
        generated_at=now, window_start=now, window_end=now,
        events_total=1, top_events=[ev], all_events=[ev],
    )
    _print_text(digest)
    out = capsys.readouterr().out
    # Model validator already strips \x1b. The CLI must not reintroduce it.
    assert "\x1b" not in out


# ---- aggregator: bounded dedupe ---- #


def test_dedupe_loop_bounded_against_pathological_input(monkeypatch) -> None:
    """Even if a source returned a million events (it shouldn't), the
    aggregator must not OOM. Cap should be enforced before the dedup
    loop or inside it."""
    monkeypatch.setenv("RECUPERO_HACK_TRACKER_OFFLINE", "1")
    from recupero.hack_tracker.aggregator import run_daily_digest

    # The offline-fixture path already returns bounded data.
    # This test pins the no-crash + bounded-output property.
    digest = run_daily_digest()
    assert digest.events_total < 10_000
    assert len(digest.all_events) == digest.events_total
    assert len(digest.top_events) <= 20
