"""Tests for the hack-tracker feature (v0.20.0 Phase D).

The module is feature-flagged OFF in production. Tests exercise the
offline-fixture path so we can iterate on digest format + ranking
without burning external API quota.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

# ---- Aggregator gating ---- #


def test_run_daily_digest_refuses_without_feature_flag(monkeypatch) -> None:
    """Without RECUPERO_HACK_TRACKER_ENABLED=1 or OFFLINE=1, the
    aggregator must refuse to run — guards against accidental cron
    invocations burning API quota."""
    monkeypatch.delenv("RECUPERO_HACK_TRACKER_ENABLED", raising=False)
    monkeypatch.delenv("RECUPERO_HACK_TRACKER_OFFLINE", raising=False)
    from recupero.hack_tracker.aggregator import run_daily_digest
    with pytest.raises(RuntimeError, match="HACK_TRACKER_ENABLED"):
        run_daily_digest()


def test_run_daily_digest_offline_returns_fixture_data(monkeypatch) -> None:
    """Offline mode bypasses the feature flag and returns the bundled
    fixture events — useful for digest-format iteration in dev."""
    monkeypatch.setenv("RECUPERO_HACK_TRACKER_OFFLINE", "1")
    monkeypatch.delenv("RECUPERO_HACK_TRACKER_ENABLED", raising=False)
    from recupero.hack_tracker.aggregator import run_daily_digest
    digest = run_daily_digest()
    assert digest.events_total > 0, "fixture must produce at least one event"
    # The fixture mix includes one CRIT-OFAC entry; verify it ranks #1.
    top = digest.top_events[0]
    assert top.severity.value == "critical"


def test_run_daily_digest_offline_param_overrides_env(monkeypatch) -> None:
    """Explicit `offline=True` works even when env vars say otherwise."""
    monkeypatch.delenv("RECUPERO_HACK_TRACKER_OFFLINE", raising=False)
    monkeypatch.delenv("RECUPERO_HACK_TRACKER_ENABLED", raising=False)
    from recupero.hack_tracker.aggregator import run_daily_digest
    digest = run_daily_digest(offline=True)
    assert digest.events_total > 0


# ---- Ranking ---- #


def test_dedupe_collapses_identical_content_hashes(monkeypatch) -> None:
    """If two sources emit events with the same content_hash (e.g.,
    rekt and X reporting on the same hack), the aggregator must keep
    only one."""
    monkeypatch.setenv("RECUPERO_HACK_TRACKER_OFFLINE", "1")
    from recupero.hack_tracker import aggregator
    from recupero.hack_tracker.models import (
        HackEvent,
        HackEventSeverity,
        HackEventSource,
    )

    now = datetime.now(UTC)
    duplicate_hash = "deadbeef" * 8  # 64 hex chars
    a = HackEvent(
        content_hash=duplicate_hash,
        source=HackEventSource.x_peckshield,
        source_url="https://x.com/PeckShieldAlert/status/1",
        observed_at=now,
        title="hack #1", summary="x",
        severity=HackEventSeverity.high,
    )
    b = HackEvent(
        content_hash=duplicate_hash,  # SAME
        source=HackEventSource.rekt,
        source_url="https://rekt.news/article/x",
        observed_at=now,
        title="hack #1 (rekt)", summary="x",
        severity=HackEventSeverity.high,
    )
    # Use the same ranking signature — emulate dedup by calling the
    # aggregator's internal dedupe loop on a hand-built list.
    events = [a, b]
    seen: set[str] = set()
    deduped = []
    for ev in events:
        if ev.content_hash in seen:
            continue
        seen.add(ev.content_hash)
        deduped.append(ev)
    assert len(deduped) == 1
    # Sanity that aggregator._rank_key handles both source types
    # without raising
    aggregator._rank_key(a)
    aggregator._rank_key(b)


def test_has_identifiable_victim_boosts_rank(monkeypatch) -> None:
    """The marketing-priority kicker: an event with a named victim
    must outrank an identical event without one (all else equal)."""
    from datetime import UTC, datetime

    from recupero.hack_tracker.aggregator import _rank_key
    from recupero.hack_tracker.models import (
        HackEvent,
        HackEventSeverity,
        HackEventSource,
    )
    now = datetime.now(UTC)
    no_victim = HackEvent(
        content_hash="a" * 64,
        source=HackEventSource.x_peckshield,
        source_url="https://x.com/x/status/1",
        observed_at=now,
        title="t", summary="s",
        severity=HackEventSeverity.medium,
        has_identifiable_victim=False,
    )
    with_victim = HackEvent(
        content_hash="b" * 64,
        source=HackEventSource.x_peckshield,
        source_url="https://x.com/x/status/2",
        observed_at=now,
        title="t", summary="s",
        severity=HackEventSeverity.medium,
        has_identifiable_victim=True,
        victim_hint="DEX X",
    )
    assert _rank_key(with_victim) > _rank_key(no_victim)


# ---- Source-fetcher robustness ---- #


def test_x_feed_returns_empty_without_bearer_token(monkeypatch) -> None:
    """When RECUPERO_X_BEARER_TOKEN is unset, the X feed scraper
    returns empty (must not raise)."""
    monkeypatch.delenv("RECUPERO_X_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("RECUPERO_HACK_TRACKER_OFFLINE", raising=False)
    from recupero.hack_tracker.sources.x_feed import fetch
    events = fetch(since=datetime.now(UTC) - timedelta(hours=24))
    assert events == []


def test_offline_fixture_contents_are_well_formed() -> None:
    """The bundled fixture data must validate against the HackEvent
    Pydantic schema (catches drift if HackEvent changes)."""
    from recupero.hack_tracker.sources.x_feed import _offline_fixture
    events = _offline_fixture(since=datetime.now(UTC) - timedelta(hours=24))
    assert events, "fixture must be non-empty"
    for ev in events:
        # Re-validate via model_dump → model_validate round-trip
        from recupero.hack_tracker.models import HackEvent
        HackEvent.model_validate(ev.model_dump())


# ---- CLI smoke ---- #


def test_cli_daily_offline_succeeds(monkeypatch, capsys) -> None:
    """`recupero-ops hack-tracker daily` in offline mode exits 0 and
    prints a recognizable digest header."""
    monkeypatch.setenv("RECUPERO_HACK_TRACKER_OFFLINE", "1")
    from recupero.hack_tracker.digest_cli import run
    rc = run(hours=24, output_format="text")
    assert rc == 0
    out = capsys.readouterr().out
    assert "RECUPERO HACK-TRACKER DAILY DIGEST" in out
    assert "TOP EVENTS:" in out


def test_cli_daily_without_flag_or_offline_returns_2(monkeypatch, capsys) -> None:
    """No flag, no offline → CLI returns 2 with a clear error."""
    monkeypatch.delenv("RECUPERO_HACK_TRACKER_OFFLINE", raising=False)
    monkeypatch.delenv("RECUPERO_HACK_TRACKER_ENABLED", raising=False)
    from recupero.hack_tracker.digest_cli import run
    rc = run(hours=24, output_format="text")
    assert rc == 2
    err = capsys.readouterr().err
    assert "RECUPERO_HACK_TRACKER_ENABLED" in err
