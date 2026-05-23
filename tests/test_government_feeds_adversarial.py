"""Adversarial-input tests for hack_tracker.sources.government_feeds.

The government feeds (OFAC, IC3, CISA, rekt) are stubs in v0.20.0 but
the URL constants + fixture surface need defensive properties so the
real fetchers (v0.20.1) can layer on without re-litigating the safety
invariants.

Patterns covered:
  * Feed URLs are HTTPS-only — no http://, file://, ftp://, gopher://
  * Offline fixtures validate against the HackEvent model
  * Each fetch_* helper returns a list (never None) on every code path
  * Fetchers never raise — operators expect "log + return empty" semantics
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


# ---- URL hygiene ---- #


def test_all_feed_url_constants_are_https() -> None:
    """Every external feed URL must use https:// — no http://, ftp://,
    gopher:// or file:// schemes leak into the live fetcher path."""
    from recupero.hack_tracker.sources import government_feeds as gf

    for name in (
        "_OFAC_RECENT_ACTIONS",
        "_OFAC_SDN_FEED",
        "_IC3_RSS",
        "_CISA_RSS",
        "_REKT_RSS",
    ):
        url = getattr(gf, name)
        assert isinstance(url, str), f"{name} must be a string"
        assert url.startswith("https://"), (
            f"{name} = {url!r}: only https:// allowed for external feeds"
        )


def test_no_feed_url_contains_credentials() -> None:
    """No `user:pass@host` form should slip into a pinned feed URL —
    those leak credentials into logs and HackEvent.source_url."""
    from recupero.hack_tracker.sources import government_feeds as gf

    for name in (
        "_OFAC_RECENT_ACTIONS",
        "_OFAC_SDN_FEED",
        "_IC3_RSS",
        "_CISA_RSS",
        "_REKT_RSS",
    ):
        url = getattr(gf, name)
        # After the scheme, there must be no '@' before the first '/'
        rest = url.split("://", 1)[1]
        path_start = rest.find("/")
        host_part = rest if path_start == -1 else rest[:path_start]
        assert "@" not in host_part, f"{name}={url!r} has embedded creds"


# ---- Fetcher contract: never raise, always list ---- #


def test_fetch_ofac_offline_returns_list() -> None:
    """Offline fetch returns a list (never None, never raises)."""
    from recupero.hack_tracker.sources.government_feeds import fetch_ofac
    out = fetch_ofac(since=datetime.now(UTC) - timedelta(hours=24), offline=True)
    assert isinstance(out, list)
    assert len(out) >= 1  # fixture is non-empty


def test_fetch_ic3_offline_returns_list() -> None:
    from recupero.hack_tracker.sources.government_feeds import fetch_ic3
    out = fetch_ic3(since=datetime.now(UTC) - timedelta(hours=24), offline=True)
    assert isinstance(out, list)


def test_fetch_cisa_offline_returns_list() -> None:
    from recupero.hack_tracker.sources.government_feeds import fetch_cisa
    out = fetch_cisa(since=datetime.now(UTC) - timedelta(hours=24), offline=True)
    assert isinstance(out, list)


def test_fetch_rekt_offline_returns_list() -> None:
    from recupero.hack_tracker.sources.government_feeds import fetch_rekt
    out = fetch_rekt(since=datetime.now(UTC) - timedelta(hours=24), offline=True)
    assert isinstance(out, list)


# ---- Fixture validation ---- #


def test_ofac_fixture_validates_through_model() -> None:
    """OFAC offline fixture must round-trip through HackEvent — catches
    drift if the model adds new validators."""
    from recupero.hack_tracker.models import HackEvent
    from recupero.hack_tracker.sources.government_feeds import (
        _offline_ofac_fixture,
    )
    events = _offline_ofac_fixture()
    assert events
    for ev in events:
        HackEvent.model_validate(ev.model_dump())


def test_ic3_fixture_validates_through_model() -> None:
    from recupero.hack_tracker.models import HackEvent
    from recupero.hack_tracker.sources.government_feeds import (
        _offline_ic3_fixture,
    )
    events = _offline_ic3_fixture()
    assert events
    for ev in events:
        HackEvent.model_validate(ev.model_dump())


def test_cisa_fixture_validates_through_model() -> None:
    from recupero.hack_tracker.models import HackEvent
    from recupero.hack_tracker.sources.government_feeds import (
        _offline_cisa_fixture,
    )
    events = _offline_cisa_fixture()
    assert events
    for ev in events:
        HackEvent.model_validate(ev.model_dump())


# ---- Stub fetcher safety in non-offline mode ---- #


def test_fetch_ofac_nonoffline_returns_empty_when_stub(monkeypatch) -> None:
    """v0.20.0 stub path: when offline=False AND env not set, the
    function still returns a list (empty)."""
    monkeypatch.delenv("RECUPERO_HACK_TRACKER_OFFLINE", raising=False)
    from recupero.hack_tracker.sources.government_feeds import fetch_ofac
    out = fetch_ofac(since=datetime.now(UTC) - timedelta(hours=24), offline=False)
    assert isinstance(out, list)
    # Stub path returns empty (per docstring)
    assert out == []


def test_fetch_ic3_nonoffline_returns_empty_when_stub(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_HACK_TRACKER_OFFLINE", raising=False)
    from recupero.hack_tracker.sources.government_feeds import fetch_ic3
    out = fetch_ic3(since=datetime.now(UTC) - timedelta(hours=24), offline=False)
    assert out == []


# ---- since-parameter robustness ---- #


def test_fetch_handles_extreme_since_values() -> None:
    """A bizarre since=epoch-0 or since=year-9999 must not crash."""
    from recupero.hack_tracker.sources.government_feeds import (
        fetch_cisa,
        fetch_ic3,
        fetch_ofac,
    )
    # Epoch zero (1970-01-01)
    extreme_old = datetime(1970, 1, 1, tzinfo=UTC)
    # Far future
    extreme_new = datetime(9999, 12, 31, tzinfo=UTC)
    for since in (extreme_old, extreme_new):
        for fn in (fetch_ofac, fetch_ic3, fetch_cisa):
            out = fn(since=since, offline=True)
            assert isinstance(out, list)
