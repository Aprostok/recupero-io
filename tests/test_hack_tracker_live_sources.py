"""Tests for the hack-tracker's live sources, its XML hardening, and the
cost brakes on the (billable) X feed.

No test here touches the network: HTTP is always monkeypatched, or the source is
driven in offline/fixture mode. A test that reached a real feed would be slow,
flaky, and — for the X source — would spend money.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from fastapi import HTTPException

from recupero.hack_tracker.models import HackEventSeverity, HackEventSource
from recupero.hack_tracker.sources import defillama_hacks as dl
from recupero.hack_tracker.sources import government_feeds as gf
from recupero.hack_tracker.sources import x_feed as xf

# --------------------------------------------------------------------------
# RSS date handling
# --------------------------------------------------------------------------


def test_rss_datetime_preserves_colon_style_offset() -> None:
    """IC3 emits `-04:00`, which parsedate_to_datetime parses to a NAIVE
    datetime (dropping the offset). The model then coerces naive -> UTC, which
    would silently shift every IC3 timestamp by its offset. Regression lock."""
    dt = gf._rss_datetime("Mon, 20 Jul 2026 10:00:00 -04:00")
    assert dt is not None
    assert dt.tzinfo is not None
    # 10:00 at -04:00 is 14:00 UTC. If the offset were dropped it would be 10:00.
    assert dt.hour == 14


def test_rss_datetime_handles_standard_and_two_digit_year() -> None:
    a = gf._rss_datetime("Fri, 26 Jun 2026 12:30:00 -0400")
    b = gf._rss_datetime("Tue, 28 Jul 26 12:00:00 +0000")
    assert a is not None and a.hour == 16
    assert b is not None and b.hour == 12


@pytest.mark.parametrize("bad", ["", "   ", "garbage", "not a date at all"])
def test_rss_datetime_returns_none_on_junk(bad: str) -> None:
    assert gf._rss_datetime(bad) is None


# --------------------------------------------------------------------------
# XML hardening
# --------------------------------------------------------------------------


def test_parse_rss_items_refuses_doctype() -> None:
    """ElementTree is documented as vulnerable to entity expansion. Rather than
    add defusedxml, any DOCTYPE/ENTITY document is refused outright."""
    billion_laughs = (
        b'<?xml version="1.0"?>\n'
        b'<!DOCTYPE lolz [<!ENTITY lol "lol">]>\n'
        b"<rss><channel><item><title>&lol;</title></item></channel></rss>"
    )
    assert gf._parse_rss_items(billion_laughs, url="http://x/") == []


def test_parse_rss_items_refuses_entity_declaration_without_doctype() -> None:
    raw = b'<?xml version="1.0"?><!ENTITY a "b"><rss><item><title>t</title></item></rss>'
    assert gf._parse_rss_items(raw, url="http://x/") == []


def test_parse_rss_items_returns_empty_on_malformed_xml() -> None:
    assert gf._parse_rss_items(b"<rss><item>unclosed", url="http://x/") == []
    assert gf._parse_rss_items(b"not xml at all", url="http://x/") == []


def test_parse_rss_items_caps_item_count() -> None:
    many = b"<rss><channel>" + (
        b"<item><title>t</title><link>http://ic3.gov/a</link></item>"
        * (gf._MAX_ITEMS_PER_FEED + 25)
    ) + b"</channel></rss>"
    items = gf._parse_rss_items(many, url="http://x/")
    assert len(items) == gf._MAX_ITEMS_PER_FEED


def test_parse_rss_items_extracts_fields() -> None:
    raw = (
        b"<rss><channel><item>"
        b"<title>Crypto theft advisory</title>"
        b"<link>https://www.ic3.gov/PSA/2026/PSA260101</link>"
        b"<pubDate>Mon, 20 Jul 2026 10:00:00 -04:00</pubDate>"
        b'<guid isPermaLink="false">260101</guid>'
        b"</item></channel></rss>"
    )
    items = gf._parse_rss_items(raw, url="http://x/")
    assert len(items) == 1
    assert items[0]["title"] == "Crypto theft advisory"
    assert items[0]["guid"] == "260101"


# --------------------------------------------------------------------------
# Crypto-relevance gate
# --------------------------------------------------------------------------


def test_crypto_relevance_filter() -> None:
    assert gf._is_crypto_relevant("Scammers use couriers in cryptocurrency scams")
    assert gf._is_crypto_relevant("DPRK actors target exchanges")
    assert gf._is_crypto_relevant("", "wallet drained")
    # CISA publishes a great deal of this; it must not reach a crypto feed.
    assert not gf._is_crypto_relevant(
        "Guidance to Isolate Operational Technology in Critical Infrastructure"
    )
    assert not gf._is_crypto_relevant("")


def test_rss_to_events_filters_offtopic_and_old(monkeypatch) -> None:
    raw = (
        b"<rss><channel>"
        b"<item><title>Cryptocurrency investment scam warning</title>"
        b"<link>https://www.ic3.gov/PSA/a</link>"
        b"<pubDate>Mon, 20 Jul 2026 10:00:00 -0400</pubDate></item>"
        b"<item><title>Operational technology advisory</title>"
        b"<link>https://www.ic3.gov/PSA/b</link>"
        b"<pubDate>Mon, 20 Jul 2026 10:00:00 -0400</pubDate></item>"
        b"<item><title>Old bitcoin theft advisory</title>"
        b"<link>https://www.ic3.gov/PSA/c</link>"
        b"<pubDate>Mon, 20 Jul 2020 10:00:00 -0400</pubDate></item>"
        b"</channel></rss>"
    )
    monkeypatch.setattr(gf, "_fetch_url", lambda url: raw)
    events = gf._rss_to_events(
        url="http://ic3/", since=datetime(2026, 1, 1, tzinfo=UTC),
        source=HackEventSource.ic3_alert,
        severity=HackEventSeverity.high, publisher="FBI IC3",
    )
    titles = [e.title for e in events]
    assert titles == ["Cryptocurrency investment scam warning"]


def test_rss_to_events_returns_empty_when_fetch_fails(monkeypatch) -> None:
    monkeypatch.setattr(gf, "_fetch_url", lambda url: None)
    assert gf._rss_to_events(
        url="http://x/", since=datetime(2026, 1, 1, tzinfo=UTC),
        source=HackEventSource.cisa_alert,
        severity=HackEventSeverity.high, publisher="CISA",
    ) == []


def test_sources_without_a_live_feed_return_empty_not_raise() -> None:
    """rekt (upstream 500) and OFAC (HTML-only) have no live source. They must
    degrade to empty, never raise, so one dead feed cannot fail the digest."""
    since = datetime.now(UTC) - timedelta(days=7)
    assert gf.fetch_rekt(since=since) == []
    assert gf.fetch_ofac(since=since) == []


# --------------------------------------------------------------------------
# DefiLlama adapter
# --------------------------------------------------------------------------


@pytest.mark.parametrize(("usd", "expected"), [
    (50_000_000, HackEventSeverity.critical),
    (10_000_000, HackEventSeverity.critical),
    (9_999_999, HackEventSeverity.high),
    (1_000_000, HackEventSeverity.high),
    (100_000, HackEventSeverity.medium),
    (99_999, HackEventSeverity.low),
    (None, HackEventSeverity.medium),
])
def test_defillama_severity_from_loss(usd, expected) -> None:
    loss = None if usd is None else Decimal(str(usd))
    assert dl._severity_for(loss) is expected


def test_defillama_row_to_event_carries_the_forensic_fields() -> None:
    occurred = datetime(2026, 6, 1, tzinfo=UTC)
    ev = dl._row_to_event({
        "name": "Bridge X", "amount": 12_000_000, "date": 1780000000,
        "chain": ["ethereum", "arbitrum"], "technique": "Signature Verification",
        "classification": "Protocol Logic", "targetType": "Bridge",
        "bridgeHack": True, "returnedFunds": 500_000,
        "source": "https://example.com/writeup",
    }, occurred)
    assert ev is not None
    assert ev.severity is HackEventSeverity.critical
    assert ev.estimated_loss_usd == Decimal("12000000")
    assert ev.chains_mentioned == ["ethereum", "arbitrum"]
    assert "bridge_exploit" in ev.tags
    assert ev.has_identifiable_victim is True
    # The arbitrary upstream host must NOT become source_url; it is kept as
    # text so the model's host allowlist keeps its meaning.
    assert "example.com" not in ev.source_url
    assert ev.source_url == dl._CITATION_URL
    assert "example.com/writeup" in ev.summary
    assert "Funds returned" in ev.summary


def test_defillama_row_without_a_name_is_dropped() -> None:
    assert dl._row_to_event({"amount": 1, "date": 1780000000}, datetime.now(UTC)) is None
    assert dl._row_to_event({"name": "  ", "date": 1780000000}, datetime.now(UTC)) is None


@pytest.mark.parametrize("bad_date", [None, "", "abc", 0, -5, 1_000_000])
def test_defillama_rejects_implausible_dates(bad_date) -> None:
    assert dl._row_datetime({"date": bad_date}) is None


def test_defillama_rejects_far_future_date() -> None:
    far = datetime.now(UTC).timestamp() + (400 * 86400)
    assert dl._row_datetime({"date": far}) is None


@pytest.mark.parametrize("bad", ["NaN", "Infinity", "-1", "notanumber", None])
def test_defillama_loss_rejects_hostile_amounts(bad) -> None:
    assert dl._loss_usd({"amount": bad}) is None


def test_defillama_fetch_filters_by_window(monkeypatch) -> None:
    recent = int((datetime.now(UTC) - timedelta(days=2)).timestamp())
    old = int((datetime.now(UTC) - timedelta(days=400)).timestamp())
    monkeypatch.setattr(dl, "_fetch_rows", lambda: [
        {"name": "Recent", "amount": 5_000_000, "date": recent},
        {"name": "Old", "amount": 9_000_000, "date": old},
    ])
    events = dl.fetch(since=datetime.now(UTC) - timedelta(days=30))
    assert [e.title.split(" ")[0] for e in events] == ["Recent"]


def test_defillama_fetch_returns_empty_when_transport_fails(monkeypatch) -> None:
    monkeypatch.setattr(dl, "_fetch_rows", lambda: None)
    assert dl.fetch(since=datetime.now(UTC) - timedelta(days=30)) == []


def test_defillama_offline_fixture_needs_no_network(monkeypatch) -> None:
    def _boom():
        raise AssertionError("offline mode must not fetch")
    monkeypatch.setattr(dl, "_fetch_rows", _boom)
    events = dl.fetch(since=datetime(2020, 1, 1, tzinfo=UTC), offline=True)
    assert len(events) == 1
    assert events[0].source is HackEventSource.defillama


# --------------------------------------------------------------------------
# X feed cost brakes  (X bills PER POST READ — these guard real money)
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_x_budget():
    """Each test starts with a clean budget; module state must not leak."""
    xf._budget["last_fetch_monotonic"] = None
    xf._budget["day"] = None
    xf._budget["reads_today"] = 0
    xf._user_id_cache.clear()
    yield
    xf._budget["last_fetch_monotonic"] = None
    xf._budget["reads_today"] = 0
    xf._user_id_cache.clear()


def test_x_fetch_without_token_spends_nothing(monkeypatch) -> None:
    monkeypatch.delenv("RECUPERO_X_BEARER_TOKEN", raising=False)

    def _boom(*a, **k):
        raise AssertionError("must not call the X API without a token")
    monkeypatch.setattr(xf, "_x_get", _boom)
    assert xf.fetch(since=datetime.now(UTC) - timedelta(days=1)) == []
    assert xf._budget["reads_today"] == 0


def test_x_max_tweets_is_clamped_to_api_bounds(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_X_MAX_TWEETS_PER_HANDLE", "999")
    assert xf._max_tweets_per_handle() == 100
    monkeypatch.setenv("RECUPERO_X_MAX_TWEETS_PER_HANDLE", "1")
    assert xf._max_tweets_per_handle() == 5
    monkeypatch.setenv("RECUPERO_X_MAX_TWEETS_PER_HANDLE", "garbage")
    assert xf._max_tweets_per_handle() == xf._DEFAULT_MAX_TWEETS


def test_x_interval_brake_refuses_a_second_fetch(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_X_MIN_FETCH_INTERVAL_S", "3600")
    assert xf._x_budget_allows() is True
    # Second call inside the interval must be refused: the feed endpoint's
    # 15-minute cache would otherwise poll X ~96x/day.
    assert xf._x_budget_allows() is False


def test_x_interval_of_zero_allows_back_to_back(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_X_MIN_FETCH_INTERVAL_S", "0")
    assert xf._x_budget_allows() is True
    assert xf._x_budget_allows() is True


def test_x_daily_read_cap_stops_further_fetches(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_X_MIN_FETCH_INTERVAL_S", "0")
    monkeypatch.setenv("RECUPERO_X_MAX_READS_PER_DAY", "10")
    assert xf._x_budget_allows() is True
    xf._record_reads(10)
    assert xf._x_budget_allows() is False


def test_x_record_reads_ignores_nonpositive() -> None:
    xf._record_reads(0)
    xf._record_reads(-5)
    assert xf._budget["reads_today"] == 0


def test_x_fetch_is_blocked_by_the_budget_before_any_request(monkeypatch) -> None:
    monkeypatch.setenv("RECUPERO_X_BEARER_TOKEN", "token")
    monkeypatch.setenv("RECUPERO_X_MAX_READS_PER_DAY", "0")

    def _boom(*a, **k):
        raise AssertionError("budget must be checked before any HTTP call")
    monkeypatch.setattr(xf, "_x_get", _boom)
    assert xf.fetch(since=datetime.now(UTC) - timedelta(days=1)) == []


def test_x_user_id_cache_avoids_a_repeat_lookup(monkeypatch) -> None:
    calls: list[str] = []

    def fake_get(url, *, params, bearer_token, label):
        calls.append(url)
        return {"data": {"id": "12345"}}

    monkeypatch.setattr(xf, "_x_get", fake_get)
    a = xf._resolve_user_id(handle="PeckShieldAlert", bearer_token="t")
    b = xf._resolve_user_id(handle="PeckShieldAlert", bearer_token="t")
    assert a == b == "12345"
    assert len(calls) == 1, "handle->id is immutable; it must be memoized"


@pytest.mark.parametrize("payload", [
    {"data": {"id": "not-numeric"}},
    {"data": {}},
    {"data": []},
    {},
])
def test_x_resolve_user_id_rejects_bad_payloads(monkeypatch, payload) -> None:
    monkeypatch.setattr(
        xf, "_x_get", lambda url, **k: payload,
    )
    assert xf._resolve_user_id(handle="h", bearer_token="t") is None


# --------------------------------------------------------------------------
# /v1/hack-tracker endpoint
# --------------------------------------------------------------------------


def _clear_feed_cache() -> None:
    from recupero.api import hack_tracker_api as api
    with api._cache_lock:
        api._cache.clear()


def test_feed_requires_the_admin_key(monkeypatch) -> None:
    from recupero.api import hack_tracker_api as api
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    _clear_feed_cache()
    with pytest.raises(HTTPException) as missing:
        api.get_hack_feed(x_recupero_admin_key=None)
    assert missing.value.status_code == 401
    with pytest.raises(HTTPException) as wrong:
        api.get_hack_feed(x_recupero_admin_key="nope")
    assert wrong.value.status_code == 401


def test_feed_503s_when_admin_key_not_configured(monkeypatch) -> None:
    from recupero.api import hack_tracker_api as api
    monkeypatch.delenv("RECUPERO_ADMIN_KEY", raising=False)
    _clear_feed_cache()
    with pytest.raises(HTTPException) as exc:
        api.get_hack_feed(x_recupero_admin_key="anything")
    assert exc.value.status_code == 503


def test_feed_503s_with_actionable_message_when_flag_is_off(monkeypatch) -> None:
    from recupero.api import hack_tracker_api as api
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    monkeypatch.delenv("RECUPERO_HACK_TRACKER_ENABLED", raising=False)
    monkeypatch.delenv("RECUPERO_HACK_TRACKER_OFFLINE", raising=False)
    _clear_feed_cache()
    with pytest.raises(HTTPException) as exc:
        api.get_hack_feed(x_recupero_admin_key="secret")
    assert exc.value.status_code == 503
    assert "RECUPERO_HACK_TRACKER_ENABLED" in exc.value.detail


def test_feed_returns_ranked_payload_in_offline_mode(monkeypatch) -> None:
    from recupero.api import hack_tracker_api as api
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    monkeypatch.setenv("RECUPERO_HACK_TRACKER_OFFLINE", "1")
    _clear_feed_cache()
    rep = api.get_hack_feed(window_days=365, x_recupero_admin_key="secret")
    assert rep["events_total"] >= 1
    assert rep["cached"] is False
    assert len(rep["events"]) == rep["events_total"]
    assert rep["events_by_severity"]
    # Loss must serialize as a string: JSON has no Decimal and a float would
    # lose precision on large USD figures.
    for ev in rep["events"]:
        assert ev["estimated_loss_usd"] is None or isinstance(
            ev["estimated_loss_usd"], str
        )
    # Every source gets a status note so a zero never reads as a bug.
    assert "cisa_alert" in rep["source_notes"]

    again = api.get_hack_feed(window_days=365, x_recupero_admin_key="secret")
    assert again["cached"] is True, "repeat calls must be served from cache"


def test_feed_refresh_bypasses_the_cache(monkeypatch) -> None:
    from recupero.api import hack_tracker_api as api
    monkeypatch.setenv("RECUPERO_ADMIN_KEY", "secret")
    monkeypatch.setenv("RECUPERO_HACK_TRACKER_OFFLINE", "1")
    _clear_feed_cache()
    api.get_hack_feed(window_days=30, x_recupero_admin_key="secret")
    forced = api.get_hack_feed(
        window_days=30, refresh=True, x_recupero_admin_key="secret",
    )
    assert forced["cached"] is False
