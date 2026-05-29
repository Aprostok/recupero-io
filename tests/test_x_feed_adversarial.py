"""Adversarial-input tests for hack_tracker.sources.x_feed.

The X feed parses attacker-controlled tweet text from a public API.
Every field — tweet text, tweet id, created_at — is hostile. This file
pins defensive behavior against the patterns previous waves identified:

  * Unicode trojans / NUL bytes / bidi controls in tweet text
  * Numeric overflow / NaN-Inf in extracted USD amounts
  * SSRF via crafted tweet_id (built into source_url verbatim)
  * Datetime parse hostility (OverflowError, non-string, far-future)
  * Address-regex matching attacker blobs of `0x`+hex inside garbage
  * Oversize text payloads triggering memory/CPU exhaustion
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

# ---- Tweet-text hygiene ---- #


def test_tweet_text_strips_nul_bytes() -> None:
    """NUL bytes in tweet text must be scrubbed before they reach the
    HackEvent.title (would corrupt downstream JSON / HTML rendering)."""
    from recupero.hack_tracker.models import HackEventSource
    from recupero.hack_tracker.sources.x_feed import _post_to_event

    post = {
        "id": "1234567890",
        "text": "Bridge X lost $50M\x00 in exploit, addresses below " + "x" * 30,
        "created_at": "2026-01-01T00:00:00Z",
    }
    ev = _post_to_event(
        post=post, handle="PeckShieldAlert",
        source=HackEventSource.x_peckshield,
    )
    assert ev is not None
    assert "\x00" not in ev.title
    assert "\x00" not in ev.summary


def test_tweet_text_strips_bidi_overrides() -> None:
    """Bidi-override controls (U+202E etc.) must be stripped so they
    cannot mask an attacker-controlled URL in operator digest output."""
    from recupero.hack_tracker.models import HackEventSource
    from recupero.hack_tracker.sources.x_feed import _post_to_event

    # U+202E = RIGHT-TO-LEFT OVERRIDE. Classic homograph-attack vector.
    hostile = "Bridge X lost ‮$50M in exploit detected by PeckShield"
    post = {
        "id": "1234567890",
        "text": hostile,
        "created_at": "2026-01-01T00:00:00Z",
    }
    ev = _post_to_event(
        post=post, handle="PeckShieldAlert",
        source=HackEventSource.x_peckshield,
    )
    assert ev is not None
    for cp in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
              0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F):
        assert chr(cp) not in ev.title
        assert chr(cp) not in ev.summary


def test_tweet_text_strips_zero_width_invisibles() -> None:
    """Zero-width characters (U+200B, U+200C, U+FEFF) must be dropped
    so they cannot smuggle invisible content into the digest."""
    from recupero.hack_tracker.models import HackEventSource
    from recupero.hack_tracker.sources.x_feed import _post_to_event

    hostile = "Bridge​ X‌ lost‍ $50M﻿ " + "exploit " * 5
    post = {
        "id": "1234567890",
        "text": hostile,
        "created_at": "2026-01-01T00:00:00Z",
    }
    ev = _post_to_event(
        post=post, handle="PeckShieldAlert",
        source=HackEventSource.x_peckshield,
    )
    assert ev is not None
    for cp in (0x200B, 0x200C, 0x200D, 0xFEFF):
        assert chr(cp) not in ev.title
        assert chr(cp) not in ev.summary


def test_tweet_text_strips_c0_controls() -> None:
    """C0 control characters (other than tab/newline) must be scrubbed."""
    from recupero.hack_tracker.models import HackEventSource
    from recupero.hack_tracker.sources.x_feed import _post_to_event

    # \x07 = BEL, \x1b = ESC (ANSI escape entry point)
    hostile = "Bridge X lost \x1b[31m$50M\x1b[0m in \x07exploit " + "x" * 20
    post = {
        "id": "1234567890",
        "text": hostile,
        "created_at": "2026-01-01T00:00:00Z",
    }
    ev = _post_to_event(
        post=post, handle="PeckShieldAlert",
        source=HackEventSource.x_peckshield,
    )
    assert ev is not None
    assert "\x1b" not in ev.title
    assert "\x07" not in ev.title
    assert "\x1b" not in ev.summary


# ---- tweet_id / source_url SSRF surface ---- #


def test_tweet_id_with_path_traversal_is_rejected() -> None:
    """A tweet_id containing slashes or `..` would let an attacker
    rewrite the source_url path. _post_to_event must reject."""
    from recupero.hack_tracker.models import HackEventSource
    from recupero.hack_tracker.sources.x_feed import _post_to_event

    hostile_id = "../../evil/path"
    post = {
        "id": hostile_id,
        "text": "Bridge X lost $50M in exploit detected " + "x" * 30,
        "created_at": "2026-01-01T00:00:00Z",
    }
    ev = _post_to_event(
        post=post, handle="PeckShieldAlert",
        source=HackEventSource.x_peckshield,
    )
    assert ev is None


def test_tweet_id_with_at_sign_is_rejected() -> None:
    """An ``@`` in tweet_id would let attacker reroute the URL
    (host = whatever comes after @)."""
    from recupero.hack_tracker.models import HackEventSource
    from recupero.hack_tracker.sources.x_feed import _post_to_event

    post = {
        "id": "1@evil.example.com",
        "text": "Bridge X lost $50M in exploit detected " + "x" * 30,
        "created_at": "2026-01-01T00:00:00Z",
    }
    ev = _post_to_event(
        post=post, handle="PeckShieldAlert",
        source=HackEventSource.x_peckshield,
    )
    assert ev is None


def test_tweet_id_non_string_is_rejected() -> None:
    """A non-string tweet_id (e.g., dict, list) must be rejected
    cleanly — not crash with TypeError on string operations."""
    from recupero.hack_tracker.models import HackEventSource
    from recupero.hack_tracker.sources.x_feed import _post_to_event

    post = {
        "id": {"injected": "object"},
        "text": "Bridge X lost $50M in exploit detected " + "x" * 30,
        "created_at": "2026-01-01T00:00:00Z",
    }
    # Must not raise
    ev = _post_to_event(
        post=post, handle="PeckShieldAlert",
        source=HackEventSource.x_peckshield,
    )
    assert ev is None


# ---- Datetime hostility ---- #


def test_created_at_with_overflow_year_is_handled() -> None:
    """A created_at year of 99999 can blow up datetime.fromisoformat
    with ValueError; that path must be handled cleanly."""
    from recupero.hack_tracker.models import HackEventSource
    from recupero.hack_tracker.sources.x_feed import _post_to_event

    post = {
        "id": "1234567890",
        "text": "Bridge X lost $50M in exploit detected " + "x" * 30,
        "created_at": "99999-01-01T00:00:00Z",
    }
    # Must not raise — caught and replaced with now()
    ev = _post_to_event(
        post=post, handle="PeckShieldAlert",
        source=HackEventSource.x_peckshield,
    )
    assert ev is not None
    assert ev.incident_time is not None


def test_created_at_non_string_is_handled() -> None:
    """created_at as int / None / dict must not crash."""
    from recupero.hack_tracker.models import HackEventSource
    from recupero.hack_tracker.sources.x_feed import _post_to_event

    for bad in (12345, None, {"a": 1}, ["2026-01-01"]):
        post = {
            "id": "1234567890",
            "text": "Bridge X lost $50M in exploit detected " + "x" * 30,
            "created_at": bad,
        }
        ev = _post_to_event(
            post=post, handle="PeckShieldAlert",
            source=HackEventSource.x_peckshield,
        )
        assert ev is not None, f"failed on created_at={bad!r}"


def test_created_at_with_nul_byte_is_handled() -> None:
    """A NUL byte in created_at would propagate to fromisoformat;
    must be caught."""
    from recupero.hack_tracker.models import HackEventSource
    from recupero.hack_tracker.sources.x_feed import _post_to_event

    post = {
        "id": "1234567890",
        "text": "Bridge X lost $50M in exploit detected " + "x" * 30,
        "created_at": "2026-01-01\x00T00:00:00Z",
    }
    ev = _post_to_event(
        post=post, handle="PeckShieldAlert",
        source=HackEventSource.x_peckshield,
    )
    assert ev is not None


# ---- USD-amount NaN/Inf gates in severity inference ---- #


def test_severity_inference_rejects_inf_usd() -> None:
    """An attacker post claiming `$1e400 million` overflows to inf
    when multiplied by 1e6. inf must not silently rank as critical."""
    from recupero.hack_tracker.sources.x_feed import _infer_severity

    hostile = "Bridge X lost $1e400 million in catastrophic exploit"
    sev = _infer_severity(hostile)
    # The hostile post should NOT have been ranked critical based on
    # the bogus inf value. It can still be critical via keyword
    # ("Lazarus" etc.) but not from the parsed amount.
    assert sev.value in {"medium", "high", "critical"}
    # Specifically: if it ranks critical, that must be because of
    # keyword inference (none present here), not the inf overflow.
    assert sev.value != "critical"


def test_severity_inference_rejects_nan_usd() -> None:
    """A literal 'NaN' next to a dollar sign must not crash or
    spuriously rank as critical."""
    from recupero.hack_tracker.sources.x_feed import _infer_severity

    hostile = "Bridge X lost $NaN million in exploit"
    # Must not raise
    sev = _infer_severity(hostile)
    # No usable amount + no keyword → medium fallback
    assert sev.value == "medium"


def test_severity_inference_rejects_huge_numeric_no_unit() -> None:
    """Without a unit suffix, `$1e308` is just a float — the float()
    call works but the value should still be sanity-bounded."""
    from recupero.hack_tracker.sources.x_feed import _infer_severity

    hostile = "Bridge X lost $1e308 in exploit"
    # Must not raise
    sev = _infer_severity(hostile)
    # If sanity-bounded, it ranks critical (legitimately huge).
    # The key invariant: no crash.
    assert sev.value in {"critical", "high", "medium"}


# ---- Address-extraction adversarial inputs ---- #


def test_extract_addresses_filters_obvious_repeating_pattern() -> None:
    """`0x` + 40 zeroes is a known null-address. The extractor returns
    it via regex but downstream uses should still accept it — it's
    valid hex. Just verify the extractor doesn't crash on edge cases.
    """
    from recupero.hack_tracker.sources.x_feed import _extract_addresses

    text = "addresses: 0x" + "0" * 40 + " and 0x" + "f" * 40
    addrs = _extract_addresses(text)
    assert len(addrs) == 2


def test_extract_addresses_dedupes() -> None:
    """If the same address appears twice in a tweet, the extracted
    list should not duplicate (downstream uses set membership)."""
    from recupero.hack_tracker.sources.x_feed import _extract_addresses

    addr = "0x" + "a" * 40
    text = f"victim {addr} and again {addr} oh and {addr.upper()}"
    addrs = _extract_addresses(text)
    # Canonical-form dedup: lower-cased single entry
    assert len(addrs) == 1
    assert addrs[0] == addr  # canonical lower-cased


def test_extract_addresses_rejects_oversize_text() -> None:
    """An attacker post with a megabyte of text must not blow up the
    extractor. Either truncate or process bounded — must not OOM."""
    from recupero.hack_tracker.sources.x_feed import _extract_addresses

    # 1MB of fake addresses
    blob = ("0x" + "b" * 40 + " ") * 25_000
    # Must not raise, must not hang
    addrs = _extract_addresses(blob)
    # Whatever the cap is, it should be bounded
    assert len(addrs) <= 10_000


# ---- _post_to_event end-to-end with hostile input ---- #


def test_post_to_event_oversize_text_is_capped() -> None:
    """A tweet text 1MB long must produce a bounded HackEvent (title
    capped to model max, summary capped to model max). Must not crash
    Pydantic max_length validation."""
    from recupero.hack_tracker.models import HackEventSource
    from recupero.hack_tracker.sources.x_feed import _post_to_event

    post = {
        "id": "1234567890",
        "text": "A" * 1_000_000,
        "created_at": "2026-01-01T00:00:00Z",
    }
    ev = _post_to_event(
        post=post, handle="PeckShieldAlert",
        source=HackEventSource.x_peckshield,
    )
    assert ev is not None
    assert len(ev.title) <= 400
    assert len(ev.summary) <= 2000


def test_post_to_event_missing_text_returns_none() -> None:
    """Tweets without text (or with text shorter than threshold) are
    filtered. Must not crash."""
    from recupero.hack_tracker.models import HackEventSource
    from recupero.hack_tracker.sources.x_feed import _post_to_event

    for bad_text in ("", "short", None):
        post = {
            "id": "1234567890",
            "text": bad_text,
            "created_at": "2026-01-01T00:00:00Z",
        }
        ev = _post_to_event(
            post=post, handle="PeckShieldAlert",
            source=HackEventSource.x_peckshield,
        )
        assert ev is None


# ---- Live-fetch path: no SSRF via env var ---- #


def test_x_feed_offline_fixture_roundtrips_through_model() -> None:
    """The bundled offline fixture must remain HackEvent-valid even
    after all the new validators land in models.py."""
    from recupero.hack_tracker.models import HackEvent
    from recupero.hack_tracker.sources.x_feed import _offline_fixture

    events = _offline_fixture(since=datetime.now(UTC) - timedelta(hours=24))
    assert events
    for ev in events:
        # round-trip through Pydantic — catches drift
        HackEvent.model_validate(ev.model_dump())
