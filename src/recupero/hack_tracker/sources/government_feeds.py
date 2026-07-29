"""Government / regulator feed scrapers.

Three feeds:
  * OFAC SDN list updates + cyber-advisories (treasury.gov)
  * FBI IC3 public service announcements (ic3.gov RSS)
  * CISA cybersecurity advisories (cisa.gov RSS)

All three are public, no auth required. The scrapers parse the RSS / XML
and emit ``HackEvent`` instances with source-specific weights:
  * OFAC SDN     → severity=critical (sanctions == max-priority)
  * IC3 alert    → severity=high (federal advisory)
  * CISA alert   → severity=high (cyber-infrastructure advisory)

This module deliberately uses urllib (stdlib) instead of httpx so it
has no extra dependency footprint — the daily-digest cron must be
robust even when the rest of the worker is down.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime, timedelta

from recupero.hack_tracker.models import (
    HackEvent,
    HackEventSeverity,
    HackEventSource,
)

log = logging.getLogger(__name__)


# Public feed URLs. Source-of-truth lives here; if any of these moves,
# update in one place.
#
# Re-probed 2026-07-28 (the v0.20.0 "all three confirmed accessible" note had
# gone stale):
#   * IC3   — /PSA/PSARss now serves the press-release HTML page, NOT RSS. The
#             real feed is /PSA/RSS (application/rss+xml). Corrected below.
#   * CISA  — news.xml still valid RSS 2.0.
#   * rekt  — every feed path (/feed/, /rss, /feed.xml, /rss.xml) returns
#             HTTP 500 from the origin. Nothing to parse; fetch_rekt stays a
#             documented no-op rather than pretending.
#   * OFAC  — recent-actions is an HTML page and has no XML sibling
#             (recent-actions.xml → 404), so it needs HTML scraping or the
#             existing SDN pipeline, not an RSS parser. See fetch_ofac.
_OFAC_RECENT_ACTIONS = "https://ofac.treasury.gov/recent-actions"
_OFAC_SDN_FEED       = "https://ofac.treasury.gov/specially-designated-nationals-sdn-list-data-formats-data-schemas"
_IC3_RSS             = "https://www.ic3.gov/PSA/RSS"
_CISA_RSS            = "https://www.cisa.gov/news.xml"
_REKT_RSS            = "https://rekt.news/feed/"

# Bound every fetch. These feeds are public and unauthenticated, so treat the
# response as untrusted input: cap the body before it reaches the XML parser
# and never block the digest cron for long.
_HTTP_TIMEOUT_S = 15
_MAX_FEED_BYTES = 2 * 1024 * 1024
_MAX_ITEMS_PER_FEED = 60
_USER_AGENT = "recupero-hack-tracker/1.0 (+https://recupero.io)"

# Crypto relevance gate. CISA and IC3 publish mostly non-crypto material
# (operational-technology advisories, parcel-fraud PSAs); importing all of it
# would bury the crypto signal this tracker exists to surface. Matching is on
# title + summary, case-insensitive substring.
_CRYPTO_TERMS = frozenset({
    "crypto", "cryptocurrency", "bitcoin", "ethereum", "blockchain",
    "digital asset", "digital currency", "virtual currency", "virtual asset",
    "wallet", "exchange", "defi", "stablecoin", "token", "nft",
    "ransomware", "pig butchering", "pig-butchering", "romance scam",
    "investment scam", "confidence scam", "money laundering", "launder",
    "mixer", "tumbler", "north korea", "dprk", "lazarus",
})


def fetch_ofac(*, since: datetime, offline: bool = False) -> list[HackEvent]:
    """Fetch OFAC recent-actions list. Returns HackEvent rows for any
    cyber-related entries (those mentioning blockchain / crypto /
    digital-currency / wallet address)."""
    if offline or _is_offline():
        return _offline_ofac_fixture()
    # No live implementation: OFAC's recent-actions page is HTML with no XML
    # sibling (recent-actions.xml → 404, re-probed 2026-07-28), so it needs an
    # HTML scraper — markup-fragile, and a wrong parse here would mis-state a
    # SANCTIONS fact. The repo already ingests OFAC authoritatively elsewhere
    # (labels/ ofac_crypto_live.csv); wiring this source to THAT pipeline is
    # the correct fix, not scraping the press-release page.
    log.info(
        "hack_tracker.ofac: no live source (recent-actions is HTML-only); "
        "returning empty",
    )
    return []


def fetch_ic3(*, since: datetime, offline: bool = False) -> list[HackEvent]:
    """Fetch FBI IC3 public service announcements (RSS, no auth).

    Only crypto-relevant PSAs are kept — IC3 also publishes parcel-fraud and
    other non-crypto advisories that would bury the signal.
    """
    if offline or _is_offline():
        return _offline_ic3_fixture()
    return _rss_to_events(
        url=_IC3_RSS, since=since,
        source=HackEventSource.ic3_alert,
        severity=HackEventSeverity.high,
        publisher="FBI IC3",
    )


def fetch_cisa(*, since: datetime, offline: bool = False) -> list[HackEvent]:
    """Fetch CISA cybersecurity advisories (RSS, no auth).

    Only crypto-relevant advisories are kept — most CISA output concerns
    operational-technology and critical-infrastructure, not digital assets.
    """
    if offline or _is_offline():
        return _offline_cisa_fixture()
    return _rss_to_events(
        url=_CISA_RSS, since=since,
        source=HackEventSource.cisa_alert,
        severity=HackEventSeverity.high,
        publisher="CISA",
    )


def fetch_rekt(*, since: datetime, offline: bool = False) -> list[HackEvent]:
    """rekt.news postmortems — NO live implementation, by necessity.

    rekt.news' feed is down at the origin: /feed/, /rss, /feed.xml and
    /rss.xml all return HTTP 500 (re-probed 2026-07-28). There is nothing to
    parse, so this returns empty rather than shipping a parser for a response
    that never arrives. Restore by pointing ``_REKT_RSS`` at a working path and
    calling ``_rss_to_events`` — the generic machinery is ready.
    """
    if offline or _is_offline():
        return _offline_rekt_fixture()
    log.info(
        "hack_tracker.rekt: upstream feed returns HTTP 500 (no live source); "
        "returning empty",
    )
    return []


# ---- internals ---- #


def _is_offline() -> bool:
    from recupero._common import env_truthy
    return env_truthy("RECUPERO_HACK_TRACKER_OFFLINE")


def _fetch_url(url: str) -> bytes | None:
    """GET ``url`` with a timeout and a hard body cap. None on any failure.

    stdlib urllib by design (see module docstring) so the digest cron carries
    no extra dependency. Reads at most ``_MAX_FEED_BYTES + 1`` so an endless
    or hostile response can't exhaust memory.
    """
    import urllib.error
    import urllib.request

    req = urllib.request.Request(  # noqa: S310 — fixed https:// constants above
        url, headers={"User-Agent": _USER_AGENT, "Accept": "application/rss+xml, application/xml, text/xml"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:  # noqa: S310
            if getattr(resp, "status", 200) != 200:
                log.warning("hack_tracker: %s returned HTTP %s", url, resp.status)
                return None
            body = resp.read(_MAX_FEED_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.warning("hack_tracker: fetch %s failed: %s", url, exc)
        return None
    if len(body) > _MAX_FEED_BYTES:
        log.warning(
            "hack_tracker: %s exceeded the %d-byte cap; skipping "
            "(feed not parsed)", url, _MAX_FEED_BYTES,
        )
        return None
    return body


def _parse_rss_items(raw: bytes, *, url: str) -> list[dict[str, str]]:
    """Parse RSS 2.0 ``<item>`` elements into plain dicts. [] on any problem.

    Security: ``xml.etree.ElementTree`` is documented as vulnerable to
    entity-expansion attacks (billion laughs / quadratic blowup). Rather than
    add a defusedxml dependency, reject any document carrying a DOCTYPE or
    ENTITY declaration outright — legitimate RSS never needs one, and without
    entity declarations neither attack is expressible.
    """
    import xml.etree.ElementTree as ET

    head = raw[:4096].lstrip().lower()
    if b"<!doctype" in head or b"<!entity" in raw[:65536].lower():
        log.warning(
            "hack_tracker: %s declares a DOCTYPE/ENTITY — refusing to parse "
            "(entity-expansion hardening)", url,
        )
        return []
    try:
        root = ET.fromstring(raw)  # noqa: S314 — DOCTYPE/ENTITY rejected above
    except ET.ParseError as exc:
        log.warning("hack_tracker: %s is not parseable XML: %s", url, exc)
        return []

    items: list[dict[str, str]] = []
    for node in root.iter("item"):
        if len(items) >= _MAX_ITEMS_PER_FEED:
            log.info(
                "hack_tracker: %s truncated at %d items (feed had more)",
                url, _MAX_ITEMS_PER_FEED,
            )
            break
        row: dict[str, str] = {}
        for tag in ("title", "link", "description", "pubDate", "guid"):
            el = node.find(tag)
            row[tag] = (el.text or "").strip() if el is not None and el.text else ""
        if not row["title"] and not row["link"]:
            continue
        items.append(row)
    return items


def _rss_datetime(value: str) -> datetime | None:
    """Parse an RSS pubDate to a tz-aware UTC datetime. None if unparseable.

    IC3 emits offsets as ``-04:00``, which ``parsedate_to_datetime`` silently
    parses to a NAIVE datetime (the offset is dropped). The model coerces naive
    values to UTC, which would silently shift every IC3 timestamp by its
    offset, so normalize ``+HH:MM`` to ``+HHMM`` first.
    """
    import re
    from email.utils import parsedate_to_datetime

    s = (value or "").strip()
    if not s:
        return None
    s = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", s)
    try:
        dt = parsedate_to_datetime(s)
    except (TypeError, ValueError, OverflowError):
        return None
    if dt.tzinfo is None:
        # Still naive after normalization — assume UTC rather than drop the
        # item, but say so, since a wrong offset is a silent evidence error.
        log.debug("hack_tracker: pubDate %r had no offset; assuming UTC", value)
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _is_crypto_relevant(*texts: str) -> bool:
    """True if any term in ``_CRYPTO_TERMS`` appears in the given text."""
    blob = " ".join(t for t in texts if t).lower()
    return any(term in blob for term in _CRYPTO_TERMS)


def _rss_to_events(
    *,
    url: str,
    since: datetime,
    source: HackEventSource,
    severity: HackEventSeverity,
    publisher: str,
) -> list[HackEvent]:
    """Fetch + parse one RSS feed into crypto-relevant HackEvents.

    Never raises: every failure path logs and yields a shorter list, because a
    single unavailable government feed must not fail the whole digest.
    """
    raw = _fetch_url(url)
    if raw is None:
        return []
    items = _parse_rss_items(raw, url=url)
    if not items:
        return []

    out: list[HackEvent] = []
    n_old = n_offtopic = n_bad = 0
    for row in items:
        title = row["title"]
        desc = row["description"]
        published = _rss_datetime(row["pubDate"])
        if published is not None and published < since:
            n_old += 1
            continue
        if not _is_crypto_relevant(title, desc):
            n_offtopic += 1
            continue
        link = row["link"] or url
        summary = desc or (
            f"{publisher} advisory. The feed carries no summary text; open the "
            "source link for the full advisory."
        )
        try:
            out.append(HackEvent(
                # guid is the feed's own stable id; fall back to the link so
                # dedup still works on feeds that omit it.
                content_hash=_hash(source.value, row["guid"] or link, title),
                source=source,
                source_url=link,
                observed_at=datetime.now(UTC),
                incident_time=published,
                title=title[:200],
                summary=summary[:2000],
                severity=severity,
                tags=[source.value],
                has_identifiable_victim=False,
            ))
        except (ValueError, TypeError) as exc:
            # Model validation rejected it (e.g. link host not allowlisted).
            n_bad += 1
            log.debug("hack_tracker: %s item rejected: %s", publisher, exc)

    log.info(
        "hack_tracker.%s: %d event(s) kept (%d older than window, "
        "%d not crypto-relevant, %d rejected by validation)",
        source.value, len(out), n_old, n_offtopic, n_bad,
    )
    return out


def _hash(*parts: str) -> str:
    blob = "|".join(parts).encode()
    return hashlib.sha256(blob).hexdigest()


# ---- offline fixtures ---- #


def _offline_ofac_fixture() -> list[HackEvent]:
    """One illustrative OFAC SDN cyber addition."""
    now = datetime.now(UTC)
    return [
        HackEvent(
            content_hash=_hash("ofac_fixture", "DPRK-related crypto designations"),
            source=HackEventSource.ofac_sdn,
            source_url=_OFAC_RECENT_ACTIONS,
            observed_at=now,
            incident_time=now - timedelta(hours=6),
            title=(
                "[FIXTURE] OFAC SDN update — DPRK-linked crypto "
                "addresses added"
            ),
            summary=(
                "Fixture data. Treasury adds 5 EVM addresses + 2 Bitcoin "
                "addresses tied to DPRK cyber operations to the SDN list. "
                "All US persons + entities prohibited from transacting. "
                "Recommended: bulk-add to high_risk.json + re-screen "
                "any case touching these addresses in the last 90 days."
            ),
            severity=HackEventSeverity.critical,
            chains_mentioned=["ethereum", "bitcoin"],
            attributed_actor="Lazarus / DPRK",
            tags=["ofac", "sanctioned"],
            has_identifiable_victim=False,
        ),
    ]


def _offline_ic3_fixture() -> list[HackEvent]:
    """One illustrative IC3 PSA."""
    now = datetime.now(UTC)
    return [
        HackEvent(
            content_hash=_hash("ic3_fixture", "fraud surge"),
            source=HackEventSource.ic3_alert,
            source_url=_IC3_RSS,
            observed_at=now,
            incident_time=now - timedelta(days=1),
            title=(
                "[FIXTURE] FBI IC3: surge in fraudulent crypto-recovery "
                "services targeting prior victims"
            ),
            summary=(
                "Fixture data. PSA warning consumers about scammers "
                "impersonating recovery firms via Reddit DMs + cold "
                "calls. Victims of prior thefts are re-targeted with "
                "promises of recovery for upfront 'gas fees.' This "
                "directly affects Recupero's market — operator should "
                "monitor for impersonators using Recupero's name."
            ),
            severity=HackEventSeverity.high,
            tags=["phishing", "recovery_scam"],
            has_identifiable_victim=True,
            victim_hint="Prior crypto theft victims",
        ),
    ]


def _offline_cisa_fixture() -> list[HackEvent]:
    """One illustrative CISA advisory."""
    now = datetime.now(UTC)
    return [
        HackEvent(
            content_hash=_hash("cisa_fixture", "DPRK cyber alert"),
            source=HackEventSource.cisa_alert,
            source_url=_CISA_RSS,
            observed_at=now,
            incident_time=now - timedelta(days=2),
            title=(
                "[FIXTURE] CISA joint advisory: DPRK crypto-theft "
                "TTPs targeting DeFi protocols"
            ),
            summary=(
                "Fixture data. Joint advisory from CISA / NSA / Treasury "
                "documenting recent DPRK-attributed TTPs against DeFi: "
                "social engineering of developers, supply-chain attacks "
                "on web-end JS deps, post-compromise USDC/USDT routing "
                "through cross-chain bridges to Tron."
            ),
            severity=HackEventSeverity.high,
            tags=["dprk", "supply_chain", "defi_exploit"],
            has_identifiable_victim=False,
        ),
    ]


def _offline_rekt_fixture() -> list[HackEvent]:
    """Empty — rekt-style postmortems are surfaced through the X feed
    fixture instead. Real rekt RSS parser ships in v0.20.1."""
    return []
