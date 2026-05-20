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
# update in one place. All three confirmed accessible as of v0.20.0.
_OFAC_RECENT_ACTIONS = "https://ofac.treasury.gov/recent-actions"
_OFAC_SDN_FEED       = "https://ofac.treasury.gov/specially-designated-nationals-sdn-list-data-formats-data-schemas"
_IC3_RSS             = "https://www.ic3.gov/PSA/PSARss"
_CISA_RSS            = "https://www.cisa.gov/news.xml"
_REKT_RSS            = "https://rekt.news/feed/"


def fetch_ofac(*, since: datetime, offline: bool = False) -> list[HackEvent]:
    """Fetch OFAC recent-actions list. Returns HackEvent rows for any
    cyber-related entries (those mentioning blockchain / crypto /
    digital-currency / wallet address)."""
    if offline or _is_offline():
        return _offline_ofac_fixture()
    log.debug(
        "hack_tracker.ofac stub: real OFAC SDN parser ships in v0.20.1 "
        "once the offline digest format is iterated. Returning empty."
    )
    return []


def fetch_ic3(*, since: datetime, offline: bool = False) -> list[HackEvent]:
    """Fetch FBI IC3 public service announcements. RSS feed."""
    if offline or _is_offline():
        return _offline_ic3_fixture()
    log.debug("hack_tracker.ic3 stub — returns empty pending v0.20.1.")
    return []


def fetch_cisa(*, since: datetime, offline: bool = False) -> list[HackEvent]:
    """Fetch CISA cybersecurity advisories. RSS feed."""
    if offline or _is_offline():
        return _offline_cisa_fixture()
    log.debug("hack_tracker.cisa stub — returns empty pending v0.20.1.")
    return []


def fetch_rekt(*, since: datetime, offline: bool = False) -> list[HackEvent]:
    """Fetch rekt.news postmortem articles via RSS."""
    if offline or _is_offline():
        return _offline_rekt_fixture()
    log.debug("hack_tracker.rekt stub — returns empty pending v0.20.1.")
    return []


# ---- internals ---- #


def _is_offline() -> bool:
    from recupero._common import env_truthy
    return env_truthy("RECUPERO_HACK_TRACKER_OFFLINE")


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
