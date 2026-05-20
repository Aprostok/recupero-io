"""Daily hack-tracker — feed aggregator for marketing intelligence.

Scans public sources (X / Twitter, government feeds, hack-watcher blogs)
for newly reported crypto thefts, hacks, and OFAC actions. Output is a
ranked daily digest the operator can use for:

  * Marketing outreach to fresh victims while they're actively
    searching for help.
  * Trend monitoring (new attack vectors, vendor incidents, regulator
    actions) that should inform Recupero's playbook.
  * Compliance posture (OFAC additions, FinCEN advisories, sanctioned
    address publications) that change which addresses we mark
    high-risk.

**Status: FEATURE-FLAGGED OFF (build phase only).**

This module is wired but does NOT auto-run anywhere in production.
To enable in dev:

    RECUPERO_HACK_TRACKER_ENABLED=1 recupero-ops hack-tracker daily

The scrapers themselves return synthetic data when network is disabled
(``RECUPERO_HACK_TRACKER_OFFLINE=1``) so we can iterate on the digest
format without burning API quotas during development.

Sources covered (each in its own submodule):

  * ``recupero.hack_tracker.sources.x_feed``       — X (Twitter) handles:
        @PeckShieldAlert / @CertiK / @SlowMist_Team / @beosin / @BlockSecTeam
        — the four canonical hack-watcher accounts. Read-only via
        official X API v2 (token via RECUPERO_X_BEARER_TOKEN).

  * ``recupero.hack_tracker.sources.ofac_feed``    — OFAC SDN list +
        cyber-related advisories. Sourced from treasury.gov's public XML
        publishing endpoint (no API key required, polite rate limit).

  * ``recupero.hack_tracker.sources.ic3_alerts``   — FBI/IC3 public
        service announcements + cyber-fraud alerts. RSS feed at
        ic3.gov.

  * ``recupero.hack_tracker.sources.cisa_alerts``  — CISA cybersecurity
        advisories. RSS feed at cisa.gov.

  * ``recupero.hack_tracker.sources.rekt_feed``    — rekt.news (the
        industry-canonical hack-postmortem blog). RSS feed at
        rekt.news/feed.

Each source returns a normalized ``HackEvent`` dataclass; the
aggregator dedupes by content hash, ranks by recency × source-weight,
and emits a daily digest HTML + JSON. The digest is the artifact
operators consume; this module does NOT directly send marketing emails
(that's a separate, deliberately-manual operator step).
"""

from __future__ import annotations

from recupero.hack_tracker.models import HackEvent, HackEventSource

__all__ = ("HackEvent", "HackEventSource")
