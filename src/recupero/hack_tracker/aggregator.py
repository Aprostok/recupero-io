"""Cross-source aggregator. Dedupes, ranks, writes the daily digest.

Public entry:
  * ``run_daily_digest(*, since, offline) -> DailyDigest``
    Pulls from every source, dedupes by content_hash, ranks by
    (severity_weight × source_weight × recency_decay), returns a
    sorted DailyDigest dataclass the CLI / operator can render.

Feature flag:
  * ``RECUPERO_HACK_TRACKER_ENABLED=1`` is required to run the live
    fetchers. Without it, ``run_daily_digest`` raises so an accidental
    cron invocation can't burn API quotas. The CLI command checks the
    flag and exits with a clear "set RECUPERO_HACK_TRACKER_ENABLED=1
    to opt in" message.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from recupero._common import env_truthy
from recupero.hack_tracker.models import (
    HackEvent,
    HackEventSeverity,
    HackEventSource,
)
from recupero.hack_tracker.sources import government_feeds, x_feed

log = logging.getLogger(__name__)


# Source weight — higher = more credible / more operator-relevant.
# OFAC at the top because a sanctions designation literally changes
# the risk classification of every Recupero case. PeckShield + rekt
# tied for highest editorial reputation.
_SOURCE_WEIGHT: dict[HackEventSource, float] = {
    HackEventSource.ofac_sdn:      10.0,
    HackEventSource.ofac_advisory:  9.0,
    HackEventSource.cisa_alert:     8.0,
    HackEventSource.ic3_alert:      8.0,
    HackEventSource.x_peckshield:   7.0,
    HackEventSource.rekt:           7.0,
    HackEventSource.x_slowmist:     6.5,
    HackEventSource.x_certik:       6.0,
    HackEventSource.x_beosin:       6.0,
    HackEventSource.x_blocksec:     6.0,
    HackEventSource.x_other:        3.0,
    HackEventSource.manual:         5.0,
}

_SEVERITY_WEIGHT: dict[HackEventSeverity, float] = {
    HackEventSeverity.critical: 10.0,
    HackEventSeverity.high:      6.0,
    HackEventSeverity.medium:    3.0,
    HackEventSeverity.low:       1.0,
    HackEventSeverity.info:      0.5,
}


@dataclass
class DailyDigest:
    """One day's worth of aggregated events, ranked for the operator.

    Field ordering matches the operator's reading priority: top
    section = highest-rank events; then a per-source breakdown for
    completeness.
    """

    generated_at: datetime
    window_start: datetime
    window_end: datetime
    events_total: int
    events_by_source: dict[str, int] = field(default_factory=dict)
    events_by_severity: dict[str, int] = field(default_factory=dict)
    top_events: list[HackEvent] = field(default_factory=list)  # top 20
    all_events: list[HackEvent] = field(default_factory=list)


def run_daily_digest(
    *,
    since: datetime | None = None,
    offline: bool | None = None,
) -> DailyDigest:
    """Pull every source, dedupe + rank, return the digest.

    ``since`` defaults to the last 24h. ``offline`` defaults to the
    value of ``RECUPERO_HACK_TRACKER_OFFLINE`` env var; explicit
    True/False overrides.

    Raises ``RuntimeError`` if neither feature-flag nor offline-mode
    is set — we refuse to run the live fetchers without an explicit
    opt-in to avoid surprising API quota burns.
    """
    now = datetime.now(UTC)
    since = since or (now - timedelta(hours=24))

    # Resolve offline mode
    if offline is None:
        offline = env_truthy("RECUPERO_HACK_TRACKER_OFFLINE")

    # Feature-flag guard
    if not offline and not env_truthy("RECUPERO_HACK_TRACKER_ENABLED"):
        raise RuntimeError(
            "hack_tracker live mode requires "
            "RECUPERO_HACK_TRACKER_ENABLED=1. To exercise the digest "
            "format without external calls, set "
            "RECUPERO_HACK_TRACKER_OFFLINE=1 instead."
        )

    # Collect from every source. None of the source-fetchers raise;
    # they log + return empty on transient errors. A misconfigured
    # source must not poison the whole digest.
    log.info(
        "hack_tracker: running daily digest (offline=%s, since=%s)",
        offline, since.isoformat(),
    )

    events: list[HackEvent] = []
    events.extend(x_feed.fetch(since=since, offline=offline))
    events.extend(government_feeds.fetch_ofac(since=since, offline=offline))
    events.extend(government_feeds.fetch_ic3(since=since, offline=offline))
    events.extend(government_feeds.fetch_cisa(since=since, offline=offline))
    events.extend(government_feeds.fetch_rekt(since=since, offline=offline))

    # Dedupe by content_hash. Keep the first occurrence (deterministic
    # since fetch order is fixed).
    seen: set[str] = set()
    deduped: list[HackEvent] = []
    for ev in events:
        if ev.content_hash in seen:
            continue
        seen.add(ev.content_hash)
        deduped.append(ev)

    # Rank
    deduped.sort(key=_rank_key, reverse=True)
    top_n = deduped[:20]

    # Per-source / per-severity histograms (operator finds these
    # useful for trend monitoring across days)
    by_source: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for ev in deduped:
        by_source[ev.source.value] = by_source.get(ev.source.value, 0) + 1
        by_severity[ev.severity.value] = by_severity.get(ev.severity.value, 0) + 1

    return DailyDigest(
        generated_at=now,
        window_start=since,
        window_end=now,
        events_total=len(deduped),
        events_by_source=by_source,
        events_by_severity=by_severity,
        top_events=top_n,
        all_events=deduped,
    )


def _rank_key(ev: HackEvent) -> float:
    """Composite rank score for digest sorting.

    Score = severity_weight × source_weight × recency_decay
        + (5.0 if has_identifiable_victim else 0.0)

    `has_identifiable_victim` is the marketing-priority kicker —
    events that point at a specific victim (e.g., "DEX-X lost $50M")
    are higher-leverage outreach signals than generic advisories.
    """
    sev = _SEVERITY_WEIGHT.get(ev.severity, 1.0)
    src = _SOURCE_WEIGHT.get(ev.source, 1.0)
    # Recency: full weight if observed in last 6 hours, decays linearly
    # to 0.25 weight at 7 days, then floor at 0.25.
    now = datetime.now(UTC)
    age_h = (now - ev.observed_at).total_seconds() / 3600.0
    if age_h < 6:
        recency = 1.0
    elif age_h < 168:  # 7 days
        recency = 1.0 - 0.75 * ((age_h - 6) / (168 - 6))
    else:
        recency = 0.25
    kicker = 5.0 if ev.has_identifiable_victim else 0.0
    return sev * src * recency + kicker
