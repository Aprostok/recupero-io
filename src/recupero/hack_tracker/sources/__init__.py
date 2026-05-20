"""Per-source scrapers for the hack-tracker.

Each scraper implements ``fetch(*, since: datetime, offline: bool) ->
list[HackEvent]``. Scrapers MUST:

  * Return synthetic / cached data when ``offline=True`` so the
    aggregator can be exercised without burning API quotas in dev.
  * Catch + log all transient errors; never raise to the aggregator
    (a single source failing must not poison the daily digest).
  * Cap their return list at ~50 events per call to keep memory
    bounded for the operator's daily digest.
"""

from __future__ import annotations

__all__ = ()
