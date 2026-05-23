"""``recupero-ops hack-tracker`` subcommand.

Runs the aggregator + prints a ranked daily digest to stdout. Designed
for ops-side ad-hoc invocation while we iterate on the digest format
during the feature-flagged build phase. NOT wired into any cron yet.

Usage:
    # Iterate on digest format using offline fixtures (no API quota)
    RECUPERO_HACK_TRACKER_OFFLINE=1 \\
        recupero-ops hack-tracker daily

    # Live mode (requires the feature flag + per-source API keys)
    RECUPERO_HACK_TRACKER_ENABLED=1 \\
    RECUPERO_X_BEARER_TOKEN=... \\
        recupero-ops hack-tracker daily

When `--format=json` is passed, writes the full DailyDigest as JSON to
stdout — useful for piping into operator dashboards or test fixtures.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime, timedelta

from recupero.hack_tracker.aggregator import DailyDigest, run_daily_digest

log = logging.getLogger(__name__)


def run(*, hours: int = 24, output_format: str = "text") -> int:
    """Run the daily digest. Returns 0 on success, 2 on configuration
    errors (e.g., feature-flag not set in non-offline mode).

    Adversarial-input hardening (v0.20.1):
      * ``hours`` is clamped to ``[1, _MAX_HOURS_WINDOW]`` so neither
        ``hours=-1`` (since=future) nor ``hours=10**18`` (timedelta
        OverflowError) can blow up the digest.
    """
    # Clamp the lookback window. A negative value would compute a
    # `since` in the future (no events would match). A huge value
    # overflows `timedelta` with OverflowError.
    try:
        hours_int = int(hours)
    except (TypeError, ValueError):
        hours_int = 24
    if hours_int < 1:
        hours_int = 1
    if hours_int > _MAX_HOURS_WINDOW:
        hours_int = _MAX_HOURS_WINDOW

    since = datetime.now(UTC) - timedelta(hours=hours_int)
    try:
        digest = run_daily_digest(since=since)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if output_format == "json":
        _print_json(digest)
    else:
        # Unknown formats fall back to text rather than crashing.
        _print_text(digest)
    return 0


# Upper bound on the daily-digest lookback window. 10 years covers
# every reasonable operator use case (typical use is hours=24, ad-hoc
# investigations up to a month). Anything beyond this is almost
# certainly attacker / accidental input.
_MAX_HOURS_WINDOW = 24 * 365 * 10


def _print_text(digest: DailyDigest) -> None:
    """Human-readable digest. Header → top-20 events → per-source counts."""
    print("=" * 78)
    print("RECUPERO HACK-TRACKER DAILY DIGEST")
    print(f"Generated: {digest.generated_at.isoformat()}")
    print(
        f"Window:    {digest.window_start.isoformat()} → "
        f"{digest.window_end.isoformat()}"
    )
    print(f"Events:    {digest.events_total}")
    print("=" * 78)
    print()
    print("BY SEVERITY:")
    for sev, count in sorted(digest.events_by_severity.items()):
        print(f"  {sev:10s} {count:4d}")
    print()
    print("BY SOURCE:")
    for src, count in sorted(digest.events_by_source.items()):
        print(f"  {src:20s} {count:4d}")
    print()
    print("TOP EVENTS:")
    print("-" * 78)
    if not digest.top_events:
        print("  (no events)")
    for i, ev in enumerate(digest.top_events, 1):
        marker = "MARKETING" if ev.has_identifiable_victim else ""
        print(f"#{i:2d}  [{ev.severity.value.upper():8s}] {ev.source.value:18s}  {marker}")
        print(f"     {ev.title[:150]}")
        if ev.attributed_actor:
            print(f"     ACTOR: {ev.attributed_actor}")
        if ev.chains_mentioned:
            print(f"     CHAINS: {', '.join(ev.chains_mentioned)}")
        if ev.addresses:
            preview = ", ".join(ev.addresses[:3])
            extra = "" if len(ev.addresses) <= 3 else f" (+{len(ev.addresses) - 3} more)"
            print(f"     ADDRS:  {preview}{extra}")
        print(f"     URL: {ev.source_url}")
        print()


def _print_json(digest: DailyDigest) -> None:
    """JSON dump for piping into dashboards / fixtures."""
    payload = {
        "generated_at": digest.generated_at.isoformat(),
        "window_start": digest.window_start.isoformat(),
        "window_end": digest.window_end.isoformat(),
        "events_total": digest.events_total,
        "events_by_source": digest.events_by_source,
        "events_by_severity": digest.events_by_severity,
        "top_events": [
            ev.model_dump(mode="json") for ev in digest.top_events
        ],
    }
    json.dump(payload, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


__all__ = ("run",)
