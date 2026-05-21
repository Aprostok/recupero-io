"""Cron-driven subscription poller for live address monitoring (v0.14.6).

The v0.13.2 monitoring module shipped the database schema, the
trigger evaluator, and the webhook dispatcher — but no worker stage
that actually iterates active subscriptions on a schedule. This
module is that stage.

Operator workflow
-----------------

1. Operator (or admin UI) creates a row in
   ``public.monitoring_subscriptions``:

   .. code-block:: sql

      INSERT INTO public.monitoring_subscriptions
        (address, chain, created_by, trigger_type, threshold_usd,
         webhook_url)
      VALUES
        ('0xperp...', 'ethereum', 'alec@recupero.io',
         'movement_above_usd', 50000.00, 'https://hooks.example/');

2. Cron runs ``recupero-worker monitor-tick`` every N minutes
   (recommended: every 5 minutes for high-priority cases, every 30
   for routine compliance).

3. Each tick:

   a. Pulls active subscriptions ordered by last_polled_at NULLS
      FIRST (so brand-new subs get bootstrapped immediately).
   b. For each, calls the appropriate chain adapter to fetch
      recent activity above the cursor (last_observed_tx_hash).
   c. Evaluates each observation against the trigger
      (any_movement / movement_above_usd / balance_drop / ofac_contact).
   d. Fires the webhook for trigger matches (with optional HMAC
      signing), records the attempt in ``monitoring_alerts``.
   e. Advances the cursor regardless of whether the trigger
      fired — so the same tx isn't evaluated twice.

Per-tick guardrails
-------------------

  * Max subscriptions processed per tick: 50 (env-tunable). Prevents
    a backlog from starving newer subs.
  * Max activity history per subscription: 25 events. Protects against
    a runaway feed.
  * Cron-friendly: returns exit code 0 on success, 1 on DB
    unavailability, 2 on partial-success-with-errors. Cron alerts
    on non-zero.

Out of scope for v0.14.6
------------------------

  * Adapter-specific activity fetchers — this module currently
    supports EVM via Etherscan. Tron and Bitcoin poller adapters
    are queued for v0.14.7. The trigger evaluator (v0.13.2) is
    chain-agnostic, only the activity fetch is per-chain.
  * Backfilling history for newly-created subs — current behavior
    is "bookmark the newest tx and don't alert on past activity"
    (per evaluate_all_activities). Alerting on history is queued.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from recupero._common import db_connect

log = logging.getLogger(__name__)


# Per-tick guardrails. Tunable via env.
_MAX_SUBSCRIPTIONS_PER_TICK = int(
    os.environ.get("RECUPERO_MONITOR_MAX_SUBS_PER_TICK", "50")
)
_MAX_ACTIVITY_PER_SUB = int(
    os.environ.get("RECUPERO_MONITOR_MAX_ACTIVITY_PER_SUB", "25")
)


@dataclass
class MonitorTickResult:
    """Summary of one tick's work — what the cron logs / Prometheus
    metrics will surface."""
    subscriptions_polled: int
    activities_evaluated: int
    alerts_fired: int
    alerts_succeeded: int
    alerts_failed: int
    errors: list[str]

    @property
    def ok(self) -> bool:
        # v0.16.8 (round-9 worker-resilience HIGH): a tick is OK iff
        # every fired alert succeeded AND no errors were logged.
        # Pre-v0.16.8 the property was just
        # `alerts_fired == alerts_succeeded`. When the subscription
        # fetch itself failed (returned early with an error appended
        # to `errors`), `alerts_fired == alerts_succeeded == 0` was
        # True, so the cron exited 0 and the operator saw a healthy
        # tick when the DB was actually down. Including `errors` in
        # the predicate makes the failure visible.
        return (
            self.alerts_fired == self.alerts_succeeded
            and not self.errors
        )


def run_monitor_tick(
    dsn: str,
    *,
    max_subscriptions: int | None = None,
    fetch_activities_fn: Any = None,
) -> MonitorTickResult:
    """One cron-driven monitoring tick.

    Args:
      dsn: SUPABASE_DB_URL.
      max_subscriptions: per-tick cap (default 50).
      fetch_activities_fn: testing seam — a callable that takes
        ``(subscription, chain) -> list[ObservedActivity]``. In
        production this dispatches to the appropriate chain adapter;
        tests inject a synthetic version to avoid network calls.

    Returns:
      MonitorTickResult with counters + any per-sub errors.
    """
    cap = max_subscriptions or _MAX_SUBSCRIPTIONS_PER_TICK
    result = MonitorTickResult(
        subscriptions_polled=0,
        activities_evaluated=0,
        alerts_fired=0,
        alerts_succeeded=0,
        alerts_failed=0,
        errors=[],
    )

    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError:  # pragma: no cover
        result.errors.append("psycopg not installed")
        return result

    # PUNISH-B W-2 + RIGOR-1: atomic claim via UPDATE-FROM-SELECT-FOR-
    # UPDATE-SKIP-LOCKED-RETURNING. Pre-RIGOR-1 the SELECT carried
    # FOR UPDATE SKIP LOCKED, but the row-lock was released as soon
    # as the SELECT's transaction closed (just one statement later);
    # dispatch + cursor UPDATE happened in subsequent SHORT
    # transactions, by which time the lock was gone and a second
    # cron instance could re-claim the same rows. The source-level
    # guard ("FOR UPDATE SKIP LOCKED in source") was true; the race
    # was not closed. tests/integration/test_real_concurrent_races.py
    # caught it under 2-4 thread contention.
    #
    # New shape: a single statement atomically locks, advances
    # last_polled_at to NOW() (the "claim mark"), and RETURNs the
    # claimed rows. A second concurrent cron sees those rows now
    # have a recent last_polled_at and the WHERE filter
    # (last_polled_at < NOW() - INTERVAL '30 seconds') excludes
    # them. The 30-second claim TTL is the worker-death recovery
    # window — if this tick crashes mid-dispatch, the next cron
    # picks the row up after 30s.
    #
    # PUNISH-B W-3: the post-dispatch update_sql still filters
    # status='active' so a partner DELETE-mid-poll (status →
    # 'deleted') doesn't get its cursor rewritten. The
    # test_real_concurrent_races.py W-3 test exercises this
    # against real Postgres.
    claim_sql = """
        UPDATE public.monitoring_subscriptions s
           SET last_polled_at = NOW()
          FROM (
            SELECT id FROM public.monitoring_subscriptions
             WHERE status = 'active'
               AND (expires_at IS NULL OR expires_at > NOW())
               AND (last_polled_at IS NULL
                    OR last_polled_at < NOW() - INTERVAL '30 seconds')
             ORDER BY last_polled_at NULLS FIRST, created_at ASC
             LIMIT %(cap)s
             FOR UPDATE SKIP LOCKED
          ) c
         WHERE s.id = c.id
        RETURNING
            s.id, s.address, s.chain, s.trigger_type, s.threshold_usd,
            s.webhook_url, s.webhook_secret, s.last_observed_tx_hash,
            s.last_polled_at,
            COALESCE(s.alert_channels, ARRAY['webhook']::TEXT[]) AS alert_channels,
            s.alert_email,
            s.case_id, s.investigation_id;
    """
    # NOTE: last_polled_at is set by the claim above. The
    # post-dispatch UPDATE only records the cursor + last_alerted_at.
    # COALESCE on cursor: keep prior value when this tick produced
    # no new cursor (no activities to evaluate).
    update_sql = """
        UPDATE public.monitoring_subscriptions
           SET last_observed_tx_hash = COALESCE(%(cursor)s, last_observed_tx_hash),
               last_alerted_at       = COALESCE(%(alerted)s, last_alerted_at)
         WHERE id = %(id)s
           AND status = 'active';
    """

    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            cur.execute(claim_sql, {"cap": cap})
            rows = list(cur.fetchall())
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"subscription fetch failed: {exc}")
        return result

    # v0.18.4 (round-11 worker-MED-039): clear per-tick adapter
    # cache at the start so we don't reuse stale adapter state
    # across ticks. The close-on-tick-end is in a `finally` below.
    _reset_adapter_cache()

    for row in rows:
        sub_id = row["id"]
        try:
            sub = _row_to_subscription(row)
            activities = _resolve_activities(sub, row["chain"], fetch_activities_fn)
            result.activities_evaluated += len(activities)
            result.subscriptions_polled += 1

            from recupero.monitoring.poller import evaluate_all_activities
            to_fire, new_cursor = evaluate_all_activities(sub, activities)

            # v0.18.4 (round-11 worker-HIGH-019): dispatch each alert
            # in its own try/except. Pre-v0.18.4 a single webhook
            # raising (rate limit, network error) propagated through
            # the loop AND skipped the cursor UPDATE below — the
            # next tick re-evaluated the SAME activities and re-fired
            # the SAME webhooks, double-alerting the recipient. Now:
            # per-activity isolation; cursor advances regardless.
            last_alerted_at: datetime | None = None
            for activity in to_fire:
                try:
                    fired = _dispatch_alert_for_activity(
                        sub=sub, activity=activity, dsn=dsn,
                    )
                except Exception as disp_exc:  # noqa: BLE001
                    log.warning(
                        "monitor_tick: alert dispatch raised for sub %s "
                        "activity %s: %s — continuing with next activity",
                        sub_id, getattr(activity, "tx_hash", "?"), disp_exc,
                    )
                    fired = False
                result.alerts_fired += 1
                if fired:
                    result.alerts_succeeded += 1
                    last_alerted_at = datetime.now(UTC)
                else:
                    result.alerts_failed += 1

            # Always update the cursor — even when no alerts fired or
            # when every alert dispatch failed — so the next tick
            # doesn't re-evaluate the same history.
            try:
                with db_connect(dsn) as conn, conn.cursor() as cur:
                    cur.execute(update_sql, {
                        "cursor": new_cursor or None,
                        "alerted": last_alerted_at,
                        "id": sub_id,
                    })
            except Exception as upd_exc:  # noqa: BLE001
                result.errors.append(
                    f"sub {sub_id} cursor update failed: {upd_exc}"
                )

        except Exception as sub_exc:  # noqa: BLE001
            # One bad subscription must not poison the whole tick.
            result.errors.append(
                f"sub {sub_id} eval failed: {sub_exc}"
            )
            log.warning("monitor_tick: sub %s failed: %s", sub_id, sub_exc)

    # v0.18.4 (round-11 worker-MED-039): release adapter FDs at end of tick.
    _reset_adapter_cache()
    return result


def _row_to_subscription(row: dict[str, Any]) -> Any:
    """Convert a monitoring_subscriptions row dict to a
    poller.Subscription dataclass.

    v0.21.0: surfaces alert_channels / alert_email / case_id /
    investigation_id so dispatch_all_channels can fan out the alert
    across webhook + email and the email body can deep-link to the
    case dashboard.
    """
    from recupero.monitoring.poller import Subscription
    threshold = row.get("threshold_usd")
    if threshold is not None and not isinstance(threshold, Decimal):
        threshold = Decimal(str(threshold))
    # alert_channels arrives as a Python list from psycopg's array
    # decoder. Freeze it into a tuple so the dataclass stays
    # hashable / immutable. Default ('webhook',) handles pre-v0.21.0
    # rows that haven't been migrated.
    raw_channels = row.get("alert_channels") or ["webhook"]
    if isinstance(raw_channels, str):
        # Tolerant of a CSV string in case the DB driver decodes
        # the TEXT[] as a literal string on some adapter versions.
        raw_channels = [c.strip() for c in raw_channels.strip("{}").split(",") if c.strip()]
    return Subscription(
        subscription_id=row["id"],
        address=row["address"],
        chain=row["chain"],
        trigger_type=row["trigger_type"],
        threshold_usd=threshold,
        webhook_url=row.get("webhook_url"),
        webhook_secret=row.get("webhook_secret"),
        last_observed_tx_hash=row.get("last_observed_tx_hash"),
        alert_channels=tuple(raw_channels),
        alert_email=row.get("alert_email"),
        case_id=row.get("case_id"),
        investigation_id=row.get("investigation_id"),
    )


def _resolve_activities(
    sub: Any,
    chain: str,
    fetch_activities_fn: Any = None,
) -> list[Any]:
    """Dispatch to the right activity fetcher for this subscription's
    chain. Returns a list of ObservedActivity records.

    Production path: ``_fetch_evm_activities(sub)`` (Etherscan).
    Test seam: caller can pass ``fetch_activities_fn`` to inject
    synthetic activities.

    Returns [] if the chain isn't supported yet.
    """
    if fetch_activities_fn is not None:
        return fetch_activities_fn(sub, chain)
    if chain in ("ethereum", "arbitrum", "base", "bsc", "polygon"):
        return _fetch_evm_activities(sub)
    log.info(
        "monitor_tick: chain %r not yet supported in the activity fetcher "
        "(returning empty); subscription %s",
        chain, sub.subscription_id,
    )
    return []


# v0.18.4 (round-11 worker-MED-039): per-chain adapter cache for the
# monitor_tick fan-out. Each tick handles N subscriptions across a
# small set of chains; the adapter construction is per-chain, not
# per-subscription. Cache lives for the duration of a single
# run_monitor_tick invocation (cleared by the caller via
# `_reset_adapter_cache` at tick boundary).
_ADAPTER_CACHE: dict[Any, Any] = {}


def _get_cached_adapter(chain_enum):
    """Build-or-fetch the adapter for `chain_enum`. Single
    config-load + single adapter per chain per tick."""
    cached = _ADAPTER_CACHE.get(chain_enum)
    if cached is not None:
        return cached
    from recupero.chains.base import ChainAdapter
    from recupero.config import load_config
    cfg, env = load_config()
    bundle = (cfg, env)
    adapter = ChainAdapter.for_chain(chain_enum, bundle)
    _ADAPTER_CACHE[chain_enum] = adapter
    return adapter


def _reset_adapter_cache() -> None:
    """Close + clear the per-tick adapter cache. Called by
    run_monitor_tick at tick boundary to release FDs."""
    for adapter in list(_ADAPTER_CACHE.values()):
        try:
            close = getattr(adapter, "close", None)
            if close is not None:
                close()
        except Exception:  # noqa: BLE001
            pass
    _ADAPTER_CACHE.clear()


def _fetch_evm_activities(sub: Any) -> list[Any]:
    """Best-effort EVM activity fetch via the existing chain adapter.

    Pulls recent ERC-20 transfers FROM the watched address (outflow
    monitoring). The result is normalized into ObservedActivity
    records for the trigger evaluator.

    DB-unavailable / API-unavailable → empty list (best-effort).
    """
    # Lazy imports to keep import cost low when monitor_tick isn't
    # in use.
    try:
        from recupero.chains.base import ChainAdapter
        from recupero.config import load_config
        from recupero.models import Chain
        from recupero.monitoring.poller import ObservedActivity
    except ImportError as e:  # pragma: no cover
        log.warning("activity fetcher imports failed: %s", e)
        return []

    # v0.18.4 (round-11 worker-MED-039): cache adapter per chain
    # across the tick. Pre-v0.18.4 every subscription rebuilt
    # `load_config()` + `ChainAdapter.for_chain(...)`. 50 EVM subs/
    # tick × 50ms setup = 2.5s of pure overhead per tick, plus FD
    # leaks since adapter.close() was never called.
    try:
        chain_enum = Chain(sub.chain)
        adapter = _get_cached_adapter(chain_enum)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "could not build adapter for chain %r sub %s: %s",
            sub.chain, sub.subscription_id, exc,
        )
        return []

    # Use start_block=0 so we get full history; the poller's
    # evaluate_all_activities cursor logic does the "since-last-tick"
    # filter, not the adapter.
    try:
        raw = adapter.fetch_erc20_outflows(sub.address, start_block=0)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "fetch_erc20_outflows failed for sub %s: %s",
            sub.subscription_id, exc,
        )
        return []

    # Newest-first ordering matches what evaluate_all_activities expects.
    # The adapter may not guarantee order; sort by block_number desc.
    raw = sorted(raw, key=lambda r: r.get("block_number", 0), reverse=True)[
        :_MAX_ACTIVITY_PER_SUB
    ]

    # v0.17.10 (round-10 forensic MED): canonical-key the watched
    # address compare so base58 Solana / Tron watchlist subscriptions
    # actually match the adapter's case-preserved "from" field.
    from recupero._common import canonical_address_key as _ck
    sub_addr_key = _ck(sub.address)
    out: list[Any] = []
    for r in raw:
        # Filter: only emit OUTBOUND from our watched address.
        if _ck(r.get("from") or "") != sub_addr_key:
            continue
        block_time = r.get("block_time")
        block_time_iso = (
            block_time.isoformat().replace("+00:00", "Z")
            if isinstance(block_time, datetime) else ""
        )
        # Approximate USD value — not all adapters fetch pricing;
        # for monitoring we accept None and let trigger rules handle.
        amount_usd = r.get("usd_value_at_tx")
        out.append(ObservedActivity(
            tx_hash=r.get("tx_hash", ""),
            block_time_iso=block_time_iso,
            amount_usd=Decimal(str(amount_usd)) if amount_usd is not None else None,
            direction="outflow",
            counterparty=r.get("to"),
            counterparty_label=None,
            counterparty_is_ofac=False,  # enriched at brief-time, not here
            explorer_url=r.get("explorer_url", ""),
        ))
    return out


def _dispatch_alert_for_activity(
    *,
    sub: Any,
    activity: Any,
    dsn: str,
) -> bool:
    """Fire all configured channels (webhook + email) + record one
    combined audit row. Returns True iff every attempted channel
    succeeded.

    v0.21.0: uses dispatch_all_channels instead of the legacy
    webhook-only dispatch_alert. Pre-v0.21.0 subscriptions
    (alert_channels=['webhook']) continue to behave identically —
    only the webhook columns of the audit row get populated.
    """
    from recupero.monitoring.dispatcher import (
        AlertPayload,
        dispatch_all_channels,
        record_alert_attempt,
    )

    payload = AlertPayload(
        subscription_id=sub.subscription_id,
        trigger_type=sub.trigger_type,
        address=sub.address,
        chain=sub.chain,
        tx_hash=activity.tx_hash,
        block_time_iso=activity.block_time_iso,
        amount_usd=activity.amount_usd,
        counterparty=activity.counterparty,
        counterparty_label=activity.counterparty_label,
        explorer_url=activity.explorer_url,
    )
    portal_base_url = os.environ.get("RECUPERO_PORTAL_BASE_URL", "").strip() or None
    combined = dispatch_all_channels(
        payload,
        subscription=sub,
        dsn=dsn,
        portal_base_url=portal_base_url,
    )
    # Audit-log the attempt regardless of success/failure.
    record_alert_attempt(dsn=dsn, payload=payload, result=combined)
    return combined.succeeded


# ---- CLI ---- #


def main() -> int:
    """``recupero-worker monitor-tick`` entry point. Returns exit code:
      0 — clean tick; alerts fired succeeded or none needed
      1 — DB unavailable / catastrophic
      2 — partial success (some alerts failed dispatch)
    """
    logging.basicConfig(level=logging.INFO)
    dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        print("ERROR: SUPABASE_DB_URL not set.", file=sys.stderr)
        return 1

    result = run_monitor_tick(dsn)
    print(
        f"monitor_tick: polled={result.subscriptions_polled} "
        f"activities={result.activities_evaluated} "
        f"alerts_fired={result.alerts_fired} "
        f"succeeded={result.alerts_succeeded} "
        f"failed={result.alerts_failed}"
    )
    if result.errors:
        for err in result.errors:
            print(f"  [warn] {err}")
    if not result.ok:
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = (
    "MonitorTickResult",
    "run_monitor_tick",
    "main",
)
