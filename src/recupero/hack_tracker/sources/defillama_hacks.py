"""DefiLlama curated hack dataset — the tracker's primary live source.

Why this exists: every other configured source turned out unusable as a live
crypto-hack feed (re-probed 2026-07-28).

  * OFAC recent-actions is HTML-only (no XML sibling).
  * rekt.news' feed returns HTTP 500 on every path.
  * CISA returns 403 to any server-side Python client (urllib AND httpx), while
    curl succeeds — a CDN client-fingerprint block. Defeating it would mean
    impersonating a browser, which we don't do.
  * IC3's RSS works but publishes roughly one crypto-relevant PSA per year.
  * The X feed needs a paid API tier AND its fetch is still a stub.

``https://api.llama.fi/hacks`` is free, unauthenticated, reachable from Python,
and purpose-built: ~600 records, each with a USD amount, date, chain,
classification and technique. That is an actual hack feed.

Attribution note: each upstream record carries a ``source`` link to an
arbitrary third-party write-up (tweet, blog, news post). Those hosts are NOT
added to the model's ``source_url`` allowlist — ``source_url`` cites
defillama.com, and the upstream link is carried as scrubbed summary text. The
allowlist keeps meaning "a host we trust to attribute to".

No feature flag of its own: the aggregator's ``RECUPERO_HACK_TRACKER_ENABLED``
gate already governs live fetches.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation

from recupero.hack_tracker.models import (
    HackEvent,
    HackEventSeverity,
    HackEventSource,
)

log = logging.getLogger(__name__)

_HACKS_URL = "https://api.llama.fi/hacks"
_CITATION_URL = "https://defillama.com/hacks"

_HTTP_TIMEOUT_S = 30
# The full dataset is ~170KB today. Cap well above that but far below anything
# that could exhaust memory if the endpoint ever misbehaves.
_MAX_BYTES = 8 * 1024 * 1024
# Bound how many records one call turns into events, newest first.
_MAX_EVENTS = 200

# Severity from USD loss. These are the operator-facing buckets already defined
# on HackEventSeverity: critical == 8-figure+, high == 7-figure, medium == 6.
_CRIT_USD = Decimal("10000000")   # $10M+
_HIGH_USD = Decimal("1000000")    # $1M+
_MED_USD = Decimal("100000")      # $100k+


def fetch(*, since: datetime, offline: bool = False) -> list[HackEvent]:
    """Fetch DefiLlama hacks with ``date`` at or after ``since``.

    Never raises — logs and returns a (possibly empty) list, so one dead source
    cannot fail the whole digest.
    """
    if offline or _is_offline():
        log.info("hack_tracker.defillama: offline mode — returning fixture")
        return _offline_fixture()

    rows = _fetch_rows()
    if rows is None:
        return []

    out: list[HackEvent] = []
    n_old = n_bad = 0
    # Newest first so the _MAX_EVENTS cap keeps the most recent hacks.
    for row in sorted(rows, key=_row_sort_key, reverse=True):
        if len(out) >= _MAX_EVENTS:
            log.info(
                "hack_tracker.defillama: stopped at the %d-event cap "
                "(dataset had %d rows)", _MAX_EVENTS, len(rows),
            )
            break
        occurred = _row_datetime(row)
        if occurred is None or occurred < since:
            n_old += 1
            continue
        ev = _row_to_event(row, occurred)
        if ev is None:
            n_bad += 1
            continue
        out.append(ev)

    log.info(
        "hack_tracker.defillama: %d event(s) kept (%d outside window, "
        "%d unusable)", len(out), n_old, n_bad,
    )
    return out


# ---- internals ---- #


def _is_offline() -> bool:
    from recupero._common import env_truthy
    return env_truthy("RECUPERO_HACK_TRACKER_OFFLINE")


def _fetch_rows() -> list[dict] | None:
    """GET the dataset. None on any failure (never raises)."""
    try:
        import httpx
    except ImportError:  # pragma: no cover — httpx is a base dependency
        log.warning("hack_tracker.defillama: httpx unavailable")
        return None
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT_S, follow_redirects=True) as c:
            resp = c.get(
                _HACKS_URL,
                headers={"User-Agent": "recupero-hack-tracker/1.0 (+https://recupero.io)"},
            )
        if resp.status_code != 200:
            log.warning(
                "hack_tracker.defillama: HTTP %s from %s",
                resp.status_code, _HACKS_URL,
            )
            return None
        if len(resp.content) > _MAX_BYTES:
            log.warning(
                "hack_tracker.defillama: response exceeded the %d-byte cap",
                _MAX_BYTES,
            )
            return None
        data = resp.json()
    except Exception as exc:  # noqa: BLE001 — transport / JSON / anything
        log.warning("hack_tracker.defillama: fetch failed: %s", exc)
        return None

    rows = data if isinstance(data, list) else None
    if rows is None and isinstance(data, dict):
        maybe = data.get("hacks")
        rows = maybe if isinstance(maybe, list) else None
    if rows is None:
        log.warning("hack_tracker.defillama: unexpected payload shape")
        return None
    return [r for r in rows if isinstance(r, dict)]


def _row_sort_key(row: dict) -> float:
    raw = row.get("date")
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


def _row_datetime(row: dict) -> datetime | None:
    """`date` is a unix timestamp (seconds). None if unusable."""
    raw = row.get("date")
    try:
        ts = float(raw)
    except (TypeError, ValueError):
        return None
    # Reject absurd stamps rather than letting them skew the ranker: anything
    # before Bitcoin existed or more than a year ahead is a bad record.
    if ts <= 1230768000 or ts > datetime.now(UTC).timestamp() + 31_536_000:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=UTC)
    except (OSError, OverflowError, ValueError):
        return None


def _loss_usd(row: dict) -> Decimal | None:
    """Upstream `amount` is USD. None when absent or nonsensical."""
    raw = row.get("amount")
    if raw is None:
        return None
    try:
        val = Decimal(str(raw))
    except (InvalidOperation, ValueError, TypeError):
        return None
    if not val.is_finite() or val < 0:
        return None
    return val


def _severity_for(loss: Decimal | None) -> HackEventSeverity:
    if loss is None:
        return HackEventSeverity.medium
    if loss >= _CRIT_USD:
        return HackEventSeverity.critical
    if loss >= _HIGH_USD:
        return HackEventSeverity.high
    if loss >= _MED_USD:
        return HackEventSeverity.medium
    return HackEventSeverity.low


def _row_to_event(row: dict, occurred: datetime) -> HackEvent | None:
    name = str(row.get("name") or "").strip()
    if not name:
        return None

    loss = _loss_usd(row)
    technique = str(row.get("technique") or "").strip()
    classification = str(row.get("classification") or "").strip()
    target = str(row.get("targetType") or "").strip()

    chains: list[str] = []
    raw_chain = row.get("chain")
    if isinstance(raw_chain, list):
        chains = [str(c).strip().lower() for c in raw_chain if str(c).strip()]
    elif raw_chain:
        chains = [str(raw_chain).strip().lower()]

    loss_txt = f"${loss:,.0f}" if loss is not None else "an undisclosed amount"
    title = f"{name} — {loss_txt} lost"
    if technique:
        title += f" ({technique})"

    bits = [f"DefiLlama records a {loss_txt} loss at {name} on "
            f"{occurred.date().isoformat()}."]
    if technique:
        bits.append(f"Technique: {technique}.")
    if classification:
        bits.append(f"Classification: {classification}.")
    if target:
        bits.append(f"Target type: {target}.")
    if chains:
        bits.append("Chain(s): " + ", ".join(chains) + ".")
    if row.get("bridgeHack"):
        bits.append("Recorded as a BRIDGE hack.")
    returned = _returned_funds(row)
    if returned is not None:
        bits.append(f"Funds returned so far: ${returned:,.0f}.")
    # Upstream write-up link kept as TEXT, not source_url — its host is
    # arbitrary and deliberately not on the allowlist.
    upstream = str(row.get("source") or "").strip()
    if upstream.lower().startswith(("http://", "https://")):
        bits.append(f"Upstream write-up: {upstream}")

    tags = ["defillama"]
    if row.get("bridgeHack"):
        tags.append("bridge_exploit")
    if technique:
        tags.append(technique.lower().replace(" ", "_"))

    try:
        return HackEvent(
            content_hash=_hash("defillama", name, str(row.get("date"))),
            source=HackEventSource.defillama,
            source_url=_CITATION_URL,
            observed_at=datetime.now(UTC),
            incident_time=occurred,
            title=title[:200],
            summary=" ".join(bits)[:2000],
            severity=_severity_for(loss),
            chains_mentioned=chains,
            estimated_loss_usd=loss,
            # A named protocol IS an identifiable victim — this is the outreach
            # signal the ranker's kicker is for.
            has_identifiable_victim=True,
            victim_hint=target or "protocol",
            tags=tags,
        )
    except (ValueError, TypeError) as exc:
        log.debug("hack_tracker.defillama: row %r rejected: %s", name, exc)
        return None


def _returned_funds(row: dict) -> Decimal | None:
    raw = row.get("returnedFunds")
    if raw in (None, 0, "0"):
        return None
    try:
        val = Decimal(str(raw))
    except (InvalidOperation, ValueError, TypeError):
        return None
    if not val.is_finite() or val <= 0:
        return None
    return val


def _hash(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _offline_fixture() -> list[HackEvent]:
    """One deterministic record for digest-format iteration without network."""
    occurred = datetime(2026, 1, 15, tzinfo=UTC)
    return [HackEvent(
        content_hash=_hash("defillama", "[FIXTURE] Bridge X", "1768435200"),
        source=HackEventSource.defillama,
        source_url=_CITATION_URL,
        observed_at=datetime.now(UTC),
        incident_time=occurred,
        title="[FIXTURE] Bridge X — $12,000,000 lost (Signature Verification)",
        summary=(
            "Fixture record — set RECUPERO_HACK_TRACKER_OFFLINE=0 to pull the "
            "live DefiLlama dataset. Technique: Signature Verification. "
            "Classification: Protocol Logic. Chain(s): ethereum."
        ),
        severity=HackEventSeverity.critical,
        chains_mentioned=["ethereum"],
        estimated_loss_usd=Decimal("12000000"),
        has_identifiable_victim=True,
        victim_hint="protocol",
        tags=["defillama", "bridge_exploit"],
    )]


__all__ = ("fetch",)
