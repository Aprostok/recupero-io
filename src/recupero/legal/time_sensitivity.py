"""Case time-sensitivity advisory — the urgency facts we know cold, plus
the jurisdiction's limitation references (citable info, not legal advice).

Two clocks matter to a theft victim:

* The **practical clock** — how long ago funds reached each exchange (the
  window in which an administrative freeze is realistic). Computed entirely
  from on-chain timestamps we already have; no legal claim.
* The **legal clock** — the criminal / civil limitation periods that bar
  action once they run. Sourced from :mod:`recupero.legal.limitations`, which
  only ships periods with real statutory citations and otherwise defers to
  counsel.

Everything here is deterministic given ``as_of`` (tests pin it); production
defaults ``as_of`` to today. The approximate limitation "runout" dates are
explicitly labelled estimates — they assume the clock started on the incident
date, which counsel must confirm (accrual / tolling / the discovery rule can
move it). This module computes; it does not advise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from recupero.legal.limitations import (
    LimitationReference,
    normalize_jurisdiction,
    resolve_limitations,
)

# Within this many days of an approximate runout we flag the clock as
# "approaching" so the advisory draws the eye to it.
_APPROACHING_DAYS = 365

_PERIOD_RE = re.compile(r"^\s*(\d+)\s+(year|month|day)s?\b", re.IGNORECASE)


@dataclass(frozen=True)
class ExchangeClock:
    """How long ago stolen funds first reached a given exchange."""

    exchange: str
    first_flow_at: str | None
    days_since_first_flow: int | None


@dataclass(frozen=True)
class LimitationClock:
    """A limitation reference with an OPTIONAL approximate runout estimate.

    ``approx_deadline`` / ``approx_days_remaining`` are computed ONLY for
    non-illustrative entries with a simple "N years/months/days" period, and
    ONLY by assuming the clock started on the incident date. They are estimates
    a reviewer uses to gauge urgency — never a substitute for counsel
    confirming the true accrual date and any tolling.
    """

    ref: LimitationReference
    approx_deadline: str | None       # ISO date, or None when not computable
    approx_days_remaining: int | None
    status: str                       # running | approaching | may_have_elapsed | unknown


@dataclass(frozen=True)
class TimeSensitivity:
    """Assembled, render-ready time-sensitivity advisory."""

    case_id: str
    victim_name: str
    jurisdiction_raw: str | None
    jurisdiction_canonical: str | None
    incident_date: str | None
    as_of: str                        # ISO date actually used
    days_since_incident: int | None
    exchange_clocks: tuple[ExchangeClock, ...]
    limitation_clocks: tuple[LimitationClock, ...]
    has_verified_reference: bool
    confirm_with_counsel: bool        # no jurisdiction-specific verified reference


def _parse_date(value: object) -> date | None:
    """Parse an ISO date or ISO datetime (with optional trailing Z) to a date.
    Returns ``None`` on anything unparseable — never raises."""
    if not value:
        return None
    s = str(value).strip()
    if not s:
        return None
    # Date-only fast path.
    try:
        return date.fromisoformat(s[:10])
    except ValueError:
        pass
    try:
        s2 = s.replace("Z", "+00:00")
        return datetime.fromisoformat(s2).astimezone(UTC).date()
    except ValueError:
        return None


def _approx_runout(incident: date, period: str) -> date | None:
    """Approximate runout date for a simple 'N year/month/day(s)' period,
    assuming the clock starts on ``incident``. Returns ``None`` for compound or
    unparseable periods (e.g. '6 years, or 2 years from discovery')."""
    m = _PERIOD_RE.match(period or "")
    if not m:
        return None
    n = int(m.group(1))
    unit = m.group(2).lower()
    if n <= 0 or n > 100:  # sanity bound; nothing realistic exceeds a century
        return None
    if unit == "day":
        return incident + timedelta(days=n)
    if unit == "month":
        return incident + timedelta(days=30 * n)  # approximate, labelled as such
    # years
    try:
        return incident.replace(year=incident.year + n)
    except ValueError:
        # Feb 29 -> Feb 28 in a non-leap target year.
        return incident.replace(month=2, day=28, year=incident.year + n)


def _onward_cex_flows(brief: dict) -> list[dict]:
    fa = brief.get("_freeze_asks") if isinstance(brief, dict) else None
    if isinstance(fa, dict):
        flows = fa.get("onward_cex_flows")
        if isinstance(flows, list):
            return [f for f in flows if isinstance(f, dict)]
    return []


def build_time_sensitivity(
    brief: dict,
    *,
    as_of: date | None = None,
) -> TimeSensitivity:
    """Assemble the time-sensitivity advisory from a brief.

    Reads ``CASE_ID`` / ``VICTIM_NAME`` / ``VICTIM_JURISDICTION`` /
    ``INCIDENT_DATE`` and the onward-CEX flows (via the ``_freeze_asks``
    injection seam). ``as_of`` defaults to today (UTC) and is the only source
    of "now" — pass it for deterministic tests.
    """
    today = as_of or datetime.now(UTC).date()
    case_id = str(brief.get("CASE_ID") or "")
    victim = str(brief.get("VICTIM_NAME") or "the victim")
    juris_raw = brief.get("VICTIM_JURISDICTION") or None
    juris_raw = str(juris_raw) if juris_raw else None
    canon = normalize_jurisdiction(juris_raw)

    incident = _parse_date(brief.get("INCIDENT_DATE"))
    days_since_incident = (today - incident).days if incident else None

    # --- Practical clocks: days since funds reached each exchange. ---
    seen: set[str] = set()
    exchange_clocks: list[ExchangeClock] = []
    for flow in _onward_cex_flows(brief):
        name = str(flow.get("exchange") or "").strip()
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        first = flow.get("first_flow_at")
        first_d = _parse_date(first)
        exchange_clocks.append(
            ExchangeClock(
                exchange=name,
                first_flow_at=str(first) if first else None,
                days_since_first_flow=(today - first_d).days if first_d else None,
            )
        )
    exchange_clocks.sort(key=lambda c: c.exchange.lower())

    # --- Legal clocks: limitation references for the jurisdiction. ---
    refs = resolve_limitations(juris_raw)
    limitation_clocks: list[LimitationClock] = []
    for ref in refs:
        deadline: date | None = None
        if incident and not ref.illustrative:
            deadline = _approx_runout(incident, ref.period)
        if deadline is None:
            limitation_clocks.append(
                LimitationClock(ref=ref, approx_deadline=None,
                                approx_days_remaining=None, status="unknown")
            )
            continue
        remaining = (deadline - today).days
        if remaining < 0:
            status = "may_have_elapsed"
        elif remaining <= _APPROACHING_DAYS:
            status = "approaching"
        else:
            status = "running"
        limitation_clocks.append(
            LimitationClock(
                ref=ref,
                approx_deadline=deadline.isoformat(),
                approx_days_remaining=remaining,
                status=status,
            )
        )

    has_verified = any(c.ref.verified for c in limitation_clocks)
    return TimeSensitivity(
        case_id=case_id,
        victim_name=victim,
        jurisdiction_raw=juris_raw,
        jurisdiction_canonical=canon,
        incident_date=incident.isoformat() if incident else None,
        as_of=today.isoformat(),
        days_since_incident=days_since_incident,
        exchange_clocks=tuple(exchange_clocks),
        limitation_clocks=tuple(limitation_clocks),
        has_verified_reference=has_verified,
        confirm_with_counsel=(canon is None or not limitation_clocks),
    )


__all__ = (
    "ExchangeClock",
    "LimitationClock",
    "TimeSensitivity",
    "build_time_sensitivity",
)
