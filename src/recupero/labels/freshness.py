"""Label-freshness SLA monitor (v0.35.15 — roadmap J3).

We already have a bridge-spec staleness monitor; this generalizes the idea to
EVERY label source — OFAC feed, multi-regime sanctions, bridges, CEX deposits,
mixers, ransomware, issuers, etc. — each with a per-class freshness SLA. Stale
attribution data is silently-wrong attribution: an un-refreshed OFAC feed misses
a just-added wallet; a stale CEX-deposit set mis-routes a freeze. This surfaces
which sources are overdue, with the OFAC feed as the headline alarm.

Design: a PURE ``evaluate_label_freshness(sources, *, now)`` (age vs per-class
SLA → fresh / stale / critical / unknown; deterministic, ``now`` is passed in,
no hidden clock) + a ``scan_label_sources(seeds_dir)`` that reads each seed's
``<file>.meta.json`` ``last_synced_utc`` (falling back to file mtime) + a
``build_freshness_report`` that joins them. The ops ``label-freshness`` command
supplies the wall-clock ``now`` at the boundary.

Forensic posture: this reports data age, never invents a "last updated" — a
source with no recoverable timestamp is reported ``unknown`` (and treated as
overdue for review), never silently assumed fresh.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_SEEDS_DIR = Path(__file__).parent / "seeds"

# Per-source freshness SLA (days). A source older than its SLA is "stale";
# older than 2× SLA is "critical". OFAC is the tightest (regulatory feed that
# should refresh ~weekly); structural sets (mixers, issuers) are loosest.
# (filename, class, sla_days)
_SOURCES: tuple[tuple[str, str, int], ...] = (
    ("ofac_crypto_live.csv", "ofac_sanctions", 7),
    ("sanctions_intl_live.csv", "intl_sanctions", 14),
    ("bridges.json", "bridges", 30),
    ("cex_deposits.json", "exchange_deposits", 30),
    ("mixers.json", "mixers", 90),
    ("ransomware.json", "ransomware", 90),
    ("high_risk.json", "high_risk", 60),
    ("defi_protocols.json", "defi_protocols", 60),
    ("issuers.json", "issuers", 180),
)


@dataclass(frozen=True)
class LabelSourceStatus:
    """Freshness verdict for one label source."""
    name: str
    source_class: str
    last_updated_utc: str | None
    age_days: int | None
    sla_days: int
    status: str            # "fresh" | "stale" | "critical" | "unknown"
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source_class": self.source_class,
            "last_updated_utc": self.last_updated_utc,
            "age_days": self.age_days,
            "sla_days": self.sla_days,
            "status": self.status,
            "message": self.message,
        }


def _parse_iso(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    raw = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def evaluate_label_freshness(
    sources: list[dict[str, Any]],
    *,
    now: datetime,
) -> list[LabelSourceStatus]:
    """PURE: per-source freshness verdicts against each source's SLA.

    Each ``sources`` entry: ``{name, source_class, last_updated_utc (iso|None),
    sla_days}``. ``now`` is supplied by the caller (no hidden clock) so the
    result is deterministic + testable. A source with no parseable timestamp is
    ``unknown`` (treated as overdue for review, never assumed fresh).
    Sorted worst-first (critical, then stale, then unknown, then fresh).
    """
    out: list[LabelSourceStatus] = []
    for s in sources:
        name = str(s.get("name") or "(unknown)")
        cls = str(s.get("source_class") or "unknown")
        sla = int(s.get("sla_days") or 0) or 30
        ts = _parse_iso(s.get("last_updated_utc"))
        if ts is None:
            out.append(LabelSourceStatus(
                name=name, source_class=cls, last_updated_utc=None,
                age_days=None, sla_days=sla, status="unknown",
                message=(
                    f"{name}: no recoverable last-updated timestamp — review "
                    "freshness manually (treated as overdue)."
                ),
            ))
            continue
        age_days = max(0, int((now - ts).total_seconds() // 86400))
        if age_days > 2 * sla:
            status = "critical"
            msg = (
                f"{name}: {age_days}d old — CRITICALLY overdue (>2× the "
                f"{sla}d SLA). Re-sync now; attribution may be missing recent "
                "additions."
            )
        elif age_days > sla:
            status = "stale"
            msg = f"{name}: {age_days}d old — past the {sla}d SLA; schedule a re-sync."
        else:
            status = "fresh"
            msg = f"{name}: {age_days}d old — within the {sla}d SLA."
        out.append(LabelSourceStatus(
            name=name, source_class=cls,
            last_updated_utc=ts.isoformat().replace("+00:00", "Z"),
            age_days=age_days, sla_days=sla, status=status, message=msg,
        ))

    rank = {"critical": 0, "stale": 1, "unknown": 2, "fresh": 3}
    out.sort(key=lambda x: (rank.get(x.status, 9), -(x.age_days or 0)))
    return out


def _last_updated_for(seed_path: Path) -> str | None:
    """Best-effort last-updated ISO for a seed file: prefer the sibling
    ``<file>.meta.json`` ``last_synced_utc``, else the file mtime, else None."""
    meta = seed_path.with_suffix(seed_path.suffix + ".meta.json")
    if meta.exists():
        try:
            data = json.loads(meta.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict):
                for key in ("last_synced_utc", "last_updated_utc", "generated_at"):
                    val = data.get(key)
                    if val:
                        return str(val)
        except Exception as exc:  # noqa: BLE001
            log.debug("freshness: meta read failed for %s: %s", meta, exc)
    if seed_path.exists():
        try:
            mtime = seed_path.stat().st_mtime
            return datetime.fromtimestamp(mtime, UTC).isoformat().replace("+00:00", "Z")
        except OSError:
            return None
    return None


def scan_label_sources(seeds_dir: Path | None = None) -> list[dict[str, Any]]:
    """Read each known seed source's last-updated timestamp + SLA from disk.

    Missing seed files are still reported (``last_updated_utc=None`` →
    ``unknown``) so an absent OFAC feed is loud, not silently skipped.
    """
    base = seeds_dir or DEFAULT_SEEDS_DIR
    sources: list[dict[str, Any]] = []
    for filename, cls, sla in _SOURCES:
        path = base / filename
        sources.append({
            "name": filename,
            "source_class": cls,
            "sla_days": sla,
            "last_updated_utc": _last_updated_for(path),
        })
    return sources


def build_freshness_report(
    *,
    seeds_dir: Path | None = None,
    now: datetime,
) -> dict[str, Any]:
    """Scan + evaluate + summarize. ``now`` supplied by the caller."""
    statuses = evaluate_label_freshness(
        scan_label_sources(seeds_dir), now=now,
    )
    ofac = next((s for s in statuses if s.source_class == "ofac_sanctions"), None)
    return {
        "sources": [s.to_dict() for s in statuses],
        "summary": {
            "total": len(statuses),
            "critical": sum(1 for s in statuses if s.status == "critical"),
            "stale": sum(1 for s in statuses if s.status == "stale"),
            "unknown": sum(1 for s in statuses if s.status == "unknown"),
            "fresh": sum(1 for s in statuses if s.status == "fresh"),
            "ofac_status": ofac.status if ofac else "unknown",
            "ofac_age_days": ofac.age_days if ofac else None,
        },
    }


__all__ = (
    "LabelSourceStatus",
    "evaluate_label_freshness",
    "scan_label_sources",
    "build_freshness_report",
    "DEFAULT_SEEDS_DIR",
)
