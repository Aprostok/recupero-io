"""OFAC-delta re-screen of open cases (roadmap-to-#1 v3 item #9).

When Treasury adds a crypto wallet to the OFAC SDN list, this surfaces a
FORWARD-LOOKING alert if that wallet is already on the watchlist of an active
case: "OFAC newly listed wallet X today; it's on the watchlist of case Y →
re-screen, consider a freeze ask / SAR."

Point-in-time discipline (forensic): this NEVER rewrites a brief's historical
label — a brief reflects what was known when it was produced. It only emits a
new, forward-looking operator alert about a state change AFTER the fact.

Delta detection: diff the freshly-synced OFAC active-address set against a
persisted snapshot of the previously-seen set. The FIRST run (no snapshot)
establishes a baseline and emits NOTHING — so we never flood on day one or
right after a fresh deploy. Subsequent runs alert only on genuine new additions.

The pure cores (``diff_ofac_additions`` / ``match_additions_to_watchlist`` /
snapshot IO) take plain data and are unit-tested without a DB; the orchestrator
(:func:`screen_ofac_additions`) is DSN-gated and best-effort.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def _ck(addr: str) -> str:
    from recupero._common import canonical_address_key
    return canonical_address_key(addr)


@dataclass(frozen=True)
class OFACDeltaAlert:
    """One forward-looking 'OFAC just listed a wallet that's in an open case'
    prompt. Advisory — the operator re-screens + decides on a freeze ask / SAR.
    """
    address: str
    chain: str
    sdn_entry_name: str
    listing_date: str
    investigation_id: str
    watch_role: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "address": self.address,
            "chain": self.chain,
            "sdn_entry_name": self.sdn_entry_name,
            "listing_date": self.listing_date,
            "investigation_id": self.investigation_id,
            "watch_role": self.watch_role,
            "message": self.message,
        }


def diff_ofac_additions(prev_keys: set[str], current_keys: set[str]) -> set[str]:
    """Newly-added canonical address keys = current − previously-seen. Pure."""
    return current_keys - prev_keys


# roadmap-v4 #3: the recommended_action carried on each persisted console row.
_RESCREEN_RECOMMENDED_ACTION = (
    "OFAC just listed this watched wallet — exchanges/issuers will block it "
    "imminently. Re-screen the case and race the freeze ask / SAR NOW. "
    "Point-in-time: do NOT rewrite the brief's historical label."
)


def alerts_to_recovery_rows(
    alerts: Iterable[OFACDeltaAlert],
) -> list[dict[str, str]]:
    """Map OFAC-delta alerts onto ``recovery_alerts``-row dicts so the cron can
    persist them via ``recovery_alerts_store.persist_alerts`` and the operator
    console's act-now queue (``/v1/recovery-alerts``) surfaces them between
    runs — previously they lived only in the cron log. Pure.

    ``kind='ofac_delta_listing'`` distinguishes them from watch-tick movement
    alerts; ``severity='high'`` ('critical' stays reserved for freezable funds
    in motion). The SDN entry name rides in ``label_name``; the case id is in
    the message (the table has no investigation_id column)."""
    rows: list[dict[str, str]] = []
    for a in alerts or []:
        rows.append({
            "address": a.address,
            "chain": a.chain or "?",
            "severity": "high",
            "kind": "ofac_delta_listing",
            "role": a.watch_role,
            "label_name": a.sdn_entry_name,
            "message": a.message,
            "recommended_action": _RESCREEN_RECOMMENDED_ACTION,
        })
    return rows


def build_watch_index(rows: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Index active-watchlist rows by canonical address key. Each row should
    carry ``address`` / ``chain`` / ``investigation_id`` / ``role``."""
    index: dict[str, list[dict[str, Any]]] = {}
    for row in rows or []:
        addr = (row.get("address") or "").strip()
        if not addr:
            continue
        index.setdefault(_ck(addr), []).append(row)
    return index


def match_additions_to_watchlist(
    added_entries: Iterable[Any],
    watch_index: dict[str, list[dict[str, Any]]],
) -> list[OFACDeltaAlert]:
    """For each newly-listed OFAC entry whose address is on an active
    watchlist, emit one alert per (entry, watching case). Pure.

    ``added_entries`` are OFACCryptoEntry-shaped objects (``.address`` /
    ``.chain`` / ``.sdn_entry_name`` / ``.listing_date``).
    """
    alerts: list[OFACDeltaAlert] = []
    for entry in added_entries:
        addr = getattr(entry, "address", "") or ""
        key = _ck(addr)
        matches = watch_index.get(key)
        if not matches:
            continue
        name = getattr(entry, "sdn_entry_name", "") or "(unnamed SDN entry)"
        listing_date = getattr(entry, "listing_date", "") or "(date unknown)"
        ofac_chain = getattr(entry, "chain", "") or "?"
        for row in matches:
            inv = str(row.get("investigation_id") or "?")
            role = str(row.get("role") or "unlabeled")
            message = (
                f"OFAC newly listed {addr} (SDN: {name}, listed {listing_date}) "
                f"— this address is on the watchlist of active case {inv} "
                f"(role={role}). Re-screen the case and consider a freeze ask / "
                f"SAR; point-in-time: do NOT rewrite the brief's historical label."
            )
            alerts.append(OFACDeltaAlert(
                address=addr,
                chain=ofac_chain,
                sdn_entry_name=name,
                listing_date=listing_date,
                investigation_id=inv,
                watch_role=role,
                message=message,
            ))
    return alerts


def load_snapshot(path: Path) -> set[str] | None:
    """Load the previously-seen OFAC key set. Returns ``None`` (NOT an empty
    set) when the snapshot is absent — the caller treats that as 'establish a
    baseline, emit nothing'. A corrupt/unreadable snapshot also returns
    ``None`` (degrade to a fresh baseline rather than alert on everything)."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    keys = raw.get("keys")
    if not isinstance(keys, list):
        return None
    return {str(k) for k in keys}


def write_snapshot(path: Path, keys: set[str]) -> None:
    """Persist the current OFAC key set as the next run's baseline. Best-effort
    — a write failure logs and is swallowed (we never block the sync)."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"keys": sorted(keys)}, separators=(",", ":")),
            encoding="utf-8",
        )
    except OSError as exc:
        log.warning("ofac-rescreen: could not write snapshot %s: %s", path, exc)


def _query_active_watchlist(dsn: str) -> list[dict[str, Any]]:
    """Fetch active watchlist rows (address/chain/investigation_id/role).
    Best-effort: returns ``[]`` on any DB error / missing driver."""
    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return []
    from recupero._common import db_connect
    try:
        with db_connect(dsn) as conn, conn.cursor() as cur:
            # status defaults to 'active'; treat anything not explicitly
            # 'closed'/'archived' as an open case worth re-screening.
            cur.execute(
                "SELECT address, chain, investigation_id, role "
                "FROM public.watchlist "
                "WHERE COALESCE(status, 'active') NOT IN ('closed', 'archived')"
            )
            cols = ("address", "chain", "investigation_id", "role")
            return [dict(zip(cols, r, strict=False)) for r in cur.fetchall()]
    except Exception as exc:  # noqa: BLE001
        log.warning("ofac-rescreen: watchlist query failed: %s", exc)
        return []


def _default_snapshot_path() -> Path:
    from recupero.trace.ofac_sync import DEFAULT_OFAC_CSV_PATH
    return DEFAULT_OFAC_CSV_PATH.with_suffix(".rescreen_seen.json")


def screen_ofac_additions(
    *,
    dsn: str | None,
    csv_path: Path | None = None,
    snapshot_path: Path | None = None,
) -> list[OFACDeltaAlert]:
    """Re-screen open cases against the OFAC additions since the last run.

    Loads the freshly-synced OFAC CSV (active entries only — removed listings
    are excluded), diffs against the persisted snapshot, and — only when a
    baseline already exists — matches genuine new additions against the active
    watchlist. Always updates the snapshot to the current set.

    Returns the list of forward-looking alerts (also logged at WARNING so they
    surface in the ops log pipeline). Best-effort throughout — never raises.
    """
    from recupero.trace.ofac_sync import load_ofac_csv

    entries = load_ofac_csv(csv_path, staleness_warn_days=0)
    # Active = not removed/delisted. (removed_at_utc set ⇒ delisted.)
    cur_index: dict[str, Any] = {
        _ck(e.address): e
        for e in entries
        if not (getattr(e, "removed_at_utc", "") or "").strip()
    }
    cur_keys = set(cur_index)

    # Adversarial-review fix: an EMPTY current set means the CSV is absent /
    # empty / corrupt (load_ofac_csv returns [] there) — NOT that every SDN
    # wallet was delisted. Advancing the baseline to ∅ would make the next
    # healthy run diff (∅ → ALL) and flag every active OFAC address (an alert
    # flood). Treat empty as "no data this run": skip, baseline UNTOUCHED.
    if not cur_keys:
        log.warning(
            "ofac-rescreen: current OFAC set is EMPTY (CSV absent/empty/corrupt) "
            "— skipping; baseline NOT advanced (avoids a next-run alert flood).",
        )
        return []

    snap_path = snapshot_path or _default_snapshot_path()
    prev = load_snapshot(snap_path)
    if prev is None:
        write_snapshot(snap_path, cur_keys)
        log.info(
            "ofac-rescreen: baseline established (%d active OFAC addresses); "
            "no alerts emitted on the first run / fresh snapshot.",
            len(cur_keys),
        )
        return []

    added = diff_ofac_additions(prev, cur_keys)
    alerts: list[OFACDeltaAlert] = []
    if added and dsn:
        watch_index = build_watch_index(_query_active_watchlist(dsn))
        added_entries = [cur_index[k] for k in added]
        alerts = match_additions_to_watchlist(added_entries, watch_index)

    # Adversarial-review fix: guard a SUSPICIOUS COLLAPSE (a partial/corrupt CSV
    # that parsed to far fewer rows than last run). Advancing the baseline to a
    # shrunken set would re-flag the dropped-then-restored addresses next run.
    if len(cur_keys) < len(prev) // 2:
        log.warning(
            "ofac-rescreen: current OFAC set (%d) collapsed below half the prior "
            "baseline (%d) — likely a partial sync; baseline NOT advanced.",
            len(cur_keys), len(prev),
        )
        return alerts

    # Advance the baseline (so the same addition isn't re-alerted).
    write_snapshot(snap_path, cur_keys)

    for a in alerts:
        log.warning("ofac-rescreen ALERT: %s", a.message)
    log.info(
        "ofac-rescreen: %d new OFAC listing(s) since last run, %d match an "
        "active case watchlist.", len(added), len(alerts),
    )
    return alerts


__all__ = (
    "OFACDeltaAlert",
    "alerts_to_recovery_rows",
    "diff_ofac_additions",
    "build_watch_index",
    "match_additions_to_watchlist",
    "load_snapshot",
    "write_snapshot",
    "screen_ofac_additions",
)
