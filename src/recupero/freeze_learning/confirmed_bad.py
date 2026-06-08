"""Confirmed-win auto-arm — the compounding moat (v0.39, Activation Sprint #2).

When stolen funds are ACTUALLY frozen or returned at an address (an issuer or
exchange acted on our freeze request), that address is confirmed known-bad at the
highest possible confidence. This promotes those addresses into the internal
blacklist so every FUTURE case routing through them fires instantly — the data
only Recupero has (its own won casework), compounding with every recovery.

Persistence: ``freeze_outcomes`` (Postgres) is the durable source of truth. This
re-materializes the operator-manual blacklist file from the DB on every run, so it
is fully idempotent and survives an ephemeral ``data_dir`` (a redeploy that wipes
the file is healed on the next cron tick). Run from the managed cron scheduler.

Forensic line: ONLY outcomes that PROVE the address held stolen funds arm it —
``full_freeze`` / ``partial_freeze`` / ``returned_to_victim``. An ``acknowledged``,
``declined``, ``released``, or ``silence_*`` outcome does NOT confirm bad (declined/
released may affirmatively mean it was NOT the perpetrator's), so it never arms.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Outcomes that prove stolen funds sat at the target (an institution acted).
WIN_ARM_OUTCOMES = frozenset(["full_freeze", "partial_freeze", "returned_to_victim"])


def arm_reason(*, outcome_type: str, issuer: str, case_id: Any) -> tuple[str, str]:
    """(reason, label_name) for a confirmed-win armed entry. Pure + testable."""
    label = f"confirmed known-bad ({outcome_type})"
    reason = (
        f"Confirmed known-bad: a '{outcome_type}' outcome was recorded via "
        f"{issuer} (case {case_id}) — stolen funds were frozen/returned at this "
        "address. Auto-armed from a won case (highest-confidence, "
        "outcome-provenance)."
    )
    return reason, label


def arm_rows(rows: list[dict[str, Any]], *, manual_path: Path) -> int:
    """Arm every confirmed-win row into the manual blacklist file. Defensive:
    re-checks the win-outcome gate (never trusts the caller), skips malformed/
    empty addresses, and never raises (one bad row can't abort the batch).
    Idempotent — ``add_manual_arm`` upserts by canonical (address, chain)."""
    from recupero.labels.internal_blacklist import add_manual_arm

    armed = 0
    for r in rows:
        if not isinstance(r, dict):
            continue
        if r.get("outcome_type") not in WIN_ARM_OUTCOMES:
            continue
        addr = r.get("target_address")
        if not isinstance(addr, str) or not addr.strip():
            continue
        chain = str(r.get("chain") or "ethereum")
        reason, label = arm_reason(
            outcome_type=str(r.get("outcome_type")),
            issuer=str(r.get("issuer") or "an issuer"),
            case_id=r.get("case_id") if r.get("case_id") is not None else "?",
        )
        try:
            add_manual_arm(manual_path, addr, chain, reason=reason, label_name=label)
            armed += 1
        except ValueError:
            # un-canonicalizable address — skip, never abort the batch
            log.warning("confirmed-bad: skipping un-armable address %r", addr)
            continue
        except Exception as exc:  # noqa: BLE001
            log.warning("confirmed-bad: skip %r: %s", addr, exc)
            continue
    return armed


def fetch_confirmed_bad_rows(dsn: str) -> list[dict[str, Any]]:
    """Join freeze_outcomes → freeze_letters_sent for every WIN outcome. Returns
    rows with target_address/chain/issuer/case_id/outcome_type. DB-unavailable →
    [] (best-effort, never raises)."""
    try:
        from psycopg.rows import dict_row
    except ImportError:  # pragma: no cover
        return []
    from recupero._common import db_connect

    sql = """
        SELECT fl.target_address, fl.chain, fl.issuer, fl.case_id,
               fo.outcome_type
          FROM public.freeze_outcomes fo
          JOIN public.freeze_letters_sent fl ON fo.letter_id = fl.id
         WHERE fo.outcome_type = ANY(%(wins)s);
    """
    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            cur.execute(sql, {"wins": list(WIN_ARM_OUTCOMES)})
            return [dict(r) for r in (cur.fetchall() or [])]
    except Exception as exc:  # noqa: BLE001
        log.warning("confirmed-bad: fetch failed: %s", exc)
        return []


def promote_confirmed_wins(*, dsn: str, manual_path: Path | None = None) -> int:
    """Re-materialize confirmed-win known-bad addresses from the DB into the
    internal blacklist manual file. Returns the count armed this run."""
    from recupero.labels.internal_blacklist import default_manual_arm_path

    path = manual_path or default_manual_arm_path()
    n = arm_rows(fetch_confirmed_bad_rows(dsn), manual_path=path)
    if n:
        log.info(
            "confirmed-bad: armed %d confirmed-win address(es) into the internal "
            "blacklist (%s)", n, path,
        )
    return n


__all__ = (
    "WIN_ARM_OUTCOMES",
    "arm_reason",
    "arm_rows",
    "fetch_confirmed_bad_rows",
    "promote_confirmed_wins",
)
