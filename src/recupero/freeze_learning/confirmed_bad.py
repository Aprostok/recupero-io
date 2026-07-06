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

# H3 (confirmed_bad service-screen): label categories that mark a SHARED
# SERVICE. A win outcome at a service address (an exchange froze funds AT ITS
# OWN hot wallet, or returned them via a bridge) does NOT make that shared
# infrastructure address known-bad — arming it would wrongly freeze a wallet
# thousands of innocent users transact through. Such targets are skipped and
# logged for manual review instead.
_SERVICE_LABEL_CATEGORIES = frozenset({
    "exchange_hot_wallet", "exchange_deposit", "bridge",
    "defi_protocol", "staking",
})


def _service_label_for(address: str, chain: str) -> str | None:
    """Best-effort: return the address's service label category if it carries
    one (exchange/bridge/defi/staking), else None. Never raises — a label-store
    failure must not abort the confirmed-win arming batch."""
    try:
        from recupero.config import load_config
        from recupero.labels.store import LabelStore
        from recupero.models import Chain

        cfg, _ = load_config()
        store = LabelStore.load(cfg)
        try:
            chain_enum = Chain(chain)
        except (ValueError, KeyError):
            chain_enum = Chain.ethereum
        label = store.lookup(address, chain_enum)
        if label is None:
            return None
        cat = getattr(label.category, "value", label.category)
        cat = str(cat).strip().lower()
        return cat if cat in _SERVICE_LABEL_CATEGORIES else None
    except Exception as exc:  # noqa: BLE001
        log.debug("confirmed-bad: service-label screen unavailable: %s", exc)
        return None


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


def arm_rows(
    rows: list[dict[str, Any]],
    *,
    manual_path: Path,
    service_label_lookup: Any = None,
) -> int:
    """Arm every confirmed-win row into the manual blacklist file. Defensive:
    re-checks the win-outcome gate (never trusts the caller), skips malformed/
    empty addresses, and never raises (one bad row can't abort the batch).
    Idempotent — ``add_manual_arm`` upserts by canonical (address, chain).

    H3 (service-screen): before arming, the target is screened against the
    label store; a target carrying an exchange_hot_wallet / exchange_deposit /
    bridge / defi_protocol / staking label is SKIPPED (logged for manual
    review) — a win at a shared service address must never arm that service.
    ``service_label_lookup`` (``(address, chain) -> category|None``) is
    injectable for testing; it defaults to the real label-store screen."""
    from recupero.labels.internal_blacklist import add_manual_arm

    lookup = service_label_lookup or _service_label_for

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
        # H3 service-screen: skip a target that is labeled shared infrastructure.
        try:
            svc_cat = lookup(addr, chain)
        except Exception as exc:  # noqa: BLE001
            log.debug("confirmed-bad: service screen errored for %r: %s", addr, exc)
            svc_cat = None
        if svc_cat:
            log.warning(
                "confirmed-bad: SKIPPING arm of %r (chain=%s) — carries service "
                "label %r; a win at shared infrastructure must not arm it "
                "(manual review required)", addr, chain, svc_cat,
            )
            continue
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
