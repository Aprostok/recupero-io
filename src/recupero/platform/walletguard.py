"""Wallet Guard (WalletBlock) — proactive, consumer/SMB-facing wallet protection.

The rest of the platform is POST-theft (trace → freeze → recover). Wallet Guard is
the PRE-theft half: an org keeps an address book of wallets it watches, asks
"is this address safe to send to?" before a transaction, and accrues alerts when
a watched (or just-checked) address screens risky.

It is deliberately thin: the risk signal is the existing offline screener
(``screen.screener.screen_address`` — <50ms, no on-chain calls), and this module
adds (a) a pure ScreeningResult → consumer verdict mapping and (b) the org-scoped
persistence for the address book + alert feed. No new risk logic, no fabrication:
a "block" verdict is only ever a real sanctioned/labeled hit.

DAO functions take an open psycopg connection (caller owns the transaction, same
pattern as ``platform.store``); all SQL is static + parameterized.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ---- pure verdict mapping (no DB, no network) ---- #

# Verdicts at or above this map to an ALERT being raised (sanctioned / high).
_ALERT_VERDICTS = frozenset({"sanctioned", "high"})

# Consumer-facing action per screener verdict. "block" = do not send; "warn" =
# proceed only with strong caution; "allow" = no detected risk (never a promise
# of safety — absence of a label is not proof of cleanliness).
_ACTION_BY_VERDICT = {
    "sanctioned": "block",
    "high": "block",
    "medium": "warn",
    "low": "allow",
    "clean": "allow",
}

_TITLE_BY_ACTION = {
    "block": "Do not send",
    "warn": "Proceed with caution",
    "allow": "No risk detected",
}


@dataclass(frozen=True)
class GuardVerdict:
    """A consumer-facing decision derived from a ScreeningResult."""
    action: str        # block | warn | allow
    title: str
    verdict: str       # the underlying screener verdict
    risk_score: int    # 0..10
    headline: str
    advice: str
    should_alert: bool

    def to_json(self) -> dict[str, Any]:
        return {
            "action": self.action, "title": self.title, "verdict": self.verdict,
            "risk_score": self.risk_score, "headline": self.headline,
            "advice": self.advice, "should_alert": self.should_alert,
        }


def guard_verdict(screening: Any) -> GuardVerdict:
    """Map a ``ScreeningResult`` to a Wallet Guard decision (pure).

    ``screening`` is a ``screen.screener.ScreeningResult`` (or any object exposing
    ``risk_verdict``, ``risk_score`` and ``investigator_note``). The advice text is
    protective and never over-promises: "allow" states that no label was found,
    NOT that the address is safe.
    """
    verdict = str(getattr(screening, "risk_verdict", "clean") or "clean").lower()
    score = int(getattr(screening, "risk_score", 0) or 0)
    note = str(getattr(screening, "investigator_note", "") or "").strip()
    action = _ACTION_BY_VERDICT.get(verdict, "warn")
    title = _TITLE_BY_ACTION[action]

    if action == "block":
        advice = (
            "This address is flagged as high-risk. Do NOT send funds to it — "
            "money sent here is very likely unrecoverable, and (if sanctioned) "
            "transacting with it may itself carry legal exposure."
        )
    elif action == "warn":
        advice = (
            "This address shows risk indicators. Verify the counterparty through "
            "an independent channel before sending, and start with a small test "
            "amount if you proceed."
        )
    else:
        advice = (
            "No high-risk label was found for this address. That is NOT a "
            "guarantee it is safe — always confirm the recipient independently "
            "before sending."
        )

    headline = note or f"Risk verdict: {verdict} (score {score}/10)."
    return GuardVerdict(
        action=action, title=title, verdict=verdict, risk_score=score,
        headline=headline, advice=advice,
        should_alert=verdict in _ALERT_VERDICTS,
    )


def check_address(
    address: str,
    *,
    chain: str = "ethereum",
    high_risk_db: dict[str, Any] | None = None,
    use_correlation_db: bool = True,
) -> dict[str, Any]:
    """Screen an address and return ``{screening, guard}`` (offline, ~<50ms).

    Reuses the offline screener wholesale — no new risk logic. Raises the
    screener's own ``ValueError`` / ``TypeError`` on a malformed address so the
    caller can map it to a 422.
    """
    from recupero.screen.screener import screen_address

    result = screen_address(
        address, chain=chain, use_correlation_db=use_correlation_db,
        high_risk_db=high_risk_db,
    )
    verdict = guard_verdict(result)
    return {"screening": result.to_json_safe(), "guard": verdict.to_json()}


# --------------------------------------------------------------------------- #
# DAO — address book (watched_addresses)
# --------------------------------------------------------------------------- #


def add_watched_address(
    conn: Any, *, org_id: str, chain: str, address: str, label: str | None,
    created_by: str | None, verdict: str | None = None,
    risk_score: int | None = None,
) -> str:
    """Upsert a watched address (address book). Re-adding an existing
    (org, chain, address) refreshes its label + cached screen rather than
    erroring on the UNIQUE constraint. Returns the row id."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.watched_addresses "
            "(org_id, chain, address, label, created_by, last_verdict, "
            " last_risk_score, last_checked_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, "
            # %s::text so Postgres can infer the param type — it appears only in
            # this IS NULL test, which otherwise yields IndeterminateDatatype.
            "        CASE WHEN %s::text IS NULL THEN NULL ELSE now() END) "
            "ON CONFLICT (org_id, chain, address) DO UPDATE SET "
            "  label = EXCLUDED.label, "
            "  last_verdict = EXCLUDED.last_verdict, "
            "  last_risk_score = EXCLUDED.last_risk_score, "
            "  last_checked_at = EXCLUDED.last_checked_at "
            "RETURNING id::text",
            (org_id, chain, address, label, created_by, verdict, risk_score,
             verdict),
        )
        return cur.fetchone()[0]


def list_watched_addresses(conn: Any, org_id: str) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id::text, chain, address, label, last_verdict, "
            "       last_risk_score, last_checked_at, created_at "
            "FROM public.watched_addresses WHERE org_id = %s "
            "ORDER BY created_at DESC",
            (org_id,),
        )
        rows = cur.fetchall()
    return [
        {"id": r[0], "chain": r[1], "address": r[2], "label": r[3],
         "last_verdict": r[4], "last_risk_score": r[5],
         "last_checked_at": r[6], "created_at": r[7]}
        for r in rows
    ]


def delete_watched_address(conn: Any, *, org_id: str, watched_id: str) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM public.watched_addresses WHERE id = %s AND org_id = %s",
            (watched_id, org_id),
        )
        return cur.rowcount > 0


def count_watched(conn: Any, org_id: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM public.watched_addresses WHERE org_id = %s",
            (org_id,),
        )
        return int(cur.fetchone()[0])


# --------------------------------------------------------------------------- #
# DAO — alerts (wallet_alerts)
# --------------------------------------------------------------------------- #


def create_alert(
    conn: Any, *, org_id: str, chain: str, address: str, verdict: str,
    severity: int, headline: str, category: str | None = None,
    watched_address_id: str | None = None, source: str = "guard_check",
) -> str:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.wallet_alerts "
            "(org_id, watched_address_id, chain, address, verdict, severity, "
            " category, headline, source) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id::text",
            (org_id, watched_address_id, chain, address, verdict, severity,
             category, headline, source),
        )
        return cur.fetchone()[0]


def list_alerts(
    conn: Any, *, org_id: str, only_unacked: bool = False, limit: int = 50,
) -> list[dict[str, Any]]:
    # Static SQL: the optional unacked filter is a fixed clause chosen by a
    # boolean, never string-interpolated.
    sql = (
        "SELECT id::text, watched_address_id::text, chain, address, verdict, "
        "       severity, category, headline, source, created_at, "
        "       acknowledged_at "
        "FROM public.wallet_alerts WHERE org_id = %s "
    )
    if only_unacked:
        sql += "AND acknowledged_at IS NULL "
    sql += "ORDER BY created_at DESC LIMIT %s"
    with conn.cursor() as cur:
        cur.execute(sql, (org_id, max(1, min(limit, 200))))
        rows = cur.fetchall()
    return [
        {"id": r[0], "watched_address_id": r[1], "chain": r[2], "address": r[3],
         "verdict": r[4], "severity": r[5], "category": r[6], "headline": r[7],
         "source": r[8], "created_at": r[9], "acknowledged": r[10] is not None}
        for r in rows
    ]


def ack_alert(conn: Any, *, org_id: str, alert_id: str, user_id: str | None) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE public.wallet_alerts "
            "SET acknowledged_at = now(), acknowledged_by = %s "
            "WHERE id = %s AND org_id = %s AND acknowledged_at IS NULL",
            (user_id, alert_id, org_id),
        )
        return cur.rowcount > 0


def count_unacked_alerts(conn: Any, org_id: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM public.wallet_alerts "
            "WHERE org_id = %s AND acknowledged_at IS NULL",
            (org_id,),
        )
        return int(cur.fetchone()[0])


__all__ = (
    "GuardVerdict",
    "guard_verdict",
    "check_address",
    "add_watched_address",
    "list_watched_addresses",
    "delete_watched_address",
    "count_watched",
    "create_alert",
    "list_alerts",
    "ack_alert",
    "count_unacked_alerts",
)
