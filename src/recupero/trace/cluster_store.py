"""Continuous (cross-case) address-cluster store (migration 036, #7).

Moves clustering from per-case to PERSISTENT: per-case clusters are accumulated
into a durable address→cluster map and UNIONED over time, so a later trace can
ask "is this address already in a known cluster?". This is the persistent,
ahead-of-case clustering that distinguishes a continuous engine from a per-case
heuristic.

The union decision is a PURE function (``plan_cluster_assignment``) so it's
fully testable without a DB; ``accumulate_cluster`` applies it (best-effort,
guarded — never breaks a trace) and ``lookup_cluster`` reads it (degrades to
None without DSN/table).
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

_CONF_RANK = {"high": 3, "medium": 2, "low": 1}


def _new_cluster_id(members: list[str]) -> str:
    """Deterministic id from the sorted member set (stable across runs)."""
    h = hashlib.sha256("|".join(sorted(members)).encode("utf-8")).hexdigest()
    return f"cluster_{h[:12]}"


@dataclass
class ClusterAssignment:
    """Result of planning where an incoming cluster's members land."""

    canonical_id: str
    merged_from: list[str]  # existing cluster_ids merged INTO canonical_id


def plan_cluster_assignment(
    incoming_members: list[str],
    existing: dict[str, str],
) -> ClusterAssignment:
    """PURE union-find step. Given a new cluster's members and a map of any
    members already assigned (``{address: cluster_id}``), decide the canonical
    cluster_id and which existing cluster_ids merge into it.

    - No member is known → mint a deterministic new id (no merges).
    - Members touch existing cluster(s) → canonical = the lexicographically
      smallest existing id (deterministic); every OTHER touched id merges into
      it. This unions previously-separate clusters that now share an address.
    """
    existing_ids = sorted({cid for cid in existing.values() if cid})
    if not existing_ids:
        return ClusterAssignment(_new_cluster_id(incoming_members), [])
    canonical = existing_ids[0]
    merged_from = [cid for cid in existing_ids if cid != canonical]
    return ClusterAssignment(canonical, merged_from)


def accumulate_cluster(
    dsn: str | None,
    addresses: list[str],
    chain: str,
    *,
    heuristic: str | None = None,
    confidence: str = "low",
) -> str | None:
    """Union a per-case cluster into the persistent store. Returns the canonical
    cluster_id, or None (no DSN, <2 members, or any DB failure). Best-effort:
    never raises into the caller (a trace must not break on accumulation)."""
    members = sorted({a for a in addresses if isinstance(a, str) and a.strip()})
    if not dsn or len(members) < 2:
        return None
    try:
        from recupero._common import db_connect
        with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            # Existing assignments among the incoming members (constant SQL +
            # ANY(%s) list param → inline-SQL-audit safe).
            cur.execute(
                "SELECT address, cluster_id FROM public.cluster_membership "
                "WHERE chain = %s AND address = ANY(%s)",
                (chain, members),
            )
            existing = {r[0]: r[1] for r in cur.fetchall()}
            plan = plan_cluster_assignment(members, existing)

            if plan.merged_from:
                # Fold other clusters into the canonical id.
                cur.execute(
                    "UPDATE public.cluster_membership SET cluster_id = %s, "
                    "last_seen = now() WHERE cluster_id = ANY(%s)",
                    (plan.canonical_id, plan.merged_from),
                )
            for addr in members:
                cur.execute(
                    """
                    INSERT INTO public.cluster_membership
                        (address, chain, cluster_id, heuristic, confidence)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (address, chain) DO UPDATE
                        SET cluster_id = EXCLUDED.cluster_id,
                            heuristic = COALESCE(EXCLUDED.heuristic,
                                                 public.cluster_membership.heuristic),
                            last_seen = now()
                    """,
                    (addr, chain, plan.canonical_id, heuristic, confidence),
                )
        return plan.canonical_id
    except Exception as exc:  # noqa: BLE001
        log.warning("cluster_store: accumulate failed (chain=%s, n=%d): %s",
                    chain, len(members), exc)
        return None


def lookup_cluster(
    dsn: str | None, address: str, chain: str,
) -> dict[str, Any] | None:
    """Return the persistent cluster an address belongs to (with its size), or
    None. Degrades to None without DSN/table; never raises."""
    if not dsn or not address:
        return None
    try:
        from recupero._common import db_connect
        with db_connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT cluster_id, heuristic, confidence FROM "
                "public.cluster_membership WHERE address = %s AND chain = %s",
                (address, chain),
            )
            row = cur.fetchone()
            if row is None:
                return None
            cluster_id = row[0]
            cur.execute(
                "SELECT count(*) FROM public.cluster_membership "
                "WHERE cluster_id = %s",
                (cluster_id,),
            )
            size_row = cur.fetchone()
            size = int(size_row[0]) if size_row else 1
        return {
            "cluster_id": cluster_id,
            "heuristic": row[1],
            "confidence": row[2],
            "size": size,
        }
    except Exception as exc:  # noqa: BLE001
        log.debug("cluster_store: lookup failed for %s/%s: %s", address, chain, exc)
        return None


__all__ = (
    "ClusterAssignment",
    "plan_cluster_assignment",
    "accumulate_cluster",
    "lookup_cluster",
)
