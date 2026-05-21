"""Cross-case cluster builder (v0.23.0).

The compounding-moat feature for Recupero: when emit_brief produces a
freeze_brief, the cluster builder asks "have any of the perp wallets
in THIS case appeared as perp wallets in PRIOR cases?" If yes, this
case joins an existing multi-victim cluster (or creates one when no
prior cluster exists for those wallets).

The result is a persistent cluster_id that:

  * Surfaces in the LE handoff Section 5.6 — "this case is part of
    cluster CL-2026-0011 with 11 other victims and $42M aggregated
    loss". Tells the AUSA: this isn't a one-off; coordinate.

  * Drives the standalone aggregated cluster handoff (rendered via
    ``recupero-ops render-cluster <public_id>``) — one filing
    document covering ALL victims at once. The unlock for the law-
    firm market.

  * Updates as new cases join. When victim #4 of the same drainer
    files a case, the cluster grows from 3 → 4 automatically and
    the next render reflects it.

Detection strategy: walk PERP_HUB + ALL_ISSUER_HOLDINGS in the brief
and for each (address, chain) ask address_observations for prior
appearances WHERE role='perpetrator_hub' AND investigation_id !=
THIS_INVESTIGATION. Any prior case sharing such an address with this
case joins them in a cluster. Address_observations is the data
substrate (migration 011) that the cross_case_correlation pass
(v0.11.0) already queries — we reuse it.

Idempotency: the case_clusters table has UNIQUE on the seed perp
address. Re-emitting the brief on the same case either re-joins
the same cluster (case_cluster_members PK prevents dup) or no-ops.

Failure mode: every DB op is wrapped — a Supabase outage cannot
break brief emission. The brief itself is the authoritative
artifact; cluster metadata is downstream bookkeeping.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from uuid import UUID

log = logging.getLogger(__name__)


# Roles in address_observations that indicate the address is a
# PERP-controlled wallet — these are the bridges between cases.
# Excludes victim / unlabeled / exchange_deposit etc.
_PERP_ROLES_FOR_CLUSTERING = frozenset({
    "perpetrator_hub",
    "perpetrator_hop",
    "drainer_contract",
    "high_risk_destination",
})


@dataclass(frozen=True)
class ClusterMembership:
    """Result of build_or_update_cluster_for_case() — what cluster
    (if any) this case is now a member of."""
    cluster_id: UUID | None        # None when no overlap → no cluster
    public_id: str | None          # operator-facing identifier
    is_new_cluster: bool           # True if this call created the cluster
    member_case_count: int         # cluster size AFTER this join
    total_loss_usd: Decimal        # aggregate across the cluster
    joined_via_address: str | None # perp wallet that bound this case in
    joined_via_chain: str | None
    co_victim_count: int           # member_case_count - 1


def _gen_cluster_public_id(seed_address: str, seed_chain: str) -> str:
    """Stable, hash-derived public identifier for a cluster.

    Same seed (address, chain) always produces the same public_id so
    two operators racing to create a cluster for the same wallet land
    on the same string — defends idempotency under concurrent
    emit_brief calls.

    Shape: ``CL-<6 hex chars>``. The seed-only hash is intentional:
    if the SAME perp wallet appears across cases, every observer
    builds the same id, which is the desired property.
    """
    h = hashlib.sha256(
        f"{seed_address.lower()}|{seed_chain.lower()}".encode("utf-8"),
    ).hexdigest()
    return f"CL-{h[:6].upper()}"


def _extract_perp_wallets_from_brief(
    brief: dict[str, Any],
) -> list[tuple[str, str]]:
    """Return the list of (canonical_address, chain) tuples for every
    perp-controlled wallet in this case's brief — the hub + any
    freezable holding addresses + any UNRECOVERABLE holding addresses
    (Sky DAI etc.) — that we want to use as cluster-bridge candidates.
    """
    primary_chain = (brief.get("PRIMARY_CHAIN") or "ethereum").lower()
    pairs: set[tuple[str, str]] = set()

    hub = brief.get("PERP_HUB") or {}
    hub_addr = hub.get("address")
    if hub_addr:
        canon = hub_addr.lower() if hub_addr.startswith("0x") else hub_addr
        chain = (hub.get("chain") or primary_chain).lower()
        pairs.add((canon, chain))

    for entry in brief.get("ALL_ISSUER_HOLDINGS") or []:
        if not isinstance(entry, dict):
            continue
        for holding in entry.get("holdings") or []:
            if not isinstance(holding, dict):
                continue
            addr = holding.get("address")
            if not addr:
                continue
            canon = addr.lower() if addr.startswith("0x") else addr
            chain = (holding.get("chain") or primary_chain).lower()
            pairs.add((canon, chain))

    return sorted(pairs)


def _find_prior_overlap_cases(
    perp_pairs: list[tuple[str, str]],
    *,
    current_investigation_id: UUID | None,
    dsn: str,
) -> list[tuple[UUID, UUID | None, str, str]]:
    """For each (address, chain) in ``perp_pairs``, look up prior
    address_observations entries that recorded the SAME wallet as a
    perp-role address in a DIFFERENT investigation. Returns a list of
    ``(investigation_id, case_id, address, chain)`` tuples.

    Excludes the current investigation (so the case doesn't link
    against itself) and rows without an investigation_id (one-off
    research traces).
    """
    if not perp_pairs:
        return []

    from recupero._common import db_connect

    roles_list = list(_PERP_ROLES_FOR_CLUSTERING)
    sql = """
        SELECT DISTINCT o.investigation_id, o.case_id,
                        o.address, o.chain
          FROM public.address_observations o
         WHERE o.investigation_id IS NOT NULL
           AND o.investigation_id != %(self_inv)s
           AND o.role = ANY(%(roles)s::TEXT[])
           AND (o.address, o.chain) = ANY(
               SELECT * FROM unnest(%(addrs)s::TEXT[], %(chains)s::TEXT[])
           )
         LIMIT 500;
    """
    addrs = [p[0] for p in perp_pairs]
    chains = [p[1] for p in perp_pairs]
    out: list[tuple[UUID, UUID | None, str, str]] = []
    try:
        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(sql, {
                "self_inv": str(current_investigation_id) if current_investigation_id else "00000000-0000-0000-0000-000000000000",
                "roles": roles_list,
                "addrs": addrs,
                "chains": chains,
            })
            for row in cur.fetchall():
                out.append((row[0], row[1], row[2], row[3]))
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "cluster_builder: prior-overlap query failed (cluster "
            "skipped): %s", exc,
        )
        return []
    return out


def _parse_usd(s: Any) -> Decimal:
    """Parse a formatted USD string like '$3,600,000.00' into Decimal."""
    if isinstance(s, (int, float, Decimal)):
        return Decimal(str(s))
    if not s:
        return Decimal(0)
    try:
        return Decimal(str(s).replace("$", "").replace(",", "").strip() or "0")
    except Exception:  # noqa: BLE001
        return Decimal(0)


def build_or_update_cluster_for_case(
    brief: dict[str, Any],
    *,
    investigation_id: UUID | None,
    case_id: UUID | None,
    dsn: str,
) -> ClusterMembership | None:
    """Top-level entry point. Returns a ClusterMembership when this
    case is part of a cluster (existing or newly created), or
    ``None`` when no cross-case overlap exists.

    Pure-orchestration: extracts perp wallets from the brief, asks
    address_observations for prior cases, picks a cluster to join
    (or creates one), inserts the bridge row, updates aggregates.

    Idempotent — re-emitting the brief on the same case re-targets
    the same cluster via the PK on case_cluster_members.

    No-op return (None) when no DSN OR no perp wallets OR no prior
    overlap. NEVER raises — every DB op is wrapped so emit_brief
    cannot be broken by a cluster-bookkeeping failure.
    """
    if not dsn or not investigation_id:
        return None

    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return None

    perp_pairs = _extract_perp_wallets_from_brief(brief)
    if not perp_pairs:
        return None

    # Pre-flight: ensure the case_clusters table exists. Cheap query;
    # avoids loud errors on deploys that haven't applied migration 019.
    if not _table_exists("case_clusters", dsn=dsn):
        log.info(
            "cluster_builder: case_clusters table missing — migration "
            "019 likely not applied. Skipping cluster build."
        )
        return None

    prior = _find_prior_overlap_cases(
        perp_pairs,
        current_investigation_id=investigation_id,
        dsn=dsn,
    )
    if not prior:
        return None  # no overlap → no cluster

    # Pick the (address, chain) with the most prior cases as the
    # cluster seed. Ties broken by lexicographic address (stable).
    counts: dict[tuple[str, str], int] = {}
    for _inv, _case, addr, chain in prior:
        counts[(addr, chain)] = counts.get((addr, chain), 0) + 1
    seed_addr, seed_chain = max(
        counts.items(), key=lambda kv: (kv[1], -ord(kv[0][0][0]) if kv[0][0] else 0),
    )[0]

    public_id = _gen_cluster_public_id(seed_addr, seed_chain)
    this_loss = _parse_usd(brief.get("TOTAL_LOSS_USD"))

    # Atomic upsert: get-or-create the cluster, then bridge this case.
    from recupero._common import db_connect

    try:
        with db_connect(dsn) as conn:
            with conn.cursor() as cur:
                # 1. Get or create cluster row.
                cur.execute(
                    """
                    INSERT INTO public.case_clusters
                        (public_id, seed_perp_address, seed_perp_chain,
                         shared_perp_addresses, shared_perp_chains,
                         member_case_count, total_loss_usd, status,
                         created_at, updated_at)
                    VALUES (%s, %s, %s, %s::TEXT[], %s::TEXT[],
                            0, 0, 'active', NOW(), NOW())
                    ON CONFLICT (seed_perp_address, seed_perp_chain)
                    DO UPDATE SET updated_at = NOW()
                    RETURNING id, public_id, shared_perp_addresses,
                              shared_perp_chains, member_case_count,
                              total_loss_usd
                    """,
                    (
                        public_id, seed_addr, seed_chain,
                        [seed_addr], [seed_chain],
                    ),
                )
                row = cur.fetchone()
                if not row:
                    log.warning(
                        "cluster_builder: cluster upsert returned no row"
                    )
                    return None
                cluster_id, public_id_db, _shared_addrs, _shared_chains, prev_count, prev_loss = row
                is_new = (prev_count == 0)

                # 2. Bridge this case into the cluster (PK prevents dup).
                cur.execute(
                    """
                    INSERT INTO public.case_cluster_members
                        (cluster_id, case_id, investigation_id, role,
                         case_total_loss_usd, joined_via_address,
                         joined_via_chain, joined_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (cluster_id, investigation_id) DO UPDATE
                       SET case_total_loss_usd = EXCLUDED.case_total_loss_usd,
                           joined_via_address = EXCLUDED.joined_via_address,
                           joined_via_chain = EXCLUDED.joined_via_chain
                    RETURNING (xmax = 0) AS inserted
                    """,
                    (
                        cluster_id,
                        str(case_id) if case_id else None,
                        str(investigation_id),
                        "originator" if is_new else "joined",
                        this_loss,
                        seed_addr, seed_chain,
                    ),
                )
                bridge_row = cur.fetchone()
                bridge_inserted = bool(bridge_row and bridge_row[0])

                # 3. Maintain cluster aggregates. Recompute from the
                #    members table so a re-emit with a different loss
                #    figure properly replaces (not double-counts) the
                #    case's contribution.
                cur.execute(
                    """
                    UPDATE public.case_clusters
                       SET member_case_count = sub.cnt,
                           total_loss_usd    = sub.tot,
                           shared_perp_addresses = (
                               SELECT array_agg(DISTINCT seed_perp_address)
                                 FROM public.case_clusters cc2
                                WHERE cc2.id = %(cid)s
                               UNION
                               SELECT array_agg(DISTINCT joined_via_address)
                                 FROM public.case_cluster_members
                                WHERE cluster_id = %(cid)s
                                  AND joined_via_address IS NOT NULL
                           ),
                           updated_at = NOW()
                      FROM (
                          SELECT COUNT(*) AS cnt,
                                 COALESCE(SUM(case_total_loss_usd), 0) AS tot
                            FROM public.case_cluster_members
                           WHERE cluster_id = %(cid)s
                      ) AS sub
                     WHERE id = %(cid)s
                    RETURNING member_case_count, total_loss_usd
                    """,
                    {"cid": cluster_id},
                )
                agg = cur.fetchone()
                final_count = agg[0] if agg else 0
                final_loss = Decimal(str(agg[1])) if agg and agg[1] is not None else Decimal(0)

        log.info(
            "cluster_builder: case %s %s cluster %s "
            "(members=%d, total_loss=%s)",
            investigation_id,
            "JOINED" if bridge_inserted and not is_new else
                "CREATED" if is_new else "RE-JOINED",
            public_id_db, final_count, final_loss,
        )

        return ClusterMembership(
            cluster_id=cluster_id,
            public_id=public_id_db,
            is_new_cluster=is_new,
            member_case_count=final_count,
            total_loss_usd=final_loss,
            joined_via_address=seed_addr,
            joined_via_chain=seed_chain,
            co_victim_count=max(0, final_count - 1),
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("cluster_builder: cluster upsert failed: %s", exc)
        return None


def _table_exists(table: str, *, dsn: str) -> bool:
    """Cheap "is this table in the public schema?" probe. Used to
    short-circuit cluster builds on deploys that haven't applied
    migration 019.
    """
    from recupero._common import db_connect

    try:
        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1 FROM information_schema.tables
                 WHERE table_schema = 'public' AND table_name = %s
                """,
                (table,),
            )
            return cur.fetchone() is not None
    except Exception:  # noqa: BLE001
        return False


def fetch_cluster_summary(public_id: str, *, dsn: str) -> dict[str, Any] | None:
    """Look up a cluster by its public_id (CL-XXXXXX) and return a
    dict suitable for template rendering. Returns None when the
    cluster doesn't exist, the DB is unreachable, or no DSN.

    Shape:
      {
        "public_id": "CL-AB12CD",
        "seed_perp_address": "0x...",
        "seed_perp_chain": "ethereum",
        "shared_perp_addresses": ["0x...", ...],
        "member_case_count": 12,
        "total_loss_usd": Decimal("42500000.00"),
        "members": [
            {"investigation_id": UUID, "case_id": UUID, "role": "...",
             "case_total_loss_usd": Decimal(...), "joined_via_address": "...",
             "joined_at": datetime},
            ...
        ],
      }
    """
    if not dsn:
        return None
    try:
        import psycopg  # noqa: F401
    except ImportError:  # pragma: no cover
        return None
    from recupero._common import db_connect
    from psycopg.rows import dict_row

    try:
        with db_connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, public_id, seed_perp_address, seed_perp_chain,
                       shared_perp_addresses, shared_perp_chains,
                       member_case_count, total_loss_usd, status,
                       label, notes, created_at, updated_at
                  FROM public.case_clusters
                 WHERE public_id = %s
                """,
                (public_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            cluster_id = row["id"]
            cur.execute(
                """
                SELECT cluster_id, case_id, investigation_id, role,
                       case_total_loss_usd, joined_via_address,
                       joined_via_chain, joined_at
                  FROM public.case_cluster_members
                 WHERE cluster_id = %s
                 ORDER BY joined_at ASC
                """,
                (cluster_id,),
            )
            members = cur.fetchall()
            return {**row, "members": members}
    except Exception as exc:  # noqa: BLE001
        log.warning("fetch_cluster_summary failed: %s", exc)
        return None


__all__ = (
    "ClusterMembership",
    "build_or_update_cluster_for_case",
    "fetch_cluster_summary",
)
