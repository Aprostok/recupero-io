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
#
# v0.32.1 (forensic-audit): only roles that genuinely denote
# PERPETRATOR CONTROL may bind a cross-case cluster, because the cluster
# LE-handoff asserts the binding address is "perpetrator-controlled
# infrastructure" to an AUSA. The two roles below are exactly those:
#   * perpetrator_hub — emitted ONLY from a confident `perpetrator` label
#     (correlation._role_from_label_category).
#   * drainer_contract — the malicious approval-drainer contract itself.
# Pruned here: `perpetrator_hop` and `high_risk_destination` — NEITHER is
# ever emitted by correlation._emit (the former is dead; step-3 emits
# `exchange_deposit`, not `high_risk_destination`). `high_risk_destination`
# in particular is a HEURISTIC risk-score role; binding a cluster on it
# would turn a correlation into a falsely-asserted "common perpetrator
# control" claim. Removing them is behavior-preserving today (they're
# never produced) and closes the latent over-claim foot-gun.
_PERP_ROLES_FOR_CLUSTERING = frozenset({
    "perpetrator_hub",
    "drainer_contract",
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
        f"{seed_address.lower()}|{seed_chain.lower()}".encode(),
    ).hexdigest()
    return f"CL-{h[:6].upper()}"


def _extract_perp_wallets_from_brief(
    brief: dict[str, Any],
) -> list[tuple[str, str]]:
    """Return the list of (canonical_address, chain) tuples for every
    perp-controlled wallet in this case's brief — the hub + any
    freezable holding addresses + any UNRECOVERABLE holding addresses
    (Sky DAI etc.) — that we want to use as cluster-bridge candidates.

    v0.23.1 (audit-fix HIGH-2): use the canonical_address_key helper
    so addresses with trailing whitespace, mixed case on EVM, or
    future canonicalization rules match what address_observations
    stored. Pre-v0.23.1 the parallel lowercase-only normalization
    drifted from the rest of the codebase.
    """
    from recupero._common import canonical_address_key

    primary_chain = (brief.get("PRIMARY_CHAIN") or "ethereum").lower()
    pairs: set[tuple[str, str]] = set()

    hub = brief.get("PERP_HUB") or {}
    hub_addr = hub.get("address")
    if hub_addr:
        canon = canonical_address_key(hub_addr)
        if canon:
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
            canon = canonical_address_key(addr)
            if not canon:
                continue
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
    """Parse a formatted USD string like '$3,600,000.00' into Decimal.

    v0.23.1 (audit-fix HIGH-4): clamps negative inputs to 0. A
    typo / sign-flip in TOTAL_LOSS_USD could otherwise inject a
    negative loss into the cluster aggregate, producing misleading
    Section 5.6 totals and potentially flipping the OFAC/$5M
    threshold language. Loss is non-negative by definition.
    """
    if isinstance(s, (int, float, Decimal)):
        try:
            val = Decimal(str(s))
        except Exception:  # noqa: BLE001
            return Decimal(0)
    elif not s:
        return Decimal(0)
    else:
        try:
            val = Decimal(
                str(s).replace("$", "").replace(",", "").strip() or "0"
            )
        except Exception:  # noqa: BLE001
            return Decimal(0)
    # Reject NaN / Infinity — they poison every downstream aggregate
    # and "NEVER raises" docs are violated by `val > 0` on a NaN.
    if not val.is_finite():
        return Decimal(0)
    return val if val > 0 else Decimal(0)


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
    # cluster seed. v0.23.1 (audit-fix HIGH-3): ties broken by full
    # lexicographic (address, chain) tuple so the choice is fully
    # deterministic. Pre-v0.23.1 the tiebreaker used `-ord(first_char)`
    # which is identical for every EVM address (all start with '0')
    # and reduced to "whichever showed up first in dict iteration"
    # — non-deterministic across runs, could flip the cluster's
    # public_id between re-emits.
    counts: dict[tuple[str, str], int] = {}
    for _inv, _case, addr, chain in prior:
        counts[(addr, chain)] = counts.get((addr, chain), 0) + 1
    seed_addr, seed_chain = max(
        counts.items(),
        key=lambda kv: (kv[1], kv[0][0], kv[0][1]),
    )[0]

    public_id = _gen_cluster_public_id(seed_addr, seed_chain)
    this_loss = _parse_usd(brief.get("TOTAL_LOSS_USD"))

    # v0.23.1 (audit-fix CRIT-4): explicit transaction with SELECT FOR
    # UPDATE on the cluster row so concurrent emit_briefs on different
    # cases sharing the same perp wallet serialize their joins. Pre-
    # v0.23.1 the steps ran under autocommit=True — two concurrent
    # writers could both observe member_case_count=0 and both tag
    # their case role='originator', producing a degenerate cluster.
    from recupero._common import db_connect

    # Collect the distinct (investigation_id, case_id) tuples of every
    # prior case that overlaps with this one. CRIT-2 requires us to
    # bridge these into the cluster when we create it — otherwise the
    # FIRST victim is invisible to the cluster.
    prior_investigations: dict[UUID, UUID | None] = {}
    for prior_inv, prior_case, _addr, _chain in prior:
        # Preserve the FIRST case_id we see for each investigation
        # (typically there's only one; this is defense-in-depth).
        if prior_inv not in prior_investigations:
            prior_investigations[prior_inv] = prior_case

    try:
        with db_connect(dsn, autocommit=False) as conn, conn.cursor() as cur:
            # 1. Get or create cluster row, then LOCK it for the
            # rest of the transaction (CRIT-4 — serialize concurrent
            # joins on the same cluster).
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
                    RETURNING id, public_id
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
                conn.rollback()
                return None
            cluster_id, public_id_db = row[0], row[1]

            # Acquire the row lock for the rest of the transaction.
            cur.execute(
                "SELECT id FROM public.case_clusters WHERE id = %s FOR UPDATE",
                (cluster_id,),
            )

            # Determine whether the cluster is brand-new (no prior
            # members) — derived from the LOCKED row's current
            # member_case_count, which serializes properly under
            # concurrent writers thanks to the FOR UPDATE.
            cur.execute(
                "SELECT COUNT(*) FROM public.case_cluster_members "
                "WHERE cluster_id = %s",
                (cluster_id,),
            )
            existing_count_row = cur.fetchone()
            existing_member_count = (
                existing_count_row[0] if existing_count_row else 0
            )
            is_new = (existing_member_count == 0)

            # 2. Bridge the PRIOR cases first (CRIT-2 — pre-v0.23.1
            # the originator case was never bridged because the
            # priors-empty branch returned None at line 246 before
            # ever opening this transaction). When this cluster is
            # newly created, we must explicitly insert bridge rows
            # for every prior investigation we identified — the
            # FIRST such prior becomes the role='originator'.
            prior_inv_ids_sorted = sorted(prior_investigations.keys(), key=str)
            if is_new and prior_inv_ids_sorted:
                originator_inv = prior_inv_ids_sorted[0]
                for idx, prior_inv in enumerate(prior_inv_ids_sorted):
                    prior_case_id = prior_investigations.get(prior_inv)
                    cur.execute(
                        """
                            INSERT INTO public.case_cluster_members
                                (cluster_id, case_id, investigation_id,
                                 role, case_total_loss_usd,
                                 joined_via_address, joined_via_chain,
                                 joined_at)
                            VALUES (%s, %s, %s, %s, 0, %s, %s, NOW())
                            ON CONFLICT (cluster_id, investigation_id)
                            DO NOTHING
                            """,
                        (
                            cluster_id,
                            str(prior_case_id) if prior_case_id else None,
                            str(prior_inv),
                            "originator" if prior_inv == originator_inv else "joined",
                            seed_addr, seed_chain,
                        ),
                    )

            # 3. Bridge THIS case. When the cluster was newly
            # created, this case is 'joined' (one of the priors is
            # the originator). When the cluster already existed,
            # this case is also 'joined'.
            cur.execute(
                """
                    INSERT INTO public.case_cluster_members
                        (cluster_id, case_id, investigation_id, role,
                         case_total_loss_usd, joined_via_address,
                         joined_via_chain, joined_at)
                    VALUES (%s, %s, %s, 'joined', %s, %s, %s, NOW())
                    ON CONFLICT (cluster_id, investigation_id) DO UPDATE
                       SET case_total_loss_usd = EXCLUDED.case_total_loss_usd
                       -- v0.23.1 (audit-fix HIGH-6): preserve the
                       -- historic joined_via_address; do NOT overwrite
                       -- on re-emit. The forensic audit trail "this
                       -- case joined because of wallet W on date D"
                       -- stays stable.
                    RETURNING (xmax = 0) AS inserted
                    """,
                (
                    cluster_id,
                    str(case_id) if case_id else None,
                    str(investigation_id),
                    this_loss,
                    seed_addr, seed_chain,
                ),
            )
            bridge_row = cur.fetchone()
            bridge_inserted = bool(bridge_row and bridge_row[0])

            # 4. Maintain cluster aggregates. v0.23.1 (audit-fix
            # CRIT-3): the prior UNION-of-array_agg scalar subquery
            # would return 2 rows the moment any member had a
            # joined_via_address different from the seed — Postgres
            # raises 21000. Replaced with ARRAY(... UNION ALL ...)
            # which flattens to a single text[]. Also recompute
            # member_case_count from the bridge table to absorb the
            # CRIT-2 prior-bridge inserts above.
            cur.execute(
                """
                    UPDATE public.case_clusters
                       SET member_case_count = sub.cnt,
                           total_loss_usd    = sub.tot,
                           shared_perp_addresses = (
                               SELECT ARRAY(
                                   SELECT DISTINCT a FROM (
                                       SELECT seed_perp_address AS a
                                         FROM public.case_clusters
                                        WHERE id = %(cid)s
                                       UNION ALL
                                       SELECT joined_via_address
                                         FROM public.case_cluster_members
                                        WHERE cluster_id = %(cid)s
                                          AND joined_via_address IS NOT NULL
                                   ) u
                                  WHERE a IS NOT NULL
                               )
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
            # All three statements committed atomically.
            conn.commit()

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
    from psycopg.rows import dict_row

    from recupero._common import db_connect

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
