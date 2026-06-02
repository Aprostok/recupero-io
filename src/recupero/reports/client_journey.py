"""Client-safe fund-flow "journey" data (v0.35).

The operator-facing interactive graph (``reports.graph_ui``) exposes
everything: every counterparty address, every vendor label, explorer
links, full USD ledgers. That is the right surface for an investigator
but the wrong one for a victim looking at their case portal — it leaks
forensic internals and is visually overwhelming.

``build_journey_data(case)`` produces a *sanitized projection* of the
same node/edge model that powers the operator graph (it calls the very
same ``worker._flow_diagram._aggregate`` pass, so the two never drift),
but:

  * **Friendly, bucketed labels.** Every node is mapped to a plain-
    English *recoverability status* ("At a regulated exchange",
    "Entered a mixer", "Freeze-eligible (stablecoin issuer)", …) derived
    purely from the existing classifier categories — no new claims, no
    fabrication.
  * **No operator internals.** Raw vendor identity strings are surfaced
    ONLY for endpoint *entities* (the exchange / mixer / issuer the
    client needs to understand recovery). Pass-through wallets become a
    generic "Intermediary wallet"; nothing else leaks.
  * **Clustering.** Same-entity addresses (an issuer family, a named
    exchange, the same address seen across chains) collapse into one
    expandable bubble the client can click in and out of.
  * **Truncation.** The graph is capped to a clean, readable size —
    victim + all endpoints always kept, top intermediary wallets by
    value fill the rest.

The output is a JSON-serializable dict the portal embeds into the
``journey.html.j2`` page. It never contains raw ``case.json`` — the
portal builds this server-side and hands only the projection to the
browser.
"""

from __future__ import annotations

import hashlib
import logging
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any

# Reuse the operator graph's vetted helpers so the two renderings stay
# consistent (chain colors, explorer-URL mapping, NaN/Inf-safe USD
# coercion). These are package-private but live in the same package.
from recupero.reports.graph_ui import (
    _CHAIN_COLOR,
    _explorer_url,
    _safe_usd_decimal,
    _safe_usd_float,
)
from recupero._common import canonical_address_key as _key
from recupero._common import short_addr as _short_addr

if TYPE_CHECKING:  # pragma: no cover
    from recupero.models import Case

log = logging.getLogger(__name__)


# Maximum nodes in the client journey graph. Victim + every endpoint
# entity is always kept; remaining slots go to the highest-value
# intermediary wallets. Keeps the client view legible — investigators
# use the full operator graph for the long tail.
_MAX_CLIENT_NODES = 80

# Cap on per-edge transactions surfaced in the edge drill-down panel.
# Top-N by USD; the count of the remainder is disclosed.
_MAX_EDGE_TX = 12


# Classifier category (from ``_flow_diagram._NodeAttrs.category``) →
# client recoverability *status* key. This is the ONLY place category
# semantics turn into client-facing language; every status is a
# description of where funds are, never a promise of recovery.
_STATUS_BY_CATEGORY: dict[str, str] = {
    "victim": "origin",
    "freezable_holding": "freezable",
    "exchange_deposit": "exchange",
    "exchange_hot_wallet": "exchange",
    "bridge": "bridge",
    "defi_protocol": "defi",
    "staking": "defi",
    "mixer": "unrecoverable",
    "perpetrator": "suspect",
    "wallet": "intermediary",
}


# Status → display metadata. ``order`` drives the "where your funds are"
# breakdown (most actionable first). ``terminal`` marks endpoint
# statuses that count toward the funds breakdown (intermediaries /
# origin are pass-through and excluded from the totals).
@dataclass(frozen=True)
class _StatusMeta:
    label: str
    color: str
    blurb: str
    order: int
    terminal: bool


_STATUS_META: dict[str, _StatusMeta] = {
    "origin": _StatusMeta(
        "Your funds (origin)", "#1D4ED8",
        "Where the loss began — your wallet.", 0, False,
    ),
    "freezable": _StatusMeta(
        "Freeze-eligible (stablecoin issuer)", "#B45309",
        "Funds reached a stablecoin issuer that can freeze them on a "
        "valid legal request — the most actionable outcome.", 1, True,
    ),
    "exchange": _StatusMeta(
        "At a regulated exchange", "#15803D",
        "Funds reached a regulated exchange. Recovery is actionable "
        "through a legal request or freeze to the exchange.", 2, True,
    ),
    "bridge": _StatusMeta(
        "Bridged to another chain", "#C2410C",
        "Funds crossed to another blockchain; tracing continues on the "
        "destination chain.", 3, True,
    ),
    "defi": _StatusMeta(
        "In a DeFi protocol", "#6D28D9",
        "Funds entered a smart-contract protocol (a swap, stake, or "
        "lending market).", 4, True,
    ),
    "suspect": _StatusMeta(
        "Suspect-controlled wallet", "#9F1239",
        "A wallet attributed to the party that moved your funds.", 5, True,
    ),
    "unrecoverable": _StatusMeta(
        "Entered a mixer", "#B91C1C",
        "Funds entered a mixing service. Funds that enter a mixer are "
        "typically unrecoverable.", 6, True,
    ),
    "intermediary": _StatusMeta(
        "Intermediary wallet", "#64748B",
        "A pass-through wallet used to move funds along.", 7, False,
    ),
}

# Categories that carry a meaningful endpoint *identity* the client
# should see (the named exchange / mixer / issuer / bridge). For every
# other category the identity is suppressed so operator-internal label
# strings never reach the client.
_ENTITY_CATEGORIES = frozenset(
    _STATUS_BY_CATEGORY.keys()
) - {"wallet", "victim"}


def _status_for(category: str) -> str:
    return _STATUS_BY_CATEGORY.get(category or "wallet", "intermediary")


def _cluster_key(attrs: Any, status: str) -> tuple[str, str] | None:
    """Stable grouping key for a node, or ``None`` for a singleton.

    Grouping priority: issuer family → named entity identity. Plain
    intermediary wallets are never clustered (each is its own node).
    """
    issuer = getattr(attrs, "issuer", None)
    if issuer:
        return ("issuer", str(issuer))
    identity = getattr(attrs, "identity", None)
    category = getattr(attrs, "category", "wallet") or "wallet"
    if category in _ENTITY_CATEGORIES and identity:
        # Group by (status, identity) so e.g. two "Binance" exchange
        # nodes merge but a same-named entity in a different role does not.
        return ("entity", f"{status}:{identity}")
    return None


def _cluster_id(key: tuple[str, str]) -> str:
    raw = f"{key[0]}|{key[1]}".encode("utf-8", errors="replace")
    return "c_" + hashlib.sha256(raw).hexdigest()[:12]


def _cluster_label(key: tuple[str, str]) -> str:
    kind, val = key
    if kind == "issuer":
        return f"{val} (issuer)"
    # entity key is "status:identity" — show the identity only.
    return val.split(":", 1)[-1]


@dataclass
class _MutNode:
    """Working node before we decide truncation + clustering."""
    id: str
    short: str
    status: str
    chain: str
    identity: str | None
    inbound: Decimal
    outbound: Decimal
    explorer_url: str
    cluster_id: str | None = None
    cluster_label: str | None = None


def _addr_multichain_clusters(case: Any) -> dict[str, str]:
    """Map address → cluster id for the same EVM address seen on 2+
    chains (the one persisted-clustering heuristic). Best-effort;
    failures degrade to no extra clustering."""
    out: dict[str, str] = {}
    try:
        from recupero.trace.address_clustering import cluster_addresses
        for cl in cluster_addresses(case):
            if len(cl.addresses) < 2:
                continue
            cid = _cluster_id(("multichain", "|".join(sorted(cl.addresses))))
            for a in cl.addresses:
                out[a.lower()] = cid
    except Exception as exc:  # noqa: BLE001
        log.debug("journey: multichain clustering skipped: %s", exc)
    return out


# Risk verdict (from trace.risk_scoring) → node color for the operator
# "colour by risk" overlay. CLEAN stays green; severity climbs to red.
_RISK_COLOR: dict[str, str] = {
    "SANCTIONED": "#7f1d1d",
    "CRITICAL": "#b91c1c",
    "HIGH-RISK": "#ea580c",
    "MODERATE": "#d97706",
    "CLEAN": "#15803d",
}


def build_operator_graph_data(
    case: Case, *, high_risk_db: Any | None = None
) -> dict[str, Any]:
    """Operator-fidelity graph: same shape as the client journey but
    **un-sanitized** (every counterparty identity surfaced, larger node
    budget) and enriched with per-node **risk score/verdict** and
    **indirect-exposure** overlays. Internal investigator tool only —
    never served to the victim portal.
    """
    return build_journey_data(
        case, sanitize=False, max_nodes=250,
        with_risk=True, high_risk_db=high_risk_db,
    )


def _risk_overlay(
    case: Case, high_risk_db: Any | None
) -> tuple[dict[str, Any], dict[str, float]]:
    """(risk_by_addr, indirect_usd_by_addr), both keyed by canonical
    address. Best-effort — any failure yields empty dicts so the graph
    still renders without the overlay."""
    risk_out: dict[str, Any] = {}
    indirect_out: dict[str, float] = {}
    try:
        from recupero.trace.risk_scoring import load_high_risk_db, score_addresses
        db = high_risk_db if high_risk_db is not None else load_high_risk_db()
        for addr, rs in score_addresses(case, high_risk_db=db).items():
            risk_out[_key(addr)] = {
                "score": int(getattr(rs, "score", 0) or 0),
                "verdict": getattr(rs, "verdict", "CLEAN") or "CLEAN",
                "color": _RISK_COLOR.get(
                    getattr(rs, "verdict", "CLEAN") or "CLEAN", "#64748B"
                ),
            }
        try:
            from recupero.trace.indirect_exposure import compute_indirect_exposure
            for addr, ie in compute_indirect_exposure(case, db).items():
                indirect_out[_key(addr)] = _safe_usd_float(
                    getattr(ie, "total_indirect_usd", 0)
                )
        except Exception as exc:  # noqa: BLE001
            log.debug("operator graph: indirect exposure skipped: %s", exc)
    except Exception as exc:  # noqa: BLE001
        log.debug("operator graph: risk overlay skipped: %s", exc)
    return risk_out, indirect_out


def build_journey_data(
    case: Case,
    *,
    sanitize: bool = True,
    max_nodes: int = _MAX_CLIENT_NODES,
    with_risk: bool = False,
    high_risk_db: Any | None = None,
) -> dict[str, Any]:
    """Build the sanitized client journey graph from a ``Case``.

    ``sanitize`` (default True) suppresses raw identity strings on non-
    entity wallets and is the client-portal mode. ``sanitize=False`` +
    ``with_risk=True`` is the operator mode (see ``build_operator_graph_data``).

    Returns a JSON-serializable dict:
        {
          "nodes":    [ {id, label, short, status, statusLabel,
                         statusColor, chain, chainColor, inboundUsd,
                         outboundUsd, explorerUrl, clusterId} ],
          "edges":    [ {source, target, totalUsd, totalUsdNumeric,
                         transferCount, dominantSymbol, isCrossChain} ],
          "clusters": [ {id, label, status, statusLabel, statusColor,
                         size, memberIds, inboundUsd, outboundUsd} ],
          "statusTotals": [ {status, label, color, usd, usdLabel,
                             count} ],   # endpoint buckets, ordered
          "meta": { nodeCount, edgeCount, totalUsdTraced, chain,
                    truncated, hiddenNodeCount, summaryLine },
        }
    """
    from recupero.worker._flow_diagram import _aggregate

    nodes_map, edges_list = _aggregate(case)
    multichain = _addr_multichain_clusters(case)

    # ---- Pass 1: build working nodes with status + sanitized fields ----
    work: dict[str, _MutNode] = {}
    for addr, attrs in nodes_map.items():
        category = (attrs.category or "wallet")
        status = _status_for(category)
        # In sanitized (client) mode, identity is surfaced only for
        # endpoint entities; intermediary/victim wallets never expose a
        # raw identity string. In operator mode (sanitize=False) every
        # available identity is shown.
        identity = None
        if attrs.identity and (not sanitize or category in _ENTITY_CATEGORIES):
            identity = attrs.identity
        ck = _cluster_key(attrs, status)
        cid = _cluster_id(ck) if ck else multichain.get(addr.lower())
        clabel = _cluster_label(ck) if ck else None
        chain = (attrs.chain or "ethereum")
        work[addr] = _MutNode(
            id=addr,
            short=_short_addr(addr),
            status=status,
            chain=chain,
            identity=identity,
            inbound=_safe_usd_decimal(attrs.inbound_usd),
            outbound=_safe_usd_decimal(attrs.outbound_usd),
            explorer_url=_explorer_url(chain, addr),
            cluster_id=cid,
            cluster_label=clabel,
        )

    # ---- Exposure: received-from / sent-to USD split by neighbor status
    # (the client-safe analogue of an exposure wheel). ----
    in_by: dict[str, dict[str, Decimal]] = {}
    out_by: dict[str, dict[str, Decimal]] = {}
    for e in edges_list:
        su = _safe_usd_decimal(e.total_usd)
        if su <= 0:
            continue
        src_status = work[e.src].status if e.src in work else "intermediary"
        dst_status = work[e.dst].status if e.dst in work else "intermediary"
        if e.dst in work:
            slot = in_by.setdefault(e.dst, {})
            slot[src_status] = slot.get(src_status, Decimal(0)) + su
        if e.src in work:
            slot = out_by.setdefault(e.src, {})
            slot[dst_status] = slot.get(dst_status, Decimal(0)) + su

    # ---- Per-edge transactions for the drill-down panel ----
    tx_by_edge: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for t in case.transfers:
        fk, tk = _key(t.from_address), _key(t.to_address)
        if not fk or not tk or fk == tk:
            continue
        tx_by_edge.setdefault((fk, tk), []).append({
            "date": _iso_date(getattr(t, "block_time", None)),
            "usd": _safe_usd_float(getattr(t, "usd_value_at_tx", None)),
            "usdLabel": f"${_safe_usd_decimal(getattr(t, 'usd_value_at_tx', None)):,.2f}",
            "token": (t.token.symbol if getattr(t, "token", None) else None),
            "txUrl": getattr(t, "explorer_url", None) or None,
        })

    # ---- Risk + indirect-exposure overlay (operator mode only) ----
    risk_by, indirect_by = (
        _risk_overlay(case, high_risk_db) if with_risk else ({}, {})
    )

    # ---- Truncation: keep victim + all endpoints, then top wallets ----
    def _is_kept_always(n: _MutNode) -> bool:
        return n.status not in ("intermediary",)

    always = [n for n in work.values() if _is_kept_always(n)]
    rest = [n for n in work.values() if not _is_kept_always(n)]
    rest.sort(key=lambda n: float(n.inbound + n.outbound), reverse=True)
    slots = max(0, max_nodes - len(always))
    kept_nodes = always + rest[:slots]
    kept_ids = {n.id for n in kept_nodes}
    hidden = len(work) - len(kept_ids)

    # ---- Build JSON nodes ----
    json_nodes: list[dict[str, Any]] = []
    for n in kept_nodes:
        meta = _STATUS_META[n.status]
        label = n.identity or meta.label
        node_dict: dict[str, Any] = {
            "id": n.id,
            "label": label,
            "short": n.short,
            "status": n.status,
            "statusLabel": meta.label,
            "statusColor": meta.color,
            "chain": n.chain,
            "chainColor": _CHAIN_COLOR.get(n.chain.lower(), "#94A3B8"),
            "inboundUsd": f"${n.inbound:,.2f}",
            "outboundUsd": f"${n.outbound:,.2f}",
            "explorerUrl": n.explorer_url,
            "clusterId": n.cluster_id,
            "inByCategory": {
                k: _safe_usd_float(v) for k, v in in_by.get(n.id, {}).items()
            },
            "outByCategory": {
                k: _safe_usd_float(v) for k, v in out_by.get(n.id, {}).items()
            },
        }
        if with_risk:
            rk = risk_by.get(n.id) or risk_by.get(_key(n.id))
            node_dict["risk"] = rk
            node_dict["riskColor"] = (rk or {}).get("color", "#94A3B8")
            node_dict["indirectExposureUsd"] = (
                indirect_by.get(n.id) or indirect_by.get(_key(n.id)) or 0.0
            )
        json_nodes.append(node_dict)

    # ---- Build JSON edges (only between kept nodes) ----
    json_edges: list[dict[str, Any]] = []
    total_usd = Decimal(0)
    assets: set[str] = set()
    time_min: datetime | None = None
    time_max: datetime | None = None
    for e in edges_list:
        if e.src not in kept_ids or e.dst not in kept_ids:
            continue
        safe_total = _safe_usd_decimal(e.total_usd)
        total_usd += safe_total
        if e.dominant_symbol:
            assets.add(e.dominant_symbol)
        for t in (e.first_time, e.last_time):
            if t is None:
                continue
            time_min = t if time_min is None or t < time_min else time_min
            time_max = t if time_max is None or t > time_max else time_max
        json_edges.append({
            "source": e.src,
            "target": e.dst,
            "totalUsd": f"${safe_total:,.2f}",
            "totalUsdNumeric": _safe_usd_float(e.total_usd),
            "transferCount": e.transfer_count,
            "dominantSymbol": e.dominant_symbol,
            "isCrossChain": (e.src_chain != e.dst_chain),
            "firstTime": _iso_date(e.first_time),
            "lastTime": _iso_date(e.last_time),
            **_edge_tx_payload(tx_by_edge.get((e.src, e.dst), [])),
        })

    # ---- Hop depth from the origin (drives the directional "flow"
    # layout). Shortest forward hop-count from the victim; unreachable
    # nodes sit one column past the deepest reachable node. ----
    origin_id = next(
        (n.id for n in kept_nodes if n.status == "origin"), None
    )
    depths = _compute_depths(origin_id, kept_ids, json_edges)
    for jn in json_nodes:
        jn["depth"] = depths.get(jn["id"], 0)

    # ---- Clusters (only those with 2+ kept members) ----
    cluster_members: dict[str, list[_MutNode]] = {}
    for n in kept_nodes:
        if n.cluster_id:
            cluster_members.setdefault(n.cluster_id, []).append(n)
    json_clusters: list[dict[str, Any]] = []
    for cid, members in cluster_members.items():
        if len(members) < 2:
            # A cluster that ended up with a single kept member is just
            # a normal node — drop the bubble so the client isn't asked
            # to "expand" a group of one.
            for m in members:
                # null the clusterId on the emitted node too
                for jn in json_nodes:
                    if jn["id"] == m.id:
                        jn["clusterId"] = None
            continue
        status = members[0].status
        smeta = _STATUS_META[status]
        # Prefer an entity label if any member carried one.
        label = next(
            (m.cluster_label for m in members if m.cluster_label),
            smeta.label,
        )
        cin = sum((m.inbound for m in members), Decimal(0))
        cout = sum((m.outbound for m in members), Decimal(0))
        json_clusters.append({
            "id": cid,
            "label": label,
            "status": status,
            "statusLabel": smeta.label,
            "statusColor": smeta.color,
            "size": len(members),
            "memberIds": [m.id for m in members],
            "inboundUsd": f"${cin:,.2f}",
            "outboundUsd": f"${cout:,.2f}",
        })

    # ---- "Where your funds are" breakdown over terminal statuses ----
    by_status: dict[str, dict[str, Any]] = {}
    for n in kept_nodes:
        meta = _STATUS_META[n.status]
        if not meta.terminal:
            continue
        slot = by_status.setdefault(
            n.status, {"usd": Decimal(0), "count": 0}
        )
        slot["usd"] += n.inbound
        slot["count"] += 1
    status_totals: list[dict[str, Any]] = []
    for status, slot in sorted(
        by_status.items(), key=lambda kv: _STATUS_META[kv[0]].order
    ):
        meta = _STATUS_META[status]
        status_totals.append({
            "status": status,
            "label": meta.label,
            "color": meta.color,
            "blurb": meta.blurb,
            "usd": _safe_usd_float(slot["usd"]),
            "usdLabel": f"${_safe_usd_decimal(slot['usd']):,.2f}",
            "count": slot["count"],
        })

    summary_line = _summary_line(status_totals)

    return {
        "nodes": json_nodes,
        "edges": json_edges,
        "clusters": json_clusters,
        "statusTotals": status_totals,
        "meta": {
            "nodeCount": len(json_nodes),
            "edgeCount": len(json_edges),
            "totalUsdTraced": f"${_safe_usd_decimal(total_usd):,.2f}",
            "chain": case.chain.value,
            "truncated": hidden > 0,
            "hiddenNodeCount": hidden,
            "summaryLine": summary_line,
            "assets": sorted(assets),
            "timeRange": (
                {"min": _iso_date(time_min), "max": _iso_date(time_max)}
                if time_min and time_max else None
            ),
            "maxDepth": max((jn["depth"] for jn in json_nodes), default=0),
            "riskScored": bool(with_risk and risk_by),
            "sanitized": sanitize,
        },
    }


def _edge_tx_payload(txs: list[dict[str, Any]]) -> dict[str, Any]:
    """Top-N transactions (by USD) for an edge + the dropped count."""
    if not txs:
        return {"transfers": [], "txMore": 0}
    ordered = sorted(txs, key=lambda t: t.get("usd") or 0.0, reverse=True)
    shown = ordered[:_MAX_EDGE_TX]
    return {"transfers": shown, "txMore": max(0, len(ordered) - len(shown))}


def _iso_date(dt: datetime | None) -> str | None:
    """Date-only ISO string (drops time-of-day to limit precision)."""
    if dt is None:
        return None
    try:
        return dt.date().isoformat()
    except Exception:  # noqa: BLE001
        return None


def _compute_depths(
    origin_id: str | None,
    node_ids: set[str],
    edges: list[dict[str, Any]],
) -> dict[str, int]:
    """Shortest forward hop-count from ``origin_id`` over the directed
    edge set. Nodes not reachable forward are placed one column past the
    deepest reachable node so the flow layout still has somewhere to put
    them."""
    adj: dict[str, list[str]] = {nid: [] for nid in node_ids}
    for e in edges:
        s, t = e["source"], e["target"]
        if s in adj and t in adj:
            adj[s].append(t)
    depth: dict[str, int] = {}
    if origin_id and origin_id in adj:
        depth[origin_id] = 0
        dq = deque([origin_id])
        while dq:
            u = dq.popleft()
            for v in adj[u]:
                if v not in depth:
                    depth[v] = depth[u] + 1
                    dq.append(v)
    max_reached = max(depth.values(), default=0)
    for nid in node_ids:
        depth.setdefault(nid, max_reached + 1)
    return depth


def _summary_line(status_totals: list[dict[str, Any]]) -> str:
    """One plain-English sentence: where the largest share of traced
    funds currently sits. Empty string if nothing terminal was found."""
    if not status_totals:
        return ""
    ranked = sorted(status_totals, key=lambda s: s["usd"], reverse=True)
    top = ranked[0]
    if top["usd"] <= 0:
        return ""
    return f"The largest traced share of your funds is {top['label'].lower()}."


__all__ = ("build_journey_data", "build_operator_graph_data")
