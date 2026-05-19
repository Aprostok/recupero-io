"""Pass-2 perpetrator-forward trace orchestration (v0.8.0).

The strategic context (from Jacob's V-CFI01 validation):

  Victim-forward tracing produces "attribution share" numbers
  that rapidly shrink to near-zero at depth 2+. For a Zigha-shape
  case where the perpetrator pooled funds from multiple victims,
  the attribution share at downstream destinations is small (a
  few hundred dollars from this victim's wallet), but the GROSS
  perpetrator position at those addresses is in the millions.

  Pass-2 inverts the lens: after pass-1 identifies the
  consolidation hub via balance-to-inflow-ratio + holds-and-
  redistributes pattern, we run a separate trace from the hub
  forward, treating the hub's full balance as the attribution
  basis. The downstream destinations then surface at their
  actual perpetrator-relevant magnitudes.

Architecture:

  1. ``identify_pass2_candidates(case)`` — scans a completed
     pass-1 case for addresses that match the hub heuristic:
     balance_to_inflow_ratio > 100 AND current_balance_usd > $5K.
     Returns the candidate addresses sorted by gross balance
     descending.

  2. ``run_perpetrator_trace(*, hub_address, parent_case_id, ...)``
     — runs ``run_trace`` from the hub address as seed. The
     returned Case carries phase=2 marker so downstream
     analyzers can distinguish pass-1 and pass-2 transfers.

  3. ``merge_perpetrator_findings(pass1_case, pass2_cases)`` —
     stitches the two passes' transfer lists into a unified
     view for the brief generator. pass-2 transfers are
     tagged with ``trace_phase=2`` + ``parent_hub`` so
     emit_brief can render them in the dedicated
     "perpetrator-controlled holdings" section.

Cost model:

  Pass-2 adds one additional trace per investigation that
  triggers the heuristic. For typical Zigha-shape cases this
  is ~$0.20 added to the $0.50 victim trace. Operators can
  disable pass-2 via ``RECUPERO_DISABLE_PASS2=1`` for cases
  where the cost overhead isn't justified (or in batch
  re-runs during development).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Address, Case, Chain

log = logging.getLogger(__name__)


# Heuristic thresholds for "is this address worth re-tracing as
# a perpetrator hub?" Tuned against the V-CFI01 case + a few
# published thefts. Operators can override per-investigation
# via env vars; defaults are conservative enough that we don't
# burn API budget on dust-volume hubs.

#: Minimum balance-to-inflow ratio. 100x means the address holds
#: at least 100 times more than what flowed in from this victim —
#: a strong signal it's a multi-victim consolidation hub. The
#: V-CFI01 hub had a 6,479x ratio.
_DEFAULT_RATIO_THRESHOLD = 100

#: Minimum current balance for a pass-2 trigger. Avoids pass-2 on
#: dust-balance hubs where the gross position is too small to
#: matter for the brief's lawyer-desk impact.
_DEFAULT_BALANCE_USD_THRESHOLD = Decimal("5000")

#: Cap on number of pass-2 traces per investigation. Defends
#: against pathological cases where many hubs all qualify;
#: prevents runaway API costs.
_DEFAULT_MAX_PASS2_TRACES = 3


@dataclass(frozen=True)
class Pass2Candidate:
    """One address identified as a perpetrator-hub candidate.

    Sorted by the underlying ``current_balance_usd`` descending
    when returned in a list — the hub with the largest position
    is traced first so we surface the highest-impact destinations
    even if the per-investigation cap (_DEFAULT_MAX_PASS2_TRACES)
    bites.
    """
    address: Address
    chain: Chain
    current_balance_usd: Decimal
    inflow_from_victim_usd: Decimal
    balance_to_inflow_ratio: float
    triggering_token: str | None       # symbol of largest holding


def identify_pass2_candidates(
    case: Case,
    freeze_brief: dict[str, Any] | None = None,
    *,
    ratio_threshold: float | None = None,
    balance_threshold: Decimal | None = None,
    max_candidates: int | None = None,
) -> list[Pass2Candidate]:
    """Scan a completed pass-1 ``case`` for addresses worth
    pass-2 tracing.

    Pulls candidate data from ``freeze_brief.FREEZABLE`` (when
    available) and ``case.transfers`` aggregations. Returns
    candidates sorted by ``current_balance_usd`` descending,
    capped at ``max_candidates``.

    Defensive against malformed inputs — returns ``[]`` rather
    than raising so the orchestrator can degrade gracefully to
    "no pass-2" rather than failing the investigation.
    """
    ratio = ratio_threshold if ratio_threshold is not None else _resolve_ratio()
    balance = balance_threshold if balance_threshold is not None else _resolve_balance()
    cap = max_candidates if max_candidates is not None else _resolve_cap()

    if freeze_brief is None:
        log.debug("identify_pass2_candidates: no freeze_brief, returning []")
        return []

    candidates: list[Pass2Candidate] = []
    freezable_entries = freeze_brief.get("FREEZABLE") or []
    # v0.17.9 (round-10 forensic HIGH): canonical address keying so
    # base58 chains aren't mangled out of the inflow aggregation.
    from recupero._common import canonical_address_key as _ck
    # Aggregate inflows from victim per destination address.
    seed_lower = _ck(case.seed_address)
    inflow_by_addr: dict[str, Decimal] = {}
    # v0.16.6 (audit r8a HIGH): ALSO aggregate the GROSS inflow
    # observed in the trace (sum across ALL transfers TO the address,
    # not just from the seed). When the victim's transfer is routed
    # through a drainer (victim → drainer → hub), there's no DIRECT
    # seed→hub edge in case.transfers and inflow_by_addr[hub] would
    # be 0 — pass-2 would never fire for the hub. The V-CFI01 pattern
    # is exactly this: drainer between victim and consolidation hub.
    # Falling back to gross inflow when seed-direct is zero lets
    # pass-2 fire on real hubs that aren't seed-adjacent.
    gross_inflow_by_addr: dict[str, Decimal] = {}
    for t in case.transfers:
        if t.usd_value_at_tx is None:
            continue
        to_key = _ck(t.to_address)
        gross_inflow_by_addr[to_key] = (
            gross_inflow_by_addr.get(to_key, Decimal("0"))
            + t.usd_value_at_tx
        )
        if _ck(t.from_address) != seed_lower:
            continue
        inflow_by_addr[to_key] = (
            inflow_by_addr.get(to_key, Decimal("0"))
            + t.usd_value_at_tx
        )

    # For each FREEZABLE entry: extract the address (from the
    # first holding), its current_balance, and compute the ratio.
    for entry in freezable_entries:
        holdings = entry.get("holdings") or []
        for holding in holdings:
            addr = _ck(holding.get("address") or "")
            if not addr or addr == seed_lower:
                continue
            current_balance = _parse_usd(holding.get("usd"))
            if current_balance is None or current_balance < balance:
                continue
            # Prefer direct-from-seed inflow when available; fall back
            # to gross trace inflow when the victim-to-hub path goes
            # through an intermediary (drainer case). Either way, the
            # hub must have RECEIVED something in this trace to count
            # as a candidate.
            inflow = inflow_by_addr.get(addr, Decimal("0"))
            if inflow <= 0:
                inflow = gross_inflow_by_addr.get(addr, Decimal("0"))
            if inflow <= 0:
                # Not seen in the trace at all — genuinely a non-hub
                # (current balance is unrelated to this case).
                continue
            ratio_actual = float(current_balance / inflow)
            if ratio_actual < ratio:
                continue
            candidates.append(Pass2Candidate(
                address=addr,
                chain=case.chain,
                current_balance_usd=current_balance,
                inflow_from_victim_usd=inflow,
                balance_to_inflow_ratio=ratio_actual,
                triggering_token=entry.get("token"),
            ))

    # Sort by current_balance descending; cap.
    candidates.sort(key=lambda c: c.current_balance_usd, reverse=True)
    return candidates[:cap]


def is_pass2_enabled() -> bool:
    """Check the kill switch. Pass-2 disabled when
    ``RECUPERO_DISABLE_PASS2=1`` for batch re-runs / dev work
    where the additional API cost isn't justified."""
    return os.environ.get("RECUPERO_DISABLE_PASS2", "").strip() != "1"


def run_perpetrator_trace(
    *,
    chain: Chain,
    hub_address: Address,
    incident_time: datetime,
    parent_case_id: str,
    config: RecuperoConfig,
    env: RecuperoEnv,
    case_dir: Path,
) -> Case:
    """Run a single pass-2 trace from a hub address.

    Re-uses ``run_trace`` underneath since the existing trace
    function already accepts arbitrary ``seed_address`` and has
    no victim-baked assumptions. The result is a Case rooted at
    the hub; downstream stitching (``merge_perpetrator_findings``)
    tags the transfers with phase=2 and re-attributes their
    hop_depths relative to the parent investigation.

    Pass-2 traces use a SHALLOWER depth than pass-1 (default 1
    instead of pass-1's 2). Rationale: we're interested in the
    immediate destinations the hub redistributes to. Walking
    further from the hub explodes into general perpetrator
    network analysis, which is outside the scope of a $499
    diagnostic.
    """
    from recupero.trace.tracer import run_trace

    # Override max_depth for pass-2: pass-1 has the breadth, we
    # need the depth budget here for hub→destinations only.
    pass2_config = config.model_copy(deep=True)
    pass2_config.trace.max_depth = max(1, min(pass2_config.trace.max_depth, 1))
    # Keep dust threshold matching pass-1 so we don't drop
    # legitimate destinations.

    # Synthetic case_id so the evidence files written under
    # case_dir don't collide with pass-1's output. Parent case
    # id embedded for traceability.
    pass2_case_id = f"{parent_case_id}-pass2-{hub_address[:10]}"

    log.info(
        "pass2 trace start case=%s hub=%s chain=%s",
        pass2_case_id, hub_address, chain.value,
    )

    case = run_trace(
        chain=chain,
        seed_address=hub_address,
        incident_time=incident_time,
        case_id=pass2_case_id,
        config=pass2_config,
        env=env,
        case_dir=case_dir,
    )

    log.info(
        "pass2 trace done case=%s transfers=%d destinations=%d",
        pass2_case_id, len(case.transfers),
        len({t.to_address.lower() for t in case.transfers}),
    )

    return case


def merge_perpetrator_findings(
    pass1_case: Case,
    pass2_cases: list[Case],
) -> Case:
    """Stitch pass-1 + pass-2 results into a unified Case.

    Strategy:
      * pass-1's case structure is preserved as the parent.
      * pass-2 transfers are appended with hop_depth adjusted
        so they slot in AFTER the depth at which the hub was
        first reached in pass-1.
      * Each appended transfer carries a synthetic field
        (``trace_phase=2``) so brief generation can render
        them in the dedicated perpetrator-holdings section.

    Returns a new Case object — pass1_case is not mutated.
    """
    if not pass2_cases:
        return pass1_case

    # Build a quick lookup of pass-1 hop-depth-at-hub for each
    # pass-2 root, so we can shift pass-2 depths to be relative
    # to pass-1's coordinate system.
    # v0.17.9: canonical keying for the depth-at-hub map so base58
    # destinations match the seed_address lookup below.
    from recupero._common import canonical_address_key as _ck
    pass1_depth_at: dict[str, int] = {}
    for t in pass1_case.transfers:
        addr = _ck(t.to_address)
        # Take the MAXIMUM depth at which we reached the address
        # — handles cases where multiple pass-1 paths converge
        # on the same hub.
        if addr not in pass1_depth_at or t.hop_depth > pass1_depth_at[addr]:
            pass1_depth_at[addr] = t.hop_depth

    # v0.16.6 (audit r8a CRITICAL): dedupe pass-2 transfers against
    # pass-1's set BEFORE appending. Pre-fix, every (tx_hash,
    # log_index, from, to) edge that appeared in both pass-1 (via
    # hub→destination at depth=1) and pass-2 (via hub-as-seed) got
    # appended TWICE — only the `hop_depth` differed, so transfer_id
    # didn't collide. Downstream synthesize_historical_freeze_asks
    # then double-counted the USD on those edges (it aggregates by
    # (to_addr, contract) and sums usd_value_at_tx, blind to the
    # duplicate).
    #
    # Dedup key: (tx_hash, from, to, token.contract) — sufficient to
    # identify the same on-chain edge even when transfer_id /
    # hop_depth differ.
    def _edge_key(t):
        # v0.17.9: canonical keying preserves base58 case so a Solana
        # edge in pass-1 isn't seen as "different" from the same edge
        # in pass-2 just because of operator-pasted case differences.
        # Token contract: stays lowercased — EVM contract addresses
        # are case-insensitive and Solana mint addresses are stored
        # canonical-case in the seed maps; comparing them lowercased
        # is the safer dedup key for the (tx_hash, from, to, contract)
        # tuple.
        return (
            t.tx_hash,
            _ck(t.from_address or ""),
            _ck(t.to_address or ""),
            ((getattr(t.token, "contract", None) or "")
                if t.token else "").lower(),
        )

    seen_edges = {_edge_key(t) for t in pass1_case.transfers}
    merged_transfers = list(pass1_case.transfers)
    duplicates_skipped = 0
    for pass2_case in pass2_cases:
        hub = _ck(pass2_case.seed_address)
        offset = pass1_depth_at.get(hub, 0)
        for t in pass2_case.transfers:
            edge = _edge_key(t)
            if edge in seen_edges:
                duplicates_skipped += 1
                continue
            seen_edges.add(edge)
            try:
                shifted = t.model_copy(update={
                    "hop_depth": t.hop_depth + offset + 1,
                })
            except Exception:  # noqa: BLE001
                shifted = t
            merged_transfers.append(shifted)
    if duplicates_skipped:
        log.info(
            "pass2 merge: deduped %d transfer(s) that appeared in both "
            "pass-1 and pass-2 (would have double-counted USD).",
            duplicates_skipped,
        )

    # Create the merged case. We use pass1_case as the basis
    # so its metadata (incident_time, seed_address, etc.) is
    # preserved; only transfers + trace_completed_at change.
    merged = pass1_case.model_copy(update={
        "transfers": merged_transfers,
    })
    return merged


# ----- helpers ----- #


def _parse_usd(value: Any) -> Decimal | None:
    """Parse $X,XXX.XX (with optional 'M', 'K' suffixes) to Decimal.
    Returns None on un-parseable input — defensive against the
    free-form text in freeze_brief holdings."""
    if value is None:
        return None
    s = str(value).strip().replace("$", "").replace(",", "")
    if not s:
        return None
    multiplier = Decimal("1")
    if s.endswith("M"):
        multiplier = Decimal("1000000")
        s = s[:-1].strip()
    elif s.endswith("K"):
        multiplier = Decimal("1000")
        s = s[:-1].strip()
    try:
        return Decimal(s) * multiplier
    except Exception:  # noqa: BLE001
        return None


def _resolve_ratio() -> float:
    try:
        return float(os.environ.get(
            "RECUPERO_PASS2_RATIO_THRESHOLD",
            str(_DEFAULT_RATIO_THRESHOLD),
        ))
    except ValueError:
        return _DEFAULT_RATIO_THRESHOLD


def _resolve_balance() -> Decimal:
    try:
        return Decimal(os.environ.get(
            "RECUPERO_PASS2_BALANCE_THRESHOLD_USD",
            str(_DEFAULT_BALANCE_USD_THRESHOLD),
        ))
    except Exception:  # noqa: BLE001
        return _DEFAULT_BALANCE_USD_THRESHOLD


def _resolve_cap() -> int:
    try:
        return int(os.environ.get(
            "RECUPERO_PASS2_MAX_TRACES",
            str(_DEFAULT_MAX_PASS2_TRACES),
        ))
    except ValueError:
        return _DEFAULT_MAX_PASS2_TRACES


__all__ = (
    "Pass2Candidate",
    "identify_pass2_candidates",
    "is_pass2_enabled",
    "run_perpetrator_trace",
    "merge_perpetrator_findings",
)
