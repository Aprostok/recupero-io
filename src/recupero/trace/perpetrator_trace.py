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
from recupero.models import Address, Case, Chain, Transfer

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
    # Aggregate inflows from victim per destination address.
    seed_lower = case.seed_address.lower()
    inflow_by_addr: dict[str, Decimal] = {}
    for t in case.transfers:
        if t.from_address.lower() != seed_lower:
            continue
        if t.usd_value_at_tx is None:
            continue
        key = t.to_address.lower()
        inflow_by_addr[key] = inflow_by_addr.get(key, Decimal("0")) + t.usd_value_at_tx

    # For each FREEZABLE entry: extract the address (from the
    # first holding), its current_balance, and compute the ratio.
    for entry in freezable_entries:
        holdings = entry.get("holdings") or []
        for holding in holdings:
            addr = (holding.get("address") or "").lower()
            if not addr or addr == seed_lower:
                continue
            current_balance = _parse_usd(holding.get("usd"))
            if current_balance is None or current_balance < balance:
                continue
            inflow = inflow_by_addr.get(addr, Decimal("0"))
            if inflow <= 0:
                # No traceable inflow from this victim → not a
                # candidate (it's downstream noise, not a hub).
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
    pass1_depth_at: dict[str, int] = {}
    for t in pass1_case.transfers:
        addr = t.to_address.lower()
        # Take the MAXIMUM depth at which we reached the address
        # — handles cases where multiple pass-1 paths converge
        # on the same hub.
        if addr not in pass1_depth_at or t.hop_depth > pass1_depth_at[addr]:
            pass1_depth_at[addr] = t.hop_depth

    merged_transfers = list(pass1_case.transfers)
    for pass2_case in pass2_cases:
        hub = pass2_case.seed_address.lower()
        offset = pass1_depth_at.get(hub, 0)
        for t in pass2_case.transfers:
            # Build a new Transfer with shifted depth + phase tag.
            # We rely on Transfer being a pydantic model with
            # model_copy() — adjust if the underlying impl changes.
            try:
                shifted = t.model_copy(update={
                    "hop_depth": t.hop_depth + offset + 1,
                })
            except Exception:  # noqa: BLE001
                shifted = t
            merged_transfers.append(shifted)

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
