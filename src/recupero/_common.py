"""Shared helpers used across reports / worker / recovery / ops.

Single source of truth for:
  * freeze_capability raw ↔ display mapping
  * chain-explorer URL prefixes
  * evidence-mode aggregation across freezable holdings

Pre-v0.16.4 these lived as literal dicts and ad-hoc helpers duplicated
across 5+ modules. Behavior is identical; this module just centralizes
the mapping tables so future updates (new chain, new capability tier)
happen in one place.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


# ---- freeze_capability mapping ---- #

# `IssuerEntry.freeze_capability` raw values come from issuers.json.
# emit_brief.py + the worker's skip-editorial synthesizer map these
# to display form ("HIGH"/"MEDIUM"/"LOW") for the trace_report,
# investigator_findings, and freeze-letter templates.
CAPABILITY_DISPLAY: dict[str, str] = {
    "yes": "HIGH",
    "limited": "MEDIUM",
    "no": "LOW",
}

# Capabilities that BLOCK the freeze pathway entirely. Both raw and
# display forms accepted because consumer code reads from either
# layer of the pipeline.
_NON_FREEZABLE_CAPABILITIES: frozenset[str] = frozenset({"no", "low"})

# Capabilities that have ACTIONABLE freeze authority.
_FREEZABLE_CAPABILITIES: frozenset[str] = frozenset({
    "yes", "limited", "high", "medium",
})


def capability_display(raw: str | None) -> str:
    """Map a raw freeze_capability ('yes'/'limited'/'no') to display
    form ('HIGH'/'MEDIUM'/'LOW'). Unknown / empty → 'UNKNOWN'."""
    if not raw:
        return "UNKNOWN"
    return CAPABILITY_DISPLAY.get(raw.lower(), "UNKNOWN")


def capability_blocks_freeze(capability: str | None) -> bool:
    """True if the capability indicates the issuer CANNOT freeze the
    token (e.g., DAI / Sky Protocol). Accepts both raw ("no") and
    display ("LOW") forms — emit_brief.py maps raw → display, but
    older brief readers + the skip-editorial synthesizer may carry
    the raw form."""
    if not capability:
        return False
    return capability.lower() in _NON_FREEZABLE_CAPABILITIES


def capability_is_freezable(capability: str | None) -> bool:
    """True if the issuer has actionable freeze authority. Accepts
    both raw and display forms; treats empty/unknown as False."""
    if not capability:
        return False
    return capability.lower() in _FREEZABLE_CAPABILITIES


# ---- Chain-explorer URL prefixes ---- #

# Pre-v0.16.4 this dict was duplicated in 5 files. Centralized here.
ADDRESS_EXPLORER_BY_CHAIN: dict[str, str] = {
    "ethereum":    "https://etherscan.io/address/",
    "arbitrum":    "https://arbiscan.io/address/",
    "polygon":     "https://polygonscan.com/address/",
    "base":        "https://basescan.org/address/",
    "bsc":         "https://bscscan.com/address/",
    "solana":      "https://solscan.io/account/",
    "hyperliquid": "https://app.hyperliquid.xyz/explorer/address/",
    "bitcoin":     "https://mempool.space/address/",
    "tron":        "https://tronscan.org/#/address/",
}


# ---- Evidence-mode aggregation ---- #

# `evidence_mode` aggregates the per-holding evidence_type fields up
# to a single label that templates can branch on. v0.16.1 added these
# at the per-issuer level (emit_brief._extract_freezable); v0.16.2
# extended to aggregate-across-issuers for customer/engagement letters.
_VALID_EVIDENCE_MODES: frozenset[str] = frozenset({
    "current_balance_only",
    "historical_only",
    "mixed",
})


def aggregate_evidence_mode_from_holdings(
    holdings: Iterable[Mapping[str, Any]],
    *,
    evidence_type_key: str = "evidence_type",
) -> str:
    """Compute the per-issuer evidence_mode from a list of holding
    dicts. Each holding should carry an `evidence_type` field
    ('current_balance' or 'historical_inflow').

    Returns one of: 'current_balance_only' / 'historical_only' /
    'mixed'. Defaults to 'current_balance_only' when holdings is
    empty (the conservative default — matches pre-v0.16.4 behavior).
    """
    n_historical = 0
    n_current = 0
    for h in holdings:
        ev = h.get(evidence_type_key)
        if ev == "historical_inflow":
            n_historical += 1
        else:
            n_current += 1
    if n_historical > 0 and n_current == 0:
        return "historical_only"
    if n_historical > 0 and n_current > 0:
        return "mixed"
    return "current_balance_only"


def aggregate_evidence_mode_from_entries(
    entries: Iterable[Mapping[str, Any]],
    *,
    mode_key: str = "evidence_mode",
) -> str:
    """Compute the aggregate evidence_mode across multiple FREEZABLE
    entries (one per issuer). Used by the customer-letter + engagement-
    letter contexts to pick the right "currently held" vs "received at"
    phrasing.

    Each entry's `evidence_mode` is one of historical_only / mixed /
    current_balance_only. The aggregate is:
      * 'historical_only'  iff ALL entries are historical_only
      * 'current_balance_only' iff NO entry is historical_only AND NO
        entry is mixed
      * 'mixed' otherwise
    """
    n_with_current = 0
    n_with_historical = 0
    for entry in entries:
        mode = entry.get(mode_key)
        if mode in ("current_balance_only", "mixed"):
            n_with_current += 1
        if mode in ("historical_only", "mixed"):
            n_with_historical += 1
    if n_with_historical > 0 and n_with_current == 0:
        return "historical_only"
    if n_with_historical > 0 and n_with_current > 0:
        return "mixed"
    return "current_balance_only"


__all__ = (
    "CAPABILITY_DISPLAY",
    "ADDRESS_EXPLORER_BY_CHAIN",
    "capability_display",
    "capability_blocks_freeze",
    "capability_is_freezable",
    "aggregate_evidence_mode_from_holdings",
    "aggregate_evidence_mode_from_entries",
)
