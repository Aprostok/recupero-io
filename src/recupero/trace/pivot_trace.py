"""Multi-chain perpetrator-pivot trace (v0.34, operator-requested "find
everything stolen").

Why this exists
---------------

A victim-forward trace on ONE chain only sees the victim's slice on that chain.
But a perpetrator consolidates the full haul at a hub and **splits it across
chains** — bridging to another L2/L1, swapping, and parking the proceeds far
from the victim's chain. The Zigha backward-trace proved it: the victim seed's
$3.12M went to the hub → Midas on Ethereum, while the hub's ~$18M ALSO sits on
Arbitrum and bridges to Ethereum where it becomes the dormant DAI. A single
`--chain ethereum` run can never see the Arbitrum side.

The pivot inverts the lens once the hub is known: re-trace the HUB on EVERY
supported EVM chain (value-directed, so it stays on the money path), then merge
those findings into the victim case. The hub ties the perpetrator's cross-chain
activity together; tracing it everywhere is what surfaces the funds the
single-chain victim trace structurally cannot reach.

This module is deliberately thin: it reuses ``run_trace`` (per chain, with
value-trace forced on) and ``merge_perpetrator_findings`` (dedupe + depth-shift)
from the existing pass-2 plumbing. The only new logic is (a) identifying the
hub from a completed case and (b) the per-chain orchestration loop.

Gated OFF by default (``RECUPERO_PIVOT_MULTICHAIN``) — it multiplies API cost by
the number of pivot chains, so it is opt-in per investigation.
"""

from __future__ import annotations

import logging
import os
from decimal import Decimal

from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Address, Case, Chain

log = logging.getLogger(__name__)

#: Default EVM chains to pivot across — the major laundering rails. One
#: Etherscan V2 key covers all of them (chain_id dispatch), so adding chains
#: costs only the per-chain trace, not new credentials. Override with
#: ``RECUPERO_PIVOT_CHAINS=arbitrum,base,...``.
DEFAULT_PIVOT_CHAINS: tuple[Chain, ...] = (
    Chain.ethereum,
    Chain.arbitrum,
    Chain.base,
    Chain.optimism,
    Chain.polygon,
    Chain.bsc,
)

#: Minimum inbound USD for an address to be considered a consolidation hub
#: worth pivoting on. Avoids burning N-chain traces on a dust counterparty.
_DEFAULT_PIVOT_MIN_USD = Decimal("50000")

#: Label categories that mark an address as a SERVICE (not a perpetrator hub) —
#: re-tracing an exchange / bridge / mixer / DeFi protocol across chains is
#: pointless (it's everyone's money, not the perp's). Matched case-insensitively
#: against the counterparty label's category/name.
_SERVICE_LABEL_MARKERS = (
    "exchange", "cex", "bridge", "mixer", "tumbler", "defi", "dex",
    "router", "pool", "lending", "staking", "vault", "protocol", "market",
)


def is_pivot_enabled() -> bool:
    """Multi-chain pivot is OPT-IN (it multiplies API cost). Enable with
    ``RECUPERO_PIVOT_MULTICHAIN`` in {1,true,yes,on}."""
    return os.environ.get(
        "RECUPERO_PIVOT_MULTICHAIN", "",
    ).strip().lower() in ("1", "true", "yes", "on")


def resolve_pivot_chains() -> list[Chain]:
    """Resolve the pivot chain set from ``RECUPERO_PIVOT_CHAINS`` (comma list of
    Chain enum values) or the default major-EVM set. Unknown names are skipped
    with a warning; duplicates removed; order preserved."""
    raw = os.environ.get("RECUPERO_PIVOT_CHAINS", "").strip()
    if not raw:
        return list(DEFAULT_PIVOT_CHAINS)
    out: list[Chain] = []
    for part in raw.split(","):
        name = part.strip().lower()
        if not name:
            continue
        try:
            ch = Chain(name)
        except ValueError:
            log.warning("RECUPERO_PIVOT_CHAINS: unknown chain %r — skipping", name)
            continue
        if ch not in out:
            out.append(ch)
    return out or list(DEFAULT_PIVOT_CHAINS)


def _is_service_label(label: object) -> bool:
    if label is None:
        return False
    for attr in ("category", "type", "name"):
        v = getattr(label, attr, None)
        if v is None and isinstance(label, dict):
            v = label.get(attr)
        if isinstance(v, str):
            lv = v.lower()
            if any(m in lv for m in _SERVICE_LABEL_MARKERS):
                return True
    return False


def identify_pivot_hub(
    case: Case,
    *,
    min_usd: Decimal | None = None,
) -> tuple[Address, Chain] | None:
    """Pick the perpetrator consolidation hub from a completed case.

    The hub is the largest-USD inbound recipient of the traced funds that is
    (a) not the seed, (b) not a labeled service (exchange/bridge/mixer/DeFi),
    and (c) preferably an EOA — the perp's pass-through wallet, not a terminal
    vault/contract position (e.g. a Midas vault). Falls back to including
    contracts only if no qualifying EOA exists (covers Safe-multisig hubs).

    Returns ``(address, chain)`` (the hub's discovery chain) or ``None`` when no
    address qualifies. Defensive: never raises — degrades to "no pivot".
    """
    floor = min_usd if min_usd is not None else _resolve_min_usd()
    from recupero._common import canonical_address_key as _ck

    seed = _ck(case.seed_address)
    inflow: dict[str, Decimal] = {}
    display: dict[str, Address] = {}
    chain_of: dict[str, Chain] = {}
    min_depth: dict[str, int] = {}
    is_contract: dict[str, bool] = {}
    is_service: dict[str, bool] = {}

    for t in case.transfers:
        if t.usd_value_at_tx is None:
            continue
        k = _ck(t.to_address)
        if k == seed:
            continue
        inflow[k] = inflow.get(k, Decimal(0)) + t.usd_value_at_tx
        display.setdefault(k, t.to_address)
        chain_of[k] = t.chain
        d = getattr(t, "hop_depth", 0)
        if k not in min_depth or d < min_depth[k]:
            min_depth[k] = d
        cp = getattr(t, "counterparty", None)
        if cp is not None:
            if getattr(cp, "is_contract", False):
                is_contract[k] = True
            if _is_service_label(getattr(cp, "label", None)):
                is_service[k] = True

    qualified = {
        k: v for k, v in inflow.items()
        if v >= floor and not is_service.get(k, False)
    }
    if not qualified:
        return None

    # Prefer EOAs (perp pass-through wallets). Sort key: EOA-first, then
    # shallowest hop, then largest USD. A vault/contract terminal position
    # (e.g. Midas) only wins if no EOA qualifies.
    def _rank(k: str) -> tuple:
        return (
            0 if not is_contract.get(k, False) else 1,  # EOA first
            min_depth.get(k, 99),                        # shallowest first
            -float(qualified[k]),                        # largest USD first
        )

    best = min(qualified, key=_rank)
    return display[best], chain_of[best]


def run_pivot_multichain(
    *,
    hub_address: Address,
    hub_chain: Chain,
    incident_time,
    parent_case_id: str,
    config: RecuperoConfig,
    env: RecuperoEnv,
    case_dir,
    chains: list[Chain] | None = None,
) -> list[Case]:
    """Re-trace ``hub_address`` on every pivot chain EXCEPT ``hub_chain`` (the
    discovery chain, already traced in the victim pass). Value-directed tracing
    is forced ON so each re-trace follows the money path and stays narrow.

    Returns the list of Cases for chains where the hub was active (had any
    transfers). Per-chain failures are logged and skipped — one dead RPC never
    fails the whole pivot.
    """
    from recupero.trace.tracer import run_trace

    pivot_chains = chains if chains is not None else resolve_pivot_chains()
    out: list[Case] = []
    for ch in pivot_chains:
        if ch == hub_chain:
            continue
        pivot_case_id = f"{parent_case_id}-pivot-{ch.value}-{hub_address[:8]}"
        try:
            case = run_trace(
                chain=ch,
                seed_address=hub_address,
                incident_time=incident_time,
                case_id=pivot_case_id,
                config=config,
                env=env,
                case_dir=case_dir,
                value_trace=True,
            )
        except Exception as exc:  # noqa: BLE001 — one chain must not fail the pivot
            log.warning("pivot trace on %s failed (non-fatal): %s", ch.value, exc)
            continue
        if case.transfers:
            log.info(
                "pivot %s: hub active — %d transfer(s) on chain",
                ch.value, len(case.transfers),
            )
            out.append(case)
        else:
            log.debug("pivot %s: hub inactive (0 transfers) — skipped", ch.value)
    return out


def _resolve_min_usd() -> Decimal:
    try:
        return Decimal(os.environ.get(
            "RECUPERO_PIVOT_MIN_USD", str(_DEFAULT_PIVOT_MIN_USD),
        ))
    except Exception:  # noqa: BLE001
        return _DEFAULT_PIVOT_MIN_USD


__all__ = (
    "DEFAULT_PIVOT_CHAINS",
    "identify_pivot_hub",
    "is_pivot_enabled",
    "resolve_pivot_chains",
    "run_pivot_multichain",
)
