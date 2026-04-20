"""Aggregate stolen-funds tally across multiple cases.

Given a list of cases (typically: one victim wallet's case per wallet) and a
list of perpetrator addresses, this filters every transfer where the destination
is a known perpetrator and sums the USD value by asset.

Example:

    recupero aggregate \\
        --cases ZIGHA-VERIFY,ZIGHA-VERIFY-W2,ZIGHA-DUST-01,...,ZIGHA-DUST-20 \\
        --perpetrators 0xF4bE227b...,0x3e2E66af...

Output is a markdown table summarising the theft, plus a JSON file written to
data/cases/aggregate_<timestamp>.json with full per-transfer detail.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

from recupero.models import Case
from recupero.storage.case_store import CaseStore

log = logging.getLogger(__name__)


@dataclass
class StolenAssetSummary:
    symbol: str
    contract: str | None
    transfer_count: int = 0
    total_amount: Decimal = Decimal("0")
    total_usd: Decimal = Decimal("0")
    has_unpriced_transfers: bool = False


@dataclass
class AggregateResult:
    cases_examined: list[str]
    perpetrators: list[str]
    total_usd: Decimal
    transfer_count: int
    by_asset: list[StolenAssetSummary]
    by_victim_wallet: dict[str, Decimal]    # wallet -> total stolen USD from that wallet
    matched_transfers: list[dict[str, Any]] = field(default_factory=list)


def aggregate_stolen(
    *,
    cases: list[Case],
    perpetrator_addresses: list[str],
    exclude_internal_transfers: bool = True,
) -> AggregateResult:
    """Sum perpetrator-bound transfers across the given cases.

    If ``exclude_internal_transfers=True`` (default), transfers between two
    known perpetrator addresses are NOT counted. This is the behavior you
    almost always want: internal perp-to-perp movements represent the same
    stolen funds sloshing through the perpetrator's wallet network, not
    additional theft. Without this, the $3.12M mSyrupUSDp gets counted once
    when it leaves the victim (correct) and again when it's forwarded from
    the perpetrator's wallet #1 to wallet #2 (double-count).
    """
    perp_lower = {a.lower() for a in perpetrator_addresses}
    by_asset_map: dict[tuple[str, str | None], StolenAssetSummary] = {}
    by_victim: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    matched: list[dict[str, Any]] = []
    total_usd = Decimal("0")
    n = 0
    skipped_internal = 0

    for case in cases:
        for t in case.transfers:
            if t.to_address.lower() not in perp_lower:
                continue
            # Skip perpetrator-to-perpetrator internal movements — that's the
            # same stolen money, not additional theft.
            if exclude_internal_transfers and t.from_address.lower() in perp_lower:
                skipped_internal += 1
                continue
            n += 1
            key = (t.token.symbol, t.token.contract)
            summary = by_asset_map.setdefault(key, StolenAssetSummary(
                symbol=t.token.symbol, contract=t.token.contract,
            ))
            summary.transfer_count += 1
            summary.total_amount += t.amount_decimal
            if t.usd_value_at_tx is not None:
                summary.total_usd += t.usd_value_at_tx
                total_usd += t.usd_value_at_tx
                by_victim[t.from_address] += t.usd_value_at_tx
            else:
                summary.has_unpriced_transfers = True
            matched.append({
                "case_id": case.case_id,
                "tx_hash": t.tx_hash,
                "block_time": t.block_time.isoformat(),
                "from": t.from_address,
                "to": t.to_address,
                "symbol": t.token.symbol,
                "contract": t.token.contract,
                "amount": str(t.amount_decimal),
                "usd": str(t.usd_value_at_tx) if t.usd_value_at_tx is not None else None,
                "explorer_url": t.explorer_url,
            })

    if skipped_internal:
        log.info(
            "aggregate: excluded %d perpetrator-to-perpetrator internal transfers "
            "(same stolen funds moving between already-identified perp wallets)",
            skipped_internal,
        )

    return AggregateResult(
        cases_examined=[c.case_id for c in cases],
        perpetrators=list(perpetrator_addresses),
        total_usd=total_usd,
        transfer_count=n,
        by_asset=sorted(by_asset_map.values(), key=lambda s: s.total_usd, reverse=True),
        by_victim_wallet=dict(by_victim),
        matched_transfers=matched,
    )


def format_aggregate_markdown(r: AggregateResult) -> str:
    """Render the aggregate as a human-readable markdown summary."""
    lines = []
    lines.append(f"# Stolen funds aggregate")
    lines.append("")
    lines.append(f"- **Cases examined:** {len(r.cases_examined)}")
    lines.append(f"- **Perpetrator addresses:** {len(r.perpetrators)}")
    lines.append(f"- **Matched transfers:** {r.transfer_count}")
    lines.append(f"- **Total USD stolen (priced transfers only):** ${r.total_usd:,.2f}")
    lines.append("")

    lines.append("## By asset")
    lines.append("")
    lines.append("| Asset | Contract | # Transfers | Total amount | Total USD |")
    lines.append("|-------|----------|-------------|--------------|-----------|")
    for s in r.by_asset:
        contract = s.contract or "(native)"
        contract_short = contract[:10] + "..." if len(contract) > 14 else contract
        usd_str = f"${s.total_usd:,.2f}"
        if s.has_unpriced_transfers:
            usd_str += " *"
        amount_str = f"{s.total_amount:,}" if s.total_amount == s.total_amount.to_integral_value() else f"{s.total_amount:,.6f}".rstrip("0").rstrip(".")
        lines.append(f"| {s.symbol} | `{contract_short}` | {s.transfer_count} | {amount_str} | {usd_str} |")
    if any(s.has_unpriced_transfers for s in r.by_asset):
        lines.append("")
        lines.append("`*` = some transfers of this asset could not be priced; the listed total reflects priced transfers only.")
    lines.append("")

    lines.append("## By victim wallet")
    lines.append("")
    lines.append("| Wallet | Total stolen (USD) |")
    lines.append("|--------|-------------------|")
    for wallet, usd in sorted(r.by_victim_wallet.items(), key=lambda kv: kv[1], reverse=True):
        lines.append(f"| `{wallet}` | ${usd:,.2f} |")
    lines.append("")

    return "\n".join(lines)


def write_aggregate_json(r: AggregateResult, out_path: Path) -> None:
    """Write the full aggregate (with all per-transfer detail) to disk."""
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cases_examined": r.cases_examined,
        "perpetrators": r.perpetrators,
        "total_usd": str(r.total_usd),
        "transfer_count": r.transfer_count,
        "by_asset": [
            {
                "symbol": s.symbol, "contract": s.contract,
                "transfer_count": s.transfer_count,
                "total_amount": str(s.total_amount),
                "total_usd": str(s.total_usd),
                "has_unpriced_transfers": s.has_unpriced_transfers,
            }
            for s in r.by_asset
        ],
        "by_victim_wallet": {k: str(v) for k, v in r.by_victim_wallet.items()},
        "matched_transfers": r.matched_transfers,
    }
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
