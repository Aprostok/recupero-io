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
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from recupero._common import atomic_write_text, resolve_render_time
from recupero.models import Case

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
    # v0.17.9 (round-10 forensic HIGH): canonical address keying.
    from recupero._common import canonical_address_key as _ck
    perp_lower = {_ck(a) for a in perpetrator_addresses}
    by_asset_map: dict[tuple[str, str | None], StolenAssetSummary] = {}
    by_victim: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    matched: list[dict[str, Any]] = []
    total_usd = Decimal("0")
    n = 0
    skipped_internal = 0
    skipped_nonfinite_usd = 0
    skipped_nonfinite_amount = 0

    for case in cases:
        for t in case.transfers:
            if _ck(t.to_address) not in perp_lower:
                continue
            # Skip perpetrator-to-perpetrator internal movements — that's the
            # same stolen money, not additional theft.
            if exclude_internal_transfers and _ck(t.from_address) in perp_lower:
                skipped_internal += 1
                continue
            n += 1
            key = (t.token.symbol, t.token.contract)
            summary = by_asset_map.setdefault(key, StolenAssetSummary(
                symbol=t.token.symbol, contract=t.token.contract,
            ))
            summary.transfer_count += 1
            # W8-09++ adversarial harden: NaN / Inf must NEVER enter a
            # running sum. The prior W8-09 fix only made `json.dumps`
            # raise at write time — by then `total_usd` is already
            # `Decimal('NaN')` and `format_aggregate_markdown` has
            # leaked "$NaN" into the operator-facing cover line. Skip
            # poisoned transfers at the source and tag the asset as
            # having unpriced transfers so downstream readers know
            # the total understates reality.
            if t.amount_decimal.is_finite():
                summary.total_amount += t.amount_decimal
            else:
                skipped_nonfinite_amount += 1
                summary.has_unpriced_transfers = True
            if t.usd_value_at_tx is not None and t.usd_value_at_tx.is_finite():
                summary.total_usd += t.usd_value_at_tx
                total_usd += t.usd_value_at_tx
                by_victim[t.from_address] += t.usd_value_at_tx
            elif t.usd_value_at_tx is None:
                summary.has_unpriced_transfers = True
            else:
                # NaN / Inf USD — treat as unpriced.
                skipped_nonfinite_usd += 1
                summary.has_unpriced_transfers = True
            # Scrub non-finite values out of the per-transfer record too,
            # so a single poisoned transfer can't render "NaN" / "Inf"
            # into the matched_transfers JSON either. (The W8-09
            # ``allow_nan=False`` dump guard catches floats but
            # str(Decimal('NaN')) == 'NaN' slips through as a string.)
            _matched_usd: str | None
            if t.usd_value_at_tx is None or not t.usd_value_at_tx.is_finite():
                _matched_usd = None
            else:
                _matched_usd = str(t.usd_value_at_tx)
            _matched_amount = (
                str(t.amount_decimal) if t.amount_decimal.is_finite() else None
            )
            matched.append({
                "case_id": case.case_id,
                "tx_hash": t.tx_hash,
                "block_time": t.block_time.isoformat(),
                "from": t.from_address,
                "to": t.to_address,
                "symbol": t.token.symbol,
                "contract": t.token.contract,
                "amount": _matched_amount,
                "usd": _matched_usd,
                "explorer_url": t.explorer_url,
            })

    if skipped_internal:
        log.info(
            "aggregate: excluded %d perpetrator-to-perpetrator internal transfers "
            "(same stolen funds moving between already-identified perp wallets)",
            skipped_internal,
        )
    if skipped_nonfinite_usd or skipped_nonfinite_amount:
        log.warning(
            "aggregate: skipped %d transfers with non-finite USD and %d with "
            "non-finite amount_decimal (NaN/Inf — price-oracle or parser glitch). "
            "These are flagged as unpriced on their asset row.",
            skipped_nonfinite_usd, skipped_nonfinite_amount,
        )

    # Collapse `by_victim` on canonical (lower-cased) EVM keys so the
    # same victim wallet shipped in mixed case across cases (checksum
    # from one Etherscan response, lower-case from another) doesn't
    # appear as two rows in the "By victim wallet" table. Preserve
    # first-seen casing as the display key.
    collapsed_victim: dict[str, Decimal] = {}
    display_for: dict[str, str] = {}
    for raw_addr, v in by_victim.items():
        canon = _ck(raw_addr)
        if canon not in display_for:
            display_for[canon] = raw_addr
        collapsed_victim[display_for[canon]] = (
            collapsed_victim.get(display_for[canon], Decimal("0")) + v
        )

    # Deduplicate `cases_examined` on canonical (lower-cased) case_id so
    # that if the same logical case is shipped in twice with different
    # casing (operator typo at the CLI, mixed-case manifest) the cover
    # line reflects the true count. We preserve first-seen order.
    _seen: set[str] = set()
    cases_examined: list[str] = []
    for c in cases:
        key = c.case_id.lower().strip()
        if key in _seen:
            continue
        _seen.add(key)
        cases_examined.append(c.case_id)

    return AggregateResult(
        cases_examined=cases_examined,
        perpetrators=list(perpetrator_addresses),
        total_usd=total_usd,
        transfer_count=n,
        by_asset=sorted(by_asset_map.values(), key=lambda s: s.total_usd, reverse=True),
        by_victim_wallet=collapsed_victim,
        matched_transfers=matched,
    )


def format_aggregate_markdown(r: AggregateResult) -> str:
    """Render the aggregate as a human-readable markdown summary."""
    lines = []
    lines.append("# Stolen funds aggregate")
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
        "generated_at": resolve_render_time().isoformat(),
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
    # v0.30.4 (V030_2_CORRECTNESS_AUDIT T2-C): every other report
    # writer uses `_common.atomic_write_text`; aggregate JSON was
    # shipping through bare `Path.write_text`. A worker SIGKILL
    # mid-write leaves a truncated `aggregate_<timestamp>.json` on
    # disk that the next CLI invocation reads and treats as
    # authoritative. Same fix as v0.20.13 R17-C for
    # emit_editorial_template.
    atomic_write_text(
        out_path,
        json.dumps(data, indent=2, allow_nan=False, ensure_ascii=False, sort_keys=True),
    )
