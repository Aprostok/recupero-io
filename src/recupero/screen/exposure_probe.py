"""#5 — direct (1-hop) high-risk counterparty exposure probe for instant KYT.

The offline screener (`screen.screener.screen_address`) answers "is THIS address
labeled?" — sanctioned / mixer / drainer / correlation history. It does NOT look
at the chain: an address that has never been labeled but just received 400 ETH
FROM a sanctioned mixer screens "clean" offline. That inbound exposure is the
single most important KYT signal a compliance desk wants on a bare address.

This module adds the on-chain half: a BOUNDED, 1-hop probe that fetches the
address's recent inbound + outbound transfers and flags any counterparty that is
a known high-risk address (OFAC-sanctioned / mixer / ransomware / drainer /
darknet). It is deliberately shallow:

  * DIRECT counterparties only (1 hop) — a structural fact ("this address
    transacted directly with a sanctioned entity"), not an inference.
  * No pricing — the raw adapter rows carry no USD, and a court-facing USD-
    weighted, multi-hop exposure % is the FULL-TRACE deliverable
    (`trace.exposure_summary`). The probe reports counterparty + direction +
    transfer count + sample tx hashes as evidence.
  * Bounded by a lookback window + the adapter's own row caps, so it stays a
    seconds-latency enrichment rather than a full recursive trace.

Returns ``None`` when there is no direct high-risk counterparty (keeps a clean
screen clean), mirroring `compute_exposure_summary`'s benign-case posture.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from recupero._common import canonical_address_key as _ck
from recupero.trace.exposure_summary import _CATEGORY_RANK, _human

log = logging.getLogger(__name__)

_DEFAULT_LOOKBACK_DAYS = 90
# Cap evidence tx hashes per (counterparty, direction) so the response stays
# small even when an address has hundreds of transfers to one mixer.
_MAX_SAMPLE_TX = 5


def probe_counterparty_exposure(
    address: str,
    *,
    chain: Any,
    adapter: Any,
    high_risk_db: dict[str, Any],
    lookback_days: int = _DEFAULT_LOOKBACK_DAYS,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    """Probe an address's DIRECT (1-hop) exposure to high-risk counterparties.

    Args:
      address: the address to probe (chain-canonical form).
      chain: the chain (used only for the returned ``chain`` field).
      adapter: a ``ChainAdapter`` — its ``fetch_*_outflows`` /
        ``fetch_*_inflows`` + ``block_at_or_before`` are called.
      high_risk_db: ``{canonical_addr: HighRiskEntry}`` from
        ``risk_scoring.load_high_risk_db``.
      lookback_days: how far back to scan (start block derived from it).
      now: injectable clock for testing (defaults to ``datetime.now(UTC)``).

    Returns a dict with ``direct_high_risk_counterparties`` (ranked),
    ``by_category`` rollup, a ``headline``, and provenance — or ``None`` when
    no direct high-risk counterparty is found.
    """
    if not high_risk_db:
        return None

    clock = now or datetime.now(UTC)
    since = clock - timedelta(days=max(1, lookback_days))
    try:
        start_block = int(adapter.block_at_or_before(since))
    except Exception as exc:  # noqa: BLE001
        log.debug("exposure_probe: block_at_or_before failed (%s); scanning from 0", exc)
        start_block = 0

    # Collect 1-hop transfers in both directions, both asset classes. Each
    # fetch is best-effort: a single failing fetcher must not void the probe.
    tagged: list[tuple[str, dict[str, Any]]] = []  # (direction, row)
    for fn in (adapter.fetch_native_outflows, adapter.fetch_erc20_outflows):
        try:
            tagged.extend(("outbound", r) for r in (fn(address, start_block) or []))
        except Exception as exc:  # noqa: BLE001
            log.debug("exposure_probe: outflow fetch %s failed: %s", fn.__name__, exc)
    for fn in (adapter.fetch_native_inflows, adapter.fetch_erc20_inflows):
        try:
            tagged.extend(("inbound", r) for r in (fn(address, start_block) or []))
        except Exception as exc:  # noqa: BLE001
            log.debug("exposure_probe: inflow fetch %s failed: %s", fn.__name__, exc)

    # Match each transfer's COUNTERPARTY (the non-self side) against the db.
    # key = (counterparty_key, direction, category)
    hits: dict[tuple[str, str, str], dict[str, Any]] = {}
    for direction, row in tagged:
        if not isinstance(row, dict):
            continue
        cp = row.get("to") if direction == "outbound" else row.get("from")
        if not cp or not isinstance(cp, str):
            continue
        entry = high_risk_db.get(_ck(cp))
        if entry is None:
            continue
        cat = (getattr(entry, "risk_category", "") or "").lower()
        if not cat:
            continue
        key = (_ck(cp), direction, cat)
        hit = hits.get(key)
        if hit is None:
            hit = {
                "counterparty": cp,
                "direction": direction,
                "category": cat,
                "name": getattr(entry, "name", None),
                "severity": getattr(entry, "severity", None),
                "transfer_count": 0,
                "sample_tx_hashes": [],
            }
            hits[key] = hit
        hit["transfer_count"] += 1
        txh = row.get("tx_hash")
        if (txh and len(hit["sample_tx_hashes"]) < _MAX_SAMPLE_TX
                and txh not in hit["sample_tx_hashes"]):
            hit["sample_tx_hashes"].append(txh)

    if not hits:
        return None

    # Rank counterparties: severest category first, then most transfers.
    counterparties = sorted(
        hits.values(),
        key=lambda c: (-_CATEGORY_RANK.get(c["category"], 0), -c["transfer_count"]),
    )

    # Category rollup (distinct counterparties + total transfers per category).
    cat_tx: dict[str, int] = defaultdict(int)
    cat_cps: dict[str, set[str]] = defaultdict(set)
    cat_dirs: dict[str, set[str]] = defaultdict(set)
    for c in counterparties:
        cat_tx[c["category"]] += c["transfer_count"]
        cat_cps[c["category"]].add(_ck(c["counterparty"]))
        cat_dirs[c["category"]].add(c["direction"])
    by_category = [
        {
            "category": cat,
            "label": _human(cat),
            "counterparty_count": len(cat_cps[cat]),
            "transfer_count": cat_tx[cat],
            "directions": sorted(cat_dirs[cat]),
        }
        for cat in sorted(cat_tx, key=lambda c: -_CATEGORY_RANK.get(c, 0))
    ]

    top = counterparties[0]
    dir_word = "received funds from" if top["direction"] == "inbound" else "sent funds to"
    name = top["name"] or "a high-risk address"
    headline = (
        f"Direct exposure: this address {dir_word} {_human(top['category'])} "
        f"({name}) in {len(counterparties)} flagged counterparty relationship(s)"
    )

    return {
        "address": address,
        "chain": getattr(chain, "value", None) or str(chain),
        "lookback_days": lookback_days,
        "headline": headline,
        "by_category": by_category,
        "direct_high_risk_counterparties": counterparties,
        "note": (
            "Direct (1-hop) counterparty exposure — a structural fact that this "
            "address transacted directly with a labeled high-risk address within "
            "the lookback window. Multi-hop, USD-weighted exposure requires a "
            "full trace."
        ),
    }
