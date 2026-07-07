"""Observed-NFT-flow runner (roadmap-v4 Tier-2 #6, phase A).

``trace/nft_transfers.py`` (v0.32.1 trace gap B) parses ERC-721/1155 transfer
rows but was wired into NOTHING — NFT-sale laundering and mint-and-flip moves
simply vanished from the case record. This runner activates it the same way
``demix_runner`` activated ``demix_candidates``: an opt-in, post-trace pass
that fetches each traced wallet's NFT transfers and writes them into a case
artifact (``nft_flows.json``) + a guarded trace-report section.

Forensic doctrine (phase A = OBSERVATIONS ONLY):
  * every row is a real on-chain transfer involving a traced wallet — facts,
    never inferences; malformed provider rows are skipped, never repaired;
  * NO value claim is made — Etherscan supplies no NFT pricing and we never
    fabricate one; ``value_at_transfer_usd`` is carried only when a provider
    explicitly supplied it;
  * NFT recipients are NOT followed and the recoverable total is NOT touched.
    Matching an NFT exit to its marketplace-sale proceeds (the high-confidence
    continuation) is a separate, future phase.

Gated by ``RECUPERO_NFT_FLOWS`` (default off) — same opt-in discipline as
``RECUPERO_DEMIX_LEADS`` — since it adds two Etherscan calls per wallet.

The tokennfttx / token1155tx row shapes (tokenID casing, tokenValue quantity,
no category field) are LIVE-VERIFIED against api.etherscan.io v2 (2026-06).
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from typing import Any

from recupero.trace.nft_transfers import NFTTransfer, fetch_nft_transfers

log = logging.getLogger(__name__)

# Bound the per-case fan-out: traced wallets beyond this many are skipped
# (logged), and each wallet's NFT-row fetch is capped server-side.
DEFAULT_MAX_WALLETS = 25
DEFAULT_MAX_ROWS_PER_WALLET = 200


def nft_flows_enabled() -> bool:
    """Opt-in gate (RECUPERO_NFT_FLOWS). Default off — two extra explorer
    calls per traced wallet."""
    return (os.environ.get("RECUPERO_NFT_FLOWS", "") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def traced_wallets(transfers: Iterable[Any], *, max_wallets: int = DEFAULT_MAX_WALLETS) -> list[str]:
    """The case's traced wallet set = every ``from_address`` in the trace
    (the wallets whose outflows the BFS followed), first-seen order, capped.
    Works on Case.transfers or any objects exposing ``from_address``."""
    seen: set[str] = set()
    out: list[str] = []
    for t in transfers or []:
        frm = getattr(t, "from_address", None)
        if not frm:
            continue
        key = str(frm).lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(str(frm))
        if len(out) >= max_wallets:
            log.info("nft-flows: wallet cap reached (%d) — remaining traced "
                     "wallets skipped", max_wallets)
            break
    return out


def collect_nft_flows(
    *,
    transfers: Iterable[Any],
    adapter: Any,
    chain: str,
    start_block: int = 0,
    end_block: int = 99_999_999,
    max_wallets: int = DEFAULT_MAX_WALLETS,
    max_rows_per_wallet: int = DEFAULT_MAX_ROWS_PER_WALLET,
    force: bool = False,
) -> list[dict[str, Any]]:
    """Fetch each traced wallet's NFT transfers (both directions) and return
    JSON-safe flow records annotated with the wallet + direction. Opt-in:
    returns ``[]`` unless ``force`` or ``RECUPERO_NFT_FLOWS`` is set.
    Best-effort — a per-wallet fetch failure skips that wallet, never aborts.

    Dedup: a transfer BETWEEN two traced wallets appears in both wallets'
    histories; it is emitted once per (tx, contract, token, from, to)."""
    if not (force or nft_flows_enabled()):
        return []
    wallets = traced_wallets(transfers, max_wallets=max_wallets)
    flows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for wallet in wallets:
        wl = wallet.lower()
        try:
            rows: list[NFTTransfer] = fetch_nft_transfers(
                wallet, chain, start_block, end_block, adapter,
            )
        except Exception as exc:  # noqa: BLE001 — best-effort per wallet
            log.warning("nft-flows: fetch failed wallet=%s: %s", wallet, exc)
            continue
        if max_rows_per_wallet and len(rows) > max_rows_per_wallet:
            # No silent caps: WARN (not INFO — INFO is routinely filtered and the
            # truncation would never surface to a case reviewer). A launderer who
            # exits via many NFT sales can exceed this, so the dropped rows may
            # include the exits to fresh wallets.
            log.warning(
                "nft-flows: wallet %s has %d NFT rows — keeping only the first "
                "%d; %d row(s) dropped from the case NFT history (raise "
                "max_rows_per_wallet or query the wallet directly).",
                wallet, len(rows), max_rows_per_wallet,
                len(rows) - max_rows_per_wallet,
            )
            rows = rows[:max_rows_per_wallet]
        for r in rows:
            key = (r.tx_hash, r.contract_address, r.token_id,
                   r.from_address, r.to_address)
            if key in seen:
                continue
            seen.add(key)
            flows.append({
                "traced_wallet": wl,
                "direction": "out" if r.from_address == wl else "in",
                "counterparty": r.to_address if r.from_address == wl else r.from_address,
                "tx_hash": r.tx_hash,
                "contract_address": r.contract_address,
                "collection_name": r.collection_name,
                "token_id": r.token_id,
                "token_standard": r.token_standard,
                "value_count": r.value_count,
                "block_time": r.block_time,
                "value_at_transfer_usd": (
                    str(r.value_at_transfer_usd)
                    if r.value_at_transfer_usd is not None else None
                ),
                "chain": chain,
            })
    return flows


def flows_to_json(flows: list[dict[str, Any]]) -> dict[str, Any]:
    """Serialize collect_nft_flows output to the nft_flows.json artifact."""
    return {
        "kind": "recupero_nft_flows",
        "disclaimer": (
            "Observed on-chain NFT transfers involving traced wallets — "
            "OBSERVATIONS only. No USD value is claimed unless the data "
            "provider supplied one, NFT recipients are not followed, and the "
            "recoverable total is unchanged. Matching an NFT exit to its "
            "marketplace-sale proceeds requires a separate manual review."
        ),
        "flow_count": len(flows),
        "flows": flows,
    }


__all__ = (
    "DEFAULT_MAX_WALLETS",
    "DEFAULT_MAX_ROWS_PER_WALLET",
    "nft_flows_enabled",
    "traced_wallets",
    "collect_nft_flows",
    "flows_to_json",
)
