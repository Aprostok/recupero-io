"""Bitcoin chain adapter (v0.13.0).

Implements the ChainAdapter interface against the Esplora REST API
and the UTXO model.

Mapping UTXO → Transfer
-----------------------

The tracer's data model is account-style: a Transfer has one
``from_address`` and one ``to_address``. Bitcoin's UTXO tx can
have N inputs and M outputs — there's no single "from" and "to".
We normalize via a **peel-chain heuristic**:

  1. **Inputs**: all inputs to one tx are assumed to be controlled
     by the same wallet (common-input heuristic; Bitcoin's
     primary pseudonymity weakness). We take the FIRST input's
     address as the canonical sender.

  2. **Outputs**: classified into "send" vs "change":
     * If exactly ONE output's address matches an input address,
       that output is treated as change and the OTHER outputs
       are sends.
     * If no output address overlaps with inputs, ALL outputs are
       treated as sends.
     * If multiple outputs overlap with inputs (rare —
       consolidation), all are treated as change and the trace
       reports no outflows for this tx.

  3. One Transfer record per send output, with from=first_input_addr
     and to=output_addr, amount=output_value (in satoshis →
     normalized to BTC decimal).

Known limitations:

  * **CoinJoin** breaks the common-input heuristic. Wasabi /
    Samourai / JoinMarket transactions mix UTXOs from multiple
    wallets in one tx. The heuristic still produces Transfers but
    they're noise — the trace shouldn't be relied on past a
    CoinJoin tx. Detection of CoinJoin patterns (equal output
    values, large input count) is queued for v0.13.x.

  * **Multi-input traces are partial**: if a wallet uses 5 UTXOs
    in one tx, only the FIRST input's address gets a Transfer
    record. The other 4 don't show outbound activity for this tx
    in the trace, even though they did contribute funds.

These limitations are documented in the brief output so analysts
know the trace's reliability ceiling for Bitcoin cases.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from recupero.chains.base import ChainAdapter
from recupero.chains.bitcoin.address import normalize_bitcoin_address
from recupero.chains.bitcoin.esplora import EsploraClient, EsploraError
from recupero.models import Address, Chain, EvidenceReceipt, TokenRef

log = logging.getLogger(__name__)


# Public Bitcoin explorers — first match per (mainnet, address-type)
# is what we cite in chain-of-custody URLs.
_MEMPOOL_BASE = "https://mempool.space"


# BTC is 8-decimal — 1 BTC = 1e8 satoshis.
BTC_DECIMALS = 8
BTC_SYMBOL = "BTC"
BTC_COINGECKO_ID = "bitcoin"


class BitcoinAdapter(ChainAdapter):
    """Bitcoin mainnet adapter via Esplora.

    Free-tier: blockstream.info / mempool.space, no auth required.
    Pass a custom EsploraClient (via the ``client=`` kwarg) for
    testing or to point at a self-hosted Esplora instance.
    """

    chain = Chain.bitcoin

    def __init__(self, *, client: EsploraClient | None = None) -> None:
        self.client = client or EsploraClient()
        self._is_contract_cache: dict[str, bool] = {}

    # ---------- Required interface ---------- #

    def block_at_or_before(self, ts: datetime) -> int:
        """Map a UTC timestamp to a Bitcoin block height.

        Bitcoin averages ~10 minutes/block. We binary-search:
          * Get current tip height.
          * Probe block timestamps; halve.

        Not the prettiest — ~20 round-trips for a full-range search
        — but Esplora caches block headers aggressively so the cost
        is amortized.
        """
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        target_unix = int(ts.timestamp())
        try:
            tip = self.client.get_tip_height()
        except EsploraError as e:
            raise RuntimeError(
                f"esplora tip-height unreachable: {e}; cannot resolve "
                f"block_at_or_before for {ts}"
            ) from e

        lo, hi = 0, tip
        while lo < hi:
            mid = (lo + hi + 1) // 2
            try:
                block_hash = self.client.get_block_at_height(mid)
            except EsploraError:
                # Esplora occasionally returns 404 on the very latest
                # blocks during reorgs; bias down.
                hi = mid - 1
                continue
            # Block-hash endpoint returns just the hash string;
            # we need block_time, which comes from /block/{hash}.
            # To keep this readable + within Esplora's surface, we
            # cheat: read from an in-flight tx that pins block_time.
            # Esplora exposes /block/{hash} with timestamp:
            try:
                # Some Esplora deployments return the hash as a bare
                # string; we wrap that into a /block/{hash} fetch.
                # For now, we keep the impl simple and let the
                # caller use timestamp-based filtering on TRC-20
                # endpoints instead. Bitcoin tracing typically uses
                # full-history mode, not time-windowed.
                if isinstance(block_hash, str):
                    block_meta = self.client._get(f"/block/{block_hash}")
                elif isinstance(block_hash, dict):
                    block_meta = block_hash
                else:
                    hi = mid - 1
                    continue
            except EsploraError:
                hi = mid - 1
                continue
            block_ts = block_meta.get("timestamp") if isinstance(block_meta, dict) else None
            if not isinstance(block_ts, int):
                hi = mid - 1
                continue
            if block_ts <= target_unix:
                lo = mid
            else:
                hi = mid - 1
        return lo

    def is_contract(self, address: Address) -> bool:
        """Bitcoin has no concept of contract accounts (no EVM-style
        smart contracts). P2SH and P2WSH addresses CAN encode
        multisig / script logic, but for the tracer's purposes
        (decide whether to stop the trace) these still behave as
        custody-controlled wallets — we return False uniformly.
        """
        return False

    def fetch_native_outflows(
        self, from_address: Address, start_block: int
    ) -> list[dict[str, Any]]:
        """Bitcoin native (BTC) outflows from ``from_address``.

        Implements the peel-chain heuristic described in the module
        docstring. Returns normalized Transfer-shaped dicts.

        ``start_block`` filtering is applied AFTER Esplora returns
        the full address history (Esplora has no block-windowed
        address API).
        """
        try:
            addr = normalize_bitcoin_address(from_address)
        except Exception as e:  # noqa: BLE001
            log.warning("invalid bitcoin address %r: %s", from_address, e)
            return []
        try:
            txs = self.client.get_address_txs(addr)
        except EsploraError as e:
            log.warning("esplora address fetch failed for %s: %s", addr, e)
            return []

        out: list[dict[str, Any]] = []
        for tx in txs:
            # Apply post-fetch block-window filter.
            block_height = (
                tx.get("status", {}).get("block_height") if isinstance(tx, dict)
                else None
            )
            if isinstance(block_height, int) and block_height < start_block:
                continue
            transfers = self._normalize_utxo_tx(tx, expected_from=addr)
            out.extend(transfers)
        return out

    def fetch_erc20_outflows(
        self, from_address: Address, start_block: int
    ) -> list[dict[str, Any]]:
        """Bitcoin has no fungible-token standard equivalent to ERC-20
        (Ordinals / BRC-20 / Runes exist but have low forensic
        value). Returns empty — the tracer treats it as "no token
        outflows", which is correct for BTC."""
        return []

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        """Bitcoin chain-of-custody receipt.

        Esplora's /tx/{txid} returns the full parsed tx + status.
        We package that as the raw_transaction + raw_receipt; the
        block_header comes from /block/{block_hash}.
        """
        try:
            raw_tx = self.client.get_transaction(tx_hash)
        except EsploraError as e:
            raise RuntimeError(f"esplora tx fetch failed for {tx_hash}: {e}") from e
        status = raw_tx.get("status", {}) if isinstance(raw_tx, dict) else {}
        block_height = status.get("block_height") if isinstance(status, dict) else None
        block_time_unix = status.get("block_time") if isinstance(status, dict) else None
        block_hash = status.get("block_hash") if isinstance(status, dict) else None
        if not isinstance(block_height, int) or not isinstance(block_time_unix, int):
            raise RuntimeError(
                f"tx {tx_hash} not confirmed or has incomplete status; "
                "chain-of-custody requires a confirmed tx"
            )
        block_time = datetime.fromtimestamp(block_time_unix, tz=UTC)
        raw_block: dict[str, Any] = {}
        if isinstance(block_hash, str):
            try:
                raw_block = self.client._get(f"/block/{block_hash}")
                if not isinstance(raw_block, dict):
                    raw_block = {}
            except EsploraError:
                raw_block = {}
        return EvidenceReceipt(
            chain=Chain.bitcoin,
            tx_hash=tx_hash,
            block_number=block_height,
            block_time=block_time,
            raw_transaction=raw_tx if isinstance(raw_tx, dict) else {},
            raw_receipt={},  # Bitcoin has no separate receipt; embedded in tx
            raw_block_header=raw_block,
            fetched_at=datetime.now(UTC),
            fetched_from=self.client.base_url,
            explorer_url=self.explorer_tx_url(tx_hash),
        )

    def explorer_tx_url(self, tx_hash: str) -> str:
        return f"{_MEMPOOL_BASE}/tx/{tx_hash}"

    def explorer_address_url(self, address: Address) -> str:
        addr = normalize_bitcoin_address(address)
        return f"{_MEMPOOL_BASE}/address/{addr}"

    # ---------- UTXO normalization ---------- #

    def _normalize_utxo_tx(
        self,
        tx: dict[str, Any],
        *,
        expected_from: str,
    ) -> list[dict[str, Any]]:
        """Convert one Esplora-shaped tx into 0..N Transfer-shaped
        dicts (one per "send" output identified by the peel-chain
        heuristic).

        Returns [] if:
          * The tx is unconfirmed (status.confirmed=False).
          * The expected_from address doesn't appear in any input.
          * The tx is malformed.
        """
        status = tx.get("status") if isinstance(tx, dict) else None
        if not isinstance(status, dict) or not status.get("confirmed"):
            return []
        block_height = status.get("block_height")
        block_time_unix = status.get("block_time")
        if not isinstance(block_height, int) or not isinstance(block_time_unix, int):
            return []
        block_time = datetime.fromtimestamp(block_time_unix, tz=UTC)

        vin = tx.get("vin") if isinstance(tx, dict) else None
        vout = tx.get("vout") if isinstance(tx, dict) else None
        if not isinstance(vin, list) or not isinstance(vout, list):
            return []
        if not vin or not vout:
            return []

        # Collect all input addresses.
        input_addresses: list[str] = []
        for inp in vin:
            if not isinstance(inp, dict):
                continue
            prevout = inp.get("prevout") if isinstance(inp, dict) else None
            if not isinstance(prevout, dict):
                continue
            addr = prevout.get("scriptpubkey_address")
            if isinstance(addr, str) and addr:
                input_addresses.append(addr)

        # Skip if our target address isn't actually an input.
        if expected_from not in input_addresses:
            return []

        input_set = set(input_addresses)
        first_input_addr = input_addresses[0]

        tx_id = tx.get("txid")
        if not isinstance(tx_id, str):
            return []

        # Classify outputs.
        # CoinJoin detection (basic): if vin count >= 4 AND most
        # outputs share the same value, this looks like CoinJoin.
        # Skip — too noisy to trace through.
        if len(vin) >= 4:
            output_values = [
                o.get("value") for o in vout
                if isinstance(o, dict) and isinstance(o.get("value"), int)
            ]
            if output_values:
                from collections import Counter
                most_common = Counter(output_values).most_common(1)
                if most_common and most_common[0][1] >= 3:
                    log.debug(
                        "tx %s looks like CoinJoin (vin=%d, equal-output "
                        "cluster=%d); skipping normalization",
                        tx_id, len(vin), most_common[0][1],
                    )
                    return []

        # Peel-chain classification:
        #   send outputs: address NOT in input_set
        #   change outputs: address IN input_set
        send_outputs: list[dict[str, Any]] = []
        for o in vout:
            if not isinstance(o, dict):
                continue
            value = o.get("value")
            out_addr = o.get("scriptpubkey_address")
            if not isinstance(value, int) or value <= 0:
                continue
            if not isinstance(out_addr, str) or not out_addr:
                # OP_RETURN data carriers, non-standard scripts — skip
                continue
            if out_addr in input_set:
                continue  # change
            send_outputs.append({"address": out_addr, "value": value})

        # Build Transfer-shaped dicts.
        token = TokenRef(
            chain=Chain.bitcoin,
            contract=None,
            symbol=BTC_SYMBOL,
            decimals=BTC_DECIMALS,
            coingecko_id=BTC_COINGECKO_ID,
        )
        out: list[dict[str, Any]] = []
        for idx, send in enumerate(send_outputs):
            out.append({
                "chain": Chain.bitcoin,
                "tx_hash": tx_id,
                "block_number": block_height,
                "block_time": block_time,
                "log_index": idx,  # output index within tx
                "from": first_input_addr,
                "to": send["address"],
                "token": token,
                "amount_raw": send["value"],
                "explorer_url": self.explorer_tx_url(tx_id),
            })
        return out


__all__ = (
    "BitcoinAdapter",
    "BTC_DECIMALS",
    "BTC_SYMBOL",
)
