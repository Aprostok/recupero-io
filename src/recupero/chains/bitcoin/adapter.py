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
import threading
from datetime import UTC, datetime
from typing import Any

from recupero.chains.base import ChainAdapter
from recupero.chains.bitcoin.address import normalize_bitcoin_address
from recupero.chains.bitcoin.esplora import EsploraClient, EsploraError
from recupero.models import Address, Chain, EvidenceReceipt, TokenRef

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic-CoinJoin provenance registry (v0.32.1 round-2 CRIT-NEW-3)
# ─────────────────────────────────────────────────────────────────────────────
#
# Round-1 CRIT-NEW-3 closure: the CoinJoin-unwrap path in
# ``_unwrap_coinjoin_to_transfers`` emits Transfer-shaped dicts whose
# amounts are *probabilistic* (a hypothesis's total_output_value_sats
# divided evenly across the hypothesized output addresses). The
# tracer's ``_build_transfer`` constructs ``Transfer`` records from a
# whitelisted set of keys — extra dict keys like
# ``_synthetic_coinjoin_unwrap`` are silently dropped.
#
# Consequence pre-v0.32.1-round-2: the brief renders these synthetic
# rows indistinguishably from directly-observed transfers, so the LE
# reader sees a confident "$X moved from addr A to addr B" sentence
# that is actually an unwrap heuristic with confidence 0.4-0.7.
#
# Workaround within the v0.32.1 fix scope (tracer.py is locked):
# mirror the ``inputs_registry`` pattern — record the tx_hash +
# output-address of every synthetic Transfer emitted, and expose a
# lookup helper the brief / LE renderer can call. The model field
# would be the cleaner long-term fix; this registry is the shippable
# one. ``mark_synthetic`` is idempotent and thread-safe.

_SYNTHETIC_COINJOIN_KEYS: set[tuple[str, str]] = set()
_SYNTHETIC_COINJOIN_META: dict[tuple[str, str], dict[str, Any]] = {}
_SYNTHETIC_LOCK = threading.Lock()


def mark_synthetic_coinjoin(
    tx_hash: str,
    to_address: str,
    *,
    confidence_score: float | None = None,
    rationale: str | None = None,
) -> None:
    """Record that ``(tx_hash, to_address)`` is a synthetic
    CoinJoin-unwrap row, not an on-chain observed transfer.

    Called by ``_unwrap_coinjoin_to_transfers`` for every synthetic
    Transfer-shaped dict it emits. Brief / LE renderers MUST call
    ``is_synthetic_coinjoin`` on every Bitcoin Transfer they're about
    to display and tag the row with a "[CoinJoin unwrap heuristic, not
    on-chain transfer]" badge when it returns True.
    """
    if not isinstance(tx_hash, str) or not tx_hash:
        return
    if not isinstance(to_address, str) or not to_address:
        return
    key = (tx_hash, to_address)
    with _SYNTHETIC_LOCK:
        _SYNTHETIC_COINJOIN_KEYS.add(key)
        meta: dict[str, Any] = {}
        if confidence_score is not None:
            meta["confidence_score"] = confidence_score
        if rationale is not None:
            meta["rationale"] = rationale
        if meta:
            _SYNTHETIC_COINJOIN_META[key] = meta


def is_synthetic_coinjoin(tx_hash: str, to_address: str) -> bool:
    """Return True iff ``(tx_hash, to_address)`` was emitted as a
    probabilistic CoinJoin unwrap (not a direct on-chain transfer).

    Brief / LE renderers SHOULD call this for every Bitcoin Transfer
    row and prefix the line with a "[CoinJoin unwrap heuristic, not
    on-chain transfer]" tag when True so the reader can tell apart
    confident on-chain evidence from probabilistic unwrap inference.
    """
    if not isinstance(tx_hash, str) or not tx_hash:
        return False
    if not isinstance(to_address, str) or not to_address:
        return False
    with _SYNTHETIC_LOCK:
        return (tx_hash, to_address) in _SYNTHETIC_COINJOIN_KEYS


def synthetic_coinjoin_metadata(
    tx_hash: str, to_address: str
) -> dict[str, Any]:
    """Return the confidence_score + rationale for a synthetic
    CoinJoin row, or empty dict if the row was not registered as
    synthetic (or carried no metadata).
    """
    if not isinstance(tx_hash, str) or not tx_hash:
        return {}
    if not isinstance(to_address, str) or not to_address:
        return {}
    with _SYNTHETIC_LOCK:
        return dict(_SYNTHETIC_COINJOIN_META.get((tx_hash, to_address), {}))


def clear_synthetic_coinjoin_registry() -> None:
    """Reset the registry. For tests and between-case cleanup."""
    with _SYNTHETIC_LOCK:
        _SYNTHETIC_COINJOIN_KEYS.clear()
        _SYNTHETIC_COINJOIN_META.clear()


def synthetic_coinjoin_registry_size() -> int:
    """Number of synthetic (tx_hash, to_address) pairs registered.

    For tests + observability.
    """
    with _SYNTHETIC_LOCK:
        return len(_SYNTHETIC_COINJOIN_KEYS)


def _safe_unix_to_datetime(ts: Any) -> datetime:
    """Convert an untrusted unix-seconds value to a UTC datetime.

    Esplora is an external HTTP service. A buggy / compromised
    response can carry timestamps that crash
    ``datetime.fromtimestamp`` — OverflowError on year-> 9999,
    OSError on Windows for very-negative, ValueError on Linux. We
    clamp to epoch so the BFS hop keeps moving.
    """
    try:
        ts_int = int(ts or 0)
    except (TypeError, ValueError):
        return datetime.fromtimestamp(0, tz=UTC)
    try:
        return datetime.fromtimestamp(ts_int, tz=UTC)
    except (OverflowError, OSError, ValueError):
        log.warning(
            "bitcoin: clamping out-of-range timestamp %r to epoch", ts_int,
        )
        return datetime.fromtimestamp(0, tz=UTC)


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
        self, from_address: Address, start_block: int,
        *, max_results: int | None = None,
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
        self, from_address: Address, start_block: int,
        *, max_results: int | None = None,
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
        block_time = _safe_unix_to_datetime(block_time_unix)
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
        block_time = _safe_unix_to_datetime(block_time_unix)

        vin = tx.get("vin") if isinstance(tx, dict) else None
        vout = tx.get("vout") if isinstance(tx, dict) else None
        if not isinstance(vin, list) or not isinstance(vout, list):
            return []
        if not vin or not vout:
            return []

        # Collect all input addresses AND their per-input values.
        # v0.32.1 (CRIT-1): pre-v0.32.1 we kept only the first input
        # address; everything else got silently dropped. Now we keep
        # the full list so:
        #   1. Pro-rata accounting attributes the right share of the
        #      output value to ``expected_from`` (the queried address)
        #      based on its contribution to total inputs.
        #   2. The full input-set is registered in the shared
        #      bitcoin.inputs_registry so the H1 (co-spending)
        #      clustering heuristic in trace/clustering.py can fire on
        #      the actual common-input set rather than the random-first
        #      one.
        input_addresses: list[str] = []
        input_values_by_addr: dict[str, int] = {}
        for inp in vin:
            if not isinstance(inp, dict):
                continue
            prevout = inp.get("prevout") if isinstance(inp, dict) else None
            if not isinstance(prevout, dict):
                continue
            addr = prevout.get("scriptpubkey_address")
            val = prevout.get("value")
            if isinstance(addr, str) and addr:
                input_addresses.append(addr)
                if isinstance(val, int) and val > 0:
                    # Same address may appear in multiple inputs;
                    # sum the values so pro-rata math is correct.
                    input_values_by_addr[addr] = (
                        input_values_by_addr.get(addr, 0) + val
                    )

        # Skip if our target address isn't actually an input.
        if expected_from not in input_addresses:
            return []

        input_set = set(input_addresses)
        input_addresses[0]  # retained for legacy callers

        tx_id = tx.get("txid")
        if not isinstance(tx_id, str):
            return []

        # v0.32.1 (CRIT-1): record the full input-address set so
        # downstream clustering can read the common-input edges
        # without re-fetching the raw tx.
        from recupero.chains.bitcoin.inputs_registry import (
            register as _register_btc_inputs,
        )
        _register_btc_inputs(tx_id, input_addresses)

        # CoinJoin detection + probabilistic unwrap (v0.14.6).
        # Pre-v0.14.6 we dropped CoinJoin txs entirely — the trace
        # dead-ended at Wasabi / Whirlpool / JoinMarket. Now we:
        #   1. Detect CoinJoin via the same heuristic (>= 4 inputs +
        #      3+ equal-value outputs).
        #   2. Call unwrap_coinjoin() to enumerate participant
        #      hypotheses with confidence scores.
        #   3. For HIGH-confidence hypotheses where expected_from
        #      is in the input set, emit synthetic Transfer records
        #      to the hypothesis's output addresses — the trace
        #      CONTINUES past the CoinJoin to the unwrapped
        #      destination.
        #   4. Medium/low-confidence hypotheses are logged at INFO
        #      for the operator to review manually (we don't pollute
        #      the trace with speculative continuations).
        if len(vin) >= 4:
            from collections import Counter
            output_values = [
                o.get("value") for o in vout
                if isinstance(o, dict) and isinstance(o.get("value"), int)
            ]
            if output_values:
                most_common = Counter(output_values).most_common(1)
                if most_common and most_common[0][1] >= 3:
                    return self._unwrap_coinjoin_to_transfers(
                        tx=tx,
                        expected_from=expected_from,
                        tx_id=tx_id,
                        block_height=block_height,
                        block_time=block_time,
                    )

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
        #
        # v0.32.1 (CRIT-1): emit one Transfer per send-output with
        # ``from = expected_from`` (the queried address) and
        # ``amount_raw`` = the queried address's pro-rata share of
        # the output value, based on its contribution to total inputs.
        # Pre-v0.32.1 we emitted ``from = first_input_addr`` and
        # ``amount_raw = full output value`` regardless of who
        # actually contributed — so the trace silently OVER-reported
        # the first input's outflow and UNDER-reported (= zero) the
        # other inputs' outflows. With pro-rata, each input address's
        # BFS hop attributes the correct share of value movement,
        # and the sum across all input-address hops equals the
        # ACTUAL output value (modulo integer rounding).
        #
        # Pro-rata uses input VALUES, not input counts: an address
        # contributing 90% of inputs gets 90% of every output. This
        # is the standard forensic accounting model (Reactor, TRM
        # follow the same convention).
        total_input_value = sum(input_values_by_addr.values())
        expected_from_value = input_values_by_addr.get(expected_from, 0)
        if total_input_value <= 0 or expected_from_value <= 0:
            # Degenerate: Esplora returned a tx with no per-input
            # values (rare; happens on truncated responses). Fall
            # back to equal-split by distinct input-address count so
            # we still emit SOMETHING — better than silent drop.
            n_distinct_inputs = max(1, len(input_set))
            share_num, share_den = 1, n_distinct_inputs
        else:
            share_num, share_den = expected_from_value, total_input_value

        token = TokenRef(
            chain=Chain.bitcoin,
            contract=None,
            symbol=BTC_SYMBOL,
            decimals=BTC_DECIMALS,
            coingecko_id=BTC_COINGECKO_ID,
        )
        out: list[dict[str, Any]] = []
        is_single_input_owner = len(input_set) == 1
        for idx, send in enumerate(send_outputs):
            output_value = int(send["value"])
            if is_single_input_owner:
                # Single distinct input address — no pro-rata needed,
                # the queried address owns 100% of the input value.
                # Preserves byte-identical behavior for the common
                # single-input case (= every test fixture written
                # pre-v0.32.1).
                pro_rata_amount = output_value
            else:
                # Floor-divide to keep integer sats. Total drift
                # across all inputs is at most (n_inputs - 1) sats
                # per output — negligible for forensic purposes.
                pro_rata_amount = (output_value * share_num) // share_den
                if pro_rata_amount <= 0:
                    # Skip negligible contributions rather than emit
                    # zero-value Transfers (which would fail the
                    # Transfer model's amount_raw > 0 expectation
                    # via the dust filter downstream).
                    continue
            out.append({
                "chain": Chain.bitcoin,
                "tx_hash": tx_id,
                "block_number": block_height,
                "block_time": block_time,
                "log_index": idx,  # output index within tx
                "from": expected_from,
                "to": send["address"],
                "token": token,
                "amount_raw": pro_rata_amount,
                "explorer_url": self.explorer_tx_url(tx_id),
            })
        return out

    def _unwrap_coinjoin_to_transfers(
        self,
        *,
        tx: dict[str, Any],
        expected_from: str,
        tx_id: str,
        block_height: int,
        block_time: datetime,
    ) -> list[dict[str, Any]]:
        """Run unwrap_coinjoin() over a detected-CoinJoin tx and
        emit synthetic Transfer records for HIGH-confidence
        hypotheses that include ``expected_from`` in their input
        addresses.

        Medium/low confidence hypotheses are logged at INFO for
        operator review but DO NOT enter the trace — too noisy to
        confidently follow.

        Returns the list of synthetic Transfer dicts (possibly
        empty if no high-confidence unwrap involved
        ``expected_from``).
        """
        # Local import to avoid loading the unwrap module on
        # adapters that never see Bitcoin traffic.
        from recupero.trace.coinjoin_unwrap import (
            UTXOInput,
            UTXOOutput,
            unwrap_coinjoin,
        )

        # Build UTXOInput / UTXOOutput records from the raw tx.
        utxo_inputs: list[UTXOInput] = []
        for inp in tx.get("vin", []):
            if not isinstance(inp, dict):
                continue
            prevout = inp.get("prevout") if isinstance(inp, dict) else None
            if not isinstance(prevout, dict):
                continue
            addr = prevout.get("scriptpubkey_address")
            value = prevout.get("value")
            if isinstance(addr, str) and isinstance(value, int) and value > 0:
                utxo_inputs.append(UTXOInput(address=addr, value_sats=value))

        utxo_outputs: list[UTXOOutput] = []
        for idx, o in enumerate(tx.get("vout", [])):
            if not isinstance(o, dict):
                continue
            addr = o.get("scriptpubkey_address")
            value = o.get("value")
            if isinstance(addr, str) and isinstance(value, int) and value > 0:
                utxo_outputs.append(UTXOOutput(
                    address=addr, value_sats=value, output_index=idx,
                ))

        result = unwrap_coinjoin(
            tx_id=tx_id, inputs=utxo_inputs, outputs=utxo_outputs,
        )
        if result is None:
            log.debug("tx %s: unwrap returned None (not CoinJoin-shaped)", tx_id)
            return []

        # Find hypotheses that include our expected_from address
        # AND are high-confidence. Those become synthetic Transfers.
        token = TokenRef(
            chain=Chain.bitcoin,
            contract=None,
            symbol=BTC_SYMBOL,
            decimals=BTC_DECIMALS,
            coingecko_id=BTC_COINGECKO_ID,
        )
        transfers: list[dict[str, Any]] = []
        actionable_hypotheses = [
            h for h in result.hypotheses
            if expected_from in h.input_addresses
            and h.confidence == "high"
        ]
        for hyp in actionable_hypotheses:
            # Emit one synthetic Transfer per output address in the
            # hypothesis. Amount split evenly across outputs (we don't
            # know which specific output each $1 went to — that's
            # the whole point of CoinJoin obfuscation).
            for out_addr in hyp.output_addresses:
                transfers.append({
                    "chain": Chain.bitcoin,
                    "tx_hash": tx_id,
                    "block_number": block_height,
                    "block_time": block_time,
                    "log_index": None,
                    "from": expected_from,
                    "to": out_addr,
                    "token": token,
                    "amount_raw": hyp.total_output_value_sats // len(hyp.output_addresses),
                    "explorer_url": self.explorer_tx_url(tx_id),
                    # Mark synthetic so downstream consumers can
                    # tell it apart from direct on-chain evidence.
                    # The brief surfaces this as "unwrap-derived".
                    "_synthetic_coinjoin_unwrap": True,
                    "_unwrap_confidence_score": hyp.confidence_score,
                    "_unwrap_rationale": hyp.rationale,
                })
                # v0.32.1 round-2 CRIT-NEW-3: persist the synthetic
                # provenance to the module-level registry. The dict
                # keys above (``_synthetic_coinjoin_unwrap`` etc.) are
                # stripped by ``tracer._build_transfer`` because the
                # ``Transfer`` model has ``extra="forbid"`` and only a
                # whitelisted set of keys is read. The registry
                # survives the strip; brief / LE renderers consult it
                # via ``is_synthetic_coinjoin(tx_hash, to_address)`` to
                # tag the row with "[CoinJoin unwrap heuristic, not
                # on-chain transfer]" so the LE reader does not mistake
                # a probabilistic unwrap for confident on-chain
                # evidence.
                mark_synthetic_coinjoin(
                    tx_id,
                    out_addr,
                    confidence_score=hyp.confidence_score,
                    rationale=hyp.rationale,
                )

        # Log non-actionable hypotheses for operator review.
        non_actionable = [
            h for h in result.hypotheses
            if expected_from in h.input_addresses
            and h.confidence != "high"
        ]
        if non_actionable:
            log.info(
                "tx %s CoinJoin (%s): %d high-confidence hypothesis(es) "
                "actioned; %d medium/low not actioned (logged for review).",
                tx_id, result.detected_pattern,
                len(actionable_hypotheses), len(non_actionable),
            )
            for h in non_actionable:
                log.info(
                    "  unwrap %s: %s → %s — %s",
                    h.confidence, list(h.input_addresses)[:2],
                    list(h.output_addresses)[:2], h.rationale,
                )
        elif actionable_hypotheses:
            log.info(
                "tx %s CoinJoin (%s): %d high-confidence hypothesis(es) "
                "unwrapped into trace.",
                tx_id, result.detected_pattern, len(actionable_hypotheses),
            )
        else:
            log.debug(
                "tx %s CoinJoin: no hypotheses involved %s; trace skips tx.",
                tx_id, expected_from,
            )
        return transfers


__all__ = (
    "BitcoinAdapter",
    "BTC_DECIMALS",
    "BTC_SYMBOL",
    # v0.32.1 round-2 CRIT-NEW-3: synthetic-CoinJoin provenance API
    # consumed by brief / LE renderers to tag probabilistic unwrap
    # rows so they are not mistaken for on-chain evidence.
    "mark_synthetic_coinjoin",
    "is_synthetic_coinjoin",
    "synthetic_coinjoin_metadata",
    "clear_synthetic_coinjoin_registry",
    "synthetic_coinjoin_registry_size",
)
