"""Tron chain adapter (v0.12.0).

Conforms to :class:`recupero.chains.base.ChainAdapter`. The tracer
doesn't care that it's Tron — it gets the same normalized dicts
back from ``fetch_native_outflows`` / ``fetch_erc20_outflows`` as
it does from EVM, just with chain=Chain.tron.

Mapping decisions
-----------------

  * TRC-20 transfers are surfaced via ``fetch_erc20_outflows``. The
    interface is named after the ERC-20 idiom for legacy reasons —
    the contract is "non-native fungible-token transfer". TRC-20
    fits cleanly.

  * Native TRX transfers are *not* implemented in v0.12.0. The
    method returns an empty list — the tracer treats this as
    "no native outflows", which is correct for our focused use
    case (USDT laundering). Adding native TRX support is a
    follow-on; see TODO in the method body.

  * ``is_contract`` reads the ``data[0].type`` from the account
    endpoint. ``"Contract"`` indicates a smart-contract account;
    ``"Account"`` (or missing) indicates EOA.

  * ``block_at_or_before`` is NOT implemented; raises
    NotImplementedError. The tracer only calls this for time-
    windowed traces. Tron's REST API has no direct timestamp→block
    endpoint; doing a binary search across millions of blocks is
    expensive enough that we've punted it to v0.12.x. Most Tron
    cases trace the full address history, which the TRC-20 endpoint
    handles natively via min_timestamp / max_timestamp.

  * ``fetch_evidence_receipt`` is implemented via the
    /v1/transactions endpoint — returns the raw signed transaction
    + its receipt for chain-of-custody.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any

from recupero.chains.base import ChainAdapter
from recupero.chains.tron.address import (
    normalize_tron_address,
)
from recupero.chains.tron.client import TronGridClient, TronGridError
from recupero.models import Address, Chain, EvidenceReceipt, TokenRef

log = logging.getLogger(__name__)


# Public Tron explorer used for chain-of-custody URLs.
_TRONSCAN_BASE = "https://tronscan.org/#"


class TronAdapter(ChainAdapter):
    """Tron mainnet adapter (USDT-TRC20 + other TRC-20 tokens)."""

    chain = Chain.tron

    def __init__(
        self,
        *,
        api_key: str | None = None,
        client: TronGridClient | None = None,
    ) -> None:
        """Construct an adapter.

        ``api_key`` resolution order:
          1. Explicit ``api_key`` arg
          2. ``TRON_PRO_API_KEY`` env var
          3. None (TronGrid's unauthenticated tier)

        ``client`` is an injection point for tests — pass a
        TronGridClient backed by respx to avoid touching the live
        API.
        """
        resolved_key = api_key or os.environ.get("TRON_PRO_API_KEY") or ""
        self.client = client or TronGridClient(api_key=resolved_key)
        self._is_contract_cache: dict[str, bool] = {}

    # ---------- Required interface ---------- #

    def block_at_or_before(self, ts: datetime) -> int:
        """Return the unix timestamp of ``ts``, opaque to the tracer.

        Tron's TRC-20 endpoint filters by min_timestamp/max_timestamp,
        not by block number — there is no native "block at timestamp"
        REST endpoint, and the binary-search workaround would cost
        ~24 RPC calls per trace. The tracer treats the return value
        opaquely as ``start_block`` and passes it through to
        ``fetch_erc20_outflows`` (which currently ignores it and
        returns full history; future versions will honor it via
        min_timestamp).

        v0.16.6 and earlier raised NotImplementedError here, which
        was a CRITICAL bug: the tracer's per-address try/except
        caught the exception and silently returned 0 outflows for
        every Tron seed, making all Tron traces (the largest
        USDT-laundering surface in crypto) appear to have no
        activity. Returning the timestamp matches Solana's pattern.
        """
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return int(ts.timestamp())

    def is_contract(self, address: Address) -> bool:
        """True if address is a smart-contract account.

        Tron exposes this via the account-type field in
        /v1/accounts/{address}. Cached per-instance because the
        tracer probes every counterparty.
        """
        addr = normalize_tron_address(address)
        if addr in self._is_contract_cache:
            return self._is_contract_cache[addr]
        try:
            body = self.client.get_account(addr)
        except TronGridError as e:
            # Unknown / dust addresses → treat as EOA. Logging at
            # DEBUG only because this is high-volume.
            log.debug("is_contract probe failed for %s: %s", addr, e)
            self._is_contract_cache[addr] = False
            return False
        data = body.get("data") or []
        if not data:
            # Never observed on-chain → not a contract.
            self._is_contract_cache[addr] = False
            return False
        entry = data[0] if isinstance(data, list) else {}
        type_field = entry.get("type") if isinstance(entry, dict) else None
        is_contract = type_field == "Contract"
        self._is_contract_cache[addr] = is_contract
        return is_contract

    def fetch_native_outflows(
        self, from_address: Address, start_block: int
    ) -> list[dict[str, Any]]:
        """Native TRX outflows.

        v0.12.0 returns ``[]`` (not implemented). The tracer treats
        this as "no native outflows", which is correct for our
        primary use case (USDT-TRC20 laundering). TRX itself moves
        relatively little laundering volume because gas-fee
        bandwidth requires holding TRX in the destination wallet —
        scammers route through stablecoins instead.

        TODO(v0.12.x): wire to /v1/accounts/{addr}/transactions for
        the TRX transfer history. Tron returns these under
        ``raw_data.contract[].parameter.value`` with type
        TransferContract — needs unwrapping logic similar to TRC-20.
        """
        log.debug(
            "fetch_native_outflows: TRX native not implemented for v0.12.0; "
            "returning empty list for %s", from_address,
        )
        return []

    def fetch_erc20_outflows(
        self, from_address: Address, start_block: int
    ) -> list[dict[str, Any]]:
        """TRC-20 outbound transfers from ``from_address``.

        ``start_block`` is currently ignored — Tron's TRC-20
        endpoint windows by timestamp, not block number. The
        tracer historically passes block_at_or_before's output
        here; for Tron it gets a no-op. Time-window callers
        should use the future block_at_or_before once implemented,
        or trace the full address history (which is fine for most
        forensic cases).
        """
        addr = normalize_tron_address(from_address)
        # v0.18.5 (round-11 chains-CRIT-006): thread start_block through.
        # `block_at_or_before` returns unix-seconds (Tron has no
        # block-by-timestamp API), and TronGrid's TRC-20 endpoint
        # filters by `min_timestamp` in MILLISECONDS. Pre-v0.18.5
        # `start_block` was silently dropped — every Tron trace
        # fetched FULL history, hitting the 10k pagination cap and
        # truncating the OLDEST data (= incident period). Now: pass
        # min_timestamp = start_block * 1000.
        min_timestamp_ms = int(start_block) * 1000 if start_block > 0 else None
        try:
            raw = self.client.get_trc20_transfers(
                addr, only_from=True, min_timestamp=min_timestamp_ms,
            )
        except TronGridError as e:
            log.warning("trc20 outflow fetch failed for %s: %s", addr, e)
            return []

        out: list[dict[str, Any]] = []
        for ev in raw:
            try:
                norm = self._normalize_trc20(ev, expected_from=addr)
            except (KeyError, ValueError, TypeError) as e:
                log.warning(
                    "trc20 normalization failed (event=%s): %s",
                    ev.get("transaction_id", "?"), e,
                )
                continue
            if norm is None:
                continue
            out.append(norm)
        return out

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        """Tron chain-of-custody receipt (v0.17.5).

        Fetches the raw signed transaction, the receipt (post-execution
        info), and the block header containing the transaction. Packages
        them into an EvidenceReceipt identical in shape to the EVM
        evidence files — the freeze-letter generator and the
        forensic-bundle archive treat them interchangeably.

        Tron tx hashes are 64-char lowercase hex WITHOUT a 0x prefix.
        The client strips a leading 0x if a caller passes one.

        Raises:
            TronGridError: when any of the three wallet endpoints fail
                or return an empty envelope. Callers should catch and
                fall back to a tx-hash-only chain-of-custody row.
        """
        signed_tx = self.client.get_transaction_by_id(tx_hash)
        if not signed_tx or not signed_tx.get("txID"):
            raise TronGridError(
                f"empty signed-tx envelope for {tx_hash} — "
                "TronGrid returned no txID (may be unknown or pending)"
            )
        receipt = self.client.get_transaction_info_by_id(tx_hash)
        if not receipt or "id" not in receipt:
            raise TronGridError(
                f"empty receipt for {tx_hash} — TronGrid returned no id "
                "(tx may be unconfirmed)"
            )
        block_number = int(receipt.get("blockNumber") or 0)
        block_ts_ms = int(receipt.get("blockTimeStamp") or 0)
        if block_ts_ms <= 0:
            raise TronGridError(
                f"receipt for {tx_hash} missing blockTimeStamp — "
                "cannot assemble evidence (tx may be unconfirmed)"
            )
        block_time = datetime.fromtimestamp(block_ts_ms / 1000.0, tz=UTC)
        try:
            block_header = self.client.get_block_by_num(block_number)
        except TronGridError as e:
            # Block-header fetch is best-effort — its absence doesn't
            # invalidate the receipt for legal purposes. We persist an
            # empty dict + log so ops can see degraded coverage.
            log.warning(
                "tron block-header fetch failed for tx=%s block=%d: %s",
                tx_hash, block_number, e,
            )
            block_header = {}
        return EvidenceReceipt(
            chain=Chain.tron,
            tx_hash=tx_hash,
            block_number=block_number,
            block_time=block_time,
            raw_transaction=signed_tx,
            raw_receipt=receipt,
            raw_block_header=block_header,
            fetched_at=datetime.now(tz=UTC),
            fetched_from="api.trongrid.io/wallet/gettransactionbyid",
            explorer_url=self.explorer_tx_url(tx_hash),
        )

    def explorer_tx_url(self, tx_hash: str) -> str:
        return f"{_TRONSCAN_BASE}/transaction/{tx_hash}"

    def explorer_address_url(self, address: Address) -> str:
        addr = normalize_tron_address(address)
        return f"{_TRONSCAN_BASE}/address/{addr}"

    # ---------- Normalizers ---------- #

    def _normalize_trc20(
        self,
        event: dict[str, Any],
        *,
        expected_from: str | None = None,
    ) -> dict[str, Any] | None:
        """Convert a TronGrid TRC-20 transfer event to the tracer's
        normalized dict shape (matches the EVM adapter output).

        Returns None if the event should be filtered (wrong
        direction, malformed token_info, etc.).
        """
        # Direction filter — we asked for only_from but TronGrid's
        # server-side filter occasionally bleeds the other direction
        # for newly-confirmed events. Belt-and-suspenders.
        from_raw = event.get("from") or ""
        to_raw = event.get("to") or ""
        try:
            from_b58 = normalize_tron_address(from_raw)
        except Exception:  # noqa: BLE001
            return None
        try:
            to_b58 = normalize_tron_address(to_raw)
        except Exception:  # noqa: BLE001
            return None
        if expected_from and from_b58 != expected_from:
            return None

        tx_id = event.get("transaction_id") or ""
        if not tx_id:
            return None

        block_ts_ms = event.get("block_timestamp")
        if not isinstance(block_ts_ms, (int, float)):
            return None
        block_time = datetime.fromtimestamp(block_ts_ms / 1000.0, tz=UTC)

        token_info = event.get("token_info") or {}
        if not isinstance(token_info, dict):
            return None
        contract_addr_raw = token_info.get("address")
        if not isinstance(contract_addr_raw, str) or not contract_addr_raw.strip():
            return None
        try:
            contract_addr = normalize_tron_address(contract_addr_raw)
        except Exception:  # noqa: BLE001
            return None

        symbol = (token_info.get("symbol") or "?") or "?"
        try:
            decimals = int(token_info.get("decimals", 6) or 6)
        except (TypeError, ValueError):
            decimals = 6

        # Tron's value field is a string of the raw integer (smallest
        # unit). We keep it as int for the tracer; downstream pricing
        # divides by 10**decimals.
        try:
            amount_raw = int(event.get("value", "0"))
        except (TypeError, ValueError):
            return None
        if amount_raw <= 0:
            return None

        token = TokenRef(
            chain=Chain.tron,
            contract=contract_addr,
            symbol=symbol,
            decimals=decimals,
            coingecko_id=_COINGECKO_ID_BY_TRC20.get(contract_addr),
        )

        # Tron doesn't have per-event log_index in the parsed REST
        # response — the same tx can have multiple TRC-20 transfer
        # events but TronGrid returns them as separate rows without
        # an index. Synthesize one from the tx + (from, to, value)
        # tuple so the tracer's de-duplication keys are stable.
        synthetic_log_index = None

        # v0.18.5 (round-11 chains-HIGH-003): use the event's
        # block_number when present. Pre-v0.18.5 we hardcoded
        # block_number=0 for every Tron transfer; downstream
        # BFS-cursor logic (`block_number + 1` for next-page
        # start_block) was pegged at 1 forever; brief's
        # "earliest/latest block" was always 0..0; cross-chain
        # comparisons mis-ordered Tron rows relative to EVM.
        # TronGrid's v1 endpoint emits `block_number` (or
        # `blockNumber` depending on endpoint variant) per row.
        block_number_raw = (
            event.get("block_number")
            or event.get("blockNumber")
            or 0
        )
        try:
            block_number = int(block_number_raw)
        except (TypeError, ValueError):
            block_number = 0

        return {
            "chain": Chain.tron,
            "tx_hash": tx_id,
            "block_number": block_number,
            "block_time": block_time,
            "log_index": synthetic_log_index,
            "from": from_b58,
            "to": to_b58,
            "token": token,
            "amount_raw": amount_raw,
            "explorer_url": self.explorer_tx_url(tx_id),
        }


# CoinGecko ID for the major TRC-20 tokens. Used so the pricing
# stage can fetch USD values without round-tripping through the
# pricing-cache fallback. The list is short and well-known —
# adding more is just a JSON edit.
_COINGECKO_ID_BY_TRC20: dict[str, str] = {
    # USDT-TRC20 (Tether)
    "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": "tether",
    # USDC on Tron (Bridged via Justswap)
    "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8": "usd-coin",
    # USDD (TRON DAO)
    "TPYmHEhy5n8TCEfYGqW2rPxsghSfzghPDn": "usdd",
    # JUST (JST)
    "TCFLL5dx5ZJdKnWuesXxi1VPwjLVmWZZy9": "just",
}


__all__ = (
    "TronAdapter",
)
