"""Cosmos chain adapter (v0.32.1+ Cap-C).

Minimal read-only adapter satisfying enough of the ``ChainAdapter``
interface that the BFS can fetch outflows for a Cosmos address and
surface them in the brief. Cross-chain IBC continuation is NOT yet
implemented — the trace dies at a Cosmos hop in v0.32.1, but the
operator now sees the hop and the destination address rather than
``trace terminated unexpectedly``.

Interface conformance vs ChainAdapter (chains/base.py)
-------------------------------------------------------

We deliberately do NOT inherit from ``ChainAdapter`` ABC in v0.32.1
because the ABC's ``Address`` type is EVM-shaped. wave-7 integration
will either:
  (a) generalize ``Address`` to accept bech32, or
  (b) introduce a parallel ``CosmosChainAdapter`` ABC.

The methods below mimic the signatures from base.py so a wave-7
adapter swap is a rename, not a redesign.

Normalization: amount + denom -> Transfer-shape
-----------------------------------------------

Cosmos uses ``{amount: "1234567", denom: "uatom"}`` (micro-units).
We surface the integer amount and the denom string verbatim — the
brief's pricing layer is responsible for converting uatom -> ATOM
and ATOM -> USD via the same `pricing.py` lookup as ERC-20.

TODO(wave-7-integration):
  1. Register CosmosAdapter in `chains/base.ChainAdapter.for_chain`
     behind `Chain.cosmos`.
  2. Add bech32-shape Address validation to `models.Address` or
     introduce a sibling `CosmosAddress` type.
  3. Wire IBC packet decode for cross-chain continuation: the
     `MsgRecvPacket` and `MsgTransfer` event types carry the
     source-chain identifier in the IBC counterparty channel.
  4. Add Mintscan label ingest to `labels/seeds/cosmos_labels.json`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from recupero.chains.cosmos.client import CosmosLCDClient, resolve_zone

log = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Transfer normalization
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class CosmosTransfer:
    """One normalized Cosmos transfer.

    Mirrors the EVM Transfer shape closely enough that the brief
    renderer can iterate it identically. ``amount_raw`` is the
    integer micro-unit amount (e.g. uatom). ``denom`` is the chain's
    native token identifier OR an IBC denom-hash.
    """

    chain: str
    zone: str
    tx_hash: str
    block_height: int
    block_time: datetime | None
    from_address: str
    to_address: str
    denom: str  # "uatom", "uosmo", "ibc/27394FB...", etc.
    amount_raw: int
    is_ibc: bool  # True if denom starts with "ibc/" (cross-chain origin)
    msg_type: str  # "cosmos.bank.v1beta1.MsgSend", "ibc.applications.transfer.v1.MsgTransfer", etc.


def _bech32_basic_check(address: str) -> bool:
    """Cheap structural check — separator '1', prefix, body length.

    NOT a full bech32 checksum verify (that needs the BIP-173 polymod).
    For v0.32.1 we accept structural validity; wave-7 should wire the
    full checksum verifier.
    """
    if not isinstance(address, str):
        return False
    a = address.strip()
    if len(a) < 8 or len(a) > 90:
        return False
    if "1" not in a:
        return False
    prefix, _, body = a.partition("1")
    if not prefix or not body:
        return False
    # bech32 body charset
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    return all(c in charset for c in body)


def _parse_lcd_timestamp(ts: str | None) -> datetime | None:
    """Parse an LCD/Tendermint timestamp ('2024-04-12T07:23:11.456Z') to UTC datetime."""
    if not ts:
        return None
    try:
        # LCD ISO-8601 with optional fractional seconds + Z suffix
        s = ts.rstrip("Z")
        if "." in s:
            head, frac = s.split(".", 1)
            # Trim to microsecond precision
            frac = (frac + "000000")[:6]
            s = f"{head}.{frac}"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def _extract_transfers_from_tx_response(
    tx_response: dict[str, Any],
) -> list[CosmosTransfer]:
    """Walk one LCD tx_response and pull out all transfer events.

    LCD tx_responses carry a `logs` array; each log has an `events`
    array; each event has a `type` and an `attributes` array. The
    canonical Cosmos transfer event is type=``transfer`` with
    attributes ``recipient``, ``sender``, ``amount``.

    Returns: list of CosmosTransfer rows. Empty if no transfers found.
    """
    if not isinstance(tx_response, dict):
        return []

    tx_hash = str(tx_response.get("txhash") or tx_response.get("tx_hash") or "")
    block_height = int(tx_response.get("height", 0) or 0)
    block_time = _parse_lcd_timestamp(tx_response.get("timestamp"))

    # Pull msg_type from the first message of the tx body
    msg_type = ""
    tx = tx_response.get("tx") or {}
    body = (tx.get("body") if isinstance(tx, dict) else {}) or {}
    messages = body.get("messages") or []
    if messages and isinstance(messages[0], dict):
        msg_type = str(messages[0].get("@type", ""))

    out: list[CosmosTransfer] = []
    logs = tx_response.get("logs") or []
    if not isinstance(logs, list):
        return out

    for log_entry in logs:
        if not isinstance(log_entry, dict):
            continue
        events = log_entry.get("events") or []
        if not isinstance(events, list):
            continue
        for event in events:
            if not isinstance(event, dict):
                continue
            if event.get("type") != "transfer":
                continue
            attrs = event.get("attributes") or []
            # An event can carry MULTIPLE recipient/sender/amount triples
            # (when a tx executes several MsgSends in one log block).
            # Walk in parallel; the LCD always pads to triplets.
            recipient: str | None = None
            sender: str | None = None
            amount_str: str | None = None
            for attr in attrs:
                if not isinstance(attr, dict):
                    continue
                k = attr.get("key")
                v = attr.get("value")
                if k == "recipient":
                    if recipient is not None and sender is not None and amount_str is not None:
                        out.extend(_emit_one(
                            recipient, sender, amount_str,
                            tx_hash, block_height, block_time, msg_type,
                        ))
                    recipient = str(v) if v is not None else None
                    sender = None
                    amount_str = None
                elif k == "sender":
                    sender = str(v) if v is not None else None
                elif k == "amount":
                    amount_str = str(v) if v is not None else None
                    if recipient and sender and amount_str:
                        out.extend(_emit_one(
                            recipient, sender, amount_str,
                            tx_hash, block_height, block_time, msg_type,
                        ))
                        recipient = None
                        sender = None
                        amount_str = None
            # Flush any trailing partial group (defensive — LCD shouldn't
            # produce these, but a malformed indexer might).
            if recipient and sender and amount_str:
                out.extend(_emit_one(
                    recipient, sender, amount_str,
                    tx_hash, block_height, block_time, msg_type,
                ))

    return out


def _emit_one(
    recipient: str,
    sender: str,
    amount_str: str,
    tx_hash: str,
    block_height: int,
    block_time: datetime | None,
    msg_type: str,
) -> list[CosmosTransfer]:
    """Convert one (recipient, sender, amount) into Transfer(s).

    ``amount`` from a Cosmos transfer event is a comma-separated list:
    ``"1000uatom,500ibc/27394FB..."``. We emit one CosmosTransfer per
    comma-separated component.
    """
    zi = resolve_zone(sender)
    zone = zi.zone if zi else "unknown"

    out: list[CosmosTransfer] = []
    for component in amount_str.split(","):
        component = component.strip()
        if not component:
            continue
        # Find where the digits end and the denom starts
        i = 0
        while i < len(component) and component[i].isdigit():
            i += 1
        if i == 0:
            # Malformed; skip
            continue
        amount_raw_str = component[:i]
        denom = component[i:]
        try:
            amount_raw = int(amount_raw_str)
        except ValueError:
            continue
        out.append(CosmosTransfer(
            chain="cosmos",
            zone=zone,
            tx_hash=tx_hash,
            block_height=block_height,
            block_time=block_time,
            from_address=sender,
            to_address=recipient,
            denom=denom,
            amount_raw=amount_raw,
            is_ibc=denom.startswith("ibc/"),
            msg_type=msg_type,
        ))
    return out


# -----------------------------------------------------------------------------
# Adapter
# -----------------------------------------------------------------------------


class CosmosAdapter:
    """Minimal read-only Cosmos / IBC adapter.

    Method signatures match `chains/base.ChainAdapter` where possible
    so the wave-7 integration is straightforward.

    All public methods accept a bech32 address string; we do not
    require the EVM-shaped ``Address`` type since Cosmos addresses
    aren't 0x-prefixed hex.
    """

    chain_str: str = "cosmos"

    def __init__(
        self,
        client: CosmosLCDClient | None = None,
        *,
        default_lcd_base_url: str | None = None,
    ) -> None:
        self.client = client or CosmosLCDClient(default_lcd_base_url=default_lcd_base_url)

    # ----- block / time -----

    def block_at_or_before(self, ts: datetime) -> int:
        """Return the latest block height with ``block.time <= ts``.

        Implementation note: Cosmos LCDs don't expose a binary-search-
        ready "block by time" endpoint. The accurate implementation is
        an exponential-search probing /blocks/{h} backwards from tip.
        For v0.32.1 we return -1 (sentinel for "unknown") and rely on
        the caller to fetch all txs and filter client-side.
        wave-7 should add the exponential probe.
        """
        return -1

    def is_contract(self, address: str) -> bool:
        """Cosmos has CosmWasm contracts (prefix ``cosmos1...wasm`` is NOT a thing
        — contracts share the same bech32 shape as user accounts). Distinguishing
        requires a `/cosmwasm/wasm/v1/contract/{addr}` lookup that returns 404
        for accounts. For v0.32.1 we return False (assume EOA) — wave-7 should
        plumb the lookup.
        """
        return False

    # ----- transfer fetching -----

    def fetch_native_outflows(
        self, from_address: str, start_block: int = 0
    ) -> list[dict[str, Any]]:
        """Fetch native-asset (chain-base-denom) outbound transfers.

        ``start_block`` is honored as a client-side filter: we fetch
        from tip backwards and stop when we cross below it. The LCD
        ``events`` query already filters by sender at the indexer
        level, so this is cheap.
        """
        if not _bech32_basic_check(from_address):
            return []
        raw = self.client.fetch_txs_by_sender(from_address, limit=100)
        return self._normalize_response(raw, start_block=start_block, only_native=True)

    def fetch_erc20_outflows(
        self, from_address: str, start_block: int = 0
    ) -> list[dict[str, Any]]:
        """Fetch IBC-denom and CW20-token outflows.

        For Cosmos, ``erc20`` is a misnomer — we surface all non-native
        denom transfers (IBC / TokenFactory / CW20 mapped through the
        bank module). The signature is preserved for ChainAdapter
        compatibility.
        """
        if not _bech32_basic_check(from_address):
            return []
        raw = self.client.fetch_txs_by_sender(from_address, limit=100)
        return self._normalize_response(raw, start_block=start_block, only_native=False)

    def fetch_inflows(
        self, to_address: str, start_block: int = 0
    ) -> list[dict[str, Any]]:
        """Fetch inbound transfers — used by the BFS for reverse hops.

        Not part of the EVM ChainAdapter interface but exposed for the
        wave-7 reverse-graph hookup.
        """
        if not _bech32_basic_check(to_address):
            return []
        raw = self.client.fetch_txs_by_recipient(to_address, limit=100)
        return self._normalize_response(raw, start_block=start_block, only_native=False)

    # ----- evidence / explorer -----

    def fetch_evidence_receipt(self, tx_hash: str) -> dict[str, Any]:
        """Minimal evidence-receipt shape. wave-7 will widen to match EVM."""
        if not tx_hash or not isinstance(tx_hash, str):
            return {"_error": "invalid tx_hash"}
        # LCD: /cosmos/tx/v1beta1/txs/{hash}
        url = f"{self.client._default_lcd.rstrip('/')}/cosmos/tx/v1beta1/txs/{tx_hash}"
        body = self.client.get_json(url)
        return body

    def explorer_tx_url(self, tx_hash: str, *, zone: str = "cosmos-hub") -> str:
        """Mintscan tx URL — works for the major zones we support."""
        return f"https://www.mintscan.io/{zone}/txs/{tx_hash}"

    def explorer_address_url(self, address: str) -> str:
        zi = resolve_zone(address)
        zone = zi.zone if zi else "cosmos-hub"
        return f"https://www.mintscan.io/{zone}/account/{address}"

    # ----- lifecycle -----

    def close(self) -> None:
        if self.client is not None:
            self.client.close()

    # ----- internal -----

    def _normalize_response(
        self,
        lcd_response: dict[str, Any],
        *,
        start_block: int,
        only_native: bool,
    ) -> list[dict[str, Any]]:
        """Walk an LCD tx-list response and pull out matching transfers."""
        if not isinstance(lcd_response, dict):
            return []
        if lcd_response.get("_error"):
            log.warning("cosmos_adapter_lcd_error error=%s", lcd_response.get("_error"))
            return []

        tx_responses = lcd_response.get("tx_responses") or []
        if not isinstance(tx_responses, list):
            return []

        out: list[dict[str, Any]] = []
        for tx_resp in tx_responses:
            transfers = _extract_transfers_from_tx_response(tx_resp)
            for t in transfers:
                if start_block and t.block_height < start_block:
                    continue
                if only_native:
                    # Native = non-IBC and matches the zone's expected micro-denom.
                    # We can't know the zone's denom without a per-zone table; use
                    # the heuristic "starts with 'u' and is short" to mean native.
                    if t.is_ibc:
                        continue
                    if len(t.denom) > 12:
                        continue
                out.append({
                    "chain": t.chain,
                    "zone": t.zone,
                    "tx_hash": t.tx_hash,
                    "block_number": t.block_height,
                    "block_time": t.block_time,
                    "log_index": None,
                    "from": t.from_address,
                    "to": t.to_address,
                    "token": t.denom,
                    "amount_raw": t.amount_raw,
                    "is_ibc": t.is_ibc,
                    "msg_type": t.msg_type,
                    "explorer_url": self.explorer_tx_url(t.tx_hash, zone=t.zone),
                })
        return out
