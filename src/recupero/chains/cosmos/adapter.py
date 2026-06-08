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

DONE (v0.39, Activation Sprint #5): CosmosAdapter is now a concrete
``ChainAdapter`` registered in ``chains/base.ChainAdapter.for_chain`` behind
``Chain.cosmos`` with a real httpx transport injected at the factory, and
bech32 addresses validate structurally — ``models.Address`` is an
unconstrained ``str`` (chain-aware normalization happens here), so no model
change was needed. The BFS now reaches + follows funds ON Cosmos and persists
a real ``EvidenceReceipt`` per hop.

TODO(wave-8-integration) — remaining cross-chain depth:
  1. Wire IBC packet decode for cross-chain continuation OUT of Cosmos: the
     ``MsgRecvPacket`` / ``MsgTransfer`` event types carry the source-chain
     identifier in the IBC counterparty channel.
  2. Add Mintscan label ingest to ``labels/seeds/cosmos_labels.json``.
  3. Upgrade ``_bech32_basic_check`` to a full BIP-173 polymod checksum verify
     + plumb the ``/cosmwasm/wasm/v1/contract`` lookup into ``is_contract``.
"""

from __future__ import annotations

import base64
import binascii
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from recupero.chains.base import ChainAdapter
from recupero.chains.cosmos.client import (
    CosmosLCDClient,
    base_denom_for,
    resolve_zone,
)
from recupero.models import Chain, EvidenceReceipt

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
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except (ValueError, TypeError):
        return None


_KNOWN_ATTR_KEYS = frozenset({"recipient", "sender", "amount"})


def _try_b64_to_text(value: Any) -> str | None:
    """Strict base64 → UTF-8 text decode, or None if it isn't valid b64 text.

    Used only to *probe* whether an event's attribute keys are base64.
    Returns None for anything that doesn't cleanly round-trip to printable
    UTF-8 (so genuine plaintext is never mistaken for base64).
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if base64.b64encode(raw).decode("ascii") != value:
        return None
    try:
        return raw.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None


def _decode_attr_value(value: Any, *, is_b64: bool) -> str | None:
    """Decode one attribute value given a known per-event b64 flag.

    When the event is confirmed base64-encoded we decode; otherwise we
    return the raw string. This avoids guessing per-value (which is
    error-prone because plaintext amounts/denoms are themselves valid
    base64 charset).
    """
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value)
    if not is_b64:
        return value
    decoded = _try_b64_to_text(value)
    # If the event was deemed b64 but THIS value won't decode, fall back
    # to the raw string rather than dropping it.
    return decoded if decoded is not None else value


# Back-compat shim: some callers/tests reference the older name. Decodes a
# single value only when it unambiguously round-trips as base64 text.
def _maybe_b64_decode_attr(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value)
    decoded = _try_b64_to_text(value)
    # Only accept the decode if the plaintext is a KNOWN attribute key —
    # otherwise treat the input as already-plaintext and return verbatim.
    if decoded is not None and decoded in _KNOWN_ATTR_KEYS:
        return decoded
    return value


def _event_is_base64(attrs: list[Any]) -> bool:
    """Decide whether an event's attributes are base64-encoded.

    Signal: in the base64 LCD variant, the attribute KEYS are also
    base64 (``recipient`` → ``cmVjaXBpZW50``). If any key decodes to a
    known attribute name AND no key is already a plaintext known name,
    the event is base64-encoded. Plaintext events leave keys as-is.
    """
    saw_b64_known = False
    for attr in attrs:
        if not isinstance(attr, dict):
            continue
        k = attr.get("key")
        if isinstance(k, str) and k in _KNOWN_ATTR_KEYS:
            # A plaintext known key proves this event is NOT base64.
            return False
        decoded = _try_b64_to_text(k)
        if decoded in _KNOWN_ATTR_KEYS:
            saw_b64_known = True
    return saw_b64_known


def _extract_transfers_from_events(
    events: list[Any],
    *,
    tx_hash: str,
    block_height: int,
    block_time: datetime | None,
    msg_type: str,
    decode_b64: bool,
) -> list[CosmosTransfer]:
    """Pull transfer rows from a flat ``events`` list (per-log OR top-level).

    Each event is ``{"type": str, "attributes": [{"key", "value"}, ...]}``.
    The canonical transfer event is type=``transfer`` with ``recipient`` /
    ``sender`` / ``amount`` attribute triples (an event may carry several
    triples when one tx executes multiple sends). When ``decode_b64`` is
    set, we probe each event for base64-encoded attributes (SDK >= v0.46
    LCD variants) and decode consistently per-event.
    """
    out: list[CosmosTransfer] = []
    if not isinstance(events, list):
        return out
    for event in events:
        if not isinstance(event, dict):
            continue
        # ``type`` itself may be base64 in the encoded variant.
        ev_type = event.get("type")
        type_plain = ev_type if isinstance(ev_type, str) else None
        if type_plain != "transfer":
            decoded_type = _try_b64_to_text(ev_type)
            if decoded_type != "transfer":
                continue
        attrs = event.get("attributes") or []
        if not isinstance(attrs, list):
            continue
        # Probe per-event whether attributes are base64 (only in the
        # top-level events path; legacy logs are always plaintext).
        is_b64 = decode_b64 and _event_is_base64(attrs)
        # Walk attributes, grouping into (recipient, sender, amount)
        # triples. The LCD pads each send to a full triple.
        recipient: str | None = None
        sender: str | None = None
        amount_str: str | None = None
        for attr in attrs:
            if not isinstance(attr, dict):
                continue
            k = _decode_attr_value(attr.get("key"), is_b64=is_b64)
            v = _decode_attr_value(attr.get("value"), is_b64=is_b64)
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


def _extract_transfers_from_tx_response(
    tx_response: dict[str, Any],
) -> list[CosmosTransfer]:
    """Walk one LCD tx_response and pull out all transfer events.

    Two event-layout paths are supported:

    * Legacy (Cosmos SDK < v0.46): events live under per-message ``logs``,
      i.e. ``tx_response["logs"][*]["events"]``. Attributes are plaintext.
    * Modern (Cosmos SDK ≥ v0.46 — Hub, Osmosis, Injective, every live
      zone today): ``tx_response["logs"]`` is ``[]`` and the events are
      flattened into the top-level ``tx_response["events"]`` array.
      Some LCD versions base64-encode the attribute key/value strings.

    We prefer ``logs`` when it carries data; otherwise we fall back to
    the top-level ``events`` array. Reading ONLY ``logs`` (the old
    behavior) silently dropped *every* transfer on modern chains.

    Returns: list of CosmosTransfer rows. Empty if no transfers found.
    """
    if not isinstance(tx_response, dict):
        return []

    tx_hash = str(tx_response.get("txhash") or tx_response.get("tx_hash") or "")
    try:
        block_height = int(tx_response.get("height", 0) or 0)
    except (ValueError, TypeError):
        block_height = 0
    block_time = _parse_lcd_timestamp(tx_response.get("timestamp"))

    # Pull msg_type from the first message of the tx body
    msg_type = ""
    tx = tx_response.get("tx") or {}
    body = (tx.get("body") if isinstance(tx, dict) else {}) or {}
    messages = body.get("messages") or []
    if isinstance(messages, list) and messages and isinstance(messages[0], dict):
        msg_type = str(messages[0].get("@type", ""))

    out: list[CosmosTransfer] = []

    # --- legacy path: per-message logs (plaintext attributes) ---
    logs = tx_response.get("logs")
    if isinstance(logs, list):
        for log_entry in logs:
            if not isinstance(log_entry, dict):
                continue
            events = log_entry.get("events") or []
            out.extend(_extract_transfers_from_events(
                events,
                tx_hash=tx_hash,
                block_height=block_height,
                block_time=block_time,
                msg_type=msg_type,
                decode_b64=False,
            ))

    # --- modern path: top-level events (SDK >= v0.46) ---
    # Only fall back when ``logs`` produced nothing, so old chains that
    # populate BOTH arrays don't double-count. Top-level event attrs may
    # be base64-encoded depending on LCD version → decode defensively.
    if not out:
        top_events = tx_response.get("events")
        out.extend(_extract_transfers_from_events(
            top_events if isinstance(top_events, list) else [],
            tx_hash=tx_hash,
            block_height=block_height,
            block_time=block_time,
            msg_type=msg_type,
            decode_b64=True,
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
        # Find where the digits end and the denom starts. Restrict to
        # ASCII 0-9 — str.isdigit() also matches Unicode digit forms
        # (e.g. superscripts) that int() then rejects.
        i = 0
        while i < len(component) and component[i] in "0123456789":
            i += 1
        if i == 0:
            # No leading amount; malformed → skip.
            continue
        amount_raw_str = component[:i]
        denom = component[i:].strip()
        if not denom:
            # Bare number with no denom → not a real coin; skip.
            continue
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
# Native-denom classification
# -----------------------------------------------------------------------------

# Denom namespaces that are NEVER the chain's native staking/fee asset,
# regardless of zone: IBC vouchers, TokenFactory denoms, and CW20 maps.
_NON_NATIVE_DENOM_PREFIXES = ("ibc/", "factory/", "cw20:")


def _is_native_denom(denom: str, owner_address: str) -> bool:
    """Return True iff ``denom`` is the native base denom of its zone.

    Replaces the broken ``len(denom) > 12`` heuristic, which
    misclassified short non-native micro-denoms (e.g. ``uusdc``) as
    native and could let long-but-native edge cases through.

    Rules:
      * ``ibc/``, ``factory/``, ``cw20:`` namespaces are NEVER native.
      * Otherwise native iff ``denom`` EXACTLY equals the zone's base
        denom (resolved via the address bech32 prefix).
      * If the zone is unknown (no base denom on record), we cannot
        prove nativeness → treat as NON-native (conservative; a forensic
        trace would rather surface it under the token path than silently
        mislabel an unknown denom as the chain coin).
    """
    if not isinstance(denom, str) or not denom:
        return False
    d = denom.strip()
    lower = d.lower()
    if any(lower.startswith(p) for p in _NON_NATIVE_DENOM_PREFIXES):
        return False
    base = base_denom_for(owner_address)
    if base is None:
        return False
    return d == base


# -----------------------------------------------------------------------------
# Page-cap resolution (v0.32.1 follow-up)
# -----------------------------------------------------------------------------

# CosmosLCDClient fetches this many txs per LCD page.
_LCD_PAGE_SIZE = 100
# Mirror the project transfer budget: config.trace.max_transfers_per_address
# defaults to 50_000 (industry-best mode). 50_000 / 100 = 500 pages.
# Pre-follow-up the paginators used a hardcoded max_pages=50 (5_000 txs) —
# a 10x silent truncation BELOW the configured budget on a very high-volume
# forensic target. NB: tron/client.py + solana/helius.py still carry the
# same hardcoded 50 default at their client layer (parallel follow-up;
# their adapters likewise don't yet thread a config-derived cap).
_DEFAULT_MAX_TRANSFERS_PER_ADDRESS = 50_000
# Absolute upper bound on pages so a misconfig / "disabled" budget can't
# walk an unbounded address forever. 5_000 pages = 500k txs.
_HARD_PAGE_CEILING = 5_000


def _resolve_max_pages(max_transfers_per_address: int | None) -> int:
    """Translate a per-address transfer budget into an LCD page cap.

    ``max_transfers_per_address <= 0`` means "disabled / unbounded"
    (industry-best mode's 0-disables convention) → return the hard
    ceiling. Otherwise ceil(cap / page_size), clamped to
    ``[1, _HARD_PAGE_CEILING]``.
    """
    cap = (
        _DEFAULT_MAX_TRANSFERS_PER_ADDRESS
        if max_transfers_per_address is None
        else max_transfers_per_address
    )
    if cap <= 0:
        return _HARD_PAGE_CEILING
    pages = -(-cap // _LCD_PAGE_SIZE)  # ceil division, no float
    return max(1, min(_HARD_PAGE_CEILING, pages))


# -----------------------------------------------------------------------------
# Adapter
# -----------------------------------------------------------------------------


class CosmosAdapter(ChainAdapter):
    """Read-only Cosmos / IBC adapter.

    v0.39 (Activation Sprint #5): now a concrete ``ChainAdapter`` subclass and
    wired into ``ChainAdapter.for_chain`` behind ``Chain.cosmos``. The earlier
    "don't inherit because the ABC's ``Address`` is EVM-shaped" rationale is
    moot — ``models.Address`` is an unconstrained ``str`` alias (chain-aware
    normalization happens in the adapter), so a bech32 string is already a
    valid ``Address``.

    All public methods accept a bech32 address string. Cross-chain IBC
    *continuation* (following funds OUT of Cosmos via ``MsgRecvPacket`` /
    ``MsgTransfer`` counterparty channels) is the next layer and not yet
    wired — the trace reaches and follows funds ON Cosmos and surfaces the
    hop + destination address rather than dead-ending.
    """

    chain = Chain.cosmos
    chain_str: str = "cosmos"

    def __init__(
        self,
        client: CosmosLCDClient | None = None,
        *,
        default_lcd_base_url: str | None = None,
        max_transfers_per_address: int | None = None,
    ) -> None:
        self.client = client or CosmosLCDClient(default_lcd_base_url=default_lcd_base_url)
        # v0.32.1 follow-up: derive the LCD page cap from the project
        # transfer budget instead of the client's hardcoded max_pages=50,
        # so a high-volume forensic target isn't silently truncated at
        # 5_000 txs. When ChainAdapter.for_chain wires Cosmos live it
        # should pass config.trace.max_transfers_per_address here. As a
        # fallback (the adapter isn't config-aware yet) we honor the same
        # RECUPERO_MAX_TRANSFERS_PER_ADDRESS env override the tracer's
        # per-hop fetch uses, defaulting to the config default (50_000).
        if max_transfers_per_address is None:
            import os
            _env = os.environ.get("RECUPERO_MAX_TRANSFERS_PER_ADDRESS")
            if _env is not None:
                try:
                    max_transfers_per_address = int(_env)
                except (TypeError, ValueError):
                    max_transfers_per_address = None
        self._max_pages = _resolve_max_pages(max_transfers_per_address)

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

        Paginates across all LCD pages (not just the first 100 txs) so
        high-volume addresses aren't silently truncated.
        """
        if not _bech32_basic_check(from_address):
            return []
        raw = self.client.fetch_all_txs_by_sender(
            from_address, limit=100, max_pages=self._max_pages,
        )
        return self._normalize_response(raw, start_block=start_block, only_native=True)

    def fetch_erc20_outflows(
        self, from_address: str, start_block: int = 0
    ) -> list[dict[str, Any]]:
        """Fetch IBC-denom and CW20-token outflows.

        For Cosmos, ``erc20`` is a misnomer — we surface all non-native
        denom transfers (IBC / TokenFactory / CW20 mapped through the
        bank module). The signature is preserved for ChainAdapter
        compatibility. Paginates across all LCD pages.
        """
        if not _bech32_basic_check(from_address):
            return []
        raw = self.client.fetch_all_txs_by_sender(
            from_address, limit=100, max_pages=self._max_pages,
        )
        return self._normalize_response(raw, start_block=start_block, only_native=False)

    def fetch_inflows(
        self, to_address: str, start_block: int = 0
    ) -> list[dict[str, Any]]:
        """Fetch inbound transfers — used by the BFS for reverse hops.

        Not part of the EVM ChainAdapter interface but exposed for the
        wave-7 reverse-graph hookup. Paginates across all LCD pages.
        """
        if not _bech32_basic_check(to_address):
            return []
        raw = self.client.fetch_all_txs_by_recipient(
            to_address, limit=100, max_pages=self._max_pages,
        )
        return self._normalize_response(raw, start_block=start_block, only_native=False)

    # ----- evidence / explorer -----

    def fetch_evidence_receipt(self, tx_hash: str) -> EvidenceReceipt:
        """Fetch the full chain-of-custody receipt for ``tx_hash``.

        Builds a real :class:`~recupero.models.EvidenceReceipt` from the LCD
        ``/cosmos/tx/v1beta1/txs/{hash}`` response — its ``tx_response`` carries
        the block ``height`` + ``timestamp`` + the raw tx/result. Raises
        ``ValueError`` if the tx can't be fetched or lacks a block timestamp:
        the tracer's evidence writer is best-effort (it logs the failure) and we
        never fabricate a chain-of-custody record with a made-up block time.
        """
        if not tx_hash or not isinstance(tx_hash, str):
            raise ValueError("invalid tx_hash for cosmos evidence receipt")
        base = self.client._default_lcd.rstrip("/")
        url = f"{base}/cosmos/tx/v1beta1/txs/{tx_hash}"
        body = self.client.get_json(url)
        if not isinstance(body, dict) or body.get("_error"):
            err = body.get("_error") if isinstance(body, dict) else "no response"
            raise ValueError(f"cosmos evidence fetch failed tx={tx_hash}: {err}")
        tx_response = body.get("tx_response")
        if not isinstance(tx_response, dict):
            raise ValueError(f"cosmos evidence: no tx_response for tx={tx_hash}")
        block_time = _parse_lcd_timestamp(tx_response.get("timestamp"))
        if block_time is None:
            raise ValueError(f"cosmos evidence: no block timestamp for tx={tx_hash}")
        try:
            block_number = int(tx_response.get("height") or 0)
        except (TypeError, ValueError):
            block_number = 0
        raw_tx = tx_response.get("tx")
        return EvidenceReceipt(
            chain=Chain.cosmos,
            tx_hash=tx_hash,
            block_number=block_number,
            block_time=block_time,
            raw_transaction=raw_tx if isinstance(raw_tx, dict) else {},
            raw_receipt=tx_response,
            raw_block_header={},
            fetched_at=datetime.now(UTC),
            fetched_from=f"{base}/cosmos/tx/v1beta1/txs",
            explorer_url=self.explorer_tx_url(tx_hash),
        )

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

        # Finding 4: a positive start_block is a real filter; a non-positive
        # value (0, or the -1 sentinel from ``block_at_or_before``) means
        # "no filter" so the sentinel can never accidentally drop rows.
        apply_block_filter = isinstance(start_block, int) and start_block > 0

        out: list[dict[str, Any]] = []
        for tx_resp in tx_responses:
            transfers = _extract_transfers_from_tx_response(tx_resp)
            for t in transfers:
                if apply_block_filter and t.block_height < start_block:
                    continue
                if only_native and not _is_native_denom(t.denom, t.from_address):
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
