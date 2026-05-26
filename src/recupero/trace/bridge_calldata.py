"""Bridge calldata parsing (v0.9.5).

When the trace detects a transfer to a known bridge contract,
we can sometimes extract the **destination address** from the
bridge transaction's input calldata. This converts an "investigator
must follow up at the bridge's explorer" handoff into a concrete
"funds went to ADDRESS X on CHAIN Y" finding.

Three bridges supported in v0.9.5 — the ones the V-CFI01 case
and typical Zigha-shape cases route through:

  * **Wormhole** (TokenBridge.transferTokens) — recipient address
    is in the calldata; destination chain encoded by Wormhole's
    chain-id mapping (1=solana, 2=ethereum, 4=bsc, 5=polygon, ...).

  * **Across** (SpokePool.deposit / depositV3) — recipient is the
    second argument; destination chainId is the third arg.

  * **Stargate** (Router.swap / swapETH) — uses LayerZero chain
    IDs (different from EVM chain IDs). dstChainId is encoded.

How this fits the broader trace

When ``identify_cross_chain_handoffs`` from cross_chain.py fires,
it returns a ``CrossChainHandoff`` with the bridge contract
detected. v0.9.5 adds a follow-up step: if we have the
transaction's input data (we do — it's in ``case.transfers[i]``),
we run the appropriate parser. On success, the handoff carries:

  * ``destination_chain: str`` — concrete chain (instead of a
    list of candidates).
  * ``destination_address: str`` — the recipient on the
    destination chain.

When parsing fails (unknown method signature, malformed input),
the existing destination_chain_candidates list + follow_up_url
remain — graceful degradation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)


# Bitcoin / Solana / Tron base58 alphabet (same set, same order).
# Used by the Wormhole decoder to convert raw 32-byte pubkeys
# (Solana destinations) and 21-byte payloads (Tron destinations)
# into the canonical address forms the downstream adapters expect.
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode_no_checksum(b: bytes) -> str:
    """Encode raw bytes as base58 (no checksum step).

    Solana addresses are b58(pubkey) with no checksum, so this is the
    direct encoding. Tron addresses are b58(payload + sha256d(payload)[:4]);
    the caller computes the checksum and passes the concatenation.

    Duplicates the implementation in chains.tron.address._b58encode
    intentionally — pulling it in would create a dependency from a
    chain-agnostic module to a chain-specific one. The alphabet and
    encoding rules are fixed by the base58 spec (Satoshi 2009), so
    duplication carries near-zero drift risk.
    """
    n_leading_zeros = 0
    for byte in b:
        if byte == 0:
            n_leading_zeros += 1
        else:
            break
    num = int.from_bytes(b, "big")
    encoded = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = _B58_ALPHABET[rem] + encoded
    return ("1" * n_leading_zeros) + encoded


@dataclass(frozen=True)
class BridgeDecodeResult:
    """One decoded bridge call.

    ``confidence`` is one of:
      'high'   — method signature recognized + all fields extracted
      'medium' — signature recognized but one field missing (e.g.,
                 destination address there but chain unclear)
      'low'    — partial decode based on heuristics
    """
    destination_chain: str | None
    destination_address: str | None
    bridge_method: str               # 'transferTokens' | 'deposit' | 'swap' | ...
    confidence: str
    raw_calldata_excerpt: str        # first 200 chars for forensic record


# Method-ID prefixes (first 4 bytes of keccak256(signature)) for
# the bridge call entry points. Each bridge has multiple
# overloads — we map a few key ones.
#
# Format: { "0xMETHODID": ("bridge_protocol", "method_name") }
#
# Generated via web3.py / cast: e.g.,
#   cast sig "transferTokens(address,uint256,uint16,bytes32,uint256,uint32)"
# returns 0x0f5287b0 for Wormhole's transferTokens.

_WORMHOLE_METHODS = {
    "0x0f5287b0": ("Wormhole", "transferTokens"),
    "0xc6878519": ("Wormhole", "transferTokensWithPayload"),
    "0x9981509f": ("Wormhole", "wrapAndTransferETH"),
}

_ACROSS_METHODS = {
    # depositV3(address depositor, address recipient, address inputToken,
    #           address outputToken, uint256 inputAmount, uint256 outputAmount,
    #           uint256 destinationChainId, address exclusiveRelayer, ...)
    "0x7b939232": ("Across", "depositV3"),
    # deposit(address recipient, address originToken, uint256 amount,
    #         uint256 destinationChainId, int64 relayerFeePct, ...)
    "0xf0826b7d": ("Across", "deposit"),
}

_STARGATE_METHODS = {
    # swap(uint16 dstChainId, uint256 srcPoolId, uint256 dstPoolId,
    #      address refundAddress, uint256 amountLD, uint256 minAmountLD,
    #      lzTxObj, bytes to, bytes payload)
    "0x9fbf10fc": ("Stargate", "swap"),
    # swapETH(uint16 dstChainId, ...)
    "0x1114cd2a": ("Stargate", "swapETH"),
}

# v0.28.0 (Jacob Zigha review item 2, step 2.2): DeBridge protocol
# recognition. DeBridge DLN createOrder calldata layouts are
# documented at https://docs.debridge.finance but the exact ABI
# parsing requires bookkeeping I haven't validated against
# authoritative on-chain data. The conservative path: recognize the
# protocol + method, return confidence='low' with no destination
# address. The handoff is still detected (bridges.json has the
# Arbitrum DeBridge entries as of v0.28.0); the trace report
# surfaces "Bridged via DeBridge — follow up at
# app.debridge.finance/orders". A full DLN order decoder ships in a
# v0.28.x point release once an authoritative test fixture is
# available.
_DEBRIDGE_METHODS = {
    # createSaleOrder(...) — DLN Source primary order creation.
    # Method selector verified against DLN source contract on
    # mainnet. Multiple overloads exist; we treat any selector
    # starting with 0xfb96b66e or 0xfaee513f as DeBridge for
    # recognition purposes.
    "0xfb96b66e": ("DeBridge", "createSaleOrder"),
    "0xfaee513f": ("DeBridge", "createOrder"),
    # send(...) — deBridgeGate forwarding call. Wraps an arbitrary
    # destination-chain payload + bridges via DLN.
    "0xb3c10b67": ("DeBridge", "send"),
}

# v0.28.0: 1inch router method recognition. 1inch Fusion+ deploys
# the same router on Arbitrum + Ethereum, and the cross-chain
# swap path produces calldata we can recognize at the method-ID
# layer. Same conservative treatment as DeBridge — confidence=low
# until a vetted DLN/1inch ABI test fixture exists.
_1INCH_METHODS = {
    # swap(...) on Aggregation Router v5 / v6
    "0x12aa3caf": ("1inch", "swap"),
    # unoswap(...) - direct DEX swap path
    "0x0502b1c5": ("1inch", "unoswap"),
    # uniswapV3Swap(...) - V3-path swap
    "0xe449022e": ("1inch", "uniswapV3Swap"),
}

# Wormhole chain-ID mapping. Wormhole assigns its own chain IDs
# (different from EVM chain IDs).
# Source: https://docs.wormhole.com/wormhole/reference/blockchains
_WORMHOLE_CHAIN_IDS = {
    1: "solana",
    2: "ethereum",
    4: "bsc",
    5: "polygon",
    6: "avalanche",
    7: "oasis",
    10: "fantom",
    11: "karura",
    12: "acala",
    13: "klaytn",
    14: "celo",
    16: "moonbeam",
    23: "arbitrum",
    24: "optimism",
    30: "base",
    # v0.17.5 (round-10 forensic HIGH): Tron + Bitcoin coverage.
    # Tron (chain 18) and Bitcoin (chain 21) handoffs were silently
    # dropped pre-v0.17.5 because their Wormhole IDs weren't mapped;
    # adapter exists for both now.
    18: "tron",
    21: "bitcoin",
}

# LayerZero chain IDs (Stargate uses these).
# Source: https://layerzero.gitbook.io/docs/technical-reference/mainnet
_LZ_CHAIN_IDS = {
    101: "ethereum",
    102: "bsc",
    106: "avalanche",
    109: "polygon",
    110: "arbitrum",
    111: "optimism",
    112: "fantom",
    184: "base",
    195: "linea",
}


def decode_bridge_calldata(
    *,
    bridge_protocol: str,
    input_data: str | None,
) -> BridgeDecodeResult | None:
    """Attempt to decode a bridge transaction's input calldata.

    Returns None if:
      - input_data is empty / too short
      - the method signature isn't one we know how to parse
      - decoding throws (malformed input)

    Returns a BridgeDecodeResult on partial-or-better decode.
    The handoff renderer uses None as "no extracted destination;
    fall back to candidates list."
    """
    if not input_data or not isinstance(input_data, str):
        return None
    data = input_data.lower().strip()
    if data.startswith("0x"):
        data = data[2:]
    if len(data) < 8:
        return None

    method_id = "0x" + data[:8]
    args_blob = data[8:]

    # Dispatch by protocol — each bridge's calldata has a different
    # argument layout.
    if bridge_protocol.lower().startswith("wormhole"):
        return _decode_wormhole(method_id, args_blob, data)
    if bridge_protocol.lower().startswith("across"):
        return _decode_across(method_id, args_blob, data)
    if bridge_protocol.lower().startswith("stargate"):
        return _decode_stargate(method_id, args_blob, data)
    # v0.28.0 (Jacob Zigha review item 2, step 2.2):
    # DeBridge + 1inch protocol-recognition decoders. Both return
    # confidence='low' / 'medium' (no destination decode yet — see
    # _decode_debridge / _decode_1inch docstrings for the rationale)
    # so the BFS won't auto-continue, but the handoff IS surfaced
    # in the trace report. Pre-v0.28 these were silently dropped.
    if "debridge" in bridge_protocol.lower():
        return _decode_debridge(method_id, args_blob, data)
    if "1inch" in bridge_protocol.lower():
        return _decode_1inch(method_id, args_blob, data)
    return None


# ----- per-bridge decoders ----- #


def _decode_wormhole(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode Wormhole TokenBridge.transferTokens calldata.

    Signature:
      transferTokens(address token, uint256 amount, uint16 recipientChain,
                     bytes32 recipient, uint256 arbiterFee, uint32 nonce)

    All args are 32-byte right-padded. Layout:
      [0..32]   token              (right-padded)
      [32..64]  amount             (uint256)
      [64..96]  recipientChain     (uint16 in last 2 bytes)
      [96..128] recipient          (bytes32 — for Solana this is the
                                    pubkey directly; for EVM chains
                                    it's the address right-padded)
      [128..160] arbiterFee
      [160..192] nonce
    """
    method_entry = _WORMHOLE_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    if len(args_blob) < 192 * 2:  # 192 bytes = 384 hex chars
        return BridgeDecodeResult(
            destination_chain=None,
            destination_address=None,
            bridge_method=method_name,
            confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )

    try:
        # recipientChain — uint16 right-aligned in slot [64..96]
        chain_id_hex = args_blob[64*2 + 60:64*2 + 64]  # last 4 hex of 32-byte slot
        chain_id = int(chain_id_hex, 16) if chain_id_hex else 0
        dest_chain = _WORMHOLE_CHAIN_IDS.get(chain_id)

        # recipient — bytes32 at slot [96..128]
        recipient_hex = args_blob[96*2:128*2]
        # For EVM destinations: right-padded address (last 40 hex)
        # For Solana: full 32-byte pubkey → base58
        # For Tron: 21-byte payload (prefix 0x41 + 20 address bytes) → base58check
        if dest_chain == "solana":
            # v0.17.5 (round-10 forensic CRIT): pre-v0.17.5 we surfaced
            # the raw "0x" + 64-hex form of the 32-byte pubkey, but
            # Solana's RPC and the Helius client both require base58
            # — so any cross-chain BFS continuation against the decoded
            # destination silently failed at the adapter boundary
            # (returned []). Encode here so the downstream Solana
            # adapter receives the canonical form.
            try:
                pubkey_bytes = bytes.fromhex(recipient_hex)
                dest_address = _b58encode_no_checksum(pubkey_bytes)
            except ValueError:
                dest_address = None
        elif dest_chain == "tron":
            # v0.17.5 (round-10 forensic CRIT): Wormhole-to-Tron is
            # rare but legitimate. The bytes32 recipient encodes the
            # full 21-byte payload (0x41 prefix + 20 address bytes)
            # right-padded into 32 bytes — last 21 are the payload.
            try:
                payload = bytes.fromhex(recipient_hex[-42:])
                # Append checksum and encode.
                import hashlib as _hl
                checksum = _hl.sha256(_hl.sha256(payload).digest()).digest()[:4]
                dest_address = _b58encode_no_checksum(payload + checksum)
            except ValueError:
                dest_address = None
        else:
            dest_address = "0x" + recipient_hex[24:]  # last 20 bytes

        return BridgeDecodeResult(
            destination_chain=dest_chain,
            destination_address=dest_address if dest_chain else None,
            bridge_method=method_name,
            confidence="high" if dest_chain else "medium",
            raw_calldata_excerpt=full_data[:400],
        )
    except (ValueError, IndexError) as exc:
        log.debug("wormhole decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain=None,
            destination_address=None,
            bridge_method=method_name,
            confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


def _decode_across(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode Across SpokePool.deposit / depositV3 calldata.

    depositV3 layout (Across v3, the current standard):
      [0..32]   depositor             (address right-padded)
      [32..64]  recipient             (address right-padded)
      [64..96]  inputToken            (address right-padded)
      [96..128] outputToken           (address right-padded)
      [128..160] inputAmount          (uint256)
      [160..192] outputAmount         (uint256)
      [192..224] destinationChainId   (uint256 EVM chain id — different
                                       from Wormhole's mapping; here it's
                                       the actual EVM chainId like 42161
                                       for Arbitrum, 10 for Optimism, etc.)
    """
    method_entry = _ACROSS_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    if method_name == "depositV3":
        return _decode_across_deposit_v3(args_blob, full_data, method_name)
    # Legacy deposit
    return _decode_across_deposit_legacy(args_blob, full_data, method_name)


def _decode_across_deposit_v3(
    args_blob: str, full_data: str, method_name: str,
) -> BridgeDecodeResult:
    if len(args_blob) < 224 * 2:
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )
    try:
        # recipient — slot [32..64], address in last 20 bytes
        recipient = "0x" + args_blob[32*2 + 24:64*2]
        # destinationChainId — slot [192..224], uint256
        dest_chain_id_hex = args_blob[192*2:224*2]
        dest_chain_id = int(dest_chain_id_hex, 16)
        dest_chain = _EVM_CHAIN_BY_ID.get(dest_chain_id)
        return BridgeDecodeResult(
            destination_chain=dest_chain,
            destination_address=recipient,
            bridge_method=method_name,
            confidence="high" if dest_chain else "medium",
            raw_calldata_excerpt=full_data[:400],
        )
    except (ValueError, IndexError) as exc:
        log.debug("across deposit_v3 decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


def _decode_across_deposit_legacy(
    args_blob: str, full_data: str, method_name: str,
) -> BridgeDecodeResult:
    """Legacy across deposit. Same recipient + chain extraction
    but different field positions."""
    if len(args_blob) < 128 * 2:
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )
    try:
        # recipient is the first arg
        recipient = "0x" + args_blob[24:64]
        # destinationChainId is the fourth arg
        dest_chain_id_hex = args_blob[96*2:128*2]
        dest_chain_id = int(dest_chain_id_hex, 16)
        dest_chain = _EVM_CHAIN_BY_ID.get(dest_chain_id)
        return BridgeDecodeResult(
            destination_chain=dest_chain,
            destination_address=recipient,
            bridge_method=method_name,
            confidence="high" if dest_chain else "medium",
            raw_calldata_excerpt=full_data[:400],
        )
    except (ValueError, IndexError):
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


def _decode_stargate(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode Stargate Router.swap / swapETH calldata.

    swap(uint16 dstChainId, uint256 srcPoolId, uint256 dstPoolId,
         address refundAddress, uint256 amountLD, uint256 minAmountLD,
         lzTxObj, bytes to, bytes payload)

    'to' is a dynamic-bytes field encoding the destination address.
    Layout in calldata:
      [0..32]   dstChainId (LayerZero chain ID)
      [32..64]  srcPoolId
      [64..96]  dstPoolId
      [96..128] refundAddress
      [128..160] amountLD
      [160..192] minAmountLD
      [192..256] lzTxObj struct
      [256..288] offset to 'to' bytes
      [288..320] offset to 'payload' bytes
      then [to_offset..] = (32-byte length) + (actual bytes data,
        zero-padded to 32-byte boundary). For EVM destinations,
        'to' is 20 bytes containing the address.

    We extract dstChainId (always at slot 0) and the 'to' field
    via the offset pointer.
    """
    method_entry = _STARGATE_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    if len(args_blob) < 32 * 2:
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )
    try:
        # dstChainId — first slot
        lz_chain_id_hex = args_blob[60:64]
        lz_chain_id = int(lz_chain_id_hex, 16)
        dest_chain = _LZ_CHAIN_IDS.get(lz_chain_id)

        # 'to' offset is at slot [256..288] in 'swap'.
        # For 'swapETH' the layout is shifted (one less arg).
        # Try the swap layout first.
        dest_address = None
        if method_name == "swap" and len(args_blob) >= 320 * 2:
            try:
                to_offset_hex = args_blob[256*2:288*2]
                to_offset = int(to_offset_hex, 16) * 2  # convert byte offset to hex offset
                # 'to' = length (32 bytes) then bytes (padded)
                if to_offset + 32*2 <= len(args_blob):
                    to_len_hex = args_blob[to_offset:to_offset + 32*2]
                    to_len = int(to_len_hex, 16)
                    if to_len > 0 and to_len <= 32:
                        # Read the actual bytes
                        to_data_start = to_offset + 32*2
                        to_data_end = to_data_start + (to_len * 2)
                        if to_data_end <= len(args_blob):
                            to_bytes_hex = args_blob[to_data_start:to_data_end]
                            if to_len == 20:
                                # EVM address
                                dest_address = "0x" + to_bytes_hex
                            else:
                                dest_address = "0x" + to_bytes_hex
            except (ValueError, IndexError):
                dest_address = None

        confidence = (
            "high" if (dest_chain and dest_address)
            else "medium" if (dest_chain or dest_address)
            else "low"
        )
        return BridgeDecodeResult(
            destination_chain=dest_chain,
            destination_address=dest_address,
            bridge_method=method_name,
            confidence=confidence,
            raw_calldata_excerpt=full_data[:400],
        )
    except (ValueError, IndexError) as exc:
        log.debug("stargate decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


# EVM chain IDs (used by Across, which uses real EVM chain IDs
# rather than Wormhole/LayerZero internal IDs).
_EVM_CHAIN_BY_ID = {
    1: "ethereum",
    10: "optimism",
    137: "polygon",
    42161: "arbitrum",
    8453: "base",
    324: "zksync",
    56: "bsc",
    43114: "avalanche",
}


# ─────────────────────────────────────────────────────────────────────────────
# v0.28.0 (Jacob Zigha review item 2, step 2.2) — DeBridge + 1inch
# protocol-recognition decoders.
# ─────────────────────────────────────────────────────────────────────────────


def _decode_debridge(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Recognize DeBridge DLN calldata; return low-confidence decode.

    DeBridge DLN's `createSaleOrder(...)` / `createOrder(...)` /
    `send(...)` methods have multiple overloads with non-trivial
    ABI layouts. The destination chain ID + receiver address ARE
    encoded but extracting them reliably requires bookkeeping I
    haven't validated against authoritative on-chain test fixtures.

    The conservative path: emit confidence='low' with no
    destination address. Outcomes:
      * cross-chain BFS does NOT auto-continue (the
        decoded_conf != "high" gate in tracer.py blocks it)
      * trace_report DOES surface "Bridged via DeBridge — follow
        up at app.debridge.finance/orders"
      * operator can manually pursue the destination via the
        DeBridge explorer

    Full destination-decode lands in a v0.28.x point release once
    an authoritative DLN ABI test fixture is checked in. Until
    then this is strictly recognition + handoff surfacing.
    """
    method_entry = _DEBRIDGE_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry
    return BridgeDecodeResult(
        destination_chain=None,
        destination_address=None,
        bridge_method=method_name,
        confidence="low",
        raw_calldata_excerpt=full_data[:400],
    )


def _decode_1inch(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Recognize 1inch Aggregation Router calldata; low-confidence.

    1inch routers (v5/v6) primarily perform same-chain DEX swaps
    rather than cross-chain bridging. Fusion+ adds cross-chain
    routing as a layered protocol on top. When a transfer to a
    1inch router shows up in a trace, we want to surface "passed
    through 1inch" without claiming a specific destination chain
    (that would be wrong for most 1inch txs, which stay on the
    source chain).

    Same conservative treatment as DeBridge: confidence='low',
    no destination address. The trace report shows "Routed via
    1inch" and the operator follows up via 1inch's own explorers
    or the source-chain block explorer for the swap outputs.
    """
    method_entry = _1INCH_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry
    return BridgeDecodeResult(
        destination_chain=None,
        destination_address=None,
        bridge_method=method_name,
        confidence="low",
        raw_calldata_excerpt=full_data[:400],
    )


__all__ = (
    "BridgeDecodeResult",
    "decode_bridge_calldata",
)
