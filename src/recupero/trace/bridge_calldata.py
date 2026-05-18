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
        # For Solana: full 32-byte pubkey (use as-is)
        if dest_chain == "solana":
            # Solana addresses are base58 of the 32-byte pubkey. We can
            # surface the hex form; the operator's tooling (Solscan etc.)
            # will accept it.
            dest_address = "0x" + recipient_hex
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


__all__ = (
    "BridgeDecodeResult",
    "decode_bridge_calldata",
)
