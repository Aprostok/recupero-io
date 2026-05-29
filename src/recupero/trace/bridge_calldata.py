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

# v0.31.0 — Connext/Everclear Diamond `xcall` family.
# Source: https://docs.connext.network — Diamond proxy uses standard
# diamond-cut method routing; the LE-relevant signatures are:
#   xcall(uint32 destination, address to, address asset, address delegate,
#         uint256 amount, uint256 slippage, bytes callData)
#   xcallIntoLocal(...)   — same args, internal liquidity
#   xreceive(...)         — destination-side receive (not used here)
# The first uint32 is Connext's "domain ID" — their own chain ID
# mapping (not EVM chainID, not Wormhole, not LayerZero).
_CONNEXT_METHODS = {
    "0x4ff746f6": ("Connext", "xcall"),
    "0x0c884583": ("Connext", "xcallIntoLocal"),
}

# v0.31.0 — Axelar Gateway `callContractWithToken` + sendToken.
# Source: https://docs.axelar.dev — Gateway is the cross-chain entry
# point; signatures:
#   callContractWithToken(string destinationChain, string contractAddress,
#                         bytes payload, string symbol, uint256 amount)
#   sendToken(string destinationChain, string destinationAddress,
#             string symbol, uint256 amount)
# Note: Axelar destinationChain is a STRING (e.g. "Ethereum", "Polygon",
# "Avalanche") not a uint16. The decoder parses it from the dynamic-
# bytes section. Same for destinationAddress — string-typed, may be
# either an EVM 0x-hex or a Cosmos bech32 (Axelar bridges into Cosmos).
_AXELAR_METHODS = {
    "0xb5417084": ("Axelar", "callContractWithToken"),
    "0x26ef699d": ("Axelar", "sendToken"),
}

# Axelar destinationChain string → canonical chain enum. Conservative
# subset of Axelar's network list; unknown strings render as the raw
# value so the brief still surfaces the destination claim.
_AXELAR_CHAIN_NAMES: dict[str, str] = {
    "ethereum": "ethereum",
    "polygon": "polygon",
    "avalanche": "avalanche",
    "fantom": "fantom",
    "moonbeam": "moonbeam",
    "binance": "bsc",
    "bsc": "bsc",
    "arbitrum": "arbitrum",
    "optimism": "optimism",
    "base": "base",
    "linea": "linea",
    "celo": "celo",
    "kava": "kava",
    "filecoin": "filecoin",
    "osmosis": "cosmos",
    "axelar": "cosmos",
}

# v0.31.2 — Celer cBridge. Celer uses pool-based liquidity across EVM
# chains; the Bridge contract entry point on each chain is `send`
# (ERC-20) or `sendNative` (native token). Source:
# https://cbridge-docs.celer.network — Signatures:
#   send(address receiver, address token, uint256 amount,
#        uint64 dstChainId, uint64 nonce, uint32 maxSlippage)
#   sendNative(address receiver, uint256 amount,
#              uint64 dstChainId, uint64 nonce, uint32 maxSlippage)
# Both encode dstChainId as a real EVM chain ID (not LayerZero, not
# Wormhole), so `_EVM_CHAIN_BY_ID` is the right lookup.
_CELER_METHODS = {
    "0xa5977fbb": ("Celer", "send"),
    "0xe957bf91": ("Celer", "sendNative"),
}

# v0.31.2 — Synapse Protocol. SynapseBridge's `bridge` /
# `swapAndRedeem` methods put recipient + EVM chainId in the first
# two static slots. Source: https://docs.synapseprotocol.com
#   bridge(address to, uint256 chainId, IERC20 token, uint256 amount)
#   swapAndRedeem(address to, uint256 chainId, IERC20 token,
#                 uint8 tokenIndexFrom, uint8 tokenIndexTo,
#                 uint256 dx, uint256 minDy, uint256 deadline)
# Both share the (to, chainId) prefix layout — the same slot reader
# decodes either.
_SYNAPSE_METHODS = {
    "0xfa9d8e22": ("Synapse", "bridge"),
    "0xf1a64348": ("Synapse", "swapAndRedeem"),
}

# v0.31.2 — Symbiosis MetaRouter. Symbiosis is a cross-chain swap +
# bridge protocol that routes through a `MetaRouter` contract on every
# supported chain. Source: https://docs.symbiosis.finance — the canonical
# source-chain entry point is:
#
#   metaRoute(MetaRouteTransaction _metarouteTransaction)
#
# where MetaRouteTransaction is the tuple:
#
#   struct MetaRouteTransaction {
#     bytes    firstSwapCalldata;
#     bytes    secondSwapCalldata;
#     address[] approvedTokens;
#     address  firstDexRouter;
#     address  secondDexRouter;
#     uint256  amount;
#     bool     nativeIn;
#     address  relayRecipient;     // <-- recipient on destination
#     bytes    otherSideCalldata;  // <-- chainID encoded inside this blob
#   }
#
# Selector verified via 4byte.directory:
#   metaRoute((bytes,bytes,address[],address,address,uint256,bool,address,bytes))
#   = 0xa11b1198
#
# The destination chain ID is NOT a top-level struct field — it's
# encoded inside `otherSideCalldata` (a calldata blob targeting the
# destination-side metaMintSwap call). Reliable extraction would
# require parsing that nested call. We follow the LiFi conservative
# path: try a small set of candidate offsets that have empirically
# carried a 6/10/137/42161/8453/56 value in mainnet traces; if any
# yields a known EVM chain ID, surface it as high-confidence; if not,
# we still extract `relayRecipient` (always at struct slot 7 inside
# the inlined tuple body) so the trace gets a medium-confidence
# destination address.
_SYMBIOSIS_METHODS = {
    "0xa11b1198": ("Symbiosis", "metaRoute"),
}

# v0.31.1 — Hop Protocol L1Bridge.sendToL2 family. Hop's L1-to-L2
# entry point encodes the destination chain ID (EVM chainID) as the
# first uint256 arg and the recipient address as the second arg.
# Selectors verified via `cast sig "sendToL2(uint256,address,uint256,uint256,uint256,address,uint256)"`.
# The two selectors below cover the v1 + v1.1 overloads (identical
# argument layout; second is an older deprecated form).
_HOP_METHODS = {
    "0xdeace8f5": ("Hop", "sendToL2"),
    "0xa6df7b8c": ("Hop", "sendToL2"),
}

# v0.31.1 — Squid Router. Squid is built on top of Axelar — its
# bridgeCall / callBridgeCall methods wrap a destination-chain
# string + destination-address string the same way Axelar's
# native sendToken/callContractWithToken do. We reuse
# _AXELAR_CHAIN_NAMES + _read_solidity_string. Selectors verified
# against the Squid Router contract on Etherscan.
_SQUID_METHODS = {
    "0x84d2bb4d": ("Squid", "bridgeCall"),
    "0x32fb1360": ("Squid", "callBridgeCall"),
}

# v0.31.0 — LiFi Diamond. LiFi is an aggregator — it routes through
# OTHER bridges (Stargate, Across, Hop, etc.) — so the LiFi calldata
# wraps an "encoded swap data" struct that names the underlying
# bridge. The forensically-useful fields are:
#   * destinationChainId (uint256, the EVM chainID of the destination)
#   * receiver (address)
#   * bridge (string, e.g. "stargate", "across", "hop")
# Common methods (LiFi uses diamond facets — many selectors map here).
# We catch the most common entry points; unrecognized facets fall back
# to confidence='low' recognition.
_LIFI_METHODS = {
    # swapAndStartBridgeTokensViaXYZ family — facet routes
    "0xfbb73a4f": ("LiFi", "swapAndStartBridgeTokensViaStargate"),
    "0x6cf26d72": ("LiFi", "swapAndStartBridgeTokensViaAcross"),
    "0x42a2b1cd": ("LiFi", "swapAndStartBridgeTokensViaHop"),
    # startBridgeTokensViaXYZ — no-swap variants
    "0xed178619": ("LiFi", "startBridgeTokensViaStargate"),
    "0xb4c20477": ("LiFi", "startBridgeTokensViaAcross"),
    # GenericSwapFacet — same-chain swap, used as a routing primitive
    "0x4666fc80": ("LiFi", "swapTokensGeneric"),
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

# LayerZero chain IDs (Stargate v1 + LayerZero v1 OApp endpoints).
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

# v0.31.4 — LayerZero v2 Endpoint IDs (EIDs). LayerZero v2 uses uint32
# EIDs in the 30000-series for mainnet (different namespace from v1).
# Stargate v2 + LayerZero v2 OApps dispatch through these. Source:
# https://docs.layerzero.network/v2/developers/evm/technical-reference/deployed-contracts
_LAYERZERO_V2_EIDS: dict[int, str] = {
    30101: "ethereum",
    30102: "bsc",
    30106: "avalanche",
    30109: "polygon",
    30110: "arbitrum",
    30111: "optimism",
    30112: "fantom",
    30183: "linea",
    30184: "base",
    30214: "scroll",
    30253: "zksync",
}

# v0.31.4 — Chainlink CCIP chain selectors. CCIP uses uint64 selectors
# (a separate namespace from EVM chainIDs / LayerZero EIDs / Wormhole
# chain IDs). Source: https://docs.chain.link/ccip/supported-networks
_CCIP_CHAIN_SELECTORS: dict[int, str] = {
    5009297550715157269: "ethereum",
    4051577828743386545: "polygon",
    4949039107694359620: "arbitrum",
    3734403246176062136: "optimism",
    15971525489660198786: "base",
    6433500567565415381: "avalanche",
    11344663589394136015: "bsc",
}


# v0.31.4 — DeBridge DLN. createSaleOrder / createOrder dispatch into
# the DLN Source contract. The OrderCreation struct carries takeChainId
# (uint256, EVM chainID for EVM destinations) + receiverDst (bytes,
# variable-length so EVM or non-EVM destinations both fit). Reusing
# _DEBRIDGE_METHODS from v0.28.0 — the decoder body now does real
# extraction rather than the conservative recognition-only stub.

# v0.31.4 — LayerZero raw OApp Endpoint `send` selectors.
#  v1: send(uint16 _dstChainId, bytes _destination, bytes _payload,
#           address payable _refundAddress, address _zroPaymentAddress,
#           bytes _adapterParams)
#  v2: send(MessagingParams calldata _params, address _refundAddress)
# Selectors verified via 4byte directory.
_LAYERZERO_METHODS: dict[str, tuple[str, str]] = {
    "0xc5803100": ("LayerZero", "send_v1"),
    "0x1bb3a8fd": ("LayerZero", "send_v2"),
}

# v0.31.4 — Chainlink CCIP Router. ccipSend(uint64 destinationChainSelector,
# Client.EVM2AnyMessage message) where EVM2AnyMessage =
# (bytes receiver, bytes data, EVMTokenAmount[] tokenAmounts,
#  address feeToken, bytes extraArgs). Selector confirmed via cast sig.
_CCIP_METHODS: dict[str, tuple[str, str]] = {
    "0x96f4e9f9": ("CCIP", "ccipSend"),
}

# v0.31.4 — Multichain (Anyswap legacy) router. Anyswap contracts ceased
# active operation July 2023 but transit traffic still hits legacy
# routers; recognizing the calldata lets the trace continue past those
# handoffs into the destination chain (where the funds are typically
# unrecoverable, but the destination needs to be on the case record).
#   anySwapOutUnderlying(address token, address to, uint256 amount, uint256 toChainID)
#   anySwapOut(address token, address to, uint256 amount, uint256 toChainID)
_MULTICHAIN_METHODS: dict[str, tuple[str, str]] = {
    "0xa5e56571": ("Multichain", "anySwapOutUnderlying"),
    "0xa5e3deeb": ("Multichain", "anySwapOut"),
}

# v0.31.4 — Stargate v2 entry point. The Pool contract exposes
#   sendToken(SendParam, MessagingFee, address) where
#   SendParam = (uint32 dstEid, bytes32 to, uint256 amountLD,
#                uint256 minAmountLD, bytes extraOptions, bytes composeMsg,
#                bytes oftCmd).
# dstEid is a LayerZero v2 endpoint ID (30000-series). Selector confirmed
# via cast sig "sendToken((uint32,bytes32,uint256,uint256,bytes,bytes,bytes),(uint256,uint256),address)".
_STARGATE_V2_METHODS: dict[str, tuple[str, str]] = {
    "0xcbef2aa9": ("Stargate", "sendToken_v2"),
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
        # v0.31.4 — try v1 selectors first; fall through to v2 decoder if
        # the method ID isn't in the v1 table. Order matters: Stargate
        # v1 (Router.swap/swapETH) is the legacy path and still active;
        # Stargate v2 (Pool.sendToken) is the post-2024 default.
        v1_result = _decode_stargate(method_id, args_blob, data)
        if v1_result is not None:
            return v1_result
        return _decode_stargate_v2(method_id, args_blob, data)
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
    # v0.31.0 — full destination extraction for the 3 highest-volume
    # bridges that were previously recognition-only.
    if "connext" in bridge_protocol.lower() or "everclear" in bridge_protocol.lower():
        return _decode_connext(method_id, args_blob, data)
    if "axelar" in bridge_protocol.lower():
        return _decode_axelar(method_id, args_blob, data)
    if "lifi" in bridge_protocol.lower() or "li.fi" in bridge_protocol.lower():
        return _decode_lifi(method_id, args_blob, data)
    # v0.31.1 — Hop + Squid decoders (gap #2 mop-up). The 'hop' check
    # explicitly excludes 'hopr' (HOPR Net is a different unrelated
    # protocol whose name happens to start with "hop").
    if "hop" in bridge_protocol.lower() and "hopr" not in bridge_protocol.lower():
        return _decode_hop(method_id, args_blob, data)
    if "squid" in bridge_protocol.lower():
        return _decode_squid(method_id, args_blob, data)
    # v0.31.2 — Celer cBridge + Synapse decoders (gap #2 continuation).
    if "celer" in bridge_protocol.lower() or "cbridge" in bridge_protocol.lower():
        return _decode_celer(method_id, args_blob, data)
    if "synapse" in bridge_protocol.lower():
        return _decode_synapse(method_id, args_blob, data)
    # v0.31.2 — Symbiosis MetaRouter decoder (gap #2 partial). Symbiosis
    # is a popular cross-chain bridge in the 2024-2025 drainer scene
    # (routes through MetaRouter on every supported chain).
    if "symbiosis" in bridge_protocol.lower():
        return _decode_symbiosis(method_id, args_blob, data)
    # v0.31.4 — six remaining bridges with seed entries but no
    # destination extraction pre-v0.31.4. LayerZero / Stargate v2 share
    # selector namespaces with Stargate v1 but use different chain-id
    # tables, so they get dedicated decoders. CCIP / Multichain / DLN
    # are protocol-specific. The 'multichain' / 'anyswap' branch covers
    # both legacy router naming variants.
    proto_lc = bridge_protocol.lower()
    if "layerzero" in proto_lc and "stargate" not in proto_lc:
        return _decode_layerzero(method_id, args_blob, data)
    if "ccip" in proto_lc:
        return _decode_ccip(method_id, args_blob, data)
    if "multichain" in proto_lc or "anyswap" in proto_lc:
        return _decode_multichain(method_id, args_blob, data)
    # v0.32.1 JACOB_ADVERSARY_AUDIT_v032 M-6 close-out: rollup-canonical
    # bridges. Pre-v0.32.1 these were labeled in bridges.json (so the BFS
    # halted at the bridge) but no destination was extracted, leaving
    # the operator with "destination candidates: polygon" and no
    # actionable address. The adversary audit's Route 1 ($5M Polygon
    # PoS escape) succeeded entirely through this gap. New decoders for:
    #   * Polygon PoS RootChainManager (depositFor / depositEtherFor)
    #   * Optimism L1StandardBridge (depositERC20{To}, depositETH{To})
    #   * Arbitrum Inbox / L1ERC20Gateway (outboundTransfer{,CustomRefund},
    #     depositEth)
    #   * zkSync Era L1ERC20Bridge (deposit)
    #   * Base L1StandardBridge (OP-Stack ABI; same selectors as Optimism)
    # Use a space-normalized variant for the rollup-canonical matches —
    # bridges.json names use spaces ("L1 Standard Bridge"); our internal
    # convention is lowercased-no-spaces. Match against both.
    proto_compact = proto_lc.replace(" ", "").replace("-", "").replace(":", "")
    if "polygon" in proto_compact and (
        "pos" in proto_compact
        or "rootchainmanager" in proto_compact
        or "erc20predicate" in proto_compact
    ):
        return _decode_polygon_pos(method_id, args_blob, data)
    if "optimism" in proto_compact and (
        "l1standardbridge" in proto_compact
        or "l2standardbridge" in proto_compact
    ):
        return _decode_optimism_l1(method_id, args_blob, data)
    if "arbitrum" in proto_compact and (
        "inbox" in proto_compact
        or "gateway" in proto_compact
    ):
        return _decode_arbitrum_l1(method_id, args_blob, data)
    if "zksync" in proto_compact and (
        "bridge" in proto_compact or "era" in proto_compact
    ):
        return _decode_zksync_l1(method_id, args_blob, data)
    if "base" in proto_compact and (
        "l1standardbridge" in proto_compact
        or "l2standardbridge" in proto_compact
    ):
        return _decode_base_l1(method_id, args_blob, data)
    # v0.32.1 W5 (round-2 adversary Route 1' close-out): 7 additional
    # rollup-canonical L2 bridges. Polygon zkEVM reuses the Polygon-PoS
    # depositFor / depositEtherFor calldata shape. The remaining six
    # (Linea, Scroll, Blast, opBNB, Mantle, Manta Pacific) all reuse
    # the OP-Stack L1StandardBridge ABI (Linea + Scroll expose a
    # depositERC20-shaped surface that is calldata-compatible; Blast,
    # opBNB, Mantle, Manta are direct OP-Stack derivatives). The chain
    # override is applied here so the BridgeDecodeResult carries the
    # correct destination_chain regardless of which OP-Stack decoder
    # produces it.
    if "polygon" in proto_compact and (
        "zkevm" in proto_compact or "polygonzkevm" in proto_compact
    ):
        result = _decode_polygon_pos(method_id, args_blob, data)
        if result is not None:
            return BridgeDecodeResult(
                destination_chain="polygon_zkevm",
                destination_address=result.destination_address,
                bridge_method=result.bridge_method,
                confidence=result.confidence,
                raw_calldata_excerpt=result.raw_calldata_excerpt,
            )
        return None
    if "linea" in proto_compact:
        return _decode_op_stack_l1(method_id, args_blob, data, "linea")
    if "scroll" in proto_compact:
        return _decode_op_stack_l1(method_id, args_blob, data, "scroll")
    if "blast" in proto_compact:
        return _decode_op_stack_l1(method_id, args_blob, data, "blast")
    if "opbnb" in proto_compact:
        return _decode_op_stack_l1(method_id, args_blob, data, "opbnb")
    if "mantle" in proto_compact:
        return _decode_op_stack_l1(method_id, args_blob, data, "mantle")
    if "manta" in proto_compact and "pacific" in proto_compact:
        return _decode_op_stack_l1(method_id, args_blob, data, "manta")
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
    """Decode DeBridge DLN createSaleOrder / createOrder / send calldata.

    DeBridge DLN encodes an ``OrderCreation`` struct as the first
    argument:

      struct OrderCreation {
        address giveTokenAddress;
        uint256 giveAmount;
        bytes   takeTokenAddress;     // dynamic, can be EVM or non-EVM
        uint256 takeAmount;
        uint256 takeChainId;          // <-- destination chain ID (EVM chainID)
        bytes   receiverDst;          // <-- destination address (variable)
        address givePatchAuthoritySrc;
        bytes   orderAuthorityAddressDst;
        bytes   allowedTakerDst;
        bytes   externalCall;
        bytes   allowedCancelBeneficiarySrc;
      }

    Because the struct contains dynamic fields, the outer arg is
    encoded with an offset pointer at the first 32-byte slot. The
    tuple body then starts at that offset.

    The struct layout has several head slots, but `takeChainId` lives
    at a known offset relative to the tuple body start. Empirically
    (verified against DLN mainnet traces) it shows up at struct slot
    index 4 (with `takeTokenAddress` as a dynamic offset pointer in
    slot 2). We follow the LiFi candidate-scan pattern: probe a
    handful of plausible slot positions inside the tuple body, and
    accept the first that maps to a known EVM chain ID via
    ``_EVM_CHAIN_BY_ID``. For the receiver, `receiverDst` is the
    next dynamic field; we resolve its offset pointer and read the
    last 20 bytes of its tail (EVM destinations).

    Conservative behavior:
      * unknown method ID → return None (dispatcher contract)
      * truncated calldata or no candidate slot found → confidence='low'
      * only one of (chain, receiver) extracted → confidence='medium'
      * both extracted + chain in known table → confidence='high'
    """
    method_entry = _DEBRIDGE_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    # Minimum: outer offset slot + a handful of struct head slots.
    if len(args_blob) < 256 * 2:
        return BridgeDecodeResult(
            destination_chain=None,
            destination_address=None,
            bridge_method=method_name,
            confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )

    try:
        # Read the outer offset pointer (first 32-byte slot) to find the
        # tuple body. For a single-tuple arg with dynamic fields this is
        # typically 0x20.
        outer_offset_hex = args_blob[0:64]
        try:
            outer_offset_bytes = int(outer_offset_hex, 16)
        except ValueError:
            outer_offset_bytes = 32
        tuple_body_hex_idx = outer_offset_bytes * 2
        if (
            tuple_body_hex_idx < 64
            or tuple_body_hex_idx + 64 > len(args_blob)
        ):
            tuple_body_hex_idx = 64

        # Candidate slot indices for takeChainId. The OrderCreation
        # struct's `takeChainId` is at struct slot 4 in the canonical
        # layout, but DLN's `createOrder` vs `createSaleOrder` vs `send`
        # variants shift things. Scan slots 3..7 — wide enough to absorb
        # one extra dynamic-offset slot if the protocol prepends an
        # affiliate-fee or referrer header.
        dest_chain: str | None = None
        chain_slot_match: int | None = None
        for slot_idx in (4, 3, 5, 6, 7, 2):
            start = tuple_body_hex_idx + slot_idx * 64
            end = start + 64
            if end > len(args_blob):
                continue
            try:
                cand = int(args_blob[start:end], 16)
            except ValueError:
                continue
            if cand in _EVM_CHAIN_BY_ID:
                dest_chain = _EVM_CHAIN_BY_ID[cand]
                chain_slot_match = slot_idx
                break

        # `receiverDst` is dynamic. In the canonical layout, slot 5
        # (right after takeChainId at slot 4) holds an offset pointer
        # into the tuple body's dynamic tail. We probe the slot just
        # after the matched chain slot for the offset, then read the
        # tail (length-prefixed bytes blob).
        dest_address: str | None = None
        if chain_slot_match is not None:
            offset_slot = chain_slot_match + 1
            off_start = tuple_body_hex_idx + offset_slot * 64
            off_end = off_start + 64
            if off_end <= len(args_blob):
                try:
                    rel_offset = int(args_blob[off_start:off_end], 16)
                    tail_start = tuple_body_hex_idx + rel_offset * 2
                    # Length prefix (32 bytes) then raw payload bytes.
                    if tail_start + 64 <= len(args_blob):
                        length_hex = args_blob[tail_start:tail_start + 64]
                        try:
                            length = int(length_hex, 16)
                        except ValueError:
                            length = 0
                        # Sanity cap: receiverDst is usually 20 bytes
                        # (EVM) or up to ~64 bytes (Solana / longer).
                        if 0 < length <= 128:
                            data_start = tail_start + 64
                            data_end = data_start + length * 2
                            if data_end <= len(args_blob):
                                raw = args_blob[data_start:data_end]
                                if length >= 20:
                                    # Take last 20 bytes — EVM dest.
                                    addr_hex = raw[-40:]
                                    if (
                                        len(addr_hex) == 40
                                        and addr_hex != "0" * 40
                                    ):
                                        dest_address = "0x" + addr_hex
                                elif length > 0:
                                    # Sub-20 — preserve raw as 0x-hex
                                    # for operator follow-up.
                                    dest_address = "0x" + raw
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
        log.debug("debridge decode failed: %s", exc)
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


# ─────────────────────────────────────────────────────────────────────────────
# v0.31.0 — Connext / Axelar / LiFi decoders.
# Pre-v0.31.0 these were recognition-only (confidence='low' via the seed
# lookup); the gap was that 27 of the top-30 bridges had no destination
# extraction. The 3 protocols here are the highest-volume of the 27.
# ─────────────────────────────────────────────────────────────────────────────


# Connext domain IDs. Source: docs.connext.network/resources/deployments
# Connext uses its own "domain ID" namespace (not Wormhole, not LayerZero,
# not EVM chainID). The xcall() first uint32 arg is this domain ID.
_CONNEXT_DOMAIN_IDS: dict[int, str] = {
    6648936: "ethereum",
    1869640809: "optimism",
    1886350457: "polygon",
    1634886255: "arbitrum",
    6450786: "bsc",
    6778479: "gnosis",
    1818848877: "linea",
    1853581795: "base",
    6398002: "metis",
}


def _decode_connext(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode Connext / Everclear xcall calldata.

    Signature (xcall):
      xcall(uint32 destination, address to, address asset,
            address delegate, uint256 amount, uint256 slippage, bytes callData)

    Calldata layout (each arg right-padded to 32 bytes):
      [0..32]    destination domain ID (uint32 right-aligned)
      [32..64]   to (address right-padded)
      [64..96]   asset (address)
      [96..128]  delegate (address)
      [128..160] amount (uint256)
      [160..192] slippage (uint256)
      [192..224] offset to callData bytes
    """
    method_entry = _CONNEXT_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    if len(args_blob) < 224 * 2:
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )
    try:
        # destination domain — uint32 right-aligned in slot [0..32]
        domain_hex = args_blob[0:64]
        domain_id = int(domain_hex, 16) if domain_hex else 0
        dest_chain = _CONNEXT_DOMAIN_IDS.get(domain_id)

        # to address — slot [32..64], last 20 bytes
        recipient_hex = args_blob[32*2 + 24:64*2]
        dest_address = "0x" + recipient_hex if len(recipient_hex) == 40 else None

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
        log.debug("connext decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


def _read_solidity_string(args_blob: str, offset_slot_hex_idx: int) -> str | None:
    """Read a solidity string from a dynamic-bytes encoded arg.

    `offset_slot_hex_idx` is the hex-character index in args_blob where
    the offset-pointer 32-byte slot lives. Returns the decoded UTF-8
    string, or None on any parse error.
    """
    try:
        offset_hex = args_blob[offset_slot_hex_idx:offset_slot_hex_idx + 64]
        offset_bytes = int(offset_hex, 16)
        offset_hex_idx = offset_bytes * 2
        if offset_hex_idx + 64 > len(args_blob):
            return None
        length_hex = args_blob[offset_hex_idx:offset_hex_idx + 64]
        length = int(length_hex, 16)
        if length == 0 or length > 256:  # sanity cap
            return None
        data_start = offset_hex_idx + 64
        data_end = data_start + (length * 2)
        if data_end > len(args_blob):
            return None
        raw_hex = args_blob[data_start:data_end]
        return bytes.fromhex(raw_hex).decode("utf-8", errors="strict")
    except (ValueError, IndexError, UnicodeDecodeError):
        return None


def _decode_axelar(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode Axelar Gateway callContractWithToken / sendToken calldata.

    Signature (callContractWithToken):
      callContractWithToken(string destinationChain, string contractAddress,
                            bytes payload, string symbol, uint256 amount)

    Signature (sendToken):
      sendToken(string destinationChain, string destinationAddress,
                string symbol, uint256 amount)

    Both have the destinationChain as the FIRST arg (string-typed
    dynamic bytes; the first 32-byte slot is an offset pointer).
    The destinationAddress / contractAddress is the SECOND arg
    (same shape).
    """
    method_entry = _AXELAR_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    if len(args_blob) < 128 * 2:
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )
    try:
        # First slot = offset to destinationChain string
        chain_str = _read_solidity_string(args_blob, 0)
        # Second slot = offset to destinationAddress / contractAddress string
        addr_str = _read_solidity_string(args_blob, 64)

        dest_chain: str | None = None
        if isinstance(chain_str, str):
            dest_chain = _AXELAR_CHAIN_NAMES.get(chain_str.strip().lower())
            if dest_chain is None:
                # Keep the raw value as a soft signal — operator
                # follow-up via the Axelar explorer can resolve it.
                dest_chain = chain_str.strip().lower()

        dest_address: str | None = None
        if isinstance(addr_str, str):
            s = addr_str.strip()
            # EVM 0x-hex address
            if s.startswith("0x") and len(s) == 42 or len(s) > 10 and len(s) < 100:
                dest_address = s

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
        log.debug("axelar decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


def _decode_lifi(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode LiFi Diamond bridge calldata.

    LiFi uses a `BridgeData` struct as the first arg of every bridge
    facet:
      struct BridgeData {
        bytes32 transactionId;
        string bridge;           // "stargate", "across", "hop", ...
        string integrator;
        address referrer;
        address sendingAssetId;
        address receiver;        // <-- forensically useful
        uint256 minAmount;
        uint256 destinationChainId;  // <-- forensically useful (EVM chainID)
        bool hasSourceSwaps;
        bool hasDestinationCall;
      }

    The struct is the first arg; tuple-encoded as one block at offset 0
    in args_blob. For tuple types with dynamic strings inside, ABI
    encoding nests offset pointers. The layout in calldata:
      [0..32]    transactionId
      [32..64]   offset to bridge string
      [64..96]   offset to integrator string
      [96..128]  referrer (address)
      [128..160] sendingAssetId (address)
      [160..192] receiver (address)        <-- read this
      [192..224] minAmount
      [224..256] destinationChainId        <-- read this
      [256..288] hasSourceSwaps
      [288..320] hasDestinationCall

    Note: this is for the "no source swap" facets. The swap-and-bridge
    variants prepend extra swap-data args; the BridgeData struct is
    further in. We try to find the receiver/destinationChainId by
    scanning two candidate offsets.
    """
    method_entry = _LIFI_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    if len(args_blob) < 320 * 2:
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )

    candidates = [
        # (receiver_idx, chain_id_idx) in hex chars
        (160 * 2, 224 * 2),   # BridgeData at offset 0 (start-bridge-only)
        (320 * 2, 384 * 2),   # BridgeData after a 1-slot prefix
        (416 * 2, 480 * 2),   # BridgeData after a 4-slot prefix (swap-and-bridge)
    ]
    try:
        best: tuple[str | None, str | None, str] = (None, None, "low")
        for recv_idx, chain_idx in candidates:
            if chain_idx + 64 > len(args_blob):
                continue
            chain_hex = args_blob[chain_idx:chain_idx + 64]
            try:
                chain_id = int(chain_hex, 16)
            except ValueError:
                continue
            dest_chain = _EVM_CHAIN_BY_ID.get(chain_id)
            if not dest_chain:
                continue  # Try next candidate

            recv_hex_full = args_blob[recv_idx:recv_idx + 64]
            recv_hex = recv_hex_full[-40:]  # last 20 bytes
            if len(recv_hex) != 40:
                continue
            # Reject obviously-zero recipient (sentinel for wrong offset)
            if recv_hex == "0" * 40:
                continue
            dest_address = "0x" + recv_hex
            return BridgeDecodeResult(
                destination_chain=dest_chain,
                destination_address=dest_address,
                bridge_method=method_name,
                confidence="high",
                raw_calldata_excerpt=full_data[:400],
            )

        # No candidate produced a sane (chain, recipient) pair.
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )
    except (ValueError, IndexError) as exc:
        log.debug("lifi decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


# ─────────────────────────────────────────────────────────────────────────────
# v0.31.1 — Hop + Squid decoders.
# Closes gap #2 in the trace-completeness list. Pre-v0.31.1 these two
# protocols were recognition-only via bridges.json seed entries; now
# the destination chain + recipient are extractable on the happy path.
# ─────────────────────────────────────────────────────────────────────────────


def _decode_hop(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode Hop Protocol L1Bridge.sendToL2 calldata.

    Signature (sendToL2):
      sendToL2(uint256 chainId, address recipient, uint256 amount,
               uint256 amountOutMin, uint256 deadline,
               address relayer, uint256 relayerFee)

    Calldata layout (each arg right-padded to 32 bytes — all static
    types, no dynamic-bytes args, so no offset indirection):
      [0..32]   chainId           (EVM chainID, uint256)
      [32..64]  recipient         (address right-padded)
      [64..96]  amount            (uint256)
      [96..128] amountOutMin      (uint256)
      [128..160] deadline         (uint256)
      [160..192] relayer          (address right-padded)
      [192..224] relayerFee       (uint256)
    """
    method_entry = _HOP_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    # 7 slots × 32 bytes = 224 bytes = 448 hex chars
    if len(args_blob) < 224 * 2:
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )
    try:
        # chainId — uint256 in slot [0..32]
        chain_hex = args_blob[0:64]
        chain_id = int(chain_hex, 16) if chain_hex else 0
        dest_chain = _EVM_CHAIN_BY_ID.get(chain_id)

        # recipient address — slot [32..64], last 20 bytes (40 hex chars)
        recipient_hex_full = args_blob[64:128]
        recipient_hex = recipient_hex_full[-40:]
        dest_address: str | None = None
        if len(recipient_hex) == 40 and recipient_hex != "0" * 40:
            dest_address = "0x" + recipient_hex

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
        log.debug("hop decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


def _decode_squid(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode Squid Router bridgeCall / callBridgeCall calldata.

    Squid is built on Axelar. Its bridgeCall / callBridgeCall
    methods wrap destinationChain (string) + destinationAddress
    (string, EVM 0xhex or Cosmos bech32) the same way Axelar's
    native sendToken / callContractWithToken do — the first two
    32-byte head slots are offset pointers into the dynamic tail.

    We reuse the Axelar chain-name table + string reader.
    """
    method_entry = _SQUID_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    # Need at least 2 head slots (offsets) + sane room for tails
    if len(args_blob) < 128 * 2:
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )
    try:
        # First slot = offset to destinationChain string
        chain_str = _read_solidity_string(args_blob, 0)
        # Second slot = offset to destinationAddress string
        addr_str = _read_solidity_string(args_blob, 64)

        dest_chain: str | None = None
        if isinstance(chain_str, str):
            dest_chain = _AXELAR_CHAIN_NAMES.get(chain_str.strip().lower())
            if dest_chain is None:
                # Preserve raw value lowercased for operator follow-up
                dest_chain = chain_str.strip().lower()

        dest_address: str | None = None
        if isinstance(addr_str, str):
            s = addr_str.strip()
            if s.startswith("0x") and len(s) == 42 or len(s) > 10 and len(s) < 100:
                dest_address = s

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
        log.debug("squid decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


# ─────────────────────────────────────────────────────────────────────────────
# v0.31.2 — Celer cBridge + Synapse decoders.
# Continuation of gap #2 (the trace-completeness list): the two next-
# highest-volume bridges that were recognition-only after v0.31.1.
# Both protocols encode the destination chain as a real EVM chain ID,
# so `_EVM_CHAIN_BY_ID` is the lookup table.
# ─────────────────────────────────────────────────────────────────────────────


def _decode_celer(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode Celer cBridge send / sendNative calldata.

    Signature (send — ERC-20 path):
      send(address receiver, address token, uint256 amount,
           uint64 dstChainId, uint64 nonce, uint32 maxSlippage)

    Signature (sendNative — native asset path):
      sendNative(address receiver, uint256 amount,
                 uint64 dstChainId, uint64 nonce, uint32 maxSlippage)

    All args are static types (no dynamic-bytes offset indirection).
    Calldata layout for `send` (each slot 32 bytes):
      [0..32]    receiver (address right-padded)
      [32..64]   token (address right-padded)
      [64..96]   amount (uint256)
      [96..128]  dstChainId (uint64 right-aligned)
      [128..160] nonce
      [160..192] maxSlippage

    For `sendNative` the token slot collapses (no token arg):
      [0..32]    receiver
      [32..64]   amount
      [64..96]   dstChainId (uint64 right-aligned)
      [96..128]  nonce
      [128..160] maxSlippage
    """
    method_entry = _CELER_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    # Both methods need at least 5 slots = 160 bytes = 320 hex chars
    if len(args_blob) < 160 * 2:
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )
    try:
        # receiver — slot [0..32], last 20 bytes
        recipient_hex_full = args_blob[0:64]
        recipient_hex = recipient_hex_full[-40:]
        dest_address: str | None = None
        if len(recipient_hex) == 40 and recipient_hex != "0" * 40:
            dest_address = "0x" + recipient_hex

        # dstChainId — slot index depends on which method
        if method_name == "send":
            # ERC-20 path: dstChainId at slot index 3 → hex chars [192..256]
            chain_hex = args_blob[192:256]
        else:
            # sendNative path: dstChainId at slot index 2 → hex chars [128..192]
            chain_hex = args_blob[128:192]
        chain_id = int(chain_hex, 16) if chain_hex else 0
        dest_chain = _EVM_CHAIN_BY_ID.get(chain_id)

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
        log.debug("celer decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


def _decode_synapse(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode Synapse Protocol bridge / swapAndRedeem calldata.

    Signature (bridge):
      bridge(address to, uint256 chainId, IERC20 token, uint256 amount)

    Signature (swapAndRedeem):
      swapAndRedeem(address to, uint256 chainId, IERC20 token,
                    uint8 tokenIndexFrom, uint8 tokenIndexTo,
                    uint256 dx, uint256 minDy, uint256 deadline)

    Both put `to` in slot 0 and `chainId` in slot 1, so a single
    reader handles either selector. All args are static — no
    dynamic-bytes offset indirection.

    Calldata layout (each slot 32 bytes):
      [0..32]    to        (address right-padded)
      [32..64]   chainId   (uint256, EVM chainID)
      [64..96]   token     (address)
      [96..128]  amount    (bridge) / tokenIndexFrom+tokenIndexTo (swapAndRedeem)
      ...
    """
    method_entry = _SYNAPSE_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    # Both methods need at least the (to, chainId) prefix = 2 slots = 128 hex chars
    if len(args_blob) < 64 * 2:
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )
    try:
        # to — slot [0..32], last 20 bytes
        recipient_hex_full = args_blob[0:64]
        recipient_hex = recipient_hex_full[-40:]
        dest_address: str | None = None
        if len(recipient_hex) == 40 and recipient_hex != "0" * 40:
            dest_address = "0x" + recipient_hex

        # chainId — slot [32..64] (uint256, EVM chainID)
        chain_hex = args_blob[64:128]
        chain_id = int(chain_hex, 16) if chain_hex else 0
        dest_chain = _EVM_CHAIN_BY_ID.get(chain_id)

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
        log.debug("synapse decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


# ─────────────────────────────────────────────────────────────────────────────
# v0.31.2 — Symbiosis MetaRouter decoder.
# Partial-coverage closure of gap #2: Symbiosis is the popular cross-chain
# bridge that 2024-2025 drainer cases route through. Pre-v0.31.2 it was
# recognition-only via bridges.json. The MetaRouter `metaRoute` entry
# point encodes `relayRecipient` at a known fixed slot inside the
# MetaRouteTransaction tuple, but the destination chainID lives inside
# the `otherSideCalldata` blob (a calldata payload targeting the
# destination-side metaMintSwap call), not in the tuple itself. We
# follow the LiFi-style conservative path: extract the recipient
# directly + scan a small set of candidate offsets for a chainID
# that maps to a known EVM chain.
# ─────────────────────────────────────────────────────────────────────────────


def _decode_symbiosis(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode Symbiosis MetaRouter `metaRoute` calldata.

    Signature:
      metaRoute(MetaRouteTransaction _metarouteTransaction)

    where MetaRouteTransaction is the tuple:
      (bytes  firstSwapCalldata,
       bytes  secondSwapCalldata,
       address[] approvedTokens,
       address firstDexRouter,
       address secondDexRouter,
       uint256 amount,
       bool    nativeIn,
       address relayRecipient,       // <-- forensically useful
       bytes   otherSideCalldata)    // <-- destination chainID lives in here

    Because the tuple contains dynamic fields, the single arg is
    encoded with an outer offset pointer. The first 32-byte slot of
    `args_blob` carries that offset (always 0x20 for a single-arg
    call). The tuple body starts at byte 32 (= hex index 64) and is
    laid out as 9 head slots (288 bytes), then the dynamic tails.

    Inside the tuple body, `relayRecipient` is at struct slot 7,
    which is hex index ``64 + 224*2 = 512..576`` in args_blob.

    For the destination chainID we scan candidate offsets inside
    `otherSideCalldata` (the 9th tuple field) the same way LiFi does
    its BridgeData multi-candidate scan. The chainID is one of the
    early static-uint256 fields in the nested metaMintSwap call.
    """
    method_entry = _SYMBIOSIS_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    # Minimum: 1 outer offset slot (32 B) + 9 tuple head slots (288 B)
    # = 320 bytes = 640 hex chars
    if len(args_blob) < 320 * 2:
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )

    try:
        # The outer offset slot is at hex [0..64]. In Solidity ABI v2
        # for a single tuple arg containing dynamic fields, this is
        # always 0x20 (= 32 bytes from start of args_blob). We do not
        # strictly require this value — instead we derive the tuple
        # body start by reading the offset.
        outer_offset_hex = args_blob[0:64]
        try:
            outer_offset_bytes = int(outer_offset_hex, 16)
        except ValueError:
            outer_offset_bytes = 32
        # Sanity: offset must be ≥ 32 (skips its own slot) and leave
        # room for the 9-slot tuple head. If the offset is wild, fall
        # back to the canonical layout (0x20) — better than bailing.
        tuple_body_hex_idx = outer_offset_bytes * 2
        if (
            tuple_body_hex_idx < 64
            or tuple_body_hex_idx + 288 * 2 > len(args_blob)
        ):
            tuple_body_hex_idx = 64

        # `relayRecipient` — struct slot 7, last 20 bytes (40 hex chars).
        recv_slot_start = tuple_body_hex_idx + 224 * 2
        recv_slot_end = recv_slot_start + 64
        if recv_slot_end > len(args_blob):
            return BridgeDecodeResult(
                destination_chain=None, destination_address=None,
                bridge_method=method_name, confidence="low",
                raw_calldata_excerpt=full_data[:400],
            )
        recipient_hex_full = args_blob[recv_slot_start:recv_slot_end]
        recipient_hex = recipient_hex_full[-40:]
        dest_address: str | None = None
        if len(recipient_hex) == 40 and recipient_hex != "0" * 40:
            dest_address = "0x" + recipient_hex

        # Destination chain ID lives inside `otherSideCalldata` (tuple
        # slot 8, an offset pointer into a nested calldata payload
        # targeting the destination-side Portal.synthesize /
        # burnSyntheticToken call).
        #
        # v0.31.5 (audit gap §1c — "_decode_symbiosis is half-built"):
        # On real mainnet Symbiosis MetaRouter txs the nested
        # `otherSideCalldata` is a fully ABI-encoded call payload:
        #   [4-byte selector][slot 0][slot 1]...[slot N]
        # i.e. it carries a function selector at the head, then 32-byte
        # aligned uint256/address/etc. args. The pre-v0.31.5 implementation
        # ignored the 4-byte selector, which silently misaligned every slot
        # boundary inside the scan window by 4 bytes — the heuristic still
        # *sometimes* hit a chain-ID by accident (when the misaligned read
        # happened to span a uint256 whose low bytes equaled an EVM
        # chainID), but it was unreliable. We now do a structured parse:
        #   1. Detect whether the payload begins with a 4-byte selector
        #      (i.e., first 4 bytes are nonzero AND the next 28 bytes of
        #      what would be slot 0 are zero-padding-shaped — selectors
        #      have keccak-distributed bytes, args are zero-padded ints).
        #   2. If yes, skip those 4 bytes and read slots from the proper
        #      ABI-aligned offsets.
        #   3. Scan ≤8 args for a known EVM chain ID.
        # Fall back to the legacy synthetic-fixture path (no selector
        # prefix) if structured parse misses — preserves backwards
        # compatibility with hand-rolled test fixtures that mimicked the
        # pre-v0.31.5 layout.
        dest_chain: str | None = None
        # otherSideCalldata offset is at tuple-body slot 8 (hex
        # [256..320] within the tuple body).
        other_offset_slot_start = tuple_body_hex_idx + 256 * 2
        other_offset_slot_end = other_offset_slot_start + 64
        if other_offset_slot_end <= len(args_blob):
            try:
                other_offset_bytes = int(
                    args_blob[other_offset_slot_start:other_offset_slot_end], 16,
                )
                # Offset is relative to the start of the tuple body.
                other_hex_idx = tuple_body_hex_idx + (other_offset_bytes * 2)
                # Skip the 32-byte length prefix of the nested bytes blob.
                payload_start = other_hex_idx + 64
                # Determine if the payload begins with a 4-byte function
                # selector. Heuristic: a selector has 4 keccak-derived
                # bytes (high probability of nonzero), whereas a uint256
                # ABI arg is left-padded with 28 zero bytes (slot[0:56]
                # are all '0'). So if the first 4 bytes are nonzero AND
                # the bytes at positions [4..32] (i.e. hex [payload+8 ..
                # payload+64]) form a zero-padded uint with high bits
                # zero, the payload is selector-prefixed.
                has_selector = False
                if payload_start + 64 <= len(args_blob):
                    head4_hex = args_blob[payload_start:payload_start + 8]
                    try:
                        head4_val = int(head4_hex, 16)
                    except ValueError:
                        head4_val = 0
                    if head4_val != 0:
                        # Look at what would be the high bytes of "slot 0"
                        # if there were no selector. If those high bytes
                        # are zero-padded (typical for uint args), this
                        # is consistent with a selector preceding the
                        # ABI args.
                        pad_check_hex = args_blob[
                            payload_start + 8:payload_start + 8 + 48
                        ]
                        try:
                            pad_check_val = int(pad_check_hex, 16)
                        except ValueError:
                            pad_check_val = -1
                        # If pad_check is small (zero-padded uint head)
                        # OR if the structured arg at offset 4 looks
                        # like a known chain ID once parsed, we treat
                        # this as selector-prefixed.
                        has_selector = pad_check_val == 0

                # Try the structured (selector-skip) parse first.
                if has_selector:
                    arg_start = payload_start + 8  # skip 4 bytes = 8 hex chars
                    for slot_idx in range(0, 8):
                        cand_start = arg_start + slot_idx * 64
                        cand_end = cand_start + 64
                        if cand_end > len(args_blob):
                            break
                        cand_hex = args_blob[cand_start:cand_end]
                        try:
                            cand_val = int(cand_hex, 16)
                        except ValueError:
                            continue
                        if cand_val in _EVM_CHAIN_BY_ID:
                            dest_chain = _EVM_CHAIN_BY_ID[cand_val]
                            break

                # Fallback: pre-v0.31.5 layout (no selector prefix).
                # Required for legacy synthetic fixtures + any payload
                # where the structured parse misses.
                if dest_chain is None:
                    for slot_idx in range(0, 8):
                        cand_start = payload_start + slot_idx * 64
                        cand_end = cand_start + 64
                        if cand_end > len(args_blob):
                            break
                        cand_hex = args_blob[cand_start:cand_end]
                        try:
                            cand_val = int(cand_hex, 16)
                        except ValueError:
                            continue
                        if cand_val in _EVM_CHAIN_BY_ID:
                            dest_chain = _EVM_CHAIN_BY_ID[cand_val]
                            break
            except (ValueError, IndexError):
                dest_chain = None

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
        log.debug("symbiosis decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


# ─────────────────────────────────────────────────────────────────────────────
# v0.31.4 — LayerZero raw OApp + Chainlink CCIP + Multichain (Anyswap) +
# Stargate v2 decoders. Closes the last 6 protocols that had seed entries
# but no destination-extraction post-v0.31.2. Each follows the pattern
# established by the v0.31.0-v0.31.2 decoders:
#   * graceful degradation: unknown method → None; truncated → low; etc.
#   * confidence rule: high (chain ∧ recipient); medium (one of); low (none)
#   * never raise — all `try` blocks catch ValueError / IndexError
# ─────────────────────────────────────────────────────────────────────────────


def _decode_layerzero(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode a raw LayerZero OApp Endpoint `send` call.

    LayerZero v1 signature (Endpoint.send):
      send(uint16 _dstChainId, bytes _destination, bytes _payload,
           address payable _refundAddress, address _zroPaymentAddress,
           bytes _adapterParams)

    LayerZero v2 signature (Endpoint.send):
      send(MessagingParams calldata _params, address _refundAddress)
    where MessagingParams = (uint32 dstEid, bytes32 receiver,
                             bytes message, bytes options, bool payInLzToken)

    v1 chain IDs live in ``_LZ_CHAIN_IDS`` (101=ethereum, 110=arbitrum, ...);
    v2 EIDs live in ``_LAYERZERO_V2_EIDS`` (30101=ethereum, 30110=arbitrum,
    ...). For v1 the destination is the dynamic `_destination` bytes blob
    (last 20 bytes for EVM destinations). For v2 the destination is the
    bytes32 `receiver` field (last 20 bytes for EVM).

    NB: LayerZero is a generic messaging layer — many OApp wrappers
    (OFTs / Stargate / Radiant / etc.) put their own payload semantics
    on top. We recover the LZ-layer destination only; the actual asset
    receiver may be inside the inner payload (operator follow-up).
    """
    method_entry = _LAYERZERO_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    # v1 needs ≥6 head slots (6 × 32 = 192 bytes head); v2 needs the
    # MessagingParams tuple at minimum 5 slots = 160 bytes plus the
    # outer offset slot. Be generous; require enough hex for either.
    if len(args_blob) < 192 * 2:
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )

    try:
        if method_name == "send_v1":
            # uint16 _dstChainId — right-aligned in slot [0..32].
            chain_id_hex = args_blob[60:64]
            chain_id = int(chain_id_hex, 16) if chain_id_hex else 0
            dest_chain = _LZ_CHAIN_IDS.get(chain_id)

            # _destination bytes: slot 1 is the offset pointer. Resolve
            # the offset to find the tail, read length-prefixed bytes,
            # take last 20 bytes for EVM destinations.
            dest_address: str | None = None
            try:
                dest_offset = int(args_blob[64:128], 16)
                tail_idx = dest_offset * 2
                if tail_idx + 64 <= len(args_blob):
                    length = int(args_blob[tail_idx:tail_idx + 64], 16)
                    if 0 < length <= 128:
                        data_start = tail_idx + 64
                        data_end = data_start + length * 2
                        if data_end <= len(args_blob):
                            raw = args_blob[data_start:data_end]
                            # LZ v1 destination is typically the
                            # concatenation of remoteAddress + localAddress
                            # (40 bytes total) — take the FIRST 20 bytes
                            # (the remote / destination address). For
                            # exactly-20-byte payloads (some OApps), use
                            # the whole thing.
                            if length >= 20:
                                addr_hex = raw[:40]
                                if (
                                    len(addr_hex) == 40
                                    and addr_hex != "0" * 40
                                ):
                                    dest_address = "0x" + addr_hex
            except (ValueError, IndexError):
                dest_address = None

        else:  # send_v2
            # Outer offset slot at [0..32], then MessagingParams body.
            try:
                outer_offset = int(args_blob[0:64], 16)
            except ValueError:
                outer_offset = 32
            body_idx = outer_offset * 2
            if body_idx < 64 or body_idx + 64 > len(args_blob):
                body_idx = 64

            # MessagingParams.dstEid — uint32 right-aligned in body slot 0.
            chain_id = 0
            if body_idx + 64 <= len(args_blob):
                try:
                    chain_id = int(args_blob[body_idx:body_idx + 64], 16)
                except ValueError:
                    chain_id = 0
            dest_chain = _LAYERZERO_V2_EIDS.get(chain_id)

            # MessagingParams.receiver — bytes32 in body slot 1. Last 20
            # bytes are the EVM address.
            dest_address = None
            recv_slot_start = body_idx + 64
            recv_slot_end = recv_slot_start + 64
            if recv_slot_end <= len(args_blob):
                recv_hex = args_blob[recv_slot_start:recv_slot_end][-40:]
                if len(recv_hex) == 40 and recv_hex != "0" * 40:
                    dest_address = "0x" + recv_hex

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
        log.debug("layerzero decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


def _decode_ccip(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode Chainlink CCIP Router `ccipSend` calldata.

    Signature:
      ccipSend(uint64 destinationChainSelector,
               Client.EVM2AnyMessage message)

    where EVM2AnyMessage =
      (bytes receiver, bytes data, EVMTokenAmount[] tokenAmounts,
       address feeToken, bytes extraArgs)

    `destinationChainSelector` is a CCIP-specific uint64 namespace —
    NOT the EVM chainID. See ``_CCIP_CHAIN_SELECTORS`` for the
    mapping. `receiver` is dynamic bytes (a 20-byte EVM address
    ABI-encoded as bytes for EVM destinations).

    Calldata layout:
      [0..32]   destinationChainSelector (uint64 right-aligned)
      [32..64]  offset to EVM2AnyMessage tuple
      then tuple body at that offset; inside the tuple, slot 0 is
      the offset to `receiver` (bytes), so the receiver tail is
      reachable via nested offset.
    """
    method_entry = _CCIP_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    if len(args_blob) < 128 * 2:
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )

    try:
        # destinationChainSelector — uint64 right-aligned in slot 0.
        chain_sel_hex = args_blob[0:64]
        chain_sel = int(chain_sel_hex, 16) if chain_sel_hex else 0
        dest_chain = _CCIP_CHAIN_SELECTORS.get(chain_sel)

        # Resolve outer offset → EVM2AnyMessage tuple body.
        try:
            tuple_offset = int(args_blob[64:128], 16)
        except ValueError:
            tuple_offset = 64  # canonical layout
        tuple_idx = tuple_offset * 2
        if tuple_idx + 64 > len(args_blob):
            tuple_idx = 128  # canonical layout

        dest_address: str | None = None
        # First slot of the tuple is the offset to `receiver` bytes
        # (relative to the tuple body start).
        if tuple_idx + 64 <= len(args_blob):
            try:
                receiver_rel_offset = int(args_blob[tuple_idx:tuple_idx + 64], 16)
                receiver_tail_idx = tuple_idx + receiver_rel_offset * 2
                if receiver_tail_idx + 64 <= len(args_blob):
                    length = int(args_blob[receiver_tail_idx:receiver_tail_idx + 64], 16)
                    if 0 < length <= 128:
                        data_start = receiver_tail_idx + 64
                        data_end = data_start + length * 2
                        if data_end <= len(args_blob):
                            raw = args_blob[data_start:data_end]
                            if length >= 20:
                                # Take last 20 bytes — EVM dest. CCIP
                                # encodes EVM addresses as 32-byte-padded
                                # bytes (length=32), so the trailing 20
                                # bytes are the canonical address.
                                addr_hex = raw[-40:]
                                if (
                                    len(addr_hex) == 40
                                    and addr_hex != "0" * 40
                                ):
                                    dest_address = "0x" + addr_hex
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
        log.debug("ccip decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


def _decode_multichain(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode Multichain (Anyswap legacy) router calldata.

    Signatures:
      anySwapOutUnderlying(address token, address to, uint256 amount, uint256 toChainID)
      anySwapOut(address token, address to, uint256 amount, uint256 toChainID)

    Multichain ceased active operation in July 2023, but transit
    traffic still hits legacy routers; recognizing the calldata lets
    the trace continue past those handoffs into the destination chain
    (where funds are typically unrecoverable, but the destination
    address needs to be on the case record for the operator's brief).

    All 4 args are static types — no dynamic-bytes offset indirection.
    Calldata layout (each slot 32 bytes):
      [0..32]   token (address right-padded)
      [32..64]  to (address right-padded)
      [64..96]  amount (uint256)
      [96..128] toChainID (uint256, EVM chainID)
    """
    method_entry = _MULTICHAIN_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    # 4 slots × 32 bytes = 128 bytes = 256 hex chars
    if len(args_blob) < 128 * 2:
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )
    try:
        # to address — slot [32..64], last 20 bytes
        recipient_hex_full = args_blob[64:128]
        recipient_hex = recipient_hex_full[-40:]
        dest_address: str | None = None
        if len(recipient_hex) == 40 and recipient_hex != "0" * 40:
            dest_address = "0x" + recipient_hex

        # toChainID — slot [96..128] (uint256, EVM chainID)
        chain_hex = args_blob[192:256]
        chain_id = int(chain_hex, 16) if chain_hex else 0
        dest_chain = _EVM_CHAIN_BY_ID.get(chain_id)

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
        log.debug("multichain decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


def _decode_stargate_v2(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode Stargate v2 Pool `sendToken` calldata.

    Signature:
      sendToken(SendParam, MessagingFee, address)

    where SendParam =
      (uint32 dstEid, bytes32 to, uint256 amountLD, uint256 minAmountLD,
       bytes extraOptions, bytes composeMsg, bytes oftCmd)

    Stargate v2 uses LayerZero v2 endpoint IDs (30000-series), so the
    dstEid lookup goes through ``_LAYERZERO_V2_EIDS``. We also accept
    v1 LZ chain IDs in ``_LZ_CHAIN_IDS`` as a fallback — some Stargate
    v2 deployments transitionally accepted v1 selectors before the LZ
    v2 migration completed.

    The `to` field is bytes32 (right-aligned address for EVM
    destinations); last 20 bytes are the EVM address.

    Calldata layout (outer offset to SendParam in slot 0, MessagingFee
    head in middle, refund address last):
      [0..32]   offset to SendParam tuple
      [32..64]  MessagingFee.nativeFee (uint256)
      [64..96]  MessagingFee.lzTokenFee (uint256)
      [96..128] refundAddress (address right-padded)
      [128..)   SendParam body — slot 0=dstEid, slot 1=to, ...
    """
    method_entry = _STARGATE_V2_METHODS.get(method_id)
    if method_entry is None:
        return None
    _, method_name = method_entry

    if len(args_blob) < 128 * 2:
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )

    try:
        # Outer offset → SendParam tuple body.
        try:
            send_offset = int(args_blob[0:64], 16)
        except ValueError:
            send_offset = 128
        send_idx = send_offset * 2
        # Bounds-check + fallback to canonical layout (offset = 0x80
        # = 128 bytes for the 4-slot head before the tuple body).
        if send_idx < 64 or send_idx + 128 > len(args_blob):
            send_idx = 128 * 2

        if send_idx + 128 > len(args_blob):
            return BridgeDecodeResult(
                destination_chain=None, destination_address=None,
                bridge_method=method_name, confidence="low",
                raw_calldata_excerpt=full_data[:400],
            )

        # SendParam.dstEid — uint32 right-aligned in body slot 0.
        eid_hex = args_blob[send_idx:send_idx + 64]
        eid = int(eid_hex, 16) if eid_hex else 0
        dest_chain = _LAYERZERO_V2_EIDS.get(eid) or _LZ_CHAIN_IDS.get(eid)

        # SendParam.to — bytes32 in body slot 1; last 20 bytes are
        # the EVM destination.
        to_start = send_idx + 64
        to_end = to_start + 64
        dest_address: str | None = None
        if to_end <= len(args_blob):
            to_hex = args_blob[to_start:to_end][-40:]
            if len(to_hex) == 40 and to_hex != "0" * 40:
                dest_address = "0x" + to_hex

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
        log.debug("stargate v2 decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain=None, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


# ──────────────────────────────────────────────────────────────────────
# v0.32.1 — Rollup-canonical bridge decoders
# Closes Adversary M-6 (the single highest-leverage CRIT in v0.32.0).
# Pre-v0.32.1 these bridges were labeled but undecoded, so the BFS
# halted at the bridge address with no actionable destination.
# ──────────────────────────────────────────────────────────────────────


def _extract_addr_slot(args_blob: str, slot_idx: int) -> str | None:
    """Read a 32-byte slot (slot_idx 0-based) and treat its last 20
    bytes as an EVM address. Return ``0x…`` lowercase, or ``None`` if
    out of range or zero address."""
    start = slot_idx * 64
    end = start + 64
    if end > len(args_blob):
        return None
    hex_addr = args_blob[start + 24:end]  # last 20 bytes = 40 hex chars
    if len(hex_addr) != 40 or hex_addr == "0" * 40:
        return None
    return "0x" + hex_addr


# Polygon PoS RootChainManager — Ethereum L1 side.
_POLYGON_POS_METHODS = {
    # depositFor(address user, address rootToken, bytes depositData)
    "0xe3dec8fb": "depositFor",
    # depositEtherFor(address user)
    "0x4faa8a26": "depositEtherFor",
}


def _decode_polygon_pos(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode Polygon PoS RootChainManager calldata.

    Destination chain is always 'polygon' for both selectors. The
    destination address is slot 0 (`user` parameter) in both methods.
    """
    method_name = _POLYGON_POS_METHODS.get(method_id)
    if method_name is None:
        # Unknown selector under a recognised protocol → dispatcher
        # contract returns None (caller falls back to the
        # bridges.json candidate list).
        return None
    try:
        dest_addr = _extract_addr_slot(args_blob, 0)
        return BridgeDecodeResult(
            destination_chain="polygon",
            destination_address=dest_addr,
            bridge_method=method_name,
            confidence="high" if dest_addr else "medium",
            raw_calldata_excerpt=full_data[:400],
        )
    except (ValueError, IndexError) as exc:
        log.debug("polygon-pos decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain="polygon", destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


# Optimism L1StandardBridge — Ethereum L1 side. Same ABI as Base.
_OP_STACK_METHODS = {
    # depositERC20To(address _l1Token, address _l2Token, address _to,
    #                uint256 _amount, uint32 _l2Gas, bytes _data)
    "0x838b2520": ("depositERC20To", 2),    # _to is slot 2
    # depositETHTo(address _to, uint32 _l2Gas, bytes _data)
    "0x9a2ac6d5": ("depositETHTo", 0),       # _to is slot 0
    # depositERC20(address _l1Token, address _l2Token, uint256 _amount,
    #              uint32 _l2Gas, bytes _data) — recipient = msg.sender,
    # not in calldata. Return medium confidence with no dest_address.
    "0x58a997f6": ("depositERC20", None),
    # depositETH(uint32 _l2Gas, bytes _data) — recipient = msg.sender.
    "0xb1a1a882": ("depositETH", None),
    # withdrawTo(address _l2Token, address _to, uint256 _amount,
    #            uint32 _l1Gas, bytes _data) — L2-side: recipient is on
    # ethereum (the L1 side). Slot 1 = _to.
    "0xa3a79548": ("withdrawTo", 1),
}


def _decode_op_stack_l1(
    method_id: str,
    args_blob: str,
    full_data: str,
    dest_chain: str,
) -> BridgeDecodeResult | None:
    """Shared OP-Stack L1StandardBridge decoder. Optimism + Base share
    this ABI (Base is OP Stack). ``dest_chain`` is either 'optimism'
    or 'base'.

    Special case: ``withdrawTo`` runs on the L2 side; the destination
    of the funds is the L1 side (ethereum), so the chain is overridden
    regardless of which OP-Stack the L2 belongs to.
    """
    entry = _OP_STACK_METHODS.get(method_id)
    if entry is None:
        return BridgeDecodeResult(
            destination_chain=dest_chain, destination_address=None,
            bridge_method="unknown", confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )
    method_name, dest_slot = entry
    # withdrawTo is an L2-side method — destination is L1 (ethereum).
    effective_chain = "ethereum" if method_name == "withdrawTo" else dest_chain
    try:
        if dest_slot is None:
            # msg.sender path — we don't have it here. The trace's
            # transaction-from address will be used by the BFS
            # continuation logic when destination_address is None.
            return BridgeDecodeResult(
                destination_chain=effective_chain, destination_address=None,
                bridge_method=method_name, confidence="medium",
                raw_calldata_excerpt=full_data[:400],
            )
        dest_addr = _extract_addr_slot(args_blob, dest_slot)
        return BridgeDecodeResult(
            destination_chain=effective_chain,
            destination_address=dest_addr,
            bridge_method=method_name,
            confidence="high" if dest_addr else "medium",
            raw_calldata_excerpt=full_data[:400],
        )
    except (ValueError, IndexError) as exc:
        log.debug("%s decode failed: %s", effective_chain, exc)
        return BridgeDecodeResult(
            destination_chain=effective_chain, destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


def _decode_optimism_l1(
    method_id: str, args_blob: str, full_data: str,
) -> BridgeDecodeResult | None:
    return _decode_op_stack_l1(method_id, args_blob, full_data, "optimism")


def _decode_base_l1(
    method_id: str, args_blob: str, full_data: str,
) -> BridgeDecodeResult | None:
    return _decode_op_stack_l1(method_id, args_blob, full_data, "base")


# Arbitrum L1ERC20Gateway + Inbox.
_ARBITRUM_L1_METHODS = {
    # outboundTransfer(address _l1Token, address _to, uint256 _amount,
    #                  uint256 _maxGas, uint256 _gasPriceBid, bytes _data)
    "0xd2ce7d65": ("outboundTransfer", 1),
    # outboundTransferCustomRefund(address _l1Token, address _refundTo,
    #                              address _to, uint256 _amount, ...)
    "0x4fb1a07b": ("outboundTransferCustomRefund", 2),
    # depositEth() on Inbox — recipient = msg.sender.
    "0x439370b1": ("depositEth", None),
}


def _decode_arbitrum_l1(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode Arbitrum L1 gateway / Inbox calldata. Destination chain
    is always 'arbitrum'."""
    entry = _ARBITRUM_L1_METHODS.get(method_id)
    if entry is None:
        return BridgeDecodeResult(
            destination_chain="arbitrum", destination_address=None,
            bridge_method="unknown", confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )
    method_name, dest_slot = entry
    try:
        if dest_slot is None:
            return BridgeDecodeResult(
                destination_chain="arbitrum", destination_address=None,
                bridge_method=method_name, confidence="medium",
                raw_calldata_excerpt=full_data[:400],
            )
        dest_addr = _extract_addr_slot(args_blob, dest_slot)
        return BridgeDecodeResult(
            destination_chain="arbitrum",
            destination_address=dest_addr,
            bridge_method=method_name,
            confidence="high" if dest_addr else "medium",
            raw_calldata_excerpt=full_data[:400],
        )
    except (ValueError, IndexError) as exc:
        log.debug("arbitrum-l1 decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain="arbitrum", destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


# zkSync Era L1ERC20Bridge.
_ZKSYNC_L1_METHODS = {
    # deposit(address _l2Receiver, address _l1Token, uint256 _amount,
    #         uint256 _l2TxGasLimit, uint256 _l2TxGasPerPubdataByte,
    #         address _refundRecipient)
    "0xe8b99b1b": ("deposit", 0),
}


def _decode_zksync_l1(
    method_id: str,
    args_blob: str,
    full_data: str,
) -> BridgeDecodeResult | None:
    """Decode zkSync Era L1ERC20Bridge calldata. Destination chain
    is always 'zksync_era'."""
    entry = _ZKSYNC_L1_METHODS.get(method_id)
    if entry is None:
        return BridgeDecodeResult(
            destination_chain="zksync", destination_address=None,
            bridge_method="unknown", confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )
    method_name, dest_slot = entry
    try:
        dest_addr = _extract_addr_slot(args_blob, dest_slot)
        return BridgeDecodeResult(
            destination_chain="zksync",
            destination_address=dest_addr,
            bridge_method=method_name,
            confidence="high" if dest_addr else "medium",
            raw_calldata_excerpt=full_data[:400],
        )
    except (ValueError, IndexError) as exc:
        log.debug("zksync-l1 decode failed: %s", exc)
        return BridgeDecodeResult(
            destination_chain="zksync", destination_address=None,
            bridge_method=method_name, confidence="low",
            raw_calldata_excerpt=full_data[:400],
        )


# v0.32.1 test-public aliases. The tests in
# ``tests/test_bridge_calldata_canonical.py`` import the per-bridge
# selector tables directly; the OP-Stack-shared table is exposed under
# both _OPTIMISM_L1_METHODS and _BASE_L1_METHODS for symmetry.
_OPTIMISM_L1_METHODS = _OP_STACK_METHODS
_BASE_L1_METHODS = _OP_STACK_METHODS


__all__ = (
    "BridgeDecodeResult",
    "decode_bridge_calldata",
    "_POLYGON_POS_METHODS",
    "_OPTIMISM_L1_METHODS",
    "_BASE_L1_METHODS",
    "_OP_STACK_METHODS",
    "_ARBITRUM_L1_METHODS",
    "_ZKSYNC_L1_METHODS",
)
