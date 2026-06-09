"""ERC-4337 user-op decomposition (v0.32.1 trace gap A).

Account Abstraction (ERC-4337) wraps user intent inside a bundler tx
that calls `EntryPoint.handleOps(...)`. Naive trace pipelines see
"bundler EOA → EntryPoint contract" and miss the real flow — which
is encoded inside the `callData` field of each UserOp inside the
ops array.

This module decomposes a bundler transaction into its constituent
UserOps and extracts inner ERC-20 transfers from each op's callData.

Reactor parity: Reactor's "AA decomposition" panel shows the bundler
+ EntryPoint + smart-account-sender chain and pulls value movement
out of callData. Without this, every AA-wallet theft case shows
the bundler EOA as a hop and loses the smart-account sender.

The decoder is best-effort and pure (no RPC). Returns [] for
non-EntryPoint targets, malformed input, or unknown selectors.
The BFS/brief layer consumes the structured output.

# TODO(wave-4-integration): wire `decompose_user_ops` into
# trace.tracer when destination is an EntryPoint address; emit
# inner transfers as virtual hops so the BFS continues past the
# bundler.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

# Canonical EntryPoint addresses (lowercase for comparison).
ENTRYPOINT_V06 = "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789"
ENTRYPOINT_V07 = "0x0000000071727de22e5e9d8baf0edac6f37da032"

ENTRYPOINTS = frozenset({ENTRYPOINT_V06, ENTRYPOINT_V07})

# handleOps selector for v0.6 PackedUserOp tuple.
# keccak("handleOps((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[],address)")[:4]
HANDLE_OPS_SELECTOR = "0x1fad948c"

# ERC-20 selectors.
ERC20_TRANSFER_SELECTOR = "0xa9059cbb"
ERC20_TRANSFER_FROM_SELECTOR = "0x23b872dd"

# Smart-account ``execute`` wrappers. A UserOp's callData is almost never a raw
# ERC-20 transfer — the smart account calls ``execute(target, value, data)`` and
# the real ERC-20 ``transfer`` lives inside ``data``, with the token = ``target``.
# Selectors are keccak[:4] of the canonical ABI (verified against the ERC-20
# selectors above, whose keccak we know): see scripts / the commit message.
#   execute(address,uint256,bytes)        — SimpleAccount / LightAccount / most
EXECUTE_SELECTOR = "0xb61d27f6"
#   execute(address,uint256,bytes,uint8)  — Kernel / ZeroDev (trailing Operation
#   enum). The first three head words match execute(), so the SAME offsets
#   decode dest/value/data; the uint8 at head word 3 is simply ignored.
EXECUTE_WITH_OP_SELECTOR = "0x51945447"
_EXECUTE_SINGLE_SELECTORS = frozenset({EXECUTE_SELECTOR, EXECUTE_WITH_OP_SELECTOR})
#   executeBatch(address[],bytes[])            — SimpleAccount v0.6 batch form
EXECUTE_BATCH_SELECTOR = "0x18dfb3c7"
#   executeBatch(address[],uint256[],bytes[])  — SimpleAccount v0.7 batch form
EXECUTE_BATCH_VALUE_SELECTOR = "0x47e1da2a"
# Sanity cap on batch array length — real executeBatch arrays are < ~50; this
# bounds OOM / quadratic-decode exposure from an adversarial bundler tx.
_MAX_BATCH_CALLS = 256

# Known smart-account factory addresses (lowercase). Best-effort —
# AA factories proliferate quickly and these are the ones we've seen
# in real recovery cases through Q2 2026.
KNOWN_AA_FACTORIES: dict[str, str] = {
    # SimpleAccountFactory (Infinitism reference impl, v0.6)
    "0x9406cc6185a346906296840746125a0e44976454": "SimpleAccountFactory",
    # SimpleAccountFactory v0.7
    "0x91e60e0613810449d098b0b5ec8b51a0fe8c8985": "SimpleAccountFactory-v07",
    # Kernel (ZeroDev)
    "0x5de4839a76cf55d0c90e2061ef4386d962e15ae3": "Kernel-ZeroDev",
    "0xaac5d4240af87249b3f71bc8e4a2cae074a3e419": "Kernel-ZeroDev-v3",
    # Biconomy
    "0x000000a56aaca3e9a4c479ea6b6cd0dbcb6634f5": "Biconomy-V2",
    "0x00006b7e42e01957da540dc6a8f7c30c4d816af5": "Biconomy-V2-MultiChain",
    # Safe v1.4 (SafeProxyFactory)
    "0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67": "SafeProxyFactory-v14",
    # Alchemy LightAccountFactory
    "0x00000055c0b4fa41dde26a74435ff03692292fbd": "LightAccountFactory",
}


@dataclass(frozen=True)
class UserOp:
    """One ERC-4337 user operation (v0.6 layout).

    Fields mirror the on-chain struct. `call_data` is the field we
    care about most — it's what the smart account would call on the
    target contract.
    """

    sender: str
    nonce: int
    init_code: bytes
    call_data: bytes
    call_gas_limit: int
    verification_gas_limit: int
    pre_verification_gas: int
    max_fee_per_gas: int
    max_priority_fee_per_gas: int
    paymaster_and_data: bytes
    signature: bytes


@dataclass(frozen=True)
class InnerTransfer:
    """A token transfer extracted from a UserOp's callData."""

    from_address: str
    to_address: str
    token: str  # The target contract (i.e. ERC-20 contract address)
    amount_raw: int
    selector: str  # "transfer" | "transferFrom"


def _to_bytes(data: bytes | str | None) -> bytes | None:
    """Coerce hex-string / bytes into bytes. Return None on garbage."""
    if data is None:
        return None
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        s = data.strip()
        if s.startswith("0x") or s.startswith("0X"):
            s = s[2:]
        if not s:
            return b""
        try:
            return bytes.fromhex(s)
        except ValueError:
            return None
    return None


def _canon_addr(addr: str | None) -> str:
    if not isinstance(addr, str):
        return ""
    return addr.strip().lower()


def _selector_hex(data: bytes) -> str:
    """Return the 4-byte selector as `0x...` lowercase."""
    if len(data) < 4:
        return ""
    return "0x" + data[:4].hex()


def _read_uint(data: bytes, offset: int) -> int:
    """Read a 32-byte big-endian integer at offset. Raises ValueError on OOB."""
    if offset + 32 > len(data):
        raise ValueError(f"OOB read at offset {offset}, len={len(data)}")
    return int.from_bytes(data[offset:offset + 32], "big")


def _read_address(data: bytes, offset: int) -> str:
    """Read a 20-byte address (right-padded in 32-byte slot) at offset."""
    if offset + 32 > len(data):
        raise ValueError(f"OOB address read at offset {offset}")
    # Address is last 20 bytes of the 32-byte word.
    return "0x" + data[offset + 12:offset + 32].hex()


def _read_bytes(data: bytes, head_offset: int, base_offset: int) -> bytes:
    """Read a dynamic `bytes` field. `head_offset` holds the offset
    (relative to base_offset) where the bytes length+data live."""
    rel = _read_uint(data, head_offset)
    abs_off = base_offset + rel
    length = _read_uint(data, abs_off)
    start = abs_off + 32
    if start + length > len(data):
        raise ValueError(f"OOB bytes read at {abs_off} len={length}")
    return data[start:start + length]


def _read_uint_array(data: bytes, arr_off: int) -> list[int]:
    """Read a ``uint256[]`` whose length+elements start at absolute ``arr_off``
    ([len][e0][e1]...). Capped at ``_MAX_BATCH_CALLS``."""
    n = _read_uint(data, arr_off)
    if n > _MAX_BATCH_CALLS:
        raise ValueError(f"uint[] len {n} exceeds cap {_MAX_BATCH_CALLS}")
    return [_read_uint(data, arr_off + 32 + 32 * i) for i in range(n)]


def _read_address_array(data: bytes, arr_off: int) -> list[str]:
    """Read an ``address[]`` ([len][a0][a1]...). Capped at ``_MAX_BATCH_CALLS``."""
    n = _read_uint(data, arr_off)
    if n > _MAX_BATCH_CALLS:
        raise ValueError(f"address[] len {n} exceeds cap {_MAX_BATCH_CALLS}")
    return [_read_address(data, arr_off + 32 + 32 * i) for i in range(n)]


def _read_bytes_array(data: bytes, arr_off: int) -> list[bytes]:
    """Read a ``bytes[]`` dynamic array: ``arr_off`` → [len][off0][off1]...],
    each ``off_i`` relative to the first element-offset slot, pointing at
    [len_i][bytes_i]. Capped at ``_MAX_BATCH_CALLS``."""
    n = _read_uint(data, arr_off)
    if n > _MAX_BATCH_CALLS:
        raise ValueError(f"bytes[] len {n} exceeds cap {_MAX_BATCH_CALLS}")
    base = arr_off + 32  # element offsets are relative to here
    out: list[bytes] = []
    for i in range(n):
        elem_rel = _read_uint(data, base + 32 * i)
        abs_off = base + elem_rel
        blen = _read_uint(data, abs_off)
        start = abs_off + 32
        if start + blen > len(data):
            raise ValueError(f"OOB bytes[] elem {i} at {abs_off} len={blen}")
        out.append(data[start:start + blen])
    return out


def _decode_one_user_op(data: bytes, op_base: int) -> UserOp:
    """Decode one PackedUserOp tuple starting at absolute offset op_base.

    The tuple layout (head section, 11 * 32 bytes):
        0:   sender (address)
        32:  nonce (uint256)
        64:  initCode (bytes, offset)
        96:  callData (bytes, offset)
        128: callGasLimit (uint256)
        160: verificationGasLimit (uint256)
        192: preVerificationGas (uint256)
        224: maxFeePerGas (uint256)
        256: maxPriorityFeePerGas (uint256)
        288: paymasterAndData (bytes, offset)
        320: signature (bytes, offset)
    Dynamic-bytes offsets are relative to op_base.
    """
    sender = _read_address(data, op_base + 0)
    nonce = _read_uint(data, op_base + 32)
    init_code = _read_bytes(data, op_base + 64, op_base)
    call_data = _read_bytes(data, op_base + 96, op_base)
    call_gas = _read_uint(data, op_base + 128)
    verif_gas = _read_uint(data, op_base + 160)
    pre_verif_gas = _read_uint(data, op_base + 192)
    max_fee = _read_uint(data, op_base + 224)
    max_prio = _read_uint(data, op_base + 256)
    paymaster = _read_bytes(data, op_base + 288, op_base)
    signature = _read_bytes(data, op_base + 320, op_base)

    return UserOp(
        sender=sender,
        nonce=nonce,
        init_code=init_code,
        call_data=call_data,
        call_gas_limit=call_gas,
        verification_gas_limit=verif_gas,
        pre_verification_gas=pre_verif_gas,
        max_fee_per_gas=max_fee,
        max_priority_fee_per_gas=max_prio,
        paymaster_and_data=paymaster,
        signature=signature,
    )


def decompose_user_ops(
    tx_input: bytes | str | None,
    tx_to: str | None,
) -> list[UserOp]:
    """Decompose a bundler tx into its component UserOps.

    Returns [] if:
        - `tx_to` is not a known EntryPoint
        - selector is not handleOps
        - calldata is malformed / truncated
        - any decode error during op extraction
    """
    if _canon_addr(tx_to) not in ENTRYPOINTS:
        return []

    data = _to_bytes(tx_input)
    if data is None or len(data) < 4:
        return []

    if _selector_hex(data) != HANDLE_OPS_SELECTOR:
        return []

    # Skip the 4-byte selector for ABI decoding.
    payload = data[4:]
    try:
        # handleOps((tuple)[], address)
        # head: 2 slots = (ops_offset, beneficiary)
        if len(payload) < 64:
            return []
        ops_offset = _read_uint(payload, 0)
        # beneficiary at offset 32 — unused for decomposition
        # Array section: [length][element offsets...] (since elements
        # are dynamic tuples, each entry is an offset).
        array_len = _read_uint(payload, ops_offset)
        if array_len > 1024:
            # Sanity ceiling — handleOps arrays in the wild are <100.
            log.warning("erc4337.decompose: array_len=%d exceeds sanity cap", array_len)
            return []

        ops: list[UserOp] = []
        # Array base (where the offsets to each tuple live).
        array_base = ops_offset + 32
        for i in range(array_len):
            try:
                # Each entry is a 32-byte offset relative to array_base.
                tuple_rel = _read_uint(payload, array_base + 32 * i)
                op_base = array_base + tuple_rel
                op = _decode_one_user_op(payload, op_base)
                ops.append(op)
            except (ValueError, IndexError) as exc:
                log.warning("erc4337.decompose: op[%d] decode failed: %s", i, exc)
                # Skip the malformed op but keep going — partial decode
                # is more useful than total failure.
                continue
        return ops
    except (ValueError, IndexError) as exc:
        log.warning("erc4337.decompose: top-level decode failed: %s", exc)
        return []


def _decode_erc20_call(
    sender: str, target: str, data: bytes
) -> InnerTransfer | None:
    """Decode a single ``transfer`` / ``transferFrom`` call (``data``) made by
    ``sender`` on contract ``target`` → an :class:`InnerTransfer` whose ``token``
    is ``target`` (the contract called). Returns ``None`` for empty/short data or
    any non-ERC-20-transfer selector (conservative — better no row than a wrong
    one). For ``transfer`` the mover is ``sender`` (the smart account); for
    ``transferFrom`` it is the decoded first arg."""
    if not data or len(data) < 4:
        return None
    selector = _selector_hex(data)
    payload = data[4:]
    try:
        if selector == ERC20_TRANSFER_SELECTOR and len(payload) >= 64:
            return InnerTransfer(
                from_address=sender,
                to_address=_read_address(payload, 0),
                token=target,
                amount_raw=_read_uint(payload, 32),
                selector="transfer",
            )
        if selector == ERC20_TRANSFER_FROM_SELECTOR and len(payload) >= 96:
            return InnerTransfer(
                from_address=_read_address(payload, 0),
                to_address=_read_address(payload, 32),
                token=target,
                amount_raw=_read_uint(payload, 64),
                selector="transferFrom",
            )
    except (ValueError, IndexError) as exc:
        log.debug("erc4337._decode_erc20_call: decode error: %s", exc)
    return None


def _extract_execute_batch(
    sender: str, payload: bytes, *, has_value: bool
) -> list[InnerTransfer]:
    """Unwrap ``executeBatch`` — ``(address[] dest, [uint256[] value,]
    bytes[] data)`` — into per-call InnerTransfers (``token`` = each ``dest``).
    For the value-bearing form, a per-element ``value > 0`` with no ERC-20 inner
    call is a native transfer to that dest. Arrays are length-capped
    (``_MAX_BATCH_CALLS``); a per-element decode that yields nothing is skipped
    (conservative)."""
    dests = _read_address_array(payload, _read_uint(payload, 0))
    if has_value:
        values = _read_uint_array(payload, _read_uint(payload, 32))
        datas = _read_bytes_array(payload, _read_uint(payload, 64))
    else:
        values = []
        datas = _read_bytes_array(payload, _read_uint(payload, 32))
    out: list[InnerTransfer] = []
    for i, target in enumerate(dests):
        data = datas[i] if i < len(datas) else b""
        it = _decode_erc20_call(sender, target, data)
        if it is not None:
            out.append(it)
            continue
        v = values[i] if i < len(values) else 0
        if v > 0:
            out.append(InnerTransfer(
                from_address=sender, to_address=target, token="",
                amount_raw=v, selector="executeBatch",
            ))
    return out


def extract_inner_transfers(user_op: UserOp) -> list[InnerTransfer]:
    """Extract the value movement encoded in a UserOp's callData.

    The common, real-world case (SimpleAccount / LightAccount / Biconomy /
    Kernel) is a ``execute(address target, uint256 value, bytes data)`` wrapper:
    the smart account calls ``target`` with ``data``. We unwrap it and, when
    ``data`` is an ERC-20 ``transfer`` / ``transferFrom``, emit an InnerTransfer
    whose ``token`` is the unwrapped ``target`` (this is what makes the result
    actually followable — pre-v0.39 the decoder only handled a *direct* transfer
    in callData and left ``token`` blank). When ``data`` carries no ERC-20
    transfer but ``value > 0``, the execute is a NATIVE transfer of ``value`` wei
    to ``target`` (``token=""``, ``selector="execute"``).

    Also still handles a *direct* ``transfer`` / ``transferFrom`` in callData
    (no wrapper) — token unknown at this layer, kept ``""`` (pre-v0.39 behavior).

    ``executeBatch(address[],[uint256[],]bytes[])`` IS unwrapped (per-call, token
    = each dest). NOT yet unwrapped: multicall / ``execute``-of-``execute``
    nesting — tracked follow-up; those callDatas yield ``[]`` rather than a guess.
    Best-effort: any decode error → ``[]``.
    """
    cd = user_op.call_data
    if not cd or len(cd) < 4:
        return []

    selector = _selector_hex(cd)
    payload = cd[4:]
    out: list[InnerTransfer] = []
    try:
        if selector in _EXECUTE_SINGLE_SELECTORS and len(payload) >= 96:
            # execute(address target, uint256 value, bytes data[, uint8 op])
            target = _read_address(payload, 0)
            value = _read_uint(payload, 32)
            inner = _read_bytes(payload, 64, 0)
            it = _decode_erc20_call(user_op.sender, target, inner)
            if it is not None:
                out.append(it)
            elif value > 0:
                # Native-asset transfer (no ERC-20 inner call): sender → target.
                out.append(InnerTransfer(
                    from_address=user_op.sender,
                    to_address=target,
                    token="",                 # native asset (ETH / chain coin)
                    amount_raw=value,
                    selector="execute",
                ))
        elif selector == EXECUTE_BATCH_VALUE_SELECTOR and len(payload) >= 96:
            # executeBatch(address[] dest, uint256[] value, bytes[] data)
            out.extend(_extract_execute_batch(user_op.sender, payload, has_value=True))
        elif selector == EXECUTE_BATCH_SELECTOR and len(payload) >= 64:
            # executeBatch(address[] dest, bytes[] data)
            out.extend(_extract_execute_batch(user_op.sender, payload, has_value=False))
        elif selector in (ERC20_TRANSFER_SELECTOR, ERC20_TRANSFER_FROM_SELECTOR):
            # Direct ERC-20 call in callData (no execute wrapper) — the token
            # contract isn't named at this layer, so token stays "".
            it = _decode_erc20_call(user_op.sender, "", cd)
            if it is not None:
                out.append(it)
    except (ValueError, IndexError) as exc:
        log.debug("erc4337.extract: decode error: %s", exc)

    return out


def is_aa_wallet(address: str | None, evm_adapter: Any = None) -> bool:
    """Best-effort: is `address` a known smart-account / AA wallet?

    Strategy:
      1. If `evm_adapter` is None, return False (no RPC to confirm).
      2. If the adapter exposes `get_code(address)`, fetch it. If
         the deployed bytecode begins with one of the known proxy
         patterns (EIP-1167 minimal proxy, ERC-1967, etc.) and the
         implementation slot points at a known factory, return True.
      3. Fallback: check `get_contract_creator` if available; if the
         creator is a known AA factory, return True.

    The adapter API surface here is duck-typed — any object exposing
    these methods works. Production usage will go through
    `chains.ethereum.adapter.EthereumAdapter`.
    """
    if not isinstance(address, str) or evm_adapter is None:
        return False

    addr = _canon_addr(address)
    if not addr:
        return False

    # Best signal: who deployed this contract?
    try:
        get_creator = getattr(evm_adapter, "get_contract_creator", None)
        if callable(get_creator):
            creator = get_creator(addr)
            if isinstance(creator, str) and _canon_addr(creator) in KNOWN_AA_FACTORIES:
                return True
    except Exception as exc:  # pragma: no cover — adapter-specific
        log.debug("is_aa_wallet: get_contract_creator failed: %s", exc)

    # Weaker fallback: just check code presence + proxy hint.
    try:
        get_code = getattr(evm_adapter, "get_code", None)
        if callable(get_code):
            code = get_code(addr)
            if isinstance(code, (bytes, str)) and code:
                code_bytes = _to_bytes(code) if isinstance(code, str) else code
                if code_bytes and len(code_bytes) >= 1:
                    # EIP-1167 minimal proxy = 45 bytes starting with 0x363d3d37...
                    if (
                        len(code_bytes) == 45
                        and code_bytes[:4] == bytes.fromhex("363d3d37")
                    ):
                        # Proxy contract — likely an AA wallet but we can't
                        # be sure without resolving the implementation.
                        # Conservative: only flag if we also know creator.
                        return False
    except Exception as exc:  # pragma: no cover — adapter-specific
        log.debug("is_aa_wallet: get_code failed: %s", exc)

    return False
