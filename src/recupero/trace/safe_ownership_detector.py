"""Gnosis Safe / Safe{Wallet} ownership-change detector.

JACOB_ADVERSARY_AUDIT_v032.md Route 1 Hop 2 showed the most insidious
trace-evasion in the codebase: the adversary deposits stolen USDC into
a Safe (the multisig contract pattern, ex-Gnosis Safe). A standard
ERC-20 ``Transfer`` log fires for the deposit, so BFS reaches the
Safe. ``policy.stop_at_contract = True`` halts the trace there. Then
the adversary calls ``swapOwner(prevOwner, oldOwner, newOwner)`` on
the Safe — **this leaves no ERC-20 Transfer event**. The funds remain
in the Safe, but custodial control has moved to the adversary's new
key. Recupero's brief renders ``"trace terminated at contract"``;
investigators think the funds went to DeFi. They didn't — the adversary
still has them.

This module is the recognizer that turns a Safe ownership-change call
into a structured event the trace renderer can surface as a SECTION 7
"CUSTODIAL CONTROL CHANGE" warning. It is **read-only**: given a tx
hash and an EVM adapter, it returns either a :class:`SafeOwnershipChange`
record or None.

Trace integration is intentionally NOT done here — the audit explicitly
calls out ``src/recupero/trace/tracer.py`` and
``src/recupero/trace/bridge_calldata.py`` as files we may NOT touch in
this commit. The integration is wired in a follow-up.

The four Safe ownership-management selectors:

* ``0xe318b52b`` — ``swapOwner(address prevOwner, address oldOwner, address newOwner)``
* ``0x0d582f13`` — ``addOwnerWithThreshold(address owner, uint256 threshold)``
* ``0xf8dc5dd9`` — ``removeOwner(address prevOwner, address owner, uint256 threshold)``
* ``0x694e80c3`` — ``changeThreshold(uint256 threshold)``

These selectors are stable across Safe contract versions 1.0.0 through
1.4.x (Safe deploys ABI is frozen on the ownership-management surface
for compat reasons).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: 4-byte selectors for Safe ownership-management functions.
#: Constant lookup; key is the 10-char "0x" + 8 hex chars selector,
#: value is the canonical method name we surface in the trace report.
SAFE_SELECTORS: dict[str, str] = {
    "0xe318b52b": "swapOwner",
    "0x0d582f13": "addOwnerWithThreshold",
    "0xf8dc5dd9": "removeOwner",
    "0x694e80c3": "changeThreshold",
}


# Selector → list of (arg_name, slot_index) for the address fields we
# want to extract. Slots are 32-byte aligned positions in args_blob.
#
# swapOwner(prevOwner, oldOwner, newOwner) — addresses at slots 0,1,2.
# addOwnerWithThreshold(owner, threshold) — address at slot 0.
# removeOwner(prevOwner, owner, threshold) — addresses at slots 0,1.
# changeThreshold(threshold) — no address args.
_SELECTOR_ADDRESS_SLOTS: dict[str, list[tuple[str, int]]] = {
    "0xe318b52b": [("prev_owner", 0), ("old_owner", 1), ("new_owner", 2)],
    "0x0d582f13": [("new_owner", 0)],
    "0xf8dc5dd9": [("prev_owner", 0), ("old_owner", 1)],
    "0x694e80c3": [],
}


@dataclass(frozen=True)
class SafeOwnershipChange:
    """Structured Safe ownership-change event.

    Returned by :func:`detect_safe_ownership_change` when a tx matches
    one of the four Safe ownership-management selectors. The fields
    are nullable for non-addressing methods (``changeThreshold``) and
    for partial decodes (a malformed calldata returns ``method``
    populated but the address slots ``None``).

    Attributes:
        method: Canonical Safe ABI method name. One of ``swapOwner``,
            ``addOwnerWithThreshold``, ``removeOwner``,
            ``changeThreshold``.
        selector: The 10-char "0x"+selector that matched.
        safe_address: The contract being mutated — equals the tx's
            ``to_address``. Always present.
        prev_owner: The previous owner in the linked-list. Only
            meaningful for ``swapOwner`` and ``removeOwner``.
        old_owner: The owner being removed/replaced. Only meaningful
            for ``swapOwner`` and ``removeOwner``.
        new_owner: The owner being added/installed. Only meaningful
            for ``swapOwner`` and ``addOwnerWithThreshold``.
        new_threshold: The new signature threshold. Only meaningful
            for ``changeThreshold``, ``addOwnerWithThreshold``,
            ``removeOwner``.
        tx_hash: The transaction hash that contained this call. Used
            in the brief for evidence linkage.
        verified_via_get_owners: True iff the adapter confirmed the
            ``to_address`` IS a Safe by calling ``getOwners()`` (or
            equivalent) and getting a non-empty owner list. False is
            best-effort selector-only match.
    """

    method: str
    selector: str
    safe_address: str
    tx_hash: str
    prev_owner: str | None = None
    old_owner: str | None = None
    new_owner: str | None = None
    new_threshold: int | None = None
    verified_via_get_owners: bool = False


def _slot_to_address(args_blob: str, slot_index: int) -> str | None:
    """Extract an EVM address from a 32-byte slot of a calldata args blob.

    args_blob is the hex string AFTER the 4-byte selector (so the
    first 64 hex chars are slot 0). Returns the address as lowercase
    "0x" + 40 hex chars on success, None if the slot is missing or
    decodes to all-zero (the zero address is never a meaningful Safe
    owner; reject it).
    """
    start = slot_index * 64
    end = start + 64
    if len(args_blob) < end:
        return None
    slot_hex = args_blob[start:end]
    # Address is right-aligned in the 32-byte slot — last 20 bytes (40 hex chars).
    addr_hex = slot_hex[24:]
    if len(addr_hex) != 40:
        return None
    if int(addr_hex, 16) == 0:
        # Zero address sentinel — not a real owner change. Treat as
        # malformed for our purposes.
        return None
    return "0x" + addr_hex.lower()


def _slot_to_uint(args_blob: str, slot_index: int) -> int | None:
    """Extract a uint256 from a 32-byte slot of args_blob."""
    start = slot_index * 64
    end = start + 64
    if len(args_blob) < end:
        return None
    slot_hex = args_blob[start:end]
    try:
        return int(slot_hex, 16)
    except ValueError:
        return None


def _try_verify_is_safe(safe_address: str, evm_adapter: Any) -> bool:
    """Best-effort verification that ``safe_address`` is actually a Safe.

    Calls ``evm_adapter.call_view("getOwners()", safe_address)`` if the
    adapter exposes a ``call_view`` method. Returns True iff the call
    succeeds AND returns a non-empty owner list. Any exception is
    swallowed (the adapter may not support view calls, or RPC may be
    down) — in that case we return False and the caller emits the
    SafeOwnershipChange with ``verified_via_get_owners=False``.

    The adapter contract is intentionally duck-typed because the
    in-tree EVM adapter doesn't yet expose ``call_view``; this lets
    callers pass a MagicMock in tests and a real adapter in
    production.
    """
    if evm_adapter is None:
        return False
    call_view = getattr(evm_adapter, "call_view", None)
    if call_view is None or not callable(call_view):
        return False
    try:
        owners = call_view("getOwners()", safe_address)
    except Exception:  # noqa: BLE001
        return False
    if not owners:
        return False
    if isinstance(owners, (list, tuple)):
        return len(owners) > 0
    # Anything else truthy + non-empty counts.
    return True


def detect_safe_ownership_change(
    tx_hash: str,
    evm_adapter: Any,
    *,
    input_data: str | None = None,
    to_address: str | None = None,
) -> SafeOwnershipChange | None:
    """Detect a Safe ownership-change call in a transaction.

    The function is structured to accept either:

      (a) just a ``tx_hash``, in which case ``evm_adapter`` is queried
          for the input_data + to_address via ``get_transaction(tx_hash)``
          (the adapter must expose this method); or
      (b) the ``input_data`` and ``to_address`` directly, bypassing the
          adapter call (useful when the caller already has the tx in
          memory from a prior fetch — saves an RPC).

    The function returns:

      * ``None`` if the tx selector is NOT a Safe ownership-management
        selector. Most txs in the world fall here.
      * ``None`` if input_data is malformed (too short, non-hex, etc.) —
        we conservatively prefer "don't detect" to "false-positive."
      * A :class:`SafeOwnershipChange` if the selector matches. The
        ``verified_via_get_owners`` flag tells the caller whether the
        adapter confirmed the contract IS a Safe; selector-only matches
        still produce a result because the selectors are sufficiently
        rare across non-Safe contracts that the false-positive cost
        is low.

    Args:
        tx_hash: Transaction hash. Stored in the result for evidence
            linkage. Empty string is allowed but discouraged.
        evm_adapter: The chain adapter. May be ``None``; if non-None
            and ``input_data`` is None, we attempt to fetch the tx
            via ``evm_adapter.get_transaction(tx_hash)``. The adapter
            method should return a dict-shaped object with ``input``
            and ``to`` keys (Web3.py / Etherscan format).
        input_data: The raw calldata as a hex string (with or without
            ``0x`` prefix). Bypasses the adapter fetch when provided.
        to_address: The transaction's ``to`` address. Bypasses the
            adapter fetch when provided.

    Returns:
        A :class:`SafeOwnershipChange` or ``None``.
    """
    # ── Resolve input_data + to_address ──────────────────────────────
    if input_data is None or to_address is None:
        if evm_adapter is None:
            return None
        get_tx = getattr(evm_adapter, "get_transaction", None)
        if get_tx is None or not callable(get_tx):
            return None
        try:
            tx = get_tx(tx_hash)
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(tx, dict):
            return None
        if input_data is None:
            input_data = tx.get("input") or tx.get("data") or ""
        if to_address is None:
            to_address = tx.get("to") or ""

    # ── Selector match ──────────────────────────────────────────────
    if not isinstance(input_data, str):
        return None
    data = input_data.strip().lower()
    if data.startswith("0x"):
        data = data[2:]
    if len(data) < 8:
        return None
    selector = "0x" + data[:8]
    method = SAFE_SELECTORS.get(selector)
    if method is None:
        return None

    args_blob = data[8:]

    if not isinstance(to_address, str) or not to_address:
        # No contract address means no Safe — bail.
        return None
    safe_addr = to_address.strip().lower()
    if safe_addr.startswith("0x") and len(safe_addr) == 42:
        pass
    else:
        return None

    # ── Address-slot extraction ─────────────────────────────────────
    addr_fields: dict[str, str | None] = {}
    for arg_name, slot_idx in _SELECTOR_ADDRESS_SLOTS.get(selector, []):
        addr_fields[arg_name] = _slot_to_address(args_blob, slot_idx)

    # ── Threshold extraction (for methods that take a threshold) ────
    new_threshold: int | None = None
    if selector == "0x694e80c3":  # changeThreshold(uint256)
        new_threshold = _slot_to_uint(args_blob, 0)
    elif selector == "0x0d582f13":  # addOwnerWithThreshold(addr, uint256)
        new_threshold = _slot_to_uint(args_blob, 1)
    elif selector == "0xf8dc5dd9":  # removeOwner(addr, addr, uint256)
        new_threshold = _slot_to_uint(args_blob, 2)

    verified = _try_verify_is_safe(safe_addr, evm_adapter)

    return SafeOwnershipChange(
        method=method,
        selector=selector,
        safe_address=safe_addr,
        tx_hash=tx_hash,
        prev_owner=addr_fields.get("prev_owner"),
        old_owner=addr_fields.get("old_owner"),
        new_owner=addr_fields.get("new_owner"),
        new_threshold=new_threshold,
        verified_via_get_owners=verified,
    )
