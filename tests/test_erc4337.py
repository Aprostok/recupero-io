"""Tests for ERC-4337 user-op decomposition (v0.32.1 trace gap A).

Each test builds a calldata blob with the documented ABI encoding
to verify the decoder extracts the right UserOps and inner transfers.
"""

from __future__ import annotations

from recupero.trace.erc4337 import (
    ENTRYPOINT_V06,
    ENTRYPOINT_V07,
    HANDLE_OPS_SELECTOR,
    KNOWN_AA_FACTORIES,
    UserOp,
    decompose_user_ops,
    extract_inner_transfers,
    is_aa_wallet,
)

# ---- ABI-encoding helpers (test-only, mirror decoder layout) ---- #


def _u256(n: int) -> bytes:
    return n.to_bytes(32, "big")


def _addr_word(addr: str) -> bytes:
    a = addr.lower().removeprefix("0x")
    return bytes(12) + bytes.fromhex(a)


def _pad32(b: bytes) -> bytes:
    n = len(b)
    if n % 32 == 0:
        return b
    return b + bytes(32 - (n % 32))


def _encode_bytes_field(payload: bytes) -> bytes:
    """ABI dynamic bytes: 32-byte length + padded payload."""
    return _u256(len(payload)) + _pad32(payload)


def _encode_one_user_op(op: UserOp) -> bytes:
    """Encode one UserOp tuple. Returns the tuple's bytes (head+tails)."""
    head = bytearray(11 * 32)

    # Static fields
    head[0:32] = _addr_word(op.sender)
    head[32:64] = _u256(op.nonce)
    head[128:160] = _u256(op.call_gas_limit)
    head[160:192] = _u256(op.verification_gas_limit)
    head[192:224] = _u256(op.pre_verification_gas)
    head[224:256] = _u256(op.max_fee_per_gas)
    head[256:288] = _u256(op.max_priority_fee_per_gas)

    # Dynamic-bytes fields. Their tail starts after the 11-slot head.
    tails: list[bytes] = []
    cursor = 11 * 32

    init_code_enc = _encode_bytes_field(op.init_code)
    head[64:96] = _u256(cursor)
    tails.append(init_code_enc)
    cursor += len(init_code_enc)

    call_data_enc = _encode_bytes_field(op.call_data)
    head[96:128] = _u256(cursor)
    tails.append(call_data_enc)
    cursor += len(call_data_enc)

    paymaster_enc = _encode_bytes_field(op.paymaster_and_data)
    head[288:320] = _u256(cursor)
    tails.append(paymaster_enc)
    cursor += len(paymaster_enc)

    signature_enc = _encode_bytes_field(op.signature)
    head[320:352] = _u256(cursor)
    tails.append(signature_enc)

    return bytes(head) + b"".join(tails)


def _build_handle_ops_calldata(ops: list[UserOp], beneficiary: str) -> str:
    """Wrap the array+beneficiary in ABI-encoded handleOps calldata."""
    # Header: array_offset (2 slots: array, beneficiary)
    header = bytearray(64)
    header[0:32] = _u256(64)  # array offset = 0x40 (after 2 head slots)
    header[32:64] = _addr_word(beneficiary)

    # Array section: length + element offsets
    array_section = bytearray()
    array_section += _u256(len(ops))

    # Encode each tuple and compute its offset relative to array_base.
    encoded_ops = [_encode_one_user_op(op) for op in ops]
    array_base_end = 32 + 32 * len(ops)  # length + offset slots
    cursor = array_base_end
    for enc in encoded_ops:
        array_section += _u256(cursor - 32)  # offset is rel to array_base (after length)
        cursor += len(enc)
    for enc in encoded_ops:
        array_section += enc

    body = bytes(header) + bytes(array_section)
    return "0x" + HANDLE_OPS_SELECTOR[2:] + body.hex()


def _make_op(
    sender: str = "0x1111111111111111111111111111111111111111",
    nonce: int = 1,
    call_data: bytes = b"",
) -> UserOp:
    return UserOp(
        sender=sender,
        nonce=nonce,
        init_code=b"",
        call_data=call_data,
        call_gas_limit=100_000,
        verification_gas_limit=150_000,
        pre_verification_gas=21_000,
        max_fee_per_gas=20_000_000_000,
        max_priority_fee_per_gas=1_000_000_000,
        paymaster_and_data=b"",
        signature=b"\x00" * 65,
    )


# ---- Tests ---- #


def test_wrong_entrypoint_returns_empty() -> None:
    """Tx to a non-EntryPoint address → no decomposition."""
    cd = _build_handle_ops_calldata(
        [_make_op()],
        beneficiary="0xfeeb0eeb0eeb0eeb0eeb0eeb0eeb0eeb0eeb0eeb",
    )
    assert decompose_user_ops(cd, "0xdeadbeef00000000000000000000000000000000") == []


def test_unknown_selector_returns_empty() -> None:
    """Tx to EntryPoint but wrong selector → no decomposition."""
    assert decompose_user_ops("0xdeadbeef" + "00" * 100, ENTRYPOINT_V06) == []


def test_handle_ops_with_three_ops_v06() -> None:
    """Standard handleOps with 3 ops → all 3 decoded."""
    ops = [
        _make_op(
            sender="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            nonce=1,
        ),
        _make_op(
            sender="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            nonce=2,
        ),
        _make_op(
            sender="0xcccccccccccccccccccccccccccccccccccccccc",
            nonce=3,
        ),
    ]
    cd = _build_handle_ops_calldata(
        ops, beneficiary="0xfeeb0eeb0eeb0eeb0eeb0eeb0eeb0eeb0eeb0eeb"
    )
    decoded = decompose_user_ops(cd, ENTRYPOINT_V06)
    assert len(decoded) == 3
    assert decoded[0].sender == "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert decoded[1].nonce == 2
    assert decoded[2].sender == "0xcccccccccccccccccccccccccccccccccccccccc"


def test_handle_ops_v07_entrypoint_also_works() -> None:
    """v0.7 EntryPoint address recognized too."""
    cd = _build_handle_ops_calldata(
        [_make_op()],
        beneficiary="0xfeeb0eeb0eeb0eeb0eeb0eeb0eeb0eeb0eeb0eeb",
    )
    decoded = decompose_user_ops(cd, ENTRYPOINT_V07)
    assert len(decoded) == 1


def test_extract_inner_transfer_simple() -> None:
    """callData = transfer(to, amount) → one InnerTransfer."""
    # transfer(0x2222..., 1_000_000)
    to_addr = "0x2222222222222222222222222222222222222222"
    amount = 1_000_000
    call_data = (
        bytes.fromhex("a9059cbb")
        + _addr_word(to_addr)
        + _u256(amount)
    )
    op = _make_op(call_data=call_data)
    transfers = extract_inner_transfers(op)
    assert len(transfers) == 1
    assert transfers[0].to_address == to_addr
    assert transfers[0].amount_raw == amount
    assert transfers[0].from_address == op.sender
    assert transfers[0].selector == "transfer"


def test_extract_inner_transfer_from() -> None:
    """callData = transferFrom(from, to, amount) → one InnerTransfer."""
    frm = "0x3333333333333333333333333333333333333333"
    to_addr = "0x4444444444444444444444444444444444444444"
    amount = 42
    call_data = (
        bytes.fromhex("23b872dd")
        + _addr_word(frm)
        + _addr_word(to_addr)
        + _u256(amount)
    )
    op = _make_op(call_data=call_data)
    transfers = extract_inner_transfers(op)
    assert len(transfers) == 1
    assert transfers[0].from_address == frm
    assert transfers[0].to_address == to_addr
    assert transfers[0].amount_raw == amount
    assert transfers[0].selector == "transferFrom"


def test_extract_inner_transfer_unknown_selector() -> None:
    """callData with non-transfer selector → empty list."""
    op = _make_op(call_data=bytes.fromhex("deadbeef") + b"\x00" * 64)
    assert extract_inner_transfers(op) == []


def test_extract_inner_transfer_empty_calldata() -> None:
    """Empty callData → empty list (no crash)."""
    op = _make_op(call_data=b"")
    assert extract_inner_transfers(op) == []


def test_malformed_bundle_returns_empty() -> None:
    """Garbage bytes after the selector → graceful [] (not crash)."""
    bad = "0x1fad948c" + "deadbeef"  # truncated, no valid array
    assert decompose_user_ops(bad, ENTRYPOINT_V06) == []


def test_none_input_returns_empty() -> None:
    assert decompose_user_ops(None, ENTRYPOINT_V06) == []
    assert decompose_user_ops("0x", ENTRYPOINT_V06) == []


def test_is_aa_wallet_none_adapter() -> None:
    """No adapter → conservative False."""
    assert is_aa_wallet("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", None) is False


def test_is_aa_wallet_known_factory_creator() -> None:
    """Adapter says creator is a known AA factory → True."""
    factory = next(iter(KNOWN_AA_FACTORIES))  # any known factory

    class FakeAdapter:
        def get_contract_creator(self, addr: str) -> str:
            return factory

    assert is_aa_wallet("0xbeef" + "00" * 18, FakeAdapter()) is True


def test_is_aa_wallet_unknown_creator() -> None:
    """Adapter says creator is some random EOA → False."""

    class FakeAdapter:
        def get_contract_creator(self, addr: str) -> str:
            return "0x9999999999999999999999999999999999999999"

    assert is_aa_wallet("0xbeef" + "00" * 18, FakeAdapter()) is False


def test_is_aa_wallet_garbage_input() -> None:
    """Non-string address → False."""

    class FakeAdapter:
        def get_contract_creator(self, addr: str) -> str:
            return next(iter(KNOWN_AA_FACTORIES))

    assert is_aa_wallet(None, FakeAdapter()) is False  # type: ignore[arg-type]
    assert is_aa_wallet("", FakeAdapter()) is False
