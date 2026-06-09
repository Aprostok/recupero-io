"""Tests for ERC-4337 user-op decomposition (v0.32.1 trace gap A).

Each test builds a calldata blob with the documented ABI encoding
to verify the decoder extracts the right UserOps and inner transfers.
"""

from __future__ import annotations

from recupero.trace.erc4337 import (
    ENTRYPOINT_V06,
    ENTRYPOINT_V07,
    EXECUTE_BATCH_SELECTOR,
    EXECUTE_BATCH_VALUE_SELECTOR,
    EXECUTE_SELECTOR,
    EXECUTE_WITH_OP_SELECTOR,
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


# ---- v0.39: execute() wrapper unwrap (the real-world AA path) ---- #


def _transfer_cd(to: str, amount: int) -> bytes:
    return bytes.fromhex("a9059cbb") + _addr_word(to) + _u256(amount)


def _transfer_from_cd(frm: str, to: str, amount: int) -> bytes:
    return bytes.fromhex("23b872dd") + _addr_word(frm) + _addr_word(to) + _u256(amount)


def _execute_cd(target: str, value: int, inner: bytes, *,
                selector: str = EXECUTE_SELECTOR, op: int | None = None) -> bytes:
    """ABI-encode execute(address,uint256,bytes[,uint8]). When ``op`` is given
    (Kernel's execute(...,uint8)), the head has 4 words and the bytes offset is
    0x80; otherwise 3 words and 0x60."""
    if op is None:
        head = _addr_word(target) + _u256(value) + _u256(0x60)
    else:
        head = _addr_word(target) + _u256(value) + _u256(0x80) + _u256(op)
    return bytes.fromhex(selector[2:]) + head + _encode_bytes_field(inner)


_TOKEN = "0xdac17f958d2ee523a2206206994597c13d831ec7"   # USDT-like
_VICTIM_OUT = "0x2222222222222222222222222222222222222222"


def test_execute_unwraps_erc20_transfer_and_sets_token() -> None:
    """THE key v0.39 capability: execute(token, 0, transfer(to, amt)) →
    InnerTransfer with token = the unwrapped target (was blank pre-v0.39)."""
    op = _make_op(call_data=_execute_cd(_TOKEN, 0, _transfer_cd(_VICTIM_OUT, 5_000_000)))
    transfers = extract_inner_transfers(op)
    assert len(transfers) == 1
    t = transfers[0]
    assert t.selector == "transfer"
    assert t.token == _TOKEN          # <-- the smart account's execute target
    assert t.to_address == _VICTIM_OUT
    assert t.amount_raw == 5_000_000
    assert t.from_address == op.sender


def test_execute_unwraps_transfer_from() -> None:
    op = _make_op(call_data=_execute_cd(
        _TOKEN, 0, _transfer_from_cd(
            "0x3333333333333333333333333333333333333333", _VICTIM_OUT, 42)))
    transfers = extract_inner_transfers(op)
    assert len(transfers) == 1
    assert transfers[0].selector == "transferFrom"
    assert transfers[0].token == _TOKEN
    assert transfers[0].from_address == "0x3333333333333333333333333333333333333333"
    assert transfers[0].to_address == _VICTIM_OUT


def test_execute_native_value_transfer() -> None:
    """execute(recipient, value>0, empty) → a NATIVE transfer to recipient."""
    recipient = "0x4444444444444444444444444444444444444444"
    op = _make_op(call_data=_execute_cd(recipient, 5 * 10**18, b""))
    transfers = extract_inner_transfers(op)
    assert len(transfers) == 1
    t = transfers[0]
    assert t.selector == "execute"
    assert t.token == ""              # native asset
    assert t.to_address == recipient
    assert t.amount_raw == 5 * 10**18
    assert t.from_address == op.sender


def test_kernel_execute_with_op_selector_unwraps() -> None:
    """Kernel/ZeroDev execute(address,uint256,bytes,uint8) (0x51945447) unwraps
    via the same head offsets."""
    op = _make_op(call_data=_execute_cd(
        _TOKEN, 0, _transfer_cd(_VICTIM_OUT, 999),
        selector=EXECUTE_WITH_OP_SELECTOR, op=0))
    transfers = extract_inner_transfers(op)
    assert len(transfers) == 1
    assert transfers[0].token == _TOKEN
    assert transfers[0].amount_raw == 999


def test_execute_unknown_inner_no_value_is_empty() -> None:
    """execute(dest, 0, <non-transfer calldata>) → [] (conservative; no guess)."""
    op = _make_op(call_data=_execute_cd(
        _TOKEN, 0, bytes.fromhex("deadbeef") + b"\x00" * 64))
    assert extract_inner_transfers(op) == []


def test_execute_unknown_inner_with_value_is_native() -> None:
    """execute(dest, value>0, <non-transfer calldata>) → native transfer of the
    attached value to dest (a real movement even though the inner call is opaque)."""
    op = _make_op(call_data=_execute_cd(
        _TOKEN, 100, bytes.fromhex("deadbeef") + b"\x00" * 64))
    transfers = extract_inner_transfers(op)
    assert len(transfers) == 1
    assert transfers[0].selector == "execute"
    assert transfers[0].amount_raw == 100
    assert transfers[0].to_address == _TOKEN


def test_full_handleops_to_execute_to_transfer_end_to_end() -> None:
    """Bundler tx → handleOps → UserOp(execute(token, 0, transfer)) →
    decompose → extract recovers the token-set inner transfer end to end."""
    op = _make_op(
        sender="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        call_data=_execute_cd(_TOKEN, 0, _transfer_cd(_VICTIM_OUT, 7_000_000)),
    )
    cd = _build_handle_ops_calldata([op], beneficiary="0x" + "fe" * 20)
    decoded = decompose_user_ops(cd, ENTRYPOINT_V06)
    assert len(decoded) == 1
    inner = extract_inner_transfers(decoded[0])
    assert len(inner) == 1
    assert inner[0].token == _TOKEN
    assert inner[0].to_address == _VICTIM_OUT
    assert inner[0].amount_raw == 7_000_000
    assert inner[0].from_address == "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


# ---- v0.39: executeBatch unwrap ---- #


def _enc_addr_array(addrs: list[str]) -> bytes:
    return _u256(len(addrs)) + b"".join(_addr_word(a) for a in addrs)


def _enc_uint_array(vals: list[int]) -> bytes:
    return _u256(len(vals)) + b"".join(_u256(v) for v in vals)


def _enc_bytes_array(items: list[bytes]) -> bytes:
    """ABI dynamic bytes[] — [len][off0..][elem0..], offsets relative to the
    slot after the length word (mirrors _read_bytes_array)."""
    n = len(items)
    encoded = [_encode_bytes_field(b) for b in items]
    cursor = 32 * n
    offs = b""
    for enc in encoded:
        offs += _u256(cursor)
        cursor += len(enc)
    return _u256(n) + offs + b"".join(encoded)


def _execute_batch_value_cd(dests, values, datas) -> bytes:
    da, va, ba = _enc_addr_array(dests), _enc_uint_array(values), _enc_bytes_array(datas)
    off_dest = 96
    off_value = off_dest + len(da)
    off_data = off_value + len(va)
    head = _u256(off_dest) + _u256(off_value) + _u256(off_data)
    return bytes.fromhex(EXECUTE_BATCH_VALUE_SELECTOR[2:]) + head + da + va + ba


def _execute_batch_novalue_cd(dests, datas) -> bytes:
    da, ba = _enc_addr_array(dests), _enc_bytes_array(datas)
    off_dest = 64
    off_data = off_dest + len(da)
    head = _u256(off_dest) + _u256(off_data)
    return bytes.fromhex(EXECUTE_BATCH_SELECTOR[2:]) + head + da + ba


def test_execute_batch_value_unwraps_each_call() -> None:
    tok_a, tok_b = "0x" + "a1" * 20, "0x" + "b2" * 20
    to_a, to_b = "0x" + "11" * 20, "0x" + "22" * 20
    cd = _execute_batch_value_cd(
        [tok_a, tok_b], [0, 0], [_transfer_cd(to_a, 10), _transfer_cd(to_b, 20)])
    ts = extract_inner_transfers(_make_op(call_data=cd))
    assert len(ts) == 2
    assert ts[0].token == tok_a and ts[0].to_address == to_a and ts[0].amount_raw == 10
    assert ts[1].token == tok_b and ts[1].amount_raw == 20


def test_execute_batch_novalue_unwraps() -> None:
    tok, to = "0x" + "a1" * 20, "0x" + "11" * 20
    cd = _execute_batch_novalue_cd([tok], [_transfer_cd(to, 5)])
    ts = extract_inner_transfers(_make_op(call_data=cd))
    assert len(ts) == 1 and ts[0].token == tok and ts[0].amount_raw == 5


def test_execute_batch_mixed_native_and_erc20() -> None:
    tok, recipient, to = "0x" + "a1" * 20, "0x" + "cc" * 20, "0x" + "11" * 20
    cd = _execute_batch_value_cd(
        [tok, recipient], [0, 100], [_transfer_cd(to, 5), b""])
    ts = extract_inner_transfers(_make_op(call_data=cd))
    assert len(ts) == 2
    assert ts[0].selector == "transfer" and ts[0].token == tok
    assert ts[1].selector == "executeBatch" and ts[1].token == ""
    assert ts[1].to_address == recipient and ts[1].amount_raw == 100


def test_execute_batch_length_cap_is_safe() -> None:
    """An adversarial batch claiming a huge array length decodes to [] (the cap
    raises internally, caught) — no OOM / quadratic blowup."""
    head = _u256(96) + _u256(128) + _u256(160)
    payload = head + _u256(1000)  # dest array (at off 96) claims 1000 elements
    cd = bytes.fromhex(EXECUTE_BATCH_VALUE_SELECTOR[2:]) + payload
    assert extract_inner_transfers(_make_op(call_data=cd)) == []
