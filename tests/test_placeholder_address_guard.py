"""Tests for the intake-placeholder address guard in run_one.

The Hekla case (real intake submission, May 2026) burned ~$0.15 of
Anthropic budget before producing an empty case stuck in
REVIEW_REQUIRED for 6+ days. Root cause: seed_address was
``0x1234567890123456789012345678901234567890`` — sequential digits
the user filled in to advance the form. The intake form didn't
validate on-chain reachability, and the worker happily ran the
full pipeline against a placeholder.

The guard catches obvious-placeholder patterns at claim time so
the worker fails fast with a clear, actionable error_message
before burning API budget.

Tests run in <50ms total, no DB / no network.
"""

from __future__ import annotations

from recupero.worker.pipeline import _is_obvious_placeholder_address

# ---- known placeholder patterns ---- #


def test_hekla_sequential_pattern() -> None:
    """The Hekla seed: 0x1234567890 repeating four times."""
    assert _is_obvious_placeholder_address(
        "0x1234567890123456789012345678901234567890"
    )


def test_zero_address() -> None:
    """The Ethereum zero address — used to burn tokens, never
    legitimately a victim/suspect wallet."""
    assert _is_obvious_placeholder_address("0x" + "0" * 40)


def test_max_address() -> None:
    """0xfff...fff — another common placeholder sentinel."""
    assert _is_obvious_placeholder_address("0x" + "f" * 40)


def test_repeating_single_digit() -> None:
    """0x111...111, 0xaaa...aaa, etc."""
    for ch in "0123456789abcdef":
        addr = "0x" + ch * 40
        assert _is_obvious_placeholder_address(addr), (
            f"failed to flag obvious placeholder: {addr}"
        )


def test_two_char_cycle() -> None:
    """0x0101...0101 — alternating digits."""
    assert _is_obvious_placeholder_address("0x" + "01" * 20)
    assert _is_obvious_placeholder_address("0x" + "ab" * 20)


def test_four_char_cycle() -> None:
    """0xabcdabcd...abcd — 4-char cycle."""
    assert _is_obvious_placeholder_address("0x" + "abcd" * 10)


def test_dead_beef_sentinel() -> None:
    """A well-known test address."""
    assert _is_obvious_placeholder_address(
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    )


def test_cafe_babe_sentinel() -> None:
    """Another test sentinel."""
    assert _is_obvious_placeholder_address(
        "0xcafebabecafebabecafebabecafebabecafebabe"
    )


def test_case_insensitive() -> None:
    """Mixed-case checksum addresses should still be detected."""
    # Sequential pattern, mixed case
    assert _is_obvious_placeholder_address(
        "0x1234567890123456789012345678901234567890"
    )
    # Dead beef in mixed case
    assert _is_obvious_placeholder_address(
        "0xDeadBeefDeadBeefDeadBeefDeadBeefDeadBeef"
    )


# ---- real addresses should NOT be flagged ---- #


def test_real_address_not_flagged() -> None:
    """A real Ethereum address (derived from a Keccak hash) should
    never match a placeholder pattern."""
    # Sample real addresses from the test fixtures
    assert not _is_obvious_placeholder_address(
        "0x8E3b200f356724299643402148a25FD4B852Bd53"
    )
    assert not _is_obvious_placeholder_address(
        "0x2b22d1A731175a04142fE1bC3c5bbb2B2d813D2F"
    )
    # Real exchange hot wallets
    assert not _is_obvious_placeholder_address(
        "0x28C6c06298d514Db089934071355E5743bf21d60"  # Binance 14
    )


def test_address_containing_placeholder_substring_not_flagged() -> None:
    """An address that *contains* '1234567890' or 'deadbeef' as a
    substring shouldn't be flagged. The detector only matches when
    the ENTIRE body fits a placeholder pattern."""
    # Random hex with sequential substring buried in it
    assert not _is_obvious_placeholder_address(
        "0xa1234567890bcdef0000aaaa11112222333344445555"[:42]
    )
    # Real-ish address that happens to contain 'dead'
    assert not _is_obvious_placeholder_address(
        "0xDeAd0fbCe1234567A89B2Cdef5678901234567890"
    )


# ---- malformed inputs ---- #


def test_empty_string_not_flagged() -> None:
    """Empty / None / non-EVM inputs return False — the chain
    adapter handles their own validation."""
    assert not _is_obvious_placeholder_address("")
    assert not _is_obvious_placeholder_address(None)  # type: ignore[arg-type]


def test_no_0x_prefix_not_flagged() -> None:
    """Bare hex without 0x prefix → not our concern (Solana base58
    addresses don't have the prefix; we'd false-positive otherwise)."""
    assert not _is_obvious_placeholder_address("1234567890" * 4)


def test_wrong_length_not_flagged() -> None:
    """Anything not exactly 0x + 40 hex chars → False. Truncated
    or extended inputs are caller bugs, not placeholder patterns."""
    assert not _is_obvious_placeholder_address("0x1234")
    assert not _is_obvious_placeholder_address("0x" + "0" * 39)
    assert not _is_obvious_placeholder_address("0x" + "0" * 41)


def test_solana_real_address_not_flagged() -> None:
    """A real Solana address (base58, mixed-character) passes through
    as False — only obvious-placeholder shapes flip True."""
    assert not _is_obvious_placeholder_address(
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"  # Token program
    )


def test_solana_system_program_flagged() -> None:
    """v0.17.4: the Solana system program (32 base58 ones) is exactly
    the kind of sentinel operators paste into the intake form — fail
    fast before burning AI budget on an empty case. Same rationale as
    the 0x000…000 zero address on EVM."""
    assert _is_obvious_placeholder_address(
        "11111111111111111111111111111111"  # System program
    )
    assert _is_obvious_placeholder_address(
        "1nc1nerator11111111111111111111111111111111"  # Incinerator
    )


# ---- edge: realistic-looking but actually placeholder ---- #


def test_five_char_cycle() -> None:
    """An 8-char cycle: 0x12345678 repeating 5 times.
    Confirms longer cycles still get caught."""
    assert _is_obvious_placeholder_address("0x" + "12345678" * 5)
