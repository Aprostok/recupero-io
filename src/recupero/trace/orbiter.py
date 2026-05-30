"""Orbiter Finance amount-suffix destination decoder (go-deeper #4, Wave B).

Orbiter encodes the DESTINATION network in the trailing digits of the
smallest-unit (wei) transfer amount — an "identification code". This module
inverts that encoding to recover the intended destination chain of a transfer
into an Orbiter Maker.

THE RULE (verified two ways — spec AND real chain data):

  * SPEC: Orbiter-Finance/orbiter-sdk ``src/utils/core.ts``
    (``getPTextFromTAmount`` + ``SIZE_OP.P_NUMBER == 4``, sha256
    0bbc410dcd48050b1709d35fcbc74a6fbc417e873b28c03663a2df6a2c2c0502) takes
    the LAST FOUR digits of the integer (smallest-unit) amount as the code.

  * REAL DATA: 454 inbound deposits to the highest-volume Maker
    (0x80C6…bCF8) on Ethereum show the four-digit code is always of the form
    ``9000 + internalId`` (e.g. 9002→Arbitrum ×174, 9007→Optimism ×109,
    9021→Base ×118, 9019→Scroll, 9023→Linea). The leading ``9`` is a marker:
    the +9000 offset is applied UPSTREAM of core.ts (core.ts slices the
    formatted code verbatim). 95% of real inbound deposits carry it; the rest
    are ``0000`` (no flag). Requiring the ``9xxx`` marker is therefore also a
    strong false-positive gate — a coincidental amount almost never ends in
    ``90NN`` where NN is a live Orbiter internalId.

  * CODE → CHAIN: ``internalId`` (== code) maps to a chain via two byte-exact
    sources that AGREE on their overlap (1→Ethereum, 2→Arbitrum, 6→Polygon,
    7→Optimism, 14→zkSync Era, 15→BNB) — the historical orbiter-sdk
    CHAIN_INDEX and the live Orbiter API ``/sdk/chains`` (sha256
    a7eb3315513c0fa79ae21e766ee945f097972d7360c4707967f53f160c95b17e), which
    resolves the newer high-volume codes (21→Base, 19→Scroll, 23→Linea, …).
    See scripts/_v033_orbiter_decoder_provenance.md for the full derivation.

DEGRADATION (never fabricate a destination):
  * Source chain is an Orbiter "limit-number" chain (zksync / immutablex /
    dydx): the code sits at a different offset that depends on JS-regex
    zero-stripping that does not port cleanly — return None (no claim). The
    same-address lock-and-mint matcher still handles continuation.
  * No ``9xxx`` marker (e.g. trailing 0000), amount shorter than 4 digits, or
    a non-integer amount → None.
  * Marker present but ``internalId`` not in our verified map (a chain Orbiter
    added that we don't yet track) → an ``OrbiterDestination`` IS returned (it
    IS a confirmed Orbiter cross-chain deposit) but ``orbiter_chain`` /
    ``our_chain`` are None — we confirm the handoff without naming a chain.

FORENSIC POSTURE: a decoded chain is a "medium"-confidence LEAD, NEVER "high"
— it is the destination the sender ENCODED (intent), confirmed in practice
only when the same-address lock-and-mint matcher finds the corresponding
inflow there. Callers MUST gate this on a recognized Orbiter Maker label;
running it on an arbitrary transfer would risk a coincidental ``9xxx`` match.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "ORBITER_CODE_TO_CHAIN",
    "OrbiterDestination",
    "decode_orbiter_destination",
]

# Number of trailing digits carrying the code (SIZE_OP.P_NUMBER) and the
# marker offset (empirically 9000 across 454 real deposits).
_P_NUMBER = 4
_MARKER_OFFSET = 9000

# internalId (== code) -> (Orbiter chain name, our Chain enum value | None).
# Merged from the byte-exact orbiter-sdk CHAIN_INDEX (historical codes 1-17)
# and the live Orbiter API /sdk/chains (current codes incl. 18+). Where both
# define a code they agree. our_chain is None when the chain is non-EVM or not
# in recupero's Chain enum (we confirm the deposit but can't target a search).
# Note: internalId 13 was historically "boba" (orbiter-sdk) and is "NERO" in
# the current API — both map to our_chain None, so the relabel is cosmetic.
ORBITER_CODE_TO_CHAIN: dict[int, tuple[str, str | None]] = {
    1: ("Ethereum", "ethereum"),
    2: ("Arbitrum", "arbitrum"),
    3: ("zkSync Lite", "zksync"),
    4: ("Starknet", None),
    5: ("Ethereum", "ethereum"),
    6: ("Polygon", "polygon"),
    7: ("Optimism", "optimism"),
    8: ("ImmutableX", None),
    9: ("Loopring", None),
    10: ("Metis", "metis"),
    11: ("dYdX", None),
    12: ("ZKSpace", None),
    13: ("NERO", None),
    14: ("zkSync Era", "zksync"),
    15: ("BNB Chain", "bsc"),
    16: ("Arbitrum Nova", None),
    17: ("Polygon zkEVM", "polygon_zkevm"),
    19: ("Scroll", "scroll"),
    20: ("Taiko", None),
    21: ("Base", "base"),
    23: ("Linea", "linea"),
    29: ("Hyperliquid", None),
    30: ("Zora", None),
    31: ("Manta", "manta"),
    34: ("HPP", None),
    39: ("Popchain", None),
    45: ("MegaETH", None),
    51: ("Solana", None),
    52: ("Morph", None),
    57: ("BOB", None),
    62: ("Sophon", None),
    63: ("Ink", None),
    69: ("JuChain", None),
    73: ("ENI", None),
    79: ("Tron", None),
    82: ("ApeChain", None),
    90: ("Sui", None),
    92: ("HashKey", None),
    98: ("Soneium", None),
}

# --- Faithful port of orbiter-sdk core.ts pText EXTRACTION (sha256
# 0bbc410dcd48050b1709d35fcbc74a6fbc417e873b28c03663a2df6a2c2c0502), VERIFIED
# byte-identical against the reference JS (run via node) on 136 vectors — see
# tests/fixtures/orbiter_ptext_reference.json + test_v034_orbiter_limit_port.py.
#
# Most chains take the LAST 4 digits of the smallest-unit amount. The
# "limit-number" chains (zkSync LITE, ImmutableX, dYdX — packed-balance /
# StarkEx L2s that cap the encodable bits) instead take the 4 digits at a
# ``validDigit`` offset derived from MAX_BITS. CRITICAL: our Chain enum
# ``zksync`` is zkSync ERA (chainId 324, full EVM, the SDK's "zksync2") — NOT
# zkSync Lite — so it is NON-limit and uses the last-4 path. (Wave B wrongly
# degraded it to None; this restores correct decoding for zkSync-Era sources.)
# The genuine limit chains are not in our Chain enum, so for real recupero
# source chains the extraction is always last-4; the offset path is ported for
# completeness + correctness should those chains ever be traced.
_SDK_LIMIT_CHAINS: dict[str, int] = {
    "zksync_lite": 35,   # zkSync Lite (StarkWare packed balance)
    "immutablex": 28,
    "dydx": 28,          # dYdX v3 (StarkEx)
}


def _sdk_remove_sides_zero(s: str) -> str:
    """Port of core.ts ``removeSidesZero``: strip leading zeros (keep the first
    significant digit) and trailing zeros (keep the last significant digit)."""
    s = re.sub(r"^0+(\d)", r"\1", s)
    return re.sub(r"(\d)0+$", r"\1", s)


def _sdk_extract_trailing4(amount_str: str, *, limit_max_bits: int | None) -> str | None:
    """Port of core.ts ``getPTextFromTAmount`` pText extraction. Returns the
    4-digit identification string, or None when the amount is too short.

    For a limit-number chain (``limit_max_bits`` set) whose amount is longer
    than its ``validDigit`` count, the code sits at ``amount[:validDigit][-4:]``;
    otherwise (and for every non-limit chain) it is the last 4 digits. The
    ``validDigit`` derivation mirrors ``AmountValidDigits`` exactly: when the
    de-zeroed amount exceeds the chain's max digit count, the JS returns an
    error string and the ``amountLength > validDigit`` comparison is NaN-false,
    so the code falls through to last-4 (replicated here by leaving the limit
    branch un-taken).
    """
    if len(amount_str) < _P_NUMBER:
        return None
    if limit_max_bits is not None:
        region_max = 2 ** limit_max_bits - 1
        max_digits = len(str(region_max))
        ramount = _sdk_remove_sides_zero(amount_str)
        if len(ramount) <= max_digits:
            valid_digit = max_digits - 1 if int(ramount) > region_max else max_digits
            if len(amount_str) > valid_digit:
                return amount_str[:valid_digit][-_P_NUMBER:]
    return amount_str[-_P_NUMBER:]


@dataclass(frozen=True)
class OrbiterDestination:
    """Decoded Orbiter destination — a medium-confidence forensic lead.

    A non-None result means a valid Orbiter identification marker (9xxx) was
    present, i.e. the transfer IS an Orbiter cross-chain deposit. ``our_chain``
    is the chain to search for the same-address continuation, or None when the
    destination chain is one recupero doesn't track.
    """

    code: int                    # Orbiter internalId (trailing4 - 9000)
    orbiter_chain: str | None    # Orbiter's name for the destination, or None
    our_chain: str | None        # our Chain enum value, or None if untracked
    confidence: str = "medium"   # NEVER "high"


def decode_orbiter_destination(
    amount_raw: str | int,
    *,
    source_chain: str | None = None,
) -> OrbiterDestination | None:
    """Recover the Orbiter destination from a transfer's smallest-unit amount.

    ``amount_raw`` is the integer amount in the token's smallest unit (the
    ``Transfer.amount_raw`` string — exact, no rounding). Returns ``None`` when
    the transfer is not a decodable Orbiter cross-chain deposit (no 9xxx marker
    / too short / non-integer). The trailing-code extraction is the byte-exact,
    node-verified port of orbiter-sdk ``getPTextFromTAmount`` (last-4 for normal
    chains; the ``validDigit`` offset for the genuine limit chains). Pure +
    side-effect free.

    Callers MUST gate this on a recognized Orbiter Maker label (see module
    docstring) — an ungated call risks a coincidental marker match.
    """
    s = str(amount_raw).strip()
    if not s.isdigit():
        return None

    limit_max_bits = (
        _SDK_LIMIT_CHAINS.get(source_chain.lower()) if source_chain else None
    )
    ptext = _sdk_extract_trailing4(s, limit_max_bits=limit_max_bits)
    if ptext is None:
        return None
    trailing = int(ptext)
    # Require the 9xxx identification marker (9000 + internalId). This both
    # decodes the chain AND gates out coincidental amounts.
    if not (_MARKER_OFFSET < trailing < _MARKER_OFFSET + 1000):
        return None
    code = trailing - _MARKER_OFFSET

    mapped = ORBITER_CODE_TO_CHAIN.get(code)
    if mapped is None:
        # Confirmed Orbiter deposit, but a chain we don't have mapped yet.
        return OrbiterDestination(code=code, orbiter_chain=None, our_chain=None)
    orbiter_chain, our_chain = mapped
    return OrbiterDestination(code=code, orbiter_chain=orbiter_chain, our_chain=our_chain)
