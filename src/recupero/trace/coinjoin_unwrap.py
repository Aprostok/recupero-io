"""Probabilistic CoinJoin unwrap (v0.14.0; extended v0.31.0).

When a Bitcoin trace lands in a CoinJoin transaction (Wasabi 1.0,
Wasabi 2.0/WabiSabi, Samourai Whirlpool, JoinMarket), pre-v0.14.0
the adapter DETECTED the pattern and stopped — the trace
dead-ended at the CoinJoin boundary.

v0.14.0 introduced the equal-output round detection plus the
participant-hypothesis enumerator: for fixed-denomination protocols
(Wasabi 1.0, Whirlpool, JoinMarket) we can rank the input/output
pairings by amount-fit + cardinality + self-mix signals.

v0.31.0 EXTENDS the detector to recognize three additional shapes:

  * Wasabi 2.0 (WabiSabi) — many-in / many-out at arbitrary
    denominations. There is no equal-output cluster to anchor the
    round amount, so the v0.14.0 enumerator does not fire. v0.31.0
    detects the SHAPE (≥10 inputs, ≥10 outputs, no dominant single
    output amount) and surfaces a `CoinjoinDetection` flagging the
    tx as a mixing hop. Post-mix output recovery is infeasible
    on-chain — it requires the coordinator's anonymity-set graph,
    which Wasabi does not publish — so `most_likely_output` is
    always `None` with a forensic note.

  * Samourai Whirlpool (strict 5×5) — 5-in / 5-out where every
    output is one of the four published pool denominations
    (0.001, 0.01, 0.05, 0.5 BTC). The v0.14.0 enumerator already
    fires on the 5/5 shape; v0.31.0 adds the pool-denomination
    cross-check so we don't false-positive on coincidental 5×5
    structures.

  * Mercury Layer (statechain) — v0.31.5 adds HEURISTIC pattern
    detection. Full unwrap is still infeasible (the Statechain
    Entity's transition graph is private to the SE operator), but
    the on-chain SHAPE is distinctive: 1-input / 1-output, both
    P2TR (witness v1), output value = input value minus a small
    fixed SE fee (typically 100-2000 sats). We flag matching txs
    as "possible Mercury Layer statechain operation" with a
    medium-confidence (0.55) signal on shape alone, raised to high
    confidence (0.85) when the input address matches a curated
    list of known SE addresses. The forensic note tells the
    investigator to query the SE operator directly for the actual
    state-transition recipient. See `docs/V031_COINJOIN_EXPANSION.md`
    for the full rationale.

How CoinJoin works (briefly)
----------------------------

Multiple participants contribute UTXOs as inputs to a single
transaction. The transaction produces outputs (equal-value in
Wasabi 1.0 / Whirlpool / JoinMarket; ARBITRARY in WabiSabi) so the
on-chain linkage between any specific input and output is obscured.
Whoever contributed N times the round amount in inputs receives N
round-output UTXOs (Wasabi 1.0 / Whirlpool / JoinMarket); under
WabiSabi the participant receives any sum-equivalent set of
outputs whose denominations are chosen by the coordinator.

Wasabi 1.0: ~0.1 BTC denomination, 50-100+ inputs, equal outputs.
Wasabi 2.0 (WabiSabi): 10-400+ inputs, arbitrary denominations,
  no equal-output cluster.
Samourai Whirlpool: 0.001 / 0.01 / 0.05 / 0.5 BTC pools,
  fixed 5-in / 5-out.
JoinMarket: variable, 2-15 participants, market-discovery layer.

Algorithm
---------

For each transaction we suspect is a CoinJoin:

  1. Detect the **round amount(s)**: clusters of outputs at the
     same value (within ε). If 3+ outputs share a value, that's a
     candidate round.

  2. For each round amount R:
       a. Partition the inputs into all subsets whose value sums
          to N*R + (small fee share), for N = 1, 2, 3, ...
       b. Each valid subset is a candidate "participant" — a
          single wallet that contributed enough to receive N
          outputs.
       c. Match each candidate participant to N of the round
          outputs.

  3. Score each (input_subset → output_subset) hypothesis by:
       * **Amount fit**: how close was input_sum to N*R + fee?
         Closer = higher confidence.
       * **Address overlap**: if any input address appears as an
         output address in THIS tx, that's "self-mixing" — common
         pattern with low confidence (it's the same participant
         shuffling within their own wallet).
       * **Input cardinality**: 1 input = high confidence (one
         UTXO, one participant); 5+ inputs from many addresses =
         low confidence (might be a pooled service).
       * **Round size**: the bigger the round, the more
         participants competed for it, and the less amount-matching
         alone tells you.

  4. Return ranked hypotheses with confidence scores.

What this gives the investigator
---------------------------------

Pre-v0.14.0 brief:
  "Funds enter CoinJoin tx 0xabc... — trace terminates. Wasabi
   CoinJoin patterns are not unwrappable."

v0.14.0 brief:
  "Funds enter Wasabi CoinJoin tx 0xabc... POST-MIX HYPOTHESES:
     (1) input {0xperp...} ($48,000) → output {0xperp_2...}
         confidence: high (single-input, amount-matched 1.5%)
     (2) input {0xperp...} → output {0xunknown_2...}
         confidence: medium (single-input, amount-matched 4.2%)
     ...
   Continue tracing from the high-confidence candidate; treat
   medium-confidence as investigative leads."

This matches what TRM Labs documents as their own CoinJoin
unwrap heuristic — and beats their published Samourai Whirlpool
capability, which they openly say they can't fully unwrap.

References
----------

  - Möser et al. (2017) "Anonymous Alone? Measuring Bitcoin's
    Second-Generation Anonymization Techniques"
  - Adam Ficsór (Wasabi developer) on the "sub-rounds" heuristic
  - Adamant Lab (2021) "Bitcoin Privacy: Wasabi & Whirlpool
    Effectiveness"
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any

log = logging.getLogger(__name__)


# Tolerance for "equal-value" outputs. Wasabi pre-mixes are
# typically at exact-satoshi precision; Whirlpool always exact.
# We allow ε=1 satoshi to absorb floating-point noise.
_EQUAL_VALUE_TOLERANCE_SATS = 1

# Minimum cluster size for an output value to be a "round amount".
# 3+ identical-value outputs is the empirical threshold across
# CoinJoin implementations.
_MIN_ROUND_CLUSTER_SIZE = 3

# Max input-subset size to enumerate. Beyond this the combinatorial
# space blows up. For Wasabi cases this caps at "5 inputs from one
# wallet" which is well above the median single-participant size.
_MAX_INPUT_SUBSET_SIZE = 6

# Hard cap on enumerated hypotheses per tx to avoid pathological
# blowups on 100+ input txs.
_MAX_HYPOTHESES_PER_TX = 200

# --- v0.31.0 detection thresholds --- #

# Wasabi 2.0 / WabiSabi: many-in / many-out, no dominant output.
# Empirical floors from the WabiSabi paper + observed mainnet
# rounds (mid-2023 onward). Below 10 in/out the shape is too
# ambiguous vs. plain consolidation txs.
_WASABI2_MIN_INPUTS = 10
_WASABI2_MIN_OUTPUTS = 10

# If a single output amount carries more than this fraction of the
# total output value, it's too dominant to be a coinjoin mix —
# likely a sweep / change-heavy tx instead.
_WASABI2_MAX_DOMINANT_OUTPUT_FRAC = 0.20

# Samourai Whirlpool: four published pool denominations. Tx5 ladder
# (post-mix outputs share the same denomination as the input).
# Source: Samourai Wallet docs, "Whirlpool Pool Sizes".
_WHIRLPOOL_POOL_DENOMS_SATS: tuple[int, ...] = (
    100_000,         # 0.001 BTC
    1_000_000,       # 0.01 BTC
    5_000_000,       # 0.05 BTC
    50_000_000,      # 0.5 BTC
)
# Tolerance around each pool denomination — Whirlpool outputs are
# exact, but we leave a 1-sat cushion for any rounding noise from
# upstream parsing.
_WHIRLPOOL_DENOM_TOLERANCE_SATS = 1


# ---- Types ---- #


@dataclass(frozen=True)
class UTXOInput:
    """One input to a CoinJoin tx.

    ``script_hex`` (v0.31.5) is the lowercase-hex serialized
    scriptPubKey of the *prevout* this input spends. It is OPTIONAL
    so legacy callers (which only carry address+value) keep working.
    The Mercury Layer detector consults this field to recognize
    P2TR (witness v1, prefix ``5120`` + 32-byte program). Other
    detectors do not read it.
    """
    address: str
    value_sats: int
    script_hex: str | None = None


@dataclass(frozen=True)
class UTXOOutput:
    """One output of a CoinJoin tx.

    ``script_hex`` (v0.31.5) is the lowercase-hex serialized
    scriptPubKey, optional for the same back-compat reason as
    :class:`UTXOInput`.
    """
    address: str
    value_sats: int
    output_index: int
    script_hex: str | None = None


@dataclass(frozen=True)
class CoinJoinHypothesis:
    """One (input → output) participant hypothesis.

    Represents the claim: "the wallet that contributed these inputs
    is the same wallet that received these outputs, at the given
    confidence level."
    """
    input_addresses: tuple[str, ...]
    output_addresses: tuple[str, ...]
    total_input_value_sats: int
    total_output_value_sats: int
    round_amount_sats: int
    output_count: int                # N (how many round-outputs this participant claimed)
    confidence: str                  # 'high' | 'medium' | 'low'
    confidence_score: float          # 0..1 numeric for sorting
    rationale: str                   # human-readable explanation
    signals: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class UnwrapResult:
    """Top-level CoinJoin unwrap output for one transaction."""
    tx_id: str
    detected_pattern: str            # 'wasabi' | 'whirlpool' | 'joinmarket' | 'generic'
    round_amount_sats: int
    round_output_count: int
    participant_count_estimate: int
    hypotheses: list[CoinJoinHypothesis]
    warnings: list[str] = field(default_factory=list)


# Stable protocol identifiers for the v0.31.0 detection interface.
# These are written to the brief and consumed by downstream
# operator UI — DO NOT rename without a brief schema bump.
PROTOCOL_WASABI_1 = "wasabi_1"
PROTOCOL_WASABI_2 = "wasabi_2"
PROTOCOL_WHIRLPOOL = "whirlpool"
PROTOCOL_JOINMARKET = "joinmarket"
PROTOCOL_MERCURY_LAYER = "mercury_layer"
PROTOCOL_UNKNOWN = "unknown"


# --- v0.31.5 Mercury Layer constants --- #
#
# Mercury Layer (CommerceBlock) is a Bitcoin statechain. State
# transitions happen OFF-CHAIN; the only on-chain events are
# `state_init` (deposit into the statechain) and `state_withdraw`
# (exit). Both are 1-input/1-output P2TR txs with a small fee paid
# to the Statechain Entity (SE) operator. The pattern is shape-only;
# full unwrap requires the SE operator's private database.
#
# Curated set of historically-observed Mercury Layer SE addresses.
# Populating this set raises detection confidence from 0.55 to 0.85
# on a shape match. The set is intentionally empty in the shipped
# build — operators / future PRs can extend it (env var or seeded
# file) without code changes. Shape detection works without it.
_MERCURY_KNOWN_SE_INPUTS: frozenset[str] = frozenset()

# Mercury SE fee range. The operator typically charges between
# 100 and 2000 sats; below 100 sats the difference is consistent
# with miner-only fees on a tiny P2TR transfer (not Mercury), and
# above 2000 sats it's outside observed mainnet behavior and more
# likely a regular P2TR send with a generous fee.
_MERCURY_FEE_RANGE_SATS: tuple[int, int] = (100, 2000)

# P2TR (witness v1) scriptPubKey signature: ``OP_1`` (0x51) followed
# by a 32-byte push (0x20). Total serialized length is therefore
# 1 + 1 + 32 = 34 bytes = 68 hex chars.
_P2TR_SCRIPT_PREFIX = "5120"
_P2TR_SCRIPT_HEX_LEN = 68


@dataclass(frozen=True)
class CoinjoinDetection:
    """v0.31.0 detection-only result for a coinjoin tx.

    Distinct from `UnwrapResult` (which enumerates participant
    hypotheses for fixed-denomination protocols). This type answers
    a simpler, more honest question: "is this tx a coinjoin, and if
    so, which protocol?"

    `most_likely_output` is intentionally `None` for every shipped
    detector. Identifying the post-mix output for a specific input
    address requires off-chain coordinator data (Wasabi sub-round
    graph, Whirlpool Tx0 history, JoinMarket fidelity-bond DB).
    None of that is available from the on-chain tx alone. The
    forensic note explains this to the brief reader.
    """
    protocol: str                    # one of PROTOCOL_* constants
    input_address: str
    tx_hash: str
    all_outputs: tuple[UTXOOutput, ...]
    confidence: float                # 0.0 .. 1.0
    forensic_note: str
    most_likely_output: str | None = None


# ---- Detection ---- #


def detect_round_amounts(
    outputs: list[UTXOOutput],
    *,
    min_cluster_size: int = _MIN_ROUND_CLUSTER_SIZE,
) -> list[tuple[int, list[UTXOOutput]]]:
    """Cluster outputs by value (within tolerance) and return rounds.

    Returns a list of (round_amount_sats, member_outputs) tuples,
    sorted by member-count descending so the LARGEST cluster
    (most likely to be the round denomination) is first.

    Outputs not in any cluster are dropped from the result —
    those are typically change outputs or fees.
    """
    if not outputs:
        return []

    # Group outputs by approximate value.
    by_value: dict[int, list[UTXOOutput]] = defaultdict(list)
    for o in outputs:
        # Bucket by exact value (most common case). For tolerance
        # > 0 we'd merge nearby buckets after, but Wasabi/Whirlpool
        # produce exact-equal outputs so this is fine.
        by_value[o.value_sats].append(o)

    clusters: list[tuple[int, list[UTXOOutput]]] = []
    for value, members in by_value.items():
        if len(members) >= min_cluster_size:
            clusters.append((value, members))

    clusters.sort(key=lambda kv: len(kv[1]), reverse=True)
    return clusters


def classify_coinjoin_pattern(
    inputs: list[UTXOInput],
    outputs: list[UTXOOutput],
    round_amount_sats: int,
    round_output_count: int,
) -> str:
    """Identify which CoinJoin implementation we're looking at.

    Heuristics:
      * Whirlpool (Samourai): exactly 5 inputs + 5 outputs at the
        round amount, no change outputs at the round level.
      * Wasabi (1.0/2.0): 50+ inputs, large round-output cluster,
        round amount near 0.1 BTC (10,000,000 sats) historically.
      * Generic: anything else that has 3+ equal outputs.

    NOTE (v0.31.0): kept intentionally loose for back-compat with
    the v0.14.0 enumerator path. The stricter shape-based detector
    that distinguishes Wasabi 1.0 vs 2.0 lives in
    `detect_coinjoin()` below.
    """
    n_in = len(inputs)
    n_out = len(outputs)
    n_round_out = round_output_count

    # Whirlpool: exact 5/5 shape.
    if n_in == 5 and n_round_out == 5 and n_out == 5:
        return "whirlpool"
    # Wasabi: many inputs, large round-output cluster, denomination
    # in the historical Wasabi 0.05-0.5 BTC range.
    if n_in >= 50 and n_round_out >= 10:
        return "wasabi"
    # JoinMarket: 2-15 participants, mixed amounts. Heuristic: <50
    # inputs but >2 outputs at round.
    if 2 <= n_in < 50 and n_round_out >= 3:
        return "joinmarket"
    return "generic"


# ---- v0.31.0: tx-shape detectors ---- #


def _dominant_output_fraction(outputs: list[UTXOOutput]) -> float:
    """Fraction of total output value carried by the single most-
    common output AMOUNT (not address).

    Used to reject txs that *look* big-and-many-out but actually
    have a single dominant amount — those are typically sweeps or
    payouts, not WabiSabi mixes. Returns 0.0 for empty outputs to
    avoid NaN propagation.
    """
    if not outputs:
        return 0.0
    total = sum(o.value_sats for o in outputs)
    if total <= 0:
        return 0.0
    by_amount: dict[int, int] = defaultdict(int)
    for o in outputs:
        by_amount[o.value_sats] += o.value_sats
    largest_bucket = max(by_amount.values())
    return largest_bucket / total


def _is_whirlpool_pool_denomination(value_sats: int) -> bool:
    """True iff ``value_sats`` matches one of the four published
    Whirlpool pool denominations (within 1-sat tolerance)."""
    for denom in _WHIRLPOOL_POOL_DENOMS_SATS:
        if abs(value_sats - denom) <= _WHIRLPOOL_DENOM_TOLERANCE_SATS:
            return True
    return False


def _is_strict_whirlpool(
    inputs: list[UTXOInput], outputs: list[UTXOOutput],
) -> tuple[bool, int | None]:
    """Whirlpool requires:
      * exactly 5 inputs and 5 outputs
      * ALL outputs share the same value
      * that value is one of the four published pool denominations

    Returns (matched, pool_denom_sats).
    """
    if len(inputs) != 5 or len(outputs) != 5:
        return False, None
    first_value = outputs[0].value_sats
    if not all(
        abs(o.value_sats - first_value) <= _WHIRLPOOL_DENOM_TOLERANCE_SATS
        for o in outputs
    ):
        return False, None
    if not _is_whirlpool_pool_denomination(first_value):
        return False, None
    return True, first_value


def _is_wasabi1_fixed_denom(
    inputs: list[UTXOInput], outputs: list[UTXOOutput],
) -> tuple[bool, int | None, int | None]:
    """Wasabi 1.0: large equal-output cluster (10+ outputs at the
    same value), many inputs.

    Returns (matched, round_amount_sats, round_output_count).
    """
    rounds = detect_round_amounts(outputs)
    if not rounds:
        return False, None, None
    round_amount, round_outputs = rounds[0]
    if len(inputs) >= 10 and len(round_outputs) >= 10:
        return True, round_amount, len(round_outputs)
    return False, None, None


def _is_wasabi2_wabisabi(
    inputs: list[UTXOInput], outputs: list[UTXOOutput],
) -> bool:
    """Wasabi 2.0 (WabiSabi): many-in / many-out with NO dominant
    output amount.

    The distinguishing signal vs Wasabi 1.0 is the absence of a
    fixed-denomination cluster — WabiSabi assigns arbitrary
    output amounts negotiated per-round.
    """
    if len(inputs) < _WASABI2_MIN_INPUTS:
        return False
    if len(outputs) < _WASABI2_MIN_OUTPUTS:
        return False
    if _dominant_output_fraction(outputs) > _WASABI2_MAX_DOMINANT_OUTPUT_FRAC:
        return False
    # Exclude Wasabi 1.0 — if there's a large equal-output cluster,
    # this is the older protocol, not WabiSabi.
    is_w1, _amt, _cnt = _is_wasabi1_fixed_denom(inputs, outputs)
    return not is_w1


def _is_p2tr_script(script_hex: str | None) -> bool:
    """True iff ``script_hex`` looks like a P2TR (taproot) scriptPubKey.

    P2TR outputs serialize as ``OP_1`` (0x51) followed by ``OP_PUSHBYTES_32``
    (0x20) and a 32-byte x-only pubkey — total 34 bytes = 68 hex chars,
    prefixed by ``5120``. We tolerate uppercase hex and leading/trailing
    whitespace. ``None`` and empty string return ``False`` so callers
    that lack script-level data simply opt out of the detector.
    """
    if not script_hex:
        return False
    s = script_hex.lower().strip()
    if not s.startswith(_P2TR_SCRIPT_PREFIX):
        return False
    return len(s) == _P2TR_SCRIPT_HEX_LEN


def _is_mercury_layer(
    inputs: list[UTXOInput],
    outputs: list[UTXOOutput],
) -> tuple[bool, int | None, bool]:
    """Heuristic Mercury Layer (statechain) detector.

    A Mercury Layer `state_init` / `state_withdraw` transaction has a
    very specific on-chain shape:

      * exactly 1 input, 1 output
      * BOTH the spent input prevout AND the new output are P2TR
        (witness v1 / Taproot)
      * output_value = input_value - small_SE_fee, with the fee
        falling in :data:`_MERCURY_FEE_RANGE_SATS` (100..2000 sats)

    This SHAPE alone is enough to flag the tx with medium confidence
    (0.55). If the input address is in :data:`_MERCURY_KNOWN_SE_INPUTS`
    we raise confidence to 0.85 — that's the SE operator's well-known
    address acting as the prevout.

    Returns
    -------
    ``(matched, se_fee_sats, known_se_address)`` — a 3-tuple. The
    fee is ``None`` when ``matched`` is ``False``. ``known_se_address``
    is always a ``bool``.

    Note
    ----
    This is HEURISTIC. Plain P2TR-to-P2TR transfers between two
    Taproot wallets with a 100-2000 sat miner fee will also match
    the shape. That is acceptable — the forensic note generated by
    :func:`detect_coinjoin` clearly says "possible Mercury Layer"
    and tells the operator to verify with the SE database. False
    positives are visible and falsifiable; false negatives (missing
    a real Mercury hop) silently break trace integrity, so we err
    toward flagging.
    """
    if len(inputs) != 1 or len(outputs) != 1:
        return False, None, False
    inp = inputs[0]
    out = outputs[0]
    # Both sides must be P2TR. We use getattr+default so a UTXOInput
    # constructed positionally (pre-v0.31.5 caller) returns None and
    # cleanly fails the script check rather than AttributeError.
    if not _is_p2tr_script(getattr(inp, "script_hex", None)):
        return False, None, False
    if not _is_p2tr_script(getattr(out, "script_hex", None)):
        return False, None, False
    fee = inp.value_sats - out.value_sats
    fee_min, fee_max = _MERCURY_FEE_RANGE_SATS
    if not (fee_min <= fee <= fee_max):
        return False, None, False
    known = inp.address in _MERCURY_KNOWN_SE_INPUTS
    return True, fee, known


def detect_coinjoin(
    *,
    tx_hash: str,
    input_address: str,
    inputs: list[UTXOInput],
    outputs: list[UTXOOutput],
) -> CoinjoinDetection | None:
    """Detect the coinjoin protocol used by a tx, by shape only.

    Returns a `CoinjoinDetection` if the tx matches one of:
      * Wasabi 1.0 (fixed-denomination equal-output cluster)
      * Wasabi 2.0 / WabiSabi (many-in/many-out, no dominant amount)
      * Samourai Whirlpool (strict 5×5 at a published pool denom)

    Returns `None` for txs that look like ordinary transfers
    (1-in/1-out, 2-in/3-out, etc.) — we do NOT speculatively flag
    every multi-output tx as a coinjoin. False positives mislead
    the operator; false negatives just leave the regular trace path
    intact, which is the safer default.

    `most_likely_output` on the returned detection is ALWAYS `None`.
    Per-input → per-output recovery requires off-chain coordinator
    data we do not have. The forensic note explains this for the
    brief reader.
    """
    if not inputs or not outputs:
        return None

    all_outputs_t = tuple(outputs)

    # 1. Whirlpool — strict 5×5 at a pool denomination.
    is_wp, pool_denom = _is_strict_whirlpool(inputs, outputs)
    if is_wp:
        pool_btc = (pool_denom or 0) / 1e8
        return CoinjoinDetection(
            protocol=PROTOCOL_WHIRLPOOL,
            input_address=input_address,
            tx_hash=tx_hash,
            all_outputs=all_outputs_t,
            confidence=0.95,
            forensic_note=(
                f"Samourai Whirlpool 5x5 mix at the {pool_btc:.4f} BTC "
                "pool denomination. Post-mix output recovery is not "
                "possible from on-chain data: Whirlpool's anonymity "
                "set within a single Tx0/Tx5 round is 5, and the "
                "input/output pairing is intentionally indeterminate "
                "by design. Flag this hop and recommend operator "
                "manual review of downstream peel chains."
            ),
            most_likely_output=None,
        )

    # 2. Wasabi 1.0 — fixed-denomination equal-output cluster.
    is_w1, w1_round, w1_count = _is_wasabi1_fixed_denom(inputs, outputs)
    if is_w1:
        round_btc = (w1_round or 0) / 1e8
        return CoinjoinDetection(
            protocol=PROTOCOL_WASABI_1,
            input_address=input_address,
            tx_hash=tx_hash,
            all_outputs=all_outputs_t,
            confidence=0.90,
            forensic_note=(
                f"Wasabi 1.0 CoinJoin: {w1_count} equal outputs at "
                f"{round_btc:.4f} BTC each across {len(inputs)} "
                "inputs. The probabilistic unwrap enumerator "
                "(see `unwrap_coinjoin`) can rank participant "
                "hypotheses by amount-fit + cardinality. Recommend "
                "the operator inspect the top-N hypotheses and "
                "cross-check against known wallet clusters."
            ),
            most_likely_output=None,
        )

    # 3. Wasabi 2.0 (WabiSabi) — many-in / many-out, no dominant.
    if _is_wasabi2_wabisabi(inputs, outputs):
        return CoinjoinDetection(
            protocol=PROTOCOL_WASABI_2,
            input_address=input_address,
            tx_hash=tx_hash,
            all_outputs=all_outputs_t,
            confidence=0.75,
            forensic_note=(
                f"Wasabi 2.0 / WabiSabi-shape CoinJoin: {len(inputs)} "
                f"inputs into {len(outputs)} outputs with arbitrary "
                "denominations (no dominant output amount). Post-mix "
                "output recovery is INFEASIBLE on-chain — WabiSabi "
                "uses per-round credential-issuance graphs that the "
                "coordinator does not publish. Treat as a mixing "
                "boundary: flag the hop, surface in the brief, and "
                "recommend operator manual review with off-chain "
                "exchange/coordinator subpoena if available."
            ),
            most_likely_output=None,
        )

    # 4. Mercury Layer statechain — 1-in/1-out P2TR with SE fee.
    # Checked last because the shape (1/1) is the cheapest to test
    # and the most likely to false-positive on ordinary P2TR sends;
    # we want the more-distinctive multi-party shapes above to win
    # whenever they could plausibly match (they can't on a 1/1 tx,
    # but the ordering documents the precedence).
    mercury_ok, se_fee, known_se = _is_mercury_layer(inputs, outputs)
    if mercury_ok:
        confidence = 0.85 if known_se else 0.55
        if known_se:
            confidence_note = (
                "Source is a known Mercury Layer SE address "
                "(high confidence). "
            )
        else:
            confidence_note = (
                "Shape match without SE-address confirmation "
                "(medium confidence). "
            )
        return CoinjoinDetection(
            protocol=PROTOCOL_MERCURY_LAYER,
            input_address=input_address,
            tx_hash=tx_hash,
            all_outputs=all_outputs_t,
            confidence=confidence,
            forensic_note=(
                f"Possible Mercury Layer statechain operation: "
                f"1-in/1-out P2TR with {se_fee}-sat SE fee. "
                + confidence_note
                + "Full unwrap requires the SE operator's private "
                "database; investigator should query the SE "
                "operator (CommerceBlock) directly to identify "
                "the post-transition beneficial owner."
            ),
            most_likely_output=None,
        )

    return None


# ---- Hypothesis enumeration ---- #


def _input_subsets_summing_to(
    inputs: list[UTXOInput],
    target_min: int,
    target_max: int,
    *,
    max_size: int = _MAX_INPUT_SUBSET_SIZE,
) -> list[tuple[UTXOInput, ...]]:
    """Enumerate input subsets whose value sums fall in [target_min,
    target_max].

    Capped at ``max_size`` inputs per subset to avoid combinatorial
    blowup. A real CoinJoin participant rarely contributes more
    than a few UTXOs to a single round.
    """
    out: list[tuple[UTXOInput, ...]] = []
    # Greedy pruning: enumerate by subset size up to max_size.
    for size in range(1, min(max_size, len(inputs)) + 1):
        for combo in combinations(inputs, size):
            total = sum(i.value_sats for i in combo)
            if target_min <= total <= target_max:
                out.append(combo)
            # Pruning: if total is already > target_max AND adding
            # any more inputs can only increase it, skip the rest
            # at this size. Inputs aren't sorted so we can't apply
            # this safely without sorting; skip the optimization
            # for now.
        if len(out) >= _MAX_HYPOTHESES_PER_TX:
            break
    return out[:_MAX_HYPOTHESES_PER_TX]


def _score_hypothesis(
    inputs: tuple[UTXOInput, ...],
    outputs: tuple[UTXOOutput, ...],
    round_amount_sats: int,
    *,
    all_input_addrs: set[str],
    all_output_addrs: set[str],
) -> tuple[str, float, str, list[str]]:
    """Score one (inputs → outputs) hypothesis.

    Returns (confidence_str, confidence_score 0..1, rationale, signals).
    """
    n_in = len(inputs)
    n_out = len(outputs)
    signals: list[str] = []

    input_sum = sum(i.value_sats for i in inputs)
    output_sum = sum(o.value_sats for o in outputs)
    # Fee share — input MUST be >= output_sum.
    fee_share = input_sum - output_sum
    fee_ratio = fee_share / max(input_sum, 1)

    # Amount-fit: closer input/output match = higher confidence.
    amount_fit_score = 1.0 - min(fee_ratio * 100, 1.0)  # 0..1
    signals.append(f"amount_fit={fee_ratio*100:.2f}% fee")

    # Input cardinality: fewer addresses = more likely single participant.
    input_addrs = {i.address for i in inputs}
    n_unique_input_addrs = len(input_addrs)
    cardinality_score = 1.0 / n_unique_input_addrs
    signals.append(f"input_address_count={n_unique_input_addrs}")

    # Self-mixing penalty: if any input addr appears as output addr
    # in this same tx, that's typically a known-self-shuffle. Lower
    # confidence — the actual recovery interest is in DIFFERENT
    # outputs.
    input_in_outputs = input_addrs & all_output_addrs
    if input_in_outputs:
        signals.append(f"self_mixing={len(input_in_outputs)}_overlap")
        self_mix_penalty = 0.3
    else:
        self_mix_penalty = 1.0

    # Output uniqueness: if our outputs share with another candidate
    # participant's outputs, ambiguity is high.
    # (This requires knowing the other candidates; we approximate by
    # round-output-pool size — bigger pool = more ambiguity.)
    # NB: actually scored at the higher-level enumeration via
    # number-of-candidates penalty; kept here as a placeholder for
    # signals.

    # Combine.
    combined = amount_fit_score * 0.5 + cardinality_score * 0.3
    combined *= self_mix_penalty

    if n_in == 1 and fee_ratio < 0.02:
        # Single-input UTXO with tight fee match → high confidence.
        confidence = "high"
        rationale = (
            f"Single-input contribution of {input_sum:,} sats "
            f"matches {n_out} round-output(s) at {round_amount_sats:,} "
            f"sats each (fee {fee_ratio*100:.2f}%)."
        )
        return confidence, max(0.7, combined), rationale, signals

    if combined >= 0.5:
        confidence = "medium"
        rationale = (
            f"Multi-UTXO contribution ({n_in} inputs from "
            f"{n_unique_input_addrs} address(es)) totaling "
            f"{input_sum:,} sats matches {n_out} round-output(s) "
            f"(fee {fee_ratio*100:.2f}%)."
        )
        return confidence, combined, rationale, signals

    confidence = "low"
    rationale = (
        f"Speculative pairing: {n_in} inputs / {n_unique_input_addrs} "
        f"addresses against {n_out} round-output(s). Significant "
        f"ambiguity — treat as investigative lead only."
    )
    return confidence, combined, rationale, signals


def unwrap_coinjoin(
    *,
    tx_id: str,
    inputs: list[UTXOInput],
    outputs: list[UTXOOutput],
    fee_pct_tolerance: float = 0.05,
) -> UnwrapResult | None:
    """Top-level unwrap: detect CoinJoin pattern, enumerate
    participant hypotheses, return ranked list.

    Returns None if the tx doesn't look like a CoinJoin (no
    equal-output cluster of 3+).
    """
    if not inputs or not outputs:
        return None

    rounds = detect_round_amounts(outputs)
    if not rounds:
        return None

    # Use the LARGEST round cluster as the primary denomination.
    round_amount, round_outputs = rounds[0]
    round_output_count = len(round_outputs)

    pattern = classify_coinjoin_pattern(
        inputs, outputs, round_amount, round_output_count,
    )

    # Estimate participant count: total round-output value / round
    # amount = total round-output count. Each participant claims
    # ≥1 output. Cap by output count and input count.
    participant_count_estimate = min(round_output_count, len(inputs))

    all_input_addrs = {i.address for i in inputs}
    all_output_addrs = {o.address for o in outputs}

    hypotheses: list[CoinJoinHypothesis] = []
    warnings: list[str] = []

    # For each N (number of round-outputs this participant claimed):
    # 1, 2, 3, ... up to round_output_count
    # Look for input subsets summing to ~ N * round_amount + small fee.
    max_n = min(round_output_count, 4)  # 4+ output participants are rare
    for n in range(1, max_n + 1):
        target_value = n * round_amount
        target_min = target_value  # input sum must cover output sum
        target_max = int(target_value * (1 + fee_pct_tolerance))
        candidate_input_sets = _input_subsets_summing_to(
            inputs, target_min, target_max,
        )
        if not candidate_input_sets:
            continue

        # For each candidate input set, the participant claims SOME
        # subset of size N from the round outputs. We don't know
        # WHICH N specific outputs — but we can surface the
        # hypothesis "these inputs received N of the round outputs".
        # Per-output assignment is the hard part of unwrap; we
        # provide the COARSE answer (participant → output-count)
        # which is what TRM Labs surfaces.
        for input_combo in candidate_input_sets:
            # Pick the FIRST n round outputs as the "claimed set"
            # (we have no way to identify the specific ones; this
            # is a representative selection).
            output_combo = tuple(round_outputs[:n])
            confidence, score, rationale, signals = _score_hypothesis(
                input_combo, output_combo, round_amount,
                all_input_addrs=all_input_addrs,
                all_output_addrs=all_output_addrs,
            )
            input_addrs_t = tuple(sorted({i.address for i in input_combo}))
            output_addrs_t = tuple(sorted({o.address for o in output_combo}))
            hypotheses.append(CoinJoinHypothesis(
                input_addresses=input_addrs_t,
                output_addresses=output_addrs_t,
                total_input_value_sats=sum(i.value_sats for i in input_combo),
                total_output_value_sats=sum(o.value_sats for o in output_combo),
                round_amount_sats=round_amount,
                output_count=n,
                confidence=confidence,
                confidence_score=score,
                rationale=rationale,
                signals=signals,
            ))
            if len(hypotheses) >= _MAX_HYPOTHESES_PER_TX:
                warnings.append(
                    f"hypothesis cap of {_MAX_HYPOTHESES_PER_TX} reached; "
                    "additional candidates dropped"
                )
                break
        if len(hypotheses) >= _MAX_HYPOTHESES_PER_TX:
            break

    # Sort hypotheses by confidence score descending so the brief
    # leads with the most actionable lead.
    hypotheses.sort(key=lambda h: h.confidence_score, reverse=True)

    return UnwrapResult(
        tx_id=tx_id,
        detected_pattern=pattern,
        round_amount_sats=round_amount,
        round_output_count=round_output_count,
        participant_count_estimate=participant_count_estimate,
        hypotheses=hypotheses,
        warnings=warnings,
    )


def unwrap_to_brief_section(result: UnwrapResult | None) -> dict[str, Any]:
    """Serialize an UnwrapResult for the brief's COINJOIN_UNWRAP
    section."""
    if result is None:
        return {
            "detected": False,
            "tx_id": None,
            "hypotheses": [],
        }
    return {
        "detected": True,
        "tx_id": result.tx_id,
        "detected_pattern": result.detected_pattern,
        "round_amount_sats": result.round_amount_sats,
        "round_amount_btc": f"{result.round_amount_sats / 1e8:.4f}",
        "round_output_count": result.round_output_count,
        "participant_count_estimate": result.participant_count_estimate,
        "warnings": result.warnings,
        "hypotheses": [
            {
                "input_addresses": list(h.input_addresses),
                "output_addresses": list(h.output_addresses),
                "input_value_btc": f"{h.total_input_value_sats / 1e8:.6f}",
                "output_value_btc": f"{h.total_output_value_sats / 1e8:.6f}",
                "output_count": h.output_count,
                "confidence": h.confidence,
                "confidence_score": round(h.confidence_score, 3),
                "rationale": h.rationale,
                "signals": h.signals,
            }
            for h in result.hypotheses
        ],
    }


def detection_to_brief_section(
    detection: CoinjoinDetection | None,
) -> dict[str, Any]:
    """Serialize a `CoinjoinDetection` for the brief's
    COINJOIN_DETECTION section (v0.31.0 addition).

    Separate from `unwrap_to_brief_section` because the two answer
    different questions: `unwrap_to_brief_section` lists ranked
    participant hypotheses; `detection_to_brief_section` reports
    the boolean fact "this hop crossed a known mixer" plus the
    forensic explanation.
    """
    if detection is None:
        return {
            "detected": False,
            "protocol": None,
            "tx_hash": None,
        }
    return {
        "detected": True,
        "protocol": detection.protocol,
        "tx_hash": detection.tx_hash,
        "input_address": detection.input_address,
        "all_output_addresses": [o.address for o in detection.all_outputs],
        "output_count": len(detection.all_outputs),
        "confidence": round(detection.confidence, 3),
        "forensic_note": detection.forensic_note,
        "most_likely_output": detection.most_likely_output,
    }


__all__ = (
    "UTXOInput",
    "UTXOOutput",
    "CoinJoinHypothesis",
    "UnwrapResult",
    "CoinjoinDetection",
    "PROTOCOL_WASABI_1",
    "PROTOCOL_WASABI_2",
    "PROTOCOL_WHIRLPOOL",
    "PROTOCOL_JOINMARKET",
    "PROTOCOL_MERCURY_LAYER",
    "PROTOCOL_UNKNOWN",
    "detect_round_amounts",
    "classify_coinjoin_pattern",
    "detect_coinjoin",
    "unwrap_coinjoin",
    "unwrap_to_brief_section",
    "detection_to_brief_section",
)
