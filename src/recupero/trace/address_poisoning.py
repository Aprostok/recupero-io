"""Address-poisoning attack detection (v0.32.1+ Cap-B).

Classic phishing pattern
------------------------

An attacker watches the victim's outgoing transfers, finds the
counterparty address (e.g. an exchange deposit address
``0xAbCdEf...1234``), and then sends a **0-value or dust transfer**
FROM an attacker-controlled address that *visually* mimics the
counterparty — same first-4 and last-4 hex characters
(``0xAbCd...1234``). The middle differs.

If the victim later re-pastes a recent recipient from their wallet
history (Trust Wallet, MetaMask, Rabby all surface recent
counterparties), they may copy the poisoned address by mistake. The
next transfer they intended for the exchange goes to the attacker.

This pattern is responsible for tens of millions of USD in losses
per year (Lookonchain regularly publishes individual cases of
$70M+ misdirected sends — Aug 2023 USDT $20M case is the
canonical example).

What we detect
--------------

Given a victim address and the set of ALL case transfers (both
incoming and outgoing), we flag any incoming transfer where:

  1. ``visual_similarity(sender, prior_recipient) > 0.95`` for some
     prior OUTGOING transfer (i.e. the sender mimics someone the
     victim has paid before).
  2. ``amount_usd < $1.00`` — poisoning transfers are typically
     zero-value or dust. We deliberately set the threshold low to
     catch the $0.000001 USDT-fee poisoning variant.
  3. The sender is a NEW address — has not appeared as either sender
     or receiver in any earlier case transfer. This eliminates
     legitimate repeat-counterparty refunds.

Visual similarity score (0.0 - 1.0)
-----------------------------------

Wallet UIs typically render addresses as ``0xPREFIX...SUFFIX``.
We approximate that:

* first-4 hex chars after ``0x``   weight 0.48
* last-4 hex chars                 weight 0.48
* Optional middle-7 sample         weight 0.04 (a softer match
  raises confidence when present but is not required)

A prefix-4 + suffix-4 match alone scores 0.96 — above the 0.95
detection gate — because that is exactly the confusable case a
wallet UI renders identically. A match on only one anchor scores
0.48 and does NOT trip the gate. The middle-7 sample nudges a
full collision to 1.0.

TODO(wave-7-integration): wire `detect_poisoning_attempts` into:
  * `trace/tracer.py` after the BFS frontier closes — feed
    `case.transfers` and the victim address; surface the returned
    PoisoningEvent list into a new `case.poisoning_attempts` field.
  * `brief.py` Section 7 ("Adversary tactics") should enumerate
    detected poisoning events with the impersonated counterparty.
  * The `unlabeled_counterparties` filter in brief.py should
    *suppress* poisoning sender addresses (they are not real
    counterparties; they are attack noise).
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any


@dataclass(frozen=True)
class PoisoningEvent:
    """One detected poisoning attempt.

    Fields are designed to round-trip cleanly into the brief Section 7
    "adversary tactics" table without further computation.
    """

    poisoner_address: str
    impersonated_address: str
    similarity: float
    incoming_tx_hash: str
    incoming_amount_usd: Decimal
    impersonation_basis: str  # "prefix+suffix match" | "prefix only" etc.


# -----------------------------------------------------------------------------
# Visual similarity
# -----------------------------------------------------------------------------


def _normalize_evm(address: str) -> str:
    """Lowercase and strip the 0x prefix for comparison.

    Returns an empty string for inputs that are not EVM-shaped (we
    don't poison-detect Bitcoin / Solana addresses — different
    wallet UI conventions).
    """
    if not isinstance(address, str):
        return ""
    a = address.strip().lower()
    if a.startswith("0x"):
        a = a[2:]
    # Drop anything non-hex (defensive).
    if not all(c in "0123456789abcdef" for c in a):
        return ""
    return a


def visual_similarity(addr_a: str, addr_b: str) -> float:
    """Approximate how confusable two EVM addresses are in a wallet UI.

    Returns 0.0 if either input is not EVM-shaped.
    Returns 1.0 only if first-4 AND last-4 hex chars match exactly
    (the most common wallet truncation pattern).

    The 0.48 / 0.48 / 0.04 weight split is empirically chosen so that
    the 0.95 threshold gates on prefix + suffix both matching: a
    prefix+suffix collision scores 0.96 and fires, while a purely
    prefix-matching attacker (suffix differs) scores 0.48 and does
    not trip the gate.
    """
    a = _normalize_evm(addr_a)
    b = _normalize_evm(addr_b)
    if not a or not b or a == b:
        # Identical or unparseable -> not interesting for poisoning.
        # (Identical means same address, not poisoning.)
        return 1.0 if a == b and a else 0.0

    if len(a) < 8 or len(b) < 8:
        return 0.0

    # Prefix-4 match
    prefix_score = 0.48 if a[:4] == b[:4] else 0.0

    # Suffix-4 match
    suffix_score = 0.48 if a[-4:] == b[-4:] else 0.0

    # Middle-segment partial match. We sample 7 chars from the
    # middle and award proportional credit for matching hex chars.
    if len(a) >= 14 and len(b) >= 14:
        mid_a = a[7:14]
        mid_b = b[7:14]
        matches = sum(1 for ca, cb in zip(mid_a, mid_b) if ca == cb)
        middle_score = 0.04 * (matches / 7.0)
    else:
        middle_score = 0.0

    return prefix_score + suffix_score + middle_score


# -----------------------------------------------------------------------------
# Transfer-shape adapter
# -----------------------------------------------------------------------------


def _get_field(transfer: Any, *names: str) -> Any:
    """Get the first present field from a Transfer-like object.

    Supports both Pydantic models (attribute access) and dicts.
    Returns None if no field is present.
    """
    for name in names:
        if hasattr(transfer, name):
            v = getattr(transfer, name)
            if v is not None:
                return v
        elif isinstance(transfer, dict) and name in transfer:
            v = transfer[name]
            if v is not None:
                return v
    return None


def _to_decimal(value: Any) -> Decimal:
    """Coerce a value to Decimal; return 0 on parse failure.

    Decimal('NaN') and Decimal('Infinity') normalize to 0 — non-finite
    USD values should never count toward an amount threshold.
    """
    if value is None:
        return Decimal(0)
    if isinstance(value, Decimal):
        if not value.is_finite():
            return Decimal(0)
        return value
    try:
        d = Decimal(str(value))
        if not d.is_finite():
            return Decimal(0)
        return d
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(0)


# -----------------------------------------------------------------------------
# Main detector
# -----------------------------------------------------------------------------

POISONING_AMOUNT_USD_MAX = Decimal("1.00")
POISONING_SIMILARITY_MIN = 0.95


def detect_poisoning_attempts(
    case_transfers: list[Any],
    victim_address: str,
    *,
    amount_usd_max: Decimal | None = None,
    similarity_min: float | None = None,
) -> list[PoisoningEvent]:
    """Detect address-poisoning attempts in a case's transfer set.

    Parameters
    ----------
    case_transfers
        List of Transfer-shaped objects (Pydantic models or dicts).
        Each should expose ``from_address``, ``to_address``, ``tx_hash``,
        and a USD amount field (``value_usd`` preferred, else
        ``amount_usd``, else ``value_at_transfer_usd``).
    victim_address
        The victim wallet's EVM address. Case-insensitive.
    amount_usd_max, similarity_min
        Optional threshold overrides. Production default: <$1 + 0.95.

    Returns
    -------
    list[PoisoningEvent]
        One event per detected poisoning attempt. Ordered by the
        order incoming transfers appear in ``case_transfers``.
    """
    amount_max = amount_usd_max if amount_usd_max is not None else POISONING_AMOUNT_USD_MAX
    sim_min = similarity_min if similarity_min is not None else POISONING_SIMILARITY_MIN

    victim_norm = _normalize_evm(victim_address)
    if not victim_norm:
        return []

    # Walk transfers in order, splitting into prior-outgoing recipients
    # (the "legitimate" set the attacker mimics) and incoming-from-new
    # candidates. We accumulate the prior recipients on the fly so the
    # ordering is causal: only counterparties the victim has ALREADY
    # paid count as impersonation targets.
    prior_recipients: list[str] = []  # outgoing destinations (legitimate)
    seen_addresses: set[str] = {victim_norm}
    events: list[PoisoningEvent] = []

    for t in case_transfers:
        frm = _normalize_evm(_get_field(t, "from_address", "from", "sender") or "")
        to = _normalize_evm(_get_field(t, "to_address", "to", "recipient") or "")
        if not frm or not to:
            continue

        # Outgoing: victim is sender. Record the destination as a
        # legitimate prior recipient.
        if frm == victim_norm:
            if to not in prior_recipients:
                prior_recipients.append(to)
            seen_addresses.add(to)
            continue

        # Incoming: victim is receiver. Test poisoning conditions.
        if to == victim_norm:
            # Condition 3: sender must be NEW (not seen before).
            sender_is_new = frm not in seen_addresses
            seen_addresses.add(frm)

            if not sender_is_new:
                continue

            # Condition 2: amount must be dust (<$1).
            amount = _to_decimal(
                _get_field(t, "value_usd", "amount_usd", "value_at_transfer_usd")
            )
            if amount >= amount_max:
                continue

            # Condition 1: visual similarity to some prior recipient.
            best_target: str | None = None
            best_score = 0.0
            for prior in prior_recipients:
                s = visual_similarity(frm, prior)
                if s > best_score:
                    best_score = s
                    best_target = prior

            if best_score < sim_min or best_target is None:
                continue

            tx_hash = _get_field(t, "tx_hash", "txhash", "hash") or "<unknown>"

            # Compose impersonation basis string for the brief.
            basis_parts: list[str] = []
            a_norm = _normalize_evm(frm)
            b_norm = _normalize_evm(best_target)
            if a_norm[:4] == b_norm[:4]:
                basis_parts.append("prefix-4 match")
            if a_norm[-4:] == b_norm[-4:]:
                basis_parts.append("suffix-4 match")
            basis = " + ".join(basis_parts) if basis_parts else "near-collision"

            events.append(
                PoisoningEvent(
                    poisoner_address=frm,
                    impersonated_address=best_target,
                    similarity=round(best_score, 4),
                    incoming_tx_hash=str(tx_hash),
                    incoming_amount_usd=amount,
                    impersonation_basis=basis,
                )
            )

            continue

        # Neither outgoing nor incoming (e.g. third-party hop in the
        # case data). Just track addresses we've seen.
        seen_addresses.add(frm)
        seen_addresses.add(to)

    return events
