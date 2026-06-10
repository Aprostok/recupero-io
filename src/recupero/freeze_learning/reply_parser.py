"""Inbound freeze-letter REPLY ingest (roadmap-to-#1 v3 item #2).

The cooperation-intelligence moat (per-issuer response-rate / freeze-rate priors)
is data-starved: outcomes were only ever recorded by hand, so priors rarely
reached the n>=20 learned threshold. This parses an exchange/issuer reply to a
freeze request into a ``freeze_outcomes`` ``outcome_type`` and records it via the
existing :func:`record_outcome_by_target` intake — so every reply an operator
pastes (or a future IMAP/webhook feeds) updates the priors.

FORENSIC CONSTRAINT — never auto-mark a strong outcome from an AMBIGUOUS reply:
``classify_reply`` only returns a strong outcome (``returned`` / ``full_freeze`` /
``partial_freeze`` / ``declined``) on an EXPLICIT phrase, at ``confidence="high"``.
Anything unclear falls back to ``acknowledged`` at ``confidence="low"`` (a reply
arrived; content unclear). :func:`ingest_reply` records the parsed outcome ONLY
at high confidence; a low-confidence reply is recorded as ``acknowledged`` (never
the guessed strong outcome). Strong outcomes are flagged ``needs_human_review``.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

log = logging.getLogger(__name__)

# Outcomes that make a strong factual claim — recorded only on an explicit
# phrase, and always flagged for human confirmation.
_STRONG = frozenset({"returned_to_victim", "full_freeze", "partial_freeze", "declined"})

_AMOUNT_RE = re.compile(r"\$\s?([0-9][0-9,]*(?:\.[0-9]+)?)")


@dataclass(frozen=True)
class ReplyClassification:
    """Result of parsing a freeze-letter reply."""
    outcome_type: str          # one of VALID_OUTCOME_TYPES
    confidence: str            # "high" | "low"
    frozen_usd: Decimal | None
    returned_usd: Decimal | None
    needs_human_review: bool
    rationale: str


def _to_decimal(s: str) -> Decimal | None:
    try:
        return Decimal(s.replace(",", ""))
    except (InvalidOperation, ValueError):
        return None


def _amount_near(raw: str, anchors: tuple[str, ...]) -> Decimal | None:
    """The first ``$``-amount AT or AFTER the earliest ``anchors`` keyword — so
    we attach the FROZEN / RETURNED figure, not an earlier theft/requested
    amount ("Of the $300,000 stolen, we have frozen $5,000" → $5,000, not
    $300,000). Returns ``None`` when no amount follows an anchor and the reply
    has multiple amounts (never guess a $ figure from a multi-amount reply)."""
    low = raw.lower()
    positions = [low.find(a) for a in anchors if a in low]
    if positions:
        m = _AMOUNT_RE.search(raw, min(positions))
        return _to_decimal(m.group(1)) if m else None
    # No anchor matched: only safe to attach when there's exactly one amount.
    amts = _AMOUNT_RE.findall(raw)
    return _to_decimal(amts[0]) if len(amts) == 1 else None


# Negation cues that invalidate a "funds returned to the victim" reading — a
# reply that says nothing was recovered must NEVER record returned_to_victim.
_RETURNED_NEG = (
    "no funds", "not returned", "not been returned", "have not returned",
    "haven't returned", "have not yet returned", "not yet returned",
    "yet to return", "did not return", "were not returned", "unable to return",
    "cannot return", "won't return", "will not return", "have not",
    "nothing returned", "no recovery", "not recovered", "unable to recover",
)
_RETURNED_POS = (
    "returned to the victim", "returned to victim", "funds returned",
    "have returned", "remitted to", "refunded to the victim",
    "refunded the victim", "sent back to the victim",
)
_PARTIAL_POS = (
    "partially frozen", "partial freeze", "partially froze",
    "froze part", "some of the funds", "a portion of",
)
_FREEZE_POS = (
    "have frozen", "has been frozen", "been frozen", "funds frozen",
    "account frozen", "is frozen", "are frozen", "placed a hold",
    "placed on hold", "full freeze", "frozen the", "frozen all",
    "frozen $", "successfully frozen", "assets have been frozen", "we froze",
)
_FREEZE_NEG = (
    "not frozen", "cannot freeze", "unable to freeze", "could not freeze",
    "will not freeze", "won't freeze", "not be able to freeze",
    "decline to freeze", "refuse to freeze",
)
_DECLINED_POS = (
    "unable to assist", "cannot assist", "we decline", "declined",
    "will not be able", "no action will be taken", "outside our jurisdiction",
    "not able to freeze", "cannot freeze", "closed without action",
    "require a court order", "requires a court order", "valid legal process",
    "will not freeze", "won't freeze", "refuse to freeze", "decline to freeze",
)
_ACK_POS = (
    "received your request", "acknowledge receipt", "we acknowledge",
    "under review", "investigating", "will investigate", "looking into",
    "reference number", "case number", "ticket", "our compliance team will",
)
_FREEZE_AMT_ANCHORS = ("frozen", "froze", "hold", "held")
_RET_AMT_ANCHORS = ("returned", "remitted", "refunded", "sent back")


def classify_reply(text: Any) -> ReplyClassification:
    """Map a reply body to a freeze outcome. PURE + conservative.

    A strong outcome is only returned on an explicit phrase (confidence
    "high"); anything ambiguous → ``acknowledged`` (confidence "low"). NEVER
    infers ``returned_to_victim`` / ``full_freeze`` from a vague OR NEGATED
    reply, and never attributes a non-adjacent $ amount.
    """
    raw = text if isinstance(text, str) else ""
    t = raw.lower()

    def _result(outcome, conf, *, frozen=None, returned=None, why):
        return ReplyClassification(
            outcome_type=outcome, confidence=conf,
            frozen_usd=frozen, returned_usd=returned,
            needs_human_review=(outcome in _STRONG),
            rationale=why,
        )

    if not t.strip():
        return _result("acknowledged", "low", why="empty/blank reply — recorded as acknowledged")

    # Strongest claim first: funds returned to the victim. Require a positive
    # remittance phrase AND NO negation cue ("no funds were returned" / "have
    # not been returned" must never read as a recovery).
    _returned_neg = any(p in t for p in _RETURNED_NEG)
    if not _returned_neg and (
        any(p in t for p in _RETURNED_POS) or ("returned" in t and "victim" in t)
    ):
        return _result("returned_to_victim", "high",
                       returned=_amount_near(raw, _RET_AMT_ANCHORS),
                       why="explicit funds-returned-to-victim phrase")

    _freeze_pos = any(p in t for p in _FREEZE_POS)
    _freeze_neg = any(p in t for p in _FREEZE_NEG)

    # Partial freeze: explicit "partially…" OR affirmative-freeze-evidence that
    # ALSO carries a freeze-negation ("frozen $50k but cannot freeze the rest")
    # — they froze SOME, not all. This must NOT degrade to 'declined'.
    if any(p in t for p in _PARTIAL_POS) or (_freeze_pos and _freeze_neg):
        return _result("partial_freeze", "high",
                       frozen=_amount_near(raw, _FREEZE_AMT_ANCHORS),
                       why="partial freeze (explicit, or froze-some-not-all)")

    # Full freeze: affirmative freeze evidence with no contradicting negation.
    if _freeze_pos and not _freeze_neg:
        return _result("full_freeze", "high",
                       frozen=_amount_near(raw, _FREEZE_AMT_ANCHORS),
                       why="explicit freeze-placed phrase")

    # Declined: explicit refusal AND no affirmative-freeze evidence (so a mixed
    # froze-some/can't-freeze-rest reply already became partial_freeze above).
    if not _freeze_pos and any(p in t for p in _DECLINED_POS):
        return _result("declined", "high", why="explicit decline / legal-process-required phrase")

    if any(p in t for p in _ACK_POS):
        return _result("acknowledged", "high", why="explicit acknowledgement phrase")

    # A reply arrived but its content is unclear → acknowledged, low confidence.
    return _result("acknowledged", "low",
                   why="reply received but no recognized outcome phrase — recorded as acknowledged")


def ingest_reply(
    *,
    case_id: Any,
    issuer: str,
    target_address: str,
    reply_text: str,
    asset_symbol: str | None = None,
    dsn: str,
    operator_notes: str | None = None,
) -> ReplyClassification:
    """Classify ``reply_text`` and record the outcome via
    :func:`record_outcome_by_target`.

    Records the PARSED outcome only at ``confidence="high"``; a low-confidence
    (ambiguous) reply is recorded as ``acknowledged`` — never the guessed strong
    outcome. The original reply is stored verbatim in ``response_text`` and the
    parse rationale (+ a 'confirm' note for strong outcomes) in
    ``operator_notes`` so the outcome stays human-reviewable.
    """
    from recupero.freeze_learning.recorder import record_outcome_by_target

    c = classify_reply(reply_text)
    effective = c.outcome_type if c.confidence == "high" else "acknowledged"
    frozen = c.frozen_usd if effective in ("full_freeze", "partial_freeze") else None
    returned = c.returned_usd if effective == "returned_to_victim" else None

    note_bits = [f"auto-parsed reply ({c.confidence}): {c.rationale}"]
    if c.needs_human_review and effective == c.outcome_type:
        note_bits.append("STRONG outcome from auto-parse — confirm before relying on it.")
    if effective != c.outcome_type:
        note_bits.append(
            f"low-confidence parse guessed {c.outcome_type!r}; recorded as "
            "'acknowledged' instead (never auto-mark a strong outcome from an "
            "ambiguous reply)."
        )
    if operator_notes:
        note_bits.append(operator_notes)

    record_outcome_by_target(
        case_id=case_id,
        issuer=issuer,
        target_address=target_address,
        outcome_type=effective,
        asset_symbol=asset_symbol,
        frozen_usd=frozen,
        returned_usd=returned,
        response_text=reply_text,
        operator_notes=" | ".join(note_bits),
        dsn=dsn,
    )
    log.info(
        "reply-ingest: case=%s issuer=%s recorded outcome=%s (parsed=%s conf=%s)",
        case_id, issuer, effective, c.outcome_type, c.confidence,
    )
    return c


__all__ = ("ReplyClassification", "classify_reply", "ingest_reply")
