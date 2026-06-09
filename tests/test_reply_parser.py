"""Roadmap-#1 v3 item #2: inbound freeze-letter reply ingest.

classify_reply maps a reply body to a freeze outcome CONSERVATIVELY — a strong
outcome (returned/full_freeze/partial_freeze/declined) only on an explicit
phrase; anything ambiguous → acknowledged. ingest_reply records the parsed
outcome only at high confidence (ambiguous → acknowledged), so a vague reply
never auto-marks a strong outcome.
"""

from __future__ import annotations

from decimal import Decimal

import recupero.freeze_learning.recorder as recorder_mod
from recupero.freeze_learning.recorder import VALID_OUTCOME_TYPES
from recupero.freeze_learning.reply_parser import classify_reply, ingest_reply


def test_classify_strong_outcomes_high_confidence() -> None:
    assert classify_reply("We have frozen the full balance.").outcome_type == "full_freeze"
    assert classify_reply("The account has been frozen pending legal process.").outcome_type == "full_freeze"
    assert classify_reply("We partially froze the account.").outcome_type == "partial_freeze"
    assert classify_reply("Funds have been returned to the victim.").outcome_type == "returned_to_victim"
    assert classify_reply("We are unable to assist without a court order.").outcome_type == "declined"
    assert classify_reply("We acknowledge receipt; your case number is 123.").outcome_type == "acknowledged"
    for txt in ("We have frozen all funds.", "Funds returned to victim."):
        assert classify_reply(txt).confidence == "high"


def test_ambiguous_reply_never_marks_strong_outcome() -> None:
    # The forensic invariant: a vague reply must NOT become returned/full_freeze.
    for txt in ("", "   ", "Thanks for your email.", "Please see attached.",
                "We received this and will be in touch."):
        c = classify_reply(txt)
        assert c.outcome_type == "acknowledged"
        assert c.confidence == "low" or "acknowledge" in txt.lower() or "received" in txt.lower()
        assert c.outcome_type not in ("returned_to_victim", "full_freeze", "partial_freeze")


def test_partial_takes_precedence_over_full() -> None:
    # "partially frozen $500" contains 'frozen' but is a PARTIAL freeze.
    c = classify_reply("We have partially frozen $500.00 of the requested amount.")
    assert c.outcome_type == "partial_freeze"
    assert c.frozen_usd == Decimal("500.00")


def test_amount_extraction_attaches_to_matching_outcome() -> None:
    assert classify_reply("Frozen $1,234.56 in the account.").frozen_usd == Decimal("1234.56")
    _r = classify_reply("We returned $2,000 to the victim.")
    assert _r.outcome_type == "returned_to_victim"
    assert _r.returned_usd == Decimal("2000")
    # an amount in an ambiguous reply is NOT attached as a freeze/return
    amb = classify_reply("Your invoice for $50 is attached.")
    assert amb.outcome_type == "acknowledged"
    assert amb.frozen_usd is None and amb.returned_usd is None


def test_strong_outcomes_flagged_for_human_review() -> None:
    assert classify_reply("We have frozen all funds.").needs_human_review is True
    assert classify_reply("Funds returned to the victim.").needs_human_review is True
    assert classify_reply("Funds returned to the victim.").outcome_type == "returned_to_victim"
    assert classify_reply("We acknowledge receipt.").needs_human_review is False


def test_all_outcomes_are_valid_recorder_types() -> None:
    for txt in ("frozen all", "partially frozen", "returned to victim",
                "unable to assist", "acknowledge receipt", ""):
        assert classify_reply(txt).outcome_type in VALID_OUTCOME_TYPES


def test_ingest_records_parsed_outcome_at_high_confidence(monkeypatch) -> None:
    captured = {}

    def _fake_record(**kwargs):
        captured.update(kwargs)
        return "00000000-0000-0000-0000-000000000001"

    monkeypatch.setattr(recorder_mod, "record_outcome_by_target", _fake_record)
    ingest_reply(
        case_id="c1", issuer="Circle", target_address="0xabc",
        reply_text="We have frozen the full balance ($1,000).", dsn="dsn",
    )
    assert captured["outcome_type"] == "full_freeze"
    assert captured["frozen_usd"] == Decimal("1000")
    assert captured["response_text"].startswith("We have frozen")


def test_ingest_downgrades_ambiguous_to_acknowledged(monkeypatch) -> None:
    captured = {}
    monkeypatch.setattr(recorder_mod, "record_outcome_by_target",
                        lambda **kw: captured.update(kw) or "id")
    # A vague reply that a naive parser might misread → must record acknowledged.
    ingest_reply(
        case_id="c1", issuer="Circle", target_address="0xabc",
        reply_text="Thanks, we'll look at the $5,000,000 matter internally.",
        dsn="dsn",
    )
    assert captured["outcome_type"] == "acknowledged"
    assert captured["frozen_usd"] is None
    assert captured["returned_usd"] is None
