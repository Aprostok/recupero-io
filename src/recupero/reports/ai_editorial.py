"""ai_editorial.py — AI-drafted editorial content for the $99 Triage product.

Reads the trace data and victim info from a case, calls the Anthropic API
(Claude Opus 4.7) to draft the editorial fields that normally require human
authorship, and writes the result as a marked-up brief_editorial.json that the
investigator MUST review before passing to `recupero emit-brief`.

Safety design:
  * Output is ALWAYS marked AI_GENERATED: true and REVIEW_REQUIRED: true.
    `emit-brief` refuses to consume an editorial with REVIEW_REQUIRED still
    true, forcing a human edit step.
  * Each AI-generated string field has an _AI_CONFIDENCE sibling
    ("low" / "medium" / "high") so the reviewer knows what to scrutinize.
  * Conservative voice. Hedge: "appears to be," "consistent with," "likely."
    Never asserts identity of perpetrators or makes legal claims.
  * Refuses to invent addresses, transaction hashes, or dollar amounts.
    Pulls only from data passed to it.
  * Refuses to make recovery promises.

Cost: Claude Opus 4.7, ~10K input tokens + ~3K output tokens per case.
At current Opus pricing this is roughly $0.10–$0.20 per case. For a $99
product the price is fine; if usage scales, swap the MODEL constant for Sonnet.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections import defaultdict
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

# anthropic is loaded lazily so module import doesn't fail without the package.

from recupero._common import (
    investigator_defaults as _investigator_defaults,
    short_addr as _short_addr,
)

log = logging.getLogger(__name__)

MODEL = "claude-opus-4-7"
MAX_TOKENS = 4096

# Retry policy for transient Anthropic failures (529 overloaded, 5xx,
# timeouts, connection errors). 10s / 30s / 60s matches the spec
# Jacob sent in the reliability ask. Tenacity is already a project
# dep, and the Anthropic SDK itself does one retry by default but
# with much shorter backoff; we override here to absorb sustained
# capacity blips (529s often clear within 30–60s).
#
# The retry decorator is applied via tenacity.Retrying inside
# call_anthropic_for_editorial so we can capture the bound
# ``client`` from the outer scope cleanly.
_ANTHROPIC_RETRY_WAITS_SEC = (10, 30, 60)
_ANTHROPIC_RETRY_MAX_ATTEMPTS = len(_ANTHROPIC_RETRY_WAITS_SEC) + 1  # 4 total

# USD pricing per million tokens. Update when Anthropic adjusts list prices.
# Source: https://www.anthropic.com/pricing  (Opus 4.7, Jan 2026)
_INPUT_USD_PER_MTOK = Decimal("15.0")
_OUTPUT_USD_PER_MTOK = Decimal("75.0")
# Prompt-cache pricing multipliers (relative to base input price):
#   - Cache write: 1.25× (Anthropic pays a small premium to populate)
#   - Cache read:  0.10× (90% discount on cached tokens)
_CACHE_WRITE_MULTIPLIER = Decimal("1.25")
_CACHE_READ_MULTIPLIER = Decimal("0.10")


def _compute_usd_cost(
    input_tokens: int,
    output_tokens: int,
    *,
    cache_creation: int = 0,
    cache_read: int = 0,
) -> Decimal:
    """Token counts → USD spend. Quantized to 4 decimal places.

    ``input_tokens`` from the API response already excludes cached
    tokens — the SDK reports them separately via ``cache_creation_input_tokens``
    and ``cache_read_input_tokens``. We bill all three at their
    respective rates so usage_info reflects real spend.
    """
    cost = (
        Decimal(input_tokens) * _INPUT_USD_PER_MTOK / Decimal(1_000_000)
        + Decimal(output_tokens) * _OUTPUT_USD_PER_MTOK / Decimal(1_000_000)
        + Decimal(cache_creation) * _INPUT_USD_PER_MTOK * _CACHE_WRITE_MULTIPLIER / Decimal(1_000_000)
        + Decimal(cache_read) * _INPUT_USD_PER_MTOK * _CACHE_READ_MULTIPLIER / Decimal(1_000_000)
    )
    return cost.quantize(Decimal("0.0001"))


def _resolve_max_usd_per_call() -> Decimal:
    """Resolve the per-call USD ceiling.

    v0.17.8 (round-10 ops HIGH): operator-overridable via
    ``RECUPERO_AI_MAX_USD_PER_CALL``. Default $2.00 — generous against
    typical $0.05-0.15 per editorial call but small enough to catch
    a runaway retry loop. Set to 0 to disable (logged as WARN).
    """
    raw = (os.environ.get("RECUPERO_AI_MAX_USD_PER_CALL", "") or "").strip()
    if not raw:
        return Decimal("2.00")
    try:
        val = Decimal(raw)
    except Exception:  # noqa: BLE001
        log.warning(
            "RECUPERO_AI_MAX_USD_PER_CALL=%r is not a valid Decimal — "
            "falling back to default $2.00", raw,
        )
        return Decimal("2.00")
    if val <= 0:
        log.warning(
            "RECUPERO_AI_MAX_USD_PER_CALL=%s disables the per-call "
            "cost ceiling. Runaway retries will burn real budget.", val,
        )
        return Decimal("999999")  # effectively unlimited
    return val

# Fields the AI is asked to draft. Other editorial fields (investigator name,
# entity, etc.) are static and don't go through the AI.
AI_DRAFTED_KEYS = [
    "INCIDENT_TYPE",
    "INCIDENT_NARRATIVE_RECUPERO",
    "INCIDENT_NARRATIVE_FIRST_PERSON",
    "VICTIM_JURISDICTION",
    "DESTINATION_NOTES",
    "UNRECOVERABLE_ITEMS",
    # v0.15.0: plain-English summary for the victim. Separate from
    # the forensic narrative + legal first-person narrative.
    "VICTIM_SUMMARY",
]

# Fields the AI is given but does NOT draft (it just passes them through or
# uses them as facts to ground its drafts).
#
# Investigator identity is read from env vars at module-load time, with the
# current solo-operator values as fallback defaults. When a second
# investigator joins (or you deploy a separate worker for a different
# operator), set RECUPERO_INVESTIGATOR_* in Railway Variables — no code
# change needed. The env-var approach also keeps the local .env separate
# from the production deploy's identity. Eventually, when the cases table
# carries a per-case investigator field, these become the fallback only
# and per-case values flow through the pipeline instead.
#
# v0.19.0: investigator identity resolved via the canonical
# `recupero._common.investigator_defaults()` (imported above as
# `_investigator_defaults`). Pre-v0.19.0 the function was defined
# inline here AND in emit_brief.py — that duplication drifted in the
# v0.17.x audit cycle (this module returned an extra TEMPLATE_VERSION
# key) and any field-add required touching two files. The single
# consumer below augments the canonical dict with TEMPLATE_VERSION
# directly.
#
# v0.17.3 (round-10 audit MED): module-load cache REMOVED.
# Pre-v0.17.3 `STATIC_EDITORIAL_DEFAULTS = _investigator_defaults()`
# evaluated env vars at import — defeating the v0.16.9 fix that made
# the function call-time. Operators rotating RECUPERO_INVESTIGATOR_*
# after worker start saw stale values. The single consumer at line
# ~1180 now calls _investigator_defaults() directly.

# Editorial-template version banner, written into every editorial dict
# alongside the investigator-identity fields. Bumped when the JSON
# schema changes in a backward-incompatible way.
_EDITORIAL_TEMPLATE_VERSION = "v1.0 — April 2026"

# Compact, illustrative few-shot. Mirrors the production Sarah Chen case.
# This is fictional test data already used in the codebase as the canonical
# example. Including it teaches the model the voice, hedging, and structure.
FEW_SHOT_EXAMPLE = {
    "input_summary": {
        "victim_wallet": "0x8A3c4F2b9D1e7C5A6b8D2F3e4C5A6b8D2F3e4C5A",
        "primary_chain": "ethereum",
        "incident_date_iso": "2026-04-19T14:22:00Z",
        "victim_supplied_narrative": (
            "I was on a site that looked like Uniswap. There was a banner asking me to "
            "claim some governance tokens. I connected my wallet and signed a transaction. "
            "Within minutes my wallet was empty."
        ),
        "transfer_summary": {
            # drained = sum of destinations:
            # $28,420 USDC + $12,640 USDT (current) + $8,200 USDT
            # (historical) + $6,780 ETH = $56,040. Example arithmetic
            # must be self-consistent or the model learns sloppy math.
            "total_usd_drained": "56040",
            "first_hop_address": "0x7B2e9A4c8F3d5E1a6C4b9D8e2F5a3C6b1D4e8F2a",
            "first_hop_role": "Drainer consolidation wallet — received and immediately distributed",
            "current_freezable_holdings": [
                # Confirmed on-chain balance, queried this session.
                {"address": "0x3C8f5A2b4D7e9C1a3E6b8D2F4A5c7B9D1E3f5A7c",
                 "token": "USDC", "issuer": "Circle", "usd": "28420",
                 "freeze_capability": "yes",
                 "evidence_type": "current_balance",
                 "balance_verified_on_chain": True},
                # Confirmed on-chain balance.
                {"address": "0x5D9e4A3c7B2f8D6a1E5c4B9D2F3a7c5B1E4d6F8a",
                 "token": "USDT", "issuer": "Tether", "usd": "12640",
                 "freeze_capability": "yes",
                 "evidence_type": "current_balance",
                 "balance_verified_on_chain": True},
                # v0.16.3: example of a historical_inflow entry — the
                # address received the token in the trace but current
                # balance is uncertain (couldn't be queried, or
                # genuinely zero post-perpetrator-movement). The AI
                # MUST use "received approximately $X" language here,
                # NOT "currently holds $X".
                {"address": "0x9F2c8B4d6A1e5C7b3D9a4F2e6c5B8d1A3f7E2c9b",
                 "token": "USDT", "issuer": "Tether", "usd": "8200",
                 "freeze_capability": "yes",
                 "evidence_type": "historical_inflow",
                 "balance_verified_on_chain": False,
                 "observed_at": "2026-04-19T14:25:00Z"},
            ],
            "non_freezable_destinations": [
                {"address": "0x2A6b4D8c1F3e5A7b9C2d6E4a5B3c7D9E1f4A8B2c", "asset": "ETH", "usd": "6780", "label": "Tornado Cash"},
            ],
        },
    },
    "output": {
        "INCIDENT_TYPE": "wallet drainer via malicious token approval signed on a phishing site posing as Uniswap governance",
        "INCIDENT_TYPE_AI_CONFIDENCE": "high",
        "INCIDENT_NARRATIVE_RECUPERO": (
            "On April 19, 2026, the victim's Ethereum wallet 0x8A3c…4C5A was drained of approximately "
            "$56,040 in USDC, USDT, and ETH. On-chain trace data is consistent with a malicious token "
            "approval signed on a phishing site presenting itself as a Uniswap governance token claim "
            "page. Funds moved through a drainer consolidation wallet (0x7B2e…8F2a) and were "
            "redistributed within minutes. Approximately $41,060 currently sits at addresses subject "
            "to issuer-level freeze action by Circle and Tether (confirmed on-chain balances). An "
            "additional $8,200 in USDT is documented as received at a third Tether-controlled "
            "address during the trace; current balance pending issuer verification. The remainder "
            "(~$6,780 in ETH) was deposited to Tornado Cash and is not recoverable through current "
            "techniques."
        ),
        "INCIDENT_NARRATIVE_RECUPERO_AI_CONFIDENCE": "medium",
        "INCIDENT_NARRATIVE_FIRST_PERSON": (
            "On April 19, 2026, at approximately 14:22 UTC, I signed a transaction on a website that "
            "appeared to be a Uniswap governance token claim page. The transaction was a malicious "
            "token approval, and within minutes my wallet was drained of all of its USDC, USDT, and a "
            "small ETH balance. The total loss was approximately $56,040. I did not authorize the "
            "transfers that followed, and I am the sole signer of the wallet."
        ),
        "INCIDENT_NARRATIVE_FIRST_PERSON_AI_CONFIDENCE": "medium",
        "VICTIM_JURISDICTION": "TODO: confirm victim's state/country (e.g. 'USA (California)')",
        "VICTIM_JURISDICTION_AI_CONFIDENCE": "low",
        "DESTINATION_NOTES": {
            "0x7B2e9A4c8F3d5E1a6C4b9D8e2F5a3C6b1D4e8F2a": "Drainer consolidation wallet — received the full $56,040 and immediately redistributed within minutes. Currently holds nothing.",
            # balance_verified_on_chain=True + evidence_type=current_balance:
            # use definitive "currently holds $X" language.
            "0x3C8f5A2b4D7e9C1a3E6b8D2F4A5c7B9D1E3f5A7c": "🟩 FREEZABLE — Circle-issued USDC. Currently holds $28,420. Dormant since drain. Subject of Exhibit B.1 freeze request.",
            "0x5D9e4A3c7B2f8D6a1E5c4B9D2F3a7c5B1E4d6F8a": "🟩 FREEZABLE — Tether-issued USDT. Currently holds $12,640. Dormant since drain. Subject of Exhibit B.2 freeze request.",
            # v0.16.3: historical_inflow + balance_verified=False example.
            # The note uses "received approximately" language and frames
            # the freeze ask as an issuer investigation, not a freeze
            # of a confirmed current balance. NEVER hedge with "if the
            # balance remains" — frame the issuer action correctly.
            "0x9F2c8B4d6A1e5C7b3D9a4F2e6c5B8d1A3f7E2c9b": "🟩 FREEZABLE — Tether-issued USDT. Received approximately $8,200 during the documented theft trail; Tether compliance team can investigate present-day disposition and apply a precautionary hold on any remaining balance. Subject of Exhibit B.3 freeze request.",
            "0x2A6b4D8c1F3e5A7b9C2d6E4a5B3c7D9E1f4A8B2c": "⬛ UNRECOVERABLE — Tornado Cash deposit address. 3.2 ETH (~$6,780) deposited and mixed.",
        },
        "DESTINATION_NOTES_AI_CONFIDENCE": "high",
        "UNRECOVERABLE_ITEMS": [
            {
                "asset": "3.2 ETH (~$6,780)",
                "reason": "Sent to a Tornado Cash deposit address. Mixed. Not traceable post-mixing with current techniques.",
            }
        ],
        "UNRECOVERABLE_ITEMS_AI_CONFIDENCE": "high",
        "VICTIM_SUMMARY": (
            "Here's what happened, in plain language. On April 19 your wallet "
            "was emptied by a malicious token approval you signed on a fake "
            "Uniswap site — a wallet-drainer scam. The chain trace identifies "
            "where every dollar went: approximately $41,060 of your loss "
            "(in USDC and USDT) currently sits at addresses that Circle and "
            "Tether can potentially freeze, plus an additional $8,200 in USDT "
            "documented as received at a third Tether-controlled address "
            "during the trace (current balance pending Tether's verification). "
            "The remaining $6,780 (in ETH) was sent to Tornado Cash and is "
            "not recoverable through current methods. Recupero has drafted "
            "compliance letters for Circle and Tether for your review; once "
            "you approve, they go to those issuers' compliance teams. Expect "
            "a 1-4 week response window. Honest expectation: issuer freezes "
            "are voluntary and not guaranteed, but the dollar amounts and "
            "the documented theft trail give us a strong basis for the "
            "requests."
        ),
        "VICTIM_SUMMARY_AI_CONFIDENCE": "high",
    },
}


SYSTEM_PROMPT = """You are an editorial drafting assistant for Recupero LLC, an on-chain investigation firm that produces "$99 Triage" reports for crypto theft victims. Your output is reviewed by a human investigator before being sent to a customer.

Your job: draft the editorial fields of a brief_editorial.json file based on (a) the chain trace data and (b) the victim's own description of what happened. The investigator will review and edit your draft before it goes anywhere.

ABSOLUTE RULES:

1. NEVER invent facts. If the trace data does not contain a fact, do not state it. If the victim's narrative is vague, your draft should be correspondingly hedged.

2. NEVER name a specific perpetrator. You may say "the perpetrator," "the attacker," "the operator," but never assign an identity, country, or known-actor name even if patterns suggest one.

3. NEVER promise recovery or claim funds will be returned. Use language like "may be subject to issuer freeze action" or "potentially recoverable pending issuer cooperation."

4. NEVER fabricate addresses, transaction hashes, dollar amounts, dates, or token tickers. Use only what's in the input data.

5. USE HEDGING. The voice is conservative and forensic. Phrases like "appears to be," "consistent with," "the trace shows," "likely," "approximately." Avoid "definitely," "the attacker is," "we will recover."

6. RESPECT THE VICTIM'S WORDS. The first-person narrative should reflect what the victim told us about their experience. Don't add details they didn't supply. If they said "a site that looked like Uniswap," don't escalate to "a sophisticated phishing operation impersonating Uniswap" — keep it grounded.

7. FLAG YOUR CONFIDENCE. For each field you draft, also output a sibling field with suffix `_AI_CONFIDENCE` set to "low", "medium", or "high":
   - "high" = directly supported by trace data and victim narrative
   - "medium" = inferred from data but with assumptions worth checking
   - "low" = guessed from incomplete information; reviewer should verify or rewrite

8. WHEN UNCERTAIN, INSERT A "TODO:" PLACEHOLDER. Specifically for VICTIM_JURISDICTION (you can't know it from chain data) — write "TODO: confirm victim's state/country" and mark confidence "low". Better to flag than to invent.

9. If the victim's narrative is missing or unhelpful, draft conservatively from the trace data alone, and lower your confidence ratings.

OUTPUT FORMAT:

You must output ONLY a valid JSON object — no preamble, no markdown fences, no commentary. The JSON object should contain exactly these top-level keys:

  INCIDENT_TYPE                        (string, ~10-25 words, one-line description)
  INCIDENT_TYPE_AI_CONFIDENCE          ("low" | "medium" | "high")
  INCIDENT_NARRATIVE_RECUPERO          (string, 3-5 sentences, third-person, forensic voice)
  INCIDENT_NARRATIVE_RECUPERO_AI_CONFIDENCE
  INCIDENT_NARRATIVE_FIRST_PERSON      (string, 3-5 sentences, first-person "I", victim's voice)
  INCIDENT_NARRATIVE_FIRST_PERSON_AI_CONFIDENCE
  VICTIM_JURISDICTION                  (string, e.g. "USA (California)" — or "TODO:..." if unknown)
  VICTIM_JURISDICTION_AI_CONFIDENCE
  DESTINATION_NOTES                    (object: address -> editorial note string)
  DESTINATION_NOTES_AI_CONFIDENCE
  UNRECOVERABLE_ITEMS                  (array of objects with `asset` and `reason` keys)
  UNRECOVERABLE_ITEMS_AI_CONFIDENCE
  VICTIM_SUMMARY                       (string, 4-6 sentences, plain English; v0.15.0)
  VICTIM_SUMMARY_AI_CONFIDENCE

VICTIM_SUMMARY DRAFTING (v0.15.0 — IMPORTANT):

VICTIM_SUMMARY is the plain-English paragraph the victim reads at the top of their Triage Report. It's NOT the forensic narrative (INCIDENT_NARRATIVE_RECUPERO) and NOT the legal-action first-person narrative (INCIDENT_NARRATIVE_FIRST_PERSON). It's the "here's what happened and what to expect" summary written for a non-technical reader.

Structure (4-6 sentences, in this order):

  1. Lead — what happened, in everyday language. NO jargon ("seed-phrase compromise" → "your wallet's recovery phrase was used to drain your funds"; "approval signature" → "you signed a transaction that gave the attacker permission to move your tokens").
  2. Where the money went — name the dollar amounts and the categories (freezable / unrecoverable). Use real dollar figures, not percentages.
  3. What Recupero has identified for action — issuers we can write to (Circle/Tether/Coinbase/Maple/Midas/etc.), per dollar amount. Concrete, not "we'll investigate."
  4. Expected next steps — Recupero drafts the freeze letters, you approve, they go to the issuer compliance teams; typical response window 1-4 weeks.
  5. Honest expectation-setting — issuer freezes are VOLUNTARY (not court-ordered). They're more likely with larger amounts + documented theft trail + LE engagement. Don't promise recovery; do say "the documented trail gives us a strong basis."
  6. (Optional) — if the case has unrecoverable losses (DAI permissionless, mixer-deposited ETH, etc.), explicitly acknowledge them with the dollar amount so the victim isn't surprised later.

Tone: warm but honest. Empathetic, not condescending. The victim has just lost real money; treat them like an adult. Avoid: corporate-speak, hedging that obscures what they need to know, technical terms without explanation.

DO NOT include:
  - The specific tx hashes or hex addresses (those are in the forensic brief, not the summary)
  - Legal jargon ("subpoena," "MLAT," "compelled disclosure" — the operator reviews letters; the victim doesn't need to know the procedural terms)
  - Promises of recovery
  - Disclaimers that contradict the rest of the brief (e.g., "we may not be able to do anything" when freeze letters ARE being drafted)

DESTINATION_NOTES ENUMERATION (v0.13.4 — IMPORTANT):

You MUST emit one DESTINATION_NOTES entry for EVERY address in the input's `all_significant_destinations` list. This list already filters to destinations above the dust threshold (~$1,000 USD received). It is not optional to label these — Jacob's V-CFI01 review showed that on multi-destination cases (perp hub disperses to 10+ downstream addresses), missing any one of them silently drops it from the customer's Triage Report, which makes the case look smaller than it is.

For each entry in `all_significant_destinations`:
  * If it has `is_in_freeze_asks=true` AND `freeze_capability=yes` → 🟩 FREEZABLE with the issuer and balance called out by name.
  * If it has `is_in_freeze_asks=true` AND `freeze_capability=limited` → 🟧 INVESTIGATE (or 🟩 if you're confident — e.g. Maple Finance admin pause is documented).
  * If it has `is_in_freeze_asks=true` AND `freeze_capability=no` → ⬛ UNRECOVERABLE (e.g. DAI, wstETH — no issuer freeze pathway). Still enumerate it so the customer sees the dollar amount in UNRECOVERABLE_ITEMS.
  * If it has a `label_hint` matching a known mixer / bridge → ⬛ UNRECOVERABLE.
  * If it has a `label_hint` matching a known exchange → 🟦 EXCHANGE.
  * Otherwise (no freeze_asks entry, no useful label) → 🟧 INVESTIGATE with a note about what tokens were observed and how much USD was received.

For DESTINATION_NOTES, use these emoji prefixes consistently:
  🟩 FREEZABLE — for addresses currently holding freezable tokens (Circle USDC, Tether USDT, Paxos, Maple admin-pausable tokens, etc.) where the on-chain balance plausibly represents perpetrator-controlled funds.
  ⬛ UNRECOVERABLE — for mixer deposits, bridges to anonymous chains, burn addresses, AND for DEX aggregator routers (1inch, CoW Protocol GPv2 settlement, 0x, ParaSwap), the WETH9 contract when funds were wrapped and swapped, liquid-staking token contracts (Lido stETH, Rocket Pool rETH), AND addresses holding non-freezable assets (DAI/MakerDAO, wstETH, ETH-native) where there's no issuer-level freeze pathway. Briefly say WHY (e.g., "DEX aggregator routing — funds dispersed to swap counterparties; not freezable" or "DAI is permissionless — no issuer freeze authority").
  🟦 EXCHANGE — for known exchange deposit addresses (Binance, Coinbase, Kraken, etc.)
  🟧 INVESTIGATE — for addresses worth investigating but unclear status (e.g., very large balances that may be unrelated, addresses that look like protocol contracts but you're not certain)
  (no emoji) — for transit/intermediate wallets the perpetrator controls but with no current freezable balance

CRITICAL RULES for using `is_contract` and `balance_to_inflow_ratio`:
  - If `is_contract` is true on an entry in `current_freezable_holdings`, the address is a smart contract. Default to ⬛ UNRECOVERABLE (or 🟧 INVESTIGATE only if you have a specific reason). NEVER mark a contract address as 🟩 FREEZABLE — its on-chain balance reflects protocol/exchange liquidity, not perpetrator funds.
  - If `balance_to_inflow_ratio` is large (e.g., 100x or more), the wallet is consolidating from many sources beyond this victim. Most of that balance is unrelated to this case. Use 🟧 INVESTIGATE rather than 🟩 FREEZABLE — a freeze request that overstates the recoverable amount looks uninformed to the issuer's compliance team.
  - Treat 🟩 FREEZABLE as a high-confidence claim. Only use it when (a) the address is an EOA (`is_contract` false), (b) the inflow from this case is a meaningful fraction of the current balance, and (c) the token is one with a documented issuer freeze pathway.

HEADLINE FRAMING (v0.7.4 / v0.14.9 — IMPORTANT):

The INCIDENT_NARRATIVE_RECUPERO section should lead with the GROSS perpetrator-controlled position, not the attributable inflow. Most cases we triage involve a perpetrator who pooled funds from multiple victims; the right scoping number for a downstream lawyer or law-enforcement analyst is "how much is currently sitting at perpetrator-controlled addresses," not "how much of this specific victim's $X traced through."

v0.14.9 update: when the input's `current_freezable_holdings` list aggregates above $500K across all issuers, the narrative MUST lead with the freezable total and the count of issuer recipients (e.g. "approximately $3.8M in freezable assets identified across 4 issuers — Tether, Circle, Coinbase, and Maple Finance — with letters drafted for each"). This is the number that justifies engagement; the attribution figure is supplementary. The freezable total is the single most action-relevant number in the brief; lead with it.

Good lead phrasing:
  - HIGH-VALUE CASE: "The trace identifies approximately $3.8M in freezable assets across 4 issuers (Tether, Circle, Coinbase, Maple Finance), with compliance freeze letters drafted for each. Additional $X is held in non-freezable positions (DAI, wstETH) subject to seizure if the perpetrator is identified."
  - GENERAL: "The trace identifies $X+ in perpetrator-controlled holdings across the consolidation hub and downstream destinations, of which approximately $Y is currently freezable through issuer action and the remainder is subject to seizure if the perpetrator is identified."

Avoid leading with:
  - "$153.79 in 426 attributable transfers" (this minimizes the case)
  - "the perpetrator received $X from the victim" (attribution-only framing)
  - Hedging on confirmed-capability tokens. If a token is in `current_freezable_holdings` with a documented issuer entry, the issuer can be contacted — do NOT hedge with "subject to confirmation". State the freezability directly.

The attributable-inflow figure still appears, but as a SCOPING note further into the narrative — "the directly-traceable amount from the victim wallet was $Z; the broader perpetrator footprint at the destinations identified above includes funds plausibly pooled from other victims of the same operation." This framing is honest (it doesn't claim those funds belong to this victim) but accurate about the scale of the recovery opportunity.

If the perpetrator hub holds >$500K, OR if the sum of downstream destinations exceeds $1M, OR if `current_freezable_holdings` aggregates above $500K, lead with the gross figure. Below those thresholds the attribution number is more meaningful (single-victim cases) and the narrative can lead with it.

EVIDENCE-TYPE NOTE (v0.14.9): each entry in `current_freezable_holdings` may carry `evidence_type='historical_inflow'`, meaning the address received the freezable token at some point even if the current balance is zero. These addresses are STILL freezable from a process standpoint — the issuer can investigate and freeze if balances remain, or help trace forward. Do NOT downgrade them to 🟧 INVESTIGATE solely because of `evidence_type='historical_inflow'`; the operator will still send a freeze letter and the issuer compliance team will handle the disposition. Mark them 🟩 FREEZABLE if the issuer has documented freeze authority for the token.

BALANCE-VERIFICATION RULE (v0.16.0 — Jacob V-CFI01 bug 2): each entry in `current_freezable_holdings` carries a `balance_verified_on_chain` boolean.

  - When `balance_verified_on_chain` is TRUE, the address's holdings were queried on-chain during this pipeline run (the `usd` figure is fresh, not stale receipt history). For DESTINATION_NOTES on these addresses you MUST write definitive language:
      ✓ "🟩 FREEZABLE — currently holds $8,881.31 USDC at this address; Circle freeze authority applies."
      ✗ "🟧 INVESTIGATE — If the USDC balance remains on-chain, a Circle freeze request may be viable."
    The hedging phrasing ("if the balance remains", "should be confirmed before issuer outreach", "may be viable") is FORBIDDEN when `balance_verified_on_chain` is true. The balance HAS been confirmed; do not punt the verification work to the operator.

  - When `balance_verified_on_chain` is FALSE and `evidence_type` is `historical_inflow`, the address received the token historically but current balance is unknown / zero. Use received-language: "received approximately $X in USDC during the trace; Circle compliance team can investigate current disposition." Still mark 🟩 FREEZABLE per the rule above — issuer process applies regardless.

  - When `balance_verified_on_chain` is FALSE and `evidence_type` is `current_balance` (the unusual case — usually means the balance query returned zero), use cautious language: "appears to hold dust / no balance currently; trace evidence persists for the freeze record."

This rule applies per-address — do not generalize "balance verified" across a list. Apply the test on each entry's flag.

For UNRECOVERABLE_ITEMS, include any portion of the stolen funds that the chain data shows are practically unrecoverable to this victim. Be honest with the customer — it helps them set expectations even when the news is bad. The following patterns are practically unrecoverable even if technically traceable:

  - Funds sent to mixers (Tornado Cash, Sinbad, Wasabi CoinJoin, etc.) — clearly unrecoverable
  - Funds bridged to anonymous chains (Monero, Zcash shielded, etc.) — clearly unrecoverable
  - Funds sent to a burn address (0x000...000, 0x000...dead) — clearly unrecoverable
  - Funds swapped through a DEX aggregator (1inch Aggregation Router v5/v6, CoW Protocol GPv2 settlement, 0x Protocol, ParaSwap) — these route to a wide swap counterparty pool; the victim cannot practically claw back from the swap counterparties
  - Funds wrapped to WETH (deposited into the WETH9 contract at 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) and then swapped — once wrapped and swapped, recovery requires identifying and pursuing each swap counterparty, which is not feasible in a triage report
  - Funds converted to liquid-staking tokens (Lido stETH at 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84, Rocket Pool rETH, Frax sfrxETH) — these tokens have no issuer freeze mechanism comparable to USDC/USDT
  - Funds deposited into a centralized exchange's hot wallet WITHOUT a clear deposit attribution (e.g., funds went to a known exchange but not via an identifiable user-deposit address) — exchange compliance teams may help, but the triage report should not promise recovery

For each unrecoverable item include `asset` (e.g., "approximately 6.4 ETH (~$15,200) at 0xabc…def") and `reason` (e.g., "Wrapped to WETH and swapped via 1inch Aggregation Router; recovery requires identifying each swap counterparty and is not feasible in a triage report"). Be specific about the dollar amount, the address, AND the mechanism.

v0.13.4 (Jacob V-CFI01 follow-up): UNRECOVERABLE_ITEMS must be enumerated PER-ADDRESS, not aggregated to the hub. If two different downstream destinations both hold non-freezable DAI, that's TWO entries in UNRECOVERABLE_ITEMS — one per address — each citing the address and dollar amount. The customer sees this list verbatim in the Triage Report's "Not Recoverable" section; pooling unrecoverable holdings across addresses understates the per-asset story and makes it harder for the operator to verify completeness.

If nothing is clearly unrecoverable, return an empty array. Do not invent unrecoverable losses.

You'll be given a working example with input and ideal output. Use it to calibrate voice and structure. Do NOT copy its specific facts; use only the facts in the actual case input."""


# Split into two parts so the static example portion can be marked
# with cache_control and reused across calls (saves ~25% per call after
# the first within a 5-minute window). The dynamic portion contains
# only the per-investigation case input.
FEW_SHOT_PROMPT_TEMPLATE = """Below is a working example of how this task should be done, followed by the actual case to draft for.

=== EXAMPLE INPUT ===
{example_input}

=== EXAMPLE IDEAL OUTPUT ===
{example_output}

=== ACTUAL CASE INPUT ===
"""

CASE_PROMPT_TEMPLATE = """{case_input}

=== YOUR TASK ===
Draft the editorial JSON for the actual case. Output only the JSON object, no commentary."""

# Backward-compat alias — older code paths can still call format() on
# this and get a single concatenated string. New code should use the
# split templates above with cache_control on the few-shot block.
USER_PROMPT_TEMPLATE = FEW_SHOT_PROMPT_TEMPLATE + CASE_PROMPT_TEMPLATE




def _now_utc_iso_seconds() -> str:
    """UTC timestamp, second precision, ISO 8601 with trailing Z."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _summarize_case_for_ai(case: Any, victim: Any, freeze_asks: dict[str, Any], victim_narrative: str | None) -> dict[str, Any]:
    """Build a compact, readable summary of the case for the AI prompt.

    We do NOT pass the raw case.json (could be megabytes for big cases). We
    distill it to the facts the AI needs: total drained, first-hop address,
    freezable holdings by issuer, mixer/bridge destinations, label hints.
    """
    from recupero._common import canonical_address_key as _ck
    seed_lower = _ck(case.seed_address)
    total_drained = Decimal("0")
    per_first_hop_usd: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    per_first_hop_first_seen: dict[str, datetime] = {}

    # Count downstream label hints
    mixer_addresses: list[str] = []
    bridge_addresses: list[str] = []
    label_hints: dict[str, str] = {}  # addr -> label name

    # v0.20.2 (audit-round-3 R3-6): canonical-key all per-address
    # aggregates so the AI prompt doesn't see two split rows for
    # the same wallet because Etherscan emitted EIP-55 mixed-case
    # in one transfer and Alchemy emitted lowercase in another.
    # Pre-v0.20.2 a 6-tx perp-hub on V-CFI01 could fragment across
    # 6 separate "first hop" rows; the AI then either picked the
    # wrong consolidation address or emitted duplicate
    # DESTINATION_NOTES that collide downstream. We also preserve
    # the first-seen display casing in per_addr_display so
    # downstream prompts + brief output show the on-chain canonical
    # form.
    per_addr_display: dict[str, str] = {}
    for t in case.transfers:
        # First-hop tracking
        if _ck(t.from_address) == seed_lower:
            to_canon = _ck(t.to_address)
            per_addr_display.setdefault(to_canon, t.to_address)
            if t.usd_value_at_tx is not None:
                total_drained += t.usd_value_at_tx
                per_first_hop_usd[to_canon] += t.usd_value_at_tx
            if (
                to_canon not in per_first_hop_first_seen
                or t.block_time < per_first_hop_first_seen[to_canon]
            ):
                per_first_hop_first_seen[to_canon] = t.block_time

        # Label hints for any downstream address
        if t.counterparty.label:
            cat = t.counterparty.label.category.value
            cp_canon = _ck(t.counterparty.address)
            per_addr_display.setdefault(cp_canon, t.counterparty.address)
            label_hints[cp_canon] = t.counterparty.label.name
            if cat == "mixer" and cp_canon not in mixer_addresses:
                mixer_addresses.append(cp_canon)
            elif cat == "bridge" and cp_canon not in bridge_addresses:
                bridge_addresses.append(cp_canon)

    # Pick the largest first hop as the consolidation/drainer address.
    # The dict is canonical-keyed (v0.20.2 R3-6); we look up the
    # display form via per_addr_display so the AI prompt shows the
    # on-chain canonical case.
    first_hop_candidate: dict[str, Any] = {}
    if per_first_hop_usd:
        first_hop_canon, first_hop_usd = max(
            per_first_hop_usd.items(), key=lambda kv: kv[1],
        )
        first_hop_display = per_addr_display.get(first_hop_canon, first_hop_canon)
        first_hop_candidate = {
            "address": first_hop_display,
            "address_short": _short_addr(first_hop_display),
            "usd_received": f"${first_hop_usd:,.2f}",
            "first_seen_iso": per_first_hop_first_seen[first_hop_canon].isoformat().replace("+00:00", "Z"),
        }

    # Per-address signals the AI uses for emoji classification:
    # - is_contract: True if the destination has bytecode. Contracts that
    #   slip past the dormant filter should be 🟧 INVESTIGATE at most,
    #   never 🟩 FREEZABLE — their on-chain balance is public-infra liquidity.
    # - inflow_usd_during_case: how much of THIS victim's funds reached
    #   the address per our trace. If it's tiny relative to current
    #   balance, the wallet is consolidating from many sources (could
    #   be a perp aggregating victims, or just an unrelated trader).
    # v0.20.2 (audit-round-3 R3-6): canonical-key here too, mirroring
    # the first-hop loop above. The freezable_summary loop below
    # does `address_inflow_usd.get(addr, ...)` against an `addr`
    # pulled from freeze_asks JSON — those addresses are already
    # canonical (lower-cased EVM) because freeze_asks is written via
    # canonical helpers, so the canonical keys here match.
    address_is_contract: dict[str, bool] = {}
    address_inflow_usd: dict[str, Decimal] = {}
    for t in case.transfers:
        addr_canon = _ck(t.to_address)
        if t.counterparty.is_contract:
            address_is_contract[addr_canon] = True
        if t.usd_value_at_tx is not None:
            address_inflow_usd[addr_canon] = (
                address_inflow_usd.get(addr_canon, Decimal("0"))
                + t.usd_value_at_tx
            )

    # Freezable holdings from freeze_asks
    freezable_summary = []
    for issuer_name, asks in freeze_asks.get("by_issuer", {}).items():
        for a in asks:
            addr = a.get("address", "")
            balance_usd = Decimal(str(a.get("usd_value") or "0"))
            # v0.20.2 (audit-round-3 R3-6): canonical-key lookup
            # so the freeze_asks address (whatever case it has)
            # matches the canonical-keyed address_inflow_usd /
            # address_is_contract maps built above.
            addr_canon = _ck(addr)
            inflow = address_inflow_usd.get(addr_canon, Decimal("0"))
            # Magnitude ratio — None if inflow is zero (no signal).
            ratio: str | None = None
            if inflow > 0 and balance_usd > 0:
                r = balance_usd / inflow
                ratio = f"{r:.1f}x" if r < 1000 else f"{r:.0f}x"
            # v0.16.0 (Jacob V-CFI01 bug 2): explicit verification flag.
            # When evidence_type='current_balance' AND we have a non-zero
            # usd_value, this address's holdings were queried on-chain
            # during the dormant-detection stage of this same pipeline
            # run. The AI was previously seeing the balance number but
            # hedging with "if the balance remains on-chain" because
            # there was no positive signal that the number is fresh.
            # The flag makes that confirmation explicit so DESTINATION_
            # NOTES can read "currently holds $X" definitively.
            evidence_type = a.get("evidence_type", "current_balance")
            balance_verified_on_chain = (
                evidence_type == "current_balance" and balance_usd > 0
            )
            freezable_summary.append({
                "address": addr,
                "address_short": _short_addr(addr),
                "issuer": issuer_name,
                "token": a.get("symbol", ""),
                "usd": f"${balance_usd:,.2f}",
                "inflow_usd_from_this_case": f"${inflow:,.2f}",
                "balance_to_inflow_ratio": ratio,
                "is_contract": address_is_contract.get(addr_canon, False),
                "freeze_capability": a.get("freeze_capability", "unknown"),
                # v0.14.9: evidence-type carries through so the AI can
                # distinguish freeze NOW (current_balance) from
                # historical-inflow (still freezable from a process
                # standpoint; the issuer investigates and freezes if
                # the balance remains). Per the SYSTEM_PROMPT,
                # historical_inflow does NOT downgrade the
                # classification.
                "evidence_type": evidence_type,
                "balance_verified_on_chain": balance_verified_on_chain,
                "observed_at": a.get("observed_at"),
                "observed_transfer_count": a.get("observed_transfer_count", 1),
            })

    # Mixer/bridge destinations as candidate UNRECOVERABLE_ITEMS hints
    non_freezable_destinations = []
    for addr in mixer_addresses + bridge_addresses:
        non_freezable_destinations.append({
            "address": addr,
            "address_short": _short_addr(addr),
            "label": label_hints.get(addr, "unknown"),
            "category": "mixer" if addr in mixer_addresses else "bridge",
        })

    # v0.13.4 (Jacob V-CFI01 follow-up): enumerate EVERY downstream
    # destination above a dust threshold, not just the freeze-asks
    # matches. Without this, the AI prompt could only see destinations
    # that already had a freeze_asks entry, so multi-destination cases
    # (perp hub → 14 downstream addresses) silently dropped the
    # downstream destinations from DESTINATION_NOTES.
    all_significant_destinations = _enumerate_all_destinations(
        case=case,
        freeze_asks=freeze_asks,
        label_hints=label_hints,
        seed_lower=seed_lower,
    )

    return {
        "victim": {
            "wallet_full": case.seed_address,
            "wallet_short": _short_addr(case.seed_address),
            "name": getattr(victim, "name", None) or "[victim name]",
            "address": getattr(victim, "address", None) or "[unknown]",
            "email": getattr(victim, "email", None) or "[unknown]",
            "citizenship": getattr(victim, "citizenship", None) or "[unknown]",
        },
        "primary_chain": case.chain.value,
        "incident_time_iso": case.incident_time.isoformat().replace("+00:00", "Z"),
        "incident_date_human": case.incident_time.strftime("%B %d, %Y").replace(" 0", " "),
        "incident_time_utc": case.incident_time.strftime("%H:%M UTC"),
        "total_drained_usd": f"${total_drained:,.2f}",
        "transfer_count": len(case.transfers),
        "first_hop": first_hop_candidate,
        "victim_supplied_narrative": victim_narrative or "[victim did not supply a narrative — draft conservatively from chain data]",
        "current_freezable_holdings": freezable_summary,
        # v0.13.4: every destination >= dust threshold, with USD-received,
        # observed tokens, and freezability hint from freeze_asks where
        # applicable. The AI MUST emit a DESTINATION_NOTES entry per
        # row here. See SYSTEM_PROMPT.
        "all_significant_destinations": all_significant_destinations,
        "non_freezable_destinations": non_freezable_destinations,
        "label_hints": label_hints,
    }


# Dust threshold for the AI's destination enumeration. Matches the brief
# generator's default at recupero.reports.emit_brief.
_AI_DESTINATION_DUST_USD = Decimal("1000.00")


def _enumerate_all_destinations(
    *,
    case: Any,
    freeze_asks: dict[str, Any],
    label_hints: dict[str, str],
    seed_lower: str,
) -> list[dict[str, Any]]:
    """Enumerate every downstream destination in the case above the
    dust threshold so the AI can label every one in DESTINATION_NOTES.

    Pre-v0.13.4 the AI only saw destinations that had a freeze_asks
    entry (i.e., currently hold freezable tokens), missing the
    transit / dormant / non-freezable destinations entirely. The
    Triage Report would then render zero DESTINATION_NOTES for the
    14 downstream addresses in a multi-destination case.

    Returns one dict per destination address with:
      * address + short form
      * usd_received_in_trace (sum across all transfers in)
      * tokens_observed (set of token symbols seen)
      * is_in_freeze_asks (bool) + freezable_token / freezable_usd /
        freeze_capability when applicable
      * label_hint (mixer/bridge/exchange/protocol label if any)
    """
    # v0.20.2 (audit-round-3 R3-6): canonical-key per-address
    # aggregation. Pre-v0.20.2 the same wallet appearing in two
    # transfers with different case forms (Etherscan EIP-55 vs
    # Alchemy lowercase) produced two destination rows in
    # all_significant_destinations — the AI then emitted duplicate
    # DESTINATION_NOTES (or worse, contradictory classifications
    # for the same wallet). `label_hints` is already canonical-keyed
    # by the caller (`_summarize_case_for_ai` v0.20.2). Display
    # casing is preserved via per_addr_display (first-seen wins).
    from recupero._common import canonical_address_key as _ck
    per_addr_received: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    per_addr_tokens: dict[str, set[str]] = defaultdict(set)
    per_addr_display: dict[str, str] = {}
    for t in case.transfers:
        to_raw = t.to_address
        if not to_raw:
            continue
        to_canon = _ck(to_raw)
        if to_canon == seed_lower:
            continue
        per_addr_display.setdefault(to_canon, to_raw)
        if t.usd_value_at_tx is not None:
            per_addr_received[to_canon] += t.usd_value_at_tx
        if t.token and t.token.symbol:
            per_addr_tokens[to_canon].add(t.token.symbol)

    # Index freeze_asks by canonical address for collision-free lookup.
    freeze_by_addr: dict[str, dict[str, Any]] = {}
    for issuer, asks in freeze_asks.get("by_issuer", {}).items():
        for a in asks:
            addr = a.get("address")
            if isinstance(addr, str) and addr:
                addr_canon = _ck(addr)
                freeze_by_addr[addr_canon] = {**a, "issuer": issuer}
                per_addr_display.setdefault(addr_canon, addr)

    candidates: set[str] = {
        a for a, received in per_addr_received.items()
        if received >= _AI_DESTINATION_DUST_USD
    }
    # Always include freeze-asks addresses even if trace inflow is sub-
    # threshold (e.g., $1 of attribution-share but $3M in current
    # balance). The freezable position is what matters for the AI's
    # FREEZABLE classification.
    candidates.update(freeze_by_addr.keys())

    rows: list[dict[str, Any]] = []
    for canon in sorted(
        candidates,
        key=lambda a: per_addr_received.get(a, Decimal("0")),
        reverse=True,
    ):
        addr = per_addr_display.get(canon, canon)
        row: dict[str, Any] = {
            "address": addr,
            "address_short": _short_addr(addr),
            "usd_received_in_trace": f"${per_addr_received.get(canon, Decimal('0')):,.2f}",
            "tokens_observed": sorted(per_addr_tokens.get(canon, set())),
            "label_hint": label_hints.get(canon),
            "is_in_freeze_asks": canon in freeze_by_addr,
        }
        fa = freeze_by_addr.get(canon)
        if fa is not None:
            row["freezable_token"] = fa.get("symbol")
            row["freezable_amount"] = fa.get("amount")
            row["freezable_usd"] = f"${Decimal(str(fa.get('usd_value') or '0')):,.2f}"
            row["freeze_capability"] = fa.get("freeze_capability")
            row["issuer"] = fa.get("issuer")
        rows.append(row)
    return rows


# v0.18.2 (round-11 sec-HIGH-013): per-field length caps prevent a
# 4MB AI output → 4MB PDF render DoS. Conservative ceilings — the
# longest legitimate VICTIM_SUMMARY runs ~1500 chars in worst case;
# INCIDENT_NARRATIVE_RECUPERO ~3000 chars; DESTINATION_NOTES totals
# typically under 8000 chars across all addresses combined. 4× the
# typical max is room to grow without enabling abuse.
_AI_FIELD_MAX_LENGTHS: dict[str, int] = {
    "INCIDENT_TYPE": 200,
    "INCIDENT_NARRATIVE_RECUPERO": 12000,
    "INCIDENT_NARRATIVE_FIRST_PERSON": 12000,
    "VICTIM_JURISDICTION": 300,
    "DESTINATION_NOTES": 32000,  # this is a dict; checked as JSON-encoded length
    "UNRECOVERABLE_ITEMS": 16000,  # list of dicts; same JSON-encoded check
    "VICTIM_SUMMARY": 6000,
}


def _validate_ai_output(ai_obj: dict[str, Any]) -> list[str]:
    """Return a list of validation problems with the AI output. Empty = clean.

    v0.18.2 (round-11 sec-HIGH-013): now also enforces per-field
    length caps (defense against unbounded AI output → PDF DoS) and
    warns about unknown top-level keys (defense against prompt-
    injection that smuggles new fields into the output that future
    template changes might iterate over).
    """
    problems = []
    # v0.18.2: per-field length caps
    for k, max_len in _AI_FIELD_MAX_LENGTHS.items():
        v = ai_obj.get(k)
        if v is None:
            continue
        # For dicts/lists, measure JSON-encoded length (this is what
        # eventually lands in brief_editorial.json).
        if isinstance(v, (dict, list)):
            measured = len(json.dumps(v, ensure_ascii=False))
        elif isinstance(v, str):
            measured = len(v)
        else:
            continue
        if measured > max_len:
            problems.append(
                f"{k} exceeds max length {max_len} (got {measured}) — "
                f"AI output is unbounded; reject to prevent PDF-DoS"
            )
    required_keys = [
        "INCIDENT_TYPE", "INCIDENT_TYPE_AI_CONFIDENCE",
        "INCIDENT_NARRATIVE_RECUPERO", "INCIDENT_NARRATIVE_RECUPERO_AI_CONFIDENCE",
        "INCIDENT_NARRATIVE_FIRST_PERSON", "INCIDENT_NARRATIVE_FIRST_PERSON_AI_CONFIDENCE",
        "VICTIM_JURISDICTION", "VICTIM_JURISDICTION_AI_CONFIDENCE",
        "DESTINATION_NOTES", "DESTINATION_NOTES_AI_CONFIDENCE",
        "UNRECOVERABLE_ITEMS", "UNRECOVERABLE_ITEMS_AI_CONFIDENCE",
        # v0.15.0: plain-English summary for the victim's eyes.
        # Separate from INCIDENT_NARRATIVE_RECUPERO (forensic) and
        # INCIDENT_NARRATIVE_FIRST_PERSON (legal). VICTIM_SUMMARY is
        # 4-6 sentences explaining what happened, where the funds are
        # now, what Recupero is doing, and realistic expectations.
        "VICTIM_SUMMARY", "VICTIM_SUMMARY_AI_CONFIDENCE",
    ]
    for k in required_keys:
        if k not in ai_obj:
            problems.append(f"missing key: {k}")

    # v0.18.2 (round-11 sec-HIGH-013): unknown-key warning. Pydantic
    # `extra="forbid"` equivalent — prompt-injection attacker can't
    # smuggle a new field (e.g., "INCIDENT_NARRATIVE_RECUPERO_OVERRIDE")
    # that future template changes might iterate over. We WARN
    # (not hard-fail) so adding new legitimate fields in a future
    # release doesn't require updating this list in lock-step.
    _allowed_keys = set(required_keys) | {
        # Optional / forward-compat keys the model may emit.
        "REVIEW_REQUIRED",
        "REVIEW_REASON",
        "TEMPLATE_VERSION",
        "INVESTIGATOR_NOTES",
    }
    unknown = set(ai_obj.keys()) - _allowed_keys
    if unknown:
        # Don't fail — just log so the model's drift surfaces. The
        # downstream emit_brief loop picks only keys it knows.
        log.warning(
            "ai_editorial: unknown top-level keys in AI output: %s "
            "(allowed: required + %s)", sorted(unknown), sorted(_allowed_keys - set(required_keys)),
        )

    valid_confidence = {"low", "medium", "high"}
    for k, v in ai_obj.items():
        if k.endswith("_AI_CONFIDENCE") and v not in valid_confidence:
            problems.append(f"{k} = {v!r}, expected one of {valid_confidence}")

    if "DESTINATION_NOTES" in ai_obj and not isinstance(ai_obj["DESTINATION_NOTES"], dict):
        problems.append("DESTINATION_NOTES must be an object/dict")

    if "UNRECOVERABLE_ITEMS" in ai_obj:
        if not isinstance(ai_obj["UNRECOVERABLE_ITEMS"], list):
            problems.append("UNRECOVERABLE_ITEMS must be a list")
        else:
            for i, item in enumerate(ai_obj["UNRECOVERABLE_ITEMS"]):
                if not isinstance(item, dict):
                    problems.append(f"UNRECOVERABLE_ITEMS[{i}] is not an object")
                    continue
                if "asset" not in item or "reason" not in item:
                    problems.append(f"UNRECOVERABLE_ITEMS[{i}] missing 'asset' or 'reason'")

    # Forbidden hedging phrases. Scan covers DESTINATION_NOTES (only
    # when the note is tagged FREEZABLE — INVESTIGATE rows can hedge
    # legitimately) plus the narrative fields (HEADLINE FRAMING rule
    # also forbids hedging there). On match, the retry loop re-prompts
    # the model.
    _FORBIDDEN_PHRASES_NEAR_FREEZABLE = (
        "if the balance remains",
        "if balances remain",
        "if balances are still",
        "if the funds remain",
        "if funds remain at",
        "should the balance persist",
        "should be confirmed before issuer outreach",
        "current balance should be confirmed",
        "subject to confirmation",
        "pending verification of the balance",
        "pending balance verification",
        "may be viable",
    )
    notes = ai_obj.get("DESTINATION_NOTES")
    if isinstance(notes, dict):
        for addr, note_text in notes.items():
            if not isinstance(note_text, str):
                continue
            note_lower = note_text.lower()
            # Only flag if the note ALSO claims FREEZABLE — the model
            # can legitimately hedge on INVESTIGATE-status addresses.
            if "freezable" not in note_lower:
                continue
            for phrase in _FORBIDDEN_PHRASES_NEAR_FREEZABLE:
                if phrase in note_lower:
                    problems.append(
                        f"DESTINATION_NOTES[{addr}] contains forbidden "
                        f"hedging phrase {phrase!r} on a FREEZABLE-tagged "
                        f"address. Per SYSTEM_PROMPT (v0.16.0 rule), "
                        f"write definitive 'currently holds $X' language "
                        f"when balance_verified_on_chain is True, OR "
                        f"'received approximately $X during the trace' "
                        f"when evidence_type is historical_inflow."
                    )
                    break  # one problem per note is enough

    # v0.16.3: scan VICTIM_SUMMARY + INCIDENT_NARRATIVE_RECUPERO for
    # the same hedging phrases. The HEADLINE FRAMING rule in the
    # SYSTEM_PROMPT also forbids hedging in these narrative fields.
    for narrative_key in ("VICTIM_SUMMARY", "INCIDENT_NARRATIVE_RECUPERO"):
        narrative = ai_obj.get(narrative_key)
        if not isinstance(narrative, str):
            continue
        narrative_lower = narrative.lower()
        for phrase in _FORBIDDEN_PHRASES_NEAR_FREEZABLE:
            if phrase in narrative_lower:
                problems.append(
                    f"{narrative_key} contains forbidden hedging phrase "
                    f"{phrase!r}. Use definitive language for confirmed "
                    f"balances; 'received approximately $X' for "
                    f"historical-inflow asks."
                )
                break  # one problem per field is enough

    # VICTIM_SUMMARY structural checks. SYSTEM_PROMPT target is 4-6
    # sentences; validator floors at 3 / ceilings at 10 to allow some
    # slack while still catching obvious deviations. Also forbids
    # legal jargon, guaranteed-recovery claims, and hex addresses —
    # this is the customer-facing paragraph, plain English only.
    vs = ai_obj.get("VICTIM_SUMMARY")
    if isinstance(vs, str) and vs.strip():
        # Sentence count via regex so runs of punctuation (".." in
        # ellipses, "?!" emphasis) collapse to one sentence boundary
        # each. A naive `.!?` counter false-triggered the ceiling on
        # legitimate prose using ellipses.
        sentence_count = len(re.findall(r"[.!?]+", vs))
        if sentence_count < 3:
            problems.append(
                f"VICTIM_SUMMARY has only ~{sentence_count} sentence(s); "
                f"validator floor is 3 (SYSTEM_PROMPT target is 4-6)."
            )
        elif sentence_count > 10:
            problems.append(
                f"VICTIM_SUMMARY has ~{sentence_count} sentences; "
                f"validator ceiling is 10 (SYSTEM_PROMPT target is 4-6)."
            )
        vs_lower = vs.lower()
        forbidden_in_victim_summary = (
            "subpoena", "mlat", "compelled disclosure",
            "guaranteed recovery", "we guarantee",
        )
        for word in forbidden_in_victim_summary:
            if word in vs_lower:
                problems.append(
                    f"VICTIM_SUMMARY contains forbidden term {word!r}; "
                    f"the customer-facing paragraph must not use legal "
                    f"jargon or guaranteed-recovery language."
                )
        # No hex addresses in the customer paragraph.
        if "0x" in vs and any(c in vs for c in "0123456789abcdef"):
            # Crude — but the prompt forbids hex addresses entirely.
            import re as _re
            if _re.search(r"0x[0-9a-fA-F]{8,}", vs):
                problems.append(
                    "VICTIM_SUMMARY contains a hex address (0x…) — the "
                    "customer paragraph must use plain language only, "
                    "not on-chain identifiers."
                )

    return problems


def _strip_json_fences(text: str) -> str:
    """If the model wrapped JSON in ```json ... ``` fences, strip them."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _call_messages_with_retry(
    *,
    client: Any,
    system_blocks: list[dict[str, Any]],
    user_content_blocks: list[dict[str, Any]],
    transient_excs: tuple[type[BaseException], ...],
    wait_seq_sec: tuple[int, ...] = _ANTHROPIC_RETRY_WAITS_SEC,
) -> Any:
    """Call ``client.messages.create`` with explicit retry on transient
    failures (Anthropic 529 / 5xx / timeouts / connection errors).

    The Anthropic SDK has a built-in retry but defaults to 2 attempts
    with sub-second initial backoff — not enough for sustained
    capacity events. We force the SDK to do zero retries (set
    ``max_retries=0`` on the Anthropic client) and run our own loop
    here with the spec'd 10s/30s/60s waits.

    On 4xx errors that aren't 429 (validation, auth, bad request),
    we don't retry — those are caller bugs that won't fix themselves
    by waiting. We classify by exception type: anthropic.RateLimitError
    is 429 (retry), anthropic.BadRequestError is 400 (don't retry —
    but we have to defer the discriminator to runtime because the
    exception classes are only available after `import anthropic`).

    Returns the SDK response object on success. Raises the original
    exception after all retries are exhausted.
    """
    last_exc: BaseException | None = None
    total_attempts = len(wait_seq_sec) + 1
    for attempt_idx in range(total_attempts):
        try:
            return client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=system_blocks,
                messages=[{"role": "user", "content": user_content_blocks}],
            )
        except transient_excs as exc:  # noqa: PERF203 — explicit per-attempt control
            last_exc = exc
            # Try to extract HTTP status for the log line. APIStatusError
            # exposes ``status_code``; for httpx errors there's no status.
            status = getattr(exc, "status_code", None) or getattr(
                getattr(exc, "response", None), "status_code", None,
            )
            if attempt_idx >= len(wait_seq_sec):
                log.warning(
                    "anthropic call failed after %d attempts (status=%s): %s",
                    total_attempts, status, exc,
                )
                raise
            wait_sec = wait_seq_sec[attempt_idx]
            log.warning(
                "anthropic transient failure (status=%s) on attempt %d/%d — "
                "retrying in %ds: %s",
                status, attempt_idx + 1, total_attempts, wait_sec, exc,
            )
            time.sleep(wait_sec)
    # Defensive — shouldn't reach here because the loop either returns
    # or raises. v0.17.3 (round-10 audit HIGH): `assert` stripped under
    # `python -O`, then `raise None` masks the actual error.
    if last_exc is None:
        raise RuntimeError(
            "anthropic retry loop exited without exception — unreachable"
        )
    raise last_exc


def call_anthropic_for_editorial(
    case_summary: dict[str, Any],
    api_key: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Call the Anthropic API and return ``(editorial_dict, usage_info)``.

    ``usage_info`` is ``{"input_tokens": int, "output_tokens": int,
    "model": str, "usd_cost": Decimal}``, summed across retries so a
    JSON-validation retry is reflected in the cost.

    Raises RuntimeError on API failure or malformed output (after one retry).
    """
    try:
        import anthropic  # lazy import
    except ImportError as e:
        raise RuntimeError(
            "anthropic package not installed. Run: pip install anthropic --break-system-packages"
        ) from e

    # Fallback chain:
    #   1. explicit api_key argument (from --api-key flag)
    #   2. ANTHROPIC_API_KEY in shell environment ($env:ANTHROPIC_API_KEY)
    #   3. ANTHROPIC_API_KEY in .env (auto-loaded by RecuperoEnv via pydantic-settings)
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        try:
            from recupero.config import load_config
            _, env = load_config()
            api_key = env.ANTHROPIC_API_KEY or None
        except Exception:
            pass
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY not set. Add it to recupero-io/.env or your shell environment."
        )

    # The Anthropic SDK ships with a built-in `max_retries` config
    # but defaults to 2 retries with short backoff — not enough for
    # the sustained 529 overloaded_error capacity events Jacob
    # reported. We disable the SDK-level retry (max_retries=0) and
    # do our own loop below with explicit 10s/30s/60s waits.
    client = anthropic.Anthropic(api_key=api_key, max_retries=0)

    # Identify the transient-failure exception types once, here, so
    # the inner retry loop stays readable. Imports are local so this
    # module still imports cleanly when anthropic isn't installed.
    try:
        import httpx
        _transient_excs: tuple[type[BaseException], ...] = (
            anthropic.APIStatusError,        # HTTP errors incl. 529
            anthropic.APITimeoutError,
            anthropic.APIConnectionError,
            anthropic.RateLimitError,        # 429
            httpx.TimeoutException,
            httpx.ConnectError,
            httpx.RemoteProtocolError,
        )
    except Exception:  # noqa: BLE001
        # Conservative fallback if the SDK changes its exception
        # hierarchy — catch the broad APIError parent so we don't
        # silently drop retries.
        _transient_excs = (anthropic.APIError,)

    # Split the prompt into:
    #   1. system prompt (static across all calls) — cached
    #   2. few-shot example (static) — cached
    #   3. actual case input (dynamic) — not cached
    # Anthropic's prompt cache returns the cached portions at ~10% of
    # input price within a 5-minute window. For Recupero's editorial
    # prompt (~3-4K input tokens of which ~3K is static), the savings
    # is ~25% per call after the first one.
    few_shot_block = FEW_SHOT_PROMPT_TEMPLATE.format(
        example_input=json.dumps(FEW_SHOT_EXAMPLE["input_summary"], indent=2),
        example_output=json.dumps(FEW_SHOT_EXAMPLE["output"], indent=2),
    )
    case_block = CASE_PROMPT_TEMPLATE.format(
        case_input=json.dumps(case_summary, indent=2),
    )
    case_block_text = case_block  # mutable across retries

    last_error = None
    in_total = 0
    out_total = 0
    cache_creation_total = 0
    cache_read_total = 0
    # Hard cost ceiling so a misbehaving model can't burn through the
    # budget on retries. Typical cost is $0.05-0.15; $2 leaves plenty
    # of headroom while protecting against runaway loops.
    #
    # v0.17.8 (round-10 ops HIGH): operator-overridable via
    # ``RECUPERO_AI_MAX_USD_PER_CALL`` env. Tightening is desirable
    # in CI / staging where a $2 runaway burns real budget across
    # many failing tests. Disabling (set to 0) preserves backward
    # compatibility but logs a WARN.
    _MAX_USD_PER_CALL = _resolve_max_usd_per_call()
    for attempt in range(2):  # one retry on bad JSON
        # Pre-flight cost check on retries only (first attempt hasn't
        # billed anything yet).
        if attempt > 0:
            current_cost = _compute_usd_cost(
                in_total, out_total,
                cache_creation=cache_creation_total,
                cache_read=cache_read_total,
            )
            if current_cost > _MAX_USD_PER_CALL:
                raise RuntimeError(
                    f"ai_editorial: cumulative cost ${current_cost} "
                    f"exceeded ceiling ${_MAX_USD_PER_CALL}. Aborting "
                    f"retry. Last error: {last_error!r}"
                )
        try:
            resp = _call_messages_with_retry(
                client=client,
                system_blocks=[
                    {
                        "type": "text",
                        "text": SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"},
                    },
                ],
                user_content_blocks=[
                    {
                        "type": "text",
                        "text": few_shot_block,
                        "cache_control": {"type": "ephemeral"},
                    },
                    {"type": "text", "text": case_block_text},
                ],
                transient_excs=_transient_excs,
            )

            # Tally tokens even on retries — they all cost money. Track
            # cache hits separately so usage_info can show how much we saved.
            usage = getattr(resp, "usage", None)
            if usage is not None:
                in_total += int(getattr(usage, "input_tokens", 0) or 0)
                out_total += int(getattr(usage, "output_tokens", 0) or 0)
                cache_creation_total += int(getattr(usage, "cache_creation_input_tokens", 0) or 0)
                cache_read_total += int(getattr(usage, "cache_read_input_tokens", 0) or 0)

            # Concatenate text blocks
            text_parts = []
            for block in resp.content:
                if hasattr(block, "text"):
                    text_parts.append(block.text)
            raw = "".join(text_parts)
            cleaned = _strip_json_fences(raw)

            ai_obj = json.loads(cleaned)
            problems = _validate_ai_output(ai_obj)
            if problems:
                last_error = f"AI output failed validation: {problems[:3]}"
                if attempt == 0:
                    # Add an explicit nudge for the retry. Append to the
                    # case_block so the cached system + few-shot blocks
                    # still hit the cache on retry.
                    case_block_text = (
                        case_block
                        + f"\n\nYour previous response had validation problems: {problems[:3]}. "
                        "Please output ONLY a valid JSON object with all required keys."
                    )
                    continue
                raise RuntimeError(last_error)

            usage_info = {
                "input_tokens": in_total,
                "output_tokens": out_total,
                "cache_creation_input_tokens": cache_creation_total,
                "cache_read_input_tokens": cache_read_total,
                "model": MODEL,
                "usd_cost": _compute_usd_cost(
                    in_total, out_total,
                    cache_creation=cache_creation_total,
                    cache_read=cache_read_total,
                ),
            }
            return ai_obj, usage_info

        except json.JSONDecodeError as e:
            last_error = f"AI returned invalid JSON: {e}"
            if attempt == 0:
                # Append the nudge to case_block_text (the dynamic
                # block) so the cached system + few-shot blocks still
                # hit the cache on retry. Same pattern as the
                # validation-failure retry above.
                case_block_text = (
                    case_block
                    + "\n\nYour previous response was not valid JSON. "
                    "Output ONLY a JSON object, no preamble or markdown fences."
                )
                continue
            raise RuntimeError(last_error) from e

    raise RuntimeError(last_error or "Unknown failure calling Anthropic API")


def build_editorial_dict(
    ai_output: dict[str, Any],
    case_summary: dict[str, Any],
    case_id: str | None = None,
    *,
    case_row_prefill: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Combine AI-drafted fields with static defaults and review markers.

    Output is the brief_editorial.json that emit-brief consumes (with the
    REVIEW_REQUIRED gate set true, blocking emit-brief until the human flips it).

    If `case_id` is provided, it's used as the CASE_ID; otherwise CASE_ID is left
    as a TODO for the reviewer to assign.
    """
    now_iso = _now_utc_iso_seconds()
    today_human = datetime.now(UTC).strftime("%B %d, %Y").replace(" 0", " ")

    editorial: dict[str, Any] = {
        # Top-level review gate
        "AI_GENERATED": True,
        "AI_MODEL": MODEL,
        "AI_GENERATED_AT": now_iso,
        "REVIEW_REQUIRED": True,
        "REVIEW_INSTRUCTIONS": (
            "This file was drafted by an AI. Before running `recupero emit-brief`, "
            "(1) review every AI-drafted field for accuracy, (2) replace any TODO "
            "placeholders, (3) edit any fields with _AI_CONFIDENCE 'low' or 'medium', "
            "and (4) set REVIEW_REQUIRED to false. The emit-brief command will refuse "
            "to run while REVIEW_REQUIRED is true."
        ),
    }

    # Mechanical fields the AI doesn't draft — derived from the case
    editorial["CASE_ID"] = case_id if case_id else "TODO: assign case ID (e.g. RCP-2026-0427)"
    editorial["REPORT_DATE"] = today_human
    editorial["INCIDENT_DATE"] = case_summary.get("incident_date_human", "TODO: incident date")
    editorial["PRIMARY_CHAIN"] = {
        "ethereum": "Ethereum",
        "arbitrum": "Arbitrum",
        "bsc": "BNB Chain",
        "base": "Base",
        "polygon": "Polygon",
        "solana": "Solana",
        "bitcoin": "Bitcoin",
    }.get(case_summary.get("primary_chain", ""), case_summary.get("primary_chain", "Ethereum").capitalize())

    # Try to derive victim address lines from the victim object the case carries
    victim_address = case_summary.get("victim", {}).get("address", "")
    if victim_address and victim_address != "[unknown]":
        parts = [s.strip() for s in victim_address.split(",")]
        # Heuristic: if the address has at least 2 comma-separated parts,
        # use the first part as LINE1 and join the rest as LINE2.
        # If only one part (e.g., user typed full address without commas),
        # dump it all into LINE1 and leave LINE2 as TODO.
        if len(parts) >= 2:
            editorial["VICTIM_ADDRESS_LINE1"] = parts[0]
            editorial["VICTIM_ADDRESS_LINE2"] = ", ".join(parts[1:])
        else:
            editorial["VICTIM_ADDRESS_LINE1"] = parts[0] if parts else "TODO: street address"
            editorial["VICTIM_ADDRESS_LINE2"] = "TODO: city/state/zip"
    else:
        editorial["VICTIM_ADDRESS_LINE1"] = "TODO: victim street address"
        editorial["VICTIM_ADDRESS_LINE2"] = "TODO: victim city/state/zip"

    # AI-drafted fields. Single pass: copy each AI-drafted key and its
    # _AI_CONFIDENCE sibling together. Required-key validation happened
    # earlier in _validate_ai_output.
    for key in AI_DRAFTED_KEYS:
        editorial[key] = ai_output.get(key)
        conf_key = f"{key}_AI_CONFIDENCE"
        if conf_key in ai_output:
            editorial[conf_key] = ai_output[conf_key]

    # Override AI's VICTIM_JURISDICTION TODO if we have citizenship from victim.json.
    # Better-grounded values (citizenship from PII intake) trump the AI's guess.
    citizenship = case_summary.get("victim", {}).get("citizenship", "")
    if citizenship and citizenship != "[unknown]":
        # If citizenship is "USA" we still need state — leave a hedged but useful value.
        # If citizenship is something like "USA (Texas)" or "Germany", just use it directly.
        current_jurisdiction = editorial.get("VICTIM_JURISDICTION", "")
        if isinstance(current_jurisdiction, str) and current_jurisdiction.startswith("TODO"):
            editorial["VICTIM_JURISDICTION"] = citizenship
            editorial["VICTIM_JURISDICTION_AI_CONFIDENCE"] = "medium"

    # Investigator defaults — resolved at call-time so env-var rotation
    # takes effect without a worker restart (round-10 audit fix).
    for k, v in _investigator_defaults().items():
        editorial[k] = v
    # TEMPLATE_VERSION sits alongside the investigator fields in the
    # written editorial dict; it tracks the editorial schema rather
    # than operator identity, so it stays out of the canonical
    # `investigator_defaults()` return.
    editorial["TEMPLATE_VERSION"] = _EDITORIAL_TEMPLATE_VERSION

    # Pre-fill from the cases row (PR #12 columns: address_line1,
    # address_line2, jurisdiction, ic3_case_id). Applied LAST so a
    # non-empty case-row value beats both the heuristic-derived
    # VICTIM_ADDRESS_LINE1/2 from victim.json and the AI's TODO
    # placeholder for VICTIM_JURISDICTION. Empty / None values are
    # skipped — the existing TODO placeholders remain so the
    # operator review form still prompts for them.
    #
    # This eliminates the "operator re-types data that's already in
    # the database" friction Jacob flagged in the reliability ask.
    # See docs/INTAKE_ADDRESS_VALIDATION.md for the upstream
    # validation rules that ensure these columns are reasonably
    # well-formed when present.
    if case_row_prefill:
        for key, value in case_row_prefill.items():
            if not value:
                continue
            stripped = str(value).strip()
            if not stripped:
                continue
            # Defensive: reject case-row values that ALREADY look
            # like TODO placeholders. Discovered on V-ZTST01 where
            # 'TODO: victim city/state/zip' had been persisted into
            # the address_line2 column during smoke testing.
            # Without this guard we'd cheerfully pre-fill a TODO,
            # which slips past the validator at this layer and
            # forces the operator review form back into the data-
            # entry mode Jacob's ask was trying to eliminate.
            if stripped.upper().startswith("TODO"):
                continue
            editorial[key] = value
            # Mark high confidence — these came directly from
            # the operator-curated cases row, not from AI
            # inference. Lets the review form surface them
            # differently if Jacob's UI cares.
            conf_key = f"{key}_AI_CONFIDENCE"
            if conf_key in editorial or key in {
                "VICTIM_JURISDICTION", "IC3_CASE_ID",
            }:
                editorial[conf_key] = "high"

    return editorial


def run_ai_editorial(
    case_id: str,
    case_store: Any,
    victim_narrative: str | None = None,
    api_key: str | None = None,
    *,
    case_row_prefill: dict[str, str] | None = None,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    """Top-level orchestration.

    Returns ``(output_path, editorial_dict, usage_info)`` where
    ``usage_info`` carries token counts and the computed USD cost. The
    CLI ignores the third element; the worker uses it to populate
    ``investigations.api_costs_usd``.

    Reads case.json, victim.json, freeze_asks.json. Calls the Anthropic API.
    Writes brief_editorial.json (overwriting any existing file).
    """
    # Lazy import here so the module can be imported without recupero installed.
    from recupero.reports.victim import load_victim

    case_dir: Path = case_store.case_dir(case_id)

    # 1. Load case
    case = case_store.read_case(case_id)

    # 2. Load victim (may be missing — we degrade gracefully)
    try:
        victim = load_victim(case_dir)
    except Exception:
        # Fabricate a minimal stand-in so the AI prompt still works
        class _MissingVictim:
            name = None
            address = None
            email = None
            phone = None
        victim = _MissingVictim()

    # 3. Load freeze asks (may be missing — that's okay, AI handles empty case)
    freeze_asks_path = case_dir / "freeze_asks.json"
    freeze_asks: dict[str, Any] = {}
    if freeze_asks_path.exists():
        try:
            freeze_asks = json.loads(freeze_asks_path.read_text(encoding="utf-8-sig"))
        except Exception:
            freeze_asks = {}

    # 4. Build the case summary
    case_summary = _summarize_case_for_ai(case, victim, freeze_asks, victim_narrative)

    # 5. Call AI
    ai_output, usage_info = call_anthropic_for_editorial(case_summary, api_key=api_key)

    # 6. Build the editorial dict
    editorial = build_editorial_dict(
        ai_output, case_summary, case_id=case_id,
        case_row_prefill=case_row_prefill,
    )

    # 7. Write
    #
    # v0.16.9 (round-9 output-artifacts MEDIUM): ensure_ascii=True so
    # non-ASCII content survives every downstream consumer regardless
    # of OS encoding. The emoji status prefixes (🟩 🟧 ⬛ 🟦) used to
    # ship native — readable on Linux/macOS but rendered as mojibake
    # when Windows operators opened the file in cp1252-defaulting
    # tools, breaking _classify_address_status (which expects clean
    # UTF-8 to detect the prefix). \u-escapes are universal.
    out_path = case_dir / "brief_editorial.json"
    # Atomic write — same rationale as other artifact writes in v0.16.8.
    from recupero._common import atomic_write_text
    atomic_write_text(
        out_path,
        json.dumps(editorial, indent=2, ensure_ascii=True),
    )

    return out_path, editorial, usage_info


# Helper for emit_brief.py to detect AI-generated unreviewed editorials.
def is_unreviewed_ai_editorial(editorial: dict[str, Any]) -> bool:
    return bool(editorial.get("AI_GENERATED")) and bool(editorial.get("REVIEW_REQUIRED"))
