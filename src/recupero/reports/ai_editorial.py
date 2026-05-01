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
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

# anthropic is loaded lazily so module import doesn't fail without the package.

MODEL = "claude-opus-4-7"
MAX_TOKENS = 4096

# USD pricing per million tokens. Update when Anthropic adjusts list prices.
# Source: https://www.anthropic.com/pricing  (Opus 4.7, Jan 2026)
_INPUT_USD_PER_MTOK = Decimal("15.0")
_OUTPUT_USD_PER_MTOK = Decimal("75.0")


def _compute_usd_cost(input_tokens: int, output_tokens: int) -> Decimal:
    """Token counts → USD spend. Quantized to 4 decimal places."""
    cost = (
        Decimal(input_tokens) * _INPUT_USD_PER_MTOK / Decimal(1_000_000)
        + Decimal(output_tokens) * _OUTPUT_USD_PER_MTOK / Decimal(1_000_000)
    )
    return cost.quantize(Decimal("0.0001"))

# Fields the AI is asked to draft. Other editorial fields (investigator name,
# entity, etc.) are static and don't go through the AI.
AI_DRAFTED_KEYS = [
    "INCIDENT_TYPE",
    "INCIDENT_NARRATIVE_RECUPERO",
    "INCIDENT_NARRATIVE_FIRST_PERSON",
    "VICTIM_JURISDICTION",
    "DESTINATION_NOTES",
    "UNRECOVERABLE_ITEMS",
]

# Fields the AI is given but does NOT draft (it just passes them through or
# uses them as facts to ground its drafts).
# TODO: when a second investigator joins, read these from the active user's
# config or from env vars (e.g. RECUPERO_INVESTIGATOR_NAME) rather than
# hardcoding. Solo-operator mode for now.
STATIC_EDITORIAL_DEFAULTS = {
    "INVESTIGATOR_NAME": "Alec Prostok",
    "INVESTIGATOR_EMAIL": "alec@recupero.io",
    "INVESTIGATOR_ENTITY": "Recupero LLC",
    "INVESTIGATOR_ENTITY_FULL": "Recupero LLC, a Delaware limited liability company",
    "INVESTIGATOR_WEB": "recupero.io",
    "TEMPLATE_VERSION": "v1.0 — April 2026",
}

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
            "total_usd_drained": "47840",
            "first_hop_address": "0x7B2e9A4c8F3d5E1a6C4b9D8e2F5a3C6b1D4e8F2a",
            "first_hop_role": "Drainer consolidation wallet — received and immediately distributed",
            "current_freezable_holdings": [
                {"address": "0x3C8f5A2b4D7e9C1a3E6b8D2F4A5c7B9D1E3f5A7c", "token": "USDC", "issuer": "Circle", "usd": "28420"},
                {"address": "0x5D9e4A3c7B2f8D6a1E5c4B9D2F3a7c5B1E4d6F8a", "token": "USDT", "issuer": "Tether", "usd": "12640"},
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
            "$47,840 in USDC, USDT, and ETH. On-chain trace data is consistent with a malicious token "
            "approval signed on a phishing site presenting itself as a Uniswap governance token claim "
            "page. Funds moved through a drainer consolidation wallet (0x7B2e…8F2a) and were "
            "redistributed within minutes. Approximately $41,060 of the proceeds remain dormant in "
            "USDC and USDT at addresses that may be subject to issuer-level freeze action by Circle "
            "and Tether. The remainder (~$6,780 in ETH) was deposited to Tornado Cash and is not "
            "recoverable through current techniques."
        ),
        "INCIDENT_NARRATIVE_RECUPERO_AI_CONFIDENCE": "medium",
        "INCIDENT_NARRATIVE_FIRST_PERSON": (
            "On April 19, 2026, at approximately 14:22 UTC, I signed a transaction on a website that "
            "appeared to be a Uniswap governance token claim page. The transaction was a malicious "
            "token approval, and within minutes my wallet was drained of all of its USDC, USDT, and a "
            "small ETH balance. The total loss was approximately $47,840. I did not authorize the "
            "transfers that followed, and I am the sole signer of the wallet."
        ),
        "INCIDENT_NARRATIVE_FIRST_PERSON_AI_CONFIDENCE": "medium",
        "VICTIM_JURISDICTION": "TODO: confirm victim's state/country (e.g. 'USA (California)')",
        "VICTIM_JURISDICTION_AI_CONFIDENCE": "low",
        "DESTINATION_NOTES": {
            "0x7B2e9A4c8F3d5E1a6C4b9D8e2F5a3C6b1D4e8F2a": "Drainer consolidation wallet — received the full $47,840 and immediately redistributed within minutes. Currently holds nothing.",
            "0x3C8f5A2b4D7e9C1a3E6b8D2F4A5c7B9D1E3f5A7c": "🟩 FREEZABLE — Circle-issued USDC. Holds $28,420. Dormant since drain. Subject of Exhibit B.1 freeze request.",
            "0x5D9e4A3c7B2f8D6a1E5c4B9D2F3a7c5B1E4d6F8a": "🟩 FREEZABLE — Tether-issued USDT. Holds $12,640. Dormant since drain. Subject of Exhibit B.2 freeze request.",
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
    },
}


SYSTEM_PROMPT = """You are an editorial drafting assistant for Recupero LLC, an on-chain investigation firm that produces "$99 Triage" reports for crypto theft victims. Your output is reviewed by a human investigator (Alec Prostok) before being sent to a customer.

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

For DESTINATION_NOTES, use these emoji prefixes consistently:
  🟩 FREEZABLE — for addresses currently holding freezable tokens (Circle USDC, Tether USDT, Paxos, etc.)
  ⬛ UNRECOVERABLE — for mixer deposits, bridges to anonymous chains, burn addresses, AND for DEX aggregator routers (1inch, CoW Protocol GPv2 settlement, 0x, ParaSwap), the WETH9 contract when funds were wrapped and swapped, and liquid-staking token contracts (Lido stETH, Rocket Pool rETH). Briefly say WHY (e.g., "DEX aggregator routing — funds dispersed to swap counterparties; not freezable")
  🟦 EXCHANGE — for known exchange deposit addresses (Binance, Coinbase, Kraken, etc.)
  🟧 INVESTIGATE — for addresses worth investigating but unclear status (e.g., very large balances that may be unrelated, addresses that look like protocol contracts but you're not certain)
  (no emoji) — for transit/intermediate wallets the perpetrator controls but with no current freezable balance

For UNRECOVERABLE_ITEMS, include any portion of the stolen funds that the chain data shows are practically unrecoverable to this victim. Be honest with the customer — it helps them set expectations even when the news is bad. The following patterns are practically unrecoverable even if technically traceable:

  - Funds sent to mixers (Tornado Cash, Sinbad, Wasabi CoinJoin, etc.) — clearly unrecoverable
  - Funds bridged to anonymous chains (Monero, Zcash shielded, etc.) — clearly unrecoverable
  - Funds sent to a burn address (0x000...000, 0x000...dead) — clearly unrecoverable
  - Funds swapped through a DEX aggregator (1inch Aggregation Router v5/v6, CoW Protocol GPv2 settlement, 0x Protocol, ParaSwap) — these route to a wide swap counterparty pool; the victim cannot practically claw back from the swap counterparties
  - Funds wrapped to WETH (deposited into the WETH9 contract at 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) and then swapped — once wrapped and swapped, recovery requires identifying and pursuing each swap counterparty, which is not feasible in a triage report
  - Funds converted to liquid-staking tokens (Lido stETH at 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84, Rocket Pool rETH, Frax sfrxETH) — these tokens have no issuer freeze mechanism comparable to USDC/USDT
  - Funds deposited into a centralized exchange's hot wallet WITHOUT a clear deposit attribution (e.g., funds went to a known exchange but not via an identifiable user-deposit address) — exchange compliance teams may help, but the triage report should not promise recovery

For each unrecoverable item include `asset` (e.g., "approximately 6.4 ETH (~$15,200)") and `reason` (e.g., "Wrapped to WETH and swapped via 1inch Aggregation Router; recovery requires identifying each swap counterparty and is not feasible in a triage report"). Be specific about the dollar amount and the mechanism. If nothing is clearly unrecoverable, return an empty array. Do not invent unrecoverable losses.

You'll be given a working example with input and ideal output. Use it to calibrate voice and structure. Do NOT copy its specific facts; use only the facts in the actual case input."""


USER_PROMPT_TEMPLATE = """Below is a working example of how this task should be done, followed by the actual case to draft for.

=== EXAMPLE INPUT ===
{example_input}

=== EXAMPLE IDEAL OUTPUT ===
{example_output}

=== ACTUAL CASE INPUT ===
{case_input}

=== YOUR TASK ===
Draft the editorial JSON for the actual case. Output only the JSON object, no commentary."""


def _short_addr(addr: str) -> str:
    if len(addr) <= 10:
        return addr
    return f"{addr[:6]}…{addr[-4:]}"


def _now_utc_iso_seconds() -> str:
    """UTC timestamp, second precision, ISO 8601 with trailing Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _summarize_case_for_ai(case: Any, victim: Any, freeze_asks: dict[str, Any], victim_narrative: str | None) -> dict[str, Any]:
    """Build a compact, readable summary of the case for the AI prompt.

    We do NOT pass the raw case.json (could be megabytes for big cases). We
    distill it to the facts the AI needs: total drained, first-hop address,
    freezable holdings by issuer, mixer/bridge destinations, label hints.
    """
    seed_lower = case.seed_address.lower()
    total_drained = Decimal("0")
    per_first_hop_usd: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
    per_first_hop_first_seen: dict[str, datetime] = {}

    # Count downstream label hints
    mixer_addresses: list[str] = []
    bridge_addresses: list[str] = []
    label_hints: dict[str, str] = {}  # addr -> label name

    for t in case.transfers:
        # First-hop tracking
        if t.from_address.lower() == seed_lower:
            if t.usd_value_at_tx is not None:
                total_drained += t.usd_value_at_tx
                per_first_hop_usd[t.to_address] += t.usd_value_at_tx
            if t.to_address not in per_first_hop_first_seen or t.block_time < per_first_hop_first_seen[t.to_address]:
                per_first_hop_first_seen[t.to_address] = t.block_time

        # Label hints for any downstream address
        if t.counterparty.label:
            cat = t.counterparty.label.category.value
            label_hints[t.counterparty.address] = t.counterparty.label.name
            if cat == "mixer" and t.counterparty.address not in mixer_addresses:
                mixer_addresses.append(t.counterparty.address)
            elif cat == "bridge" and t.counterparty.address not in bridge_addresses:
                bridge_addresses.append(t.counterparty.address)

    # Pick the largest first hop as the consolidation/drainer address
    first_hop_candidate: dict[str, Any] = {}
    if per_first_hop_usd:
        first_hop_addr, first_hop_usd = max(per_first_hop_usd.items(), key=lambda kv: kv[1])
        first_hop_candidate = {
            "address": first_hop_addr,
            "address_short": _short_addr(first_hop_addr),
            "usd_received": f"${first_hop_usd:,.2f}",
            "first_seen_iso": per_first_hop_first_seen[first_hop_addr].isoformat().replace("+00:00", "Z"),
        }

    # Freezable holdings from freeze_asks
    freezable_summary = []
    for issuer_name, asks in freeze_asks.get("by_issuer", {}).items():
        for a in asks:
            freezable_summary.append({
                "address": a.get("address", ""),
                "address_short": _short_addr(a.get("address", "")),
                "issuer": issuer_name,
                "token": a.get("symbol", ""),
                "usd": f"${Decimal(str(a.get('usd_value') or '0')):,.2f}",
                "freeze_capability": a.get("freeze_capability", "unknown"),
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
        "non_freezable_destinations": non_freezable_destinations,
        "label_hints": label_hints,
    }


def _validate_ai_output(ai_obj: dict[str, Any]) -> list[str]:
    """Return a list of validation problems with the AI output. Empty = clean."""
    problems = []
    required_keys = [
        "INCIDENT_TYPE", "INCIDENT_TYPE_AI_CONFIDENCE",
        "INCIDENT_NARRATIVE_RECUPERO", "INCIDENT_NARRATIVE_RECUPERO_AI_CONFIDENCE",
        "INCIDENT_NARRATIVE_FIRST_PERSON", "INCIDENT_NARRATIVE_FIRST_PERSON_AI_CONFIDENCE",
        "VICTIM_JURISDICTION", "VICTIM_JURISDICTION_AI_CONFIDENCE",
        "DESTINATION_NOTES", "DESTINATION_NOTES_AI_CONFIDENCE",
        "UNRECOVERABLE_ITEMS", "UNRECOVERABLE_ITEMS_AI_CONFIDENCE",
    ]
    for k in required_keys:
        if k not in ai_obj:
            problems.append(f"missing key: {k}")

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

    return problems


def _strip_json_fences(text: str) -> str:
    """If the model wrapped JSON in ```json ... ``` fences, strip them."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


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

    client = anthropic.Anthropic(api_key=api_key)

    user_prompt = USER_PROMPT_TEMPLATE.format(
        example_input=json.dumps(FEW_SHOT_EXAMPLE["input_summary"], indent=2),
        example_output=json.dumps(FEW_SHOT_EXAMPLE["output"], indent=2),
        case_input=json.dumps(case_summary, indent=2),
    )

    last_error = None
    in_total = 0
    out_total = 0
    for attempt in range(2):  # one retry on bad JSON
        try:
            resp = client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )

            # Tally tokens even on retries — they all cost money.
            usage = getattr(resp, "usage", None)
            if usage is not None:
                in_total += int(getattr(usage, "input_tokens", 0) or 0)
                out_total += int(getattr(usage, "output_tokens", 0) or 0)

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
                    # Add an explicit nudge for the retry
                    user_prompt = (
                        user_prompt
                        + f"\n\nYour previous response had validation problems: {problems[:3]}. "
                        "Please output ONLY a valid JSON object with all required keys."
                    )
                    continue
                raise RuntimeError(last_error)

            usage_info = {
                "input_tokens": in_total,
                "output_tokens": out_total,
                "model": MODEL,
                "usd_cost": _compute_usd_cost(in_total, out_total),
            }
            return ai_obj, usage_info

        except json.JSONDecodeError as e:
            last_error = f"AI returned invalid JSON: {e}"
            if attempt == 0:
                user_prompt = user_prompt + "\n\nYour previous response was not valid JSON. Output ONLY a JSON object, no preamble or markdown fences."
                continue
            raise RuntimeError(last_error) from e

    raise RuntimeError(last_error or "Unknown failure calling Anthropic API")


def build_editorial_dict(ai_output: dict[str, Any], case_summary: dict[str, Any], case_id: str | None = None) -> dict[str, Any]:
    """Combine AI-drafted fields with static defaults and review markers.

    Output is the brief_editorial.json that emit-brief consumes (with the
    REVIEW_REQUIRED gate set true, blocking emit-brief until the human flips it).

    If `case_id` is provided, it's used as the CASE_ID; otherwise CASE_ID is left
    as a TODO for the reviewer to assign.
    """
    now_iso = _now_utc_iso_seconds()
    today_human = datetime.now(timezone.utc).strftime("%B %d, %Y").replace(" 0", " ")

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

    # Static defaults
    for k, v in STATIC_EDITORIAL_DEFAULTS.items():
        editorial[k] = v

    return editorial


def run_ai_editorial(case_id: str, case_store: Any, victim_narrative: str | None = None, api_key: str | None = None) -> tuple[Path, dict[str, Any], dict[str, Any]]:
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
    editorial = build_editorial_dict(ai_output, case_summary, case_id=case_id)

    # 7. Write
    out_path = case_dir / "brief_editorial.json"
    out_path.write_text(json.dumps(editorial, indent=2, ensure_ascii=False), encoding="utf-8")

    return out_path, editorial, usage_info


# Helper for emit_brief.py to detect AI-generated unreviewed editorials.
def is_unreviewed_ai_editorial(editorial: dict[str, Any]) -> bool:
    return bool(editorial.get("AI_GENERATED")) and bool(editorial.get("REVIEW_REQUIRED"))
