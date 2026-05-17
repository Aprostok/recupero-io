"""Token honeypot / rug-pull risk scoring (v0.13.3).

Many recovery cases dead-end at a "your-funds-are-locked" honeypot
contract — a token whose ``transfer`` function silently reverts
for non-owner addresses, or one whose ``_transfer`` includes a
hidden blacklist. Recovering from a honeypot is impossible (the
funds never moved off the contract); detecting one early saves
investigator time and lets the victim's brief explicitly say
"this was a honeypot, the funds are unrecoverable" rather than
"the funds are at this random contract".

What this module does
---------------------

Score any ERC-20 token contract for honeypot / rug-pull risk.
Two layers:

  1. **Local heuristics** (free, fast, offline):
     - Contract bytecode pattern matching for known honeypot
       signatures (``onlyOwner`` modifier on transfer, anti-bot
       blacklists, ``maxTransactionAmount`` clamps).
     - Tx history pattern checks — high buy-volume + zero sell
       success = honeypot; large LP-removal txs near the launch
       block = rug-pull pattern.

  2. **GoPlus Security API** (free tier, 30 req/min):
     Third-party honeypot scanner with broad coverage. Used as
     a confirming signal when the local heuristics are ambiguous.
     API: https://docs.gopluslabs.io/reference/api-overview

Output shape
------------

::

    TokenRiskAssessment(
        contract_address="0x...",
        chain="ethereum",
        verdict="honeypot" | "high_risk_rug" | "medium_risk" | "clean",
        risk_score=0..10,
        signals=[TokenRiskSignal(...), ...],
        investigator_note="...",
    )

Compatible with the existing risk_scoring + screen API output —
addable to the brief's RISK_ASSESSMENT section as a new
``token_risk`` category.
"""
