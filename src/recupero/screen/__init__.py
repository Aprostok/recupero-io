"""Wallet-screening API (v0.12.1).

Single-address risk lookup without running a full case trace.

Pre-v0.12.1 every risk assessment required a full ``recupero trace``
run — fetch all outflows, build a case, then run risk_scoring on
the assembled transfers. That's the right shape for forensic
investigations but overkill for compliance use cases:

  * An exchange compliance team wants to score a deposit address
    BEFORE clearing the deposit. They don't need a 200-transfer
    trace — they need a yes/no answer in 100ms.

  * An issuer (Circle, Tether, Paxos) wants to screen a freeze
    candidate against OFAC + correlation history.

  * An attorney wants to spot-check an address from a court filing.

This module exposes that capability as a pure function::

    from recupero.screen import screen_address

    result = screen_address("0xabc...", chain="ethereum")
    result.risk_verdict        # 'sanctioned' | 'high' | 'medium' | 'low' | 'clean'
    result.is_ofac_sanctioned  # bool
    result.prior_case_count    # int (from cross-case correlation DB)
    result.labels              # list[Label]
    result.investigator_note   # one-sentence verdict for humans

The function uses ONLY local seed data (high_risk.json, mixers.json,
ransomware.json, ofac_crypto_live.csv) plus the correlation DB —
zero on-chain fetches. Latency is bounded by a Postgres point-lookup
(<50ms on Supabase).

What this gives Recupero
------------------------

This is TRM Labs' core API product (their KYT — Know Your Transaction
— offering, which exchanges pay ~$50k-$200k/year for). Same surface,
same response shape. Useful directly as a CLI for ops, and easily
exposable as a REST endpoint via the worker's existing HTTP handler.
"""
