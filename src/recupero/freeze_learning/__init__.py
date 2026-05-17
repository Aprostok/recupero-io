"""Freeze-letter outcome tracking + learned priors (v0.14.2).

The compounding-moat capability for Recupero: every recovery the
operator runs makes the next one more precise. TRM/Chainalysis
can't build this because they're not the requestor — they don't
see freeze outcomes.

Three-table substrate
---------------------

  freeze_letters_sent — one row per outbound letter (created at
    send-time, immutable).
  freeze_outcomes — one row per outcome event (multiple per
    letter as the issuer's response evolves).
  issuer_freeze_priors — aggregated per-(issuer, letter_language)
    success rates + response times. Refreshed nightly. Read by
    recupero.recovery.scorer.

Workflow
--------

1. Operator sends a freeze letter via the worker's dispatch
   pathway. ``record_letter_sent()`` writes the
   freeze_letters_sent row.

2. As the issuer responds (or doesn't), the operator records
   outcome events via ``record_outcome()`` — either through
   the admin UI or the CLI.

3. Nightly cron (or on-demand via ``recupero-ops
   refresh-freeze-priors``) runs ``refresh_priors()`` which
   aggregates outcomes → priors. The recovery scorer reads from
   priors next time it runs.

4. Once an issuer has 20+ samples, the recovery scorer switches
   from hand-coded heuristics to learned priors for that issuer.
   Below 20 samples: heuristic prior + log "small sample".

The 20-sample threshold balances statistical noise vs. waiting
forever to switch over. With Recupero's case volume that lands
in 6-12 months for the major issuers.
"""
