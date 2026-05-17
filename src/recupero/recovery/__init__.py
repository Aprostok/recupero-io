"""Recovery probability scoring + cost model (v0.14.1).

This is the orthogonal-to-TRM/Chainalysis capability. They sell
compliance/KYT; Recupero sells recovery. The number that matters
to a victim or lawyer isn't "risk score" — it's "expected net
recovery after fees, given THIS case shape." That's what this
module computes.

Output
------

For any case, returns a RecoveryEstimate with:

  * P(recovered > 0 within 90 days) — does anything come back at all?
  * P(recovered > engagement_fee within 180 days) — does it pay back?
  * E[USD recovered] — expected dollar amount with 95% CI band.
  * E[net to victim] — recovered minus our fees minus expected legal.
  * Recommendation: 'recommend' / 'caveat' / 'discourage' / 'reject'

The brief surfaces:
  "Expected net recovery: $X (95% CI: $Y..$Z)
   Recommendation: RECOMMEND ENGAGEMENT
   Drivers: $3.1M concentrated in 1 freezable Maple position;
   issuer freeze probability 73%; jurisdiction USA (favorable)."

Calibration
-----------

v0.14.1 ships heuristic priors. Real outcome data feeds the model
once the freeze_outcomes table (v0.14.2) accumulates — at that
point we switch from hand-coded weights to fitted coefficients
from the operator's own historical cases.

For now, the model is a transparent function of:
  * freezable_usd, unrecoverable_usd, total_loss_usd
  * jurisdiction (USA/EU favorable; certain non-coop jurisdictions
    penalty)
  * counterparty_count (concentrated = good; dispersed = bad)
  * issuer mix (Circle/Tether > Maple > exchange-deposit > nothing)
  * time-since-incident (rapid = good; >30 days = decay)
  * OFAC/sanctioned exposure (perp is identifiable target +)
"""
