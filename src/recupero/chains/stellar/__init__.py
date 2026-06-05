"""Stellar chain support (#9 chain breadth).

Stellar is a real stablecoin off-ramp — USDC (Circle) and USDT live on it as
issued assets, which matters for the freeze pathway (issuer-controlled assets
can be frozen). Coverage:

  * ``address`` — StrKey account-id validation (``G`` + base32).
  * ``client`` — HorizonClient over the public Horizon API (account payments +
    account state). No auth needed (free public endpoint).
  * ``adapter`` — StellarAdapter: native XLM + issued-asset (USDC/USDT) payment
    outflows.

Data shapes were captured live from horizon.stellar.org before implementation.
"""
