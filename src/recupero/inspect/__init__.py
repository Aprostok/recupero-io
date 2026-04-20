"""Address inspector — quick on-chain profile of any address.

Given an address, returns a structured AddressProfile answering:
  - Is it a contract or an EOA?
  - What is its first/last on-chain activity?
  - What's its current ETH balance?
  - Top counterparties by transaction count (recency-weighted)
  - Best-guess identity heuristic
  - Any existing label in our database

Used both interactively (CLI: `recupero inspect <addr>`) and programmatically
(by future Phase 2+ code that needs to classify many counterparties at once).
"""
