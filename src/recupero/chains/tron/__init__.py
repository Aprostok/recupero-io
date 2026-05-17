"""Tron chain support (v0.12.0).

Why Tron matters
----------------

Roughly half of all USDT-denominated value moves on the Tron network
(TRC-20 USDT contract: TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t). Pig-
butchering, Southeast-Asia laundering networks, and many sanctions
evasion routes flow through Tron USDT because fees are sub-cent and
liquidity is deep. TRM Labs and Chainalysis both have full Tron
coverage — without it, any case where the victim sent funds to or
from a Tron address dead-ends.

What's in this package
----------------------

  address.py — base58check ↔ hex conversion, validation, checksum.
               Tron addresses look like ``T9zKjY...`` (base58check)
               but the hex form (``41`` + 20-byte payload) is what
               TRC-20 contract events use.

  client.py  — Thin TronGrid REST client. TronGrid is the canonical
               public JSON-RPC + REST gateway maintained by the
               Tron Foundation (similar role to Etherscan for EVM).
               Free tier: 100k req/day, ~10 req/sec.

  adapter.py — ChainAdapter implementation. Normalizes TronGrid
               responses into the Transfer / EvidenceReceipt schemas
               so the rest of the pipeline doesn't care it's Tron.

Scope of v0.12.0
----------------

Ships the core trace capability: given a Tron address, fetch TRC-20
USDT (and other TRC-20) outflows as normalized Transfer records that
flow through the same risk-scoring / clustering / brief pipeline as
EVM chains.

Out of scope (queued for v0.12.x or v0.13):
  * TRX native transfers (lower priority — laundering uses USDT)
  * TRC-10 tokens (legacy, low-volume)
  * Internal contract calls (we read top-level TRC-20 events only)
  * Cross-chain bridge calldata (Tron has its own bridge set — JustLend,
    SUN.io — not yet in bridges.json)

Reference docs:
  https://developers.tron.network/reference/getting-started-with-trongrid
  https://developers.tron.network/reference/trc20-transactions
"""
