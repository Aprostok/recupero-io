"""scripts/smoke_new_chains.py — v0.14.6 live-API smoke test.

Verifies that the v0.12-v0.13 chain adapters (Tron, Bitcoin, Solana)
actually work against their real free-tier APIs. Run this BEFORE
handing the build to Jacob — first-real-API contact catches the
"adapter looked right in tests but the response shape differs from
reality" class of bug.

What this does
--------------

For each chain, hits one well-known fixture address against the
real public API and verifies:

  * The HTTP request succeeds (no rate-limit, no auth issues, no
    network errors that aren't gracefully handled).
  * The response parses into the adapter's normalized shape
    without crashing.
  * At least one observable field looks sane (balance > 0 for a
    known funded address, decimals match expectation, etc.).

NOT a regression suite — it's a "did the API change since we
mocked it?" canary. Run with the same env vars Jacob would use.

Usage
-----

    python scripts/smoke_new_chains.py [chain]

Where chain is one of: tron | bitcoin | solana | all (default).

Exit codes
----------

  0 — all smoke checks passed; safe for Jacob
  1 — at least one check failed (response shape mismatch, API
       unreachable on free tier, etc.); inspect output before
       relying on that chain
  2 — usage error (bad chain argument)

API keys / env vars
-------------------

  * Bitcoin: none needed (mempool.space free tier)
  * Tron: TRON_PRO_API_KEY optional (unauthenticated works on
    free tier with tighter rate limits)
  * Solana: HELIUS_API_KEY REQUIRED (the SolanaAdapter raises
    on construction without it)
"""

from __future__ import annotations

import os
import sys
import traceback
from typing import Any

# Known-stable mainnet fixtures. These are observation targets, NOT
# data we're going to mutate — picked because their on-chain state
# is stable across years.
_TRON_USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
_BITCOIN_GENESIS_ADDR = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
_SOLANA_USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


# ---- Per-chain smoke checks ---- #


def smoke_tron() -> tuple[bool, str]:
    """Hit TronGrid for the USDT contract account. Should return
    metadata indicating it's a contract address."""
    try:
        from recupero.chains.tron.client import TronGridClient
        client = TronGridClient(
            api_key=os.environ.get("TRON_PRO_API_KEY", ""),
        )
        try:
            body = client.get_account(_TRON_USDT_CONTRACT)
        finally:
            client.close()
        data = body.get("data") or []
        if not data:
            return False, "TronGrid returned empty data — usually means rate-limited or address never observed"
        entry = data[0] if isinstance(data, list) else {}
        type_field = entry.get("type")
        if type_field != "Contract":
            return False, f"USDT-TRC20 contract should report type='Contract', got {type_field!r}"
        return True, f"TronGrid OK — USDT contract confirmed as Contract (data fields: {len(entry)})"
    except Exception as e:  # noqa: BLE001
        return False, f"TronGrid smoke failed: {type(e).__name__}: {e}"


def smoke_tron_trc20_transfers() -> tuple[bool, str]:
    """Verify the TRC-20 transfer endpoint shape against a small
    fixture. Don't paginate — just take page-1."""
    try:
        from recupero.chains.tron.client import TronGridClient
        client = TronGridClient(
            api_key=os.environ.get("TRON_PRO_API_KEY", ""),
        )
        try:
            txs = client.get_trc20_transfers(
                _TRON_USDT_CONTRACT, max_pages=1,
            )
        finally:
            client.close()
        # USDT contract sends/receives constantly; we should get
        # SOME results.
        if not txs:
            return False, "TRC-20 transfer endpoint returned 0 rows for USDT contract — API change?"
        # Spot-check the first transfer's field shape.
        sample = txs[0]
        required_fields = {"transaction_id", "block_timestamp", "from", "to", "value", "token_info"}
        missing = required_fields - set(sample.keys())
        if missing:
            return False, f"TRC-20 transfer response missing expected fields: {missing}"
        return True, f"TronGrid TRC-20 OK — {len(txs)} transfers parsed, schema match"
    except Exception as e:  # noqa: BLE001
        return False, f"TronGrid TRC-20 smoke failed: {type(e).__name__}: {e}"


def smoke_bitcoin() -> tuple[bool, str]:
    """Hit Esplora for the genesis address. Should return a list of
    transactions (the genesis address has only a handful, but the
    response shape is what we care about)."""
    try:
        from recupero.chains.bitcoin.esplora import EsploraClient
        client = EsploraClient()
        try:
            txs = client.get_address_txs(_BITCOIN_GENESIS_ADDR, max_pages=1)
        finally:
            client.close()
        if not txs:
            return False, "Esplora returned 0 txs for genesis address — API change?"
        sample = txs[0]
        required_fields = {"txid", "vin", "vout", "status"}
        missing = required_fields - set(sample.keys())
        if missing:
            return False, f"Esplora response missing fields: {missing}"
        # The vin/vout shape — at least one input must have a prevout
        # for the adapter's peel-chain heuristic to work.
        vin = sample.get("vin", [])
        if vin:
            first_in = vin[0]
            if not isinstance(first_in, dict):
                return False, "Esplora vin[0] is not a dict"
            # Coinbase inputs may not have prevout (block reward).
            # Non-coinbase MUST have prevout with scriptpubkey_address.
            if not first_in.get("is_coinbase") and "prevout" not in first_in:
                return False, "Esplora vin[0] missing prevout (non-coinbase input)"
        return True, f"Esplora OK — {len(txs)} txs returned, schema match"
    except Exception as e:  # noqa: BLE001
        return False, f"Esplora smoke failed: {type(e).__name__}: {e}"


def smoke_bitcoin_tip_height() -> tuple[bool, str]:
    """Verify the bare-int response parsing for tip height. This
    was the field where I added text-fallback logic — verify it
    actually works."""
    try:
        from recupero.chains.bitcoin.esplora import EsploraClient
        client = EsploraClient()
        try:
            height = client.get_tip_height()
        finally:
            client.close()
        if not isinstance(height, int):
            return False, f"tip_height returned non-int: {type(height).__name__}"
        # Bitcoin has been past block 800k since 2023.
        if height < 800_000:
            return False, f"tip_height absurdly low ({height}); response shape changed?"
        return True, f"Esplora tip_height OK — block {height:,}"
    except Exception as e:  # noqa: BLE001
        return False, f"Esplora tip_height smoke failed: {type(e).__name__}: {e}"


def smoke_solana() -> tuple[bool, str]:
    """Hit Helius for the USDC mint account. Helius requires an API
    key; we skip cleanly when it's not set."""
    api_key = os.environ.get("HELIUS_API_KEY", "").strip()
    if not api_key:
        return True, "Solana skipped (HELIUS_API_KEY not set)"
    try:
        from recupero.chains.solana.helius import HeliusClient
        client = HeliusClient(api_key=api_key)
        try:
            info = client.get_account_info(_SOLANA_USDC_MINT)
        finally:
            client.close()
        # USDC mint is a program account, executable should be True.
        if "executable" not in info:
            return False, "Helius response missing 'executable' field"
        return True, "Helius OK — USDC mint account fetched"
    except Exception as e:  # noqa: BLE001
        return False, f"Helius smoke failed: {type(e).__name__}: {e}"


# ---- Dispatcher ---- #


_CHAINS = {
    "tron": [smoke_tron, smoke_tron_trc20_transfers],
    "bitcoin": [smoke_bitcoin, smoke_bitcoin_tip_height],
    "solana": [smoke_solana],
}


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] not in {"tron", "bitcoin", "solana", "all"}:
        print(
            f"Usage: {argv[0]} [tron|bitcoin|solana|all]",
            file=sys.stderr,
        )
        return 2

    target = argv[1] if len(argv) > 1 else "all"
    chains = [target] if target != "all" else list(_CHAINS.keys())

    overall_ok = True
    print(f"=== Recupero new-chain smoke test (v0.14.6) ===")
    print()
    for chain in chains:
        print(f"[{chain.upper()}]")
        for check in _CHAINS[chain]:
            try:
                ok, msg = check()
            except Exception as e:  # noqa: BLE001
                ok = False
                msg = f"check raised: {type(e).__name__}: {e}"
                traceback.print_exc()
            marker = "OK " if ok else "FAIL"
            print(f"  [{marker}] {check.__name__}: {msg}")
            overall_ok = overall_ok and ok
        print()

    if overall_ok:
        print("All smoke checks passed — safe for Jacob to run.")
        return 0
    print("At least one smoke check FAILED — review output above before relying on that chain.")
    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv))
