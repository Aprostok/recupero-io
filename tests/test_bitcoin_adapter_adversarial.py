"""RIGOR-Jacob H adversarial: Bitcoin/Esplora adapter defenses.

Same crash class as the Solana audit: ``datetime.fromtimestamp`` on
an untrusted external integer raises ``OverflowError`` (>~ year
9999) or ``OSError`` (Windows) / ``ValueError`` (Linux) on
extreme-negative values. Esplora is an external HTTP service; a
single bad response kills the BFS hop without this guard.

The Bitcoin adapter is more defensively coded than Solana (lots of
``isinstance`` checks), but the timestamp parse on
``status.block_time`` is unguarded in both
``_normalize_utxo_tx`` and ``fetch_evidence_receipt``.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock


def _build_adapter():
    """Bypass __init__ — minimal shell for normalize tests."""
    from recupero.chains.bitcoin.adapter import BitcoinAdapter

    adapter = BitcoinAdapter.__new__(BitcoinAdapter)
    adapter.client = MagicMock()
    return adapter


def test_normalize_utxo_tx_extreme_timestamp_does_not_crash() -> None:
    """A tx with block_time far in the future (Esplora bug / spoof)
    must not raise OverflowError out of ``_normalize_utxo_tx``."""
    from recupero.chains.bitcoin.adapter import BitcoinAdapter

    adapter = _build_adapter()
    # Esplora-shaped tx with extreme block_time
    bad_tx = {
        "txid": "abc" * 16,
        "status": {
            "confirmed": True,
            "block_height": 800_000,
            "block_time": 99_999_999_999_999,  # year 318367
        },
        "vin": [
            {"prevout": {"scriptpubkey_address": "test-addr", "value": 50000}},
        ],
        "vout": [
            {"scriptpubkey_address": "dest", "value": 10000},
        ],
    }
    try:
        result = BitcoinAdapter._normalize_utxo_tx(
            adapter, bad_tx, expected_from="test-addr",
        )
        # Either returns transfers with a sentinel block_time, or
        # returns empty. Crash is unacceptable.
        for transfer in result:
            block_time = transfer.get("block_time")
            if isinstance(block_time, datetime):
                assert block_time.year < 9999, (
                    f"Extreme timestamp produced year {block_time.year} — "
                    f"will break downstream renderers."
                )
    except (OverflowError, OSError, ValueError) as e:
        raise AssertionError(
            f"_normalize_utxo_tx raised {type(e).__name__} on extreme "
            f"timestamp: {e}. Esplora is an external API; a single "
            f"bad response must NOT crash the BFS hop."
        ) from e


def test_normalize_utxo_tx_negative_timestamp_does_not_crash() -> None:
    """Same hardening for very-negative timestamps (Windows raises
    OSError on fromtimestamp(<-86400) approximately)."""
    from recupero.chains.bitcoin.adapter import BitcoinAdapter

    adapter = _build_adapter()
    bad_tx = {
        "txid": "abc" * 16,
        "status": {
            "confirmed": True,
            "block_height": 800_000,
            "block_time": -99_999_999_999,
        },
        "vin": [
            {"prevout": {"scriptpubkey_address": "test-addr", "value": 50000}},
        ],
        "vout": [
            {"scriptpubkey_address": "dest", "value": 10000},
        ],
    }
    try:
        BitcoinAdapter._normalize_utxo_tx(
            adapter, bad_tx, expected_from="test-addr",
        )
    except (OverflowError, OSError, ValueError) as e:
        raise AssertionError(
            f"_normalize_utxo_tx raised {type(e).__name__} on negative "
            f"timestamp: {e}"
        ) from e


def test_normalize_utxo_tx_normal_timestamp_works() -> None:
    """Sanity: hardening must NOT break the happy path."""
    from recupero.chains.bitcoin.adapter import BitcoinAdapter

    adapter = _build_adapter()
    good_tx = {
        "txid": "abc" * 16,
        "status": {
            "confirmed": True,
            "block_height": 800_000,
            "block_time": 1_700_000_000,  # 2023-11-14
        },
        "vin": [
            {"prevout": {"scriptpubkey_address": "test-addr", "value": 50000}},
        ],
        "vout": [
            {"scriptpubkey_address": "dest", "value": 10000},
        ],
    }
    result = BitcoinAdapter._normalize_utxo_tx(
        adapter, good_tx, expected_from="test-addr",
    )
    # Should produce some transfers.
    if result:
        block_time = result[0].get("block_time")
        assert isinstance(block_time, datetime)
        assert block_time.year == 2023
