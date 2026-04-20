"""Per-transaction evidence receipts.

For each transfer we surface, we fetch and persist a full chain receipt. This is
what makes the output verifiable: any LE recipient can take the tx_hash from our
report, paste it into Etherscan, and confirm the same data.

The receipt also captures *when we fetched it* (chain-of-custody) — non-trivial
if the chain reorgs or if we need to demonstrate the data we relied on at
report-generation time.
"""

from __future__ import annotations

import logging
from pathlib import Path

import orjson

from recupero.chains.base import ChainAdapter
from recupero.models import EvidenceReceipt

log = logging.getLogger(__name__)


def write_evidence_receipt(adapter: ChainAdapter, tx_hash: str, evidence_dir: Path) -> Path:
    """Fetch and persist the receipt for tx_hash. Returns the path written.

    Idempotent: if the receipt already exists on disk, returns the path without
    re-fetching. Use force=True to override (not exposed in Phase 1).
    """
    evidence_dir.mkdir(parents=True, exist_ok=True)
    path = evidence_dir / f"{tx_hash}.json"
    if path.exists():
        return path

    receipt: EvidenceReceipt = adapter.fetch_evidence_receipt(tx_hash)
    payload = receipt.model_dump(mode="json")
    path.write_bytes(orjson.dumps(payload, option=orjson.OPT_INDENT_2))
    log.debug("wrote evidence receipt %s", path)
    return path
