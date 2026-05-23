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


# RIGOR-Jacob Z18-2 (HIGH, path traversal): tx_hash arrives here verbatim
# from chain-adapter responses (or stale-cache replays). The
# downstream call ``evidence_dir / f"{tx_hash}.json"`` is a path-join,
# meaning ``tx_hash='../../escape'`` writes the receipt OUTSIDE
# evidence_dir — overwriting arbitrary files reachable by the worker.
# Same threat class as RIGOR-Jacob K/M (CaseStore). Validate at the
# boundary, reject hostile shapes loudly.
_TX_HASH_MAX_LEN = 256  # safely covers EVM 0x+64hex and Solana base58 ~88


def _validate_tx_hash_for_filename(tx_hash: str) -> str:
    """Reject tx_hashes that would write outside the evidence directory
    or produce ambiguous filenames.

    Legitimate tx_hashes are hex (EVM, ``0x``-prefixed) or base58
    (Solana / Bitcoin txid) — never contain ``/``, ``\\``, ``..``, null
    bytes, or Windows reserved device names. Anything else is a
    fingerprint of malformed adapter output, stale-cache replay of a
    hostile case, or an outright traversal attempt.
    """
    if not isinstance(tx_hash, str):
        raise ValueError(
            f"tx_hash must be a string, got {type(tx_hash).__name__}"
        )
    if not tx_hash:
        raise ValueError("tx_hash must not be empty (invalid adapter output)")
    if len(tx_hash) > _TX_HASH_MAX_LEN:
        raise ValueError(
            f"tx_hash exceeds max length of {_TX_HASH_MAX_LEN} chars "
            f"(got {len(tx_hash)}) — invalid"
        )
    if "\x00" in tx_hash:
        raise ValueError("tx_hash contains a null byte — invalid (control char)")
    # Reject any other ASCII control char too. These break tooling
    # (grep, logs, downstream LE handoff text fields).
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in tx_hash):
        raise ValueError("tx_hash contains a control character — invalid")
    # Path separators or traversal segments. We check the raw string
    # so we catch ``..`` even when it's not at a boundary; legitimate
    # hex / base58 sigs cannot contain ``.``.
    if "/" in tx_hash or "\\" in tx_hash:
        raise ValueError(
            f"tx_hash contains a path separator — invalid (traversal? got {tx_hash!r})"
        )
    if ".." in tx_hash:
        raise ValueError(
            f"tx_hash contains traversal segment '..' — invalid (got {tx_hash!r})"
        )
    # Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    # cannot be used as filenames even with an extension. Belt-and-
    # suspenders on a name we will write as ``{tx_hash}.json``.
    _windows_reserved = {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
    if tx_hash.upper() in _windows_reserved:
        raise ValueError(
            f"tx_hash matches Windows reserved device name — invalid (got {tx_hash!r})"
        )
    return tx_hash


def write_evidence_receipt(adapter: ChainAdapter, tx_hash: str, evidence_dir: Path) -> Path:
    """Fetch and persist the receipt for tx_hash. Returns the path written.

    Idempotent: if the receipt already exists on disk, returns the path without
    re-fetching. Use force=True to override (not exposed in Phase 1).
    """
    # RIGOR-Jacob Z18-2: validate BEFORE constructing the path. Hostile
    # tx_hash → ValueError at the boundary; never reach the filesystem.
    safe_tx = _validate_tx_hash_for_filename(tx_hash)

    evidence_dir.mkdir(parents=True, exist_ok=True)
    path = evidence_dir / f"{safe_tx}.json"

    # Defense-in-depth: confirm the resolved path is still inside the
    # evidence directory. A future refactor that bypasses the string
    # validator (or an OS-level symlink in evidence_dir) would still
    # be caught here.
    try:
        evidence_root = evidence_dir.resolve()
        resolved = path.resolve()
    except (OSError, ValueError) as e:
        raise ValueError(
            f"could not resolve evidence path for tx_hash={safe_tx!r}: {e}"
        ) from e
    try:
        resolved.relative_to(evidence_root)
    except ValueError as e:
        raise ValueError(
            f"resolved evidence path escapes evidence_dir "
            f"(tx_hash={safe_tx!r}, path={resolved!r})"
        ) from e

    if path.exists():
        return path

    receipt: EvidenceReceipt = adapter.fetch_evidence_receipt(tx_hash)
    payload = receipt.model_dump(mode="json")
    path.write_bytes(orjson.dumps(payload, option=orjson.OPT_INDENT_2))
    log.debug("wrote evidence receipt %s", path)
    return path
