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

    Legitimate tx_hashes are hex (EVM, ``0x``-prefixed), base58 (Solana / Sui /
    Bitcoin txid), or base64 (TON ``transaction_id.hash``). Traversal shapes
    (``..``, backslash, null bytes, control chars, Windows reserved names) are
    rejected. A base64 forward-slash is SANITIZED to ``_`` for the filename (it is
    not a traversal vector on its own) rather than rejected — otherwise ~half of
    TON evidence receipts would be dropped. The real tx_hash is preserved verbatim
    inside the receipt JSON for explorer verification. Returns the sanitized,
    filesystem-safe filename token.
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
    # Backslash is the Windows path separator and never appears in a legitimate
    # tx hash (hex / base58 / base64) — reject it (traversal defense).
    if "\\" in tx_hash:
        raise ValueError(
            f"tx_hash contains a backslash — invalid (traversal? got {tx_hash!r})"
        )
    # Traversal segments. Checked on the raw string so we catch ``..`` anywhere;
    # legitimate hex / base58 / base64 tx hashes never contain ``.``.
    if ".." in tx_hash:
        raise ValueError(
            f"tx_hash contains traversal segment '..' — invalid (got {tx_hash!r})"
        )
    # A FORWARD slash appears in legitimate base64 tx hashes (TON's
    # transaction_id.hash is base64, alphabet A-Za-z0-9+/). On its own it is NOT a
    # traversal vector: ``..`` and backslash are rejected above, and the caller
    # re-verifies the resolved path stays inside evidence_dir. So we map it to a
    # filesystem-safe token instead of DROPPING valid TON evidence (~half of TON
    # hashes contain '/'). base64/hex/base58 never contain '_', so this rename is
    # deterministic and collision-free; the true tx_hash is preserved in the
    # receipt JSON.
    safe = tx_hash.replace("/", "_")
    # Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    # cannot be used as filenames even with an extension. Belt-and-
    # suspenders on a name we will write as ``{safe}.json``.
    _windows_reserved = {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
    if safe.upper() in _windows_reserved:
        raise ValueError(
            f"tx_hash matches Windows reserved device name — invalid (got {tx_hash!r})"
        )
    return safe


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
