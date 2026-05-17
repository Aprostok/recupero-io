"""recupero-ops custody-keygen / custody-verify

custody-keygen
  Generate a new Ed25519 keypair for chain-of-custody signing.
  Writes the private key to RECUPERO_CUSTODY_KEY_PATH (default
  ~/.recupero/custody_key) with mode 0600, and the base64 public
  key alongside as <key>.pub.

custody-verify
  Walk a case's custody/chain.jsonl and verify every entry's
  signature + hash links + artifact hashes.

Exit codes:
  0 — chain verifies cleanly (no critical findings)
  1 — chain has critical findings (tamper detected)
  2 — operational error (missing keys, bad arguments)
"""

from __future__ import annotations

import logging
from pathlib import Path

from recupero.custody.chain import (
    generate_keypair,
    verify_chain,
)

log = logging.getLogger(__name__)


def run_keygen(*, output_path: Path | None = None) -> int:
    """Generate a new Ed25519 keypair."""
    try:
        priv_path, pub_path = generate_keypair(output_path)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: keygen failed — {exc}")
        return 2
    pub_b64 = pub_path.read_text(encoding="utf-8").strip()
    print(f"OK — generated Ed25519 chain-of-custody keypair.")
    print(f"  Private key: {priv_path}  (mode 0600 on POSIX)")
    print(f"  Public key:  {pub_path}")
    print(f"  Public key (base64): {pub_b64}")
    print()
    print(
        "Publish the PUBLIC key on your website / GitHub so verifiers "
        "can fetch it independently of any case file. The private key "
        "stays on this machine — NEVER transmit it."
    )
    return 0


def run_verify(*, case_dir: Path, public_key_b64: str | None = None) -> int:
    """Verify the custody chain in ``case_dir``.

    If ``public_key_b64`` is supplied, use it; otherwise read from
    case_dir/custody/public_key.txt.
    """
    if not case_dir.exists():
        print(f"ERROR: case dir not found — {case_dir}")
        return 2

    report = verify_chain(case_dir, public_key_b64_str=public_key_b64)
    print(f"=== Custody chain verification ===")
    print(f"  Case dir:        {report.case_dir}")
    print(f"  Chain file:      {report.chain_path}")
    print(f"  Entries checked: {report.entries_checked}")
    print()
    if report.ok and not report.findings:
        print("Chain verifies cleanly — no findings.")
        return 0
    if report.ok:
        # Only warnings.
        print("Chain verifies (no critical findings), but warnings present:")
    else:
        print("CHAIN FAILED VERIFICATION — critical findings:")
    print()
    for finding in report.findings:
        marker = "[!]" if finding.severity == "critical" else "[?]"
        print(f"  {marker} entry={finding.entry_index} kind={finding.kind}")
        print(f"      {finding.message}")
        print()
    if not report.ok:
        print(
            "Tamper detected. The case's attested artifacts no longer "
            "match what the operator signed. DO NOT rely on this case "
            "for court-admissible evidence without further investigation."
        )
        return 1
    return 0


__all__ = ("run_keygen", "run_verify")
