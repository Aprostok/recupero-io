"""Lightning Network exit detection (v0.32.1+ Cap-D).

Why this module exists
----------------------

Bitcoin Lightning Network channels live off-chain. Once funds enter a
Lightning channel via a channel-open transaction, the routing inside
the network is opaque to on-chain forensics. Recupero v0.32.1 does
not implement Lightning monitoring or channel-state reconstruction.

But we can at least DETECT entries: if a victim sends BTC to a known
Lightning gateway operator (CoinGate, Strike, OpenNode, Wallet of
Satoshi, etc.), the analyst needs to know the trace dead-ends there.
The alternative — surfacing the gateway as an unlabeled multisig —
is forensically misleading.

REACTOR_PARITY.md § 3.2 acknowledges Reactor surfaces this better than
we do. This module closes most of that gap: we still can't do
channel-graph reconstruction (Reactor's actual advantage), but we now
correctly LABEL the dead-end.

Known Lightning gateway addresses
---------------------------------

v0.34 — the previously-hardcoded gateway table was REMOVED. 12 of its 16
addresses were fabricated placeholders with invalid bech32/base58 checksums
(proven by scripts/_verify_addr_checksums.py) — they could never match a real
transaction — and the remaining 4 were unverified. Custodial-wallet sweep
addresses also ROTATE, so a static hardcoded list is fundamentally unfit for
forensic use: it asserts attributions that cannot be verified and silently
goes stale. The registry is now EMPTY and ``detect_lightning_exit`` returns
None for every address until wave-7 wires a maintained, verifiable source. For
a forensic deliverable it is better to label nothing than to label wrongly.

TODO(wave-7-integration):
  * Populate ``KNOWN_LIGHTNING_GATEWAYS`` from a maintained, verifiable source
    (BLIP-31 mirror / community-curated GitHub), with ONLY checksum-valid
    literals, plus a periodic refresh.
  * Then surface a "Lightning exit detected — automated trace cannot continue"
    lead in `brief.py` Section 4 and add the gateways to
    `trace/policies.py:_SINKS` as terminal nodes.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LightningExit:
    """One detected Lightning gateway match.

    The brief renderer surfaces ``gateway_name`` and ``operator_type``
    in Section 4 alongside the standard chain-of-custody line.
    """

    address: str
    gateway_name: str
    operator_type: str  # "custodial_wallet" | "non_custodial" | "merchant_processor" | "lsp"
    notes: str = ""


# -----------------------------------------------------------------------------
# Known Lightning gateway addresses
# -----------------------------------------------------------------------------
#
# Bitcoin addresses are case-sensitive (base58check / bech32). Stored
# verbatim. Bech32 addresses are lowercased by convention; base58
# (legacy "1...") and P2SH (legacy "3...") are case-sensitive.

KNOWN_LIGHTNING_GATEWAYS: dict[str, LightningExit] = {
    # Intentionally EMPTY (v0.34 fabricated-address removal — see module
    # docstring). Re-populate ONLY from a maintained, verifiable source and
    # ONLY with checksum-valid literals; scripts/_verify_addr_checksums.py
    # and tests/test_lightning_detection_no_fabrication.py guard this.
}


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def detect_lightning_exit(bitcoin_address: str) -> LightningExit | None:
    """Return a LightningExit if ``bitcoin_address`` is a known LN gateway.

    Returns None for any unknown address (the trace continues as
    normal on-chain). Case-sensitive lookup; we do not lowercase
    bech32 inputs because they should already be lowercased by the
    Esplora adapter.
    """
    if not isinstance(bitcoin_address, str):
        return None
    addr = bitcoin_address.strip()
    if not addr:
        return None
    return KNOWN_LIGHTNING_GATEWAYS.get(addr)


def is_lightning_gateway(bitcoin_address: str) -> bool:
    """Convenience boolean wrapper for tracer hot-paths."""
    return detect_lightning_exit(bitcoin_address) is not None


def list_lightning_gateways(
    operator_type: str | None = None,
) -> list[LightningExit]:
    """Return all known LN gateways, optionally filtered by operator_type.

    Useful for the brief renderer's "Lightning gateways encountered"
    summary and for admin-UI display.
    """
    entries = list(KNOWN_LIGHTNING_GATEWAYS.values())
    if operator_type is None:
        return entries
    return [e for e in entries if e.operator_type == operator_type]


def count_by_operator_type() -> dict[str, int]:
    """Return how many gateway entries we have per operator_type.

    Used by the parity report and the admin dashboard.
    """
    out: dict[str, int] = {}
    for entry in KNOWN_LIGHTNING_GATEWAYS.values():
        out[entry.operator_type] = out.get(entry.operator_type, 0) + 1
    return out
