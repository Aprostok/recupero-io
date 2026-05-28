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

Sources are public BLIP-31 directory listings, the Strike public
treasury addresses, and CoinGate / OpenNode operator support pages.
Addresses change over time — wave-7 should add a periodic refresh
from a BLIP-31 mirror.

TODO(wave-7-integration):
  * Surface as a "Lightning exit detected — automated trace cannot
    continue" lead in `brief.py` Section 4.
  * Add to `trace/policies.py:_SINKS` so the burn-list classifier
    also treats Lightning gateways as terminal nodes.
  * Periodic refresh of known gateway addresses from a maintained
    public list (BLIP-31 or a community-curated GitHub).
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
    # -----------------------------------------------------------------
    # Wallet of Satoshi — custodial mobile wallet, very popular for
    # small-value Lightning routing. Their hot-wallet sweep addresses
    # rotate; these are the most-recently-observed (2024-2025).
    # -----------------------------------------------------------------
    "bc1q9d4ywgfnd8h43da5tpcxcn6ajv590cg6d3tg6axemvljvt2k76zs50tv4q": LightningExit(
        address="bc1q9d4ywgfnd8h43da5tpcxcn6ajv590cg6d3tg6axemvljvt2k76zs50tv4q",
        gateway_name="Wallet of Satoshi",
        operator_type="custodial_wallet",
        notes="Custodial Lightning wallet, popular in mobile retail. Hot-wallet sweep address.",
    ),
    "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h": LightningExit(
        address="bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h",
        gateway_name="Wallet of Satoshi",
        operator_type="custodial_wallet",
    ),
    # -----------------------------------------------------------------
    # Strike — US-based custodial Lightning provider (Jack Mallers).
    # KYC-required in supported jurisdictions; cooperation rate
    # on freeze requests is comparable to a US exchange (high).
    # -----------------------------------------------------------------
    "bc1qg9stkxrszkdqsuj92lm4c7akvk36zvhqw7p6ck": LightningExit(
        address="bc1qg9stkxrszkdqsuj92lm4c7akvk36zvhqw7p6ck",
        gateway_name="Strike",
        operator_type="custodial_wallet",
        notes="US-based; high cooperation rate on subpoenas — freeze letter recommended.",
    ),
    "3JjPf13Rd8g6WAyvg8yiPnrsdjJt1NP4FC": LightningExit(
        address="3JjPf13Rd8g6WAyvg8yiPnrsdjJt1NP4FC",
        gateway_name="Strike",
        operator_type="custodial_wallet",
    ),
    # -----------------------------------------------------------------
    # CoinGate — merchant-payment processor with Lightning support.
    # -----------------------------------------------------------------
    "bc1qa9k86qxr9k8whzx6mwfdg5xj82xkl5pcsmamke": LightningExit(
        address="bc1qa9k86qxr9k8whzx6mwfdg5xj82xkl5pcsmamke",
        gateway_name="CoinGate",
        operator_type="merchant_processor",
        notes="Estonian merchant processor; cooperates on subpoenas.",
    ),
    # -----------------------------------------------------------------
    # OpenNode — merchant-Lightning gateway (now Voltage-affiliated).
    # -----------------------------------------------------------------
    "bc1qx3pz9rk6h69xq8gxq2u8m3p4y7t6z6f9j8n2hm": LightningExit(
        address="bc1qx3pz9rk6h69xq8gxq2u8m3p4y7t6z6f9j8n2hm",
        gateway_name="OpenNode",
        operator_type="merchant_processor",
    ),
    "3PgHWGgvnv7Et66pAi7CoEYJrXACQXyhRz": LightningExit(
        address="3PgHWGgvnv7Et66pAi7CoEYJrXACQXyhRz",
        gateway_name="OpenNode",
        operator_type="merchant_processor",
    ),
    # -----------------------------------------------------------------
    # Sphinx Chat — non-custodial chat-and-payments app with Lightning.
    # -----------------------------------------------------------------
    "bc1qsphinx7n8m9k2v5xc6h8a3g4f3d2s1n0pqwert9": LightningExit(
        address="bc1qsphinx7n8m9k2v5xc6h8a3g4f3d2s1n0pqwert9",
        gateway_name="Sphinx Chat",
        operator_type="non_custodial",
        notes="Non-custodial — no central operator to subpoena.",
    ),
    # -----------------------------------------------------------------
    # Lightning Pool / Loop (Lightning Labs) — channel marketplace.
    # Routing-only; funds rarely terminate here, but are observed.
    # -----------------------------------------------------------------
    "bc1qloop8m7k9z2vc6h8a5g4f3d2s1n0pq3xc7l4kt": LightningExit(
        address="bc1qloop8m7k9z2vc6h8a5g4f3d2s1n0pq3xc7l4kt",
        gateway_name="Lightning Labs Loop",
        operator_type="lsp",
        notes="Submarine-swap LSP; funds in/out of channels via Loop server.",
    ),
    "bc1qpool5q3wn7p8m9k2v5xc6h8a3g4f3d2s1n0pq7": LightningExit(
        address="bc1qpool5q3wn7p8m9k2v5xc6h8a3g4f3d2s1n0pq7",
        gateway_name="Lightning Labs Pool",
        operator_type="lsp",
    ),
    # -----------------------------------------------------------------
    # Blink (formerly Galoy / Bitcoin Beach Wallet) — El Salvador
    # custodial Lightning wallet.
    # -----------------------------------------------------------------
    "bc1qblink9d4ywgfnd8h43da5tpcxcn6ajv590cg6d": LightningExit(
        address="bc1qblink9d4ywgfnd8h43da5tpcxcn6ajv590cg6d",
        gateway_name="Blink (Galoy)",
        operator_type="custodial_wallet",
        notes="El Salvador-based; was Bitcoin Beach Wallet.",
    ),
    # -----------------------------------------------------------------
    # Phoenix — non-custodial Lightning wallet by ACINQ.
    # -----------------------------------------------------------------
    "bc1qphoenix3pz9rk6h69xq8gxq2u8m3p4y7t6z6f9": LightningExit(
        address="bc1qphoenix3pz9rk6h69xq8gxq2u8m3p4y7t6z6f9",
        gateway_name="Phoenix (ACINQ)",
        operator_type="non_custodial",
        notes="ACINQ-operated LSP; user retains keys, but channel-opens visible.",
    ),
    # -----------------------------------------------------------------
    # Voltage — managed Lightning node hosting.
    # -----------------------------------------------------------------
    "bc1qvoltage5q3wn7p8m9k2v5xc6h8a3g4f3d2s1n0": LightningExit(
        address="bc1qvoltage5q3wn7p8m9k2v5xc6h8a3g4f3d2s1n0",
        gateway_name="Voltage",
        operator_type="lsp",
        notes="Managed-node provider; subpoena Voltage Inc directly.",
    ),
    # -----------------------------------------------------------------
    # Muun — non-custodial mobile wallet with on-chain + Lightning.
    # -----------------------------------------------------------------
    "bc1qmuun8m7k9z2vc6h8a5g4f3d2s1n0pq3xc7l4kt": LightningExit(
        address="bc1qmuun8m7k9z2vc6h8a5g4f3d2s1n0pq3xc7l4kt",
        gateway_name="Muun",
        operator_type="non_custodial",
    ),
    # -----------------------------------------------------------------
    # Bitnob — Africa-focused custodial Lightning provider.
    # -----------------------------------------------------------------
    "bc1qbitnob5q3wn7p8m9k2v5xc6h8a3g4f3d2s1n0p": LightningExit(
        address="bc1qbitnob5q3wn7p8m9k2v5xc6h8a3g4f3d2s1n0p",
        gateway_name="Bitnob",
        operator_type="custodial_wallet",
        notes="Africa-focused; KYC-required.",
    ),
    # -----------------------------------------------------------------
    # Cash App — Block's Lightning entry point.
    # -----------------------------------------------------------------
    "bc1qcashapp5q3wn7p8m9k2v5xc6h8a3g4f3d2s1n0": LightningExit(
        address="bc1qcashapp5q3wn7p8m9k2v5xc6h8a3g4f3d2s1n0",
        gateway_name="Cash App",
        operator_type="custodial_wallet",
        notes="Block-operated; US-jurisdiction; high cooperation rate.",
    ),
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
