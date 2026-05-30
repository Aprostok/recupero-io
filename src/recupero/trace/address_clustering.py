"""Address clustering (brief-noise reduction primitive).

A real-world drainer rarely uses one wallet. The SAME private key controls
the SAME EVM address on every EVM chain (Ethereum, Arbitrum, Base, …), and a
single actor routinely sweeps stolen funds through that one address on a
dozen chains. The tracer records each (chain, address) hop independently, so
a brief that lists "14 destinations" may really be "1 actor, 14 wallets" —
noise that buries the signal for the human reading the handoff.

This module recognizes ONE forensically-sound clustering signal and surfaces
it so a downstream consumer can collapse the destination list. It is a PURE,
chain-agnostic primitive: it derives everything from ``case.transfers`` (both
``from_address`` and ``to_address``), performs no I/O and no network calls,
and is fully unit-testable. It is deliberately NOT wired into ``emit_brief``
or any renderer — wiring is a separate, carefully-gated follow-up.

FORENSIC INVARIANT: the only signal here is SAME-EVM-ADDRESS-ACROSS-CHAINS.
An EVM address is the last 20 bytes of the Keccak-256 of a public key; the
identical ``0x``-prefixed 40-hex address on two different EVM chains is
controlled by the identical private key on both. That is CRYPTOGRAPHIC
IDENTITY, not a statistical correlation — so, and only so, a cluster from
this signal is confidence "high" (basis ``same_evm_address_multichain``).

Non-EVM addresses (Solana / Tron / Bitcoin base58, bech32, Cosmos bech32)
have chain-specific formats and key derivations; an identical-looking string
across those is NOT the same key, so they MUST NOT cross-match and are never
clustered by this signal.

Do NOT invent a weaker "high" claim. A co-spend / common-input or
timing-correlation heuristic is an INFERENCE about common control, never
proof — if such a softer signal is ever added here it MUST be "low" or
"medium" and clearly labeled an inference, never "high", and it must never
be fabricated. This primitive intentionally ships ONLY the cryptographically
sound same-address signal: sound, high-value, and unambiguous.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from recupero._common import canonical_address_key as _ck

__all__ = [
    "AddressCluster",
    "cluster_addresses",
]

# Basis tag for the only signal this primitive emits. A consumer keys on this
# string to know WHY the addresses were collapsed.
_BASIS_SAME_EVM_MULTICHAIN = "same_evm_address_multichain"

# Every confidence value this module may emit MUST be in this set. The
# same-address signal is the only one, and it is always "high" (cryptographic
# identity). The set is wider to document the contract for any future softer
# signal (which would be "low"/"medium" — see the module FORENSIC INVARIANT).
_VALID_CONFIDENCE: frozenset[str] = frozenset({"high", "medium", "low"})


def _is_evm_address(raw: str | None) -> bool:
    """True iff ``raw`` is a syntactically valid EVM address (``0x`` + 40 hex).

    Mirrors the EVM-recognition rule in ``canonical_address_key``: only this
    exact shape is keyed (lower-cased) as a cross-chain-stable EVM identity.
    Anything else (Solana/Tron/Bitcoin base58, bech32, synthetic sentinels)
    has a chain-specific format and is NOT a cross-chain EVM identity.
    """
    if not isinstance(raw, str):
        return False
    s = raw.strip()
    if len(s) != 42 or not s.startswith("0x"):
        return False
    return all(c in "0123456789abcdefABCDEF" for c in s[2:])


def _chain_str(chain: Any) -> str:
    """Normalize a transfer's ``chain`` (a ``Chain`` enum or a raw string) to
    its lower-cased string value. Empty for unknown/missing."""
    if chain is None:
        return ""
    value = getattr(chain, "value", chain)
    return str(value).strip().lower()


@dataclass(frozen=True)
class AddressCluster:
    """A set of raw addresses inferred to be controlled by ONE actor.

    For this primitive the inference is cryptographic (same EVM address on
    multiple chains = same private key), so ``confidence`` is "high". The
    dataclass shape is intentionally signal-agnostic so a downstream consumer
    can treat every cluster uniformly when collapsing a destination list.
    """

    addresses: tuple[str, ...]   # the raw addresses in the cluster (sorted)
    chains: tuple[str, ...]      # distinct chains they appear on (sorted)
    basis: str                   # why they're clustered (machine tag)
    confidence: str              # "high" | "medium" | "low"
    reason: str                  # human-readable explanation

    def to_dict(self) -> dict[str, Any]:
        return {
            "heuristic": "address_cluster",
            "addresses": list(self.addresses),
            "chains": list(self.chains),
            "basis": self.basis,
            "attribution_confidence": self.confidence,
            "note": self.reason,
        }


def cluster_addresses(case: Any) -> list[AddressCluster]:
    """Cluster addresses in ``case.transfers`` by forensically-sound signals.

    The ONLY signal is SAME-EVM-ADDRESS-ACROSS-CHAINS: an identical EVM
    address (``0x`` + 40 hex, canonical-keyed lower-case) that appears on 2+
    DIFFERENT chains. Because an EVM address is derived from a public key, the
    same address on every EVM chain is controlled by the same private key —
    cryptographic identity, confidence "high".

    A cluster is emitted ONLY when the address spans 2+ distinct chains; an
    address seen on a single chain is not a cross-chain cluster and is
    omitted. Non-EVM addresses are never cross-matched (they have
    chain-specific formats). Robust to None/empty addresses.

    Returns a deterministic list (addresses, chains, and the list itself are
    all sorted). Pure — no I/O, no network. Empty when no address spans 2+
    chains.
    """
    transfers = getattr(case, "transfers", None) or []
    if not transfers:
        return []

    # canonical EVM key -> {"raw": first-seen raw form, "chains": set[str]}.
    # Both endpoints of every transfer participate (an actor's address can be
    # a destination on one chain and a source on the next).
    seen: dict[str, dict[str, Any]] = {}
    for t in transfers:
        chain = _chain_str(getattr(t, "chain", None))
        if not chain:
            continue
        for raw in (
            getattr(t, "from_address", None),
            getattr(t, "to_address", None),
        ):
            if not _is_evm_address(raw):
                continue
            key = _ck(raw)
            if not key:
                continue
            entry = seen.get(key)
            if entry is None:
                # Preserve the first raw form we encounter for this canonical
                # key; canonical EVM keying makes any checksum-case variant
                # collapse to the same key, so the choice is cosmetic.
                entry = {"raw": (raw or "").strip(), "chains": set()}
                seen[key] = entry
            entry["chains"].add(chain)

    clusters: list[AddressCluster] = []
    for entry in seen.values():
        chains = entry["chains"]
        if len(chains) < 2:
            continue  # single-chain address is not a cross-chain cluster
        sorted_chains = tuple(sorted(chains))
        addresses = (entry["raw"],)  # one canonical address, on N chains
        reason = (
            f"Identical EVM address active on {len(sorted_chains)} chains "
            f"({', '.join(sorted_chains)}). The same EVM address is "
            "controlled by the same private key on every EVM chain — "
            "cryptographic identity, not a correlation — so these are one "
            "actor's wallets, not separate destinations."
        )
        clusters.append(AddressCluster(
            addresses=addresses,
            chains=sorted_chains,
            basis=_BASIS_SAME_EVM_MULTICHAIN,
            confidence="high",
            reason=reason,
        ))

    # Deterministic ordering: by the cluster's (single) canonical address,
    # then by its chain tuple for stability.
    clusters.sort(key=lambda c: (c.addresses, c.chains))
    return clusters
