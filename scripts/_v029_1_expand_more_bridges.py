"""v0.29.1 bridges.json expansion — additional protocol families.

Extends the v0.29.0 Stargate/Wormhole/Hop expansion with the next
tier of TRM/Chainalysis-grade bridge families that show up in
cross-chain forensics work:

  * Connext / Everclear (rebranded 2024). Hub-and-spoke fast-finality
    bridge — 9 chains.
  * Axelar Gateway. GMP + token bridge — deterministic deploys on
    most EVM L2s.
  * LiFi Diamond. Aggregator that routes through other bridges —
    deterministic deploy across 5+ chains.
  * Squid Router (built on Axelar). Cross-chain swap.
  * Celer cBridge. Liquidity-network bridge.
  * Symbiosis. Permissionless cross-chain swap.

Run once: `python scripts/_v029_1_expand_more_bridges.py`.
Idempotent — skips entries already present via (chain, lowercased
address) key.

All addresses WebFetch-verified during v0.29.0 / v0.29.1 work.
Provenance pinned via `_audit_status` field. Each row carries
`_v029_1_addition: True` for traceability.

Sources (WebFetched 2026-05-26):
  * Connext:    https://docs.connext.network/resources/deployments
  * Axelar:     https://docs.axelar.dev/dev/reference/mainnet-contract-addresses
  * LiFi:       https://docs.li.fi/smart-contracts/deployments
  * Squid:      https://docs.squidrouter.com/reference/contract-addresses
  * Celer:      https://cbridge-docs.celer.network/reference/contract-addresses
  * Symbiosis:  https://docs.symbiosis.finance/contracts/contracts-addresses
"""
from __future__ import annotations

import json
from pathlib import Path

PATH = Path(__file__).parent.parent / "src" / "recupero" / "labels" / "seeds" / "bridges.json"
with open(PATH, encoding="utf-8") as f:
    data = json.load(f)

existing: set[tuple[str, str]] = set()
# Canonical-key → existing on-disk casing. The bridge-mapping completeness
# test rejects two entries that share the canonical key but differ in
# casing — so when we add a new (chain, address) row, we MUST adopt the
# casing already used by any sibling row.
canonical_casing: dict[str, str] = {}
for e in data:
    if isinstance(e, dict) and "address" in e:
        chain = e.get("chain", "ethereum").lower()
        addr = e["address"]
        existing.add((chain, addr.lower()))
        if isinstance(addr, str) and addr.startswith("0x"):
            canonical_casing.setdefault(addr.lower(), addr)

pre_count = len([e for e in data if isinstance(e, dict) and "address" in e])
print(f"Pre-v0.29.1 expansion: {pre_count} entries; "
      f"{len(existing)} unique (chain, address) keys")


# ─────────────────────────────────────────────────────────────────────────────
# Provenance sources (URLs WebFetched 2026-05-26).
# ─────────────────────────────────────────────────────────────────────────────
CONNEXT_URL = "https://docs.connext.network/resources/deployments"
AXELAR_URL = "https://docs.axelar.dev/dev/reference/mainnet-contract-addresses"
LIFI_URL = "https://docs.li.fi/smart-contracts/deployments"
SQUID_URL = "https://docs.squidrouter.com/reference/contract-addresses"
CELER_URL = "https://cbridge-docs.celer.network/reference/contract-addresses"
SYMBIOSIS_URL = "https://docs.symbiosis.finance/contracts/contracts-addresses"


def mk(addr, name, chain, supports_to, source_url, source_doc, follow_up_url, notes=None):
    return {
        "address": addr,
        "name": name,
        "chain": chain,
        "category": "bridge",
        "source": source_doc,
        "confidence": "high",
        "supports_to_chains": supports_to,
        "follow_up_url": follow_up_url,
        "notes": notes,
        "added_at": "2026-05-26T00:00:00Z",
        "_v029_1_addition": True,
        "_audit_status": f"externally_verified_v029_1: WebFetch from {source_url}",
    }


new_entries: list[dict] = []


def maybe_add(addr, name, chain, supports_to, source_url, source_doc, follow_up_url, notes=None):
    key = (chain, addr.lower())
    if key in existing:
        return False
    # Adopt the existing on-disk casing for this canonical address if any
    # sibling row already uses one — bridges.json must have exactly one
    # casing per canonical address (test_bridge_mapping_completeness).
    if addr.startswith("0x") and addr.lower() in canonical_casing:
        addr = canonical_casing[addr.lower()]
    elif addr.startswith("0x"):
        canonical_casing[addr.lower()] = addr
    existing.add(key)
    new_entries.append(mk(addr, name, chain, supports_to, source_url, source_doc, follow_up_url, notes))
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Connext / Everclear — Connext Diamond on each chain. Rebranded as
# "Everclear" 2024 — same on-chain contract deployments under the
# Connext Diamond proxy. EOA-shaped diamonds, not multisigs.
# Source: docs.connext.network/resources/deployments (Diamond row).
# ─────────────────────────────────────────────────────────────────────────────
connext_to = ["ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "linea", "gnosis"]
connext_data = [
    ("0x8898B472C54c31894e3B9bb83cEA802a5d0e63C6", "Connext: Diamond (Ethereum)", "ethereum"),
    ("0xEE9deC2712cCE65174B561151701Bf54b99C24C8", "Connext: Diamond (Arbitrum)", "arbitrum"),
    ("0x8f7492DE823025b4CfaAB1D34c58963F2af5DEDA", "Connext: Diamond (Optimism)", "optimism"),
    ("0xB8448C6f7f7887D36DcA487370778e419e9ebE3F", "Connext: Diamond (Base)", "base"),
    ("0x11984dc4465481512eb5b777E44061C158CF2259", "Connext: Diamond (Polygon)", "polygon"),
    ("0xCd401c10afa37d641d2F594852DA94C700e4F2CE", "Connext: Diamond (BSC)", "bsc"),
    ("0xa05eF29e9aC8C75c530c2795Fa6A800e188dE0a9", "Connext: Diamond (Linea)", "linea"),
    ("0x5bB83e95f63217CDa6aE3D181BA580Ef377D2109", "Connext: Diamond (Gnosis)", "gnosis"),
]
for addr, name, chain in connext_data:
    maybe_add(addr, name, chain, connext_to, CONNEXT_URL, "connext_docs", CONNEXT_URL)


# ─────────────────────────────────────────────────────────────────────────────
# Axelar Gateway — deterministic deploys on most EVM chains.
# Source: docs.axelar.dev (mainnet contract addresses table).
# ─────────────────────────────────────────────────────────────────────────────
axelar_to = ["ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche",
             "fantom", "linea", "moonbeam", "celo", "kava"]

# Group 1: deterministic address `0xe432150cce91c13a887f7D836923d5597adD8E31`
# Appears on Arbitrum / Optimism / Linea / Celo / Kava / Filecoin /
# Base. Axelar's CREATE2 standard deploy.
axelar_det1 = "0xe432150cce91c13a887f7D836923d5597adD8E31"
for chain in ["arbitrum", "optimism", "base", "linea", "celo", "kava"]:
    maybe_add(axelar_det1, f"Axelar: Gateway ({chain.title()})", chain,
              axelar_to, AXELAR_URL, "axelar_docs", AXELAR_URL)

# Group 2: Ethereum + Moonbeam → `0x4F4495243837681061C4743b74B3eEdf548D56A5`
axelar_g2 = "0x4F4495243837681061C4743b74B3eEdf548D56A5"
for chain in ["ethereum", "moonbeam"]:
    maybe_add(axelar_g2, f"Axelar: Gateway ({chain.title()})", chain,
              axelar_to, AXELAR_URL, "axelar_docs", AXELAR_URL)

# Group 3: Avalanche → `0x5029C0EFf6C34351a0CEc334542cDb22c7928f78`
maybe_add("0x5029C0EFf6C34351a0CEc334542cDb22c7928f78",
          "Axelar: Gateway (Avalanche)", "avalanche",
          axelar_to, AXELAR_URL, "axelar_docs", AXELAR_URL)

# Group 4: Fantom / BSC → `0x304acf330bbE08d1e512eefaa92F6a57871fD895`
axelar_g4 = "0x304acf330bbE08d1e512eefaa92F6a57871fD895"
for chain in ["fantom", "bsc"]:
    maybe_add(axelar_g4, f"Axelar: Gateway ({chain.title()})", chain,
              axelar_to, AXELAR_URL, "axelar_docs", AXELAR_URL)

# Group 5: Polygon → `0x6f015F16De9fC8791b234eF68D486d2bF203FBA8`
maybe_add("0x6f015F16De9fC8791b234eF68D486d2bF203FBA8",
          "Axelar: Gateway (Polygon)", "polygon",
          axelar_to, AXELAR_URL, "axelar_docs", AXELAR_URL)


# ─────────────────────────────────────────────────────────────────────────────
# LiFi Diamond — bridge/swap aggregator. Single deterministic
# address `0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE` on most EVM
# chains. Forensically important because LiFi-routed transfers
# appear at the LiFi diamond first; the underlying bridge sees the
# diamond as the sender, not the original wallet.
# Source: docs.li.fi/smart-contracts/deployments
# ─────────────────────────────────────────────────────────────────────────────
lifi_to = ["ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "fantom"]
lifi_det = "0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE"
for chain in ["ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "fantom"]:
    maybe_add(lifi_det, f"LiFi: Diamond ({chain.title()})", chain,
              lifi_to, LIFI_URL, "lifi_docs", LIFI_URL,
              notes="aggregator — underlying bridge differs per route")

# LiFi Linea — non-deterministic
maybe_add("0xDE1E598b81620773454588B85D6b5D4eEC32573e",
          "LiFi: Diamond (Linea)", "linea",
          lifi_to, LIFI_URL, "lifi_docs", LIFI_URL,
          notes="aggregator — underlying bridge differs per route")


# ─────────────────────────────────────────────────────────────────────────────
# Squid Router — built on Axelar, cross-chain swap.
# Source: docs.squidrouter.com — `SquidRouter` v2 deterministic.
# ─────────────────────────────────────────────────────────────────────────────
squid_to = ["ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "fantom", "linea"]
squid_det = "0xce16F69375520ab01377ce7B88f5BA8C48F8D666"
for chain in ["ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "fantom"]:
    maybe_add(squid_det, f"Squid: Router v2 ({chain.title()})", chain,
              squid_to, SQUID_URL, "squid_docs", SQUID_URL,
              notes="routes via Axelar GMP")


# ─────────────────────────────────────────────────────────────────────────────
# Celer cBridge — liquidity-network bridge.
# Source: cbridge-docs.celer.network (per-chain Bridge addresses).
# ─────────────────────────────────────────────────────────────────────────────
cbridge_to = ["ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "fantom", "linea", "metis"]
cbridge_data = [
    ("0x5427FEFA711Eff984124bFBB1AB6fbf5E3DA1820", "Celer: cBridge (Ethereum)", "ethereum"),
    ("0x1619DE6B6B20eD217a58d00f37B9d47C7663feca", "Celer: cBridge (Arbitrum)", "arbitrum"),
    ("0x9D39Fc627A6d9d9F8C831c16995b209548cc3401", "Celer: cBridge (Optimism)", "optimism"),
    ("0x88DCDC47D2f83a99CF0000FDF667A468bB958a78", "Celer: cBridge (Polygon)", "polygon"),
    ("0xdd90E5E87A2081Dcf0391920868eBc2FFB81a1aF", "Celer: cBridge (BSC)", "bsc"),
    ("0xef3c714c9425a8F3697A9C969Dc1af30ba82e5d4", "Celer: cBridge (Avalanche)", "avalanche"),
    ("0x374B8a9f3eC5eB2D97ECA84Ea27aCa45aa1C57EF", "Celer: cBridge (Fantom)", "fantom"),
    ("0x9B36f165baB9ebe611d491180418d8De4b8f3a1f", "Celer: cBridge (Metis)", "metis"),
]
for addr, name, chain in cbridge_data:
    maybe_add(addr, name, chain, cbridge_to, CELER_URL, "celer_docs", CELER_URL)


# ─────────────────────────────────────────────────────────────────────────────
# Symbiosis MetaRouter — cross-chain swap.
# Source: docs.symbiosis.finance/contracts/contracts-addresses
# ─────────────────────────────────────────────────────────────────────────────
symbiosis_to = ["ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "linea"]
symbiosis_data = [
    ("0xcE8f24A58D85eD5c5A6824f7be1F8d4711A0eb4C", "Symbiosis: MetaRouter (Ethereum)", "ethereum"),
    ("0xAE4f3b3a9a25e511ce4567Be2BE96B71b3E37db4", "Symbiosis: MetaRouter (Arbitrum)", "arbitrum"),
    ("0x4f30036b5858f77F98d8D35C3b21BeB18916Ba9C", "Symbiosis: MetaRouter (Optimism)", "optimism"),
    ("0x691df9C4561d95a4a726313089c8536DD682b946", "Symbiosis: MetaRouter (Base)", "base"),
    ("0xb8f275fBf7A959F4BCE59999A2EF122A099e81A8", "Symbiosis: MetaRouter (Polygon)", "polygon"),
    ("0x8D602356c7A6220CDE24BDfb4Ab63EBFcb0a9b5d", "Symbiosis: MetaRouter (BSC)", "bsc"),
    ("0xE5E68630B5B79e4dEb950ad42c7d80E8C16A1F0d", "Symbiosis: MetaRouter (Avalanche)", "avalanche"),
    ("0x5Aa5f7f84eD0E5db0a4a85C3947eA16B53352FD4", "Symbiosis: MetaRouter (Linea)", "linea"),
]
for addr, name, chain in symbiosis_data:
    maybe_add(addr, name, chain, symbiosis_to, SYMBIOSIS_URL, "symbiosis_docs", SYMBIOSIS_URL)


# NB: 1inch routers are deliberately in defi_protocols.json (not
# bridges.json) per v0.28.0 architecture call — they are DEX
# aggregators that primarily do same-chain swaps. The
# `bridge_calldata.py::_decode_1inch` recognition stub is reachable
# via operator-curated label override (see
# `test_v028_hardening.py::test_decoder_dispatch_1inch_protocol_reachable`).
# The decoder-seed pairing test in
# `tests/test_v029_1_decoder_seed_pairing.py` accepts either a
# bridges.json OR a defi_protocols.json entry for the protocol.

# ─────────────────────────────────────────────────────────────────────────────
# Synapse Router — multi-chain liquidity. Existing matrix has
# Ethereum only; expand to the major chains.
# Source: docs.synapseprotocol.com (router addresses per chain).
# ─────────────────────────────────────────────────────────────────────────────
SYNAPSE_URL = "https://docs.synapseprotocol.com/protocol/synapse-router/router-addresses"
synapse_to = ["ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "fantom", "metis"]
synapse_data = [
    ("0x7E7A0e201FD38d3ADAA9523Da6C109a07118C96a", "Synapse: SynapseRouter (Ethereum)", "ethereum"),
    ("0x7E7A0e201FD38d3ADAA9523Da6C109a07118C96a", "Synapse: SynapseRouter (Arbitrum)", "arbitrum"),
    ("0x7E7A0e201FD38d3ADAA9523Da6C109a07118C96a", "Synapse: SynapseRouter (Optimism)", "optimism"),
    ("0xCFd3A04E7d6Ec0BeFAcb83D88baBF8d96250b3aB", "Synapse: SynapseRouter (Base)", "base"),
    ("0x7E7A0e201FD38d3ADAA9523Da6C109a07118C96a", "Synapse: SynapseRouter (Polygon)", "polygon"),
    ("0x7E7A0e201FD38d3ADAA9523Da6C109a07118C96a", "Synapse: SynapseRouter (BSC)", "bsc"),
    ("0x7E7A0e201FD38d3ADAA9523Da6C109a07118C96a", "Synapse: SynapseRouter (Avalanche)", "avalanche"),
]
for addr, name, chain in synapse_data:
    maybe_add(addr, name, chain, synapse_to, SYNAPSE_URL, "synapse_docs", SYNAPSE_URL)


print(f"\nv0.29.1 new entries to add: {len(new_entries)}")
data.extend(new_entries)
total_with_addr = len([e for e in data if isinstance(e, dict) and "address" in e])
print(f"Post-v0.29.1 expansion total: {total_with_addr} entries")

# Validate no collisions in our additions
from collections import Counter
key_counts = Counter()
for e in data:
    if isinstance(e, dict) and "address" in e:
        key_counts[(e.get("chain", "ethereum"), e["address"].lower())] += 1
collisions = [k for k, v in key_counts.items() if v > 1]
assert not collisions, f"COLLISION: {collisions}"

with open(PATH, "w", encoding="utf-8", newline="\n") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")
print("Written.")
