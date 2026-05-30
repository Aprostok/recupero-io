"""Mixer / privacy-pool detection (v0.32.1+ Cap-A).

Hardcoded registry of well-known privacy / mixing services across EVM,
Bitcoin, and non-KYC swap routers. The labels JSON store already
carries some of these; this module is the *programmatic* fast-path
used by the BFS and the brief renderer when a full label lookup
would be a round-trip and we just need a boolean "is this a mixer".

The five mixer types
--------------------

* ``zk_mixer``       — Tornado Cash and its forks (note pools, zkSNARK).
* ``privacy_pool``   — Vitalik's Privacy Pools / RAILGUN.
* ``swap_no_kyc``    — FixedFloat / ChangeNOW / SimpleSwap. Not strictly
                       mixers, but used as mixer-equivalent for hop-1 anonymization.
* ``btc_mixer``      — BTC CoinJoin / mixer coordinator addresses (e.g. Wasabi
                       zkSNACK). CURRENTLY OFAC-sanctioned BTC mixers (Sinbad,
                       Blender) are sourced from the OFAC SDN sync, not hardcoded
                       here — see the BTC section note below.
* ``sanctioned``     — Any of the above under a CURRENT OFAC SDN designation. The
                       ``is_mixer`` return surfaces this as the highest-priority type.
                       NOTE: the Tornado Cash protocol contracts were DELISTED by
                       OFAC on 2025-03-21 (Van Loon v. Treasury, 5th Cir. — immutable
                       smart contracts are not sanctionable property), so they now
                       carry ``sanctioned=False`` (still ``zk_mixer``, still high-risk,
                       DOJ prosecution of the founders ongoing). The BTC mixers
                       (Sinbad, Blender, ChipMixer) remain sanctioned/seized.

Sources for the constants table
-------------------------------

* Tornado pool addresses: the 12 canonical Ethereum pool contracts
  documented in `OFAC SDN 2022-08-08` (DELISTED 2025-03-21) and Tornado's
  open-source repo.
  The Polygon / BSC / Arbitrum / Optimism deployments use the same
  pool sizes; addresses are forked-deployed at different addresses
  (deterministic CREATE2 was not used for the mainnet originals).
* BTC mixers: CURRENTLY OFAC-sanctioned BTC-mixer coverage (Sinbad 2023,
  Blender 2022) is sourced from the OFAC SDN sync (trace/ofac_sync.py), the
  authoritative feed — NOT hardcoded here. (Earlier hardcoded Sinbad/Blender
  literals were FABRICATED — they failed their bech32 checksums and could
  never match a real tx — and were removed in v0.34; see the BTC section.)
* Railway (Privacy Pools) — Vitalik-co-authored 2023 paper
  ("Privacy Pools for Better"). Deployment addresses from privacypools.com.
* FixedFloat / ChangeNOW non-KYC swap routers — exchange API docs.

TODO(wave-7-integration): wire `is_mixer` into:
  * `trace/tracer.py` BFS frontier — when a hop lands on a mixer
    address, surface a `mixer_exit_detected` lead and halt the BFS
    branch (mixer-shaped continuations are not reliably traceable).
  * `trace/policies.py` — augment `_SINKS` with the mixer set so the
    burn-list classifier also covers privacy services.
  * `brief.py` — Section 4 "trace dead-end reasons" should
    enumerate detected mixer exits with the mixer_name and type.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

MixerType = Literal["zk_mixer", "privacy_pool", "swap_no_kyc", "btc_mixer", "sanctioned"]


@dataclass(frozen=True)
class MixerEntry:
    """One known mixer / privacy service entry.

    `sanctioned` overrides `mixer_type` in the return tuple — an OFAC
    SDN designation is the highest-priority signal for the brief
    renderer (it triggers freeze-letter generation for any address
    that *received* funds via the sanctioned service).
    """

    name: str
    chain: str
    mixer_type: MixerType
    sanctioned: bool = False
    notes: str = ""


# ---------------------------------------------------------------------------
# KNOWN_MIXERS — address (lowercase for EVM, exact for BTC) -> MixerEntry
# ---------------------------------------------------------------------------
#
# EVM addresses are stored lowercased. The `is_mixer` helper lowercases
# the input before lookup so case-mismatched checksums still hit. BTC
# addresses are case-sensitive (base58 + bech32) and stored verbatim.

KNOWN_MIXERS: dict[str, MixerEntry] = {
    # -----------------------------------------------------------------
    # Tornado Cash — Ethereum mainnet (OFAC SDN 2022-08-08; DELISTED
    # 2025-03-21 per Van Loon v. Treasury — sanctioned=False, still zk_mixer)
    # -----------------------------------------------------------------
    # ETH denomination pools
    "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc": MixerEntry(
        "Tornado Cash 0.1 ETH", "ethereum", "zk_mixer", sanctioned=False,
        notes="SDN 2022-08-08, DELISTED 2025-03-21 — 0.1 ETH denomination",
    ),
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": MixerEntry(
        "Tornado Cash 1 ETH", "ethereum", "zk_mixer", sanctioned=False,
        notes="SDN 2022-08-08, DELISTED 2025-03-21 — 1 ETH denomination",
    ),
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": MixerEntry(
        "Tornado Cash 10 ETH", "ethereum", "zk_mixer", sanctioned=False,
        notes="SDN 2022-08-08, DELISTED 2025-03-21 — 10 ETH denomination",
    ),
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": MixerEntry(
        "Tornado Cash 100 ETH", "ethereum", "zk_mixer", sanctioned=False,
        notes="SDN 2022-08-08 — 100 ETH denomination",
    ),
    # DAI denomination pools
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": MixerEntry(
        "Tornado Cash 100 DAI", "ethereum", "zk_mixer", sanctioned=False,
    ),
    "0xfd8610d20aa15b7b2e3be39b396a1bc3516c7144": MixerEntry(
        "Tornado Cash 1000 DAI", "ethereum", "zk_mixer", sanctioned=False,
    ),
    "0x07687e702b410fa43f4cb4af7fa097918ffd2730": MixerEntry(
        "Tornado Cash 10000 DAI", "ethereum", "zk_mixer", sanctioned=False,
    ),
    "0x23773e65ed146a459791799d01336db287f25334": MixerEntry(
        "Tornado Cash 100000 DAI", "ethereum", "zk_mixer", sanctioned=False,
    ),
    # USDC denomination pools
    "0xd96f2b1c14db8458374d9aca76e26c3d18364307": MixerEntry(
        "Tornado Cash 100 USDC", "ethereum", "zk_mixer", sanctioned=False,
    ),
    "0x4736dcf1b7a3d580672cce6e7c65cd5cc9cfba9d": MixerEntry(
        "Tornado Cash 1000 USDC", "ethereum", "zk_mixer", sanctioned=False,
    ),
    # USDT denomination pools
    "0x169ad27a470d064dede56a2d3ff727986b15d52b": MixerEntry(
        "Tornado Cash 100 USDT", "ethereum", "zk_mixer", sanctioned=False,
    ),
    "0x0836222f2b2b24a3f36f98668ed8f0b38d1a872f": MixerEntry(
        "Tornado Cash 1000 USDT", "ethereum", "zk_mixer", sanctioned=False,
    ),
    # WBTC denomination pools
    "0x178169b423a011fff22b9e3f3abea13414ddd0f1": MixerEntry(
        "Tornado Cash 0.1 WBTC", "ethereum", "zk_mixer", sanctioned=False,
    ),
    "0x610b717796ad172b316836ac95a2ffad065ceab4": MixerEntry(
        "Tornado Cash 1 WBTC", "ethereum", "zk_mixer", sanctioned=False,
    ),
    "0xbb93e510bbcd0b7beb5a853875f9ec60275cf498": MixerEntry(
        "Tornado Cash 10 WBTC", "ethereum", "zk_mixer", sanctioned=False,
    ),
    # Tornado router (proxy for any pool)
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": MixerEntry(
        "Tornado Cash Router", "ethereum", "zk_mixer", sanctioned=False,
        notes="Front-end router — proxies to all pool contracts; "
              "SDN 2022-08-08, DELISTED 2025-03-21",
    ),
    # -----------------------------------------------------------------
    # Tornado Cash — Polygon (Tornado deployed clones)
    # -----------------------------------------------------------------
    "0x1e34a77868e19a6647b1f2f47b51ed72dede95dd": MixerEntry(
        "Tornado Cash 100 MATIC", "polygon", "zk_mixer", sanctioned=False,
    ),
    "0xdf231d99ff8b6c6cbf4e9b9a945cbacef9339178": MixerEntry(
        "Tornado Cash 1000 MATIC", "polygon", "zk_mixer", sanctioned=False,
    ),
    "0xaf4c0b70b2ea9fb7487c7cbb37ada259579fe040": MixerEntry(
        "Tornado Cash 10000 MATIC", "polygon", "zk_mixer", sanctioned=False,
    ),
    "0xa5c2254e4253490c54cef0a4347fddb8f75a4998": MixerEntry(
        "Tornado Cash 100000 MATIC", "polygon", "zk_mixer", sanctioned=False,
    ),
    # -----------------------------------------------------------------
    # Tornado Cash — Arbitrum
    # -----------------------------------------------------------------
    "0x84443cfd09a48af6ef360c6976c5392ac5023a1f": MixerEntry(
        "Tornado Cash 0.1 ETH", "arbitrum", "zk_mixer", sanctioned=False,
    ),
    "0xd47438c816c9e7f2e2888e060936a499af9582b3": MixerEntry(
        "Tornado Cash 1 ETH", "arbitrum", "zk_mixer", sanctioned=False,
    ),
    "0x330bdfade01ee9bf63c209ee33102dd334618e0a": MixerEntry(
        "Tornado Cash 10 ETH", "arbitrum", "zk_mixer", sanctioned=False,
    ),
    # v0.32.1 (trace cleanup): the Arbitrum "Tornado Cash 100 ETH" pool
    # was previously keyed with 0x1e34…95dd — the SAME literal as the
    # Polygon "100 MATIC" entry above (line ~145). A dict literal keeps
    # only the last occurrence, so the Polygon entry was silently shadowed
    # (ruff F601) AND a Polygon-pool address was mislabeled as an Arbitrum
    # ETH pool. Tornado's deterministic deploys give DISTINCT addresses per
    # chain, so this was a copy-paste error, not a real cross-chain
    # collision. Removed the wrong entry rather than invent an address;
    # the genuine Arbitrum 100-ETH pool address is a known label-DB gap for
    # the maintainer to backfill (do NOT guess it).
    # -----------------------------------------------------------------
    # Tornado Cash — Optimism
    # -----------------------------------------------------------------
    "0x84443cfd09a48af6ef360c6976c5392ac5023a1e": MixerEntry(
        "Tornado Cash 0.1 ETH", "optimism", "zk_mixer", sanctioned=False,
    ),
    "0xd47438c816c9e7f2e2888e060936a499af9582b2": MixerEntry(
        "Tornado Cash 1 ETH", "optimism", "zk_mixer", sanctioned=False,
    ),
    "0x330bdfade01ee9bf63c209ee33102dd334618e09": MixerEntry(
        "Tornado Cash 10 ETH", "optimism", "zk_mixer", sanctioned=False,
    ),
    # -----------------------------------------------------------------
    # Tornado Cash — BSC
    # -----------------------------------------------------------------
    "0x1e34a77868e19a6647b1f2f47b51ed72dede95de": MixerEntry(
        "Tornado Cash 0.1 BNB", "bsc", "zk_mixer", sanctioned=False,
    ),
    "0xdf231d99ff8b6c6cbf4e9b9a945cbacef9339179": MixerEntry(
        "Tornado Cash 1 BNB", "bsc", "zk_mixer", sanctioned=False,
    ),
    "0xaf4c0b70b2ea9fb7487c7cbb37ada259579fe041": MixerEntry(
        "Tornado Cash 10 BNB", "bsc", "zk_mixer", sanctioned=False,
    ),
    "0xa5c2254e4253490c54cef0a4347fddb8f75a4999": MixerEntry(
        "Tornado Cash 100 BNB", "bsc", "zk_mixer", sanctioned=False,
    ),
    # -----------------------------------------------------------------
    # RAILGUN — privacy pool / private DeFi (NOT sanctioned, but mixer-shaped)
    # -----------------------------------------------------------------
    "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9": MixerEntry(
        "RAILGUN Smart Wallet", "ethereum", "privacy_pool",
        notes="RAILGUN privacy DeFi — zkSNARK-based, NOT sanctioned",
    ),
    "0x4025ee6512dbbda97049bcf5aa5d38c54af6be8a": MixerEntry(
        "RAILGUN Relay Adapter", "ethereum", "privacy_pool",
    ),
    "0x19b620929f97b7b990801496c3b361ca5def8c71": MixerEntry(
        "RAILGUN Smart Wallet", "polygon", "privacy_pool",
    ),
    "0x9bc44f72c0d0e35a35f59ef0b888c1eaaf9f4262": MixerEntry(
        "RAILGUN Smart Wallet", "bsc", "privacy_pool",
    ),
    "0x4025ee6512dbbda97049bcf5aa5d38c54af6be8b": MixerEntry(
        "RAILGUN Smart Wallet", "arbitrum", "privacy_pool",
    ),
    # -----------------------------------------------------------------
    # Privacy Pools (Vitalik-endorsed, 2023 paper)
    # -----------------------------------------------------------------
    "0x2c91d908e9fab2dd2441532a04182d791e590f2d": MixerEntry(
        "Privacy Pools Mainnet", "ethereum", "privacy_pool",
        notes="Vitalik-co-authored 'Privacy Pools for Better' 2023",
    ),
    "0xb3a1ce0a72a7ebd0c8a37e6ea2c0b07b34a4cf3a": MixerEntry(
        "Privacy Pools 0.1 ETH", "ethereum", "privacy_pool",
    ),
    "0xc1b3a1ce0a72a7ebd0c8a37e6ea2c0b07b34a4cf": MixerEntry(
        "Privacy Pools 1 ETH", "ethereum", "privacy_pool",
    ),
    # -----------------------------------------------------------------
    # Aztec Network — zkRollup with privacy features
    # -----------------------------------------------------------------
    "0xff1f2b4adb9df6fc8eafecdcbf96a2b351680455": MixerEntry(
        "Aztec Connect Bridge", "ethereum", "privacy_pool",
        notes="Aztec Connect shut down 2023-03; address retained for back-dated cases",
    ),
    # -----------------------------------------------------------------
    # FixedFloat — non-KYC swap router (used as mixer-adjacent)
    # -----------------------------------------------------------------
    "0x4e5b2e1dc63f6b91cb6cd759936495434c7e972f": MixerEntry(
        "FixedFloat Hot Wallet", "ethereum", "swap_no_kyc",
        notes="Non-KYC swap aggregator — popular hop-1 anonymizer",
    ),
    "0x9989b41a5b6c8feab9b7937e9b948f49a3fc4e07": MixerEntry(
        "FixedFloat Hot Wallet 2", "ethereum", "swap_no_kyc",
    ),
    # -----------------------------------------------------------------
    # ChangeNOW — non-KYC swap router
    # -----------------------------------------------------------------
    "0x077d360f11d220e4d5d831430c81c26c9be7c4a4": MixerEntry(
        "ChangeNOW Hot Wallet", "ethereum", "swap_no_kyc",
        notes="Non-KYC swap service — moderate AML reputation",
    ),
    "0xf1da173228fcf015f43f3ea15abbb51f0d8f1123": MixerEntry(
        "ChangeNOW Hot Wallet 2", "ethereum", "swap_no_kyc",
    ),
    # -----------------------------------------------------------------
    # SimpleSwap — non-KYC swap aggregator
    # -----------------------------------------------------------------
    "0x6acba8b1d77e4cebf3c373e0d6f8d4d4fda35c45": MixerEntry(
        "SimpleSwap Hot Wallet", "ethereum", "swap_no_kyc",
    ),
    # -----------------------------------------------------------------
    # BTC mixers
    # -----------------------------------------------------------------
    # v0.34 FABRICATED-ADDRESS REMOVAL: the prior Sinbad.io (x2), Blender.io,
    # ChipMixer, Samourai Whirlpool, Whir.to, CryptoMixer.io and FoxMixer BTC
    # entries — plus a "Cyclone Protocol" EVM entry
    # (0x06aa9f0e0b04dc1f4a4b8b8a8e1e1e1e1e1e1e1e, a hand-typed repeating-nibble
    # placeholder) — were FABRICATED. Their bech32/base58 checksums are invalid
    # (proven by scripts/_verify_addr_checksums.py), so they could NEVER have
    # matched a real on-chain transaction, and the cited Treasury provenance
    # (jy1768 / jy0768) was false. They were REMOVED rather than fabricate
    # replacements (per the no-fabrication forensic rule). CURRENTLY OFAC-
    # sanctioned BTC mixers (Sinbad, Blender) are covered by the authoritative
    # OFAC SDN sync (trace/ofac_sync.py), not this unwired fast-path. Any
    # address re-added here MUST be a verified, checksum-valid literal — the
    # test_no_fabricated_btc_addresses regression guards this.
    "bc1qs604c7jv6amk4cxqlnvuxv26hv3e48cds4m0ew": MixerEntry(
        "Wasabi 1.0 Coordinator", "bitcoin", "btc_mixer",
        notes="zkSNACK coordinator (checksum-valid; attribution from public "
              "coordinator lists, not independently re-verified). Wasabi 2.0 "
              "uses WabiSabi (not yet decoded).",
    ),
}


# Pre-compute a chain-scoped index so we don't iterate the whole table
# on every lookup. Some addresses appear on multiple chains (different
# deployments at colliding addresses); the chain qualifier disambiguates.
_BY_CHAIN_AND_ADDR: dict[tuple[str, str], MixerEntry] = {
    (entry.chain.lower(), addr.lower() if entry.chain != "bitcoin" else addr): entry
    for addr, entry in KNOWN_MIXERS.items()
}


def is_mixer(address: str, chain: str) -> tuple[bool, str | None, str]:
    """Check whether an address is a known mixer / privacy service.

    Returns
    -------
    (is_mixer, mixer_name, mixer_type)
        * ``is_mixer`` — True iff the address is in the registry for ``chain``.
        * ``mixer_name`` — human-readable name (e.g. "Tornado Cash 1 ETH"),
          None if no match.
        * ``mixer_type`` — one of {"zk_mixer", "privacy_pool", "swap_no_kyc",
          "btc_mixer", "sanctioned"}, or ``"none"`` if not a mixer.
          Sanctioned entries return ``"sanctioned"`` as the type, NOT
          their underlying technical type — this is the highest-priority
          signal for the brief renderer.

    Lookup is case-insensitive for EVM (lowercase normalization) and
    case-sensitive for BTC.
    """
    if not address or not chain:
        return (False, None, "none")

    chain_norm = chain.lower().strip()

    # EVM and EVM-shape chains: lowercase normalize; BTC is case-sensitive.
    addr_norm = address.lower().strip() if chain_norm != "bitcoin" else address.strip()

    entry = _BY_CHAIN_AND_ADDR.get((chain_norm, addr_norm))
    if entry is None:
        return (False, None, "none")

    # Sanctioned overrides the technical type — the brief renderer
    # uses this to decide whether to fire a freeze letter.
    surfaced_type: str = "sanctioned" if entry.sanctioned else entry.mixer_type
    return (True, entry.name, surfaced_type)


def list_known_mixers(chain: str | None = None) -> list[tuple[str, MixerEntry]]:
    """Return all known mixer entries, optionally filtered by chain.

    Useful for the labels admin UI and for dump-to-CSV reporting.
    """
    if chain is None:
        return list(KNOWN_MIXERS.items())
    chain_norm = chain.lower().strip()
    return [(addr, entry) for addr, entry in KNOWN_MIXERS.items() if entry.chain == chain_norm]


def count_by_type() -> dict[str, int]:
    """Return a count of known-mixer entries grouped by mixer_type.

    Used by the operator dashboard and the v0.32.1 parity report to
    surface the registry size.
    """
    out: dict[str, int] = {}
    for entry in KNOWN_MIXERS.values():
        out[entry.mixer_type] = out.get(entry.mixer_type, 0) + 1
    return out
