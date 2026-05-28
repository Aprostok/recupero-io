"""MEV builder address list (v0.32.1 trace gap D).

`trace/mev_detection.py` already ships a 4-builder list (v0.31.0).
Reactor recognizes ~15 Ethereum mainnet builders; without that
coverage we mis-attribute many bundle-shaped txs as "regular flow"
and the trace continuity break flag never fires.

This module is the canonical builder registry. `mev_detection.py`
gets a TODO to pull from this module in wave-4 (don't import it
here yet — that's their owner's call).

Two parallel dicts:
  - KNOWN_MEV_BUILDERS: address → display name
  - BUILDER_VERIFIED: address → bool (False = saw it in the wild,
    have not personally verified via on-chain bundle signing key)

All addresses are lowercase. Lookup is case-insensitive.

# TODO(wave-4-integration): replace `trace/mev_detection._MEV_BUILDERS`
# with `KNOWN_MEV_BUILDERS` from this module. Pass through
# verified flag for confidence weighting in MEVSignal.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)


# Ethereum mainnet MEV builders observed in production traces through
# Q2 2026. Sources: relayscan.io, ultrasound.money builder rankings,
# mev.fyi builder leaderboard. Cross-referenced against actual signing
# keys where possible (verified=True).
KNOWN_MEV_BUILDERS: dict[str, str] = {
    # ---- Flashbots (two builder signing keys) ---- #
    "0xdafea492d9c6733ae3d56b7ed1adb60692c98bc5": "Flashbots: Builder",
    "0xf573d99385c05c23b24ed33de616ad16a43a0919": "Flashbots: Builder 2",
    # ---- Beaverbuild ---- #
    "0x95222290dd7278aa3ddd389cc1e1d165cc4bafe5": "beaverbuild",
    # ---- Titan ---- #
    "0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97": "Titan Builder",
    # ---- Rsync ---- #
    "0x1f9090aae28b8a3dceadf281b0f12828e676c326": "rsync-builder",
    # ---- Builder0x69 ---- #
    "0x690b9a9e9aa1c9db991c7721a92d351db4fac990": "builder0x69",
    # ---- BloXroute (three relays/builders) ---- #
    "0x199d5ed7f45f4ee35960cf22eade2076e95b253f": "bloXroute: Regulated",
    "0x9534ed1c8c2c54d4ed873c5d8a4f47fec38625fa": "bloXroute: Ethical",
    "0x3b64216ad1a58f61538b4fa1b27327675ab7ed67": "bloXroute: Max Profit",
    # ---- Eth-builder ---- #
    "0xfeebabe6b0418ec13b30aadf129f5dcdd4f70cea": "eth-builder.com",
    # ---- payload.de ---- #
    "0xaab27b150451726ec7738aa1d0a94505c8729bd1": "payload.de",
    # ---- Manifold ---- #
    "0x3b9c01dc46b6f51e9e8e8d0c30b6e6dbc54e8c2c": "Manifold",
    # ---- Penguinbuild ---- #
    "0x4675c7e5baafbffbca748158becba61ef3b0a263": "penguinbuild",
    # ---- Lightspeedbuilder ---- #
    "0xe688b84b23f322a994a53dbf8e15fa82cdb71127": "Lightspeedbuilder",
}


# Verified = we have on-chain evidence (signed block, builder-pubkey
# match against MEV-Boost relay logs). False = address-only sighting;
# treat MEVSignal at lower confidence.
BUILDER_VERIFIED: dict[str, bool] = {
    "0xdafea492d9c6733ae3d56b7ed1adb60692c98bc5": True,
    "0xf573d99385c05c23b24ed33de616ad16a43a0919": True,
    "0x95222290dd7278aa3ddd389cc1e1d165cc4bafe5": True,
    "0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97": True,
    "0x1f9090aae28b8a3dceadf281b0f12828e676c326": True,
    "0x690b9a9e9aa1c9db991c7721a92d351db4fac990": True,
    "0x199d5ed7f45f4ee35960cf22eade2076e95b253f": True,
    "0x9534ed1c8c2c54d4ed873c5d8a4f47fec38625fa": True,
    "0x3b64216ad1a58f61538b4fa1b27327675ab7ed67": False,
    "0xfeebabe6b0418ec13b30aadf129f5dcdd4f70cea": True,
    "0xaab27b150451726ec7738aa1d0a94505c8729bd1": True,
    "0x3b9c01dc46b6f51e9e8e8d0c30b6e6dbc54e8c2c": False,
    "0x4675c7e5baafbffbca748158becba61ef3b0a263": False,
    "0xe688b84b23f322a994a53dbf8e15fa82cdb71127": False,
}


def is_mev_builder(
    address: str | None,
    chain: str = "ethereum",
) -> tuple[bool, str | None]:
    """Is `address` a known MEV builder on `chain`?

    Returns (is_builder, display_name | None).
    Case-insensitive. Non-string / empty input → (False, None).

    Currently only Ethereum mainnet is supported. Other chains
    (Arbitrum, Optimism, Base) have small but distinct builder sets
    we'll grow into in v0.33+; for now they unconditionally return
    (False, None).
    """
    if not isinstance(address, str):
        return (False, None)
    addr = address.strip().lower()
    if not addr:
        return (False, None)

    if chain != "ethereum":
        return (False, None)

    name = KNOWN_MEV_BUILDERS.get(addr)
    if name is None:
        return (False, None)
    return (True, name)


def is_verified_builder(address: str | None) -> bool:
    """Has this builder been cryptographically verified (signed-block match)?"""
    if not isinstance(address, str):
        return False
    return bool(BUILDER_VERIFIED.get(address.strip().lower(), False))
