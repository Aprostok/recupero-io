"""ERC-4626 vault park-and-withdraw leads (roadmap-v4 Tier-2 #11, slice 2).

Generalizes the Aave-specific lending runner to the whole ERC-4626 vault
standard — Morpho (MetaMorpho), Yearn v3, Spark/Sky (sUSDS), Sommelier, and
every other compliant vault. The laundering pattern is identical: deposit
stolen tokens into a vault (mint shares), wait, then ``redeem``/``withdraw``
with the ``receiver`` set to a FRESH wallet. The underlying-asset transfer is
emitted by the vault, not the traced wallet, so outflow enumeration never
sees it.

The rail that makes this protocol-agnostic: ERC-4626 standardizes the events
with the depositor as an INDEXED topic, so ONE address-less ``eth_getLogs``
filtered by that topic finds a wallet's activity across ALL vaults at once —
no per-vault address list to maintain:

  ``Deposit(address indexed sender, address indexed owner,
            uint256 assets, uint256 shares)``    — owner = topic 2
  ``Withdraw(address indexed sender, address indexed receiver,
             address indexed owner, uint256 assets, uint256 shares)``
                                                  — receiver=topic2, owner=topic3;
                                                    data word0=assets, word1=shares

Both topic0 hashes and the topic/data layout are LIVE-VERIFIED (2026-06)
against real Morpho/Yearn/Spark logs (e.g. Spark sUSDS tx 0x0b75f1fe... is a
real receiver!=owner withdrawal).

Confidence — honest about the spoofing exposure of an address-less query
(any contract can emit a fake event):
  * ``high`` when the SAME owner also has an observed ``Deposit`` into the
    SAME vault — a confirmed deposit→withdraw round-trip on a real vault the
    traced wallet actually funded;
  * ``medium`` otherwise (owner-of-shares withdrew to a different receiver,
    but no deposit by this wallet was observed — shares may have been
    acquired by transfer, or the emitter is unverified).
The emitting vault address is always surfaced so a reviewer can confirm it is
a legitimate vault. Amounts are RAW (never priced); leads are for review,
never a followed destination, and never touch the recoverable total.

Gated by ``RECUPERO_VAULT_LEADS`` (default off) — two owner-filtered getLogs
per traced wallet (deposits + withdrawals).
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from typing import Any

from recupero.trace.nft_runner import traced_wallets

log = logging.getLogger(__name__)

# LIVE-VERIFIED ERC-4626 topic0 hashes (keccak recomputed + matched to real
# Morpho/Yearn/Spark logs).
ERC4626_DEPOSIT_TOPIC0 = (
    "0xdcbc1c05240f31ff3ad067ef1ee35ce4997762752e3a095284754544f4c709d7"
)
ERC4626_WITHDRAW_TOPIC0 = (
    "0xfbde797d201c681b91056529119e0b02407c7bb96a4a2c75c01fc9667232c8db"
)

_MAX_WALLETS = 25
_MAX_LEADS_PER_WALLET = 50


def vault_leads_enabled() -> bool:
    """Opt-in gate (RECUPERO_VAULT_LEADS). Default off — two getLogs per
    traced wallet."""
    return (os.environ.get("RECUPERO_VAULT_LEADS", "") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _addr_from_topic(t: Any) -> str | None:
    """20-byte address from a 32-byte indexed topic; top 12 bytes MUST be
    zero (else not address-shaped — guards against packed/non-address words
    like the non-standard sDAI owner topic)."""
    if not isinstance(t, str):
        return None
    h = t.removeprefix("0x")
    if len(h) != 64 or h[:24] != "0" * 24:
        return None
    addr = "0x" + h[24:]
    if addr == "0x" + "0" * 40:
        return None
    return addr.lower()


def deposit_vaults_by_owner(logs: Iterable[Any], *, owner: str) -> set[str]:
    """The set of vault addresses this owner DEPOSITED into (owner = indexed
    topic 2 on the ERC-4626 Deposit event). Used to confirm a round-trip."""
    owner_l = owner.lower()
    vaults: set[str] = set()
    for lg in logs or []:
        if not isinstance(lg, dict):
            continue
        topics = lg.get("topics")
        if (
            not isinstance(topics, list)
            or len(topics) < 3
            or topics[0] != ERC4626_DEPOSIT_TOPIC0
        ):
            continue
        if _addr_from_topic(topics[2]) != owner_l:
            continue
        vault = str(lg.get("address", "")).lower()
        if vault:
            vaults.add(vault)
    return vaults


def withdraws_by_owner(logs: Iterable[Any], *, owner: str) -> list[dict[str, Any]]:
    """Parse ERC-4626 ``Withdraw`` logs where owner == the traced wallet
    (indexed topic 3). receiver = topic 2; data word0 = assets, word1 =
    shares. Malformed logs skipped, never repaired."""
    owner_l = owner.lower()
    out: list[dict[str, Any]] = []
    for lg in logs or []:
        if not isinstance(lg, dict):
            continue
        topics = lg.get("topics")
        if (
            not isinstance(topics, list)
            or len(topics) < 4
            or topics[0] != ERC4626_WITHDRAW_TOPIC0
        ):
            continue
        receiver = _addr_from_topic(topics[2])
        ow = _addr_from_topic(topics[3])
        if ow != owner_l or receiver is None:
            continue
        data = lg.get("data") or ""
        data = data[2:] if data.startswith("0x") else data
        if len(data) < 128:  # assets + shares
            continue
        try:
            assets = str(int(data[0:64], 16))
            shares = str(int(data[64:128], 16))
        except ValueError:
            continue
        out.append({
            "vault": str(lg.get("address", "")).lower(),
            "receiver": receiver,
            "owner": ow,
            "assets_raw": assets,
            "shares_raw": shares,
            "tx_hash": str(lg.get("transactionHash") or lg.get("transaction_hash") or ""),
            "block_number": lg.get("blockNumber"),
        })
    return out


def run_vault_leads(
    *,
    transfers: Iterable[Any],
    adapter: Any,
    default_chain: str = "ethereum",
    force: bool = False,
) -> list[dict[str, Any]]:
    """For each traced wallet: find ERC-4626 ``Withdraw`` events where it is
    the owner and the receiver is a DIFFERENT address (the invisible exit),
    across ALL vaults via one owner-topic-filtered getLogs. A second getLogs
    for the wallet's Deposits confirms round-trips (→ high). Opt-in: ``[]``
    unless ``force`` or ``RECUPERO_VAULT_LEADS``. Best-effort per wallet."""
    if not (force or vault_leads_enabled()):
        return []
    leads: list[dict[str, Any]] = []
    for wallet in traced_wallets(transfers, max_wallets=_MAX_WALLETS):
        w = wallet.lower()
        owner_topic = "0x" + "0" * 24 + w[2:]
        try:
            # Withdraw: owner is indexed topic 3 (topic1/topic2 unfiltered).
            wd_logs = adapter.fetch_logs(
                "", ERC4626_WITHDRAW_TOPIC0,
                topics=[None, None, owner_topic],
                from_block=0, to_block="latest",
            )
        except Exception as exc:  # noqa: BLE001 — best-effort per wallet
            log.warning("vault-leads: Withdraw fetch failed wallet=%s: %s",
                        wallet, exc)
            continue
        rows = withdraws_by_owner(wd_logs, owner=w)
        exits = [r for r in rows if r["receiver"] != w][:_MAX_LEADS_PER_WALLET]
        if not exits:
            continue
        # Round-trip confirmation: which vaults did this wallet deposit into?
        deposit_vaults: set[str] = set()
        try:
            # Deposit: owner is indexed topic 2.
            dep_logs = adapter.fetch_logs(
                "", ERC4626_DEPOSIT_TOPIC0,
                topics=[None, owner_topic],
                from_block=0, to_block="latest",
            )
            deposit_vaults = deposit_vaults_by_owner(dep_logs, owner=w)
        except Exception as exc:  # noqa: BLE001 — confirmation is best-effort
            log.warning("vault-leads: Deposit fetch failed wallet=%s: %s",
                        wallet, exc)
        for r in exits:
            round_trip = r["vault"] in deposit_vaults
            leads.append({
                "chain": default_chain,
                "protocol": "erc4626",
                "vault": r["vault"],
                "owner": r["owner"],
                "exit_recipient": r["receiver"],
                "assets_raw": r["assets_raw"],
                "shares_raw": r["shares_raw"],
                "tx_hash": r["tx_hash"],
                "round_trip_confirmed": round_trip,
                # high only on a confirmed deposit→withdraw round-trip on a
                # vault this wallet actually funded; else medium (address-less
                # query → emitter not pre-verified; shares may be transferred-in).
                "confidence": "high" if round_trip else "medium",
                "basis": (
                    "ERC-4626 Withdraw: the traced wallet (indexed owner) "
                    "redeemed vault shares with the assets sent to a DIFFERENT "
                    "receiver (indexed) — an exit invisible to outflow "
                    "enumeration. "
                    + ("A Deposit by the same owner into the same vault was "
                       "also observed (confirmed round-trip)."
                       if round_trip else
                       "No deposit by this wallet was observed; confirm the "
                       "emitting vault is legitimate before relying on it.")
                ),
            })
        log.info("vault-leads: wallet %s — %d cross-address exit(s), %d vault(s) "
                 "deposited-into", wallet, len(exits), len(deposit_vaults))
    return leads


def leads_to_json(leads: list[dict[str, Any]]) -> dict[str, Any]:
    """Serialize run_vault_leads output to the vault_leads.json artifact."""
    return {
        "kind": "recupero_vault_leads",
        "disclaimer": (
            "ERC-4626 vault cross-address withdrawal LEADS (Morpho / Yearn / "
            "Spark / any compliant vault). The owner and receiver are "
            "protocol-stamped indexed topics. Confidence is HIGH only when a "
            "deposit by the same wallet into the same vault was also observed "
            "(confirmed round-trip); otherwise MEDIUM — an address-less "
            "owner-topic query does not pre-verify the emitting vault, so "
            "confirm it is legitimate. Amounts are RAW; leads are for review, "
            "never a followed destination, and the recoverable total is "
            "unchanged."
        ),
        "lead_count": len(leads),
        "leads": leads,
    }


__all__ = (
    "ERC4626_DEPOSIT_TOPIC0",
    "ERC4626_WITHDRAW_TOPIC0",
    "vault_leads_enabled",
    "deposit_vaults_by_owner",
    "withdraws_by_owner",
    "run_vault_leads",
    "leads_to_json",
)
