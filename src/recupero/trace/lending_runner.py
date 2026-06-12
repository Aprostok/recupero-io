"""Lending park-and-withdraw leads — Aave V3 + Compound III (roadmap-v4 #11).

The laundering pattern this closes: park stolen tokens in Aave (supply →
aToken), wait, then call ``Pool.withdraw(asset, amount, to)`` with ``to`` set
to a FRESH wallet. The exit ERC-20 transfer is sent BY the aToken contract —
not by the traced wallet — so enumerating the traced wallet's outflows never
sees it; the funds simply vanished into the pool.

The cryptographic rail: the Pool's ``Withdraw`` event ties the two ends
together with INDEXED topics —

  ``Withdraw(address indexed reserve, address indexed user,
             address indexed to, uint256 amount)``

``user`` (the traced wallet initiating, topic 2) and ``to`` (where the funds
actually exited, topic 3) are both protocol-stamped, so a cross-address
withdrawal is protocol identity — reported ``high`` — and the getLogs query
can filter server-side on topic2 = the traced wallet.

Topic0 (keccak recomputed), the topic layout (real mainnet log: reserve=WETH
topic 1, user topic 2, to topic 3, amount = single data word), and every
per-chain Pool address below are LIVE-VERIFIED (2026-06).

Forensic posture: only ``to != user`` rows become leads (the invisible exit);
same-recipient withdrawals return funds to a wallet whose outflows the BFS
already follows and are reported as context counts only. Amounts are RAW
reserve units (never priced/scaled here). Leads are an artifact for review,
never a followed destination, and never touch the recoverable total.

Gated by ``RECUPERO_LENDING_LEADS`` (default off) — one user-filtered
getLogs per traced wallet.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from typing import Any

from recupero.trace.nft_runner import traced_wallets

log = logging.getLogger(__name__)

# LIVE-VERIFIED topic0 hashes (keccak recomputed + matched to real logs).
AAVE_V3_SUPPLY_TOPIC0 = (
    "0x2b627736bca15cd5381dcf80b0bf11fd197d01a037c52b927a881a10fb73ba61"
)
AAVE_V3_WITHDRAW_TOPIC0 = (
    "0x3115d1449a7b732c986cba18244e897a450f61e1bb8d589cd2e69e6c8924f9f7"
)

# Per-chain Aave V3 Pool — every entry LIVE-VERIFIED (2026-06) to emit
# Withdraw on its chain via the Etherscan v2 multichain API. Do NOT add an
# entry without that verification.
AAVE_V3_POOL_BY_CHAIN: dict[str, str] = {
    "ethereum": "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",
    "polygon": "0x794a61358d6845594f94dc1db02a252b5b4814ad",
    "arbitrum": "0x794a61358d6845594f94dc1db02a252b5b4814ad",
    "optimism": "0x794a61358d6845594f94dc1db02a252b5b4814ad",
    "base": "0xa238dd80c259a72e81d7e4664a9801593f98d1c5",
    "bsc": "0x6807dc923806fe8fd134338eabca509979a7e0cb",
}

# Compound III (Comet) base-asset Withdraw(address indexed src, address indexed
# to, uint256 amount) — src=topic1, to=topic2, amount=data word0. topic0 keccak-
# recomputed + matched to real cUSDCv3/cWETHv3 logs (2026-06). NOTE: this 3-arg
# signature is GENERIC (shared by WETH-style + many contracts), so — unlike the
# distinctive 5-arg ERC-4626 Withdraw — Comet MUST be queried against PINNED
# market addresses, never address-less, or unrelated emitters become false leads.
COMPOUND_V3_WITHDRAW_TOPIC0 = (
    "0x9b1bfa7fa9ee420a16e124f794c35ac9f90472acc99140eb2f6447c714cad8eb"
)

# Per-chain flagship Comet markets — every address LIVE-VERIFIED (2026-06) to
# emit the Comet Withdraw on its chain via the Etherscan v2 multichain API.
# Flagship USDC/WETH/USDT markets only (not exhaustive); add new markets as they
# reach material TVL — each MUST be live-verified before being pinned here.
COMPOUND_V3_COMETS_BY_CHAIN: dict[str, list[str]] = {
    "ethereum": [
        "0xc3d688b66703497daa19211eedff47f25384cdc3",  # cUSDCv3
        "0xa17581a9e3356d9a858b789d68b4d866e593ae94",  # cWETHv3
        "0x3afdc9bca9213a35503b077a6072f3d0d5ab0840",  # cUSDTv3
    ],
    "base": [
        "0xb125e6687d4313864e53df431d5425969c15eb2f",  # cUSDCv3
        "0x46e6b214b524310239732d51387075e0e70970bf",  # cWETHv3
    ],
    "arbitrum": [
        "0x9c4ec768c28520b50860ea7a15bd7213a9ff58bf",  # cUSDCv3
        "0xd98be00b5d27fc98112bde293e487f8d4ca57d07",  # cUSDTv3
    ],
    "polygon": ["0xf25212e676d1f7f89cd72ffee66158f541246445"],   # cUSDCv3
    "optimism": ["0x2e44e174f7d53f0212823acc11c01a11d58c5bcb"],  # cUSDCv3
}

_MAX_WALLETS = 25
_MAX_LEADS_PER_WALLET = 50


def lending_leads_enabled() -> bool:
    """Opt-in gate (RECUPERO_LENDING_LEADS). Default off — one getLogs per
    traced wallet."""
    return (os.environ.get("RECUPERO_LENDING_LEADS", "") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _addr_from_topic(t: Any) -> str | None:
    """A 20-byte address from a 32-byte indexed topic — top 12 bytes MUST be
    zero (same guard as the bridge decoders), else not address-shaped."""
    if not isinstance(t, str):
        return None
    h = t.removeprefix("0x")
    if len(h) != 64 or h[:24] != "0" * 24:
        return None
    addr = "0x" + h[24:]
    if addr == "0x" + "0" * 40:
        return None
    return addr.lower()


def withdraws_from_logs(logs: Iterable[Any]) -> list[dict[str, Any]]:
    """Parse Aave V3 ``Withdraw`` logs → records (reserve/user/to/amount).
    Layout live-verified: topics = [topic0, reserve, user, to]; data = one
    word (raw reserve-unit amount). Malformed logs skipped, never repaired."""
    out: list[dict[str, Any]] = []
    for lg in logs or []:
        if not isinstance(lg, dict):
            continue
        topics = lg.get("topics")
        if (
            not isinstance(topics, list)
            or len(topics) < 4
            or topics[0] != AAVE_V3_WITHDRAW_TOPIC0
        ):
            continue
        reserve = _addr_from_topic(topics[1])
        user = _addr_from_topic(topics[2])
        to = _addr_from_topic(topics[3])
        if not (reserve and user and to):
            continue
        data = lg.get("data") or ""
        data = data[2:] if data.startswith("0x") else data
        if len(data) < 64:
            continue
        try:
            amount = str(int(data[0:64], 16))
        except ValueError:
            continue
        txh = lg.get("transactionHash") or lg.get("transaction_hash") or ""
        out.append({
            "reserve": reserve,
            "user": user,
            "to": to,
            "amount_raw": amount,
            "tx_hash": str(txh),
            "block_number": lg.get("blockNumber"),
        })
    return out


def comet_withdraws_from_logs(logs: Iterable[Any]) -> list[dict[str, Any]]:
    """Parse Compound III (Comet) ``Withdraw`` logs → records (src/to/amount).
    Layout live-verified: topics = [topic0, src, to]; data = one word (raw
    base-asset amount). ``src`` is the withdrawing wallet, ``to`` the recipient.
    Malformed logs skipped, never repaired."""
    out: list[dict[str, Any]] = []
    for lg in logs or []:
        if not isinstance(lg, dict):
            continue
        topics = lg.get("topics")
        if (
            not isinstance(topics, list)
            or len(topics) < 3
            or topics[0] != COMPOUND_V3_WITHDRAW_TOPIC0
        ):
            continue
        src = _addr_from_topic(topics[1])
        to = _addr_from_topic(topics[2])
        if not (src and to):
            continue
        data = lg.get("data") or ""
        data = data[2:] if data.startswith("0x") else data
        if len(data) < 64:
            continue
        try:
            amount = str(int(data[0:64], 16))
        except ValueError:
            continue
        txh = lg.get("transactionHash") or lg.get("transaction_hash") or ""
        out.append({
            "src": src,
            "to": to,
            "amount_raw": amount,
            "tx_hash": str(txh),
            "comet": str(lg.get("address", "")).lower(),
            "block_number": lg.get("blockNumber"),
        })
    return out


def run_lending_leads(
    *,
    transfers: Iterable[Any],
    adapter: Any,
    default_chain: str = "ethereum",
    force: bool = False,
) -> list[dict[str, Any]]:
    """For each traced wallet: fetch Aave V3 Pool ``Withdraw`` (user-filtered)
    AND Compound III (Comet) ``Withdraw`` (src-filtered, per pinned market) and
    emit a lead for every CROSS-ADDRESS withdrawal (recipient != the wallet) —
    the exit that is invisible to outflow enumeration (the transfer is sent by
    the aToken / Comet contract, not the wallet). Opt-in: ``[]`` unless
    ``force`` or ``RECUPERO_LENDING_LEADS``. Best-effort per wallet/market."""
    if not (force or lending_leads_enabled()):
        return []
    pool = AAVE_V3_POOL_BY_CHAIN.get(default_chain)
    comets = COMPOUND_V3_COMETS_BY_CHAIN.get(default_chain, [])
    if not pool and not comets:
        return []
    leads: list[dict[str, Any]] = []
    for wallet in traced_wallets(transfers, max_wallets=_MAX_WALLETS):
        w = wallet.lower()
        w_topic = "0x" + "0" * 24 + w[2:]
        # ----- Aave V3 (user = indexed topic 2) -----
        if pool:
            try:
                logs = adapter.fetch_logs(
                    pool, AAVE_V3_WITHDRAW_TOPIC0,
                    topics=[None, w_topic],   # topic2 = user (topic1 unfiltered)
                    from_block=0, to_block="latest",
                )
            except Exception as exc:  # noqa: BLE001 — best-effort per wallet
                log.warning("lending-leads: Aave Withdraw fetch failed "
                            "wallet=%s: %s", wallet, exc)
                logs = []
            rows = withdraws_from_logs(logs)
            # Defense-in-depth: trust only rows whose user really is this wallet
            # (a server ignoring the topic filter must not fabricate leads).
            rows = [r for r in rows if r["user"] == w]
            same_recipient = sum(1 for r in rows if r["to"] == w)
            exits = [r for r in rows if r["to"] != w][:_MAX_LEADS_PER_WALLET]
            for r in exits:
                leads.append({
                    "chain": default_chain,
                    "protocol": "aave_v3",
                    "user": r["user"],
                    "exit_recipient": r["to"],
                    "reserve": r["reserve"],
                    "amount_raw": r["amount_raw"],
                    "tx_hash": r["tx_hash"],
                    "confidence": "high",
                    "basis": (
                        "Aave V3 Pool Withdraw event: the traced wallet (indexed "
                        "user) withdrew this reserve DIRECTLY to a different "
                        "address (indexed to) — an exit invisible to outflow "
                        "enumeration (the transfer is sent by the aToken "
                        "contract). Both addresses are protocol-stamped."
                    ),
                })
            if rows:
                log.info(
                    "lending-leads: wallet %s aave — %d withdraw(s), %d "
                    "cross-address exit(s), %d back-to-self (context only)",
                    wallet, len(rows), len(exits), same_recipient,
                )
        # ----- Compound III / Comet (src = indexed topic 1; PINNED markets) -----
        for comet in comets:
            try:
                clogs = adapter.fetch_logs(
                    comet, COMPOUND_V3_WITHDRAW_TOPIC0,
                    topics=[w_topic],   # topic1 = src (the withdrawing wallet)
                    from_block=0, to_block="latest",
                )
            except Exception as exc:  # noqa: BLE001 — best-effort per market
                log.warning("lending-leads: Comet Withdraw fetch failed "
                            "wallet=%s market=%s: %s", wallet, comet, exc)
                continue
            crows = comet_withdraws_from_logs(clogs)
            # Defense-in-depth: only rows actually emitted by the pinned market
            # AND with src == this wallet (a server ignoring filters can't
            # fabricate a lead from an unrelated emitter on this generic sig).
            crows = [r for r in crows if r["src"] == w and r["comet"] == comet]
            cexits = [r for r in crows if r["to"] != w][:_MAX_LEADS_PER_WALLET]
            for r in cexits:
                leads.append({
                    "chain": default_chain,
                    "protocol": "compound_v3",
                    "user": r["src"],
                    "exit_recipient": r["to"],
                    "reserve": r["comet"],   # the Comet market (base-asset proxy)
                    "amount_raw": r["amount_raw"],
                    "tx_hash": r["tx_hash"],
                    "confidence": "high",
                    "basis": (
                        "Compound III (Comet) Withdraw event on a pinned, "
                        "verified market: the traced wallet (indexed src) "
                        "withdrew the base asset DIRECTLY to a different "
                        "address (indexed to) — an exit invisible to outflow "
                        "enumeration. Both addresses are protocol-stamped."
                    ),
                })
            if crows:
                log.info(
                    "lending-leads: wallet %s comet %s — %d withdraw(s), %d "
                    "cross-address exit(s)", wallet, comet, len(crows),
                    len(cexits),
                )
    return leads


def leads_to_json(leads: list[dict[str, Any]]) -> dict[str, Any]:
    """Serialize run_lending_leads output to the lending_leads.json artifact."""
    return {
        "kind": "recupero_lending_leads",
        "disclaimer": (
            "Lending cross-address withdrawal LEADS (Aave V3 + Compound III / "
            "Comet). Each protocol's Withdraw event stamps both the "
            "initiating wallet and the exit recipient as indexed topics — "
            "protocol identity, high confidence. Comet is queried only against "
            "PINNED, verified market addresses (its 3-arg Withdraw signature "
            "is generic). Withdrawals back to the traced wallet itself are "
            "NOT leads (those funds re-enter normal outflow tracing). "
            "Amounts are RAW reserve/base-asset units, never priced here; "
            "leads are for review, never a followed destination, and the "
            "recoverable total is unchanged."
        ),
        "lead_count": len(leads),
        "leads": leads,
    }


__all__ = (
    "AAVE_V3_SUPPLY_TOPIC0",
    "AAVE_V3_WITHDRAW_TOPIC0",
    "AAVE_V3_POOL_BY_CHAIN",
    "COMPOUND_V3_WITHDRAW_TOPIC0",
    "COMPOUND_V3_COMETS_BY_CHAIN",
    "lending_leads_enabled",
    "withdraws_from_logs",
    "comet_withdraws_from_logs",
    "run_lending_leads",
    "leads_to_json",
)
