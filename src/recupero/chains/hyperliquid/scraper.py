"""Hyperliquid scraper — fetches user ledger events and writes a case file.

Unlike EVM/Solana, Hyperliquid doesn't fit the Transfer / ChainAdapter
abstraction cleanly (no tx hashes, different event model). Instead, this
module produces a case file directly from ledger events by representing each
withdrawal or deposit as a synthetic Transfer with:

  - tx_hash = the Hyperliquid event hash (not an on-chain tx)
  - chain = Chain.ethereum (tagged as 'hyperliquid' in a separate field later)
  - token = USDC (since Hyperliquid's primary settlement token is USDC)
  - from/to = user wallet / destination (for withdrawals) or sender / user (deposits)

This is a deliberately narrow bridge. Full Hyperliquid forensics (perp
positions, liquidations, trade-level reconstruction) is deferred to a later
patch; this one documents the money flow in/out of Hyperliquid.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

from recupero.chains.hyperliquid.client import HyperliquidClient, HyperliquidLedgerEvent
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import (
    Address,
    Case,
    Chain,
    Counterparty,
    TokenRef,
    Transfer,
)
from recupero.storage.case_store import CaseStore

log = logging.getLogger(__name__)

# USDC contract on Arbitrum — Hyperliquid withdrawals land here
ARBITRUM_USDC = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"
USDC_DECIMALS = 6


def scrape_hyperliquid_case(
    *,
    user_address: str,
    case_id: str,
    incident_time: datetime,
    config: RecuperoConfig,
    env: RecuperoEnv,
) -> Case:
    """Fetch Hyperliquid ledger for ``user_address`` since ``incident_time``
    (minus the configured buffer), convert to a Case, and return it."""
    if incident_time.tzinfo is None:
        incident_time = incident_time.replace(tzinfo=timezone.utc)
    buffer_minutes = config.trace.incident_buffer_minutes
    start_ms = int((incident_time.timestamp() - buffer_minutes * 60) * 1000)

    log.info(
        "hyperliquid scrape start user=%s incident=%s start_time_ms=%d",
        user_address, incident_time.isoformat(), start_ms,
    )

    client = HyperliquidClient()
    try:
        events = client.get_non_funding_ledger_updates(user_address, start_time_ms=start_ms)
    finally:
        client.close()

    log.info("hyperliquid scrape fetched %d events", len(events))

    transfers = _events_to_transfers(events, user_address)
    now = datetime.now(timezone.utc)
    case = Case(
        case_id=case_id,
        seed_address=user_address,
        chain=Chain.ethereum,   # Hyperliquid uses Ethereum-compatible addresses
        incident_time=incident_time,
        trace_started_at=now,
        trace_completed_at=now,
        transfers=transfers,
    )
    return case


def _events_to_transfers(
    events: list[HyperliquidLedgerEvent],
    user_address: str,
) -> list[Transfer]:
    """Turn Hyperliquid ledger events into our Transfer model.

    For the Zigha case the most important events are ``withdraw`` (money
    leaving Hyperliquid, bridging to Arbitrum at the same address). Deposits
    are included for context — they show when funds arrived on Hyperliquid
    before being drained.
    """
    transfers: list[Transfer] = []
    for idx, evt in enumerate(events):
        # Only events with a real USDC delta are meaningful for the money-flow
        # picture. Skip position transfers, class transfers, etc. with zero delta.
        if evt.usdc_delta == 0:
            continue

        usdc_abs = abs(evt.usdc_delta)
        amount_raw = int(usdc_abs * Decimal(10 ** USDC_DECIMALS))

        # Direction: negative delta = outflow (withdraw / send)
        #            positive delta = inflow (deposit / receive)
        is_outflow = evt.usdc_delta < 0
        from_addr = user_address if is_outflow else (evt.destination or "hyperliquid:unknown_source")
        to_addr = (evt.destination or "hyperliquid:unknown_destination") if is_outflow else user_address

        token = TokenRef(
            chain=Chain.ethereum,
            contract=ARBITRUM_USDC,     # documented as arbitrum USDC since that's the bridge destination
            symbol="USDC",
            decimals=USDC_DECIMALS,
            coingecko_id="usd-coin",
        )
        transfer = Transfer(
            transfer_id=f"hyperliquid:{evt.hash}:{idx}",
            chain=Chain.ethereum,
            tx_hash=evt.hash,
            block_number=evt.time_ms,    # placeholder; Hyperliquid has no blocks
            block_time=evt.when,
            from_address=from_addr,
            to_address=to_addr,
            counterparty=Counterparty(
                address=to_addr if is_outflow else from_addr,
                label=None,
                is_contract=False,
            ),
            token=token,
            amount_raw=str(amount_raw),
            amount_decimal=usdc_abs,
            usd_value_at_tx=usdc_abs,   # USDC = $1.00 by definition
            pricing_source="hyperliquid_native_usdc",
            pricing_error=None,
            hop_depth=0,
            fetched_at=datetime.now(timezone.utc),
            explorer_url=f"https://app.hyperliquid.xyz/explorer/address/{user_address}",
        )
        transfers.append(transfer)
    return transfers


def write_hyperliquid_case(
    *,
    user_address: str,
    case_id: str,
    incident_time: datetime,
    config: RecuperoConfig,
    env: RecuperoEnv,
) -> Path:
    """Convenience: scrape + write. Returns the case.json path."""
    case = scrape_hyperliquid_case(
        user_address=user_address,
        case_id=case_id,
        incident_time=incident_time,
        config=config,
        env=env,
    )
    store = CaseStore(config)
    return store.write_case(case)
