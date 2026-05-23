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
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from recupero.chains.hyperliquid.client import HyperliquidClient, HyperliquidLedgerEvent
from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import (
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


def _sanitize_address_field(value: str | None, *, fallback: str) -> str:
    """Reject CRLF / NUL / control bytes in an attacker-controlled
    address-shaped field.

    Hyperliquid's ``delta.destination`` is passed through verbatim
    from a JSON API response. A poisoned (MITM, cached fixture, or
    upstream injection) value containing ``\\r\\n`` would corrupt
    log lines, CSV exports, and freeze-letter templates that
    interpolate this field. Strip every byte < 0x20, plus 0x7F,
    plus Unicode bidi overrides + zero-width joiners. If nothing
    survives, return ``fallback``.
    """
    if not isinstance(value, str):
        return fallback
    out_chars: list[str] = []
    for ch in value:
        cp = ord(ch)
        if cp < 0x20 or cp == 0x7F:
            continue
        if 0x80 <= cp <= 0x9F:
            continue
        # Bidi overrides / zero-width / BOM.
        if cp in (0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
                  0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
                  0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF):
            continue
        out_chars.append(ch)
    cleaned = "".join(out_chars).strip()
    return cleaned or fallback


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
        incident_time = incident_time.replace(tzinfo=UTC)
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
    now = datetime.now(UTC)
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
    # v0.18.5 (round-11 chains-MED-009): Hyperliquid `delta_type`
    # informs whether the event is a USDC withdraw/deposit (real
    # money flow) or a position/spot/class transfer (internal
    # accounting). Pre-v0.18.5 we attributed EVERY event with a
    # USDC delta to "USDC on Arbitrum" — including spot HYPE
    # transfers that happened to have a USDC component, and
    # internal subAccountTransfer events. The brief mislabeled
    # token type and the pricing chain mis-priced.
    #
    # Real on-chain money-flow events: `withdraw`, `deposit`. Other
    # delta_types are surfaced ONLY if their semantics align with
    # external value transfer (which today only those two do).
    _MONEY_FLOW_DELTA_TYPES = {"withdraw", "deposit"}
    transfers: list[Transfer] = []
    for idx, evt in enumerate(events):
        # Adversarial-hardening (defense-in-depth — client.py also
        # coerces non-finite Decimals to 0 at parse time): if a NaN
        # or Infinity has slipped through, ``int(NaN * 10**6)`` raises
        # ValueError and ``int(Infinity * 10**6)`` raises OverflowError.
        # Skip non-finite events outright; they don't represent
        # real money flow.
        if not evt.usdc_delta.is_finite():
            log.debug(
                "skipping hyperliquid event with non-finite usdc_delta: %s",
                evt.hash,
            )
            continue

        # Only events with a real USDC delta are meaningful for the money-flow
        # picture. Skip position transfers, class transfers, etc. with zero delta.
        if evt.usdc_delta == 0:
            continue

        # v0.18.5: skip non-money-flow event types so the brief's
        # transfer list reflects ACTUAL on-chain value movement, not
        # Hyperliquid's internal accounting categories.
        delta_type = getattr(evt, "delta_type", None)
        if delta_type and delta_type not in _MONEY_FLOW_DELTA_TYPES:
            log.debug(
                "skipping hyperliquid event delta_type=%r (not a money-flow): %s",
                delta_type, evt.hash,
            )
            continue

        usdc_abs = abs(evt.usdc_delta)
        amount_raw = int(usdc_abs * Decimal(10 ** USDC_DECIMALS))

        # Direction: negative delta = outflow (withdraw / send)
        #            positive delta = inflow (deposit / receive)
        is_outflow = evt.usdc_delta < 0
        # Adversarial-hardening: sanitize attacker-controlled ``destination``
        # so CRLF / NUL / control bytes can't poison Transfer.from_address
        # / to_address (which downstream renderers interpolate into log
        # lines, CSV cells, freeze-letter bodies).
        clean_dest = _sanitize_address_field(
            evt.destination,
            fallback=("hyperliquid:unknown_destination" if is_outflow
                      else "hyperliquid:unknown_source"),
        )
        from_addr = user_address if is_outflow else clean_dest
        to_addr = clean_dest if is_outflow else user_address

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
            fetched_at=datetime.now(UTC),
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
