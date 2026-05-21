"""Populate ``public.watchlist`` from a finished trace.

Called from the pipeline after ``_stage_list_freeze_targets`` produces
``freeze_asks.json``. We flag every non-victim wallet on the trace —
mixers, bridges, hops, the lot — so we have a complete audit trail
per case. The ``is_freezeable`` flag is what the nightly monitor
filters on; everything else sits in the table as historical record
but is never re-queried.

Definition of ``is_freezeable=True``: an EOA (non-contract) where a
stablecoin issuer (Circle, Tether, etc.) can freeze our tokens at
their protocol level. This is the legal-cooperation freeze pathway.

Explicitly NOT is_freezeable:
  * Contract addresses (Uniswap V4 PoolManager, deBridge, Across, etc.).
    Their on-chain balance is public-infrastructure liquidity, not the
    perpetrator's holdings.
  * Exchange hot wallets / deposit addresses. Recovery here goes via
    subpoena to the exchange's compliance team, not via issuer freeze;
    we don't want the nightly monitor pinging Binance balances every
    24h. They get a different deliverable (the LE handoff brief).

Idempotency: every row is inserted with ``ON CONFLICT
(address, chain, investigation_id) DO UPDATE`` so re-runs (resumed
investigations, re-processed cases) refresh the row in place rather
than creating duplicates.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from recupero._common import db_connect
from recupero.models import Case, LabelCategory

log = logging.getLogger(__name__)


# ---- LabelCategory → role mapping ---- #
_ROLE_FROM_CATEGORY: dict[LabelCategory, str] = {
    LabelCategory.exchange_deposit: "exchange_deposit",
    LabelCategory.exchange_hot_wallet: "exchange_hot_wallet",
    LabelCategory.bridge: "bridge",
    LabelCategory.mixer: "mixer",
    LabelCategory.defi_protocol: "defi_protocol",
    LabelCategory.staking: "staking",
    LabelCategory.perpetrator: "perpetrator",
    LabelCategory.victim: "victim",
    LabelCategory.unknown: "unlabeled",
}


def populate_from_case(
    *,
    dsn: str,
    case: Case,
    freeze_asks: dict[str, Any],
    investigation_id: UUID,
    case_id: UUID,
) -> int:
    """Insert / refresh watchlist rows for every wallet in ``case``.

    Returns the number of rows touched (insert + update).
    """
    rows = _build_rows(
        case=case,
        freeze_asks=freeze_asks,
        investigation_id=investigation_id,
        case_id=case_id,
    )
    if not rows:
        log.info("watchlist: no rows to insert for inv=%s", investigation_id)
        return 0

    sql = """
        INSERT INTO public.watchlist (
            address, chain, case_id, investigation_id,
            role, label_category, label_name,
            is_freezeable, issuer, asset_symbol, asset_contract,
            flagged_by, notes
        )
        VALUES (
            %(address)s, %(chain)s, %(case_id)s, %(investigation_id)s,
            %(role)s, %(label_category)s, %(label_name)s,
            %(is_freezeable)s, %(issuer)s, %(asset_symbol)s, %(asset_contract)s,
            'worker', %(notes)s
        )
        ON CONFLICT (address, chain, investigation_id)
        DO UPDATE SET
            role = EXCLUDED.role,
            label_category = EXCLUDED.label_category,
            label_name = EXCLUDED.label_name,
            is_freezeable = EXCLUDED.is_freezeable,
            issuer = COALESCE(EXCLUDED.issuer, public.watchlist.issuer),
            asset_symbol = COALESCE(EXCLUDED.asset_symbol, public.watchlist.asset_symbol),
            asset_contract = COALESCE(EXCLUDED.asset_contract, public.watchlist.asset_contract),
            notes = EXCLUDED.notes;
    """
    with db_connect(dsn, autocommit=False) as conn:
        with conn.cursor() as cur:
            cur.executemany(sql, rows)
        conn.commit()
    log.info("watchlist: upserted %d rows for inv=%s", len(rows), investigation_id)
    return len(rows)


def _build_rows(
    *,
    case: Case,
    freeze_asks: dict[str, Any],
    investigation_id: UUID,
    case_id: UUID,
) -> list[dict[str, Any]]:
    """Walk the case + freeze_asks and produce one row dict per wallet.

    Latest data wins per address: if an address shows up both as a
    transfer counterparty (role='hop') and in freeze_asks (role=
    'current_holder', is_freezeable=True), the freeze_asks pass
    overwrites the cheaper categorization.
    """
    # v0.17.9 (round-10 forensic HIGH): canonical address keying so
    # the watchlist's dedup-by-address layer doesn't merge two distinct
    # base58 addresses whose lowercase forms collide, and doesn't fail
    # to dedup the same base58 address when the operator-pasted case
    # differs from the on-chain canonical case.
    from recupero._common import canonical_address_key as _ck
    victim_addr = _ck(case.seed_address)

    # First pass: every counterparty in every transfer (excluding victim).
    by_address: dict[str, dict[str, Any]] = {}

    def _record(
        address: str,
        *,
        role: str,
        label_category: str | None,
        label_name: str | None,
        is_freezeable: bool = False,
        issuer: str | None = None,
        asset_symbol: str | None = None,
        asset_contract: str | None = None,
        notes: str | None = None,
    ) -> None:
        if not address:
            return
        addr_key = _ck(address)
        if addr_key == victim_addr:
            return
        # Promote to a "stronger" categorization on collision.
        existing = by_address.get(addr_key)
        if existing and not _should_overwrite(existing, role, is_freezeable):
            return
        by_address[addr_key] = {
            "address": address,
            "chain": case.chain.value,
            "case_id": case_id,
            "investigation_id": investigation_id,
            "role": role,
            "label_category": label_category,
            "label_name": label_name,
            "is_freezeable": is_freezeable,
            "issuer": issuer,
            "asset_symbol": asset_symbol,
            "asset_contract": asset_contract,
            "notes": notes,
        }

    # ---- Pass 1: transfer counterparties ---- #
    for tr in case.transfers:
        # to_address has the counterparty record attached via tr.counterparty.
        cp_label = tr.counterparty.label
        if cp_label is not None:
            _record(
                tr.to_address,
                role=_ROLE_FROM_CATEGORY.get(cp_label.category, "hop"),
                label_category=cp_label.category.value,
                label_name=cp_label.name,
            )
        else:
            _record(tr.to_address, role="hop", label_category=None, label_name=None)
        # from_address — if it's not the victim it's another wallet on the
        # forwarding chain. Less metadata available.
        _record(tr.from_address, role="hop", label_category=None, label_name=None)

    # ---- Pass 2: exchange endpoints from the trace aggregation ---- #
    # NOT marked is_freezeable. Exchange-deposit recovery goes via subpoena
    # to the exchange's compliance team, not via issuer-level freeze;
    # surfacing them in the nightly issuer-balance monitor would be
    # noise. They're still tracked in the watchlist for the audit trail
    # and the LE handoff brief.
    for ep in case.exchange_endpoints:
        _record(
            ep.address,
            role="exchange_deposit",
            label_category=LabelCategory.exchange_deposit.value,
            label_name=ep.label_name,
            is_freezeable=False,
            notes=f"exchange={ep.exchange}",
        )

    # ---- Pass 3: unlabeled counterparties (catch-all) ---- #
    for addr in case.unlabeled_counterparties:
        _record(addr, role="unlabeled", label_category=None, label_name=None)

    # ---- Pass 4: freeze_asks → is_freezeable rows ---- #
    # Defense in depth: even with the dormant detector's contract filter,
    # if a contract address ever slipped through (regression, edge case),
    # we re-check counterparty.is_contract here before marking
    # is_freezeable. Better to skip a real ask than auto-monitor a
    # Uniswap-style protocol balance every night.
    contract_addrs: set[str] = set()
    for tr in case.transfers:
        if tr.counterparty.is_contract:
            contract_addrs.add(_ck(tr.to_address))

    by_issuer = freeze_asks.get("by_issuer") or {}
    for issuer, asks in by_issuer.items():
        for ask in asks or []:
            ask_addr = ask.get("address")
            if not ask_addr:
                continue
            if _ck(ask_addr) in contract_addrs:
                log.info(
                    "watchlist: skipping is_freezeable=True on contract address "
                    "%s (issuer=%s, symbol=%s) — defense-in-depth filter",
                    ask_addr, issuer, ask.get("symbol"),
                )
                continue
            _record(
                ask_addr,
                role="current_holder",
                label_category=None,
                label_name=None,
                is_freezeable=True,
                issuer=issuer,
                asset_symbol=ask.get("symbol"),
                asset_contract=None,
                notes=f"freezeable via {issuer}",
            )

    for d in freeze_asks.get("exchange_deposits") or []:
        _record(
            d.get("address"),
            role="exchange_deposit",
            label_category=d.get("label_category"),
            label_name=d.get("label_name"),
            is_freezeable=True,
            notes=f"exchange={d.get('exchange')}",
        )

    return list(by_address.values())


# Categorizations ranked from weakest to strongest. A stronger entry
# replaces a weaker one for the same address.
_ROLE_RANK = {
    "hop": 0,
    "unlabeled": 0,
    "defi_protocol": 1,
    "staking": 1,
    "perpetrator": 2,
    "bridge": 3,
    "mixer": 3,
    "exchange_hot_wallet": 4,
    "exchange_deposit": 5,
    "current_holder": 6,
}


def _should_overwrite(
    existing: dict[str, Any],
    new_role: str,
    new_freezeable: bool,
) -> bool:
    # Always promote to is_freezeable=True if the new pass says so.
    if new_freezeable and not existing["is_freezeable"]:
        return True
    cur_rank = _ROLE_RANK.get(existing["role"], 0)
    new_rank = _ROLE_RANK.get(new_role, 0)
    return new_rank > cur_rank
