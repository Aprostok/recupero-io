"""Populate ``public.watchlist`` from a finished trace.

Called from the pipeline after ``_stage_list_freeze_targets`` produces
``freeze_asks.json``. We flag every non-victim wallet on the trace —
mixers, bridges, hops, the lot — so we have a complete audit trail
per case. The ``is_freezeable`` flag (set true only for wallets that
appear as freeze targets or known exchange deposits) is what the
nightly monitor filters on; everything else sits in the table as
historical record but is never re-queried.

Idempotency: every row is inserted with ``ON CONFLICT
(address, chain, investigation_id) DO UPDATE`` so re-runs (resumed
investigations, re-processed cases) refresh the row in place rather
than creating duplicates.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

import psycopg

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
    with psycopg.connect(dsn, autocommit=False) as conn:
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
    victim_addr = case.seed_address.lower()

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
        if address.lower() == victim_addr:
            return
        # Promote to a "stronger" categorization on collision.
        existing = by_address.get(address.lower())
        if existing and not _should_overwrite(existing, role, is_freezeable):
            return
        by_address[address.lower()] = {
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
    for ep in case.exchange_endpoints:
        _record(
            ep.address,
            role="exchange_deposit",
            label_category=LabelCategory.exchange_deposit.value,
            label_name=ep.label_name,
            is_freezeable=True,
            notes=f"exchange={ep.exchange}",
        )

    # ---- Pass 3: unlabeled counterparties (catch-all) ---- #
    for addr in case.unlabeled_counterparties:
        _record(addr, role="unlabeled", label_category=None, label_name=None)

    # ---- Pass 4: freeze_asks → is_freezeable rows ---- #
    by_issuer = freeze_asks.get("by_issuer") or {}
    for issuer, asks in by_issuer.items():
        for ask in asks or []:
            _record(
                ask.get("address"),
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
