"""Harvest the internal known-bad blacklist from the case corpus (v0.39).

Walks every investigation, enumerates each case's wallets + roles (mirroring the
watchlist walk, decoupled from the DB), classifies the case as a real
investigation vs a test/validation fixture, and aggregates into provenance-rich
``BlacklistEntry`` rows. ARMED entries (real + illicit role) become the
alerting blacklist the screener/tracer consult; the rest are visible context.

Supports the Supabase-backed corpus (the operator console's bucket) and a local
CaseStore. Pure enumeration (``enumerate_case_observations``) is unit-tested;
the I/O harvesters are thin.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from recupero.labels.internal_blacklist import (
    AddressObservation,
    BlacklistEntry,
    build_blacklist,
)
from recupero.models import Case

log = logging.getLogger(__name__)


def enumerate_case_observations(
    case: Case,
    freeze_asks: dict[str, Any] | None,
    *,
    investigation_id: str,
    case_is_test: bool,
) -> list[AddressObservation]:
    """Every non-victim wallet in a case, with its role (mirrors
    ``worker.watchlist._build_rows`` but emits AddressObservation, not DB rows)."""
    from recupero._common import canonical_address_key as _ck
    from recupero.worker.watchlist import _ROLE_FROM_CATEGORY

    victim = _ck(case.seed_address)
    chain = case.chain.value
    obs: list[AddressObservation] = []

    def add(address: str | None, role: str,
            label_category: str | None, label_name: str | None) -> None:
        if not address:
            return
        if _ck(address) == victim:
            return
        obs.append(AddressObservation(
            address=address, chain=chain, role=role,
            label_category=label_category, label_name=label_name,
            investigation_id=investigation_id, case_is_test=case_is_test,
        ))

    for tr in case.transfers:
        cp_label = tr.counterparty.label
        if cp_label is not None:
            add(tr.to_address,
                _ROLE_FROM_CATEGORY.get(cp_label.category, "hop"),
                cp_label.category.value, cp_label.name)
        else:
            add(tr.to_address, "hop", None, None)
        add(tr.from_address, "hop", None, None)

    for ep in case.exchange_endpoints:
        add(ep.address, "exchange_deposit", "exchange_deposit", ep.label_name)

    for addr in case.unlabeled_counterparties:
        add(addr, "unlabeled", None, None)

    fa = freeze_asks or {}
    for _issuer, asks in (fa.get("by_issuer") or {}).items():
        for ask in asks or []:
            if isinstance(ask, dict):
                add(ask.get("address"), "current_holder", None, None)
    for d in fa.get("exchange_deposits") or []:
        if isinstance(d, dict):
            add(d.get("address"), "exchange_deposit",
                d.get("label_category"), d.get("label_name"))

    return obs


def _victim_name_from_bytes(raw: bytes | None) -> tuple[bool, str | None]:
    if not raw:
        return False, None
    try:
        d = json.loads(raw.decode("utf-8-sig"))
    except Exception:  # noqa: BLE001
        return True, None
    name = d.get("name") if isinstance(d, dict) else None
    return True, (name if isinstance(name, str) else None)


def harvest_from_supabase(*, limit: int | None = None) -> tuple[list[BlacklistEntry], dict[str, Any]]:
    """Read every investigation from the Supabase bucket and build the
    blacklist. Returns ``(entries, stats)``. Requires RECUPERO_CASE_STORE=supabase
    + creds (raises RuntimeError otherwise)."""
    from recupero.api import _supabase_case_source as sb
    from recupero.api.case_index_api import classify_is_test

    if not sb.enabled():
        raise RuntimeError(
            "Supabase case store not enabled (set RECUPERO_CASE_STORE=supabase "
            "+ SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY)."
        )

    from recupero.config import load_config
    from recupero.storage.supabase_case_store import (
        SupabaseCaseStore,
        list_investigation_ids,
    )

    cfg, _ = load_config()
    url, key, bucket = sb._creds()
    ids = list_investigation_ids(cfg, url, key, bucket=bucket)
    observations: list[AddressObservation] = []
    stats = {"investigations": 0, "cases_parsed": 0, "test_cases": 0,
             "real_cases": 0, "skipped": 0}

    for inv_id in ids:
        if limit is not None and stats["investigations"] >= limit:
            break
        stats["investigations"] += 1
        try:
            store = SupabaseCaseStore(cfg, supabase_url=url, service_role_key=key,
                                      investigation_id=inv_id, bucket=bucket)
        except ValueError:
            stats["skipped"] += 1
            continue
        try:
            try:
                case = Case.model_validate(
                    json.loads(store.read_artifact("case.json").decode("utf-8-sig"))
                )
            except Exception:  # noqa: BLE001 — not a parseable case; skip
                stats["skipped"] += 1
                continue
            try:
                freeze_asks = json.loads(
                    store.read_artifact("freeze_asks.json").decode("utf-8-sig")
                )
            except Exception:  # noqa: BLE001
                freeze_asks = {}
            try:
                has_v, vname = _victim_name_from_bytes(store.read_artifact("victim.json"))
            except Exception:  # noqa: BLE001
                has_v, vname = False, None
        finally:
            store.close()

        is_test, _reason = classify_is_test(vname, has_victim_json=has_v)
        stats["cases_parsed"] += 1
        stats["test_cases" if is_test else "real_cases"] += 1
        observations.extend(enumerate_case_observations(
            case, freeze_asks, investigation_id=inv_id, case_is_test=is_test,
        ))

    return build_blacklist(observations), stats


__all__ = ("enumerate_case_observations", "harvest_from_supabase")
