"""Internal known-bad blacklist harvested from our own case corpus (v0.39).

Every wallet we've seen across prior investigations, deduped with provenance
(which investigations, what role). ARMED entries are merged into the high-risk
DB so the screener AND tracer "fire up" when a NEW case routes through one;
non-armed entries are retained as visible context the operator can promote.

THE FORENSIC LINE — an address is ARMED (alert-triggering) only when ALL hold:
  * it was seen in at least one REAL investigation (never a test/validation
    fixture — those carry fabricated/innocent addresses);
  * in an illicit role (perpetrator / mixer / current-holder of stolen funds);
  * it is NOT a victim wallet and NOT legitimate infrastructure (exchange hot
    wallet, exchange deposit, bridge, DEX/defi, staking).
Arming a fixture, a victim, or a shared service would false-alarm on legitimate
future cases and risk a wrongful freeze — the one thing a tracer must never do.

The harvest itself (reading the case corpus) lives in
``recupero.intel_harvest``; this module is the pure data model + aggregation +
load/merge, so it has no heavy dependencies and is fully unit-testable.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Roles eligible to ARM an alert: illicit handling of stolen funds.
ARMED_ROLES = frozenset({"perpetrator", "mixer", "current_holder"})

# Roles that are NEVER armed — victims + legitimate infrastructure, plus the
# ambiguous catch-alls (a bare "hop"/"unlabeled" could be anything, so arming
# it would be reckless). Kept explicit for auditability.
NEVER_ARM_ROLES = frozenset({
    "victim", "bridge", "exchange_hot_wallet", "exchange_deposit",
    "defi_protocol", "staking", "hop", "unlabeled",
})

# H2 (service-veto): roles/label-categories that mark a SHARED SERVICE address.
# A service can appear as a benign hop in one case (NEVER_ARM filters that on a
# per-sighting basis) AND be hand-labeled current_holder/perpetrator in another
# (a deposit-tracing artifact, or an analyst error). The per-sighting OR-arming
# would then arm the service — wrongly freezing e.g. a Binance hot wallet that
# thousands of innocent users share. So a service sighting is a HARD VETO over
# the whole deduped address: if ANY sighting carries a service role or a
# service label_category, the address can never be armed (manual review only).
SERVICE_VETO_ROLES = frozenset({
    "bridge", "exchange_hot_wallet", "exchange_deposit",
    "defi_protocol", "staking",
})
# label_category substrings that indicate a shared service (matched
# case-insensitively, substring — covers "exchange", "exchange_deposit",
# "bridge", "defi_protocol", "staking_pool", "cex", "dex", etc.).
_SERVICE_LABEL_CATEGORY_MARKERS = (
    "exchange", "bridge", "defi", "staking", "cex", "dex", "custodian",
    "service",
)
_SERVICE_VETO_REASON = "service-labeled; manual review required"


def _is_service_sighting(role: str, label_category: str | None) -> bool:
    """H2: True when a sighting marks the address as a shared service."""
    if role in SERVICE_VETO_ROLES:
        return True
    lc = (label_category or "").strip().lower()
    if lc and any(m in lc for m in _SERVICE_LABEL_CATEGORY_MARKERS):
        return True
    return False

# Weakest → strongest, for picking the representative role of a deduped address.
_ROLE_RANK: dict[str, int] = {
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


@dataclass(frozen=True)
class AddressObservation:
    """One (address, case) sighting feeding the blacklist build."""
    address: str
    chain: str
    role: str
    label_category: str | None
    label_name: str | None
    investigation_id: str
    case_is_test: bool


@dataclass
class BlacklistEntry:
    """One deduped address across the corpus, with provenance + arm decision."""
    address: str
    chain: str
    role: str                          # strongest role observed
    label_category: str | None
    label_name: str | None
    source_investigation_ids: list[str]
    source_case_count: int
    real_case_count: int               # of those, how many were real (non-test)
    alert_enabled: bool
    confidence: str                    # high | medium | low
    reason: str

    def to_json(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "chain": self.chain,
            "role": self.role,
            "label_category": self.label_category,
            "label_name": self.label_name,
            "source_investigation_ids": sorted(self.source_investigation_ids),
            "source_case_count": self.source_case_count,
            "real_case_count": self.real_case_count,
            "alert_enabled": self.alert_enabled,
            "confidence": self.confidence,
            "reason": self.reason,
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> BlacklistEntry:
        ids = d.get("source_investigation_ids") or []
        return cls(
            address=str(d.get("address", "")),
            chain=str(d.get("chain", "")),
            role=str(d.get("role", "unlabeled")),
            label_category=d.get("label_category"),
            label_name=d.get("label_name"),
            source_investigation_ids=[str(x) for x in ids],
            source_case_count=int(d.get("source_case_count", len(ids)) or 0),
            real_case_count=int(d.get("real_case_count", 0) or 0),
            alert_enabled=bool(d.get("alert_enabled", False)),
            confidence=str(d.get("confidence", "low")),
            reason=str(d.get("reason", "")),
        )


def _observation_arms(obs: AddressObservation) -> bool:
    """Does this single sighting justify arming the address? (the forensic line)"""
    if obs.case_is_test:
        return False
    if obs.role in NEVER_ARM_ROLES:
        return False
    return obs.role in ARMED_ROLES


def build_blacklist(observations: Iterable[AddressObservation]) -> list[BlacklistEntry]:
    """Aggregate per-(address, chain) sightings into deduped blacklist entries.

    ``alert_enabled`` is the OR over sightings of "this sighting arms" — i.e. an
    address armed by ANY real illicit sighting stays armed even if it also shows
    up as a benign hop elsewhere. The representative role is the strongest seen.
    """
    from recupero._common import canonical_address_key as _ck

    agg: dict[tuple[str, str], dict[str, Any]] = {}
    for o in observations:
        if not o.address:
            continue
        akey = _ck(o.address)
        if not akey:
            continue
        key = (akey, o.chain)
        cur = agg.get(key)
        if cur is None:
            cur = {
                "address": akey,
                "chain": o.chain,
                "role": o.role,
                "rank": _ROLE_RANK.get(o.role, 0),
                "label_category": o.label_category,
                "label_name": o.label_name,
                "inv_ids": set(),
                "real_ids": set(),
                "armed": False,
                "service_seen": False,
            }
            agg[key] = cur
        if o.investigation_id:
            cur["inv_ids"].add(o.investigation_id)
            if not o.case_is_test:
                cur["real_ids"].add(o.investigation_id)
        if _observation_arms(o):
            cur["armed"] = True
        # H2: a service sighting anywhere vetoes arming for the whole address.
        if _is_service_sighting(o.role, o.label_category):
            cur["service_seen"] = True
        new_rank = _ROLE_RANK.get(o.role, 0)
        if new_rank > cur["rank"]:
            cur["rank"] = new_rank
            cur["role"] = o.role
            # carry the label from the strongest-role sighting when present
            if o.label_category or o.label_name:
                cur["label_category"] = o.label_category
                cur["label_name"] = o.label_name

    entries: list[BlacklistEntry] = []
    for cur in agg.values():
        count = len(cur["inv_ids"])
        real = len(cur["real_ids"])
        # H2 (service-veto): a service sighting anywhere forces disarm,
        # overriding the per-sighting OR-arming.
        service_vetoed = bool(cur["service_seen"])
        armed = bool(cur["armed"]) and not service_vetoed
        confidence = ("high" if real >= 2 else "medium") if armed else "low"
        if service_vetoed:
            reason = _SERVICE_VETO_REASON
        else:
            reason = _reason_for(cur["role"], cur["label_name"], real, armed)
        entries.append(BlacklistEntry(
            address=cur["address"],
            chain=cur["chain"],
            role=cur["role"],
            label_category=cur["label_category"],
            label_name=cur["label_name"],
            source_investigation_ids=sorted(cur["inv_ids"]),
            source_case_count=count,
            real_case_count=real,
            alert_enabled=armed,
            confidence=confidence,
            reason=reason,
        ))
    # Armed first, then by how many real cases attest it (most-corroborated up).
    entries.sort(key=lambda e: (not e.alert_enabled, -e.real_case_count, e.address))
    return entries


def _reason_for(role: str, label_name: str | None, real: int, armed: bool) -> str:
    who = label_name or role
    if armed:
        n = f"{real} prior case(s)" if real else "a prior case"
        return f"Known-bad ({who}) — appeared as {role} in {n} of our investigations."
    return f"Seen as {role} ({who}); context only (test/benign source) — not alerting."


# ----- persistence ----- #


def save_blacklist(entries: list[BlacklistEntry], path: Path) -> int:
    """Write entries to ``path`` as JSON. Returns the count written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    armed = sum(1 for e in entries if e.alert_enabled)
    doc = {
        "version": 1,
        "kind": "recupero_internal_blacklist",
        "count": len(entries),
        "armed_count": armed,
        "entries": [e.to_json() for e in entries],
    }
    path.write_text(json.dumps(doc, indent=2, sort_keys=False), encoding="utf-8")
    return len(entries)


def load_blacklist_entries(path: Path) -> list[BlacklistEntry]:
    """Load entries from a saved JSON file. Missing/malformed → empty list
    (never raises — a degraded blacklist must not crash a screen/trace)."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return []
    except Exception as exc:  # noqa: BLE001
        log.warning("internal blacklist load failed at %s: %s", path, exc)
        return []
    out: list[BlacklistEntry] = []
    for row in (doc.get("entries") if isinstance(doc, dict) else None) or []:
        if isinstance(row, dict):
            try:
                out.append(BlacklistEntry.from_json(row))
            except Exception:  # noqa: BLE001
                continue
    return out


def armed_high_risk_entries(entries: Iterable[BlacklistEntry]) -> dict[str, Any]:
    """Project the ARMED entries into ``{canonical_key: HighRiskEntry}`` so they
    drop straight into ``load_high_risk_db``'s dict. Category
    ``internal_blacklist`` + severity 3 → screener score 6 → verdict "high"
    (NEVER "sanctioned" — an internal attribution is not an OFAC designation)."""
    from recupero._common import canonical_address_key as _ck
    from recupero.trace.risk_scoring import HighRiskEntry

    out: dict[str, Any] = {}
    for e in entries:
        if not e.alert_enabled:
            continue
        # H2 (service-veto), defense-in-depth: even an entry that arrives armed
        # from disk (written before the build-time veto, or hand-edited) is
        # dropped if its role/label_category marks a shared service — arming a
        # service into the high-risk DB risks a wrongful freeze.
        if _is_service_sighting(e.role, e.label_category):
            log.warning(
                "internal blacklist: refusing to arm service-labeled address "
                "%s (role=%s, label_category=%s) — %s",
                e.address, e.role, e.label_category, _SERVICE_VETO_REASON,
            )
            continue
        key = _ck(e.address)
        if not key:
            continue
        out[key] = HighRiskEntry(
            address=key,
            name=e.label_name or f"internal blacklist ({e.role})",
            risk_category="internal_blacklist",
            severity=3,
            notes=e.reason,
            confidence=e.confidence,
        )
    return out


def default_blacklist_path() -> Path:
    """Resolve the on-disk blacklist path: ``RECUPERO_INTERNAL_BLACKLIST_PATH``
    env override → else ``{data_dir}/intel/internal_blacklist.json``."""
    import os

    override = (os.environ.get("RECUPERO_INTERNAL_BLACKLIST_PATH", "") or "").strip()
    if override:
        return Path(override)
    try:
        from recupero.config import load_config
        cfg, _ = load_config()
        data_dir = Path(getattr(cfg, "data_dir", "data"))
    except Exception:  # noqa: BLE001
        data_dir = Path("data")
    return data_dir / "intel" / "internal_blacklist.json"


# ----- operator-curated manual arms (survive re-harvest) ----- #
#
# The auto-harvest re-writes its own file each run, so operator decisions live
# in a SEPARATE file that re-harvesting never touches. Every manual entry is
# armed (the operator explicitly vouched for it) — use it to blacklist a
# known-bad wallet the auto-harvest can't infer (e.g. an exploiter seed, a
# Tornado deposit you've attributed by hand).


def default_manual_arm_path() -> Path:
    """``RECUPERO_INTERNAL_BLACKLIST_MANUAL_PATH`` env override → else a
    sibling of the auto file named ``internal_blacklist_manual.json``."""
    import os

    override = (os.environ.get("RECUPERO_INTERNAL_BLACKLIST_MANUAL_PATH", "") or "").strip()
    if override:
        return Path(override)
    return default_blacklist_path().parent / "internal_blacklist_manual.json"


def load_manual_arms(path: Path) -> list[BlacklistEntry]:
    """Operator-curated armed entries. Missing/malformed → [] (never raises)."""
    from recupero._common import canonical_address_key as _ck

    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return []
    except Exception as exc:  # noqa: BLE001
        log.warning("manual blacklist load failed at %s: %s", path, exc)
        return []
    out: list[BlacklistEntry] = []
    for row in (doc.get("entries") if isinstance(doc, dict) else None) or []:
        if not isinstance(row, dict):
            continue
        addr = row.get("address")
        if not isinstance(addr, str) or not addr.strip():
            continue
        key = _ck(addr)
        if not key:
            continue
        out.append(BlacklistEntry(
            address=key,
            chain=str(row.get("chain", "")),
            role="manual",
            label_category=None,
            label_name=row.get("label_name") or "operator-flagged",
            source_investigation_ids=[],
            source_case_count=0,
            real_case_count=0,
            alert_enabled=True,
            confidence="high",
            reason=str(row.get("reason")
                       or "Operator-flagged known-bad (manual blacklist)."),
        ))
    return out


def _write_manual_doc(path: Path, entries: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"version": 1, "kind": "recupero_internal_blacklist_manual",
                    "entries": entries}, indent=2),
        encoding="utf-8",
    )


def add_manual_arm(
    path: Path, address: str, chain: str, *,
    reason: str | None = None, label_name: str | None = None,
) -> bool:
    """Arm a wallet by hand (upsert by canonical address+chain). Returns True if
    a new entry was added, False if an existing one was updated. Raises
    ValueError on an un-canonicalizable address."""
    from recupero._common import canonical_address_key as _ck

    key = _ck(address)
    if not key:
        raise ValueError(f"address does not canonicalize: {address!r}")
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
        entries = doc.get("entries") if isinstance(doc, dict) else None
    except Exception:  # noqa: BLE001
        entries = None
    if not isinstance(entries, list):
        entries = []
    for row in entries:
        if (isinstance(row, dict) and _ck(str(row.get("address", ""))) == key
                and row.get("chain") == chain):
            if reason:
                row["reason"] = reason
            if label_name:
                row["label_name"] = label_name
            _write_manual_doc(path, entries)
            return False
    entries.append({"address": key, "chain": chain,
                    "reason": reason, "label_name": label_name})
    _write_manual_doc(path, entries)
    return True


def remove_manual_arm(path: Path, address: str, chain: str) -> bool:
    """Disarm a manually-armed wallet. Returns True if an entry was removed."""
    from recupero._common import canonical_address_key as _ck

    key = _ck(address)
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
        entries = doc.get("entries") if isinstance(doc, dict) else None
    except Exception:  # noqa: BLE001
        return False
    if not isinstance(entries, list):
        return False
    kept = [r for r in entries
            if not (isinstance(r, dict)
                    and _ck(str(r.get("address", ""))) == key
                    and r.get("chain") == chain)]
    if len(kept) == len(entries):
        return False
    _write_manual_doc(path, kept)
    return True


__all__ = (
    "ARMED_ROLES",
    "NEVER_ARM_ROLES",
    "AddressObservation",
    "BlacklistEntry",
    "build_blacklist",
    "save_blacklist",
    "load_blacklist_entries",
    "armed_high_risk_entries",
    "default_blacklist_path",
    "default_manual_arm_path",
    "load_manual_arms",
    "add_manual_arm",
    "remove_manual_arm",
)
