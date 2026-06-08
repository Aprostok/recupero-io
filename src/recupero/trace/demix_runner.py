"""Mixer demixing runner (v0.39, Activation Sprint #4).

Turns the ``demix_candidates`` scorer (built for task #259 but NEVER wired — it
was dead code, called by nothing) into a LIVE, opt-in pipeline:

  1. find every transfer INTO a known Tornado pool in a finished case (the deposit),
  2. fetch that pool's ``Withdrawal`` events after the deposit (opt-in adapter
     getLogs — kept out of the hot trace path),
  3. score them with ``demix_candidates`` into ranked LEADS (always low-confidence,
     never a followed destination — a reviewer triages them into subpoena targets).

Forensic doctrine (inherited from ``demixing``): leads are ALWAYS confidence
``low``; we never fabricate a withdrawal (only real on-chain ``Withdrawal`` events
are scored); every lead carries the exact signals that fired. Gated by
``RECUPERO_DEMIX_LEADS`` (default off) — same opt-in discipline as
``RECUPERO_BRIDGE_CONFIRM`` — since the pool-event fetch can be large.

The Tornado ``Withdrawal`` event + recipient/relayer offsets are VERIFIED against
596 real 100-ETH-pool logs (topic0 + ``to`` = data word 0, relayer = topic 1).
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from recupero.trace.demixing import (
    DEFAULT_MAX_LEADS,
    DemixLead,
    MixerEvent,
    demix_candidates,
)
from recupero.trace.mixer_detection import is_mixer

log = logging.getLogger(__name__)

# Tornado Cash: Withdrawal(address to, bytes32 nullifierHash, address indexed
# relayer, uint256 fee). VERIFIED vs real 100-ETH-pool logs — recipient ``to`` is
# data word 0; the relayer is indexed topic 1.
TORNADO_WITHDRAWAL_TOPIC0 = (
    "0xe9e508bad6d4c3227e881ca19068f099da81b5164dd6d62b2eaf1e8bc6c34931"
)


def demix_enabled() -> bool:
    """Opt-in gate (RECUPERO_DEMIX_LEADS). Default off — the pool-event fetch is
    an extra, potentially large getLogs call."""
    return (os.environ.get("RECUPERO_DEMIX_LEADS", "") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


@dataclass(frozen=True)
class MixerDeposit:
    """A transfer INTO a known mixer pool — the deposit to demix."""
    pool_address: str
    chain: str
    pool_name: str
    deposit: MixerEvent


def _chain_str(c: Any) -> str | None:
    if c is None:
        return None
    return getattr(c, "value", None) or (str(c) if c else None)


def find_mixer_deposits(
    transfers: Iterable[Any], *, default_chain: str = "ethereum"
) -> list[MixerDeposit]:
    """Every transfer whose ``to_address`` is a known mixer pool, as a
    (pool, deposit-event) record. Works on Case.transfers or any objects exposing
    to_address / from_address / chain / block_time / tx_hash."""
    out: list[MixerDeposit] = []
    seen: set[tuple[str, str]] = set()
    for t in transfers or []:
        to = getattr(t, "to_address", None)
        if not to:
            continue
        chain = _chain_str(getattr(t, "chain", None)) or default_chain
        ok, name, _typ = is_mixer(str(to), chain)
        if not ok:
            continue
        txh = str(getattr(t, "tx_hash", "") or "")
        key = (str(to).lower(), txh)
        if key in seen:
            continue
        seen.add(key)
        when = getattr(t, "block_time", None)
        out.append(MixerDeposit(
            pool_address=str(to).lower(),
            chain=chain,
            pool_name=name or "mixer",
            deposit=MixerEvent(
                address=str(getattr(t, "from_address", "") or ""),
                when=when if isinstance(when, datetime) else datetime.now(UTC),
                pool=name or str(to).lower(),
                tx_hash=txh,
            ),
        ))
    return out


def _log_time(lg: dict[str, Any]) -> datetime:
    ts = lg.get("timeStamp") or lg.get("timestamp")
    try:
        if isinstance(ts, str) and ts.lower().startswith("0x"):
            return datetime.fromtimestamp(int(ts, 16), tz=UTC)
        if ts is not None:
            return datetime.fromtimestamp(int(ts), tz=UTC)
    except (ValueError, OSError, OverflowError):
        pass
    return datetime.now(UTC)


def withdrawals_from_logs(
    logs: Iterable[Any], *, pool_name: str
) -> list[MixerEvent]:
    """Parse Tornado ``Withdrawal`` logs → withdrawal MixerEvents (recipient =
    data word 0; relayer = indexed topic 1; time from the log's timeStamp).
    Malformed logs are skipped — never fabricated."""
    out: list[MixerEvent] = []
    for lg in logs or []:
        if not isinstance(lg, dict):
            continue
        data = (lg.get("data") or "")
        data = data[2:] if data.startswith("0x") else data
        if len(data) < 64:
            continue
        recipient = "0x" + data[0:64][24:]
        if recipient == "0x" + "0" * 40:
            continue
        topics = lg.get("topics") or []
        relayer = None
        if len(topics) >= 2 and isinstance(topics[1], str):
            relayer = "0x" + topics[1].removeprefix("0x")[-40:]
        txh = lg.get("transactionHash") or lg.get("transaction_hash") or ""
        out.append(MixerEvent(
            address=recipient, when=_log_time(lg), pool=pool_name,
            tx_hash=str(txh), relayer=relayer,
        ))
    return out


def run_demix_leads(
    *,
    transfers: Iterable[Any],
    adapter: Any,
    default_chain: str = "ethereum",
    window_hours: int = 0,
    max_leads: int = DEFAULT_MAX_LEADS,
    force: bool = False,
) -> dict[str, list[DemixLead]]:
    """For each mixer deposit in the case, fetch the pool's Withdrawal events
    after the deposit and score → ranked leads keyed by
    ``<pool_address>@<deposit_tx>``. Opt-in: returns ``{}`` unless ``force`` or
    ``RECUPERO_DEMIX_LEADS`` is set. Best-effort — a per-pool fetch failure skips
    that pool, never aborts."""
    if not (force or demix_enabled()):
        return {}
    deposits = find_mixer_deposits(transfers, default_chain=default_chain)
    results: dict[str, list[DemixLead]] = {}
    for md in deposits:
        try:
            from_block = adapter.block_at_or_before(md.deposit.when)
            to_block: int | str = "latest"
            if window_hours and window_hours > 0:
                to_block = adapter.block_at_or_before(
                    md.deposit.when + timedelta(hours=window_hours)
                )
            logs = adapter.fetch_logs(
                md.pool_address, TORNADO_WITHDRAWAL_TOPIC0,
                from_block=from_block, to_block=to_block,
            )
        except Exception as exc:  # noqa: BLE001 — best-effort per pool
            log.warning("demix: withdrawal fetch failed pool=%s: %s",
                        md.pool_address, exc)
            continue
        withdrawals = withdrawals_from_logs(logs, pool_name=md.pool_name)
        leads = demix_candidates(
            md.deposit, withdrawals, window_hours=window_hours, max_leads=max_leads,
        )
        if leads:
            results[f"{md.pool_address}@{md.deposit.tx_hash}"] = leads
            log.info("demix: %d lead(s) for pool=%s deposit=%s",
                     len(leads), md.pool_name, md.deposit.tx_hash[:12])
    return results


def leads_to_json(results: dict[str, list[DemixLead]]) -> dict[str, Any]:
    """Serialize run_demix_leads output to a JSON-safe demix_leads artifact."""
    return {
        "kind": "recupero_demix_leads",
        "disclaimer": (
            "Probabilistic demixing LEADS — never proof. A mixer cryptographically "
            "severs deposit↔withdrawal; these are same-pool candidates that share a "
            "behavioral signal (address reuse / relayer / gas / FIFO timing), for "
            "manual review (e.g. subpoena), NEVER a followed destination."
        ),
        "deposits": [
            {
                "key": key,
                "leads": [
                    {
                        "withdrawal_address": ld.withdrawal_address,
                        "withdrawal_tx": ld.withdrawal_tx,
                        "pool": ld.pool,
                        "score": ld.score,
                        "signals": list(ld.signals),
                        "basis": ld.basis,
                        "confidence": ld.confidence,
                    }
                    for ld in leads
                ],
            }
            for key, leads in results.items()
        ],
    }


__all__ = (
    "TORNADO_WITHDRAWAL_TOPIC0",
    "MixerDeposit",
    "demix_enabled",
    "find_mixer_deposits",
    "withdrawals_from_logs",
    "run_demix_leads",
    "leads_to_json",
)
