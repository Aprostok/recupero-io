"""Generic free-OSS attribution-feed harvest (v0.35.9 — roadmap B1/B2).

``auto_ingest.py`` already harvests bridge + CEX candidates from four hardcoded
HTTP sources (DeFiLlama / Tronscan / Solscan / Etherscan). This module
generalizes the *harvest* to any free, open attribution dataset an operator can
download to a file — community CEX/bridge label exports, public entity lists,
etc. — feeding the SAME candidate → review → promote → seeds pipeline.

Why a file harvest (not another HTTP source): the most valuable free attribution
data is published as bulk downloads (CSV / JSON / NDJSON), not query APIs, and
new free sources appear constantly. A source-agnostic file importer lets the
operator add a free feed as DATA, not code — exactly the "free sources first;
paid feeds need a vendor key" posture in the competitive roadmap (B1/B2).

Safety (inherited + enforced here):
  * NOT auto-promote. Every parsed row lands as a ``CandidateLabel`` and is
    persisted at ``status='pending_review'``; an operator must explicitly
    promote it (with the multi-source / confirm-hash gates in ``auto_ingest``)
    before it influences any brief. This is the load-bearing property — a
    free feed is attacker-influenced, so it cannot write seeds directly.
  * Never fabricates. A row missing an address, with an invalid address shape
    for its chain, or carrying a category we don't map is SKIPPED and counted
    (returned in the summary) — never coerced into a bogus label.
  * Scope-matched to the existing pipeline: only the categories the
    candidate→promote path supports (bridge / exchange hot-wallet / exchange
    deposit) are harvested. Other category strings (mixer, sanctioned, defi…)
    are reported as skipped rather than silently written, because their seed
    files have their own promotion paths (OFAC feed, sanctions_intl, mixers
    seed) that must not be bypassed by a bulk attribution import.

Pipeline:
  1. Operator downloads a free attribution feed (CSV or JSON/NDJSON).
  2. ``recupero-ops import-attribution --file <download>`` parses it →
     ``label_candidates`` (pending review).
  3. Operator reviews + promotes via the existing labels API / ops flow.
"""

from __future__ import annotations

import csv
import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from recupero.labels.auto_ingest import CandidateLabel, persist_candidates

log = logging.getLogger(__name__)

# Free-feed category synonyms → the candidate categories the promote pipeline
# supports. Anything not here is reported as skipped (see module docstring).
_CATEGORY_SYNONYMS: dict[str, str] = {
    # bridges
    "bridge": "bridge",
    "bridges": "bridge",
    "cross chain": "bridge",
    "cross-chain": "bridge",
    "crosschain": "bridge",
    # exchange hot wallets
    "exchange": "exchange_hot_wallet",
    "exchange_hot_wallet": "exchange_hot_wallet",
    "exchange hot wallet": "exchange_hot_wallet",
    "hot wallet": "exchange_hot_wallet",
    "hot_wallet": "exchange_hot_wallet",
    "cex": "exchange_hot_wallet",
    "centralized exchange": "exchange_hot_wallet",
    "exchange_wallet": "exchange_hot_wallet",
    # exchange deposit addresses
    "exchange_deposit": "exchange_deposit",
    "deposit": "exchange_deposit",
    "exchange deposit": "exchange_deposit",
    "deposit address": "exchange_deposit",
    "deposit_address": "exchange_deposit",
}

# Common header aliases in free attribution CSVs → our canonical field names.
_FIELD_ALIASES: dict[str, str] = {
    "address": "address", "wallet": "address", "account": "address",
    "addr": "address", "public_key": "address", "publickey": "address",
    "chain": "chain", "network": "chain", "blockchain": "chain",
    "category": "category", "type": "category", "label_type": "category",
    "entity_type": "category", "tag_type": "category",
    "name": "name", "entity": "name", "label": "name", "tag": "name",
    "entity_name": "name", "owner": "name",
    "source": "source", "feed": "source", "dataset": "source",
    "url": "url", "source_url": "url", "reference": "url", "ref": "url",
}

# Chain-name synonyms seen in free feeds → our Chain enum strings.
_CHAIN_SYNONYMS: dict[str, str] = {
    "eth": "ethereum", "ethereum": "ethereum", "mainnet": "ethereum",
    "arb": "arbitrum", "arbitrum": "arbitrum", "arbitrum one": "arbitrum",
    "op": "optimism", "optimism": "optimism",
    "base": "base",
    "bsc": "bsc", "bnb": "bsc", "binance": "bsc", "binance smart chain": "bsc",
    "matic": "polygon", "polygon": "polygon", "pol": "polygon",
    "avax": "avalanche", "avalanche": "avalanche",
    "ftm": "fantom", "fantom": "fantom",
    "trx": "tron", "tron": "tron",
    "sol": "solana", "solana": "solana",
    "btc": "bitcoin", "bitcoin": "bitcoin",
}


@dataclass(frozen=True)
class AttributionImportResult:
    """Summary of one attribution-feed import (no silent truncation)."""
    parsed: int           # rows that became candidates
    skipped: int          # rows dropped (invalid / unsupported)
    skipped_reasons: dict[str, int]
    persisted: int        # NEW candidate rows written to review queue


def _norm_key(k: Any) -> str:
    return str(k or "").strip().lower().replace("-", "_")


def _map_row(raw: dict[str, Any]) -> dict[str, str]:
    """Map a raw feed row's keys onto our canonical field names."""
    out: dict[str, str] = {}
    for k, v in raw.items():
        canon = _FIELD_ALIASES.get(_norm_key(k))
        if canon and canon not in out:
            out[canon] = "" if v is None else str(v).strip()
    return out


def parse_attribution_rows(
    rows: Iterable[dict[str, Any]],
    *,
    default_source: str = "attribution_feed",
) -> tuple[list[CandidateLabel], dict[str, int]]:
    """PURE: generic attribution rows → ``(candidates, skipped_reasons)``.

    Each row needs at minimum an address + a category that maps to a supported
    candidate category. Chain defaults to ``ethereum`` for an EVM-shaped
    address when unspecified. Rows that fail are tallied by reason (never
    fabricated). ``CandidateLabel.__post_init__`` is the final validation gate.
    """
    out: list[CandidateLabel] = []
    skipped: dict[str, int] = {}

    def _skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    for raw in rows:
        if not isinstance(raw, dict):
            _skip("not_an_object")
            continue
        row = _map_row(raw)
        address = (row.get("address") or "").strip()
        if not address:
            _skip("missing_address")
            continue

        cat_raw = (row.get("category") or "").strip().lower()
        category = _CATEGORY_SYNONYMS.get(cat_raw)
        if category is None:
            _skip(f"unsupported_category:{cat_raw or '(blank)'}")
            continue

        chain_raw = (row.get("chain") or "").strip().lower()
        chain = _CHAIN_SYNONYMS.get(chain_raw, chain_raw)
        if not chain:
            # Infer EVM default only for a clearly EVM-shaped address.
            chain = "ethereum" if (address.startswith("0x") and len(address) == 42) else ""
        if not chain:
            _skip("missing_chain")
            continue

        name = (row.get("name") or "").strip() or "(attribution feed)"
        source = (row.get("source") or "").strip() or default_source
        # Sanitize the source into the strict identifier the promote gate
        # requires; fall back to the default if the feed gave junk.
        safe_source = "".join(
            c for c in source.lower().replace(" ", "_")
            if c.isalnum() or c in "_.-:"
        )[:63] or default_source

        try:
            out.append(CandidateLabel(
                address=address,
                chain=chain,
                proposed_category=category,
                proposed_name=name[:200],
                source=safe_source,
                source_url=(row.get("url") or "").strip()[:500],
                proposed_confidence="low",
                raw_metadata={"attribution_feed_row": raw},
            ))
        except ValueError as exc:
            _skip(f"invalid:{exc.args[0][:40] if exc.args else 'unknown'}")
            continue

    return out, skipped


def _iter_feed_records(path: Path) -> list[dict[str, Any]]:
    """Read an attribution feed file: .csv, .json array, or .ndjson/.jsonl."""
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8-sig")
    if suffix == ".csv":
        return [dict(r) for r in csv.DictReader(text.splitlines())]
    stripped = text.lstrip()
    if stripped.startswith("["):
        data = json.loads(text)
        return [r for r in data if isinstance(r, dict)]
    if stripped.startswith("{") and "\n" not in stripped.rstrip():
        # Single JSON object.
        obj = json.loads(text)
        return [obj] if isinstance(obj, dict) else []
    # NDJSON / JSONL.
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def import_attribution_file(
    in_path: Path,
    *,
    dsn: str | None = None,
    default_source: str = "attribution_feed",
    daily_cap: int | None = None,
) -> AttributionImportResult:
    """Parse a free attribution feed file → persist candidates (review queue).

    Returns an :class:`AttributionImportResult`. Persists to the
    ``label_candidates`` table via ``auto_ingest.persist_candidates`` (which
    no-ops with a log line when ``SUPABASE_DB_URL`` is unset — local dev). The
    rows land at ``pending_review``; promotion stays operator-gated.
    """
    candidates, skipped = parse_attribution_rows(
        _iter_feed_records(in_path), default_source=default_source,
    )
    persisted = persist_candidates(candidates, dsn=dsn, daily_cap=daily_cap)
    skipped_total = sum(skipped.values())
    log.info(
        "attribution-feed import: parsed=%d skipped=%d persisted=%d (file=%s)",
        len(candidates), skipped_total, persisted, in_path,
    )
    if skipped:
        log.info("attribution-feed skipped breakdown: %s", skipped)
    return AttributionImportResult(
        parsed=len(candidates),
        skipped=skipped_total,
        skipped_reasons=skipped,
        persisted=persisted,
    )


__all__ = (
    "AttributionImportResult",
    "parse_attribution_rows",
    "import_attribution_file",
)
