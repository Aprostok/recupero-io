"""Pipeline orchestration for one investigation.

The worker runs each stage of the existing CLI pipeline against a per-
investigation tempdir, then mirrors the produced artifacts to Supabase
Storage. The pipeline functions themselves are imported and called as-is —
no changes to ``trace/``, ``reports/``, ``freeze/``, or ``dormant/`` modules.
That refactor is Phase 4.

Resume policy
-------------

When a row is re-claimed (UI flipped to ``review_approved``, or a previous
worker crashed and the heartbeat went stale), the pipeline detects the
furthest-along stage by inspecting bucket contents:

* ``case.json`` missing      → run trace
* ``freeze_asks.json`` missing → run list-freeze-targets
* ``brief_editorial.json`` missing → run ai-editorial
* ``brief_editorial.json`` present with ``REVIEW_REQUIRED: true``
                              → mark review_required and pause
* ``brief_editorial.json`` present with ``REVIEW_REQUIRED: false``
                              → run emit-brief, mark completed

This is more robust than carrying a "resume from N" flag in the row, because
upserts to Storage are atomic per file: presence implies a complete write.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

# Per-chain default trace-window start for wallet-trace rows that
# don't supply an incident_time. Each entry is the chain's genesis-
# block timestamp (UTC) — earlier values cause that chain's
# block-by-timestamp explorer endpoint to return "no closest block
# found" instead of clamping to block 1, which the tracer chokes on.
#
# Single-source documentation of chain genesis (canonical references):
#
#   * Ethereum block 1     — 2015-07-30 15:26:13 UTC (genesis at block 0
#                            is null/uncles; block 1 is the first real
#                            block — Etherscan's API answers from here.)
#   * Polygon (Matic) genesis — 2020-05-30 06:23:35 UTC
#   * BSC genesis            — 2020-08-29 03:24:14 UTC
#   * Arbitrum One genesis   — 2021-08-31 22:09:39 UTC
#   * Base genesis           — 2023-06-15 17:00:00 UTC
#   * Solana mainnet-beta    — 2020-03-16 14:00:00 UTC (not actually used
#                              by run_trace — Solana adapter uses its
#                              own slot-based lookup — but kept here
#                              for the fallback case if dispatch logic
#                              ever changes.)
#   * Hyperliquid launched   — 2024-06-01 (post-launch — not used by
#                              run_trace either; scrape_hyperliquid_case
#                              has its own start-time logic. Listed for
#                              completeness only.)
#
# The fallback (used if a chain isn't in the map or fails to parse) is
# the Ethereum block 1 timestamp — earliest known good value across
# any supported chain.
_CHAIN_GENESIS_TIMESTAMPS: dict[str, datetime] = {
    "ethereum":    datetime(2015, 7, 30, 15, 26, 13, tzinfo=UTC),
    "polygon":     datetime(2020, 5, 30,  6, 23, 35, tzinfo=UTC),
    "bsc":         datetime(2020, 8, 29,  3, 24, 14, tzinfo=UTC),
    "arbitrum":    datetime(2021, 8, 31, 22,  9, 39, tzinfo=UTC),
    "base":        datetime(2023, 6, 15, 17,  0,  0, tzinfo=UTC),
    "solana":      datetime(2020, 3, 16, 14,  0,  0, tzinfo=UTC),
    "hyperliquid": datetime(2024, 6,  1,  0,  0,  0, tzinfo=UTC),
}

_FALLBACK_GENESIS = _CHAIN_GENESIS_TIMESTAMPS["ethereum"]


# How far back to trace by default for wallet-trace runs that don't
# supply an incident_time. 365 days is the operationally-sane window:
#
#   * Long enough to cover any reasonably-recent scam or hack the
#     operator is investigating in real time.
#   * Short enough that a trace at max_depth=2 on an active wallet
#     finishes within the 5-minute reaper threshold — real-case
#     validation showed full-history (chain-genesis) traces on active
#     wallets blow past 5 minutes and get reaped mid-trace.
#   * Override via RECUPERO_WALLET_TRACE_LOOKBACK_DAYS env var; set to
#     a large value (e.g. 99999) to effectively re-enable full-history
#     tracing.
#   * Per-row override via Investigation.incident_time — when the
#     operator sets that column explicitly, we use it verbatim and
#     this default doesn't apply.
#
# Operators who need genuinely-full history on an old wallet should
# set incident_time to a specific date via the admin UI. The
# chain-genesis dict above documents the absolute floor per chain.
_DEFAULT_WALLET_TRACE_LOOKBACK_DAYS = 365


def _default_incident_time_for(chain: str, *, now: datetime | None = None) -> datetime:
    """Resolve the default trace-window start for a wallet-trace row
    that doesn't supply an incident_time.

    Returns ``now - lookback_days`` unless that would fall before the
    chain's genesis, in which case the chain-genesis timestamp wins.
    This keeps the recent-activity default fast on active wallets
    while still working on chains newer than 365 days (Base launched
    in mid-2023 — a 365-day lookback today still post-dates genesis,
    but in mid-2024 it didn't).

    ``now`` is injectable for tests. The lookback days are read from
    the ``RECUPERO_WALLET_TRACE_LOOKBACK_DAYS`` env var on each call
    so tests / ops can flip behavior without restarting the worker.
    """
    if now is None:
        now = datetime.now(UTC)
    try:
        lookback_days = int(
            os.environ.get(
                "RECUPERO_WALLET_TRACE_LOOKBACK_DAYS",
                str(_DEFAULT_WALLET_TRACE_LOOKBACK_DAYS),
            )
        )
    except ValueError:
        lookback_days = _DEFAULT_WALLET_TRACE_LOOKBACK_DAYS
    candidate = now - timedelta(days=max(1, lookback_days))
    genesis = _CHAIN_GENESIS_TIMESTAMPS.get(chain.lower(), _FALLBACK_GENESIS)
    # If the candidate would fall before chain genesis, use genesis.
    # This matters for newer chains (a 365-day lookback in early 2024
    # would have predated Base's June 2023 genesis on the next-month
    # boundary).
    return max(candidate, genesis)

from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.models import Case
from recupero.reports.victim import VictimInfo, write_victim
from recupero.storage.case_store import CaseStore
from recupero.storage.supabase_case_store import SupabaseCaseStore
from recupero.worker import state as S
from recupero.worker.db import CaseData, Investigation, WorkerDB
from recupero.worker.sync import download_editorial, upload_case_dir

log = logging.getLogger(__name__)


# ----- Placeholder-address detection ----- #


def _is_obvious_placeholder_address(addr: str) -> bool:
    """Detect intake-form placeholder / sentinel addresses that
    were obviously not real on-chain wallets.

    Catches the failure mode discovered against the Hekla case
    (a real intake submission with seed_address
    ``0x1234567890123456789012345678901234567890`` — sequential
    digits the user filled in to advance the form). Running the
    full pipeline on these burns ~$0.15 of Anthropic budget per
    submission and produces a useless empty case with a stale
    REVIEW_REQUIRED flag the operator has to triage manually.

    Patterns detected (all case-insensitive on the hex body):

      * All-same-character — zero address (``0x000…000``), max
        address (``0xfff…fff``), repeating-digit fillers
        (``0x111…111``, ``0xaaa…aaa``).
      * Cycling-digit pattern — e.g. ``1234567890`` repeating four
        times, ``abcdef0123456789`` etc.
      * Known test sentinels (``0xdead…beef``).

    Real Ethereum addresses derived from cryptographic hashes
    practically never exhibit these patterns. The function is
    conservative — it explicitly does NOT flag addresses that
    *contain* a placeholder-like substring; only addresses whose
    *entire body* matches a placeholder pattern.

    Returns False for any non-EVM-shaped input (wrong length,
    missing 0x prefix, etc.) — the chain adapter handles
    validation for those cases.
    """
    if not addr or not addr.startswith("0x"):
        return False
    body = addr[2:].lower()
    if len(body) != 40:
        return False
    # All same character — zero / max / repeating filler addresses.
    if len(set(body)) == 1:
        return True
    # Cycling-digit pattern. Try cycle lengths that divide 40 evenly.
    # 10 catches Hekla's 1234567890-repeating; 8/5/4/2 catch other
    # plausible filler patterns.
    for cycle_len in (2, 4, 5, 8, 10, 20):
        if len(body) % cycle_len != 0:
            continue
        first = body[:cycle_len]
        if body == first * (len(body) // cycle_len):
            return True
    # Known test sentinels operators sometimes paste.
    _KNOWN_SENTINELS = {
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "cafebabecafebabecafebabecafebabecafebabe",
    }
    if body in _KNOWN_SENTINELS:
        return True
    return False


# ----- Public entry point ----- #


def run_one(
    inv: Investigation,
    *,
    config: RecuperoConfig,
    env: RecuperoEnv,
    db: WorkerDB,
    store: SupabaseCaseStore,
) -> None:
    """Drive one investigation forward as far as it can go.

    Catches all exceptions per stage and marks the row failed with the
    stage name + error text. Returns cleanly on review_required (worker
    drops the row; a future claim resumes after the UI approves).
    """
    log.info("running investigation id=%s case_id=%s status=%s",
             inv.id, inv.case_id, inv.status)

    # Fail-fast on intake-form placeholder addresses. The Hekla case
    # (seed_address 0x12345...7890) burned ~$0.15 of Anthropic budget
    # before producing an empty case stuck in REVIEW_REQUIRED for 6+
    # days. Catching these at claim time saves both the API cost AND
    # the operator triage time — the admin UI surfaces the failure
    # immediately with a clear, actionable error_message.
    #
    # Skipped for chains we can't pattern-check (Solana addresses
    # are base58, not 0x-hex — the detector returns False for them
    # by construction).
    if _is_obvious_placeholder_address(inv.seed_address):
        log.warning(
            "investigation %s: seed_address %s looks like an intake "
            "placeholder — failing fast before burning API budget",
            inv.id, inv.seed_address,
        )
        db.mark_failed(
            inv.id,
            stage="setup",
            error=(
                f"seed_address {inv.seed_address!r} looks like an intake "
                f"placeholder (repeating-digit or sequential pattern). "
                f"Verify the address with the client and re-trigger the "
                f"investigation with the real wallet."
            ),
        )
        return

    # Local Case.case_id is the investigation UUID — keeps local case_dir,
    # bucket prefix, and trace artifacts in lockstep.
    case_id_str = str(inv.id)

    # Apply per-investigation config overrides if the row provided them.
    cfg = config.model_copy(deep=True)
    if inv.max_depth and inv.max_depth > 0:
        cfg.trace.max_depth = int(inv.max_depth)
    if inv.dust_threshold_usd is not None:
        cfg.trace.dust_threshold_usd = float(inv.dust_threshold_usd)

    # Wallet-trace investigations (case_id=NULL) don't have a backing
    # cases row — no victim, no incident narrative, just a wallet to
    # trace. Force skip_editorial + skip_freeze_briefs on this path
    # regardless of what the row carries, since editorial needs victim
    # context and freeze letters need a victim to address.
    case_data = None
    if inv.case_id is not None:
        case_data = db.fetch_case(inv.case_id)
        if case_data is None:
            # Don't crash silently — surface the FK referent missing so it
            # can be triaged from the admin UI.
            db.mark_failed(
                inv.id, stage="setup",
                error=f"cases row {inv.case_id} not found (FK violation)",
            )
            return
    else:
        log.info(
            "investigation %s has case_id=NULL (wallet trace) — "
            "forcing skip_editorial + skip_freeze_briefs",
            inv.id,
        )
        # Make this a no-op mutation in-memory; the row's own columns
        # are typically already true on this path, but if Jacob's
        # admin UI mis-sets them we recover gracefully.
        inv = inv.model_copy(update={
            "skip_editorial": True,
            "skip_freeze_briefs": True,
        })

    api_costs_usd: Decimal | None = None

    try:
        with _local_case_dir(cfg, case_id_str) as (local_store, case_dir):
            # Seed victim.json only when we have a backing case.
            # Wallet traces leave victim.json absent — the trace
            # report doesn't need it, and downstream stages that
            # WOULD need it (editorial / freeze letters) are all
            # skipped on this path.
            if case_data is not None:
                _write_victim_from_case(case_dir, inv, case_data)

            has_case = store.exists("case.json")
            has_freeze = store.exists("freeze_asks.json")
            has_editorial = store.exists("brief_editorial.json")

            # Trace stage --------------------------------------------------
            if not has_case:
                _run_stage(
                    db, inv.id, S.TRACING,
                    lambda: _stage_trace(inv, case_id_str, cfg, env,
                                         local_store, case_dir, store),
                )
            else:
                _hydrate_local_from_bucket(store, case_dir,
                                           ["case.json", "manifest.json", "transfers.csv"])

            # Freeze stage -------------------------------------------------
            if not has_freeze:
                _run_stage(
                    db, inv.id, S.LISTING_FREEZE_TARGETS,
                    lambda: _stage_list_freeze_targets(inv, case_id_str, cfg, env,
                                                       local_store, case_dir, store),
                )
            else:
                _hydrate_local_from_bucket(store, case_dir, ["freeze_asks.json"])

            # Watchlist population is best-effort: failures here log but do
            # not fail the investigation. The audit list is a side-effect,
            # not a deliverable.
            _populate_watchlist(inv, local_store, case_dir, db)

            # Pass-2 perpetrator-forward trace (v0.8.0) ----------------------
            # Runs from the consolidation hub(s) identified during
            # pass-1, surfacing downstream destinations that
            # victim-forward attribution-share filtering would
            # otherwise hide. See trace/perpetrator_trace.py for
            # the architecture + heuristic thresholds.
            #
            # Best-effort: failures log a warning + the
            # investigation proceeds with pass-1 only. Skipped
            # entirely on:
            #   * wallet traces (skip_freeze_briefs=True)
            #   * RECUPERO_DISABLE_PASS2=1 in env
            #   * when no candidates qualify (the heuristic
            #     correctly says "no hub worth re-tracing")
            if not inv.skip_freeze_briefs and not has_freeze:
                # Only run on fresh investigations — skip on
                # re-runs that already had freeze_asks.json
                # hydrated, since the pass-2 case.json is now
                # in storage from the prior run.
                _maybe_run_pass2(
                    inv=inv, case_id_str=case_id_str, cfg=cfg, env=env,
                    local_store=local_store, case_dir=case_dir, bucket=store,
                )

            # Editorial stage ----------------------------------------------
            # Skipped when the row has skip_editorial=True (wallet
            # traces, internal R&D — no real victim to write prose
            # about, no compliance team to address). The pipeline
            # bypasses the awaiting_review checkpoint entirely on
            # this path and proceeds straight to emit + building_package
            # with whatever computed-only artifacts we have.
            if inv.skip_editorial:
                log.info(
                    "investigation %s: skip_editorial=true — bypassing "
                    "Anthropic + awaiting_review checkpoint",
                    inv.id,
                )
            elif not has_editorial:
                api_costs_usd = _run_stage(
                    db, inv.id, S.EDITORIAL_DRAFTING,
                    lambda: _stage_ai_editorial(inv, case_id_str, case_data,
                                                local_store, case_dir, store),
                )
                # Write the cost on the row before pausing — pass 2 won't
                # have access to this local since the review checkpoint
                # resets state. mark_built_package's COALESCE preserves it.
                db.mark_review_required(inv.id, api_costs_usd=api_costs_usd)
                log.info("investigation %s paused at review_required (api_costs=$%s)",
                         inv.id, api_costs_usd)
                return
            else:
                # Editorial already exists. Re-read from bucket (UI may have
                # rewritten it during review) and decide whether to pause or emit.
                download_editorial(store, case_dir)
                editorial = json.loads(
                    (case_dir / "brief_editorial.json").read_text(encoding="utf-8-sig")
                )
                if editorial.get("REVIEW_REQUIRED", False):
                    db.mark_review_required(inv.id)
                    log.info("investigation %s still REVIEW_REQUIRED; pausing", inv.id)
                    return

            # Emit stage ---------------------------------------------------
            # The emit-brief stage produces freeze_brief.json from
            # freeze_asks.json + editorial. On skip_editorial paths
            # we bypass emit_brief entirely and synthesize a minimal
            # freeze_brief.json from freeze_asks alone — the trace
            # report's freeze-potential table only reads the
            # FREEZABLE list, which we can rebuild from freeze_asks
            # without any editorial input.
            if inv.skip_editorial:
                _run_stage(
                    db, inv.id, S.EMITTING,
                    lambda: _synthesize_freeze_brief_from_asks(
                        case_dir, store,
                    ),
                )
            else:
                _run_stage(
                    db, inv.id, S.EMITTING,
                    lambda: _stage_emit_brief(
                        inv, case_id_str, local_store, case_dir, store,
                    ),
                )

            # Per docs/investigation-integration.md, the worker passes
            # through `building_package` (output columns written here),
            # then `complete` (stamps completed_at). The Python-side
            # builder generates per-issuer freeze HTMLs + LE handoff;
            # JS-based PDF/docx production is still deferred but the
            # worker now produces the operator-ready HTML deliverables.
            summary = _summarize_brief(case_dir / "freeze_brief.json")
            db.mark_built_package(
                inv.id,
                storage_path=store.storage_prefix,  # "investigations/<id>/" (with trailing /)
                total_loss_usd=summary.get("total_loss_usd"),
                max_recoverable_usd=summary.get("max_recoverable_usd"),
                freezable_issuers=summary.get("freezable_issuers"),
                api_costs_usd=api_costs_usd,
            )
            _run_stage(
                db, inv.id, S.BUILDING_PACKAGE,
                lambda: _stage_build_package(inv, case_id_str,
                                             local_store, case_dir, store),
            )
            db.mark_completed(inv.id)
            log.info("investigation %s completed", inv.id)

    except _StageFailure as exc:
        log.exception("investigation %s failed at %s", inv.id, exc.stage)
        db.mark_failed(inv.id, stage=exc.stage, error=exc.message)
    except Exception as exc:  # noqa: BLE001
        log.exception("investigation %s failed (unstaged): %s", inv.id, exc)
        db.mark_failed(inv.id, stage="unknown", error=f"{type(exc).__name__}: {exc}")


# ----- Stages ----- #


def _stage_trace(
    inv: Investigation,
    case_id_str: str,
    config: RecuperoConfig,
    env: RecuperoEnv,
    local_store: CaseStore,
    case_dir: Path,
    bucket: SupabaseCaseStore,
) -> None:
    """Trace dispatch by chain.

    EVM chains (ethereum / arbitrum / polygon / base / bsc) and Solana go
    through ``run_trace``, which queries chain explorers, prices each
    transfer, and writes per-tx evidence receipts.

    Hyperliquid is fundamentally different — it has its own ledger API
    (no Etherscan equivalent) and no per-tx evidence concept — so it
    uses ``scrape_hyperliquid_case`` instead. The resulting Case has
    chain=ethereum baked in (Hyperliquid uses Ethereum-format addresses)
    even though the investigations row has chain='hyperliquid'.
    """
    # Wallet-trace rows (case_id=NULL) typically arrive with
    # incident_time=NULL — Jacob's admin UI doesn't collect it because
    # operators want full-history traces. Resolve the per-chain
    # genesis timestamp so the trace window covers the full chain
    # history. Each chain has its own value because using Ethereum's
    # 2015 genesis on a 2023-genesis chain like Base just wastes the
    # explorer's "no closest block" round-trip.
    incident_time = inv.incident_time or _default_incident_time_for(inv.chain)
    if inv.incident_time is None:
        log.info(
            "investigation %s: incident_time=NULL on chain=%s — "
            "defaulting to chain-genesis timestamp %s "
            "(full-history wallet trace)",
            inv.id, inv.chain, incident_time.isoformat(),
        )

    if inv.chain == "hyperliquid":
        from recupero.chains.hyperliquid.scraper import scrape_hyperliquid_case
        case = scrape_hyperliquid_case(
            user_address=inv.seed_address,
            case_id=case_id_str,
            incident_time=incident_time,
            config=config,
            env=env,
        )
    else:
        from recupero.models import Chain
        from recupero.trace.tracer import run_trace
        try:
            chain = Chain(inv.chain)
        except ValueError as e:
            raise _StageFailure(S.TRACING, f"unknown chain: {inv.chain}") from e
        case = run_trace(
            chain=chain,
            seed_address=inv.seed_address,
            incident_time=incident_time,
            case_id=case_id_str,
            config=config,
            env=env,
            case_dir=case_dir,
        )

    local_store.write_case(case)
    upload_case_dir(case_dir, bucket)


def _stage_list_freeze_targets(
    inv: Investigation,
    case_id_str: str,
    config: RecuperoConfig,
    env: RecuperoEnv,
    local_store: CaseStore,
    case_dir: Path,
    bucket: SupabaseCaseStore,
) -> None:
    """Worker-side equivalent of `recupero list-freeze-targets`.

    Mirrors the inline logic in cli.py's list_freeze_targets_cmd, minus the
    rich console output. The freeze_asks.json schema MUST match the CLI's,
    because emit_brief.py reads it.

    Phase 4 will extract a shared function and have the CLI delegate to it.
    """
    from recupero.dormant import find_dormant_in_case
    from recupero.freeze import group_by_issuer, match_freeze_asks
    from recupero.freeze.asks import (
        detect_exchange_deposits,
        synthesize_historical_freeze_asks,
    )
    from recupero.labels.store import LabelStore

    case = local_store.read_case(case_id_str)

    min_usd = Decimal("10000")
    min_holding_usd = Decimal("1000")
    # v0.16.0: historical-inflow threshold. Set lower than current-balance
    # threshold so addresses that received freezable tokens but currently
    # show $0 still surface — this is the worker-pipeline parity fix for
    # the V-CFI01 regression where addresses with confirmed downstream
    # freezable balances were absent from freeze_asks.json because the
    # worker only ever called match_freeze_asks (current-balance path).
    historical_min_inflow_usd = Decimal("1000")

    # v0.16.1 (internal audit): defensive wrapping of find_dormant_in_case.
    # That function makes live Etherscan + CoinGecko calls to query
    # current balances. If the API key is missing, the call is
    # rate-limited, or the upstream is down, we lose the current-balance
    # asks — but historically those failures also prevented the
    # historical-inflow synthesizer from running, because the exception
    # bubbled out of the stage. The historical path is pure-function
    # over case.transfers (no network), so it can and SHOULD run even
    # when the dormant detector fails. This keeps the V-CFI01-shape
    # case (7+ months after incident, no current balances) producing
    # complete freeze_asks output even on a flaky Etherscan day.
    candidates: list = []
    try:
        candidates = find_dormant_in_case(
            case=case, config=config, env=env, min_usd=min_usd,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "freeze_asks: find_dormant_in_case failed (%s) — proceeding "
            "with empty current-balance set; historical-inflow path "
            "will still run", exc,
        )
    matched, _unmatched = match_freeze_asks(
        candidates, min_holding_usd=min_holding_usd,
    )

    # v0.16.0: ALSO run the historical-inflow synthesizer. The CLI's
    # `recupero list-freeze-targets` has done this since v0.14.8, but
    # the worker pipeline (which is the path real investigations take)
    # was never updated. Result: cases where the perp had moved funds
    # off the seed wallet between incident and Recupero engagement
    # produced freeze_asks.json with only the current-balance dormants
    # — a structurally incomplete set that routes the classifier into
    # the unrecoverable variant even when freezable history exists.
    #
    # Merge logic mirrors cli.py:594-618: exclude addresses already in
    # the current-balance matched list (avoid duplicates), append the
    # historical asks, re-sort by USD descending so the highest-value
    # asks come first in by_issuer enumeration.
    exclude_addrs = {a.candidate_address.lower() for a in matched}
    try:
        historical_asks = synthesize_historical_freeze_asks(
            case,
            min_inflow_usd=historical_min_inflow_usd,
            exclude_addresses=exclude_addrs,
        )
    except Exception as exc:  # noqa: BLE001
        # The synthesizer is pure-function — a failure here is
        # genuinely unexpected (logic bug, malformed transfer record).
        # Log + proceed with empty rather than aborting the whole
        # freeze_asks emission.
        log.warning(
            "freeze_asks: synthesize_historical_freeze_asks raised (%s) — "
            "proceeding with current-balance asks only", exc,
        )
        historical_asks = []
    if historical_asks:
        log.info(
            "freeze_asks: +%d historical-inflow ask(s) from %d transfer(s) "
            "(merging with %d current-balance ask(s))",
            len(historical_asks), len(case.transfers), len(matched),
        )
    matched = matched + historical_asks
    matched.sort(
        key=lambda a: a.holding_usd_value or Decimal("0"),
        reverse=True,
    )
    grouped = group_by_issuer(matched) if matched else {}

    label_store = LabelStore.load(config)
    # v0.16.1: same defensive wrapping for the exchange-deposit detector.
    # Pure-function over case.transfers + label seeds; failure here
    # would be a logic bug, but log + continue rather than aborting
    # the freeze_asks emission.
    exchange_deposits: list = []
    try:
        exchange_deposits = detect_exchange_deposits(
            case=case,
            label_store=label_store,
            min_deposit_usd=min_holding_usd,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "freeze_asks: detect_exchange_deposits raised (%s) — "
            "proceeding without exchange-deposit section", exc,
        )

    # v0.16.0: ALSO synthesize onward-CEX flows in the worker. The CLI
    # has done this since v0.14.10, but the worker (production path)
    # never wrote `onward_cex_flows` to freeze_asks.json, which means
    # the v0.14.11 exchange-subpoena renderer had no input data when
    # invoked from worker-built cases. Result: an operator running
    # `recupero legal-requests <case> --type exchange-subpoena` on a
    # worker-built case got "No documents generated" even when the
    # trace clearly contained freezable-target → CEX flows.
    onward_flows: list = []
    if matched:
        from recupero.freeze.asks import synthesize_onward_cex_subpoenas
        upstream_addrs = {a.candidate_address for a in matched}
        try:
            onward_flows = synthesize_onward_cex_subpoenas(
                case,
                upstream_freeze_target_addresses=upstream_addrs,
                label_store=label_store,
                min_flow_usd=min_holding_usd,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "freeze_asks: synthesize_onward_cex_subpoenas raised "
                "(%s) — exchange-subpoena rendering will have no input",
                exc,
            )
        if onward_flows:
            log.info(
                "freeze_asks: +%d onward-CEX flow(s) from freeze-target "
                "addresses to CEX deposits", len(onward_flows),
            )

    payload = {
        "case_id": case_id_str,
        "total_asks": len(matched),
        "by_issuer": {
            issuer: [
                {
                    "address": a.candidate_address,
                    "chain": a.chain.value,
                    "symbol": a.holding_symbol,
                    "amount": str(a.holding_decimal_amount),
                    "usd_value": str(a.holding_usd_value) if a.holding_usd_value else None,
                    "primary_contact": a.issuer.primary_contact,
                    "freeze_capability": a.issuer.freeze_capability,
                    "explorer_url": a.explorer_url,
                    # v0.16.0: propagate evidence_type + observed-at +
                    # observed-transfer-count from the FreezeAsk record. The
                    # AI editorial + freeze-letter templates branch on
                    # evidence_type ("current_balance" vs "historical_inflow"),
                    # and emit_brief uses observed_transfer_count to set the
                    # FREEZABLE-vs-INVESTIGATE status. Without these fields the
                    # downstream consumers default to "current_balance" for
                    # everything, which loses the historical-inflow signal.
                    "evidence_type": a.evidence_type,
                    "observed_at": a.observed_at_iso,
                    "observed_transfer_count": a.observed_transfer_count,
                }
                for a in asks
            ]
            for issuer, asks in grouped.items()
        },
        "exchange_deposits": [
            {
                "address": d.candidate_address,
                "chain": d.chain.value,
                "exchange": d.exchange,
                "label_name": d.label_name,
                "label_category": d.label_category,
                "label_confidence": d.label_confidence,
                "total_deposited_usd": str(d.total_deposited_usd),
                "deposit_count": d.deposit_count,
                "first_deposit_at": d.first_deposit_at.isoformat() if d.first_deposit_at else None,
                "last_deposit_at": d.last_deposit_at.isoformat() if d.last_deposit_at else None,
                "explorer_url": d.explorer_url,
            }
            for d in exchange_deposits
        ],
        # v0.16.0: onward_cex_flows. Mirrors the CLI's freeze_asks.json
        # schema. Required input for v0.14.11 exchange-subpoena
        # rendering via `recupero legal-requests --type exchange-subpoena`.
        #
        # v0.16.1 (audit): guard datetime .isoformat() calls against
        # None. The OnwardCEXFlow dataclass types first/last_flow_at
        # as datetime (non-Optional) but the synthesizer sources them
        # from Transfer.block_time, which can be None in degraded
        # data paths. A None here would crash the whole payload write
        # (the surrounding try/except wraps the synthesizer call, not
        # the JSON serialization). Better: write null and let the
        # consumer handle it.
        "onward_cex_flows": [
            {
                "upstream_address": f.upstream_address,
                "cex_address": f.cex_address,
                "chain": f.chain.value,
                "exchange": f.exchange,
                "label_name": f.label_name,
                "label_category": f.label_category,
                "token_symbol": f.token_symbol,
                "flow_usd_value": str(f.flow_usd_value),
                "flow_amount_decimal": str(f.flow_amount_decimal),
                "transfer_count": f.transfer_count,
                "first_flow_at": (
                    f.first_flow_at.isoformat() if f.first_flow_at else None
                ),
                "last_flow_at": (
                    f.last_flow_at.isoformat() if f.last_flow_at else None
                ),
                "upstream_explorer_url": f.upstream_explorer_url,
                "cex_explorer_url": f.cex_explorer_url,
                "tx_hashes": f.tx_hashes,
            }
            for f in onward_flows
        ],
    }
    out_path = case_dir / "freeze_asks.json"
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    upload_case_dir(case_dir, bucket)


def _stage_ai_editorial(
    inv: Investigation,
    case_id_str: str,
    case_data: CaseData,
    local_store: CaseStore,
    case_dir: Path,
    bucket: SupabaseCaseStore,
) -> Decimal | None:
    """Run editorial drafting, return USD cost from this call (None on failure)."""
    from recupero.reports.ai_editorial import run_ai_editorial

    # Build a pre-fill map from the cases row. The drafting stage uses
    # this to replace TODO placeholders for fields the operator already
    # provided at intake (address_line1/2, jurisdiction, ic3_case_id).
    # Empty / None values fall through to the existing TODO behavior so
    # the review form still prompts for them on pre-PR-#12 rows.
    case_row_prefill: dict[str, str] = {}
    if case_data.address_line1:
        case_row_prefill["VICTIM_ADDRESS_LINE1"] = case_data.address_line1
    if case_data.address_line2:
        case_row_prefill["VICTIM_ADDRESS_LINE2"] = case_data.address_line2
    if case_data.jurisdiction:
        case_row_prefill["VICTIM_JURISDICTION"] = case_data.jurisdiction
    if case_data.ic3_case_id:
        case_row_prefill["IC3_CASE_ID"] = case_data.ic3_case_id

    _path, _editorial, usage = run_ai_editorial(
        case_id=case_id_str,
        case_store=local_store,
        victim_narrative=case_data.description,
        case_row_prefill=case_row_prefill,
        # api_key falls through to ANTHROPIC_API_KEY env var
    )
    upload_case_dir(case_dir, bucket)
    cost = usage.get("usd_cost") if usage else None
    if cost is not None:
        log.info(
            "ai_editorial usage: %d in / %d out tokens, $%s",
            usage.get("input_tokens", 0), usage.get("output_tokens", 0), cost,
        )
    return cost


def _stage_emit_brief(
    inv: Investigation,
    case_id_str: str,
    local_store: CaseStore,
    case_dir: Path,
    bucket: SupabaseCaseStore,
) -> None:
    from recupero.reports.emit_brief import run_emit_brief

    run_emit_brief(case_id=case_id_str, case_store=local_store)
    upload_case_dir(case_dir, bucket)


def _synthesize_freeze_brief_from_asks(
    case_dir: Path, bucket: SupabaseCaseStore,
) -> None:
    """Write a minimal freeze_brief.json directly from freeze_asks.json
    — used on skip_editorial paths where emit_brief can't run because
    there's no editorial document.

    Output shape matches what trace_report._build_freezable_table
    reads from FREEZABLE (issuer/token/freeze_capability/holdings).
    No narrative prose; no TOTAL_LOSS_USD / MAX_RECOVERABLE_USD
    aggregates beyond what's directly computable from the asks.
    """
    freeze_asks_path = case_dir / "freeze_asks.json"
    out_path = case_dir / "freeze_brief.json"
    if not freeze_asks_path.exists():
        # No freeze asks emitted (the freeze stage produced nothing).
        # Still write a stub so downstream code sees a valid file.
        out_path.write_text(
            json.dumps({"FREEZABLE": [], "DESTINATIONS": [],
                        "TOTAL_LOSS_USD": "$0", "MAX_RECOVERABLE_USD": "$0"},
                       indent=2),
            encoding="utf-8",
        )
        upload_case_dir(case_dir, bucket)
        return

    asks = json.loads(freeze_asks_path.read_text(encoding="utf-8-sig"))
    by_issuer = asks.get("by_issuer") or {}

    freezable: list[dict[str, Any]] = []
    total_recoverable = Decimal(0)
    total_suspected = Decimal(0)
    # v0.16.1 (internal audit): same yes/limited/no → HIGH/MEDIUM/LOW
    # mapping that emit_brief.py:538 uses for the main path. Previously
    # this fallback hardcoded "HIGH" for every entry, which silently
    # tagged DAI / wstETH / other non-freezable tokens as HIGH-freezable
    # in any skip_editorial run — defeating downstream consumers
    # (flow_diagram, investigator_findings, recovery scorer) that
    # branch on the capability value.
    _CAP_DISPLAY = {"yes": "HIGH", "limited": "MEDIUM", "no": "LOW"}
    for issuer, entries in by_issuer.items():
        if not entries:
            continue
        # Group holdings under one entry per issuer/token pair so the
        # trace_report's table groups cleanly.
        by_token: dict[str, dict[str, Any]] = {}
        for e in entries:
            symbol = e.get("symbol") or "TOKEN"
            usd_str = e.get("usd_value")
            try:
                usd = Decimal(usd_str) if usd_str else Decimal(0)
            except (TypeError, ValueError):
                usd = Decimal(0)
            if usd > 0:
                total_recoverable += usd
            total_suspected += usd
            # Read the actual capability from the ask, mapping to the
            # display form for parity with emit_brief.py's main path.
            cap_raw = (e.get("freeze_capability") or "").lower()
            cap_display = _CAP_DISPLAY.get(cap_raw, "UNKNOWN")
            token_entry = by_token.setdefault(symbol, {
                "issuer": issuer,
                "token": symbol,
                "freeze_capability": cap_display,
                "holdings": [],
                "total_usd": Decimal(0),
            })
            # v0.16.1 (audit): status now keys off evidence_type, not
            # just the USD amount. Historical-inflow asks carry the
            # INFLOW USD in `usd_value`, which is NOT the current
            # balance — tagging them as 'FREEZABLE' caused customer
            # letters to claim "$X currently held" when the funds had
            # actually moved on. Now historical-inflow → 'INVESTIGATE'
            # so the letter / brief language reflects "issuer is asked
            # to investigate and freeze if balances remain" rather
            # than "freeze the $X currently sitting there".
            # Also: non-freezable issuers (cap=no/low) get 'UNRECOVERABLE'
            # rather than 'FREEZABLE' even with current balance.
            evidence_type = (e.get("evidence_type") or "current_balance").lower()
            if cap_raw in ("no", "low"):
                status = "UNRECOVERABLE"
            elif evidence_type == "historical_inflow":
                status = "INVESTIGATE"
            elif usd > 1000:
                status = "FREEZABLE"
            else:
                status = "INVESTIGATE"
            token_entry["holdings"].append({
                "address": e.get("address"),
                "amount": (
                    f"{e.get('amount', '?')} {symbol}"
                    if e.get("amount") else "?"
                ),
                "usd": f"${usd:,.2f}" if usd > 0 else "$0",
                "status": status,
                # Propagate evidence-type provenance into the brief
                # so downstream templates can render the right phrase
                # ("currently holds" vs "received during the trace").
                "evidence_type": evidence_type,
                "observed_at": e.get("observed_at"),
                "observed_transfer_count": e.get("observed_transfer_count", 1),
            })
            token_entry["total_usd"] += usd
        for token_entry in by_token.values():
            token_entry["total_usd"] = f"${token_entry['total_usd']:,.2f}"
            freezable.append(token_entry)

    out = {
        "FREEZABLE": freezable,
        "DESTINATIONS": asks.get("exchange_deposits") or [],
        "TOTAL_LOSS_USD": f"${total_suspected:,.2f}",
        "MAX_RECOVERABLE_USD": f"${total_recoverable:,.2f}",
        "SOURCE": "synthesized from freeze_asks.json (skip_editorial path)",
    }
    out_path.write_text(json.dumps(out, indent=2, default=str),
                        encoding="utf-8")
    upload_case_dir(case_dir, bucket)
    log.info("synthesized freeze_brief.json for skip_editorial path: "
             "%d freezable issuer(s)", len(freezable))


def _stage_build_package(
    inv: Investigation,
    case_id_str: str,
    local_store: CaseStore,
    case_dir: Path,
    bucket: SupabaseCaseStore,
) -> None:
    """Generate per-issuer freeze briefs + LE handoff HTMLs and sync.

    Implements the worker side of the contract's ``building_package``
    state. Reads case.json + victim.json + freeze_brief.json from the
    local case_dir (already populated by prior stages), invokes the
    Jinja-based brief generator once per unique issuer in FREEZABLE,
    writes outputs to case_dir/briefs/, and uploads to the bucket.

    No exceptions caught here — any failure marks the row failed at
    stage='building_package', surfaced via the admin UI.
    """
    from recupero.reports.victim import VictimInfo, load_victim
    from recupero.worker._deliverables import build_all_deliverables

    case = local_store.read_case(case_id_str)

    # Victim may be absent on wallet-trace investigations (case_id=NULL).
    # We construct a synthetic placeholder so downstream code that expects
    # a VictimInfo (template renders, brief builder) doesn't need branching
    # — the trace_report template doesn't render victim fields anyway and
    # the freeze-letter renderer is skipped on this path.
    victim_path = case_dir / "victim.json"
    if victim_path.exists():
        victim = load_victim(case_dir)
    else:
        victim = VictimInfo(
            name=inv.label or "Wallet trace (no case)",
            wallet_address=inv.seed_address,
        )

    # freeze_brief.json may be a thin no-FREEZABLE shell on
    # skip-editorial wallet traces — emit_brief still writes it for
    # the freezable-issuer summary used by the trace report.
    freeze_brief_path = case_dir / "freeze_brief.json"
    if freeze_brief_path.exists():
        freeze_brief = json.loads(freeze_brief_path.read_text(encoding="utf-8-sig"))
    else:
        freeze_brief = {"FREEZABLE": [], "TOTAL_LOSS_USD": "$0",
                        "MAX_RECOVERABLE_USD": "$0", "DESTINATIONS": []}

    written = build_all_deliverables(
        case=case,
        victim=victim,
        freeze_brief=freeze_brief,
        case_dir=case_dir,
        # Pipeline forwards the row's skip flags so the deliverables
        # builder can omit freeze letters / LE handoffs on
        # wallet-trace runs while still emitting the trace_report.
        skip_freeze_briefs=inv.skip_freeze_briefs,
        investigation_id=str(inv.id),
        label=inv.label,
    )
    log.info("building_package wrote %d deliverable file(s)", len(written))

    # Wipe the bucket's briefs/ subdir before uploading fresh artifacts.
    # Each re-run produces new BRIEF-<timestamp> IDs, so without cleanup
    # we accumulate ~74 brief artifacts per investigation across 14+
    # re-runs (real production case e917ffc5 hit this). Customer-facing
    # admin UI showing "74 freeze letters" for what should be ~4 is
    # the actual operational pain. See docs/CUSTOMER_DRY_RUN_2026-05-15.md.
    #
    # Scoped to briefs/ only — root-level case.json, manifest.json, etc.
    # get upserted by upload_case_dir below and don't accumulate.
    #
    # Cleanup failure is non-fatal: log + continue. The new run's
    # artifacts still upload; stale artifacts persist for one more
    # cycle until the next successful cleanup. This matches our
    # "be defensive at storage boundaries" pattern from upload_case_dir
    # itself (PayloadTooLargeError handling).
    try:
        deleted = bucket.delete_under("briefs")
        if deleted:
            log.info("building_package: cleaned %d stale brief(s) from bucket", deleted)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "building_package: brief cleanup failed (continuing with upload): %s",
            exc,
        )

    upload_case_dir(case_dir, bucket)


# ----- Helpers ----- #


def _maybe_run_pass2(
    *,
    inv: Investigation,
    case_id_str: str,
    cfg: RecuperoConfig,
    env: RecuperoEnv,
    local_store: CaseStore,
    case_dir: Path,
    bucket: SupabaseCaseStore,
) -> None:
    """Pass-2 perpetrator-forward trace orchestration (v0.8.0).

    Runs after the pass-1 trace + freeze-target enumeration
    completes. Reads freeze_brief.json + case.json, identifies
    hub candidates via the heuristic in
    recupero.trace.perpetrator_trace, runs one pass-2 trace per
    candidate (capped at 3), then merges the results back into
    case.json so emit_brief sees the expanded destination set.

    Best-effort: any failure logs a warning + the investigation
    proceeds with pass-1 only. The phase=1 trace is the
    durable artifact; pass-2 augments it.
    """
    from recupero.trace.perpetrator_trace import (
        identify_pass2_candidates,
        is_pass2_enabled,
        merge_perpetrator_findings,
        run_perpetrator_trace,
    )
    if not is_pass2_enabled():
        log.info("pass2 skipped: RECUPERO_DISABLE_PASS2=1")
        return

    # Need case.json to identify candidates. freeze_brief.json is
    # additionally required at deeper stages (see worker hooks); the
    # initial existence check is just on case.json.
    case_path = case_dir / "case.json"
    if not case_path.exists():
        log.info("pass2 skipped: case.json missing (pass-1 didn't run)")
        return

    # freeze_brief.json doesn't exist YET at this point in the
    # pipeline — it's produced by the emitting stage which runs
    # AFTER editorial. What we actually have is freeze_asks.json
    # (produced by the freeze-listing stage that just ran).
    # Use that as the candidate source. freeze_asks has the
    # FREEZABLE entries already populated with holdings.
    freeze_asks_path = case_dir / "freeze_asks.json"
    if not freeze_asks_path.exists():
        log.info("pass2 skipped: freeze_asks.json missing")
        return

    try:
        case = local_store.read_case(case_id_str)
        freeze_asks = json.loads(
            freeze_asks_path.read_text(encoding="utf-8-sig"),
        )
        candidates = identify_pass2_candidates(case, freeze_asks)
    except Exception as exc:  # noqa: BLE001
        log.warning("pass2 candidate identification failed: %s", exc)
        return

    if not candidates:
        log.info("pass2: no qualifying candidates (no hub > "
                 "ratio + balance thresholds)")
        return

    log.info(
        "pass2: %d candidate(s) identified — running pass-2 traces",
        len(candidates),
    )

    pass2_cases: list[Case] = []
    for cand in candidates:
        try:
            pass2_case = run_perpetrator_trace(
                chain=cand.chain,
                hub_address=cand.address,
                incident_time=inv.incident_time,
                parent_case_id=case_id_str,
                config=cfg,
                env=env,
                case_dir=case_dir,
            )
            pass2_cases.append(pass2_case)
            log.info(
                "pass2: trace from hub=%s yielded %d transfers, %d "
                "distinct destinations",
                cand.address, len(pass2_case.transfers),
                len({t.to_address.lower() for t in pass2_case.transfers}),
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "pass2 trace from %s failed: %s — continuing with "
                "remaining candidates", cand.address, exc,
            )

    if not pass2_cases:
        log.info("pass2: all candidate traces failed; pass-1 result preserved")
        return

    # Merge findings + overwrite case.json with the expanded view.
    try:
        merged = merge_perpetrator_findings(case, pass2_cases)
        local_store.write_case(merged)
        log.info(
            "pass2: merged %d pass-2 trace(s) into case.json — "
            "transfer count %d → %d",
            len(pass2_cases), len(case.transfers), len(merged.transfers),
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("pass2 merge failed: %s — pass-1 result preserved", exc)
        return

    # Re-run freeze-target enumeration on the merged case so the
    # new pass-2 destinations get classified + their freezable
    # holdings populated in freeze_asks.json before editorial
    # drafting sees them.
    try:
        _stage_list_freeze_targets(
            inv, case_id_str, cfg, env, local_store, case_dir, bucket,
        )
        log.info("pass2: freeze-target re-enumeration complete")
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "pass2: freeze re-enum failed (%s); pass-2 destinations "
            "in case.json but not classified — editorial will still "
            "see them via case.json", exc,
        )


def _populate_watchlist(
    inv: Investigation,
    local_store: CaseStore,
    case_dir: Path,
    db: WorkerDB,
) -> None:
    """Best-effort watchlist insert. Errors logged, never propagated.

    Reads the just-produced ``case.json`` + ``freeze_asks.json`` and
    upserts one row per non-victim wallet into ``public.watchlist``.
    """
    from recupero.worker.watchlist import populate_from_case
    try:
        case = local_store.read_case(str(inv.id))
        freeze_asks_path = case_dir / "freeze_asks.json"
        if freeze_asks_path.exists():
            freeze_asks = json.loads(freeze_asks_path.read_text(encoding="utf-8-sig"))
        else:
            freeze_asks = {}
        n = populate_from_case(
            dsn=db.dsn,
            case=case,
            freeze_asks=freeze_asks,
            investigation_id=inv.id,
            case_id=inv.case_id,
        )
        log.info("watchlist populated: %d row(s) for inv=%s", n, inv.id)
    except Exception as e:  # noqa: BLE001
        log.warning("watchlist population failed for inv=%s: %s", inv.id, e)


class _StageFailure(Exception):
    """Tagged exception so we can record the stage name on DB failure."""

    def __init__(self, stage: str, message: str) -> None:
        super().__init__(f"[{stage}] {message}")
        self.stage = stage
        self.message = message


def _run_stage(
    db: WorkerDB,
    inv_id: UUID,
    stage: str,
    fn,
) -> Any:
    """Transition DB → stage, run fn(), return whatever fn() returns.

    Lets exceptions propagate as _StageFailure tagged with the current stage.
    """
    db.transition(inv_id, status=stage)
    try:
        return fn()
    except _StageFailure:
        raise
    except Exception as e:  # noqa: BLE001
        raise _StageFailure(stage, f"{type(e).__name__}: {e}") from e


@contextmanager
def _local_case_dir(
    config: RecuperoConfig,
    case_id: str,
) -> Iterator[tuple[CaseStore, Path]]:
    """Yield (CaseStore, case_dir) rooted in a fresh tempdir.

    The CaseStore is configured with data_dir pointing at the tempdir, so
    every pipeline write lands inside it. Cleanup happens on context exit.
    """
    tmp = Path(tempfile.mkdtemp(prefix="recupero-worker-"))
    try:
        # Shallow-copy the config and override storage.data_dir
        local_cfg = config.model_copy(deep=True)
        local_cfg.storage.data_dir = str(tmp)
        local_store = CaseStore(local_cfg)
        case_dir = local_store.case_dir(case_id)
        yield local_store, case_dir
    finally:
        # Best-effort recursive cleanup. Worker shouldn't crash on temp dir
        # cleanup failures (e.g., locked log file on Windows).
        try:
            _rmtree(tmp)
        except Exception as e:  # noqa: BLE001
            log.warning("could not clean up tempdir %s: %s", tmp, e)


def _rmtree(path: Path) -> None:
    if not path.exists():
        return
    if path.is_file() or path.is_symlink():
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    for child in path.iterdir():
        _rmtree(child)
    try:
        path.rmdir()
    except OSError:
        # Some Windows scenarios leave a handle open briefly; ignore.
        pass


def _write_victim_from_case(
    case_dir: Path,
    inv: Investigation,
    case_data: CaseData,
) -> None:
    """Materialize victim.json from the joined cases row.

    Required-on-VictimInfo fields (`name`, `wallet_address`) get safe
    defaults so downstream code doesn't crash on unset cases.
    """
    victim = VictimInfo(
        name=case_data.client_name or "[victim name not set]",
        wallet_address=inv.seed_address,
        email=case_data.client_email,
        phone=case_data.phone,
        citizenship=case_data.country,
        incident_summary=case_data.description,
    )
    write_victim(case_dir, victim)


def _summarize_brief(brief_path: Path) -> dict[str, Any]:
    """Extract the headline numbers from freeze_brief.json for the
    investigations row's summary columns.

    Returns a dict with keys total_loss_usd / max_recoverable_usd /
    freezable_issuers, all optional. Best-effort: if the brief file is
    missing or malformed we just return empty values so the worker still
    marks the row completed.
    """
    out: dict[str, Any] = {
        "total_loss_usd": None,
        "max_recoverable_usd": None,
        "freezable_issuers": None,
    }
    try:
        brief = json.loads(brief_path.read_text(encoding="utf-8-sig"))
    except (FileNotFoundError, ValueError) as e:
        log.warning("could not summarize %s: %s", brief_path, e)
        return out

    out["total_loss_usd"] = _parse_usd(brief.get("TOTAL_LOSS_USD"))
    out["max_recoverable_usd"] = _parse_usd(brief.get("MAX_RECOVERABLE_USD"))
    issuers = sorted({
        f.get("issuer") for f in brief.get("FREEZABLE", []) if f.get("issuer")
    })
    out["freezable_issuers"] = issuers or None
    return out


def _parse_usd(s: Any) -> Decimal | None:
    """'$1,234.56' → Decimal('1234.56'). Returns None on garbage input."""
    if s is None:
        return None
    try:
        cleaned = str(s).replace("$", "").replace(",", "").strip()
        if not cleaned:
            return None
        return Decimal(cleaned)
    except Exception:  # noqa: BLE001
        return None


def _hydrate_local_from_bucket(
    store: SupabaseCaseStore,
    case_dir: Path,
    filenames: list[str],
) -> None:
    """Pull a few files from the bucket into ``case_dir`` so a downstream
    stage can read them. Used on resume."""
    case_dir.mkdir(parents=True, exist_ok=True)
    for name in filenames:
        try:
            if name.endswith(".json"):
                data = store.read_json(name)
                (case_dir / name).write_text(
                    json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8",
                )
            else:
                text = store.read_text(name)
                (case_dir / name).write_text(text, encoding="utf-8")
        except FileNotFoundError:
            log.warning("expected %s in bucket on resume but it was missing", name)
