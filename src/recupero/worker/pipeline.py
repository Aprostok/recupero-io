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
from collections.abc import Callable, Iterator
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
# Re-export the brief schema version for callers that reach for it
# via the worker module. Canonical definition lives in reports.brief.
from recupero.reports.brief import BRIEF_SCHEMA_VERSION  # noqa: F401

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

    v0.17.4 (round-10 audit MED): non-EVM coverage extended.
    Solana base58 sentinels (all-1 system program, all-A vanity,
    11111... incinerator), Tron T-prefix repeating-fill, and
    Bitcoin all-1 bech32 are now detected so non-EVM placeholder
    submissions also fail fast before burning AI budget.
    """
    if not addr:
        return False
    if addr.startswith("0x"):
        body = addr[2:].lower()
        if len(body) != 40:
            return False
        # All same character — zero / max / repeating filler addresses.
        if len(set(body)) == 1:
            return True
        # Cycling-digit pattern. Try cycle lengths that divide 40 evenly.
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
        return body in _KNOWN_SENTINELS

    # Non-EVM detection (v0.17.4).
    # Solana addresses are 32-44 chars base58; Tron is 34 chars T-prefix
    # base58. Repeating-character / Solana system program sentinels are
    # the common placeholder shapes operators paste.
    _NON_EVM_PLACEHOLDERS = {
        # Solana system program — operators sometimes paste as "Solana
        # null address". Real cases reaching this address would be
        # genuine system-program interactions, not theft destinations.
        "11111111111111111111111111111111",
        # Solana incinerator program (burn).
        "1nc1nerator11111111111111111111111111111111",
    }
    if addr in _NON_EVM_PLACEHOLDERS:
        return True
    # All-same-character placeholder (e.g., "AAAAA..." Solana vanity).
    # Bitcoin bech32 "bc1q" + all-q is impractical but check.
    return bool(len(addr) >= 25 and len(set(addr)) <= 2)


# ----- Public entry point ----- #


def run_one(
    inv: Investigation,
    *,
    config: RecuperoConfig,
    env: RecuperoEnv,
    db: WorkerDB,
    store: SupabaseCaseStore,
    stop_heartbeat: Callable[[], None] | None = None,
) -> None:
    """Drive one investigation forward as far as it can go.

    Catches all exceptions per stage and marks the row failed with the
    stage name + error text. Returns cleanly on review_required (worker
    drops the row; a future claim resumes after the UI approves).

    v0.16.13 (round-9 worker ARCH): the optional ``stop_heartbeat``
    callable is invoked IMMEDIATELY BEFORE any final mark_* transition
    (mark_completed / mark_failed / mark_review_required). This
    eliminates the race where the heartbeat thread updates
    last_heartbeat_at AFTER mark_* clears worker_id, briefly making
    the row look "claimed but heartbeating" to the reaper. main.py
    passes the Heartbeat.stop() as this callable.

    v0.17.0 (observability): every log record emitted inside this
    function carries investigation_id + case_id + worker_id via the
    run_context contextvar — no per-call extra={} boilerplate needed.
    JSON-formatter consumers can filter Railway logs by these fields
    directly.
    """
    _stop_hb = stop_heartbeat or (lambda: None)
    from recupero.logging_setup import run_context

    with run_context(
        investigation_id=str(inv.id),
        case_id=str(inv.case_id) if inv.case_id else None,
        worker_id=db.worker_id,
    ):
        return _run_one_inner(
            inv, config=config, env=env, db=db, store=store,
            stop_heartbeat=_stop_hb,
        )


def _run_one_inner(
    inv: Investigation,
    *,
    config: RecuperoConfig,
    env: RecuperoEnv,
    db: WorkerDB,
    store: SupabaseCaseStore,
    stop_heartbeat: Callable[[], None],
) -> None:
    """Body of run_one, factored out so the public function can wrap
    every log record in the per-investigation context. See run_one
    docstring for behavior."""
    _stop_hb = stop_heartbeat
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
        _stop_hb()
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
            _stop_hb()
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

    # v0.17.4 (round-10 audit HIGH): track the "between-stage" phase so
    # the catch-all `except Exception` below can tag mark_failed with
    # something more actionable than stage="unknown". When the worker
    # blew up populating the watchlist or summarizing the freeze brief,
    # ops had no way to tell that from a tracer crash without reading
    # the full traceback. _run_stage already tags its own stage via
    # _StageFailure; this covers everything in between.
    _phase = "setup"

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

            # v0.17.4 (round-10 audit HIGH): pass-2 BEFORE watchlist.
            # Pre-v0.17.4 the watchlist was populated using only
            # pass-1 destinations, then pass-2 added new perp wallets
            # that NEVER entered the watchlist — defeating the whole
            # point of pass-2 (surface downstream destinations for
            # nightly monitoring).
            #
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

            # Watchlist population AFTER pass-2 so newly-discovered
            # downstream destinations enter monitoring. Best-effort.
            _phase = "watchlist"
            _populate_watchlist(inv, local_store, case_dir, db)

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
                # v0.17.4 (round-10 audit HIGH): persist api_costs_usd
                # BEFORE the status transition. Pre-v0.17.4, if the
                # mark_review_required UPDATE failed (transient DB
                # blip), the Anthropic spend was real but no audit
                # record survived — operators silently undercounted
                # AI costs. Now: dedicated record call first; status
                # transition is a separate operation.
                try:
                    db.record_api_cost(inv.id, api_costs_usd)
                except Exception as exc:  # noqa: BLE001
                    # Even this fails? Log loudly so monitoring catches it.
                    log.exception(
                        "investigation %s: FAILED to persist api_costs_usd=$%s "
                        "before review_required transition (anthropic spend "
                        "occurred but audit row is now incomplete): %s",
                        inv.id, api_costs_usd, exc,
                    )
                _stop_hb()
                # v0.18.1 (round-11 worker-CRIT-004): pass api_costs_usd=None
                # — record_api_cost above is the sole writer (it accumulates
                # via COALESCE+=). Passing the cumulative value here would
                # double-write on the same row.
                db.mark_review_required(inv.id, api_costs_usd=None)
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
                    _stop_hb()
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

            # v0.17.4 (round-10 audit HIGH): build_package FIRST, then
            # mark_built_package. Pre-v0.17.4 the summary columns
            # (total_loss_usd, max_recoverable_usd, freezable_issuers)
            # were committed BEFORE the deliverables were actually
            # built. If _stage_build_package then crashed, the row
            # ended up `failed` but with summary columns populated —
            # contradicting the contract that "those columns mean we
            # have artifacts." Also: this eliminates the prior double
            # DB transition to `building_package`.
            #
            # Run the package-building stage in the BUILDING_PACKAGE
            # state, then commit summary columns + transition to
            # complete only after artifacts exist.
            _phase = "summarize"
            summary = _summarize_brief(case_dir / "freeze_brief.json")
            _run_stage(
                db, inv.id, S.BUILDING_PACKAGE,
                lambda: _stage_build_package(inv, case_id_str,
                                             local_store, case_dir, store),
            )
            _phase = "finalize"
            _stop_hb()
            db.mark_built_package(
                inv.id,
                storage_path=store.storage_prefix,  # "investigations/<id>/" (with trailing /)
                total_loss_usd=summary.get("total_loss_usd"),
                max_recoverable_usd=summary.get("max_recoverable_usd"),
                freezable_issuers=summary.get("freezable_issuers"),
                # v0.18.1: api_costs_usd is recorded via record_api_cost
                # at editorial-stage exit; mark_built_package no longer
                # owns the column. Pass None so the column is preserved
                # via COALESCE on the DB side.
                api_costs_usd=None,
            )
            db.mark_completed(inv.id)
            log.info("investigation %s completed", inv.id)

    except _StageFailure as exc:
        log.exception("investigation %s failed at %s", inv.id, exc.stage)
        _stop_hb()
        db.mark_failed(inv.id, stage=exc.stage, error=exc.message)
    except Exception as exc:  # noqa: BLE001
        # v0.17.4 (round-10 audit HIGH): tag the phase (setup / watchlist /
        # summarize / finalize) instead of the bare "unknown" — gives ops
        # actionable info from the row alone without re-deriving from the
        # traceback. Genuinely unknown errors (none of the explicit phase
        # transitions fired) still surface as "unknown" because _phase
        # starts there.
        log.exception("investigation %s failed (%s): %s", inv.id, _phase, exc)
        _stop_hb()
        db.mark_failed(
            inv.id, stage=_phase, error=f"{type(exc).__name__}: {exc}",
        )


# ----- Stages ----- #


def _maybe_write_demix_leads(
    case: Case,
    case_dir: Path,
    config: RecuperoConfig,
    env: RecuperoEnv,
) -> None:
    """Mixer-demixing leads over the finished trace (Activation Sprint #4b).

    Wires the ``demix_runner`` (Sprint #4) into the live worker pipeline so a
    real case carries its same-pool withdrawal candidates instead of them being
    reachable only via the ``recupero-ops demix-leads`` CLI.

    Opt-in via ``RECUPERO_DEMIX_LEADS`` (default OFF). When off this is a no-op
    with ZERO cost — no adapter is constructed and no ``getLogs`` is issued.
    When on, for each transfer INTO a known Tornado pool we fetch that pool's
    ``Withdrawal`` events after the deposit and score them into ranked leads,
    written to ``demix_leads.json`` in the case dir (uploaded with the case).

    Forensic doctrine: a mixer cryptographically severs deposit<->withdrawal,
    so these are same-pool BEHAVIORAL candidates (address-reuse / relayer / gas
    / FIFO timing) for manual review — e.g. a subpoena target — ALWAYS
    low-confidence and NEVER a followed destination. Best-effort: any failure
    logs and the trace pipeline continues (a demixing nicety must never block a
    freeze letter).
    """
    from recupero.trace.demix_runner import demix_enabled

    if not demix_enabled():
        return  # default off → zero cost (no adapter, no getLogs)
    try:
        from recupero._common import atomic_write_text
        from recupero.chains.base import ChainAdapter
        from recupero.trace.demix_runner import leads_to_json, run_demix_leads

        adapter = ChainAdapter.for_chain(case.chain, (config, env))
        try:
            results = run_demix_leads(
                transfers=case.transfers,
                adapter=adapter,
                default_chain=case.chain.value,
            )
        finally:
            adapter.close()
        if not results:
            return
        doc = leads_to_json(results)
        atomic_write_text(
            case_dir / "demix_leads.json",
            json.dumps(doc, indent=2, ensure_ascii=False, allow_nan=False),
        )
        n_leads = sum(len(v) for v in results.values())
        log.info(
            "demix: wrote demix_leads.json (%d pool(s), %d lead(s)) for case %s",
            len(results), n_leads, getattr(case, "case_id", "?"),
        )
    except Exception as exc:  # noqa: BLE001 — best-effort, never block the trace
        log.warning("demix: lead generation failed (non-fatal): %s", exc)


def _maybe_write_nft_flows(
    case: Case,
    case_dir: Path,
    config: RecuperoConfig,
    env: RecuperoEnv,
) -> None:
    """Observed-NFT-flow artifact over the finished trace (roadmap-v4 #6 A).

    Opt-in via ``RECUPERO_NFT_FLOWS`` (default OFF → zero cost, no adapter).
    When on, each traced wallet's ERC-721/1155 transfers are fetched and
    written to ``nft_flows.json`` (uploaded with the case) so NFT-sale
    laundering / mint-and-flip moves stop vanishing from the case record.
    OBSERVATIONS only — no value claims, no followed recipients, recoverable
    total untouched. Best-effort: never blocks the trace pipeline.
    """
    from recupero.trace.nft_runner import nft_flows_enabled

    if not nft_flows_enabled():
        return  # default off → zero cost
    try:
        from recupero._common import atomic_write_text
        from recupero.chains.base import ChainAdapter
        from recupero.trace.nft_runner import collect_nft_flows, flows_to_json

        adapter = ChainAdapter.for_chain(case.chain, (config, env))
        try:
            flows = collect_nft_flows(
                transfers=case.transfers,
                adapter=adapter,
                chain=case.chain.value,
            )
        finally:
            adapter.close()
        if not flows:
            return
        doc = flows_to_json(flows)
        atomic_write_text(
            case_dir / "nft_flows.json",
            json.dumps(doc, indent=2, ensure_ascii=False, allow_nan=False),
        )
        log.info(
            "nft-flows: wrote nft_flows.json (%d flow(s)) for case %s",
            len(flows), getattr(case, "case_id", "?"),
        )
    except Exception as exc:  # noqa: BLE001 — best-effort, never block the trace
        log.warning("nft-flows: collection failed (non-fatal): %s", exc)


def _maybe_write_lp_leads(
    case: Case,
    case_dir: Path,
    config: RecuperoConfig,
    env: RecuperoEnv,
) -> None:
    """Uniswap V3 park-and-withdraw leads over the finished trace
    (roadmap-v4 #7 slice 1).

    Opt-in via ``RECUPERO_LP_LEADS`` (default OFF → zero cost). When on, each
    traced-wallet deposit into the verified NonfungiblePositionManager is
    resolved to its position tokenId (deposit receipt), and every later
    ``Collect`` on that SAME position — where the parked value actually
    exited — becomes a lead in ``lp_leads.json``. Position link = protocol
    identity (high); actor attribution medium unless the exit recipient is
    the parking wallet. Leads only — never a followed destination, the
    recoverable total untouched. Best-effort: never blocks the trace pipeline.
    """
    from recupero.trace.lp_runner import lp_leads_enabled

    if not lp_leads_enabled():
        return  # default off → zero cost
    try:
        from recupero._common import atomic_write_text
        from recupero.chains.base import ChainAdapter
        from recupero.trace.lp_runner import leads_to_json, run_lp_leads

        adapter = ChainAdapter.for_chain(case.chain, (config, env))
        try:
            leads = run_lp_leads(
                transfers=case.transfers,
                adapter=adapter,
                default_chain=case.chain.value,
            )
        finally:
            adapter.close()
        if not leads:
            return
        doc = leads_to_json(leads)
        atomic_write_text(
            case_dir / "lp_leads.json",
            json.dumps(doc, indent=2, ensure_ascii=False, allow_nan=False),
        )
        log.info(
            "lp-leads: wrote lp_leads.json (%d lead(s)) for case %s",
            len(leads), getattr(case, "case_id", "?"),
        )
    except Exception as exc:  # noqa: BLE001 — best-effort, never block the trace
        log.warning("lp-leads: lead generation failed (non-fatal): %s", exc)


def _maybe_write_lending_leads(
    case: Case,
    case_dir: Path,
    config: RecuperoConfig,
    env: RecuperoEnv,
) -> None:
    """Lending cross-address withdrawal leads over the finished trace
    (roadmap-v4 #11) -- Aave V3 + Compound III (Comet).

    Opt-in via ``RECUPERO_LENDING_LEADS`` (default OFF -> zero cost). When on,
    each traced wallet's Aave V3 (indexed-user) + Compound III Comet
    (indexed-src, pinned markets) ``Withdraw`` events are fetched and every
    CROSS-ADDRESS withdrawal -- the exit sent by the protocol contract,
    invisible to outflow enumeration -- becomes a lead in
    ``lending_leads.json``. Both addresses protocol-stamped (high).
    Leads only -- never a followed destination, the recoverable total
    untouched. Best-effort: never blocks the trace pipeline.
    """
    from recupero.trace.lending_runner import lending_leads_enabled

    if not lending_leads_enabled():
        return  # default off -> zero cost
    try:
        from recupero._common import atomic_write_text
        from recupero.chains.base import ChainAdapter
        from recupero.trace.lending_runner import leads_to_json, run_lending_leads

        adapter = ChainAdapter.for_chain(case.chain, (config, env))
        try:
            leads = run_lending_leads(
                transfers=case.transfers,
                adapter=adapter,
                default_chain=case.chain.value,
            )
        finally:
            adapter.close()
        if not leads:
            return
        doc = leads_to_json(leads)
        atomic_write_text(
            case_dir / "lending_leads.json",
            json.dumps(doc, indent=2, ensure_ascii=False, allow_nan=False),
        )
        log.info(
            "lending-leads: wrote lending_leads.json (%d lead(s)) for case %s",
            len(leads), getattr(case, "case_id", "?"),
        )
    except Exception as exc:  # noqa: BLE001 -- best-effort, never block the trace
        log.warning("lending-leads: lead generation failed (non-fatal): %s", exc)


def _maybe_write_vault_leads(
    case: Case,
    case_dir: Path,
    config: RecuperoConfig,
    env: RecuperoEnv,
) -> None:
    """ERC-4626 vault park-and-withdraw leads over the finished trace
    (roadmap-v4 #11 slice 2).

    Opt-in via ``RECUPERO_VAULT_LEADS`` (default OFF -> zero cost). When on,
    each traced wallet's ERC-4626 ``Withdraw`` events (owner = the wallet,
    across ALL vaults via one address-less owner-topic getLogs) where the
    receiver differs become leads in ``vault_leads.json``; a second getLogs
    for the wallet's Deposits confirms round-trips (-> high, else medium).
    Leads only -- never a followed destination, recoverable total untouched.
    Best-effort: never blocks the trace pipeline.
    """
    from recupero.trace.vault_runner import vault_leads_enabled

    if not vault_leads_enabled():
        return  # default off -> zero cost
    try:
        from recupero._common import atomic_write_text
        from recupero.chains.base import ChainAdapter
        from recupero.trace.vault_runner import leads_to_json, run_vault_leads

        adapter = ChainAdapter.for_chain(case.chain, (config, env))
        try:
            leads = run_vault_leads(
                transfers=case.transfers,
                adapter=adapter,
                default_chain=case.chain.value,
            )
        finally:
            adapter.close()
        if not leads:
            return
        doc = leads_to_json(leads)
        atomic_write_text(
            case_dir / "vault_leads.json",
            json.dumps(doc, indent=2, ensure_ascii=False, allow_nan=False),
        )
        log.info(
            "vault-leads: wrote vault_leads.json (%d lead(s)) for case %s",
            len(leads), getattr(case, "case_id", "?"),
        )
    except Exception as exc:  # noqa: BLE001 -- best-effort, never block the trace
        log.warning("vault-leads: lead generation failed (non-fatal): %s", exc)


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

    # v0.39 (Activation Sprint #4b): auto-run mixer-demixing leads over the
    # finished trace and persist demix_leads.json into the case dir (uploaded
    # below with the rest of the case). Gated by RECUPERO_DEMIX_LEADS — default
    # OFF means zero cost (no adapter, no getLogs); on means same-pool
    # withdrawal candidates ride along for a reviewer to triage into subpoena
    # targets. Best-effort: never blocks the trace pipeline.
    _maybe_write_demix_leads(case, case_dir, config, env)

    # roadmap-v4 #6 (phase A): observed-NFT-flow artifact. Gated by
    # RECUPERO_NFT_FLOWS (default off = zero cost); on means each traced
    # wallet's ERC-721/1155 transfers ride along as nft_flows.json —
    # observations only, no value claims, recoverable total untouched.
    _maybe_write_nft_flows(case, case_dir, config, env)

    # roadmap-v4 #7 (slice 1): Uniswap V3 park-and-withdraw leads. Gated by
    # RECUPERO_LP_LEADS (default off = zero cost); on means NPM deposits
    # resolve to position tokenIds and later Collect exits on the SAME
    # position ride along as lp_leads.json — position link is protocol
    # identity, leads never followed, recoverable total untouched.
    _maybe_write_lp_leads(case, case_dir, config, env)

    # roadmap-v4 #11 (slice 1): Aave V3 cross-address withdrawal leads.
    # Gated by RECUPERO_LENDING_LEADS (default off = zero cost); on means
    # traced wallets' Pool.withdraw(asset, amount, to!=self) exits ride
    # along as lending_leads.json -- protocol-stamped, never followed.
    _maybe_write_lending_leads(case, case_dir, config, env)

    # roadmap-v4 #11 (slice 2): ERC-4626 vault cross-address
    # withdrawal leads (Morpho/Yearn/Spark/any vault) -- gated by
    # RECUPERO_VAULT_LEADS (default off = zero cost).
    _maybe_write_vault_leads(case, case_dir, config, env)

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
    # Historical-inflow threshold is lower so addresses that received
    # freezable tokens but currently show $0 still surface. This is
    # the path that makes 7-months-after-the-fact cases produce
    # freeze letters at all.
    historical_min_inflow_usd = Decimal("1000")

    # Each network/IO call is wrapped so one failure can't take down
    # the whole stage. The historical-inflow synthesizer in particular
    # is pure-function over case.transfers (no network) — it should
    # run even when the dormant detector fails on a flaky Etherscan
    # day, otherwise V-CFI01-shape cases (no current balances, all
    # historical evidence) produce empty freeze_asks output.
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

    # Merge historical-inflow asks into the current-balance match list.
    # Exclude addresses already in matched to avoid duplicates; re-sort
    # by USD descending so highest-value asks come first.
    # v0.17.9 (round-10 forensic HIGH): canonical-key the exclusion set
    # so base58 candidate addresses don't lowercase-collide with each
    # other.
    from recupero._common import canonical_address_key as _ck
    exclude_addrs = {_ck(a.candidate_address) for a in matched}
    try:
        historical_asks = synthesize_historical_freeze_asks(
            case,
            min_inflow_usd=historical_min_inflow_usd,
            exclude_addresses=exclude_addrs,
        )
    except Exception as exc:  # noqa: BLE001
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
                    # v0.32.1 (JACOB_FREEZE_LETTER_AUDIT CRIT-FR-2 / CRIT-FR-4):
                    # surface the corporate legal name + freeze posture notes
                    # all the way from the seed DB through freeze_asks.json
                    # into the per-issuer freeze letter context. These end up
                    # in the FREEZABLE issuer dict (see _extract_freezable)
                    # and then in IssuerInfo, where the template can render
                    # the corporate legal-entity name in the "Addressed To"
                    # cover-meta row and quote the issuer-specific posture
                    # note in the new Section 6 (Freeze Posture).
                    "legal_name": a.issuer.legal_name,
                    "corporate_jurisdiction": a.issuer.corporate_jurisdiction,
                    "freeze_notes": a.issuer.freeze_notes,
                    "jurisdiction": a.issuer.jurisdiction,
                    # AI editorial + freeze-letter templates branch on
                    # evidence_type to choose between "freeze NOW" and
                    # "investigate" framing per-row.
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
        # onward_cex_flows is the input the v0.14.11 exchange-subpoena
        # renderer consumes. Datetime fields are guarded against None
        # because the underlying Transfer.block_time may be absent in
        # degraded data paths — emitting null is preferable to crashing
        # the whole payload write.
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
    # Atomic write — bucket uploader runs from a different thread/path
    # and must not pick up a half-written JSON.
    from recupero._common import atomic_write_text
    atomic_write_text(out_path, json.dumps(payload, indent=2, allow_nan=False, ensure_ascii=False))
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
    # v0.21.0: thread investigation_id + DSN through so emit_brief
    # can auto-subscribe perp wallets to live monitoring. The
    # subscriber module guards every DB op so a Supabase outage
    # cannot break brief emission.
    import os as _os

    from recupero.reports.emit_brief import run_emit_brief

    run_emit_brief(
        case_id=case_id_str,
        case_store=local_store,
        investigation_id=inv.id,
        dsn=_os.environ.get("SUPABASE_DB_URL", "").strip() or None,
    )
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
    from recupero._common import atomic_write_text
    freeze_asks_path = case_dir / "freeze_asks.json"
    out_path = case_dir / "freeze_brief.json"
    if not freeze_asks_path.exists():
        # No freeze asks emitted (the freeze stage produced nothing).
        # Write a stub so downstream code sees a valid file — stamped
        # with SCHEMA_VERSION so check_brief_schema_version doesn't
        # spuriously flag it as a "pre-v0.16.x" pipeline product.
        atomic_write_text(
            out_path,
            json.dumps({
                "SCHEMA_VERSION": BRIEF_SCHEMA_VERSION,
                "FREEZABLE": [],
                "DESTINATIONS": [],
                "TOTAL_LOSS_USD": "$0",
                "MAX_RECOVERABLE_USD": "$0",
                "SOURCE": "stub (freeze_asks.json missing — freeze stage produced no asks)",
            }, indent=2, allow_nan=False, ensure_ascii=False),
        )
        upload_case_dir(case_dir, bucket)
        return

    # Malformed freeze_asks.json must not kill the whole skip_editorial
    # path with a cryptic JSONDecodeError — emit a stub-shape brief
    # and log instead.
    try:
        asks = json.loads(freeze_asks_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "freeze_asks.json unreadable (%s) — emitting stub freeze_brief",
            exc,
        )
        atomic_write_text(
            out_path,
            json.dumps({
                "SCHEMA_VERSION": BRIEF_SCHEMA_VERSION,
                "FREEZABLE": [],
                "DESTINATIONS": [],
                "TOTAL_LOSS_USD": "$0",
                "MAX_RECOVERABLE_USD": "$0",
                "SOURCE": "stub (freeze_asks.json unreadable)",
            }, indent=2, allow_nan=False, ensure_ascii=False),
        )
        upload_case_dir(case_dir, bucket)
        return
    from recupero._common import (
        aggregate_evidence_mode_from_holdings,
        capability_display,
    )

    by_issuer = asks.get("by_issuer") or {}

    freezable: list[dict[str, Any]] = []
    total_recoverable = Decimal(0)
    total_suspected = Decimal(0)
    for issuer, entries in by_issuer.items():
        if not entries:
            continue
        # Group holdings under one entry per issuer/token pair so the
        # trace_report table groups cleanly. Collect a per-issuer
        # primary_contact upfront so send-freeze-letters can dispatch
        # off a skip_editorial brief.
        by_token: dict[str, dict[str, Any]] = {}
        issuer_primary_contact: str | None = None
        for e in entries:
            pc = e.get("primary_contact")
            if pc and issuer_primary_contact is None:
                issuer_primary_contact = pc
                break
        for e in entries:
            symbol = e.get("symbol") or "TOKEN"
            usd_str = e.get("usd_value")
            try:
                usd = Decimal(usd_str) if usd_str else Decimal(0)
            except (TypeError, ValueError):
                usd = Decimal(0)
            # v0.20.2 (audit-round-2 finding #2): `total_suspected`
            # accumulation moved BELOW status classification so it
            # tracks INVESTIGATE-only USD, matching emit_brief's
            # TOTAL_SUSPECTED_USD convention. Pre-v0.20.2 this summed
            # every holding's USD regardless of status, conflating
            # freezable + investigative + unrecoverable into the
            # top-level "suspected" headline.
            cap_raw = (e.get("freeze_capability") or "").lower()
            cap_display = capability_display(cap_raw)
            token_entry = by_token.setdefault(symbol, {
                "issuer": issuer,
                "token": symbol,
                "freeze_capability": cap_display,
                "holdings": [],
                "total_usd": Decimal(0),
                "contact_email": issuer_primary_contact or "",
                "primary_contact": issuer_primary_contact or "",
                "portal_url": "",
                "typical_response_time": "Variable",
                "freeze_note": "",
                # v0.32.1 (JACOB_FREEZE_LETTER_AUDIT CRIT-FR-2 / CRIT-FR-4):
                # mirror the main emit_brief path so the synthesizer path
                # also carries legal-entity name + posture notes through
                # to the FREEZABLE list. Pull-through from the first entry
                # carrying the field. Pre-v0.32.1 a skip_editorial run
                # silently dropped these and the freeze letter rendered
                # bare "Tether" / "Circle" again.
                "legal_name": (
                    e.get("legal_name")
                    if isinstance(e.get("legal_name"), str)
                    and e.get("legal_name").strip() else None
                ),
                "corporate_jurisdiction": (
                    e.get("corporate_jurisdiction")
                    if isinstance(e.get("corporate_jurisdiction"), str)
                    and e.get("corporate_jurisdiction").strip() else None
                ),
                "freeze_notes": (
                    e.get("freeze_notes")
                    if isinstance(e.get("freeze_notes"), str)
                    and e.get("freeze_notes").strip() else None
                ),
                "issuer_jurisdiction": (
                    e.get("jurisdiction")
                    if isinstance(e.get("jurisdiction"), str)
                    and e.get("jurisdiction").strip() else None
                ),
            })
            # Status policy (mirrors emit_brief._extract_freezable):
            #   * capability=no/low                 → TRACKED (v0.34.4: identified
            #       + still holds value but not freezable today → monitor for
            #       movement, recoverable later; NOT written off as UNRECOVERABLE)
            #   * usd > $1K (dust line)             → FREEZABLE
            #   * sub-dust                          → INVESTIGATE
            # historical_inflow at a freezable issuer stays FREEZABLE;
            # the letter template uses evidence_type per-row to choose
            # "received at" vs "currently holds" phrasing. Downgrading
            # historical_inflow to INVESTIGATE zeroes per-issuer
            # total_usd and breaks the classifier — don't.
            evidence_type = (e.get("evidence_type") or "current_balance").lower()
            if cap_raw in ("no", "low"):
                status = "TRACKED"
            elif usd > 1000:
                status = "FREEZABLE"
            else:
                status = "INVESTIGATE"
            # total_recoverable only includes FREEZABLE — TRACKED rows (e.g.,
            # DAI: identified, monitored, not freezable TODAY) must NOT
            # contribute to MAX_RECOVERABLE_USD (they're recoverable LATER, not
            # now), same as the old UNRECOVERABLE handling.
            if status == "FREEZABLE" and usd > 0:
                total_recoverable += usd
            # v0.20.2 (audit-round-2 finding #2): top-level
            # TOTAL_SUSPECTED_USD is the sum of INVESTIGATE-status
            # holdings only — same convention as emit_brief.py.
            if status == "INVESTIGATE" and usd > 0:
                total_suspected += usd
            token_entry["holdings"].append({
                "address": e.get("address"),
                # v0.17.4 (round-10 audit HIGH): preserve per-holding
                # chain so explorer URLs render against the correct
                # explorer for cross-chain freezable destinations.
                "chain": e.get("chain"),
                "amount": (
                    f"{e.get('amount', '?')} {symbol}"
                    if e.get("amount") else "?"
                ),
                "usd": f"${usd:,.2f}" if usd > 0 else "$0",
                "status": status,
                "evidence_type": evidence_type,
                "observed_at": e.get("observed_at"),
                "observed_transfer_count": e.get("observed_transfer_count", 1),
            })
            token_entry["total_usd"] += usd
        for token_entry in by_token.values():
            # Aggregate per-issuer evidence_mode so customer / engagement
            # / issuer letter templates branch on the right "currently
            # held" vs "received at" phrasing.
            n_historical = sum(
                1 for h in token_entry["holdings"]
                if h.get("evidence_type") == "historical_inflow"
            )
            n_current = len(token_entry["holdings"]) - n_historical
            token_entry["evidence_mode"] = aggregate_evidence_mode_from_holdings(
                token_entry["holdings"],
            )
            token_entry["historical_count"] = n_historical
            token_entry["current_balance_count"] = n_current
            # Earliest historical observation across holdings, mirrors
            # emit_brief.py's main path.
            earliest: str | None = None
            for h in token_entry["holdings"]:
                obs = h.get("observed_at")
                if not obs:
                    continue
                if earliest is None or obs < earliest:
                    earliest = obs
            token_entry["earliest_observed"] = earliest
            # v0.20.2 (audit-round-2 finding #2): match emit_brief.py's
            # canonical bucket convention exactly — buckets are mutually
            # exclusive (each holding lands in one and only one):
            #   total_usd           = FREEZABLE-status sum
            #   total_suspected_usd = INVESTIGATE-status sum
            #   total_excluded_usd  = UNRECOVERABLE / EXCHANGE / TRANSIT / UNKNOWN
            # Pre-v0.20.2 this bucketed FREEZABLE+INVESTIGATE into
            # `suspected_only`, double-counting FREEZABLE holdings on
            # the skip-editorial path and inflating the engagement
            # letter's "Under Investigation" total by ~20x in the
            # V-CFI01 case shape (FREEZABLE-heavy / INVESTIGATE-thin).
            freezable_only = Decimal(0)
            suspected_only = Decimal(0)
            excluded_only = Decimal(0)
            for h in token_entry["holdings"]:
                try:
                    h_usd = Decimal(
                        str(h.get("usd", "0"))
                        .replace("$", "").replace(",", "") or "0"
                    )
                except Exception:  # noqa: BLE001
                    h_usd = Decimal(0)
                h_status = h.get("status")
                if h_status == "FREEZABLE":
                    freezable_only += h_usd
                elif h_status == "INVESTIGATE":
                    suspected_only += h_usd
                else:
                    excluded_only += h_usd
            token_entry["total_usd"] = f"${freezable_only:,.2f}"
            token_entry["total_suspected_usd"] = f"${suspected_only:,.2f}"
            # Schema parity with emit_brief: include total_excluded_usd
            # so consumers reading either writer get the same shape.
            token_entry["total_excluded_usd"] = f"${excluded_only:,.2f}"
            freezable.append(token_entry)

    # Skip_editorial path has no rich destination data (that comes from
    # emit_brief._extract_destinations which needs the trace). Empty
    # DESTINATIONS list is the schema-correct value here.
    #
    # v0.19.2 (round-13 code-quality #6): TOTAL_LOSS_USD on this path
    # is intentionally $0 — the skip-editorial path is a wallet-trace /
    # R&D run without a victim, so "loss" has no meaning. Pre-v0.19.2
    # we wrote `f"${total_suspected:,.2f}"` here, but `total_suspected`
    # is the sum-across-all-asks (perp wallets' current holdings,
    # possibly from other victims) — emit_brief enforces the distinction
    # between "loss" (drained from victim) and "suspected" (held in
    # perp wallets). Writing one as the other misframed the wallet-
    # trace brief's headline number. The actionable figure on this
    # path is `MAX_RECOVERABLE_USD` (already populated correctly).
    out = {
        "SCHEMA_VERSION": BRIEF_SCHEMA_VERSION,
        "FREEZABLE": freezable,
        "DESTINATIONS": [],
        "TOTAL_LOSS_USD": "$0.00",
        "TOTAL_SUSPECTED_USD": f"${total_suspected:,.2f}",
        "MAX_RECOVERABLE_USD": f"${total_recoverable:,.2f}",
        "SOURCE": "synthesized from freeze_asks.json (skip_editorial path)",
    }
    atomic_write_text(out_path, json.dumps(out, indent=2, default=str, allow_nan=False, ensure_ascii=False))
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
        # Stale-brief detection: pre-v0.14.8 briefs lack evidence_mode
        # fields the templates branch on. Warning only — rendering
        # still happens, just with degraded language for historical
        # cases.
        from recupero.reports.brief import check_brief_schema_version
        stale_warning = check_brief_schema_version(freeze_brief)
        if stale_warning:
            log.warning(
                "freeze_brief.json at %s is stale: %s",
                freeze_brief_path, stale_warning,
            )
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
        # v0.18.4 (round-11 worker-HIGH-007): retry with backoff so
        # a transient DB hiccup doesn't permanently silently drop
        # watchlist rows. Pre-v0.18.4 a single failure logged a
        # warning and moved on — on the resumed pass `has_case` /
        # `has_freeze` / `has_editorial` are all True so this is
        # never re-attempted. Now: 3 attempts with 1s/3s backoff,
        # then surface as a stage failure (so the row goes to
        # failed/needs-attention rather than silently complete with
        # missing nightly monitoring).
        import time as _time
        attempts = 3
        last_exc: Exception | None = None
        for attempt in range(attempts):
            try:
                n = populate_from_case(
                    dsn=db.dsn,
                    case=case,
                    freeze_asks=freeze_asks,
                    investigation_id=inv.id,
                    case_id=inv.case_id,
                )
                log.info("watchlist populated: %d row(s) for inv=%s", n, inv.id)
                return
            except Exception as e:  # noqa: BLE001
                last_exc = e
                if attempt + 1 < attempts:
                    _time.sleep(1.0 if attempt == 0 else 3.0)
                    log.warning(
                        "watchlist population attempt %d/%d failed for inv=%s: %s — retrying",
                        attempt + 1, attempts, inv.id, e,
                    )
        log.error(
            "watchlist population FAILED after %d attempts for inv=%s: %s — "
            "monitoring coverage incomplete; rerun manually with "
            "`recupero-ops repopulate-watchlist %s`",
            attempts, inv.id, last_exc, inv.id,
        )
    except Exception as e:  # noqa: BLE001
        # Top-level except for non-retry-loop errors (case load,
        # freeze_asks parse, etc.).
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

    v0.16.11 (round-9 worker ARCH): structured stage-boundary logging.
    v0.17.0 (observability): also records Prometheus stage-duration
    histogram + stage-runs counter via observability.metrics.
    """
    import time as _time
    extra = {"investigation_id": str(inv_id), "stage": stage}
    db.transition(inv_id, status=stage)
    log.info("stage start: %s", stage, extra=extra)
    started = _time.monotonic()
    try:
        result = fn()
    except _StageFailure as exc:
        elapsed = _time.monotonic() - started
        log.error(
            "stage fail: %s after %.1fs: %s",
            stage, elapsed, exc.message,
            extra={**extra, "duration_sec": round(elapsed, 2), "outcome": "fail"},
        )
        _record_stage_metric(stage, elapsed, "fail")
        raise
    except Exception as e:  # noqa: BLE001
        elapsed = _time.monotonic() - started
        log.exception(
            "stage fail: %s after %.1fs: unhandled %s",
            stage, elapsed, type(e).__name__,
            extra={**extra, "duration_sec": round(elapsed, 2), "outcome": "fail"},
        )
        _record_stage_metric(stage, elapsed, "fail")
        raise _StageFailure(stage, f"{type(e).__name__}: {e}") from e
    else:
        elapsed = _time.monotonic() - started
        log.info(
            "stage end: %s in %.1fs",
            stage, elapsed,
            extra={**extra, "duration_sec": round(elapsed, 2), "outcome": "ok"},
        )
        _record_stage_metric(stage, elapsed, "ok")
        return result


def _record_stage_metric(stage: str, elapsed_sec: float, outcome: str) -> None:
    """Best-effort metrics dispatch. Never propagates failures —
    observability is a non-fatal add-on."""
    try:
        from recupero.observability.metrics import record_stage_duration
        record_stage_duration(stage, elapsed_sec, outcome=outcome)
    except Exception:  # noqa: BLE001
        pass


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
        # v0.18.4 (round-11 worker-HIGH-011 + arch-MED-017): use
        # shutil.rmtree(ignore_errors=True). Pre-v0.18.4 a hand-rolled
        # `_rmtree` recursed and `except OSError: pass`'d on rmdir
        # failures — over weeks of operation on Windows (locked log
        # files) and Linux (rare permission issues) the bare-except
        # silently leaked tempdirs that accumulated in %TEMP% / /tmp,
        # eventually exhausting disk. shutil.rmtree with ignore_errors
        # handles retries / Windows handle-release more gracefully and
        # is the canonical stdlib API for this exact use case.
        import shutil
        try:
            shutil.rmtree(tmp, ignore_errors=True)
            # Detect leak: if the dir still exists after ignore_errors,
            # surface it so ops can sweep manually before disk fills.
            if tmp.exists():
                log.warning(
                    "tempdir %s persists after shutil.rmtree(ignore_errors=True) — "
                    "likely Windows file-handle leak; manual cleanup recommended",
                    tmp,
                )
        except Exception as e:  # noqa: BLE001
            # shutil.rmtree(ignore_errors=True) shouldn't raise but be defensive.
            log.warning("tempdir cleanup unexpectedly raised: %s — %s", tmp, e)


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
    # State-machine audit #5: an entry in FREEZABLE[] is the per-issuer
    # grouping that aggregates ALL of that issuer's holdings — including
    # INVESTIGATE (sub-dust / suspected-only) and UNRECOVERABLE (no
    # freeze authority, e.g. Lido staking). Promoting such an issuer to
    # the investigations.freezable_issuers column mislabels it as a
    # confirmed freeze target on the admin dashboard and in the LE
    # handoff. Only count an issuer when at least one of its holdings
    # is genuinely status="FREEZABLE".
    issuers_set: set[str] = set()
    for f in brief.get("FREEZABLE", []) or []:
        if not isinstance(f, dict):
            continue
        issuer = f.get("issuer")
        if not issuer:
            continue
        holdings = f.get("holdings") or []
        if not isinstance(holdings, list):
            continue
        if any(
            isinstance(h, dict)
            and str(h.get("status") or "").upper() == "FREEZABLE"
            for h in holdings
        ):
            issuers_set.add(issuer)
    issuers = sorted(issuers_set)
    out["freezable_issuers"] = issuers or None
    return out


def _parse_usd(s: Any) -> Decimal | None:
    """'$1,234.56' → Decimal('1234.56'). Returns None on garbage input.

    RIGOR-Jacob Z5-2: rejects non-finite Decimals (NaN, Infinity,
    -Infinity). Python's ``Decimal("NaN")`` / ``Decimal("Infinity")``
    parses successfully, and a freeze_brief.json carrying ``"$NaN"`` /
    ``"$Infinity"`` (e.g. from upstream pricing corruption) would
    otherwise propagate through ``mark_built_package`` into the
    ``investigations.total_loss_usd`` column and silently corrupt every
    downstream aggregation that sums or compares that column.
    """
    if s is None:
        return None
    try:
        cleaned = str(s).replace("$", "").replace(",", "").strip()
        if not cleaned:
            return None
        value = Decimal(cleaned)
    except Exception:  # noqa: BLE001
        return None
    if not value.is_finite():
        return None
    return value


def _hydrate_local_from_bucket(
    store: SupabaseCaseStore,
    case_dir: Path,
    filenames: list[str],
) -> None:
    """Pull a few files from the bucket into ``case_dir`` so a downstream
    stage can read them. Used on resume.

    v0.17.4 (round-10 audit CRIT): writes are now atomic via
    `atomic_write_text` (tempfile + os.replace). Pre-v0.17.4 a worker
    crash mid-`write_text` left a TRUNCATED case.json that the next
    stage parsed without complaint — running editorial against an
    empty trace, then emitting an empty brief, then shipping a hollow
    PDF to LE. Now: bucket downloads either land in full or not at all.
    """
    from recupero._common import atomic_write_text
    case_dir.mkdir(parents=True, exist_ok=True)
    for name in filenames:
        try:
            if name.endswith(".json"):
                data = store.read_json(name)
                atomic_write_text(
                    case_dir / name,
                    json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False),
                )
            else:
                text = store.read_text(name)
                atomic_write_text(case_dir / name, text)
        except FileNotFoundError:
            log.warning("expected %s in bucket on resume but it was missing", name)
