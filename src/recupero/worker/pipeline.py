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
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterator
from uuid import UUID

from recupero.config import RecuperoConfig, RecuperoEnv
from recupero.reports.victim import VictimInfo, write_victim
from recupero.storage.case_store import CaseStore
from recupero.storage.supabase_case_store import SupabaseCaseStore
from recupero.worker import state as S
from recupero.worker.db import CaseData, Investigation, WorkerDB
from recupero.worker.sync import download_editorial, upload_case_dir

log = logging.getLogger(__name__)


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

    # Local Case.case_id is the investigation UUID — keeps local case_dir,
    # bucket prefix, and trace artifacts in lockstep.
    case_id_str = str(inv.id)

    # Apply per-investigation config overrides if the row provided them.
    cfg = config.model_copy(deep=True)
    if inv.max_depth and inv.max_depth > 0:
        cfg.trace.max_depth = int(inv.max_depth)
    if inv.dust_threshold_usd is not None:
        cfg.trace.dust_threshold_usd = float(inv.dust_threshold_usd)

    # Pull the cases row for victim info + narrative.
    case_data = db.fetch_case(inv.case_id)
    if case_data is None:
        # Don't crash silently — surface the FK referent missing so it
        # can be triaged from the admin UI.
        db.mark_failed(inv.id, stage="setup",
                       error=f"cases row {inv.case_id} not found (FK violation)")
        return

    api_costs_usd: Decimal | None = None

    try:
        with _local_case_dir(cfg, case_id_str) as (local_store, case_dir):
            # Always seed victim.json — idempotent, cheap.
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

            # Editorial stage ----------------------------------------------
            if not has_editorial:
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
            _run_stage(
                db, inv.id, S.EMITTING,
                lambda: _stage_emit_brief(inv, case_id_str, local_store, case_dir, store),
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
    if inv.chain == "hyperliquid":
        from recupero.chains.hyperliquid.scraper import scrape_hyperliquid_case
        case = scrape_hyperliquid_case(
            user_address=inv.seed_address,
            case_id=case_id_str,
            incident_time=inv.incident_time,
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
            incident_time=inv.incident_time,
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
    from recupero.freeze.asks import detect_exchange_deposits
    from recupero.labels.store import LabelStore

    case = local_store.read_case(case_id_str)

    min_usd = Decimal("10000")
    min_holding_usd = Decimal("1000")

    candidates = find_dormant_in_case(
        case=case, config=config, env=env, min_usd=min_usd,
    )
    matched, _unmatched = match_freeze_asks(
        candidates, min_holding_usd=min_holding_usd,
    )
    grouped = group_by_issuer(matched) if matched else {}

    label_store = LabelStore.load(config)
    exchange_deposits = detect_exchange_deposits(
        case=case,
        label_store=label_store,
        min_deposit_usd=min_holding_usd,
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

    _path, _editorial, usage = run_ai_editorial(
        case_id=case_id_str,
        case_store=local_store,
        victim_narrative=case_data.description,
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
    from recupero.reports.victim import load_victim
    from recupero.worker._deliverables import build_all_deliverables

    case = local_store.read_case(case_id_str)
    victim = load_victim(case_dir)
    freeze_brief_path = case_dir / "freeze_brief.json"
    freeze_brief = json.loads(freeze_brief_path.read_text(encoding="utf-8-sig"))

    written = build_all_deliverables(
        case=case,
        victim=victim,
        freeze_brief=freeze_brief,
        case_dir=case_dir,
    )
    log.info("building_package wrote %d deliverable file(s)", len(written))
    upload_case_dir(case_dir, bucket)


# ----- Helpers ----- #


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
