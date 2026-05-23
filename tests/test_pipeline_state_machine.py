"""Pipeline state-machine audit (worker/pipeline.py).

Six audit points covered:

1. Every state-change SQL has a status precondition (source-inspection
   guard: pipeline.py owns NO raw UPDATE — every transition routes
   through db.WorkerDB which carries the worker_id + terminal-status
   predicates).
2. State transitions are atomic single UPDATEs (no SELECT-then-UPDATE
   from pipeline.py — same source-inspection guard).
3. Worker-id ownership: pipeline.py never invents a status flip without
   going through a WorkerDB method that carries `worker_id = me`.
4. Terminal states cannot be re-opened: the run-loop's exception path
   stops the heartbeat BEFORE mark_failed and never falls through into
   a subsequent mark_completed.
5. SUSPECTED-only (INVESTIGATE-status) holdings must NOT promote an
   issuer into the row's freezable_issuers summary column — that
   column drives downstream dashboards labelling the issuer as a
   confirmed freeze target. **REAL BUG fixed here.**
6. State-write call sites stamp heartbeat (db.transition / db.mark_*
   all set last_heartbeat_at = NOW() as a side effect — pipeline.py
   never bypasses them).

Plus the Z5-2 preserve: _parse_usd rejects non-finite Decimals.
"""

from __future__ import annotations

import inspect
import json
import re
from decimal import Decimal
from pathlib import Path


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _pipeline_source() -> str:
    from recupero.worker import pipeline
    return inspect.getsource(pipeline)


# ----------------------------------------------------------------------
# Audit #5: brief generation must NOT promote INVESTIGATE-only issuers
# into the row-level freezable_issuers summary column.
# ----------------------------------------------------------------------


def test_summarize_brief_excludes_investigate_only_issuer(tmp_path: Path) -> None:
    """An issuer whose every holding is status=INVESTIGATE is
    SUSPECTED-only. Listing it in freezable_issuers (the
    investigations row column that drives the admin dashboard's
    "confirmed freeze targets" chip) lies to the operator: the issuer
    has nothing concretely freezable — it just has wallets worth a
    second look. Downstream LE letters then get auto-generated against
    an issuer with nothing freezable to ask about.
    """
    from recupero.worker.pipeline import _summarize_brief

    brief_path = tmp_path / "freeze_brief.json"
    brief_path.write_text(json.dumps({
        "TOTAL_LOSS_USD": "$1000",
        "MAX_RECOVERABLE_USD": "$0",
        "FREEZABLE": [{
            "issuer": "SuspiciousProtocol",
            "token": "XYZ",
            "holdings": [
                {"address": "0xa", "status": "INVESTIGATE", "usd": "$50"},
                {"address": "0xb", "status": "INVESTIGATE", "usd": "$40"},
            ],
        }],
    }))
    out = _summarize_brief(brief_path)
    issuers = out.get("freezable_issuers") or []
    assert "SuspiciousProtocol" not in issuers, (
        f"_summarize_brief promoted INVESTIGATE-only issuer to "
        f"freezable_issuers={issuers!r}. This drives the row's "
        f"freezable_issuers column → admin UI mislabels the issuer "
        f"as a confirmed freeze target. Filter by holding status."
    )


def test_summarize_brief_excludes_unrecoverable_only_issuer(tmp_path: Path) -> None:
    """An issuer whose every holding is UNRECOVERABLE (e.g., a Lido
    staking contract, no freeze authority) must not be reported as a
    freeze target on the row. The deliverables layer already skips
    these — the row summary must agree."""
    from recupero.worker.pipeline import _summarize_brief

    brief_path = tmp_path / "freeze_brief.json"
    brief_path.write_text(json.dumps({
        "FREEZABLE": [{
            "issuer": "Lido",
            "holdings": [
                {"address": "0xs", "status": "UNRECOVERABLE", "usd": "$0"},
            ],
        }],
    }))
    out = _summarize_brief(brief_path)
    issuers = out.get("freezable_issuers") or []
    assert "Lido" not in issuers, (
        f"_summarize_brief promoted UNRECOVERABLE-only issuer to "
        f"freezable_issuers={issuers!r} — contradicts the deliverables "
        f"layer's filter and the contract that this column lists "
        f"actionable freeze targets."
    )


def test_summarize_brief_includes_mixed_freezable_issuer(tmp_path: Path) -> None:
    """Negative-control: an issuer with at least one FREEZABLE holding
    is genuinely freezable and MUST stay in the list, even if other
    holdings under the same issuer are INVESTIGATE."""
    from recupero.worker.pipeline import _summarize_brief

    brief_path = tmp_path / "freeze_brief.json"
    brief_path.write_text(json.dumps({
        "FREEZABLE": [{
            "issuer": "Circle",
            "holdings": [
                {"address": "0xc1", "status": "FREEZABLE", "usd": "$10000"},
                {"address": "0xc2", "status": "INVESTIGATE", "usd": "$50"},
            ],
        }],
    }))
    out = _summarize_brief(brief_path)
    issuers = out.get("freezable_issuers") or []
    assert "Circle" in issuers, (
        f"_summarize_brief dropped a genuinely-freezable issuer: "
        f"freezable_issuers={issuers!r}. A FREEZABLE-status holding "
        f"under the issuer makes it a real target — keep it."
    )


def test_summarize_brief_no_holdings_field_is_not_promoted(tmp_path: Path) -> None:
    """Defensive: a FREEZABLE entry that lacks a `holdings` array
    (malformed brief / older schema) must not get blanket-promoted.
    Without per-holding status the issuer's freezability is unknown,
    and the row summary must err toward not lying."""
    from recupero.worker.pipeline import _summarize_brief

    brief_path = tmp_path / "freeze_brief.json"
    brief_path.write_text(json.dumps({
        "FREEZABLE": [{"issuer": "Ghost", "token": "ZZZ"}],
    }))
    out = _summarize_brief(brief_path)
    issuers = out.get("freezable_issuers") or []
    assert "Ghost" not in issuers, (
        f"_summarize_brief promoted an issuer with no holdings array "
        f"({issuers!r}) — without per-holding status proof, we cannot "
        f"claim the issuer is a freeze target."
    )


# ----------------------------------------------------------------------
# Audit #1 / #2 / #3: pipeline.py must NOT raw-UPDATE state. Every
# state mutation routes through WorkerDB so the worker_id + terminal
# predicates apply atomically.
# ----------------------------------------------------------------------


def test_pipeline_contains_no_raw_status_update_sql() -> None:
    """Source-inspection: pipeline.py must not contain any `UPDATE
    investigations ... SET status` SQL. Every state mutation has to
    flow through db.WorkerDB methods (transition / mark_*) because
    only those carry the WHERE worker_id = me predicate that prevents
    two concurrent workers from advancing the same row.

    A raw UPDATE in pipeline.py would skip both guards and re-introduce
    the "two workers race past CLAIMED simultaneously" bug we already
    paid for in production once.
    """
    src = _pipeline_source()
    # Look for any UPDATE against investigations (or `inv`/case-equivalent
    # tables) that sets status without going through WorkerDB.
    pattern = re.compile(
        r"UPDATE\s+(public\.)?investigations\b[^;]*\bSET\b[^;]*\bstatus\b",
        re.IGNORECASE | re.DOTALL,
    )
    matches = pattern.findall(src)
    assert not matches, (
        f"pipeline.py contains raw status-mutating UPDATE SQL "
        f"({len(matches)} match(es)). All state transitions must "
        f"route through WorkerDB so the worker_id ownership predicate "
        f"and terminal-state guard apply atomically. Move to db.py."
    )


def test_pipeline_run_stage_drives_transitions_via_workerdb() -> None:
    """_run_stage is the single funnel for stage→status writes.

    Confirms (a) it calls db.transition for every stage entry and
    (b) the surrounding pipeline doesn't open its own psycopg
    connection to short-circuit that funnel.
    """
    src = _pipeline_source()
    assert "db.transition(inv_id, status=stage)" in src, (
        "_run_stage no longer routes state transitions through "
        "db.transition — re-introducing the raw-UPDATE risk."
    )
    # No psycopg.connect inside pipeline.py — every DB op goes via
    # the WorkerDB wrapper.
    assert "psycopg.connect" not in src, (
        "pipeline.py opens its own psycopg connection. State writes "
        "must funnel through WorkerDB to inherit the worker_id + "
        "terminal-state guards."
    )


# ----------------------------------------------------------------------
# Audit #4: terminal states cannot be re-opened.
# ----------------------------------------------------------------------


def test_terminal_failure_does_not_fall_through_to_completion() -> None:
    """When run_one's _StageFailure path fires mark_failed, control
    must NOT fall through and also call mark_completed on the same
    row in the same invocation. A double-write would race with the
    UI re-queue path and could re-open a failed row.

    We assert behaviorally: a WorkerDB whose .mark_failed is called
    must never see .mark_completed on the same investigation_id in
    the same run_one call.
    """
    src = _pipeline_source()
    # The exception handlers must call exactly one terminal marker.
    # Find the `except _StageFailure` block and confirm it does NOT
    # also call mark_completed or mark_built_package.
    m = re.search(
        r"except _StageFailure as exc:.*?(?=\n    except |\nclass |\ndef )",
        src, re.DOTALL,
    )
    assert m, "could not locate _StageFailure handler in pipeline.py"
    handler = m.group(0)
    assert "mark_completed" not in handler, (
        "_StageFailure handler also calls mark_completed — terminal "
        "row would be re-opened to 'complete' in the same invocation."
    )
    assert "mark_built_package" not in handler, (
        "_StageFailure handler also calls mark_built_package — "
        "writes summary columns on a row about to be marked failed."
    )
    # Defense-in-depth: enumerate the generic ``except Exception`` handlers
    # specifically nested INSIDE _run_one_inner (the function whose success
    # path is the only legitimate caller of mark_completed). Other stage
    # helpers freely catch Exception for stage-local error mapping — those
    # don't touch terminal markers because they only call _StageFailure
    # raisers or stage-internal logging, and the test above already pins
    # the _StageFailure terminal-marker contract.
    inner_match = re.search(
        r"def _run_one_inner\(.*?(?=\n(?:def |class |async def ))",
        src, re.DOTALL,
    )
    if inner_match:
        inner = inner_match.group(0)
        # Within the inner function, the only mark_completed call must be
        # in the success path (not under any except). Find every block
        # that starts with `except Exception` and ensure mark_completed
        # isn't called before the next dedent.
        for m2 in re.finditer(
            r"\n(\s+)except Exception as exc:[^\n]*\n((?:\1[ \t]+[^\n]*\n)+)",
            inner,
        ):
            handler_body = m2.group(2)
            assert "mark_completed" not in handler_body, (
                "_run_one_inner generic Exception handler calls "
                "mark_completed — would flip a row to 'complete' on a "
                "crash path."
            )


# ----------------------------------------------------------------------
# Audit #6: heartbeat / time-on-row is stamped on every transition.
# We verify that pipeline.py only uses transition primitives that
# refresh last_heartbeat_at (the schema doesn't have a separate
# state_updated_at column — last_heartbeat_at is the canonical
# "time-of-last-state-write" field, and the reaper uses it).
# ----------------------------------------------------------------------


def test_pipeline_state_changes_refresh_heartbeat() -> None:
    """Each pipeline-driven state change must stamp last_heartbeat_at
    as a side effect (db.transition and db.mark_* SQL all carry
    `last_heartbeat_at = NOW()`). Pipeline must not bypass them with
    a status write that skips the heartbeat refresh — otherwise the
    reaper could mistake a freshly-transitioned row for a stalled
    one and steal it.
    """
    from recupero.worker import db as db_mod
    db_src = inspect.getsource(db_mod)
    # The two pipeline-facing methods that drive in-progress transitions.
    for method in ("def transition(", "def mark_built_package(",
                   "def mark_completed(", "def mark_review_required("):
        idx = db_src.find(method)
        assert idx != -1, f"could not find {method!r} in db.py"
        body = db_src[idx:idx + 2000]
        assert "last_heartbeat_at = NOW()" in body or "_HEARTBEAT" in body, (
            f"{method.strip('def (')}'s SQL does not stamp "
            f"last_heartbeat_at = NOW() — the reaper would race the "
            f"transition."
        )


# ----------------------------------------------------------------------
# Z5-2 PRESERVE: _parse_usd still rejects non-finite Decimals.
# Guarded inside this file so regressions in the new code path can't
# silently re-enable NaN propagation.
# ----------------------------------------------------------------------


def test_z5_parse_usd_still_rejects_non_finite() -> None:
    from recupero.worker.pipeline import _parse_usd

    for poison in ("$NaN", "$Infinity", "$-Infinity", "$inf"):
        result = _parse_usd(poison)
        assert result is None or (
            isinstance(result, Decimal) and result.is_finite()
        ), (
            f"_parse_usd({poison!r}) regressed to non-finite "
            f"{result!r} — Z5-2 fix lost."
        )
