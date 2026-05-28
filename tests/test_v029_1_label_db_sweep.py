"""v0.29.1 Recommendations #6 + #7 — label DB sweep + confidence decay.

Two contracts pinned by this file:

  1. **Chain-field presence on every list-shape seed file.** Pre-v0.29.1
     cex_deposits / defi_protocols / mixers had ZERO chain-field
     tagging; an ad-hoc query "what's our coverage on chain X?" would
     have returned 0 for ALL of them. The v0.29.1 backfill ran via
     scripts/_v029_1_label_db_sweep.py; this test pins the result.

  2. **Confidence-decay budget.** Recommendation #6 says rows with
     confidence='high' and a stale `last_verified_at` (> 90 days)
     should auto-downgrade. Implementing the auto-downgrade is a
     larger refactor (changes the LabelStore lookup contract); the
     v0.29.1 starter is a TEST that the high-confidence count of
     stale entries stays under a budget. As entries are re-verified
     via WebFetch + `last_verified_at` updated, the test naturally
     stays green. When new high-confidence entries land without a
     fresh `last_verified_at`, the budget tightens — gating drift
     by visibility, not by a destructive auto-mutation.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest


_SEEDS = Path(__file__).parent.parent / "src" / "recupero" / "labels" / "seeds"

# Files where v0.29.1 backfilled the chain field. The bridges.json
# case is covered by the separate matrix test; here we pin the rest.
LIST_FILES = ["cex_deposits.json", "defi_protocols.json", "mixers.json"]


def _load(path: Path) -> list[dict]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [e for e in raw if isinstance(e, dict) and "address" in e]


@pytest.mark.parametrize("filename", LIST_FILES)
def test_every_label_entry_has_chain_field(filename: str) -> None:
    """Every cex_deposits / defi_protocols / mixers entry MUST carry
    an explicit `chain`. The v0.29.1 backfill set it to "ethereum"
    everywhere (the implicit pre-v0.29.1 default); future
    multi-chain additions supply their own value.

    Recommendation #7 contract."""
    entries = _load(_SEEDS / filename)
    missing: list[str] = []
    for e in entries:
        chain = e.get("chain")
        if not isinstance(chain, str) or not chain.strip():
            missing.append(f"{e.get('name', '(no name)')} ({e.get('address')})")
    assert not missing, (
        f"{filename}: entries missing explicit `chain` field — these "
        f"are invisible to chain-coverage queries:\n  "
        + "\n  ".join(missing)
    )


def test_chain_values_in_known_chain_enum() -> None:
    """Every chain value across the list-shape seed files must
    resolve to a member of recupero.models.Chain. A typo'd
    `chain: "etherem"` would otherwise silently fall through and
    create a permanent invisible coverage gap."""
    from recupero.models import Chain
    allowed = {c.value for c in Chain}
    offenders: list[str] = []
    for fname in LIST_FILES + ["bridges.json"]:
        for entry in _load(_SEEDS / fname):
            chain = entry.get("chain")
            if isinstance(chain, str) and chain.strip() and chain not in allowed:
                offenders.append(
                    f"{fname}: {entry.get('name')} ({entry.get('address')}) — "
                    f"chain={chain!r} not in Chain enum"
                )
    assert not offenders, (
        "Seed entries with chain values outside Chain enum:\n  "
        + "\n  ".join(offenders)
    )


# ──────────────────────────────────────────────────────────────────────
# Confidence-decay contract (Recommendation #6).
# ──────────────────────────────────────────────────────────────────────


_DECAY_DAYS = 90


def _is_stale(verified_at: str | None, today: datetime) -> bool:
    """A row with confidence='high' is STALE if either:
      * `last_verified_at` is missing, OR
      * `last_verified_at` is older than _DECAY_DAYS ago.

    Pre-v0.29.1 the field didn't exist anywhere; the v0.29.0
    additions carry it as part of the externally_verified_v029
    audit-status marker, but we treat missing-field as stale by
    design — that's the lever that pushes the team to fill it in
    on every PR.
    """
    if not isinstance(verified_at, str) or not verified_at.strip():
        return True
    try:
        # Strip trailing Z for fromisoformat compat.
        cleaned = verified_at.rstrip("Z").rstrip("z")
        if "+" not in cleaned and "T" in cleaned:
            cleaned = cleaned + "+00:00"
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return True
    age_days = (today - dt).total_seconds() / 86_400
    return age_days > _DECAY_DAYS


def test_high_confidence_stale_entry_budget() -> None:
    """Track the count of `confidence: high` entries with stale
    or missing `last_verified_at`. The budget MUST NOT grow
    between releases; this test fails LOUD when the budget creeps.

    The current snapshot is the v0.29.1 starting baseline — every
    pre-v0.29 high-confidence entry lacks the field, so the budget
    is pinned at the count immediately after v0.29.1 ships. Future
    work re-verifies entries with WebFetch + sets the field, and
    the budget should drop on each release.

    The budget intentionally EXCLUDES entries whose `_audit_status`
    field already records external verification — those rows are
    proof-of-life from the v0.28.4 / v0.29.0 audit cycles and
    counting them as stale would falsely inflate the budget.
    """
    today = datetime(2026, 5, 26, tzinfo=timezone.utc)
    files = ["bridges.json"] + LIST_FILES
    stale_high: list[str] = []
    for fname in files:
        for e in _load(_SEEDS / fname):
            if e.get("confidence") != "high":
                continue
            # Treat externally-verified audit status as proof-of-life.
            audit = e.get("_audit_status") or ""
            if "externally_verified" in audit:
                continue
            if _is_stale(e.get("last_verified_at"), today):
                stale_high.append(
                    f"{fname}: {e.get('name')} ({e.get('address')})"
                )
    # v0.29.1 starting budget — counted at the moment the test landed.
    # 56 pre-v0.28 bridges + 77 backfilled cex/defi/mixer entries +
    # any unverified rows = ~140 max. Pin a slightly looser ceiling
    # to allow for legitimate operator additions in the same commit.
    # The ceiling MUST be lowered (never raised) in follow-up commits
    # as entries are re-verified.
    BUDGET = 145
    assert len(stale_high) <= BUDGET, (
        f"Confidence-decay budget exceeded: {len(stale_high)} stale "
        f"high-confidence entries > budget of {BUDGET}. Recommendation "
        f"#6 says these should be re-verified (WebFetch the source) "
        f"and either re-promoted with a fresh `last_verified_at` OR "
        f"downgraded to confidence='medium'. Sample:\n  "
        + "\n  ".join(stale_high[:10])
    )


def test_v029_additions_carry_last_verified_at_or_audit_status() -> None:
    """The v0.29.x batches all flowed through WebFetch verification;
    every row should carry SOMETHING that proves it — either a
    `last_verified_at` field OR a `_audit_status` marker. A v0.29.x
    addition missing both has no provenance trail."""
    entries = []
    for fname in ["bridges.json"]:
        entries.extend(_load(_SEEDS / fname))
    no_provenance: list[str] = []
    for e in entries:
        if not (e.get("_v029_addition") or e.get("_v029_1_addition")):
            continue
        has_verified_at = isinstance(e.get("last_verified_at"), str) and e["last_verified_at"].strip()
        has_audit_status = "externally_verified" in (e.get("_audit_status") or "")
        if not (has_verified_at or has_audit_status):
            no_provenance.append(
                f"{e.get('name')} ({e.get('address')}): "
                f"v0.29.x addition with neither last_verified_at nor "
                f"_audit_status — provenance untrackable."
            )
    assert not no_provenance, "\n  ".join(no_provenance)
