"""Shared helpers used across reports / worker / recovery / ops.

Single source of truth for:
  * freeze_capability raw ↔ display mapping
  * chain-explorer URL prefixes
  * evidence-mode aggregation across freezable holdings

Pre-v0.16.4 these lived as literal dicts and ad-hoc helpers duplicated
across 5+ modules. Behavior is identical; this module just centralizes
the mapping tables so future updates (new chain, new capability tier)
happen in one place.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


# ---- freeze_capability mapping ---- #

# `IssuerEntry.freeze_capability` raw values come from issuers.json.
# emit_brief.py + the worker's skip-editorial synthesizer map these
# to display form ("HIGH"/"MEDIUM"/"LOW") for the trace_report,
# investigator_findings, and freeze-letter templates.
CAPABILITY_DISPLAY: dict[str, str] = {
    "yes": "HIGH",
    "limited": "MEDIUM",
    "no": "LOW",
}

# Capabilities that BLOCK the freeze pathway entirely. Both raw and
# display forms accepted because consumer code reads from either
# layer of the pipeline.
_NON_FREEZABLE_CAPABILITIES: frozenset[str] = frozenset({"no", "low"})

# Capabilities that have ACTIONABLE freeze authority.
_FREEZABLE_CAPABILITIES: frozenset[str] = frozenset({
    "yes", "limited", "high", "medium",
})


def capability_display(raw: str | None) -> str:
    """Map a raw freeze_capability ('yes'/'limited'/'no') to display
    form ('HIGH'/'MEDIUM'/'LOW'). Unknown / empty → 'UNKNOWN'."""
    if not raw:
        return "UNKNOWN"
    return CAPABILITY_DISPLAY.get(raw.lower(), "UNKNOWN")


def capability_blocks_freeze(capability: str | None) -> bool:
    """True if the capability indicates the issuer CANNOT freeze the
    token (e.g., DAI / Sky Protocol). Accepts both raw ("no") and
    display ("LOW") forms — emit_brief.py maps raw → display, but
    older brief readers + the skip-editorial synthesizer may carry
    the raw form."""
    if not capability:
        return False
    return capability.lower() in _NON_FREEZABLE_CAPABILITIES


def capability_is_freezable(capability: str | None) -> bool:
    """True if the issuer has actionable freeze authority. Accepts
    both raw and display forms; treats empty/unknown as False."""
    if not capability:
        return False
    return capability.lower() in _FREEZABLE_CAPABILITIES


# ---- Chain-explorer URL prefixes ---- #

# Pre-v0.16.4 this dict was duplicated in 5 files. Centralized here.
ADDRESS_EXPLORER_BY_CHAIN: dict[str, str] = {
    "ethereum":    "https://etherscan.io/address/",
    "arbitrum":    "https://arbiscan.io/address/",
    "polygon":     "https://polygonscan.com/address/",
    "base":        "https://basescan.org/address/",
    "bsc":         "https://bscscan.com/address/",
    "solana":      "https://solscan.io/account/",
    "hyperliquid": "https://app.hyperliquid.xyz/explorer/address/",
    "bitcoin":     "https://mempool.space/address/",
    "tron":        "https://tronscan.org/#/address/",
}


# ---- Evidence-mode aggregation ---- #

# `evidence_mode` aggregates the per-holding evidence_type fields up
# to a single label that templates can branch on. v0.16.1 added these
# at the per-issuer level (emit_brief._extract_freezable); v0.16.2
# extended to aggregate-across-issuers for customer/engagement letters.
_VALID_EVIDENCE_MODES: frozenset[str] = frozenset({
    "current_balance_only",
    "historical_only",
    "mixed",
})


def aggregate_evidence_mode_from_holdings(
    holdings: Iterable[Mapping[str, Any]],
    *,
    evidence_type_key: str = "evidence_type",
) -> str:
    """Compute the per-issuer evidence_mode from a list of holding
    dicts. Each holding should carry an `evidence_type` field
    ('current_balance' or 'historical_inflow').

    Returns one of: 'current_balance_only' / 'historical_only' /
    'mixed'. Defaults to 'current_balance_only' when holdings is
    empty (the conservative default — matches pre-v0.16.4 behavior).
    """
    n_historical = 0
    n_current = 0
    for h in holdings:
        ev = h.get(evidence_type_key)
        if ev == "historical_inflow":
            n_historical += 1
        else:
            n_current += 1
    if n_historical > 0 and n_current == 0:
        return "historical_only"
    if n_historical > 0 and n_current > 0:
        return "mixed"
    return "current_balance_only"


def aggregate_evidence_mode_from_entries(
    entries: Iterable[Mapping[str, Any]],
    *,
    mode_key: str = "evidence_mode",
) -> str:
    """Compute the aggregate evidence_mode across multiple FREEZABLE
    entries (one per issuer). Used by the customer-letter + engagement-
    letter contexts to pick the right "currently held" vs "received at"
    phrasing.

    Each entry's `evidence_mode` is one of historical_only / mixed /
    current_balance_only. The aggregate is:
      * 'historical_only'  iff ALL entries are historical_only
      * 'current_balance_only' iff NO entry is historical_only AND NO
        entry is mixed
      * 'mixed' otherwise
    """
    n_with_current = 0
    n_with_historical = 0
    for entry in entries:
        mode = entry.get(mode_key)
        if mode in ("current_balance_only", "mixed"):
            n_with_current += 1
        if mode in ("historical_only", "mixed"):
            n_with_historical += 1
    if n_with_historical > 0 and n_with_current == 0:
        return "historical_only"
    if n_with_historical > 0 and n_with_current > 0:
        return "mixed"
    return "current_balance_only"


# ---- Atomic file writes ---- #


# ---- Display helpers ---- #


def canonical_address_key(addr: str | None) -> str:
    """Return the canonical dict-key form of an address.

    v0.17.5 (round-10 forensic HIGH): centralizes a heuristic that
    was getting reinvented (slightly differently) in trace.risk_scoring,
    screen.screener, trace.correlation, and dormant.finder.

    Convention:
      * EVM (``0x`` + 40 hex) → lower-cased canonical form. EIP-55
        checksum case is a UI convention; the lower-cased form is
        the only stable comparator.
      * Everything else (Solana / Tron / Bitcoin base58, bech32,
        synthetic Hyperliquid sentinels) → preserved as-given. Base58
        IS case-sensitive on-chain, so lowercasing it silently
        corrupts the address.

    Empty / None → empty string. Callers should treat "" as
    "not a valid address" and skip.
    """
    if not isinstance(addr, str):
        return ""
    s = addr.strip()
    if not s:
        return ""
    if s.startswith("0x") and len(s) == 42:
        return s.lower()
    return s


def short_addr(addr: str | None) -> str:
    """Truncate an address for display: 0xAAAAbb...XXXXyyyy -> 0xAAAAbb…yyyy.

    v0.16.10 (round-9 output-artifacts MEDIUM): canonical implementation.
    Pre-v0.16.10 every module had its own (slightly different) truncator:
    reports/brief.py used 0xABCDEFGH…WXYZ (8+ellipsis+4); reports/
    emit_brief.py used 0xAAAAbb…XXXXyyyy (6+ellipsis+4). The same
    address rendered differently in different artifacts, breaking
    operator diffing across the brief and LE handoff.

    Convention: 6 leading + ellipsis + 4 trailing for any address >=
    12 chars; shorter strings are returned unchanged. Works for EVM
    hex, Solana/Tron/Bitcoin base58 — all consumers can pass through
    without per-chain branching.
    """
    if not addr:
        return ""
    if len(addr) < 12:
        return addr
    return f"{addr[:6]}…{addr[-4:]}"


# ---- Atomic file writes ---- #


def atomic_write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    """Write `content` to `path` atomically.

    Writes to a sibling `.tmp` then `os.replace`s into place — atomic on
    POSIX and on Windows (Python 3.3+). Important for JSON files that a
    separate process / thread may read concurrently (the bucket uploader
    reads files after the worker writes them; without atomicity it can
    pick up a half-written truncated JSON).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp_path.write_text(content, encoding=encoding)
        os.replace(tmp_path, path)
    except Exception:
        # Best-effort cleanup of the tempfile if write succeeded but
        # rename failed.
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass
        raise


# ---- Database connect helper ---- #
#
# v0.17.3 (round-10 audit CRIT): every psycopg.connect site MUST pass
# `prepare_threshold=None` to remain compatible with Supabase's
# transaction-mode pooler (port 6543). The v0.16.7 audit added the
# flag to worker/db.py + pricing/cache.py + worker/main.py, but the
# round-10 audit found 50+ other sites that silently regressed —
# payments/dispatcher, portal/server, portal/tokens, monitoring,
# freeze_learning, screen, watchlist, ops/commands/*, etc.
#
# Centralizing the connect path here means new code can't add a new
# regression. Existing direct `psycopg.connect(..., prepare_threshold=None, connect_timeout=10)` calls are
# legacy and should be migrated; the round-10 fix touches them
# individually for surgical-blame-line preservation but new code
# should use `db_connect()`.


def db_connect(dsn: str, **overrides: Any):
    """Open a psycopg connection with Recupero's standard pooler-safe
    defaults. Caller can override any kwarg.

    Defaults:
      * ``prepare_threshold=None`` — disables psycopg auto-prepare so
        Supabase's transaction-mode pooler doesn't reject after ~5 ops.
      * ``connect_timeout=10`` — fail-fast on DB outages.
      * ``autocommit=True`` — most call sites use single-statement ops.

    Returns the same value as ``psycopg.connect(dsn, prepare_threshold=None,
    connect_timeout=10, autocommit=True)`` (a connection context manager),
    so callers can write::

        with db_connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(...)

    v0.18.1 (round-11 arch-CRIT-001): pre-v0.18.1 the function passed
    `prepare_threshold` and `connect_timeout` BOTH as explicit kwargs
    AND in `**kwargs`, raising `TypeError: got multiple values for
    keyword argument 'prepare_threshold'` on FIRST call. The helper
    was a planted bomb — module docstring claimed it consolidated
    50+ direct `psycopg.connect` call sites but the migration never
    happened (`Grep db_connect` returned only the definition). Now:
    single forward of the merged kwargs dict.
    """
    import psycopg

    kwargs: dict[str, Any] = {
        "prepare_threshold": None,
        "connect_timeout": 10,
        "autocommit": True,
    }
    kwargs.update(overrides)
    return psycopg.connect(dsn, **kwargs)


# ---- Boolean env-var parsing ---- #


_TRUTHY_VALUES: frozenset[str] = frozenset({
    "1", "true", "yes", "on", "y", "t",
})


def env_truthy(name: str, default: bool = False) -> bool:
    """Return True when an env var is set to a truthy value.

    Accepts ``1``, ``true``, ``yes``, ``on``, ``y``, ``t`` (case-
    insensitive). Anything else (including unset) returns ``default``.

    Round-10 audit found inconsistent truthy parsing across modules:
    ``RECUPERO_DISABLE_EMAIL`` accepted multiple variants in
    worker/_email.py but only ``"1"`` in worker/_followup.py — so
    an operator setting ``RECUPERO_DISABLE_EMAIL=true`` got partial
    behavior. Centralizing here closes the variant gap.
    """
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in _TRUTHY_VALUES


# ---- DSN redaction helper ---- #
#
# logging_setup.py already redacts on emit; this helper is for explicit
# logging contexts that want a pre-redacted DSN to embed in messages.


def redact_dsn(dsn: str | None) -> str:
    """Return `dsn` with the password component replaced by ``***``.

    Safe to embed in log messages, exception strings, error responses.
    Handles `postgres://`, `postgresql://`, and short-form `host:port/db`.
    Returns ``""`` for None.
    """
    if not dsn:
        return ""
    import re as _re
    return _re.sub(
        r"(postgres(?:ql)?://[^:/@\s]+:)([^@\s]+)(@)",
        r"\1***\3",
        dsn,
        flags=_re.IGNORECASE,
    )


__all__ = (
    "CAPABILITY_DISPLAY",
    "ADDRESS_EXPLORER_BY_CHAIN",
    "short_addr",
    "capability_display",
    "capability_blocks_freeze",
    "capability_is_freezable",
    "aggregate_evidence_mode_from_holdings",
    "db_connect",
    "env_truthy",
    "redact_dsn",
    "aggregate_evidence_mode_from_entries",
    "atomic_write_text",
)
