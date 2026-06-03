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

import logging
import os
import re as _re_module
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Pre-compiled DSN-password regex used by `redact_dsn` AND by the
# `db_connect` exception-message scrubber. Defined here at module top
# so name-resolution works even when called before the helper functions
# are defined (the connection helper sits earlier in the file for
# blame-line preservation).
_DSN_REDACT_RE = _re_module.compile(
    r"(postgres(?:ql)?://[^:/@\s]+:)([^@\s]+)(@)",
    flags=_re_module.IGNORECASE,
)

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
    "ton":         "https://tonviewer.com/",
    # v0.20.0 (round-13 chain-coverage research): EVM-trivial wins —
    # each chain reuses the existing EVM adapter via a chainid wire-up
    # in worker/watch_tick._CHAIN_ID_BY_NAME + chains/evm/adapter.
    # Prioritization order matches industry theft-volume reports
    # (Optimism + Avalanche CRIT; Linea/Blast/zkSync HIGH).
    "optimism":    "https://optimistic.etherscan.io/address/",
    "avalanche":   "https://snowtrace.io/address/",
    "linea":       "https://lineascan.build/address/",
    "blast":       "https://blastscan.io/address/",
    "zksync":      "https://explorer.zksync.io/address/",
    "scroll":      "https://scrollscan.com/address/",
    "mantle":      "https://mantlescan.xyz/address/",
    # v0.31.0: 6 chains promoted from destination-only to full adapter
    # coverage. Each routes through Etherscan V2 multichain. The
    # block-explorer URLs here are the chain's CANONICAL public
    # explorer (not the Etherscan-V2 endpoint), used in brief prose
    # and address-link rendering. Verified via WebFetch 2026-05-26.
    "fantom":      "https://ftmscan.com/address/",
    "celo":        "https://celoscan.io/address/",
    "gnosis":      "https://gnosisscan.io/address/",
    "moonbeam":    "https://moonscan.io/address/",
    "metis":       "https://andromeda-explorer.metis.io/address/",
    "kava":        "https://kavascan.com/address/",
    "opbnb":       "https://opbnb.bscscan.com/address/",
}


# v0.20.2 (audit-round-3 R3-9/R3-10): display name for each chain's
# canonical block explorer. Templates that previously hard-coded
# "Etherscan" / "Source: Etherscan API v2" in their prose now route
# through this table so cross-chain letters say "Tronscan" /
# "BscScan" / "Solscan" as appropriate. The default is "the block
# explorer" — generic-but-correct phrasing for any chain we add
# before this table is updated.
EXPLORER_NAME_BY_CHAIN: dict[str, str] = {
    "ethereum":    "Etherscan",
    "arbitrum":    "Arbiscan",
    "polygon":     "PolygonScan",
    "base":        "BaseScan",
    "bsc":         "BscScan",
    "solana":      "Solscan",
    "hyperliquid": "Hyperliquid Explorer",
    "bitcoin":     "Mempool.space",
    "tron":        "Tronscan",
    "ton":         "Tonviewer",
    "optimism":    "Optimistic Etherscan",
    "avalanche":   "Snowtrace",
    "linea":       "LineaScan",
    "blast":       "BlastScan",
    "zksync":      "zkSync Explorer",
    "scroll":      "ScrollScan",
    "mantle":      "MantleScan",
    # v0.31.0: promoted destination chains.
    "fantom":      "FtmScan",
    "celo":        "Celoscan",
    "gnosis":      "GnosisScan",
    "moonbeam":    "Moonscan",
    "metis":       "Metis Andromeda Explorer",
    "kava":        "KavaScan",
    "opbnb":       "opBNBScan",
}


def explorer_name_for_chain(chain: Any) -> str:
    """Return the display name of the canonical block explorer for
    ``chain``. Accepts either a `Chain` enum or a chain string.
    Falls back to "the block explorer" for unknown chains so prose
    stays correct (just less specific) — safer than rendering
    ``"Etherscan"`` on a non-EVM letter.

    Used by letter templates to render chain-conditional prose
    (e.g., "Each wallet links to its <Tronscan> record" on a Tron
    case, "<Etherscan>" on an ETH case).
    """
    if hasattr(chain, "value"):
        chain_str = chain.value
    else:
        chain_str = str(chain) if chain is not None else ""
    return EXPLORER_NAME_BY_CHAIN.get(chain_str.lower(), "the block explorer")


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
    # v0.20.10 (R14-D/R14-E LOW): validate that the 40 characters after
    # the 0x prefix are genuinely hex before returning the lowercased
    # canonical form. A 42-char string starting with 0x but containing
    # non-hex characters (e.g., spaces, letters G-Z) falls through to
    # `return s` (pass-through, verbatim) rather than being silently
    # keyed as if it were a valid EVM address.
    if s.startswith("0x") and len(s) == 42:
        suffix = s[2:]
        # Inline check avoids importing re at module level; only affects
        # the rare malformed-input path.
        if all(c in "0123456789abcdefABCDEF" for c in suffix):
            return s.lower()
    return s


def short_addr(addr: str | None) -> str:
    """Truncate an address for display: 0xAAAAbb...XXXXyyyy -> 0xAAAAbb…yyyy.

    v0.16.10 (round-9 output-artifacts MEDIUM): canonical implementation.
    v0.32.1 (Jacob cross-cutting audit §3.1): delegates to
    :func:`recupero.util.addr_format.short_address` — the single source
    of truth for display-truncation. Kept as a thin alias so legacy
    callers (reports/brief.py, reports/emit_brief.py, worker/_flow_diagram.py,
    monitoring/dispatcher.py, ...) continue to work without churn.

    Convention: 6 leading + ellipsis + 4 trailing for any address >=
    11 chars; shorter strings are returned unchanged. Works for EVM
    hex, Solana/Tron/Bitcoin base58 — all consumers can pass through
    without per-chain branching.
    """
    from recupero.util.addr_format import short_address
    return short_address(addr)


# ---- Link-like path detection (symlinks + Windows junctions) ---- #


def is_link_like(path: Path) -> bool:
    """True if ``path`` is a symbolic link OR a Windows NTFS junction.

    v0.31.3 (Windows path-traversal hardening): pre-v0.31.3 every
    safety-net call site used only ``Path.is_symlink()``, which
    returns ``False`` for NTFS junctions on Windows. That left a
    Windows-specific path-traversal hole: ``mklink /J`` doesn't even
    require admin / Developer Mode, so an attacker who could write
    one directory inside the data-dir tree could plant a junction
    pointing anywhere and bypass every "is this a symlink?" guard.

    ``os.path.isjunction`` was added in Python 3.12. On older
    interpreters it doesn't exist; we feature-detect and degrade
    cleanly. On POSIX, ``isjunction`` is always ``False``, so the
    helper collapses to the legacy ``is_symlink`` semantics — no
    behavior change on Linux / Mac.

    Defensive: any OSError from the underlying stat is swallowed
    (returns False). The caller's own write/read code will surface
    a real-FS error in a moment if there's a deeper problem.
    """
    try:
        if path.is_symlink():
            return True
    except OSError:
        return False
    try:
        # Python 3.12+ — os.path.isjunction. Feature-detect for
        # older interpreters where it's missing.
        isjunction = getattr(os.path, "isjunction", None)
        if isjunction is not None and isjunction(str(path)):
            return True
    except OSError:
        return False
    return False


# ---- Atomic file writes ---- #


def atomic_write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    """Write `content` to `path` atomically.

    Writes to a sibling tempfile then `os.replace`s into place — atomic
    on POSIX and on Windows (Python 3.3+). Important for JSON files that
    a separate process / thread may read concurrently (the bucket
    uploader reads files after the worker writes them; without
    atomicity it can pick up a half-written truncated JSON).

    v0.28.0 (JACOB-3 validator finding): newline translation is
    DISABLED. Python's default text-mode write applies platform-
    specific newline translation (LF → CRLF on Windows). The brief
    manifest hashes the in-memory string then writes via this
    helper; the on-disk bytes are then larger than the hashed
    bytes on Windows, so the recorded SHA256 is stale the moment
    the file lands. The output_integrity validator's
    manifest_sha_matches_disk check now catches this on every
    build. Force LF-only writes everywhere — manifest SHAs match,
    and the HTML on Linux/Mac/Windows is byte-identical so the
    rendered output is deterministic across platforms (which the
    `3x determinism` regression also depends on).

    Wave-3 hardening (TOCTOU/symlink audit):
      * Reject if `path` already exists as a symlink — silently
        following an operator-placed redirect to an unrelated
        directory has caused recovery-snapshot corruption in
        ops-incidents. Cheaper to fail loud.
      * v0.31.3: also reject Windows NTFS junctions via
        ``is_link_like`` — pre-v0.31.3 only ``is_symlink`` was
        checked, which returns False for junctions, leaving a
        Windows-specific path-traversal hole (`mklink /J` doesn't
        even require admin / Developer Mode).
      * Tempfile name is unique (``tempfile.mkstemp``) so concurrent
        writers targeting the SAME path (e.g. two brief generators
        racing on brief.html) don't clobber each other's tempfile
        mid-write. Pre-wave3 the tmp name was a deterministic
        ``path + ".tmp"`` which created a write-write race on the
        same intermediate file.
    """
    import tempfile

    path.parent.mkdir(parents=True, exist_ok=True)

    if is_link_like(path):
        raise ValueError(
            f"refusing to write to symlink at {path}; delete the link "
            f"and retry (wave-3 symlink-following guard)"
        )

    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        # newline="" disables universal-newline translation on
        # write — bytes go to disk exactly as supplied.
        with os.fdopen(fd, "w", encoding=encoding, newline="") as f:
            f.write(content)
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
    # Adversarial-input wave (v0.20.2): psycopg's connection errors
    # routinely include the full DSN (including the password) in the
    # exception message. A failed connect on operator stdout therefore
    # leaks the Supabase password. Re-raise with a redacted DSN
    # substituted into the message so the secret never lands in logs.
    try:
        return psycopg.connect(dsn, **kwargs)
    except Exception as exc:
        red = redact_dsn(dsn)
        msg = str(exc)
        if dsn and dsn in msg:
            msg = msg.replace(dsn, red)
        # Strip any other DSN-shaped substrings that might have been
        # composed by psycopg (e.g., with normalized hostname).
        msg = _DSN_REDACT_RE.sub(r"\1***\3", msg)
        # Try to reconstruct the same exception type with the redacted
        # message so callers' `except SpecificError` paths still work.
        # Fall back to mutating .args if the exception type doesn't
        # accept a single-string constructor (some psycopg error
        # subclasses are picky).
        try:
            new_exc: BaseException = type(exc)(msg)
        except Exception:  # noqa: BLE001
            exc.args = (msg,)
            new_exc = exc
        # Chain with `from None` so the redacted message is what gets
        # formatted in tracebacks instead of the original (which may
        # still embed the password via psycopg's own __str__ override).
        raise new_exc from None


# ---- Investigator identity defaults ---- #
#
# v0.19.0 (round-11 arch follow-up): single source for the
# operator-identity fallbacks used by emit_brief.py (no-AI template
# write path) AND ai_editorial.py (AI-prompt context). Pre-v0.19.0 both
# modules defined `_investigator_defaults()` independently — the two
# implementations drifted (ai_editorial returned an extra
# `TEMPLATE_VERSION` key; otherwise identical) and any field-add
# required touching two files. With one source, adding a new
# investigator-identity env var lives in one place.


# v0.30.0 (F7 — brief read-through): the unconfigured-name placeholder
# is a sentinel that the brief-render path checks to decide whether to
# stamp a DRAFT banner. Keep it as a single canonical string so a typo
# can't bypass the gate.
INVESTIGATOR_NAME_UNCONFIGURED = "(operator name not configured)"


def investigator_defaults() -> dict[str, str]:
    """Resolve investigator identity from env at call-time.

    Returns a dict of INVESTIGATOR_* fields populated from
    ``RECUPERO_INVESTIGATOR_*`` env vars. Unset name / email fall back
    to obvious placeholders so an unconfigured deploy can't silently
    ship the developer's name on legal documents.

    Read at call-time — never module-load — so a deploy that sets the
    env vars late (or rotates them) picks up the new value without a
    worker restart.
    """
    return {
        "INVESTIGATOR_NAME": (
            os.environ.get("RECUPERO_INVESTIGATOR_NAME", "").strip()
            or INVESTIGATOR_NAME_UNCONFIGURED
        ),
        "INVESTIGATOR_EMAIL": (
            os.environ.get("RECUPERO_INVESTIGATOR_EMAIL", "").strip()
            or "compliance@recupero.io"
        ),
        "INVESTIGATOR_ENTITY": (
            os.environ.get("RECUPERO_INVESTIGATOR_ENTITY", "Recupero LLC")
        ),
        "INVESTIGATOR_ENTITY_FULL": (
            os.environ.get(
                "RECUPERO_INVESTIGATOR_ENTITY_FULL",
                "Recupero LLC, a Delaware limited liability company",
            )
        ),
        "INVESTIGATOR_WEB": (
            os.environ.get("RECUPERO_INVESTIGATOR_WEB", "recupero.io")
        ),
    }


def resolve_render_time() -> datetime:
    """Resolve the wall-clock-or-pinned render timestamp.

    Honors ``SOURCE_DATE_EPOCH`` for reproducible-builds workflows so
    re-rendering the same case on the same code produces byte-identical
    artifacts.

    v0.30.4 (V030_2_CORRECTNESS_AUDIT T2-A): moved from `brief.py` into
    `_common.py` so every renderer can share the implementation. Pre-
    v0.30.4 only `brief.py` and `recovery_snapshot.py` honored
    SOURCE_DATE_EPOCH; 7 other renderers (cluster_handoff, aggregate,
    ai_editorial, cooperation_dashboard, legal_requests,
    subpoena_renderer, law_firm_dashboard) used bare
    ``datetime.now(UTC)`` and broke byte-reproducibility of multi-
    artifact bundles. All 7 now route here.

    On parse failure (invalid SOURCE_DATE_EPOCH), falls back to
    wall-clock with a warning.
    """
    src_epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if src_epoch:
        try:
            return datetime.fromtimestamp(int(src_epoch), tz=UTC)
        except (ValueError, TypeError):
            log.warning(
                "SOURCE_DATE_EPOCH=%r is not a valid integer epoch; "
                "falling back to wall-clock", src_epoch,
            )
    return datetime.now(UTC)


def is_investigator_configured() -> bool:
    """v0.30.0 (F7): True iff RECUPERO_INVESTIGATOR_NAME is set to a
    non-empty value.

    The §9 Investigator Attestation block is the most legally-significant
    paragraph in the LE handoff package (sworn statement, signs the
    chain of custody). Pre-v0.30.0 unconfigured deploys silently shipped
    "(operator name not configured)" in that block — which renders the
    attestation legally useless (no human accountable) and signals to
    the recipient that the package is generated by software with no
    review.

    Callers use this predicate to decide whether to stamp a DRAFT
    banner on the brief. The strict-mode helper `require_investigator_
    configured()` raises rather than returning False — useful as a
    production deploy gate / CI assertion.
    """
    raw = os.environ.get("RECUPERO_INVESTIGATOR_NAME", "").strip()
    return bool(raw) and raw != INVESTIGATOR_NAME_UNCONFIGURED


def require_investigator_configured() -> None:
    """v0.30.0 (F7): raise RuntimeError if the operator-name env var
    isn't set. Suitable as a production deploy preflight check.

    Pre-flight intent: a Railway/Render deploy where
    ``RECUPERO_REQUIRE_INVESTIGATOR=1`` is set will fail to start if
    the investigator name is missing — preventing a deploy from
    silently shipping unsigned briefs to a real customer. Dev /
    sandbox deploys leave the env var unset and the function never
    runs; only strict-mode operators call it.
    """
    if is_investigator_configured():
        return
    raise RuntimeError(
        "RECUPERO_INVESTIGATOR_NAME is not configured. "
        "Briefs shipped without a configured operator name carry an "
        "unsigned §9 Investigator Attestation block, which is legally "
        "ineffective and damages credibility with LE / issuer "
        "recipients. Set RECUPERO_INVESTIGATOR_NAME to a real human "
        "name before running brief generation in production. "
        "(To bypass this check in development, unset "
        "RECUPERO_REQUIRE_INVESTIGATOR.)"
    )


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


# ---- DSN pooler rewrite ---- #
#
# v0.19.0 (round-11 arch follow-up): single source for the
# direct-host → transaction-pooler rewrite. Pre-v0.19.0 this function
# was duplicated verbatim in worker/watch_tick.py, worker/dashboard_summary.py,
# worker/investigations_api.py, and inlined in worker/main.py. The
# pooler region ("aws-1-us-east-1") was hardcoded in 4 places — when
# Supabase added EU and AP regions, three of those four needed a copy
# edit. Centralized here so the region map lives in one place.


def pooled_dsn(dsn: str) -> str:
    """Rewrite a direct-host Supabase DSN to the transaction pooler
    (port 6543).

    Why: some home networks + Railway sandbox can't reach Supabase's
    IPv6-only direct host (``db.<ref>.supabase.co``); the pooler endpoint
    (``aws-1-us-east-1.pooler.supabase.com``) is dual-stack and is the
    long-term-supported entry point for non-transaction-mode work.

    Behavior is best-effort: if the DSN doesn't match the direct-host
    pattern (already pooled, custom DSN, env-var unset), returns it
    unchanged. The matching is regex-based on the user/password/ref
    triple so the password may contain special chars without breaking
    parsing.

    The pooler region defaults to ``us-east-1`` because that's where
    every Recupero project lives today. Operators running a Supabase
    project in another region can set ``RECUPERO_SUPABASE_POOLER_HOST``
    to override the full host string (e.g.
    ``aws-1-eu-central-1.pooler.supabase.com``).
    """
    if not dsn or "db." not in dsn or ".supabase.co" not in dsn:
        return dsn
    import re as _re
    # Wave-6 hardening (adversarial-input audit): the password slot may
    # contain ANY URL-safe character including `@`, `/`, `?`, `:` once
    # percent-decoded. The previous regex used `[^@]+` (greedy) which
    # silently truncated to the LAST `@db.` boundary, splicing a
    # malformed DSN with embedded credentials downstream. We now match
    # `.*?` (lazy) with an explicit `@db.<ref>.supabase.co` lookahead so
    # the password may contain '@', and we URL-encode the password
    # component on the way out so any reserved character (`@`, `/`,
    # `?`, `:`, `#`) round-trips through libpq's URI parser as the
    # original byte rather than corrupting the URI structure.
    m = _re.search(
        r"postgres(?:ql)?://([^:/@\s]+):(.+?)@db\.([^.]+)\.supabase\.co",
        dsn,
    )
    if not m:
        return dsn
    user, pwd, ref = m.group(1), m.group(2), m.group(3)
    from urllib.parse import quote as _q
    # `safe=""` percent-encodes every reserved char; the username is
    # constrained by [^:/@\s]+ above so it's already URI-safe, but we
    # quote it too for symmetry.
    pwd_enc = _q(pwd, safe="")
    user_enc = _q(user, safe="")
    pooler_host = (
        os.environ.get("RECUPERO_SUPABASE_POOLER_HOST", "").strip()
        or "aws-1-us-east-1.pooler.supabase.com"
    )
    return (
        f"postgresql://{user_enc}.{ref}:{pwd_enc}"
        f"@{pooler_host}:6543/postgres"
    )


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
    return _DSN_REDACT_RE.sub(r"\1***\3", dsn)


__all__ = (
    "CAPABILITY_DISPLAY",
    "ADDRESS_EXPLORER_BY_CHAIN",
    "EXPLORER_NAME_BY_CHAIN",
    "explorer_name_for_chain",
    "short_addr",
    "capability_display",
    "capability_blocks_freeze",
    "capability_is_freezable",
    "aggregate_evidence_mode_from_holdings",
    "db_connect",
    "env_truthy",
    "investigator_defaults",
    # v0.30.1 (round-N T1-B): F7 investigator-gate helpers must be in
    # __all__ so `from recupero._common import *` exposes them — without
    # this, the deploy gate is bypassable via wildcard import.
    "is_investigator_configured",
    "require_investigator_configured",
    "INVESTIGATOR_NAME_UNCONFIGURED",
    # v0.30.4 (V030_2_CORRECTNESS_AUDIT T2-A): shared render-time
    # helper used by 8 renderers for SOURCE_DATE_EPOCH coverage.
    "resolve_render_time",
    "pooled_dsn",
    "redact_dsn",
    "aggregate_evidence_mode_from_entries",
    "atomic_write_text",
    "canonical_address_key",
)
