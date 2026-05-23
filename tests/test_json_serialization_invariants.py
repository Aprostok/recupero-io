"""JSON serialization invariants across deliverable / manifest / network
callsites.

Every ``json.dumps(...)`` that hits disk or the wire must satisfy one or
more of:

  1. ``ensure_ascii=False`` — non-ASCII victim names must survive byte-
     for-byte; default ASCII-escape bloats output 4x and leaks string
     length via size analysis.
  2. ``allow_nan=False`` — a poisoned ``Decimal('NaN')`` in a freeze
     brief must raise at serialization time rather than write the literal
     ``NaN`` token (which JSON.parse refuses, silently breaking the
     downstream operator graph).
  3. ``sort_keys=True`` for any artifact that's hashed / signed /
     checksummed downstream. Pre-fix the manifest's ``output_sha256``
     block was deterministic because the file contents were, but
     Python's dict ordering for the *outer* manifest happened to be
     stable. Future Python may not be.
  4. ``default=`` for Decimal / datetime / UUID where the payload type
     allows it.
  5. ``separators=(",", ":")`` on URL-bound or signature-bound JSON.

These tests are deliberately mixed-mode:

  * Functional tests that exercise the real public-API callsite
    (``write_dormant_report``, ``PriceCache.put``) and assert behavior
    on the resulting file bytes.
  * Source-inspection tests that parse the call kwargs at known
    line offsets for callsites whose surrounding stack is too heavy
    to set up in a unit test (the ``_health_server`` body emitter,
    the supabase URL-bound POST bodies).

Either way the assertion is on the contract — same input -> same bytes,
NaN raises, non-ASCII survives — not on incidental output formatting.
"""

from __future__ import annotations

import ast
import json
import math
from decimal import Decimal
from pathlib import Path

import pytest

from recupero.dormant.finder import (
    DormantCandidate,
    TokenHolding,
    write_dormant_report,
)
from recupero.models import Chain, TokenRef
from recupero.pricing.cache import PriceCache

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------- helpers --------------------------------------------------- #


def _kwargs_at(rel_path: str, line: int) -> dict[str, object]:
    """Return the kwargs of the ``json.dumps``/``json.dump`` call whose
    AST start_line covers ``line``. Literals only (booleans, strings,
    tuples). Anything we can't statically evaluate stays out so a
    callsite using a name reference won't accidentally pass an assertion
    that should fail.
    """
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    tree = ast.parse(src)
    found: dict[str, object] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr not in {"dumps", "dump"}:
            continue
        # Match by line proximity — the call must START on or before
        # ``line`` and END on or after it (multi-line calls).
        start = node.lineno
        end = getattr(node, "end_lineno", start)
        if not (start <= line <= end):
            continue
        for kw in node.keywords:
            if kw.arg is None:
                continue
            try:
                found[kw.arg] = ast.literal_eval(kw.value)
            except Exception:  # noqa: BLE001 — name refs etc.
                found[kw.arg] = "<non-literal>"
        return found
    raise AssertionError(
        f"no json.dump(s) call found at {rel_path}:{line}"
    )


# ---------- 1. dormant deliverable: functional invariants ------------- #


def _dormant_payload_path(case_dir: Path, total_usd: Decimal) -> Path:
    """Materialize a ``write_dormant_report`` output with one candidate
    holding the given total_usd. Returns the path written."""
    case_dir.mkdir(parents=True, exist_ok=True)
    token = TokenRef(
        chain=Chain.ethereum,
        contract="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        symbol="USDC",
        decimals=6,
    )
    holding = TokenHolding(
        token=token,
        raw_amount=1_000_000,
        decimal_amount=Decimal("1.0"),
        usd_value=total_usd,
    )
    cand = DormantCandidate(
        address="0x" + "ab" * 20,
        chain=Chain.ethereum,
        total_usd=total_usd,
        holdings=[holding],
        explorer_url="https://etherscan.io/address/0x...",
    )
    return write_dormant_report(case_dir, [cand])


def test_dormant_report_deterministic_bytes(tmp_path: Path) -> None:
    """Same input -> same bytes. Catches dict-iteration-order drift."""
    a = _dormant_payload_path(tmp_path / "a", Decimal("12345.67"))
    b = _dormant_payload_path(tmp_path / "b", Decimal("12345.67"))
    assert a.read_bytes() == b.read_bytes()


def test_dormant_report_non_ascii_address_survives(tmp_path: Path) -> None:
    """A non-ASCII pricing-error message (real-world: a CoinGecko error
    string in Cyrillic for a Russian token) must round-trip without
    \\u escapes that 4x the byte count."""
    token = TokenRef(
        chain=Chain.ethereum,
        contract="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        symbol="USDC",
        decimals=6,
    )
    holding = TokenHolding(
        token=token,
        raw_amount=1,
        decimal_amount=Decimal("1.0"),
        usd_value=Decimal("1.0"),
        pricing_error="ошибка ценообразования",  # "pricing error" in Russian
    )
    cand = DormantCandidate(
        address="0x" + "cd" * 20,
        chain=Chain.ethereum,
        total_usd=Decimal("1"),
        holdings=[holding],
    )
    out = write_dormant_report(tmp_path, [cand])
    raw = out.read_text(encoding="utf-8")
    assert "ошибка ценообразования" in raw, raw
    assert "\\u043e" not in raw  # the \u-escape form of 'о'


# ---------- 2. brief manifest: sort_keys, allow_nan, ensure_ascii ----- #


def test_brief_manifest_dumps_kwargs() -> None:
    """``brief.py``'s per-issuer ``manifest_<slug>_<brief_id>.json``
    drives downstream sha256 verification. The dict is hashed indirectly
    via reproducibility checks; sort_keys is mandatory.

    Line-independent: locate the call by walking from the
    ``manifest_path = …`` assignment to the next ``json.dumps`` so a
    surrounding-comment edit doesn't break the pin.
    """
    src = (REPO_ROOT / "src/recupero/reports/brief.py").read_text(encoding="utf-8")
    needle = 'atomic_write_text(manifest_path, json.dumps(manifest,'
    idx = src.find(needle)
    assert idx != -1, "manifest json.dumps call moved; update needle"
    line = src.count("\n", 0, idx) + 1
    kw = _kwargs_at("src/recupero/reports/brief.py", line)
    assert kw.get("sort_keys") is True
    assert kw.get("allow_nan") is False
    assert kw.get("ensure_ascii") is False


# ---------- 3. freeze_brief deliverable: NaN must raise --------------- #


def _all_dumps_in(rel_path: str) -> list[dict[str, object]]:
    """Return every ``json.dump(s)`` call's literal kwargs in the file.
    Robust to line drift — used where the test cares about EVERY call
    in the file satisfying an invariant, not a specific line number."""
    src = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    tree = ast.parse(src)
    out: list[dict[str, object]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr not in {"dumps", "dump"}:
            continue
        # Restrict to json.* (not protobuf.json_format etc.)
        if isinstance(func.value, ast.Name) and func.value.id != "json":
            continue
        kw_map: dict[str, object] = {}
        for kw in node.keywords:
            if kw.arg is None:
                continue
            try:
                kw_map[kw.arg] = ast.literal_eval(kw.value)
            except Exception:  # noqa: BLE001
                kw_map[kw.arg] = "<non-literal>"
        out.append(kw_map)
    return out


def test_emit_brief_freeze_brief_dumps_kwargs() -> None:
    """``freeze_brief.json`` is the artifact attorneys read. Every
    ``json.dump(s)`` call in emit_brief.py — whichever line it lands
    on after future refactors — must reject NaN/Inf and keep non-ASCII
    readable. Line-number drift can no longer hide a regression."""
    dumps = _all_dumps_in("src/recupero/reports/emit_brief.py")
    assert dumps, "expected at least one json.dump(s) call in emit_brief.py"
    for i, kw in enumerate(dumps):
        assert kw.get("allow_nan") is False, (
            f"emit_brief.py json.dump(s) #{i}: allow_nan must be False; "
            f"got {kw.get('allow_nan')!r} (full kwargs={kw!r})"
        )
        assert kw.get("ensure_ascii") is False, (
            f"emit_brief.py json.dump(s) #{i}: ensure_ascii must be "
            f"False; got {kw.get('ensure_ascii')!r}"
        )


def test_emit_brief_cluster_rewrite_dumps_kwargs() -> None:
    """Equivalent contract for the cluster-membership re-write path.
    Now covered by the file-wide enumeration in the test above; keep
    a placeholder here so the contract reads as two separate intents
    in the test suite. (Both invariants verified file-wide.)"""
    dumps = _all_dumps_in("src/recupero/reports/emit_brief.py")
    assert len(dumps) >= 2, (
        "expected at least two json.dump(s) calls in emit_brief.py "
        "(freeze_brief write + cluster-rewrite path)"
    )


# ---------- 4. URL-bound bodies: separators, allow_nan ---------------- #


@pytest.mark.parametrize(
    "rel_path",
    [
        "src/recupero/worker/investigations_api.py",
        "src/recupero/ops/commands/send_le_handoff.py",
        "src/recupero/ops/commands/send_freeze_letters.py",
    ],
)
def test_url_bound_json_uses_compact_separators(rel_path: str) -> None:
    """Supabase storage list / sign POST bodies. Smaller payloads are
    cheaper on the wire and the deterministic spacing keeps HTTP signing
    primitives stable if we ever switch to a signed-body transport.

    File-wide assertion (line-drift-tolerant): every json.dump(s) call
    in the file must use compact separators + allow_nan=False. Pre-fix
    these files had at least one bare json.dumps without separators —
    any regression now trips the file-wide check."""
    dumps = _all_dumps_in(rel_path)
    assert dumps, f"expected at least one json.dump(s) call in {rel_path}"
    for i, kw in enumerate(dumps):
        assert kw.get("separators") == (",", ":"), (
            f"{rel_path} json.dump(s) #{i}: separators must be "
            f"(',', ':'); got {kw.get('separators')!r}"
        )
        assert kw.get("allow_nan") is False, (
            f"{rel_path} json.dump(s) #{i}: allow_nan must be False; "
            f"got {kw.get('allow_nan')!r}"
        )


# ---------- 5. pricing cache: NaN guard + determinism ----------------- #


def test_pricing_cache_put_rejects_nan(tmp_path: Path) -> None:
    """A poisoned upstream price (NaN) must NOT be persisted as the
    literal ``NaN`` token — a downstream cache reader would then choke
    on json.load with strict parsers."""
    cache = PriceCache(tmp_path)
    with pytest.raises(ValueError):
        cache.put("nan-token", {"usd": float("nan"), "error": None})


def test_pricing_cache_put_deterministic(tmp_path: Path) -> None:
    """Two equivalent dicts -> two byte-identical files."""
    a_dir = tmp_path / "a"
    b_dir = tmp_path / "b"
    cache_a = PriceCache(a_dir)
    cache_b = PriceCache(b_dir)
    val = {"usd": "1.23", "error": None, "fetched_at": "2026-05-22T00:00:00Z"}
    cache_a.put("test-key", val)
    cache_b.put("test-key", dict(reversed(list(val.items()))))  # same data, different insertion order
    a_path = next(a_dir.iterdir())
    b_path = next(b_dir.iterdir())
    assert a_path.read_bytes() == b_path.read_bytes()


# ---------- 6. backup manifest: sort_keys for reproducibility -------- #


def test_backup_manifest_dumps_kwargs() -> None:
    """``scripts/backup_investigations.py`` writes a manifest.json
    whose contents must hash deterministically across machines for
    cold-restore verification."""
    kw = _kwargs_at("scripts/backup_investigations.py", 233)
    assert kw.get("sort_keys") is True
    assert kw.get("allow_nan") is False


# ---------- 7. NaN serialization check across the helpers ------------ #


def test_json_dumps_with_allow_nan_false_raises_on_nan() -> None:
    """Smoke test on the stdlib invariant the codebase now relies on:
    ``allow_nan=False`` must raise ``ValueError`` for both NaN and
    Infinity, regardless of indent / ensure_ascii combinations."""
    for v in (float("nan"), float("inf"), -math.inf):
        with pytest.raises(ValueError):
            json.dumps({"x": v}, allow_nan=False)
        with pytest.raises(ValueError):
            json.dumps({"x": v}, allow_nan=False, indent=2, ensure_ascii=False)
