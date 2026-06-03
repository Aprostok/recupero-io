"""v0.31.4 — Env-var documentation parity gate.

The audit found that 10 of 11 new v0.31.x env vars had zero hits in
docs/. Operators had no idea they existed. This test enforces the
inverse: every `RECUPERO_*` env-var read in `src/recupero/**/*.py`
MUST appear in `docs/ENV_VARS.md`, and the doc MUST NOT list env
vars that no longer exist in source (no museum entries).

Mechanism: walk the source tree with `ast`, find every
`os.environ.get(...)` / `os.environ[...]` / `os.getenv(...)` call
whose first argument is a constant string starting with
`RECUPERO_`. Then parse `docs/ENV_VARS.md` and assert set parity.

The inventory is rebuilt at test time (not hardcoded), so the test
naturally fails on the FUTURE addition of an undocumented env var —
which is the whole point of the regression-locking guarantee.

Also adds a smoke check that the `recupero-ops envvars` CLI surface
prints the doc.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path resolution — tests/test_v031_4_env_vars_doc.py lives at repo/tests/
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src" / "recupero"
DOC_PATH = REPO_ROOT / "docs" / "ENV_VARS.md"


# ---------------------------------------------------------------------------
# Source inventory — ast walk for every os.environ.* call
# ---------------------------------------------------------------------------


# Wrappers that take an env-var-name string as their first positional
# arg and read it via os.environ internally. The scanner treats any
# Call whose first arg is a `RECUPERO_*` / known-3p string literal as
# a true env-var read regardless of the callee, but we keep this set
# for documentation purposes and to make intent obvious.
_ENV_HELPER_HINTS = {
    "env_truthy",
    "_resolve_float_env",
    "_resolve_int_env",
    "_safe_positive_int_env",
    "_env_decimal",
    "_env_int",
}

_ENV_PREFIXES = (
    "RECUPERO_",
    "SUPABASE_",
    "ETHERSCAN_",
    "HELIUS_",
    "TRON_PRO_",
    "TONCENTER_",
    "COINGECKO_",
    "ANTHROPIC_",
    "RESEND_",
    "SENTRY_",
    "STRIPE_",
    "RAILWAY_",
    "SOURCE_DATE_",
    "HEALTH_BIND_",
)
_ENV_EXACTS = {"PORT", "ENVIRONMENT", "ENV", "NODE_ENV"}


def _looks_like_env_var(s: str) -> bool:
    if s in _ENV_EXACTS:
        return True
    return any(s.startswith(p) for p in _ENV_PREFIXES) and bool(
        re.match(r"^[A-Z][A-Z0-9_]*$", s)
    )


def _scan_file(path: Path) -> set[str]:
    """Return the set of env-var names referenced in `path`.

    Detection rules (each independent — any one match counts):

    1. `os.environ.get("RECUPERO_FOO", ...)` / `os.getenv("RECUPERO_FOO")`.
    2. `os.environ["RECUPERO_FOO"]` subscript.
    3. Any Call whose first positional arg is a string literal of
       env-var shape (catches helper wrappers like
       `env_truthy("RECUPERO_DISABLE_EMAIL")`).
    4. Module-level assignment `NAME = "RECUPERO_FOO"` PLUS any
       reference to that NAME as the first arg of a Call (catches
       the `_ENV_FOO = "RECUPERO_FOO"; _env_int(_ENV_FOO, ...)`
       pattern).
    5. String literals of env-var shape appearing inside other
       string literals (catches the `RECUPERO_PDF_VARIANT` subprocess
       code-string pattern).
    """
    try:
        src = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return set()
    out: set[str] = set()

    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return out

    # Pass 1: collect module-level NAME -> "RECUPERO_FOO" mappings.
    const_map: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            tgt = node.targets[0]
            if (
                isinstance(tgt, ast.Name)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and _looks_like_env_var(node.value.value)
            ):
                const_map[tgt.id] = node.value.value

    # Pass 2: walk every node.
    for node in ast.walk(tree):
        # Subscript: os.environ["FOO"] / _os.environ["FOO"]
        if isinstance(node, ast.Subscript):
            value = node.value
            if (
                isinstance(value, ast.Attribute) and value.attr == "environ"
            ):
                idx = node.slice
                if isinstance(idx, ast.Constant) and isinstance(idx.value, str):
                    if _looks_like_env_var(idx.value):
                        out.add(idx.value)

        # Call: catch any helper / direct call with first arg = env-name.
        if isinstance(node, ast.Call) and node.args:
            first = node.args[0]
            # Literal string first arg.
            if (
                isinstance(first, ast.Constant)
                and isinstance(first.value, str)
                and _looks_like_env_var(first.value)
            ):
                out.add(first.value)
            # Name referencing a module-level env-name constant.
            elif isinstance(first, ast.Name) and first.id in const_map:
                out.add(const_map[first.id])

    # Pass 3: regex sweep for env-var-name string literals embedded
    # inside other string literals (e.g. the subprocess code string
    # in worker/_deliverables.py that contains
    # `"variant = os.environ.get('RECUPERO_PDF_VARIANT', ...)"`).
    # Limit to literals that appear in source code (not comments) to
    # avoid catching docstring mentions. The regex is intentionally
    # picky: must be enclosed by quote, in a non-comment line.
    for m in re.finditer(
        r"""(?<!#)['"]([A-Z][A-Z0-9_]+)['"]""", src
    ):
        cand = m.group(1)
        if _looks_like_env_var(cand):
            # Filter out the lines that are pure comments — re-check
            # the line start.
            line_start = src.rfind("\n", 0, m.start()) + 1
            line_prefix = src[line_start:m.start()].lstrip()
            if line_prefix.startswith("#"):
                continue
            out.add(cand)
    return out


def inventory_source_env_vars() -> tuple[set[str], set[str]]:
    """Return (recupero_vars, third_party_vars).

    Walks every .py under src/recupero and aggregates.
    """
    all_vars: set[str] = set()
    for path in SRC_ROOT.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        all_vars |= _scan_file(path)
    recupero = {v for v in all_vars if v.startswith("RECUPERO_")}
    third_party = {
        v for v in all_vars
        if not v.startswith("RECUPERO_") and _looks_like_env_var(v)
    }
    return recupero, third_party


# ---------------------------------------------------------------------------
# Doc inventory — extract env-var names from docs/ENV_VARS.md
# ---------------------------------------------------------------------------


_BACKTICK_NAME_RE = re.compile(r"`(RECUPERO_[A-Z0-9_]+)`")
_BACKTICK_3P_RE = re.compile(r"`([A-Z][A-Z0-9_]{2,})`")


def inventory_doc_env_vars() -> tuple[set[str], set[str]]:
    """Return (recupero_vars_in_doc, third_party_vars_in_doc).

    Scans every backtick-delimited identifier in docs/ENV_VARS.md.
    The doc puts every env-var name in backticks, so a regex sweep
    is both simple and complete.
    """
    if not DOC_PATH.is_file():
        return set(), set()
    text = DOC_PATH.read_text(encoding="utf-8")
    recupero = set(_BACKTICK_NAME_RE.findall(text))
    third_party: set[str] = set()
    # Look ONLY in the third-party section for non-RECUPERO names
    # so we don't pick up random uppercase tokens from code samples.
    after = text.split("## Third-party secrets", 1)
    if len(after) == 2:
        section = after[1].split("## ", 1)[0]
        third_party = set(_BACKTICK_3P_RE.findall(section))
        third_party = {v for v in third_party if not v.startswith("RECUPERO_")}
        # Drop tokens that are obviously not env vars (the doc
        # mentions e.g. RFC, JSON, OOM, USD, NaN, BFS, CEX, KYC, etc.)
        _NON_ENV_TOKENS = {
            "RFC", "JSON", "OOM", "USD", "USDC", "USDC0", "NaN", "BFS", "CEX", "KYC", "PDF", "HTML", "SVG", "API",
            "CSV", "URL", "URI", "TTL", "TCP", "IP", "DSN", "WARN",
            "INFO", "DEBUG", "EVM", "MEV", "OFAC", "SDN",
        }
        third_party -= _NON_ENV_TOKENS
    return recupero, third_party


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_doc_exists_and_is_parseable() -> None:
    """Test 1: docs/ENV_VARS.md exists and parses as a structured doc.

    "Structured doc" means: starts with a top-level `#` header, has
    the policy section, and contains the Index table + per-variable
    sections we look up by name.
    """
    assert DOC_PATH.is_file(), (
        f"docs/ENV_VARS.md missing at {DOC_PATH}. Run the v0.31.4 "
        "env-var documentation pass."
    )
    text = DOC_PATH.read_text(encoding="utf-8")
    assert text.startswith("# Recupero Environment Variables"), (
        "ENV_VARS.md must start with the '# Recupero Environment "
        "Variables' header."
    )
    # Required sections — these names are stable; if they ever change
    # the test should fail loudly so the doc keeps a known shape.
    required_sections = (
        "## Policy",
        "## Index",
        "## Per-variable detail",
        "## Third-party secrets",
        "## Adding a new env var",
    )
    for section in required_sections:
        assert section in text, (
            f"ENV_VARS.md is missing the required section header: "
            f"{section!r}. The CLI's --index parser and this test "
            "both rely on it."
        )


def test_every_recupero_env_var_is_documented() -> None:
    """Test 2: every RECUPERO_* env var read in source MUST appear
    in docs/ENV_VARS.md.

    This is the regression-locking gate. Adding a new
    `os.environ.get("RECUPERO_FOO", ...)` without doc'ing
    `RECUPERO_FOO` fails this test on CI.
    """
    source_vars, _ = inventory_source_env_vars()
    doc_vars, _ = inventory_doc_env_vars()

    undocumented = source_vars - doc_vars
    assert not undocumented, (
        "The following RECUPERO_* env vars are read in "
        "src/recupero/**/*.py but are NOT documented in "
        "docs/ENV_VARS.md:\n\n"
        + "\n".join(f"  - {v}" for v in sorted(undocumented))
        + "\n\nAdd a row to the Index table AND a per-variable "
        "section in docs/ENV_VARS.md, then re-run this test."
    )


def test_no_museum_entries_in_doc() -> None:
    """Test 3: docs/ENV_VARS.md must not list env vars that no
    longer exist in source. "Museum entries" silently rot.

    Deliberately-deprecated vars (e.g. RECUPERO_DB_POOL_SIZE which
    still produces a deprecation WARN) are still READ in source so
    they show up in the inventory — they don't trigger this check.
    """
    source_vars, _ = inventory_source_env_vars()
    doc_vars, _ = inventory_doc_env_vars()

    museum = doc_vars - source_vars
    assert not museum, (
        "The following RECUPERO_* env vars appear in "
        "docs/ENV_VARS.md but are NOT read anywhere in "
        "src/recupero/**/*.py — remove them from the doc:\n\n"
        + "\n".join(f"  - {v}" for v in sorted(museum))
    )


def test_audit_baseline_11_vars_documented() -> None:
    """The audit explicitly called out 11 v0.31.x env vars that had
    zero hits in docs/. Pin them here so a future refactor that
    accidentally drops one of these rows triggers a louder failure
    than the generic parity check.
    """
    required = {
        "RECUPERO_DUST_ATTACK_FILTER",
        "RECUPERO_CEX_CONTINUITY",
        "RECUPERO_TRACE_MAX_HOPS",
        "RECUPERO_TRACE_DUST_USD",
        "RECUPERO_CROSSCHAIN_WINDOW_HOURS",
        "RECUPERO_DUST_ATTACK_THRESHOLD_USD",
        "RECUPERO_DUST_ATTACK_MIN_FANOUT",
        "RECUPERO_CEX_CONTINUITY_MIN_USD",
        "RECUPERO_CEX_CONTINUITY_WINDOW_HOURS",
        "RECUPERO_DESTINATION_DUST_USD",
        "RECUPERO_CROSS_CHAIN_CONTINUATION",
    }
    doc_vars, _ = inventory_doc_env_vars()
    missing = required - doc_vars
    assert not missing, (
        "The v0.31.x audit baseline requires the following 11 vars "
        "to be documented; missing:\n\n"
        + "\n".join(f"  - {v}" for v in sorted(missing))
    )


def test_inventory_finds_at_least_30_recupero_vars() -> None:
    """Sanity check that the ast walker is actually working — if
    something breaks the import or the source layout we want to
    fail fast rather than silently passing parity with an empty set.

    30 is well under the real count (~70-80) but above any plausible
    "ast scanner returned zero" failure mode.
    """
    source_vars, _ = inventory_source_env_vars()
    assert len(source_vars) >= 30, (
        f"Expected the ast walker to find at least 30 RECUPERO_* "
        f"env vars in src/recupero/**/*.py; got {len(source_vars)}. "
        "The scanner is probably broken."
    )


def test_ops_cli_envvars_subcommand_prints_doc() -> None:
    """Smoke test: `python -m recupero.ops.cli envvars` reads the
    doc and emits it to stdout. Catches a regression where the
    subcommand was wired but the doc-resolution path broke.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "recupero.ops.cli", "envvars"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, (
        f"recupero-ops envvars failed (rc={proc.returncode}):\n"
        f"stderr:\n{proc.stderr}"
    )
    out = proc.stdout
    # The doc header should appear in the output.
    assert "# Recupero Environment Variables" in out, (
        "recupero-ops envvars did not print the ENV_VARS.md "
        "top-level header. Stdout sample:\n" + out[:500]
    )
    # And at least one of the audit-baseline vars should be visible.
    assert "RECUPERO_TRACE_MAX_HOPS" in out, (
        "recupero-ops envvars output is missing RECUPERO_TRACE_MAX_HOPS."
    )


def test_ops_cli_envvars_index_flag_prints_index_only() -> None:
    """`recupero-ops envvars --index` prints the tabular index, not
    the full doc — useful for piping to grep."""
    proc = subprocess.run(
        [sys.executable, "-m", "recupero.ops.cli", "envvars", "--index"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, (
        f"recupero-ops envvars --index failed (rc={proc.returncode}):\n"
        f"stderr:\n{proc.stderr}"
    )
    out = proc.stdout
    # Should contain the Index header and a table row.
    assert "## Index" in out
    assert "| Name |" in out
    # Should NOT contain the per-variable detail section header.
    assert "## Per-variable detail" not in out, (
        "--index emitted the per-variable section; only the index "
        "table was expected."
    )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v", "--tb=short"])
