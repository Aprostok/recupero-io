"""Regex ReDoS (Regular-expression Denial-of-Service) audit.

Every ``re.compile(...)`` callsite in ``src/recupero/`` was reviewed for
nested-quantifier / overlapping-class patterns that exhibit exponential
or super-polynomial backtracking on attacker-controlled input.

Each test below feeds a known pathological input to a real Recupero
regex (or its entry-point validator) under a wall-clock budget. The
hostile string is sized so that:

  * **pre-fix** (the previously deployed regex / no length cap) the
    test would run for *several seconds to minutes* — well past the
    1-second budget — and fail.
  * **post-fix** (current regex with length cap and/or unambiguous
    alternation) the call completes in single-digit milliseconds and
    the test passes.

Findings
--------

Patterns audited: 35 ``re.compile`` callsites across 13 files
(``api/monitoring_api.py``, ``logging_setup.py``, ``hack_tracker/models.py``,
``hack_tracker/sources/x_feed.py``, ``worker/investigations_api.py``,
``worker/_email.py``, ``worker/_flow_diagram.py``, ``worker/_pdf_links.py``,
``cli.py``, ``portal/server.py``, ``portal/intake.py``,
``reports/_jinja_filters.py``, ``validators/output_integrity.py``).

ReDoS-prone before this commit
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. ``portal.intake._EMAIL_RE = r"^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$"`` —
   polynomial backtracking on ``a@<huge-no-dot>``. Two ``[^@\\s]+``
   classes both admit ``.``, so the engine tries every split point for
   where the literal ``.`` lives. Length check was AFTER regex.match,
   so a multi-MB attacker payload could pin a portal worker.
   **Fixed:** length-cap moved BEFORE regex, AND regex rewritten to
   ``^[^@\\s.]+(?:\\.[^@\\s.]+)*@[^@\\s.]+(?:\\.[^@\\s.]+)+$`` —
   classes now exclude ``.`` so the literal dot is unambiguous and
   matching is linear.

Patterns that LOOKED suspicious but are safe
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* ``worker._email._EMAIL_ADDR_RE`` — has nested ``(?:label\\.)+``,
  but caller enforces ``len(addr) > 254`` BEFORE the regex (see
  ``_validate_email_address``). Max work is bounded.
* ``hack_tracker.models._SCRIPT_TAG_RE`` / ``_HTML_TAG_RE`` — ``\\s*``
  quantifiers are non-overlapping (literal text or distinct classes
  between them); linear.
* ``logging_setup`` redaction patterns — all anchor on a literal prefix
  (``Bearer ``, ``sk-``, ``AKIA``, etc.) and have linear quantifiers.
* ``portal.intake._BTC_ADDR_RE``, ``_SOL_ADDR_RE``, ``_TRON_ADDR_RE``,
  ``_EVM_ADDR_RE`` — single character class with bounded ``{n,m}``
  quantifier; linear.
* ``worker._pdf_links._EXPLORER_URL_RE`` / ``_RENDERED_ADDRESS_RE`` —
  no nested quantifiers; linear scans across the PDF text.
* ``worker._flow_diagram`` anchor / edge / text patterns — operate on
  trusted Graphviz-generated SVG, not attacker input.

The tests below exercise the regexes most exposed to attacker input
and assert each completes within a tight wall-clock budget.
"""
from __future__ import annotations

import re
import time

import pytest

# ----------------------------------------------------------------------
# Budget helper. We use wall-clock rather than ``signal.alarm`` because
# the worker also runs on Windows in dev environments and POSIX-only
# signals would skip those builds.
# ----------------------------------------------------------------------
_BUDGET_SECONDS = 1.0


def _time(fn, *args, **kwargs) -> float:
    t0 = time.perf_counter()
    fn(*args, **kwargs)
    return time.perf_counter() - t0


# ----------------------------------------------------------------------
# 1. portal.intake._EMAIL_RE — the pattern that was actually ReDoS-prone.
# ----------------------------------------------------------------------

def test_intake_email_regex_no_redos_on_long_input_without_dot():
    """``a@<huge-no-dot>`` used to take polynomial time to fail because
    the two ``[^@\\s]+`` classes both admit ``.``, forcing the engine
    to backtrack over every possible split point. Hardened regex
    excludes ``.`` from the host-part class so the dot separator is
    unambiguous and matching is linear."""
    from recupero.portal.intake import _EMAIL_RE

    hostile = "a@" + ("a" * 50_000)  # no dot in host → forced full backtrack
    elapsed = _time(_EMAIL_RE.match, hostile)
    assert elapsed < _BUDGET_SECONDS, (
        f"_EMAIL_RE took {elapsed:.3f}s on a 50k-char no-dot host — "
        "ReDoS regression. Check portal/intake.py."
    )


def test_intake_email_regex_no_redos_on_many_dots_no_at():
    """Many dots, no ``@``. Pre-fix the engine had to try every
    placement of the ``@`` boundary."""
    from recupero.portal.intake import _EMAIL_RE

    hostile = ("a." * 10_000) + "a"  # 20001 chars, no @
    elapsed = _time(_EMAIL_RE.match, hostile)
    assert elapsed < _BUDGET_SECONDS, (
        f"_EMAIL_RE took {elapsed:.3f}s on a 10k-dot input — "
        "ReDoS regression."
    )


def test_validate_intake_payload_rejects_huge_email_fast():
    """End-to-end: even before reaching the regex, ``validate_intake_payload``
    must reject a multi-MB email field via the length-cap. This is the
    real attacker entry-point (HTTP form submission)."""
    from recupero.portal.intake import (
        IntakeValidationError,
        validate_intake_payload,
    )

    hostile_email = "a@" + ("a" * 1_000_000)  # 1 MB email
    form = {
        "client_name": "Alice",
        "client_email": hostile_email,
        "seed_address": "0x" + "a" * 40,
        "chain": "ethereum",
        "incident_date_iso": "2025-01-01",
        "description": "test",
    }
    t0 = time.perf_counter()
    with pytest.raises(IntakeValidationError) as excinfo:
        validate_intake_payload(form)
    elapsed = time.perf_counter() - t0
    assert elapsed < _BUDGET_SECONDS, (
        f"validate_intake_payload took {elapsed:.3f}s on a 1MB email — "
        "length-cap must run BEFORE the regex."
    )
    assert excinfo.value.field == "client_email"


def test_intake_email_regex_still_accepts_legitimate_addresses():
    """Behavior preservation: the hardened regex must continue to accept
    real-world addresses."""
    from recupero.portal.intake import _EMAIL_RE

    for good in (
        "alice@example.com",
        "alice.bob@example.com",
        "alice+filter@mail.example.co.uk",
        "user_123@sub.domain.io",
        "a@b.co",
    ):
        assert _EMAIL_RE.match(good), f"hardened _EMAIL_RE rejected legit address: {good!r}"


def test_intake_email_regex_still_rejects_obvious_typos():
    """Behavior preservation: the hardened regex must continue to
    reject the kinds of typos the original was written to catch."""
    from recupero.portal.intake import _EMAIL_RE

    for bad in (
        "no-at-sign.com",
        "no-dot-after-at@example",
        "@no-local.com",
        "spaces in@local.com",
        "two@@example.com",
        "trailing-dot@example.",
        ".leading-dot@example.com",  # double dot or leading dot
        "a..b@example.com",          # consecutive dots in local part
    ):
        assert not _EMAIL_RE.match(bad), (
            f"hardened _EMAIL_RE accepted obvious typo: {bad!r}"
        )


# ----------------------------------------------------------------------
# 2. worker._email._EMAIL_ADDR_RE — protected by length cap; assert.
# ----------------------------------------------------------------------

def test_email_addr_regex_protected_by_length_cap():
    """``_EMAIL_ADDR_RE`` has nested ``(?:label\\.)+`` quantifiers but
    is reachable only via ``_validate_email_address`` which enforces
    ``len(addr) > 254`` BEFORE the regex. This test asserts the
    length-cap path is taken (returns False fast) on a pathological
    input, never letting the regex see it."""
    from recupero.worker._email import _validate_email_address

    # Pathological label-cluster shape: 100 short labels + no TLD.
    # Length > 254 → length-cap short-circuits before regex runs.
    hostile = "x@" + ("a." * 200) + "!"  # length ~ 403
    elapsed = _time(_validate_email_address, hostile)
    assert elapsed < _BUDGET_SECONDS, (
        f"_validate_email_address took {elapsed:.3f}s — length-cap "
        "guard regressed."
    )
    assert _validate_email_address(hostile) is False


def test_email_addr_regex_within_length_cap_completes_fast():
    """Within the 254-char cap, ``_EMAIL_ADDR_RE`` still has bounded
    nested quantifiers. Worst-case pathological is sub-cap input that
    forces backtracking on the TLD anchor."""
    from recupero.worker._email import _validate_email_address

    # Right at the boundary: 50 short labels (~150 chars) ending in
    # a char the TLD class rejects, so the engine has to walk back.
    hostile = "x@" + ("ab." * 50) + "1"  # ends with digit, TLD requires [A-Za-z]
    assert len(hostile) < 254
    elapsed = _time(_validate_email_address, hostile)
    assert elapsed < _BUDGET_SECONDS, (
        f"_validate_email_address took {elapsed:.3f}s on a sub-cap "
        "pathological label-cluster — regex needs hardening."
    )


# ----------------------------------------------------------------------
# 3. hack_tracker.models._SCRIPT_TAG_RE / _HTML_TAG_RE — sub() on
#    attacker-controlled tweet text. Length-bound: title=200, summary=2000.
# ----------------------------------------------------------------------

def test_script_tag_regex_linear_on_pathological_input():
    """``<\\s*/?\\s*script[^>]*>`` — verify the two ``\\s*`` are
    non-overlapping (separated by literal ``script``) and matching is
    linear even on huge whitespace runs."""
    from recupero.hack_tracker.models import _SCRIPT_TAG_RE

    hostile = "<" + (" " * 100_000) + "/script" + (" " * 100_000) + ">"
    elapsed = _time(_SCRIPT_TAG_RE.sub, "", hostile)
    assert elapsed < _BUDGET_SECONDS, (
        f"_SCRIPT_TAG_RE took {elapsed:.3f}s on 200k whitespace — "
        "regex needs hardening."
    )


def test_html_tag_regex_linear_on_pathological_input():
    """The HTML-stripping path on hack_tracker text fields must survive
    a multi-MB never-closing-`<` payload in well under 1s.

    The raw `_HTML_TAG_RE` regex (`<\\s*/?\\s*[a-zA-Z][^>]*>`) is itself
    polynomial on `<<<<...` runs without `>` — every `<` triggers a
    walk-to-end. The W11-01 defense is a 16KB length cap in the
    field validator (`_scrub_text`), so the regex never sees the
    pathological input. Test the production path, not the bare regex."""
    import time as _t

    from pydantic import ValidationError

    from recupero.hack_tracker.models import HackEvent

    hostile = "<" + ("a" * 5_000_000)  # 5MB, never-closing tag
    # The HackEvent model also enforces max_length (200/2000) on
    # title/summary so the 5MB input will be REJECTED by Pydantic
    # AFTER `_scrub_text` runs. Either outcome is fine for the
    # ReDoS test: what matters is that we finish in well under
    # _BUDGET_SECONDS. A pre-W11 worktree would spend 45s in the
    # regex backtrack before Pydantic even saw the value.
    start = _t.perf_counter()
    try:
        HackEvent(
            source="test", source_url="https://x.com/a",
            title=hostile, summary=hostile,
            severity="low",
            addresses=[], tx_hashes=[],
            observed_at="2026-01-01T00:00:00+00:00",
        )
    except ValidationError:
        # Expected: title/summary exceed the field max_length. The
        # validators ran fast (the cap kicked in before the regex).
        pass
    elapsed = _t.perf_counter() - start
    assert elapsed < _BUDGET_SECONDS, (
        f"HackEvent construction took {elapsed:.3f}s on 5MB hostile "
        "title/summary — _scrub_text length cap regressed or "
        "_HTML_TAG_RE is being applied without the cap."
    )


# ----------------------------------------------------------------------
# 4. worker._pdf_links._RENDERED_ADDRESS_RE — runs on rendered HTML/PDF
#    text. Pathological: 50k chars of a single base58-class character.
# ----------------------------------------------------------------------

def test_rendered_address_regex_linear_on_huge_base58_run():
    """``finditer`` across 50k chars matching the base58 class. Each
    match consumes 4-44 chars greedily; total work must be linear."""
    from recupero.worker._pdf_links import _RENDERED_ADDRESS_RE

    hostile = "a" * 50_000
    elapsed = _time(lambda: list(_RENDERED_ADDRESS_RE.finditer(hostile)))
    assert elapsed < _BUDGET_SECONDS, (
        f"_RENDERED_ADDRESS_RE took {elapsed:.3f}s on 50k chars — "
        "regex needs hardening."
    )


# ----------------------------------------------------------------------
# 5. logging_setup redaction patterns — run on EVERY log line. ReDoS
#    here would brick the worker as soon as a long-line log statement
#    fires.
# ----------------------------------------------------------------------

def test_logging_redact_linear_on_huge_log_line():
    """``_redact`` chains ~12 ``sub()`` calls over a single string.
    A 1 MB log line must redact in well under a second."""
    from recupero.logging_setup import _redact

    hostile = (
        "log prefix " + ("A" * 500_000) + " Bearer "
        + ("Z" * 100) + " trailing " + ("B" * 500_000)
    )
    elapsed = _time(_redact, hostile)
    assert elapsed < _BUDGET_SECONDS, (
        f"_redact took {elapsed:.3f}s on a 1MB log line — one of the "
        "redaction patterns regressed to non-linear."
    )


# ----------------------------------------------------------------------
# 6. Static sanity: enumerate every re.compile in src/recupero and
#    assert NO pattern contains the classic ReDoS shape ``(X+)+`` or
#    ``(X*)*`` literally. This is a coarse grep-style check that
#    future-proofs the audit — if anyone adds a literal ``)+``
#    immediately after a ``+)`` or ``*)``, this test flags it.
# ----------------------------------------------------------------------

def test_no_nested_unbounded_quantifier_in_src_recupero():
    """Walk every ``.py`` file under ``src/recupero`` and grep for the
    *catastrophic* nested-quantifier shape — a quantified group whose
    body ALSO ends in an unbounded quantifier, with no alternation-
    distinguishing prefix.

    Safe forms like ``(?:\\.X+)+`` (each iteration is anchored by a
    literal ``\\.``) and ``([^x]*)*`` (where the group body excludes
    the group separator) are not flagged. We flag only:

      * ``(X+)+`` / ``(X+)*`` / ``(X*)+`` / ``(X*)*`` where ``X`` is
        a single character class with NO leading literal anchor and
        NO ``?:\\.`` style separator inside the group.

    The check is heuristic; the empirical tests above are the
    primary defense. This guard exists to flag a future regression
    where someone writes a literal ``(\\w+)+`` or similar.
    """
    import pathlib

    root = pathlib.Path(__file__).parent.parent / "src" / "recupero"
    # Flag e.g. (\w+)+, (.+)+, (a+)*, ([abc]+)+ — group body starts
    # immediately with a class/dot/escape and ends with +/*, group
    # quantified by +/*. Excludes non-capturing-with-literal-prefix
    # like (?:\.X+)+ via the (?!\?:) lookahead.
    bad = re.compile(
        r"\((?!\?:)"      # opening paren, not (?:
        r"(?:\\[wWdDsS]|\[[^\]]+\]|\.)"  # body: \w/\d/\s class or [..] or .
        r"[+*]"           # inner unbounded quantifier
        r"\)"             # close paren
        r"[+*]"           # outer unbounded quantifier
    )
    offenders: list[str] = []
    for py in root.rglob("*.py"):
        for lineno, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if '"' not in line and "'" not in line:
                continue
            if bad.search(line):
                offenders.append(
                    f"{py.relative_to(root.parent.parent)}:{lineno}: {line.strip()}"
                )
    assert not offenders, (
        "Found classic nested-quantifier regex shape (X+)+ — "
        "these are catastrophic-backtracking ReDoS constructs:\n"
        + "\n".join(offenders)
    )
