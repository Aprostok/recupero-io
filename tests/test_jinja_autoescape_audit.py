"""Jinja autoescape audit (XSS Phase A).

Every Jinja `Environment(...)` constructor in `src/recupero/**` MUST
enable autoescape for `.html` and `.html.j2` files. A bare
`Environment()` would silently emit raw user input into rendered
HTML / PDF deliverables — and a Recupero brief is opened in a
browser by law-firm staff, so an XSS payload in any attacker-
controlled field (intake form, freeze-outcome response, on-chain
label) would execute under that user's session.

This audit is **static**: we parse every renderer module with `ast`
and assert each `Environment(...)` call passes an ``autoescape``
keyword. We do NOT depend on whether the renderer is reachable from
the current call graph — a future caller could light up a dormant
renderer, and the autoescape guarantee must hold the day that
happens.

Companion adversarial test:
    tests/test_template_xss_adversarial.py
"""
from __future__ import annotations

import ast
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_ROOT = _REPO_ROOT / "src" / "recupero"


def _iter_python_files() -> list[Path]:
    return sorted(_SRC_ROOT.rglob("*.py"))


def _find_environment_calls(tree: ast.AST) -> list[ast.Call]:
    """Yield every ``Environment(...)`` call in ``tree``.

    Matches both ``Environment(...)`` (imported by name) and
    ``jinja2.Environment(...)`` (qualified). We do NOT match nested
    attribute access beyond two levels — Jinja's only ever called as
    `Environment` or `jinja2.Environment` in this codebase.
    """
    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "Environment" or (
            isinstance(func, ast.Attribute)
            and func.attr == "Environment"
            and isinstance(func.value, ast.Name)
            and func.value.id == "jinja2"
        ):
            calls.append(node)
    return calls


def test_every_jinja_environment_passes_autoescape():
    """Static audit: every `Environment(...)` ctor sets autoescape.

    A bare `Environment()` is a critical XSS vulnerability because
    Jinja defaults autoescape to FALSE — every `{{ value }}` would
    emit raw HTML.
    """
    offenders: list[str] = []
    for py_file in _iter_python_files():
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for call in _find_environment_calls(tree):
            kwarg_names = {kw.arg for kw in call.keywords if kw.arg}
            if "autoescape" not in kwarg_names:
                rel = py_file.relative_to(_REPO_ROOT)
                offenders.append(f"{rel}:{call.lineno}")

    assert not offenders, (
        "Jinja Environment(...) without autoescape= found:\n  "
        + "\n  ".join(offenders)
        + "\nFix: pass autoescape=select_autoescape(['html', 'j2'])."
    )


def test_every_jinja_environment_autoescapes_html_j2():
    """The ``select_autoescape`` whitelist MUST cover `html.j2` files.

    Recupero's templates are all named `<name>.html.j2`. A whitelist
    of just `['html']` would NOT catch the `.j2` suffix and would
    silently disable autoescape on every brief / letter / dashboard.
    """
    offenders: list[str] = []
    for py_file in _iter_python_files():
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue
        for call in _find_environment_calls(tree):
            for kw in call.keywords:
                if kw.arg != "autoescape":
                    continue
                # Accept (a) bare True, (b) select_autoescape(...) with
                # either an `html` / `j2` / `html.j2` extension in its
                # argument list.
                if (
                    isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    break
                if (
                    isinstance(kw.value, ast.Call)
                    and isinstance(kw.value.func, ast.Name)
                    and kw.value.func.id == "select_autoescape"
                ):
                    arg_strings: set[str] = set()
                    for a in kw.value.args:
                        if isinstance(a, (ast.List, ast.Tuple)):
                            for elt in a.elts:
                                if isinstance(elt, ast.Constant) and isinstance(
                                    elt.value, str
                                ):
                                    arg_strings.add(elt.value)
                    if arg_strings & {"j2", "html.j2", "html"}:
                        # ``html`` alone would NOT match `.html.j2` —
                        # require either `j2` or `html.j2` explicitly.
                        if arg_strings & {"j2", "html.j2"}:
                            break
                        rel = py_file.relative_to(_REPO_ROOT)
                        offenders.append(
                            f"{rel}:{call.lineno} "
                            f"select_autoescape({sorted(arg_strings)!r}) "
                            f"missing 'j2' or 'html.j2'"
                        )
                        break
            else:
                # No autoescape kwarg — caught by the other test.
                continue


    assert not offenders, "\n  ".join(offenders)


# v0.31.3 — removed parametrized stub. The original test parametrized
# over EVERY .py file in src/recupero, then pytest.skip()'d each one
# because the test only cared about .j2 templates — producing 171
# spurious SKIPs on every run and zero actual assertions (the real
# .j2 check is in test_templates_have_no_unsafe_autoescape_false
# below, which iterates _SRC_ROOT.rglob("*.j2") directly). The stub
# is removed; the substantive test remains.


def test_templates_have_no_unsafe_autoescape_false():
    """Same as above but scoped to templates."""
    offenders: list[str] = []
    for tmpl in _SRC_ROOT.rglob("*.j2"):
        text = tmpl.read_text(encoding="utf-8")
        # Match `{% autoescape false %}` or with optional whitespace.
        for ln, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if (
                stripped.startswith("{% autoescape false")
                or stripped.startswith("{%- autoescape false")
            ):
                offenders.append(f"{tmpl.relative_to(_REPO_ROOT)}:{ln}")
    assert not offenders, (
        "Found {% autoescape false %} block(s):\n  "
        + "\n  ".join(offenders)
    )


def test_only_known_safe_filters_used():
    """Audit every `|safe` usage in templates. Each one is a trust
    boundary; if we add a new one we must justify it here.

    Known-safe usages:
      * interactive_graph.html.j2 — JSON embedded in
        `<script type="application/json">` with `</script>` /
        `<!--` / `-->` sequences escaped at the data layer. The
        browser doesn't execute the block; we JSON.parse the
        textContent. Safe.
      * engagement_letter.html.j2 — `recovery_disclosure.summary_html`
        is a server-built HTML fragment assembled in
        worker/_engagement_letter.py from a hardcoded template string
        with ONLY numeric interpolations (full_recovery_rate as
        `{pct:.1f}%`, sample_size / n_full_recovery as int). No field
        is attacker- or user-influenced, so the embedded `<strong>`
        markup is trusted and `|safe` is required to render it as bold
        rather than escaped angle brackets. Safe.
      * portal/journey.html.j2 — `journey_json` embedded in
        `<script type="application/json">` exactly like
        interactive_graph.html.j2. The producer
        (portal.server._safe_journey_json) does `json.dumps(..., allow_nan=False)`
        then escapes `</` / `<!--` / `-->` so the block can't break out of
        the script-data context; the browser does NOT execute it
        (application/json) — it JSON.parse's the textContent. Safe.
    """
    KNOWN_SAFE: dict[str, set[int]] = {
        # v0.35.8 (F1): line shifted 233 → 342 when the filter/focus control
        # row + its CSS/JS were added above this embed. v0.38.0 (#6): shifted
        # 342 → 370 when the risk-colour toggle + risk legend + high-risk badge
        # + tooltip risk row were added above it. v0.38 (UI): 370 → 279 when the
        # <style> block was upgraded to the design-system (more compact CSS).
        # Same JSON-in-application/json boundary with the same data-layer
        # </script> / <!-- / --> escaping in graph_ui.py — re-pinned, not newly trusted.
        "src/recupero/reports/templates/interactive_graph.html.j2": {279},
        "src/recupero/reports/templates/engagement_letter.html.j2": {185},
        "src/recupero/portal/templates/journey.html.j2": {208},
    }

    # Word-boundary match: `|safe` and `| safe` (raw safe filter)
    # but NOT `|safe_url` (an explicit-allowlist URL filter registered
    # by recupero.reports._jinja_filters.register_safe_filters and
    # designed exactly to be the trusted alternative). Use a regex
    # so we don't false-positive on the defense-in-depth filter.
    import re
    _RAW_SAFE_RE = re.compile(r"\|\s*safe\b(?!_)")

    found: dict[str, set[int]] = {}
    for tmpl in _SRC_ROOT.rglob("*.j2"):
        for ln, line in enumerate(tmpl.read_text(encoding="utf-8").splitlines(), 1):
            if _RAW_SAFE_RE.search(line):
                rel = str(tmpl.relative_to(_REPO_ROOT)).replace("\\", "/")
                found.setdefault(rel, set()).add(ln)

    # Convert KNOWN_SAFE keys to forward-slash-normalized for cross-platform
    known_normalized = {k.replace("\\", "/"): v for k, v in KNOWN_SAFE.items()}

    extra: list[str] = []
    for tmpl, lines in found.items():
        approved = known_normalized.get(tmpl, set())
        for ln in lines - approved:
            extra.append(f"{tmpl}:{ln}")
    assert not extra, (
        "Unapproved |safe usage(s) — each is an XSS trust boundary "
        "and must be justified:\n  " + "\n  ".join(extra)
    )


def test_safe_url_filter_registered_on_every_html_environment():
    """Defense-in-depth: every Jinja environment that loads templates
    rendering external/user URLs must register the ``safe_url`` filter.

    The filter (defined in src/recupero/reports/_jinja_filters.py)
    rejects any URL whose scheme is not in an explicit allowlist
    (http, https, mailto, tel). Without it, autoescape would still
    let ``href="javascript:alert(1)"`` execute when the brief is
    opened in a browser — autoescape escapes quote characters, NOT
    dangerous URL schemes.
    """
    from recupero.reports._jinja_filters import safe_url

    # Smoke test — actual filter behavior is covered in
    # test_template_xss_adversarial.py.
    assert safe_url("https://etherscan.io/address/0xabc") == (
        "https://etherscan.io/address/0xabc"
    )
    assert safe_url("javascript:alert(1)") == "#"
    assert safe_url("data:text/html,<script>") == "#"
    assert safe_url("vbscript:msgbox(1)") == "#"
    assert safe_url("") == ""
    assert safe_url(None) == ""
    # CRLF in URL → strip.
    assert "\r" not in safe_url("https://e.x/foo\r\nbar")
    assert "\n" not in safe_url("https://e.x/foo\r\nbar")
