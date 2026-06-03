"""Regression: operator-console HTML must be bundled as package-data.

The operator console (`/v1/console`) and every per-phase console router read
their template via ``Path(__file__).parent... / "web" / "templates" / "*.html"``
+ ``.read_text()``. In the editable dev install that reads the source tree, so
it works locally — but a non-editable ``pip install .`` (the Docker/Railway
image) only ships files declared in ``[tool.setuptools.package-data]``. Before
this was declared, the templates were missing from the image and EVERY
``/v1/console*`` route returned 503 "Template could not be read" in production.

These tests lock the declaration + the on-disk presence so the regression
can't recur silently.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = REPO_ROOT / "src" / "recupero" / "web" / "templates"


def _package_data() -> dict:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return data["tool"]["setuptools"]["package-data"]


def test_web_templates_declared_in_package_data() -> None:
    """The api/operator_console.py hub + console routers read web/templates/*.html;
    those files MUST be declared as package-data or the deployed image 503s."""
    pkg_data = _package_data()
    assert "recupero.web.templates" in pkg_data, (
        "recupero.web.templates is not in [tool.setuptools.package-data]; the "
        "operator-console HTML won't ship in a non-editable install (Docker) "
        "and /v1/console* will 503."
    )
    globs = pkg_data["recupero.web.templates"]
    assert any(g == "*.html" or g.endswith(".html") for g in globs), (
        f"recupero.web.templates package-data must include an *.html glob; got {globs}"
    )


def test_hub_template_present_on_disk() -> None:
    """operator_dashboard.html is what the hub route reads; it must exist."""
    hub = TEMPLATES_DIR / "operator_dashboard.html"
    assert hub.is_file(), f"operator console hub template missing: {hub}"
    assert hub.stat().st_size > 0


def test_console_templates_are_html() -> None:
    """Every file the package-data glob is meant to cover is an .html template
    (sanity: the dir holds what we think it does, all bundled by *.html)."""
    files = list(TEMPLATES_DIR.glob("*.html"))
    assert len(files) >= 1, f"no console templates found under {TEMPLATES_DIR}"
    # All non-dunder files in the dir should be .html (so the *.html glob is
    # sufficient — nothing important is left unbundled).
    non_html = [
        p.name for p in TEMPLATES_DIR.iterdir()
        if p.is_file() and p.suffix.lower() not in {".html"} and not p.name.startswith("__")
    ]
    assert not non_html, (
        f"non-.html files in web/templates not covered by the *.html "
        f"package-data glob: {non_html}"
    )
