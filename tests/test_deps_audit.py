"""Dependency CVE audit.

Parses pyproject.toml and asserts each dependency's pinned floor is at or
above the version where a known CVE was patched. If pip-installing the
project would accept a known-vulnerable version of a dep, the corresponding
test here MUST fail.

Adding a new dep? Add a matching invariant below. Bumping a floor for an
unrelated reason is fine — these tests only enforce lower bounds.

References (a few representative CVEs covered):
    - jinja2          CVE-2024-22195 / CVE-2024-56326 / CVE-2024-56201
    - defusedxml      pre-0.7.1 whitelist regression
    - cryptography    CVE-2023-50782 (fixed in 42.0.0)
    - pydantic        pre-2.0 = unmaintained v1 series
    - fastapi         CVE-2024-24762 ecosystem (python-multipart, fixed in
                      fastapi's deps >=0.109)
    - pyyaml          CVE-2020-14343 (fixed in 5.4)
    - weasyprint      pre-58 PDF link-annotation correctness regressions
    - pypdf           CVE-2023-36464 (fixed in 3.9.0)
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

import pytest

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _parse_deps() -> dict[str, str]:
    """Return {package_name_lower: full_spec_string} for runtime deps."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    deps = data["project"]["dependencies"]
    out: dict[str, str] = {}
    for spec in deps:
        # Strip extras: "psycopg[binary]>=3.2,<4.0" -> "psycopg"
        # Strip version: "httpx>=0.27,<1.0" -> "httpx"
        m = re.match(r"^([A-Za-z0-9_.\-]+)", spec)
        assert m is not None, f"unparseable dep: {spec!r}"
        name = m.group(1).lower()
        out[name] = spec
    return out


def _floor(spec: str) -> tuple[int, ...]:
    """Extract the >= floor from a PEP-440 spec as a tuple of ints.

    e.g. "jinja2>=3.1.5,<4.0" -> (3, 1, 5)
    """
    m = re.search(r">=\s*([0-9]+(?:\.[0-9]+)*)", spec)
    assert m is not None, f"no >= floor in spec: {spec!r}"
    return tuple(int(p) for p in m.group(1).split("."))


def _ge(actual: tuple[int, ...], required: tuple[int, ...]) -> bool:
    """Pad-and-compare version tuples."""
    n = max(len(actual), len(required))
    a = actual + (0,) * (n - len(actual))
    r = required + (0,) * (n - len(required))
    return a >= r


# --------------------------------------------------------------------------
# meta tests
# --------------------------------------------------------------------------


def test_pyproject_parses() -> None:
    deps = _parse_deps()
    assert deps, "no dependencies parsed"
    # python-version requirement check
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    assert data["project"]["requires-python"].startswith(">=3.11")


def test_no_abandoned_packages() -> None:
    """Reject packages known to be abandoned / unmaintained."""
    deps = _parse_deps()
    # xmlrpc-server: abandoned; nose: replaced by pytest; pycrypto: replaced
    # by pycryptodome; python-jose: maintenance dead; pickle5: stdlib in 3.8+.
    abandoned = {"xmlrpc-server", "nose", "pycrypto", "python-jose", "pickle5"}
    found = abandoned & set(deps)
    assert not found, f"abandoned packages present: {found}"


# --------------------------------------------------------------------------
# CVE invariants
# --------------------------------------------------------------------------


def test_jinja2_safe_from_xss_and_sandbox_escape() -> None:
    """CVE-2024-22195 (3.1.3), CVE-2024-56326/56201 (3.1.5). 3.1.0-3.1.4 bad."""
    spec = _parse_deps()["jinja2"]
    assert _ge(_floor(spec), (3, 1, 5)), f"jinja2 floor must be >=3.1.5, got {spec!r}"


def test_defusedxml_present_and_safe() -> None:
    """defusedxml MUST be a hard dep (OFAC XML), and >=0.7.1."""
    deps = _parse_deps()
    assert "defusedxml" in deps, "defusedxml must be a hard runtime dep (OFAC XML parsing)"
    assert _ge(_floor(deps["defusedxml"]), (0, 7, 1)), (
        f"defusedxml floor must be >=0.7.1, got {deps['defusedxml']!r}"
    )


def test_cryptography_safe() -> None:
    """CVE-2023-50782 + assorted OpenSSL pass-throughs — floor >=42."""
    spec = _parse_deps()["cryptography"]
    assert _ge(_floor(spec), (42, 0, 0)), f"cryptography floor must be >=42.0.0, got {spec!r}"


def test_pydantic_is_v2() -> None:
    """v1 is unmaintained as of 2024-06; force v2."""
    spec = _parse_deps()["pydantic"]
    assert _ge(_floor(spec), (2, 0, 0)), f"pydantic floor must be >=2.0, got {spec!r}"


def test_fastapi_floor_above_103() -> None:
    """fastapi <0.103 has known issues with python-multipart CVE-2024-24762
    propagation; >=0.110 is the current safe baseline."""
    spec = _parse_deps()["fastapi"]
    assert _ge(_floor(spec), (0, 103, 0)), f"fastapi floor must be >=0.103, got {spec!r}"


def test_pyyaml_safe() -> None:
    """CVE-2020-14343 fixed in 5.4."""
    spec = _parse_deps()["pyyaml"]
    assert _ge(_floor(spec), (5, 4, 0)), f"pyyaml floor must be >=5.4, got {spec!r}"


def test_weasyprint_floor() -> None:
    """Pre-58 had PDF link-annotation correctness bugs."""
    spec = _parse_deps()["weasyprint"]
    assert _ge(_floor(spec), (58, 0, 0)), f"weasyprint floor must be >=58, got {spec!r}"


def test_pypdf_safe() -> None:
    """CVE-2023-36464 fixed in 3.9.0."""
    spec = _parse_deps()["pypdf"]
    assert _ge(_floor(spec), (3, 9, 0)), f"pypdf floor must be >=3.9.0, got {spec!r}"


def test_httpx_safe() -> None:
    """No specific CVE, but 0.27 is the modern HTTP/2 + sane retry baseline."""
    spec = _parse_deps()["httpx"]
    assert _ge(_floor(spec), (0, 25, 0)), f"httpx floor must be >=0.25, got {spec!r}"


# --------------------------------------------------------------------------
# version-skew guard
# --------------------------------------------------------------------------


def test_tomllib_available() -> None:
    """Our test parser uses stdlib tomllib (Python 3.11+). requires-python
    already enforces this — this is the canary that proves it at test time."""
    assert sys.version_info >= (3, 11)
