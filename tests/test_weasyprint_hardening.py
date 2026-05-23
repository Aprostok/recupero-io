"""W7-02 — WeasyPrint subprocess hardening (SSRF + scheme allowlist).

WeasyPrint by default fetches any URL referenced from an HTML
deliverable (``<img src>``, ``@font-face url()``, ``<link href>``,
``@import``, ``<image href>`` in SVG). The editorial AI controls
text in INCIDENT_NARRATIVE_* and is a prompt-injection vector — a
hostile editor could slip a fetch into the rendered HTML and:

  * Hit the cloud metadata service (http://169.254.169.254/...)
  * Exfiltrate case identifiers via referer / DNS
  * Decode an arbitrary payload via ``data:`` URLs that the
    pre-W7-02 fetcher allowed through (it only rejected http/https/ftp)

The fix is a strict allowlist: empty + ``file:`` schemes only, with
the resolved path constrained to ``case_dir`` via ``realpath`` +
``commonpath`` (not naive ``startswith``, which is vulnerable to
sibling-prefix attacks like ``/case_dir_evil/...``).
"""

from __future__ import annotations

import inspect
import os
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from recupero.worker import _deliverables
from recupero.worker._deliverables import validate_url_for_weasyprint


# ---------------------------------------------------------------------------
# 1. Remote schemes — every network-capable scheme must raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/iam/credentials",
        "https://attacker.example/exfil.css",
        "ftp://attacker.example/font.ttf",
        "http://localhost:8080/internal",
        "http://railway.internal/secrets",
    ],
)
def test_remote_scheme_refused(url: str) -> None:
    """http / https / ftp must all raise — these are the classic
    SSRF exfil vectors. The cloud-metadata IP is the canary case:
    a successful fetch leaks IAM credentials in the response body.
    """
    with TemporaryDirectory() as tmp, pytest.raises(ValueError):
        validate_url_for_weasyprint(url, tmp)


# ---------------------------------------------------------------------------
# 2. ``data:`` URLs — the pre-W7-02 gap. Pre-fix the fetcher only rejected
#    http/https/ftp and fell through to default_url_fetcher for data:,
#    which would decode arbitrary inline payloads (CSS @import, fonts,
#    images). Now refused by the allowlist.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "data:text/css,@import%20url('http://attacker/exfil.css');",
        "data:font/woff2;base64,d09GMgABAAAA...",
        "data:image/svg+xml,<svg onload=alert(1)/>",
    ],
)
def test_data_url_refused(url: str) -> None:
    """``data:`` is a network-free scheme but still untrusted — it
    carries inline payloads the editorial AI prompt-injection can
    embed. Allowlist-based rejection catches it."""
    with TemporaryDirectory() as tmp, pytest.raises(ValueError):
        validate_url_for_weasyprint(url, tmp)


# ---------------------------------------------------------------------------
# 3. Exotic schemes — gopher, sftp, jar, javascript: all refused.
#    Pre-W7-02 these silently passed to default_url_fetcher because the
#    rejection list was http/https/ftp only.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "gopher://attacker.example/_GET%20/",
        "sftp://attacker.example/key",
        "jar:http://attacker.example/x.jar!/META-INF/",
        "javascript:alert(1)",
        "blob:https://attacker.example/abc",
    ],
)
def test_exotic_scheme_refused(url: str) -> None:
    """Allowlist policy rejects every scheme outside ('', 'file')."""
    with TemporaryDirectory() as tmp, pytest.raises(ValueError):
        validate_url_for_weasyprint(url, tmp)


# ---------------------------------------------------------------------------
# 4. Out-of-tree file:// paths refused — even with valid scheme,
#    a path outside case_dir is refused (would otherwise read /etc/shadow
#    via file:///etc/shadow).
# ---------------------------------------------------------------------------


def test_file_url_outside_case_dir_refused() -> None:
    """``file:///etc/shadow`` must raise even though the scheme is
    allowlisted — the boundary check rejects out-of-tree resolved paths.
    """
    with TemporaryDirectory() as tmp, pytest.raises(ValueError):
        # Use a path guaranteed not under tmp.
        outside = os.path.abspath(os.sep + "etc" + os.sep + "shadow")
        validate_url_for_weasyprint(f"file://{outside}", tmp)


# ---------------------------------------------------------------------------
# 5. Sibling-prefix attack — naive startswith allows /tmp_evil to match /tmp.
#    The fix uses commonpath, which respects path-component boundaries.
# ---------------------------------------------------------------------------


def test_sibling_prefix_attack_refused() -> None:
    """Pre-W7-02 the boundary check was ``path.startswith(_case_dir)``.
    If case_dir was ``/var/case_a`` then ``/var/case_a_evil/payload.css``
    passed the prefix check despite being a different directory.
    The commonpath-based check rejects this — case_a_evil's commonpath
    with case_a is ``/var``, not ``/var/case_a``.
    """
    with TemporaryDirectory() as parent:
        case_dir = Path(parent) / "case_a"
        case_dir.mkdir()
        evil_dir = Path(parent) / "case_a_evil"
        evil_dir.mkdir()
        evil_file = evil_dir / "payload.css"
        evil_file.write_text("body{}", encoding="utf-8")
        with pytest.raises(ValueError):
            validate_url_for_weasyprint(str(evil_file), str(case_dir))


# ---------------------------------------------------------------------------
# 6. In-tree file is allowed — the happy path
# ---------------------------------------------------------------------------


def test_in_tree_file_allowed() -> None:
    """A file genuinely inside case_dir must not raise — this is the
    legitimate case (flow_<hash>.svg, embedded fonts, etc.).
    """
    with TemporaryDirectory() as tmp:
        f = Path(tmp) / "flow.svg"
        f.write_text("<svg/>", encoding="utf-8")
        # Must not raise.
        validate_url_for_weasyprint(str(f), tmp)


# ---------------------------------------------------------------------------
# 7. Inline subprocess scripts contain the hardened policy. Defense-in-depth
#    static check — the validator above is testable in-process, but the
#    actual render runs in a subprocess with its own copy of the policy.
#    If a future edit weakens the inline script, this test catches it.
# ---------------------------------------------------------------------------


def test_inline_subprocess_script_uses_strict_allowlist() -> None:
    """Both _html_to_pdf and _svg_to_pdf embed their fetcher policy as
    a string literal in the subprocess script. Verify the strict
    allowlist phrases are present and the pre-W7-02 weak phrases are
    absent.
    """
    html_src = inspect.getsource(_deliverables._html_to_pdf)
    svg_src = inspect.getsource(_deliverables._svg_to_pdf)

    for src, label in ((html_src, "_html_to_pdf"), (svg_src, "_svg_to_pdf")):
        # Strict allowlist: scheme NOT IN ('', 'file') → reject
        assert "scheme not in ('','file')" in src or "scheme not in ('', 'file')" in src, (
            f"{label}: strict allowlist phrase missing — fetcher must reject "
            f"every scheme outside ('', 'file')"
        )
        # Boundary check upgraded to commonpath
        assert "commonpath" in src, (
            f"{label}: commonpath-based boundary check missing — startswith "
            f"is vulnerable to sibling-prefix attacks (/case_dir_evil/...)"
        )
        # realpath used to resolve symlinks
        assert "realpath" in src, (
            f"{label}: realpath missing — symlink-inside-case_dir can "
            f"point at /etc/shadow and pass a non-realpath boundary check"
        )
        # Sanity: the weak pre-W7-02 phrase "in ('http', 'https', 'ftp')"
        # MUST be gone — that was the explicit-blocklist policy that
        # silently passed data:, gopher:, etc.
        assert "in ('http', 'https', 'ftp')" not in src, (
            f"{label}: weak explicit-blocklist phrase still present — "
            f"this lets data:/gopher:/sftp: fall through to default fetcher"
        )
