"""Deeper adversarial-input tests for _common helpers.

Wave-6 audit extension. Focus areas (per wave-5 follow-up):
  * pooled_dsn: password URL-encoding for `@`, `/`, `?`, `:` chars
  * canonical_address_key: bidi marks, NUL bytes, very-long inputs
  * atomic_write_text: mkstemp dir-existence semantics, symlink guard
  * investigator_defaults: env-var bleed-through and call-time read
  * db_connect: defaults are pooler-safe
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

# ---- pooled_dsn URL-encoding ---- #


def test_pooled_dsn_encodes_at_sign_in_password() -> None:
    """A password containing `@` must be percent-encoded in the rewritten
    DSN — otherwise libpq's URI parser splits on the literal `@` and
    routes the connection to the wrong host (or, worse, to an
    attacker-controlled hostname embedded in the leaked credential)."""
    from recupero._common import pooled_dsn

    src = "postgresql://user:p@ssword@db.abcref.supabase.co:5432/postgres"
    out = pooled_dsn(src)
    # The literal `@` of the password must not appear inside what would
    # be the userinfo segment of the rewritten URI. The rewritten DSN
    # has exactly ONE `@` (the userinfo/host delimiter); a leaked
    # password `@` would create a second one before that delimiter.
    # Count `@` occurrences AFTER the scheme `://`.
    body = out.split("://", 1)[1]
    assert body.count("@") == 1, (
        f"unencoded @ in password leaked into URI body: {out}"
    )
    # The literal substring `p@ssword` must not survive verbatim.
    assert "p@ssword" not in out, f"raw @ leaked: {out}"
    # And the encoded form should be present.
    assert "p%40ssword" in out, f"@ not percent-encoded: {out}"


def test_pooled_dsn_encodes_slash_and_question_mark() -> None:
    """`/` and `?` in the password break URI parsing (path / query
    delimiters). Both must be percent-encoded."""
    from recupero._common import pooled_dsn

    src = "postgresql://user:a/b?c:d@db.abcref.supabase.co/postgres"
    out = pooled_dsn(src)
    # The rewritten DSN's path is "/postgres" — any `/` from the
    # password must be encoded so we still see exactly one `/postgres`
    # path component.
    assert out.endswith("/postgres"), f"path corrupted: {out}"
    # No raw `?` should appear (would start a query string).
    body_after_userinfo = out.split("@", 1)[1]
    assert "?" not in body_after_userinfo or body_after_userinfo.find("?") > body_after_userinfo.find("/postgres"), (
        f"raw ? in host/path section: {out}"
    )
    assert "a/b" not in out, f"raw / in password: {out}"
    assert "a%2Fb" in out, f"/ not encoded: {out}"


def test_pooled_dsn_passthrough_for_already_pooled() -> None:
    """A DSN that doesn't match the direct-host pattern returns
    unchanged (no false rewrite)."""
    from recupero._common import pooled_dsn
    src = "postgresql://u:p@aws-1-us-east-1.pooler.supabase.com:6543/postgres"
    assert pooled_dsn(src) == src


# ---- canonical_address_key adversarial ---- #


def test_canonical_address_key_handles_nul_byte() -> None:
    """A NUL embedded in a hex-shaped address must not produce a
    silently-lower-cased canonical form — the bytes aren't valid hex,
    so the function must fall through to pass-through (not key as if
    it were a real EVM address)."""
    from recupero._common import canonical_address_key
    nul_addr = "0xDEADBEEF" + "0" * 32 + "\x00"  # 43 chars, has NUL
    out = canonical_address_key(nul_addr)
    # 43 chars → not the 42-char EVM shape → pass-through.
    assert out == nul_addr
    # Even if we squeeze to 42, embedded NUL fails hex validation:
    nul_addr42 = "0x" + "\x00" * 40
    out2 = canonical_address_key(nul_addr42)
    assert out2 == nul_addr42  # pass-through, not lower-cased.


def test_canonical_address_key_handles_bidi_override() -> None:
    """U+202E (Right-to-Left Override) inside an address must NOT
    pass the EVM hex check — the bidi control flips visual order so
    an attacker could craft an address that displays as one thing but
    keys as another. Fall through to pass-through."""
    from recupero._common import canonical_address_key
    # 42-char string starting with 0x, but one char is U+202E.
    bidi = "0xAB" + "‮" + "DEF" + "0" * 34
    assert len(bidi) == 42
    out = canonical_address_key(bidi)
    # U+202E is not in [0-9a-fA-F], so we must NOT lower-case-key it.
    assert out == bidi, f"bidi-poisoned addr was canonicalized: {out!r}"


def test_canonical_address_key_handles_very_long_input() -> None:
    """A 100k-char input must not crash and must not blow up the
    canonicalizer — it should pass through (or empty) quickly."""
    from recupero._common import canonical_address_key
    huge = "0x" + "a" * 100_000
    out = canonical_address_key(huge)
    # Not the 42-char shape → pass-through (verbatim).
    assert out == huge
    assert len(out) == 100_002


# ---- atomic_write_text additional ---- #


def test_atomic_write_text_refuses_symlink_target(tmp_path: Path) -> None:
    """Wave-3 hardening: writing through a symlink is rejected loud.

    v0.31.3 — uses the cross-platform link helper. On Windows the
    file-symlink path needs Dev Mode; if unavailable, the companion
    junction test below (which only requires `mklink /J`) catches
    the same is_link_like guard."""
    import pytest

    from recupero._common import atomic_write_text
    from tests._link_helper import LinkUnsupported, make_file_link
    real = tmp_path / "real.json"
    real.write_text("orig", encoding="utf-8")
    link = tmp_path / "link.json"
    try:
        make_file_link(real, link)
    except LinkUnsupported as e:
        pytest.skip(f"file symlink unavailable: {e}")
    with pytest.raises(ValueError, match="symlink"):
        atomic_write_text(link, "new content")
    # The real file must NOT have been modified.
    assert real.read_text(encoding="utf-8") == "orig"


def test_atomic_write_text_refuses_junction_target(tmp_path: Path) -> None:
    """v0.31.3 — Windows-only companion: writing through an NTFS
    junction is also rejected. Pre-v0.31.3 ``Path.is_symlink``
    returned False for junctions, leaving a Windows-only bypass.
    """
    import sys

    import pytest
    if sys.platform != "win32":
        pytest.skip("junctions are a Windows NTFS concept")

    from recupero._common import atomic_write_text
    from tests._link_helper import LinkUnsupported, make_dir_link

    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    (real_dir / "marker.txt").write_text("INTACT")

    # Plant a junction at the file path itself.
    link = tmp_path / "case.json"
    try:
        make_dir_link(real_dir, link)
    except LinkUnsupported as e:
        pytest.skip(f"junction unavailable: {e}")

    with pytest.raises(ValueError, match="symlink"):
        atomic_write_text(link, "new content")
    # Marker inside the junction target dir MUST be intact.
    assert (real_dir / "marker.txt").read_text() == "INTACT"


# ---- investigator_defaults env reads ---- #


def test_investigator_defaults_reads_at_call_time(monkeypatch) -> None:
    """A late env-var change must be reflected on the NEXT call —
    never module-cached."""
    from recupero._common import investigator_defaults
    monkeypatch.setenv("RECUPERO_INVESTIGATOR_NAME", "Alice")
    d1 = investigator_defaults()
    assert d1["INVESTIGATOR_NAME"] == "Alice"
    monkeypatch.setenv("RECUPERO_INVESTIGATOR_NAME", "Bob")
    d2 = investigator_defaults()
    assert d2["INVESTIGATOR_NAME"] == "Bob"


def test_investigator_defaults_uses_placeholder_when_unset(monkeypatch) -> None:
    """An unset name must produce an obvious placeholder so legal docs
    don't silently ship the developer's identity."""
    from recupero._common import investigator_defaults
    monkeypatch.delenv("RECUPERO_INVESTIGATOR_NAME", raising=False)
    d = investigator_defaults()
    assert "not configured" in d["INVESTIGATOR_NAME"].lower()


# ---- db_connect defaults ---- #


def test_db_connect_forwards_pooler_safe_defaults() -> None:
    """Critical: prepare_threshold=None, connect_timeout=10,
    autocommit=True. The whole point of this helper is these defaults."""
    from recupero._common import db_connect
    sentinel = MagicMock(name="conn")
    with patch("psycopg.connect", return_value=sentinel) as mc:
        db_connect("postgresql://u:p@h/d")
    _, kwargs = mc.call_args
    assert kwargs.get("prepare_threshold") is None
    assert kwargs.get("connect_timeout") == 10
    assert kwargs.get("autocommit") is True


def test_db_connect_override_wins() -> None:
    """Caller-supplied kwargs override the defaults (e.g., a caller
    that needs autocommit=False for a multi-statement transaction)."""
    from recupero._common import db_connect
    sentinel = MagicMock(name="conn")
    with patch("psycopg.connect", return_value=sentinel) as mc:
        db_connect("postgresql://u:p@h/d", autocommit=False, connect_timeout=2)
    _, kwargs = mc.call_args
    assert kwargs.get("autocommit") is False
    assert kwargs.get("connect_timeout") == 2
    # prepare_threshold default still applies.
    assert kwargs.get("prepare_threshold") is None
