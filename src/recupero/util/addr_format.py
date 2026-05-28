"""Canonical address truncation.

v0.32.1 cross-cutting polish pass (Jacob audit §3.1): pre-v0.32.1 the
codebase had 17+ ad-hoc truncations: some 6+4, some 10+6, some prefix-only
with ``...`` ellipsis, some prefix-only with ``…`` ellipsis. The audit
flagged this as the wince-factor #4 — same address rendering differently
in the brief PDF vs the LE-handoff PDF made it impossible for an operator
to diff artifacts by eye.

This module is the single source of truth for display-truncation. All
human-facing addresses (briefs, LE handoff, freeze letter prose, log
lines, audit-trail rows) go through :func:`short_address`. The default
6+4 with a true unicode ellipsis ``…`` matches the v0.16.10 helper
``recupero._common.short_addr``, which now delegates here.

Do NOT use this for storage. The canonical storage form is the full,
lower-cased / base58 address from ``canonical_address_key``. Truncation
is presentation-only.

Examples
--------
>>> short_address("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1")
'0x742d…bEb1'

>>> short_address("TXYZopqrSTUVwxyz1234567890abcdefGHIJ")
'TXYZop…GHIJ'

>>> short_address(None)
''

>>> short_address("0xabc")
'0xabc'

>>> short_address("0xABCDEF1234567890ABCDEF1234567890ABCDEF12", prefix=8, suffix=6)
'0xABCDEF…CDEF12'
"""

from __future__ import annotations

from typing import Optional

__all__ = ["short_address"]


# Canonical ellipsis character. We use the unicode horizontal ellipsis
# (U+2026) rather than three ASCII dots to keep the truncation visually
# distinct from arbitrary "..." in URLs, prose, or paths. All non-ASCII-
# safe consumers (e.g. PDF rendering where the font might miss U+2026)
# should explicitly request ``ascii_safe=True``.
_ELLIPSIS = "…"


def short_address(
    addr: Optional[str],
    prefix: int = 6,
    suffix: int = 4,
    *,
    ascii_safe: bool = False,
) -> str:
    """Truncate an address for display.

    Canonical form: ``0xABCD12…1234`` (6 leading + horizontal-ellipsis +
    4 trailing). Used everywhere user-facing addresses appear: briefs,
    LE handoff PDFs, freeze letters, log lines, dashboard, CLI.

    Args:
        addr: The address string to truncate. ``None`` and empty string
            both return the empty string. Strings shorter than
            ``prefix + suffix + 1`` are returned unchanged.
        prefix: Number of leading characters to preserve. Default 6.
        suffix: Number of trailing characters to preserve. Default 4.
        ascii_safe: When True, uses ``...`` (three ASCII dots) instead
            of the unicode ``…`` ellipsis. Use for environments where
            the rendering font lacks U+2026 (some legacy PDF fonts).

    Returns:
        The truncated string. Empty string for falsy inputs.

    Raises:
        ValueError: if ``prefix < 0`` or ``suffix < 0``.
    """
    if prefix < 0 or suffix < 0:
        raise ValueError(
            f"short_address: prefix and suffix must be non-negative; "
            f"got prefix={prefix}, suffix={suffix}"
        )
    if not addr:
        return ""
    # Below the meaningful-truncation threshold, return unchanged. We
    # add +1 so that we don't ever waste characters: truncating an
    # 11-char address to ``XXXXXX…XXXX`` (also 11 chars) saves zero
    # and just makes it harder to read.
    if len(addr) < prefix + suffix + 1:
        return addr
    sep = "..." if ascii_safe else _ELLIPSIS
    return f"{addr[:prefix]}{sep}{addr[-suffix:] if suffix else ''}"
