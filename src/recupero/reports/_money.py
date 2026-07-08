"""Canonical USD parse/format helpers for the reports layer.

Historically ``_parse_usd_string`` and ``usd`` were copy-pasted into
``emit_brief.py`` and ``legal_requests.py`` (the latter's docstring even
confessed it was a "local copy of emit_brief._parse_usd_string ... kept
here to avoid importing the heavy emit_brief module"). The copies had
*diverging* semantics that this module now makes explicit rather than
accidental:

* parsing — ``emit_brief`` kept a **lenient** parse (does not clamp
  negative / non-finite values), whereas ``legal_requests`` used a
  **strict** parse that collapses negative / non-finite to ``0``. Both
  behaviours are preserved via :func:`parse_usd_lenient` and
  :func:`parse_usd`.
* formatting — ``emit_brief.usd`` trims cents on round numbers
  (``"$47,840"``) and renders ``None`` as ``"$0"``; ``legal_requests.usd``
  always shows cents (``"$47,840.00"``) and renders ``None`` as
  ``"$0.00"``. Preserved via :func:`format_usd_trim` and
  :func:`format_usd_cents`.

This is a tiny, dependency-free module so any code path can import the
canonical helpers without dragging in the heavy ``emit_brief`` module.
The two report modules keep their existing public names
(``_parse_usd_string`` / ``usd``) as thin delegators so imports and
rendered output stay byte-identical.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation


def _strip(value: object) -> str:
    """Normalize a raw USD-ish value into a bare numeric string."""
    return str(value).replace("$", "").replace(",", "").strip()


def parse_usd_lenient(value: object) -> Decimal:
    """Parse ``'$47,840.12'`` -> ``Decimal('47840.12')``. ``0`` on failure.

    Lenient: negative and non-finite values pass through unchanged (matches
    the historical ``emit_brief._parse_usd_string``).
    """
    cleaned = _strip(value)
    try:
        return Decimal(cleaned)
    except (InvalidOperation, ValueError):
        return Decimal("0")


def parse_usd(value: object) -> Decimal:
    """Parse ``'$47,840.12'`` -> ``Decimal('47840.12')``. ``0`` on failure.

    Strict / forensic-safe: empty, non-finite (NaN/Inf) and negative inputs
    all collapse to ``Decimal('0')`` (matches the historical
    ``legal_requests._parse_usd_string``).
    """
    cleaned = _strip(value)
    try:
        d = Decimal(cleaned) if cleaned else Decimal("0")
    except (InvalidOperation, ValueError):
        return Decimal("0")
    if not d.is_finite() or d < 0:
        return Decimal("0")
    return d


def format_usd_trim(v: Decimal | float | int | None) -> str:
    """Format a USD amount trimming cents on round numbers.

    ``None`` / non-finite -> ``"$0"``; ``47840`` -> ``"$47,840"``;
    ``47840.12`` -> ``"$47,840.12"``. Matches ``emit_brief.usd``.
    """
    if v is None:
        return "$0"
    try:
        d = Decimal(str(v))
    except (InvalidOperation, ValueError):
        return "$0"
    if not d.is_finite():
        return "$0"
    if d == d.to_integral_value():
        return f"${int(d):,}"
    return f"${d:,.2f}"


def format_usd_cents(v: Decimal | None) -> str:
    """Format a USD amount always showing cents.

    ``None`` / non-finite -> ``"$0.00"``; ``47840`` -> ``"$47,840.00"``;
    ``47840.12`` -> ``"$47,840.12"``. Matches ``legal_requests.usd``.
    """
    if v is None:
        return "$0.00"
    # Coerce first (matches format_usd_trim): a bare ``.is_finite()`` on a float
    # NaN/Inf would raise AttributeError and crash brief rendering rather than
    # fall back — so a stray float can't take down a court-facing document.
    try:
        d = Decimal(str(v))
    except (InvalidOperation, ValueError):
        return "$0.00"
    if not d.is_finite():
        return "$0.00"
    if d == d.to_integral_value():
        return f"${int(d):,}.00"
    return f"${d:,.2f}"
