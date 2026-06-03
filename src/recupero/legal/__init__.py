"""Legal-information helpers (NOT legal advice).

This package produces *legal-information* references — most importantly a
time-sensitivity / statute-of-limitations advisory for the victim and engaged
law enforcement. Recupero is an investigation firm, not counsel; everything
here is general information that MUST be confirmed with licensed counsel in the
relevant jurisdiction before it is relied upon.

Design discipline (mirrors the verified-aware exchange-freeze contacts):
  * Every limitation period carries a REAL statutory citation. We never invent
    a citation — an entry with no verifiable citation is not shipped.
  * We seed only the few periods we can cite accurately (US federal criminal
    limitations). Everything else resolves to an explicit "confirm with
    counsel" placeholder rather than a fabricated period.
"""

from __future__ import annotations

from recupero.legal.limitations import (
    LimitationReference,
    load_limitation_overrides,
    normalize_jurisdiction,
    resolve_limitations,
)
from recupero.legal.time_sensitivity import (
    TimeSensitivity,
    build_time_sensitivity,
)

__all__ = (
    "LimitationReference",
    "TimeSensitivity",
    "build_time_sensitivity",
    "load_limitation_overrides",
    "normalize_jurisdiction",
    "resolve_limitations",
)
