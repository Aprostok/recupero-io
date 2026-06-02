"""Address / entity profile API + operator console (v0.35.14 — roadmap F3).

"Type any address → instant profile" — the Arkham / TRM / Chainalysis surface an
analyst reaches for first. It runs the existing local-seed screener
(``screen_address`` — offline, no network; correlation DB optional + graceful)
and presents a single profile view: risk verdict + score, exposure tags
(OFAC / mixer / ransomware / drainer), the label hits with source + confidence,
the cross-case sighting history, and the investigator note.

Security model mirrors ``watchlist_api`` (the established secure-shell pattern):
the CONSOLE at ``/v1/address/console`` is served unauthenticated and carries NO
data; every value is fetched client-side from the admin-gated JSON endpoint with
the operator's ``X-Recupero-Admin-Key`` (a browser navigation can't send a custom
header, so gating the HTML would force the key into the URL/logs).

  * ``GET /v1/address/profile?address=&chain=`` — admin-gated profile JSON
  * ``GET /v1/address/console``                 — unauthenticated shell (no data)

Forensic posture: the profile reports only what the screener found — label
confidence is carried through verbatim (high only for authoritative hits), and
nothing is inferred or fabricated. An empty profile means "no local-seed hit",
not "clean" in any guaranteed sense; the view says so.
"""

from __future__ import annotations

import hmac
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Header, HTTPException, status
from fastapi.responses import HTMLResponse

if TYPE_CHECKING:  # pragma: no cover
    from recupero.screen.screener import ScreeningResult

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/address", tags=["address"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "address_profile.html"
)

# Max accepted address length (longest supported is ~ Solana base58 ~44; we
# allow generous headroom but cap to reject junk / DoS-y inputs).
_MAX_ADDR_LEN = 128

# verdict → display band (the screener's verdict vocabulary).
_VERDICT_BAND = {
    "sanctioned": "SANCTIONED",
    "high": "HIGH RISK",
    "medium": "MEDIUM RISK",
    "low": "LOW RISK",
    "clean": "NO LOCAL-SEED HIT",
}


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Duplicated from watchlist_api to keep this module standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="address profile API disabled — set RECUPERO_ADMIN_KEY to enable",
        )
    if not provided or not provided.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing X-Recupero-Admin-Key",
        )
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid X-Recupero-Admin-Key",
        )


def build_address_profile(result: ScreeningResult) -> dict[str, Any]:
    """PURE: a ``ScreeningResult`` → a presentation-oriented profile dict.

    Carries the screener's verdict/score/labels/correlation through verbatim
    (no new inference), adds a display band + the active exposure tags + a
    flagged flag + an explicit honesty note when nothing matched.
    """
    base = result.to_json_safe()
    verdict = str(base.get("risk_verdict") or "clean")
    tags: list[str] = []
    if base.get("is_ofac_sanctioned"):
        tags.append("OFAC-sanctioned")
    if base.get("is_mixer"):
        tags.append("Mixer")
    if base.get("is_ransomware"):
        tags.append("Ransomware")
    if base.get("is_drainer"):
        tags.append("Drainer")

    labels = base.get("labels") or []
    correlation = base.get("correlation") or {}
    flagged = bool(tags) or verdict not in ("clean", "low")

    profile = {
        "address": base.get("address"),
        "chain": base.get("chain"),
        "verdict": verdict,
        "risk_band": _VERDICT_BAND.get(verdict, verdict.upper()),
        "risk_score": base.get("risk_score"),
        "is_flagged": flagged,
        "exposure_tags": tags,
        "label_count": len(labels),
        "labels": labels,
        "sighting_history": correlation,
        "investigator_note": base.get("investigator_note") or "",
        "data_sources_used": base.get("data_sources_used") or [],
    }
    if not flagged and not labels:
        profile["note"] = (
            "No local-seed or correlation hit for this address. This is NOT a "
            "guarantee the address is clean — only that it is absent from the "
            "screened seed sets and prior cases. Run a full trace for assurance."
        )
    return profile


@router.get(
    "/profile",
    summary=(
        "Instant address profile: risk verdict + score, exposure tags, label "
        "hits (source + confidence), cross-case sighting history. Admin-gated."
    ),
)
def get_address_profile(
    address: str,
    chain: str = "ethereum",
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    addr = (address or "").strip()
    if not addr or len(addr) > _MAX_ADDR_LEN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"address must be 1..{_MAX_ADDR_LEN} chars",
        )
    chain_norm = (chain or "ethereum").strip().lower()[:32] or "ethereum"
    from recupero.screen.screener import screen_address
    try:
        # use_correlation_db=True degrades gracefully when SUPABASE_DB_URL is
        # unset (the screener skips the DB lookup), so this stays a fast,
        # offline-capable local-seed screen by default.
        result = screen_address(addr, chain=chain_norm, use_correlation_db=True)
    except Exception as exc:  # noqa: BLE001
        log.warning("address profile screen failed for %r: %s", addr, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="screening unavailable",
        ) from None
    return build_address_profile(result)


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Address-profile operator console (HTML shell). Unauthenticated by "
        "design — contains NO data; fetches /v1/address/profile client-side."
    ),
)
def address_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("address_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Address console unavailable</h1>"
                "<p>Template could not be read; use <code>recupero screen</code>.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router", "build_address_profile")
