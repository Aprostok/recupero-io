"""Bulk address-screening operator console + admin JSON endpoint (v0.35.18).

The high-throughput sibling of ``/v1/address`` (single-address profile): paste a
list of addresses, screen them all at once through the E2 high-throughput cache
(``cached_screen`` — load-once high-risk DB + lock-guarded result LRU) and the
E5 multi-sanctions seeds, and read back a compact risk table. Each result is
turned into a presentation dict by the SAME pure assembler the single-address
profile uses (``build_address_profile``), so verdict / band / labels are
byte-identical to the profile view — nothing here re-derives or invents fields.

Security model mirrors ``/v1/address`` and ``/v1/freshness`` (the established
secure-shell pattern): the CONSOLE at ``/v1/screen/console`` is served
unauthenticated and carries NO data; every value is fetched client-side from the
admin-gated JSON endpoints with the operator's ``X-Recupero-Admin-Key`` (a
browser navigation cannot send a custom header, so gating the HTML would force
the key into the URL/logs).

  * ``GET /v1/screen?addresses=&chain=`` — admin-gated bulk-screen JSON
  * ``GET /v1/screen/cache-stats``       — admin-gated cache hit/miss snapshot
  * ``GET /v1/screen/console``           — unauthenticated shell (no data)

Forensic posture: the screen path is OFFLINE (local-seed DB only; correlation is
intentionally not cached) and reports only what the seeds found. A bad address
yields a per-entry ``error`` rather than failing the batch, and the address list
is deduped + capped at 100 with an explicit ``truncated`` flag — never silently
dropped.
"""

from __future__ import annotations

import hmac
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status
from fastapi.responses import HTMLResponse

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/screen", tags=["screening"])

_CONSOLE_HTML = (
    Path(__file__).resolve().parent.parent
    / "web" / "templates" / "screening_console.html"
)

# Max addresses screened per request. Beyond this the extras are dropped and the
# response carries truncated=True (never a silent cap).
_MAX_ADDRESSES = 100

# Max accepted address length — reject junk / DoS-y inputs (matches the
# single-address profile route's cap).
_MAX_ADDR_LEN = 128


def _require_admin_auth(provided: str | None) -> None:
    """503 when RECUPERO_ADMIN_KEY is unset (deny-by-default); 401 otherwise.
    Duplicated from address_profile / freshness_api to keep this module
    standalone-importable."""
    expected = (os.environ.get("RECUPERO_ADMIN_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="screening API disabled — set RECUPERO_ADMIN_KEY to enable",
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


def _parse_addresses(raw: str) -> tuple[list[str], bool]:
    """Split on commas/newlines, strip, drop empties, dedupe (order-preserving),
    cap at ``_MAX_ADDRESSES``. Returns (addresses, truncated)."""
    seen: set[str] = set()
    out: list[str] = []
    truncated = False
    for chunk in (raw or "").replace("\r", "\n").replace(",", "\n").split("\n"):
        addr = chunk.strip()
        if not addr or addr in seen:
            continue
        if len(out) >= _MAX_ADDRESSES:
            truncated = True
            break
        seen.add(addr)
        out.append(addr)
    return out, truncated


@router.get(
    "/cache-stats",
    summary=(
        "Screening-cache hit/miss/size snapshot (E2 high-throughput cache). "
        "Admin-gated."
    ),
)
def get_cache_stats(
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    try:
        from recupero.screen.screen_cache import cache_stats
        return cache_stats()
    except Exception as exc:  # noqa: BLE001
        log.warning("cache-stats failed: %s", exc)
        return {"error": "cache stats unavailable"}


@router.get(
    "",
    summary=(
        "Bulk address screen — paste comma/newline-separated addresses, get a "
        "per-address risk verdict/band/labels table via the high-throughput "
        "cache (offline local-seed). Deduped + capped at 100. Admin-gated."
    ),
)
def bulk_screen(
    addresses: str,
    chain: str = "ethereum",
    x_recupero_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_admin_auth(x_recupero_admin_key)
    addrs, truncated = _parse_addresses(addresses)
    if not addrs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="no addresses supplied (comma- or newline-separated)",
        )
    chain_norm = (chain or "ethereum").strip().lower()[:32] or "ethereum"

    from recupero.api.address_profile import build_address_profile
    from recupero.screen.screen_cache import cached_screen

    results: list[dict[str, Any]] = []
    for addr in addrs:
        if len(addr) > _MAX_ADDR_LEN:
            results.append({"address": addr, "error": "address too long"})
            continue
        try:
            result = cached_screen(addr, chain=chain_norm)
            profile = build_address_profile(result)
            results.append({
                "address": addr,
                "verdict": profile.get("verdict"),
                "risk_band": profile.get("risk_band"),
                "score": profile.get("risk_score"),
                "labels": profile.get("labels"),
                "label_count": profile.get("label_count"),
                "flagged": profile.get("is_flagged"),
            })
        except Exception as exc:  # noqa: BLE001
            log.warning("bulk-screen failed for %r: %s", addr, exc)
            results.append({"address": addr, "error": "screen failed"})

    return {
        "results": results,
        "count": len(results),
        "chain": chain_norm,
        "truncated": truncated,
    }


@router.get(
    "/console",
    response_class=HTMLResponse,
    summary=(
        "Bulk-screening operator console (HTML shell). Unauthenticated by "
        "design — contains NO data; fetches /v1/screen client-side with the key."
    ),
)
def screening_console() -> HTMLResponse:
    try:
        html = _CONSOLE_HTML.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("screening_console: template read failed: %s", exc)
        return HTMLResponse(
            content=(
                "<h1>Bulk Screening console unavailable</h1>"
                "<p>Template could not be read; use <code>recupero screen</code>.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


__all__ = ("router",)
