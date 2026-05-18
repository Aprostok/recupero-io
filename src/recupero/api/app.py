"""FastAPI app for Recupero's REST service (v0.15.1).

Exposes screening / token-risk / correlation as authenticated
REST endpoints. The CLI commands all share the same underlying
pure-function implementations — the API is a thin wrapper that
adds auth + rate limiting + OpenAPI surface.

Run via ``recupero-api`` (console script) or directly with
``uvicorn recupero.api.app:app``.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from recupero.api.auth import require_api_key

log = logging.getLogger(__name__)


# Module-load time for /v1/health uptime reporting.
_BOOT_AT = time.time()


def _resolve_version() -> str:
    """Best-effort version lookup so /v1/health surfaces the
    deployed release."""
    try:
        from importlib.metadata import version as _v
        return _v("recupero")
    except Exception:  # noqa: BLE001
        return "unknown"


def _resolve_git_sha() -> str | None:
    """Read git HEAD sha from RECUPERO_GIT_SHA env (set at deploy
    time) so /v1/health can confirm the deployed commit."""
    import os as _os
    sha = _os.environ.get("RECUPERO_GIT_SHA", "").strip()
    return sha or None


app = FastAPI(
    title="Recupero API",
    description=(
        "Authenticated REST surface for Recupero's wallet "
        "screening / token-risk / correlation capabilities. "
        "Designed for integration by exchanges, KYC providers, "
        "recovery attorneys, and OSINT teams."
    ),
    version=_resolve_version(),
    docs_url="/docs",
    openapi_url="/openapi.json",
    redoc_url="/redoc",
)


# ---- Request / response models ---- #


class ScreenRequest(BaseModel):
    address: str = Field(..., description="Wallet address to screen.")
    chain: str = Field(
        "ethereum",
        description=(
            "Chain hint: 'ethereum' | 'arbitrum' | 'base' | 'bsc' | "
            "'polygon' | 'solana' | 'tron' | 'bitcoin'."
        ),
    )
    use_correlation_db: bool = Field(
        True,
        description=(
            "If True, includes cross-case correlation history. "
            "If False, the screen runs against local seed files only."
        ),
    )


class TokenRiskRequest(BaseModel):
    contract_address: str = Field(..., description="Token contract address.")
    chain: str = Field("ethereum")
    bytecode: str | None = Field(
        None,
        description=(
            "Optional contract runtime bytecode (hex). When supplied, "
            "the bytecode-heuristic pass runs to detect honeypot "
            "selectors (setBuyTax, setMaxTxAmount, etc.)."
        ),
    )
    tx_history_stats: dict[str, Any] | None = Field(
        None,
        description=(
            "Optional tx-history aggregates: buy_count, "
            "sell_success_count, lp_removed_within_24h_of_launch."
        ),
    )
    goplus_result: dict[str, Any] | None = Field(
        None,
        description=(
            "Optional GoPlus Security API response. Caller fetches "
            "from GoPlus; this endpoint interprets it."
        ),
    )


class HealthResponse(BaseModel):
    status: str
    version: str
    git_sha: str | None
    uptime_seconds: float


# ---- Endpoints ---- #


@app.get(
    "/v1/health",
    response_model=HealthResponse,
    tags=["meta"],
    summary="Liveness check + deployed version info",
)
async def health() -> HealthResponse:
    """Returns process status, deployed version, optional git SHA,
    and uptime. The deploy script's --skip-health=false path GETs
    this to confirm Railway is running the expected build.

    No auth required — health checks must work for unauthenticated
    probes (Railway, Kubernetes, etc.).
    """
    return HealthResponse(
        status="ok",
        version=_resolve_version(),
        git_sha=_resolve_git_sha(),
        uptime_seconds=round(time.time() - _BOOT_AT, 1),
    )


@app.post(
    "/v1/screen",
    tags=["screening"],
    summary="Score an address against OFAC + mixer + correlation data",
)
async def screen_address_endpoint(
    req: ScreenRequest,
    api_key_name: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Wallet-screening lookup. Uses ONLY local seed data + correlation
    DB; no on-chain RPC calls. Latency < 50ms with DB lookup.

    Returns:
      ``{ address, chain, risk_verdict, risk_score, is_ofac_sanctioned,
          is_mixer, is_ransomware, is_drainer, labels, correlation,
          investigator_note, data_sources_used }``.
    """
    try:
        from recupero.screen.screener import screen_address
    except ImportError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"screener module unavailable: {e}",
        ) from e

    try:
        result = screen_address(
            req.address,
            chain=req.chain,
            use_correlation_db=req.use_correlation_db,
        )
    except (TypeError, ValueError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    log.info("/v1/screen api_key=%s address=%s verdict=%s",
             api_key_name, req.address, result.risk_verdict)
    return result.to_json_safe()


@app.post(
    "/v1/token-risk",
    tags=["screening"],
    summary="Score a token contract for honeypot / rug-pull risk",
)
async def token_risk_endpoint(
    req: TokenRiskRequest,
    api_key_name: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Token honeypot / rug-pull risk score. Caller-supplied
    inputs only — this endpoint doesn't make any on-chain calls.
    The bytecode + tx_history + goplus_result inputs all feed the
    score; passing none returns 'clean' (no signals).
    """
    try:
        from recupero.token_risk.scorer import score_token
    except ImportError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"token-risk scorer unavailable: {e}",
        ) from e

    try:
        result = score_token(
            req.contract_address,
            chain=req.chain,
            bytecode=req.bytecode,
            tx_history_stats=req.tx_history_stats,
            goplus_result=req.goplus_result,
        )
    except (TypeError, ValueError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e

    log.info(
        "/v1/token-risk api_key=%s contract=%s verdict=%s",
        api_key_name, req.contract_address, result.verdict,
    )
    return result.to_json_safe()


@app.get(
    "/v1/correlations/{address}",
    tags=["screening"],
    summary="Cross-case correlation lookup for one address",
)
async def correlation_endpoint(
    address: str,
    chain: str = "ethereum",
    api_key_name: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Cross-case correlation lookup. Returns prior-case count plus
    OFAC / mixer / drainer exposure flags if any."""
    import os
    dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="correlation DB not configured (SUPABASE_DB_URL unset)",
        )
    try:
        from recupero.trace.correlation import lookup_correlations
        results = lookup_correlations([address], dsn=dsn)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"correlation lookup failed: {e}",
        ) from e
    found = results.get(address.lower()) or results.get(address)
    if found is None:
        return {
            "address": address,
            "chain": chain,
            "total_prior_cases": 0,
            "found": False,
        }
    return {
        "address": found.address,
        "chain": found.chain,
        "total_prior_cases": found.total_prior_cases,
        "prior_ofac_exposed_count": found.prior_ofac_exposed_count,
        "prior_mixer_exposed_count": found.prior_mixer_exposed_count,
        "prior_drainer_attributed_count": found.prior_drainer_attributed_count,
        "prior_total_usd_flowed": str(found.prior_total_usd_flowed),
        "prior_roles_seen": found.prior_roles_seen,
        "found": True,
    }


# ---- Uvicorn entry point ---- #


def main() -> None:  # pragma: no cover
    """``recupero-api`` console-script entry. Runs the app via
    uvicorn on host/port from env vars."""
    import os
    import uvicorn
    host = os.environ.get("RECUPERO_API_HOST", "0.0.0.0")
    port = int(os.environ.get("RECUPERO_API_PORT", "8000"))
    log_level = os.environ.get("RECUPERO_LOG_LEVEL", "info").lower()
    uvicorn.run(
        "recupero.api.app:app",
        host=host, port=port, log_level=log_level,
    )


__all__ = ("app", "main")
