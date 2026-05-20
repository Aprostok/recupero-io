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


def _docs_locked_in_production() -> bool:
    """v0.18.9 (round-11 api-MED-005): lock /docs, /openapi.json,
    /redoc in production. Operator opt-in via
    RECUPERO_API_DOCS_PUBLIC=1 to re-expose."""
    import os as _os
    if (_os.environ.get("RECUPERO_API_DOCS_PUBLIC", "") or "").strip() == "1":
        return False
    try:
        from recupero.api.auth import _is_production_environment
        return _is_production_environment()
    except Exception:  # noqa: BLE001
        return False


app = FastAPI(
    title="Recupero API",
    description=(
        "Authenticated REST surface for Recupero's wallet "
        "screening / token-risk / correlation capabilities. "
        "Designed for integration by exchanges, KYC providers, "
        "recovery attorneys, and OSINT teams."
    ),
    version=_resolve_version(),
    # v0.18.9 (round-11 api-MED-005): /docs, /openapi.json, /redoc
    # auth-gate in production. Pre-v0.18.9 these were unconditionally
    # public — the OpenAPI spec leaks the full endpoint surface +
    # Pydantic model shapes + internal field names. In production
    # opt-in only via RECUPERO_API_DOCS_PUBLIC=1.
    docs_url="/docs" if not _docs_locked_in_production() else None,
    openapi_url="/openapi.json" if not _docs_locked_in_production() else None,
    redoc_url="/redoc" if not _docs_locked_in_production() else None,
)


# ---- Request / response models ---- #

# v0.19.2 (round-13 type-HIGH-3): supported-chain enum for API request
# validation. Pre-v0.19.2 the request models accepted any `chain: str`
# — Pydantic let `chain="foobar"` through, the screener then failed
# deep inside with a TypeError that surfaced as a confusing 400.
# Now: Pydantic returns a 422 up-front listing the allowed values.
# Mirrors `recupero.models.Chain` (we don't import that enum directly
# because Chain is a `str` Enum that pickles oddly through FastAPI
# OpenAPI; a Literal keeps the OpenAPI spec readable).
from typing import Literal as _Literal

_SupportedChain = _Literal[
    "ethereum", "arbitrum", "base", "bsc", "polygon",
    "solana", "tron", "bitcoin", "hyperliquid",
]


class ScreenRequest(BaseModel):
    # v0.19.2 (round-13 sec-MED-5 follow-on): max_length cap on the
    # address field so an authenticated caller can't POST a 16MB
    # address string and force downstream lookups to walk it.
    address: str = Field(
        ..., min_length=1, max_length=128,
        description="Wallet address to screen.",
    )
    chain: _SupportedChain = Field(
        "ethereum",
        description="Chain hint — one of the supported chains.",
    )
    use_correlation_db: bool = Field(
        True,
        description=(
            "If True, includes cross-case correlation history. "
            "If False, the screen runs against local seed files only."
        ),
    )


class TokenRiskRequest(BaseModel):
    contract_address: str = Field(
        ..., min_length=1, max_length=128,
        description="Token contract address.",
    )
    chain: _SupportedChain = Field("ethereum")
    # v0.18.9 (round-11 api-MED-004): cap at 64KB hex (32KB binary).
    # Real contract bytecode tops out around ~24KB binary at the
    # EIP-170 contract-size limit; 64KB hex is 2.7× headroom for
    # init-code analysis. Without the cap a malicious caller can
    # POST a 16MB hex string (FastAPI's default body cap) and
    # quadratic-worst-case the bytecode-heuristic regex pass.
    bytecode: str | None = Field(
        None, max_length=65536,
        description=(
            "Optional contract runtime bytecode (hex). When supplied, "
            "the bytecode-heuristic pass runs to detect honeypot "
            "selectors (setBuyTax, setMaxTxAmount, etc.). Capped at "
            "64KB hex (= 32KB binary, 2.7× EIP-170 limit)."
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
        # v0.18.2 (round-11 sec-HIGH-005, api-MED-002): generic detail.
        # Pre-v0.18.2 the message leaked the internal env-var name.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="correlation lookup unavailable",
        )
    try:
        from recupero.trace.correlation import lookup_correlations
        results = lookup_correlations([address], dsn=dsn)
    except Exception as e:  # noqa: BLE001
        # v0.18.2 (round-11 sec-HIGH-005): psycopg's exception messages
        # routinely embed the full DSN with embedded password
        # ("FATAL: password authentication failed for user 'postgres'
        # at host 'db.xxxxxx.supabase.co:6543'"). Pre-v0.18.2 we echoed
        # that verbatim to the API consumer. Now: log server-side
        # (where _redact strips the DSN) but return a generic detail
        # to the wire.
        log.warning("correlation lookup failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="correlation lookup failed",
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


# ---- v0.21.0: freeze-outcome intake endpoint ---- #


class FreezeOutcomeIn(BaseModel):
    """Inbound payload for ``POST /v1/freeze-outcomes``.

    The caller (issuer compliance team via portal, AUSA via webhook,
    operator via Postman) identifies the freeze letter by the same
    triple that uniquely identifies it in our database:
      (case_id, issuer, target_address)

    + ``asset_symbol`` when more than one asset per (issuer, address)
    is plausible. Without asset_symbol the lookup picks the most
    recent letter matching the triple, which is fine for the common
    single-asset case.
    """
    case_id: str = Field(..., description="The case UUID as a string.")
    issuer: str = Field(..., min_length=1, max_length=200)
    target_address: str = Field(..., min_length=4, max_length=128)
    outcome_type: str = Field(
        ...,
        description=(
            "One of: acknowledged, request_more_info, declined, "
            "partial_freeze, full_freeze, released, returned_to_victim, "
            "silence_14d, silence_30d, silence_90d."
        ),
    )
    asset_symbol: str | None = Field(default=None, max_length=32)
    frozen_usd: float | None = Field(default=None, ge=0)
    returned_usd: float | None = Field(default=None, ge=0)
    response_text: str | None = Field(default=None, max_length=8000)
    operator_notes: str | None = Field(default=None, max_length=2000)


@app.post(
    "/v1/freeze-outcomes",
    tags=["freeze"],
    summary="Record an issuer response to a freeze letter (v0.21.0).",
    status_code=status.HTTP_201_CREATED,
)
async def record_freeze_outcome_endpoint(
    req: FreezeOutcomeIn,
    api_key_name: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Insert a freeze_outcomes row for the freeze letter identified
    by (case_id, issuer, target_address[, asset_symbol]).

    Designed for two integration paths:

    1. **Exchange compliance teams.** Once we've issued enough freeze
       letters to a given exchange, we hand them a per-exchange API
       key + this endpoint URL. They POST acknowledgements / freeze
       confirmations directly into our system — no email parsing, no
       operator data entry, no time lag.

    2. **Operator-driven webhooks.** A compliance team that does NOT
       have an API integration can still close the loop: an AUSA's
       paralegal forwards the issuer's response email to a webhook
       parser (out of scope here), which fires this endpoint.

    Returns: ``{outcome_id, letter_id, recorded_at}`` on success.

    Errors:
      * 404 — no freeze letter matches the supplied triple
      * 422 — invalid outcome_type (Pydantic + recorder validation)
      * 503 — DB unavailable
    """
    from decimal import Decimal
    from uuid import UUID

    import os
    dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="freeze-outcome intake unavailable",
        )

    try:
        case_uuid = UUID(req.case_id)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="case_id is not a valid UUID",
        ) from None

    try:
        from recupero.freeze_learning.recorder import (
            LetterNotFoundError,
            VALID_OUTCOME_TYPES,
            record_outcome_by_target,
        )
    except ImportError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"recorder unavailable: {e}",
        ) from e

    if req.outcome_type not in VALID_OUTCOME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"outcome_type must be one of "
                f"{sorted(VALID_OUTCOME_TYPES)}"
            ),
        )

    try:
        outcome_id = record_outcome_by_target(
            case_id=case_uuid,
            issuer=req.issuer,
            target_address=req.target_address,
            asset_symbol=req.asset_symbol,
            outcome_type=req.outcome_type,
            frozen_usd=Decimal(str(req.frozen_usd)) if req.frozen_usd is not None else None,
            returned_usd=Decimal(str(req.returned_usd)) if req.returned_usd is not None else None,
            response_text=req.response_text,
            operator_notes=req.operator_notes,
            dsn=dsn,
        )
    except LetterNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from None
    except ValueError as e:  # outcome_type invalid (defense-in-depth)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        ) from None
    except RuntimeError as e:
        # Don't leak DSN / internal error details to the caller.
        log.warning(
            "/v1/freeze-outcomes record failed for case=%s issuer=%s: %s",
            req.case_id, req.issuer, e,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="freeze-outcome record failed",
        ) from None

    log.info(
        "/v1/freeze-outcomes api_key=%s case=%s issuer=%s outcome=%s "
        "outcome_id=%s",
        api_key_name, req.case_id, req.issuer, req.outcome_type, outcome_id,
    )
    return {
        "outcome_id": str(outcome_id),
        "case_id": req.case_id,
        "issuer": req.issuer,
        "outcome_type": req.outcome_type,
        "recorded_at": time.time(),
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
