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

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator

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
    import os
    from decimal import Decimal
    from uuid import UUID
    dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="freeze-outcome intake unavailable",
        )

    # v0.28.0 (S-1): multi-tenant authorization gate. Pre-v0.28 ANY
    # valid API key could write outcomes against ANY case/issuer.
    # Now the key must either be in RECUPERO_API_KEY_ADMINS (operator
    # keys) OR have the requested issuer in its
    # RECUPERO_API_KEY_ISSUERS allow-list. Default is deny.
    from recupero.api.auth import is_authorized_to_record_outcome
    if not is_authorized_to_record_outcome(
        api_key_name=api_key_name, issuer=req.issuer,
    ):
        # Mirror the 404 path's response shape so an unauthorized
        # caller can't distinguish "you don't own this issuer" from
        # "this letter doesn't exist" — both surface as 404 with the
        # same generic detail. Prevents enumeration of valid
        # (case_id, issuer, target_address) triples via response-code
        # oracle.
        log.warning(
            "/v1/freeze-outcomes DENIED for api_key=%s issuer=%s "
            "(missing admin/issuer allow-list entry)",
            api_key_name, req.issuer,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="freeze outcome not recorded",
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
            VALID_OUTCOME_TYPES,
            LetterNotFoundError,
            record_outcome_by_target,
        )
    except ImportError as e:
        # v0.28.0 (S-1 hardening): do not echo ImportError {e} into
        # the wire body — its string may contain file paths.
        log.warning(
            "/v1/freeze-outcomes recorder import failed: %s", e,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="freeze-outcome intake unavailable",
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
        # v0.28.0 (S-1): do not echo LetterNotFoundError detail
        # which contains the supplied (case_id, issuer, target_address)
        # triple. A response body that repeats the caller's input
        # lets a probing attacker confirm valid combinations via
        # response-body diff (vs an authorization-denied response).
        # Generic "freeze outcome not recorded" matches the
        # unauthorized branch above — indistinguishable from outside.
        log.info(
            "/v1/freeze-outcomes letter not found (api_key=%s "
            "case=%s issuer=%s): %s",
            api_key_name, req.case_id, req.issuer, e,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="freeze outcome not recorded",
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


# ---- v0.27.0: Exchange / compliance monitoring + bulk screening API ---- #


class MonitorSubscribeRequest(BaseModel):
    """Request body for POST /v1/monitor/subscribe.

    Audience: exchange compliance teams + KYC providers that want
    push notifications when an address moves. The supplied
    webhook_url receives a JSON POST with HMAC-SHA256 signing if
    webhook_secret is set.
    """
    address: str = Field(
        ..., min_length=1, max_length=256,
        description="Address to watch.",
    )
    chain: _SupportedChain = Field("ethereum")
    trigger_type: str = Field(
        ...,
        description=(
            "Trigger condition. One of: any_movement, "
            "movement_above_usd, balance_drop, ofac_contact."
        ),
    )
    threshold_usd: float | None = Field(
        None, ge=0,
        description=(
            "Required for movement_above_usd and balance_drop "
            "triggers. Ignored for any_movement / ofac_contact."
        ),
    )
    webhook_url: str = Field(
        ..., min_length=1, max_length=2048,
        description=(
            "Fully-qualified http(s)://… URL we POST to when the "
            "trigger fires."
        ),
    )
    label: str | None = Field(
        None, max_length=200,
        description="Friendly label for partner-side bookkeeping.",
    )
    webhook_secret: str | None = Field(
        None, max_length=256,
        description=(
            "Optional shared secret. When set, every webhook "
            "carries X-Recupero-Signature: hex(HMAC-SHA256(secret, "
            "payload)) so the partner can verify authenticity."
        ),
    )


class BulkScreenRequest(BaseModel):
    """Request body for POST /v1/screen/bulk.

    Compliance teams typically batch hundreds of addresses per
    minute. The single-address /v1/screen endpoint is fine for
    interactive flows, but a daily reconciliation against a
    sanctions list wants higher throughput per round-trip.
    """
    # v0.27.1 (CRIT-2): per-element length validator. The list-level
    # max_length=100 only caps the *list*; without a per-element cap
    # a partner could POST 100 × ~16MB strings and exhaust process
    # memory on parse + force pathological string ops downstream.
    addresses: list[str] = Field(
        ..., min_length=1, max_length=100,
        description=(
            "List of addresses to screen, max 100 per request. "
            "Larger batches: page through with multiple calls."
        ),
    )
    chain: _SupportedChain = Field("ethereum")
    use_correlation_db: bool = Field(
        False,
        description=(
            "Set True to include cross-case correlation lookup "
            "for each address. Adds DB hit per address; only enable "
            "when needed."
        ),
    )

    @field_validator("addresses")
    @classmethod
    def _validate_per_address_length(cls, v: list[str]) -> list[str]:
        """v0.27.1 (CRIT-2): each address must fit within 128 chars
        — parity with the single-address /v1/screen endpoint."""
        for i, addr in enumerate(v):
            if not addr or not addr.strip():
                raise ValueError(
                    f"addresses[{i}] is empty"
                )
            if len(addr) > 128:
                raise ValueError(
                    f"addresses[{i}] exceeds 128-character limit"
                )
        return v


@app.post(
    "/v1/monitor/subscribe",
    tags=["monitoring"],
    summary="Subscribe an address to webhook alerts (v0.27.0)",
    # PUNISH-A v0.27 fix: REST convention for resource-creation
    # endpoints is 201 Created. Pre-fix returned 200, which is
    # technically wrong (200 = "request succeeded, no new resource").
    # Partner integrations that branch on status_code (typical SDK
    # pattern: `if 200 <= status < 300: parse_body()`) would still
    # work, but 201 is the correct signal that a new row was made.
    status_code=status.HTTP_201_CREATED,
)
async def monitor_subscribe_endpoint(
    req: MonitorSubscribeRequest,
    api_key_name: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Create or update a monitoring subscription for the calling
    API key. Subscriptions are isolated per API key: partners
    cannot list / modify / delete subscriptions created by other
    keys.
    """
    import os
    from decimal import Decimal

    from recupero.api.monitoring_api import (
        MonitoringApiError,
        create_subscription,
    )

    dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="monitoring subscription unavailable",
        )

    threshold = (
        Decimal(str(req.threshold_usd))
        if req.threshold_usd is not None else None
    )

    try:
        record = create_subscription(
            api_key_name=api_key_name,
            address=req.address,
            chain=req.chain,
            trigger_type=req.trigger_type,
            threshold_usd=threshold,
            webhook_url=req.webhook_url,
            label=req.label,
            webhook_secret=req.webhook_secret,
            dsn=dsn,
        )
    except MonitoringApiError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{e.field}: {e.detail}",
        ) from None
    except RuntimeError as e:
        log.warning(
            "/v1/monitor/subscribe failed (api_key=%s): %s",
            api_key_name, e,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="subscription create failed",
        ) from None

    log.info(
        "/v1/monitor/subscribe api_key=%s subscription_id=%s "
        "address=%s chain=%s trigger=%s",
        api_key_name, record.id, record.address, record.chain,
        record.trigger_type,
    )
    return record.to_json_safe()


@app.get(
    "/v1/monitor/subscriptions",
    tags=["monitoring"],
    summary="List subscriptions belonging to the calling API key (v0.27.0)",
)
async def monitor_list_endpoint(
    api_key_name: str = Depends(require_api_key),
    limit: int = 100,
) -> dict[str, Any]:
    """Return the subscriptions created by this API key. The
    multi-tenant boundary is enforced server-side — there is no
    way to see another key's subscriptions through this endpoint.
    """
    import os

    from recupero.api.monitoring_api import (
        MonitoringDbError,
        list_subscriptions,
    )

    dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="monitoring lookup unavailable",
        )
    try:
        records = list_subscriptions(
            api_key_name=api_key_name, dsn=dsn, limit=limit,
        )
    except MonitoringDbError:
        # v0.27.1 (HIGH-5): surface DB blip as 503 instead of an
        # empty list that the partner would misread as "no subs."
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="monitoring lookup temporarily unavailable",
        ) from None
    # v0.27.1 (HIGH-4): list response masks the webhook URL to limit
    # leak impact if the partner's API key is compromised.
    return {
        "subscriptions": [
            r.to_json_safe(mask_webhook_url=True) for r in records
        ],
        "count": len(records),
    }


@app.get(
    "/v1/monitor/{subscription_id}",
    tags=["monitoring"],
    summary="Fetch one subscription by id (v0.27.0)",
)
async def monitor_get_endpoint(
    subscription_id: str,
    api_key_name: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Return the subscription with this id, ONLY if it was created
    by the calling API key. Foreign keys see a 404 (not a 403 —
    a 403 would leak the existence of the row to a probing attacker)."""
    import os
    from uuid import UUID as _UUID

    from recupero.api.monitoring_api import (
        MonitoringDbError,
        get_subscription,
    )

    try:
        sub_uuid = _UUID(subscription_id)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="subscription not found",
        ) from None

    dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="monitoring lookup unavailable",
        )
    try:
        record = get_subscription(
            api_key_name=api_key_name,
            subscription_id=sub_uuid,
            dsn=dsn,
        )
    except MonitoringDbError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="monitoring lookup temporarily unavailable",
        ) from None
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="subscription not found",
        )
    # v0.27.1 (HIGH-4): mask the webhook URL on read responses.
    return record.to_json_safe(mask_webhook_url=True)


@app.delete(
    "/v1/monitor/{subscription_id}",
    tags=["monitoring"],
    summary="Soft-delete a subscription (v0.27.0)",
)
async def monitor_delete_endpoint(
    subscription_id: str,
    api_key_name: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Mark the subscription as deleted (status='deleted'). The
    worker stops polling on the next claim cycle. Returns 404 when
    the id doesn't exist OR doesn't belong to this api key — same
    behavior as get, deliberately, to avoid leaking existence."""
    import os
    from uuid import UUID as _UUID

    from recupero.api.monitoring_api import (
        MonitoringDbError,
        soft_delete_subscription,
    )

    try:
        sub_uuid = _UUID(subscription_id)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="subscription not found",
        ) from None

    dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="monitoring delete unavailable",
        )

    try:
        deleted = soft_delete_subscription(
            api_key_name=api_key_name,
            subscription_id=sub_uuid,
            dsn=dsn,
        )
    except MonitoringDbError:
        # v0.27.1 (HIGH-5): DB blip on delete → 503 with retry hint,
        # not a misleading 404 that would lead the partner to assume
        # the subscription is gone while the worker keeps polling it.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="monitoring delete temporarily unavailable",
        ) from None
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="subscription not found",
        )
    log.info(
        "/v1/monitor/delete api_key=%s subscription_id=%s",
        api_key_name, sub_uuid,
    )
    return {"id": str(sub_uuid), "deleted": True}


@app.post(
    "/v1/screen/bulk",
    tags=["screening"],
    summary="Bulk wallet screening (max 100 per call) (v0.27.0)",
)
async def screen_bulk_endpoint(
    req: BulkScreenRequest,
    api_key_name: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Batch screening. Returns a list of {address, verdict} results
    in the same order as the request. Per-address screening is the
    same pure-function as /v1/screen; this endpoint just amortizes
    the HTTP round-trip cost for compliance-team batch flows.

    The list cap (100) is enforced by the Pydantic model. Larger
    batches: page client-side.
    """
    try:
        from recupero.screen.screener import screen_address
    except ImportError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"screener module unavailable: {e}",
        ) from e

    # v0.27.1 (CRIT-3): broaden the exception handler so that
    # ANY per-row failure (RuntimeError from a DB blip, KeyError
    # from a malformed correlation row, etc.) is contained to that
    # row instead of aborting the entire batch with a 500. The
    # docstring already promised this contract; the implementation
    # didn't honor it.
    results: list[dict[str, Any]] = []
    for addr in req.addresses:
        try:
            r = screen_address(
                addr, chain=req.chain,
                use_correlation_db=req.use_correlation_db,
            )
            results.append(r.to_json_safe())
        except (TypeError, ValueError) as e:
            # Input-shape errors get the specific message so the
            # caller can fix the bad row and re-screen.
            results.append({
                "address": addr,
                "chain": req.chain,
                "error": str(e),
            })
        except Exception as e:  # noqa: BLE001
            # Anything else (DB outage, network hiccup) gets a
            # generic per-row error — no DSN / internal trace leaks
            # to the partner.
            log.warning(
                "/v1/screen/bulk row failed (api_key=%s address=%s): %s",
                api_key_name, addr, e,
            )
            results.append({
                "address": addr,
                "chain": req.chain,
                "error": "screening failed for this address",
            })

    log.info(
        "/v1/screen/bulk api_key=%s n_addresses=%d",
        api_key_name, len(req.addresses),
    )
    return {"results": results, "count": len(results)}


# ---- v0.25.0: public victim intake form ---- #


# v0.25.1 (CRIT D-1): IP-based rate limit for the unauthenticated
# intake endpoint. Without this, a bot can POST tens of thousands
# of plausible-looking submissions per minute, each creating a
# `public.cases` row that an operator must triage manually —
# operator-time DoS plus database pollution.
#
# In-memory fixed-window counter is intentionally simple: the API
# is single-process on Railway (uvicorn behind a single replica),
# and the cost of upgrading to Redis is not justified for this
# attack model. If the API scales to N replicas the counter
# becomes per-replica (N× higher effective limit) — still
# acceptable; the absolute floor remains finite.
#
# Limit: 5 submissions per 60-second window per source IP. A real
# victim retries 1-2 times tops; 5/min leaves headroom for the
# accidental double-click + immediate validation-error retry.
_INTAKE_RL_WINDOW_S = 60
_INTAKE_RL_MAX = 5
_intake_rl_state: dict[str, tuple[float, int]] = {}


def _intake_rl_client_ip(request: Request) -> str:
    """Resolve the client IP for rate-limit bucketing.

    PUNISH-B S-3 fix: the pre-fix implementation read the LEFTMOST
    X-Forwarded-For element as "the client IP". Railway + Cloudflare
    both APPEND their own value to that header rather than strip it,
    so the leftmost is whatever the upstream client typed. A bot
    rotating leftmost-XFF per request would get unlimited submissions
    despite the 5/min cap.

    Correct pattern: honor RECUPERO_TRUSTED_PROXY_HOPS (number of
    trusted proxies between the client and the worker). The
    trusted-hop element is `xff_chain[-N]` — the address inserted
    by the closest proxy to us. Mirrors portal/server.py's
    `_extract_client_ip` (audited in v0.18.2).

    Fallback chain when no/zero trusted hops configured:
      1. `x-real-ip` (set by Railway/Fly's edge AFTER stripping XFF)
      2. `request.client.host` (socket peer)
      3. "unknown"
    """
    import os as _os
    raw_xff = (request.headers.get("x-forwarded-for", "") or "").strip()
    xff_chain = [p.strip() for p in raw_xff.split(",") if p.strip()]
    try:
        trusted_hops = int(_os.environ.get("RECUPERO_TRUSTED_PROXY_HOPS", "0"))
    except (TypeError, ValueError):
        trusted_hops = 0

    if trusted_hops > 0 and xff_chain:
        # Walk N hops back from the tail. If the chain is shorter
        # than N, take the leftmost entry inside the trusted
        # segment (don't fabricate trust by extrapolating).
        idx = max(0, len(xff_chain) - trusted_hops)
        candidate = xff_chain[idx]
        if candidate:
            return candidate

    # x-real-ip is set by some edge proxies after XFF normalization.
    # Still client-influenceable through misconfiguration, but a
    # better default than leftmost-XFF.
    real_ip = (request.headers.get("x-real-ip", "") or "").strip()
    if real_ip:
        return real_ip

    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _intake_rl_check(ip: str) -> bool:
    """Token-bucket-ish fixed-window counter. Returns True when the
    request is within budget, False when over.
    """
    import time as _time
    now = _time.time()
    entry = _intake_rl_state.get(ip)
    if entry is None or now - entry[0] >= _INTAKE_RL_WINDOW_S:
        _intake_rl_state[ip] = (now, 1)
        # Trim stale entries periodically to bound memory under
        # broad scanning.
        if len(_intake_rl_state) > 1024:
            cutoff = now - _INTAKE_RL_WINDOW_S
            for k, v in list(_intake_rl_state.items()):
                if v[0] < cutoff:
                    _intake_rl_state.pop(k, None)
        return True
    window_start, count = entry
    if count >= _INTAKE_RL_MAX:
        return False
    _intake_rl_state[ip] = (window_start, count + 1)
    return True


def _render_intake_html(
    form: dict[str, Any] | None = None,
    error: dict[str, str] | None = None,
) -> str:
    """Render the intake form via Jinja. ``form`` repopulates fields
    on validation failure; ``error`` shows the inline error banner.

    Pulled into a helper so the GET and POST routes share the same
    template path and the test suite can render the form directly.
    """
    from pathlib import Path

    from jinja2 import Environment, FileSystemLoader, select_autoescape

    templates_dir = (
        Path(__file__).resolve().parent.parent / "portal" / "templates"
    )
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    return env.get_template("intake.html.j2").render(
        form=form or {},
        error=error,
    )


@app.get(
    "/v1/intake",
    response_class=HTMLResponse,
    tags=["intake"],
    summary="Self-service victim intake form (v0.25.0).",
)
async def intake_form_get() -> HTMLResponse:
    """Public-facing victim intake form. No auth required — this is
    the top of the funnel.

    Submitting the form (POST /v1/intake) creates a `cases` row
    with status='intake' and returns the diagnostic Stripe Checkout
    URL. After payment, the existing Stripe webhook dispatcher
    creates the `investigations` row that the worker picks up.
    """
    return HTMLResponse(content=_render_intake_html())


@app.post(
    "/v1/intake",
    tags=["intake"],
    summary="Submit the intake form (v0.25.0).",
)
async def intake_form_post(  # noqa: PLR0913 — form fields are deliberately explicit
    request: Request,
    client_name: str = Form(...),
    client_email: str = Form(...),
    chain: str = Form(...),
    seed_address: str = Form(...),
    incident_date: str = Form(...),
    description: str = Form(...),
    country: str = Form(default=""),
) -> Any:
    """Validate the intake form + create the `cases` row + return the
    diagnostic Payment Link URL.

    Validation errors re-render the form with the bad field flagged.
    DB / config errors return a generic 5xx.

    The dispatcher (payments/dispatcher.py) handles the payment-side
    side-effects when the webhook fires; v0.25.0 only owns the
    pre-payment intake.
    """
    import os

    from recupero.payments.payment_links import (
        PaymentLinkConfigError,
        build_diagnostic_link,
    )
    from recupero.portal.intake import (
        IntakeValidationError,
        create_case_from_intake,
        validate_intake_payload,
    )

    # v0.25.1 (CRIT D-1): rate-limit by client IP BEFORE touching the
    # DB. The unauthenticated /v1/intake endpoint is otherwise free
    # to flood — an attacker could create 10k garbage cases that
    # operators must triage. Failing closed here costs the legitimate
    # double-clicker nothing (5 req / 60s budget).
    client_ip = _intake_rl_client_ip(request)
    if not _intake_rl_check(client_ip):
        log.info("/v1/intake POST: rate-limit hit for ip=%s", client_ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Too many submissions from your network. Please wait a "
                "minute before trying again."
            ),
        )

    raw_form = {
        "client_name": client_name,
        "client_email": client_email,
        "chain": chain,
        "seed_address": seed_address,
        "incident_date": incident_date,
        "description": description,
        "country": country,
    }

    # 1. Validate.
    try:
        payload = validate_intake_payload(raw_form)
    except IntakeValidationError as e:
        # Re-render the form with the bad field flagged. Status 422
        # so the form's POST flow gets a structured error response
        # that can be machine-read; HTML body for the human flow.
        return HTMLResponse(
            content=_render_intake_html(
                form=raw_form,
                error={"field": e.field, "detail": e.detail},
            ),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    # 2. Create the case row.
    dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
    if not dsn:
        log.warning("/v1/intake POST: SUPABASE_DB_URL unset; cannot create case")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Intake temporarily unavailable. Please try again shortly.",
        )

    try:
        case_id = create_case_from_intake(payload, dsn=dsn)
    except RuntimeError as e:
        log.warning(
            "/v1/intake POST: case creation failed (email=%s): %s",
            payload.client_email, e,
        )
        # Don't leak DSN / SQL detail in the response.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Something went wrong creating your case. Please try again.",
        ) from None

    # 3. Build the diagnostic Stripe Checkout URL.
    try:
        checkout_url = build_diagnostic_link(
            case_id=case_id,
            chain=payload.chain,
            seed_address=payload.seed_address,
            prefilled_email=payload.client_email,
        )
    except (PaymentLinkConfigError, ValueError) as e:
        log.warning(
            "/v1/intake POST: payment link build failed for case %s: %s",
            case_id, e,
        )
        # The case row is already created — operator can manually
        # send a payment link from the admin UI. Surface a clear
        # error to the victim so they don't pay twice.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "We've recorded your intake but our payment system is "
                "temporarily unavailable. We'll email you a payment link "
                "shortly."
            ),
        ) from None

    log.info(
        "/v1/intake POST: case created (case_id=%s email=%s chain=%s); "
        "redirecting to Stripe Checkout",
        case_id, payload.client_email, payload.chain,
    )

    # 4. 303 redirect to Stripe Checkout. 303 (See Other) is the
    # correct status for a POST → GET redirect — preserves the POST
    # semantics but forces the browser to GET the checkout URL.
    return RedirectResponse(
        url=checkout_url,
        status_code=status.HTTP_303_SEE_OTHER,
    )


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
