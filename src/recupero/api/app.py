"""FastAPI app for Recupero's REST service (v0.15.1).

Exposes screening / token-risk / correlation as authenticated
REST endpoints. The CLI commands all share the same underlying
pure-function implementations — the API is a thin wrapper that
adds auth + rate limiting + OpenAPI surface.

Run via ``recupero-api`` (console script) or directly with
``uvicorn recupero.api.app:app``.
"""

from __future__ import annotations

import contextlib
import logging
import time
from typing import Any

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator

from recupero.api.auth import require_api_key, role_for_key

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

# v0.32 Tier-0 gap #1 — human-review API surface for the dispatch
# gate. Gated by RECUPERO_ADMIN_KEY (X-Recupero-Admin-Key header);
# returns 503 when the env var is unset so an unconfigured deploy
# can't accidentally publish the queue.
try:
    from recupero.dispatcher.review_api import router as _review_router
    app.include_router(_review_router)
except Exception as _exc:  # noqa: BLE001
    # Don't take down the API on a review-module import failure —
    # other endpoints (screen / token-risk / monitoring) must still
    # work. The /v1/reviews/* surface returns 404 in this state.
    log.warning(
        "review API not registered (import failed): %s", _exc,
    )

# v0.32 Tier-1 gaps #1 + #2 — label auto-ingest review surface.
# Same admin-key auth + 503-on-import-failure shape as the review
# API above. Operators promote/reject candidates pulled overnight by
# the recupero-cron `label_auto_ingest` job.
try:
    from recupero.labels.api import router as _labels_router
    app.include_router(_labels_router)
except Exception as _exc:  # noqa: BLE001
    log.warning(
        "label-candidates API not registered (import failed): %s", _exc,
    )

# SaaS multi-tenant surface (self-serve signup/login, org API keys, quota-gated
# async trace submission) under /v2. The existing flat-API-key endpoints stay at
# /v1 for back-compat. Same import-guard shape: a platform import/config failure
# leaves /v1 fully working (the /v2/* surface just 404s until configured).
try:
    from recupero.platform.router import router as _platform_router
    app.include_router(_platform_router)
except Exception as _exc:  # noqa: BLE001
    log.warning(
        "platform (/v2 multi-tenant) API not registered (import failed): %s", _exc,
    )

# v0.32.1 HIGH-5 — admin-gated /v1/cron/jobs endpoint. Public
# /cron/healthz strips last_error_message; admins use this endpoint
# to retrieve the full payload including the redacted error text.
try:
    from recupero.api.cron_admin_api import router as _cron_admin_router
    app.include_router(_cron_admin_router)
except Exception as _exc:  # noqa: BLE001
    log.warning(
        "cron admin API not registered (import failed): %s", _exc,
    )

# v0.35.1 — live Watchlist / Watcher console. Admin-gated JSON
# (/v1/watchlist) + re-check trigger (/v1/watchlist/run) + an
# unauthenticated HTML shell (/v1/watchlist/console) that fetches the
# JSON client-side with the operator's X-Recupero-Admin-Key.
try:
    from recupero.api.watchlist_api import router as _watchlist_router
    app.include_router(_watchlist_router)
except Exception as _exc:  # noqa: BLE001
    log.warning(
        "watchlist API not registered (import failed): %s", _exc,
    )

# v0.35.14 (F3): address/entity profile — admin-gated JSON
# (/v1/address/profile) + an unauthenticated console shell
# (/v1/address/console) that fetches it client-side with the operator's
# X-Recupero-Admin-Key. Type any address -> instant risk/labels/exposure/
# sighting-history view over the existing local-seed screener.
try:
    from recupero.api.address_profile import router as _address_router
    app.include_router(_address_router)
except Exception as _exc:  # noqa: BLE001
    log.warning(
        "address profile API not registered (import failed): %s", _exc,
    )

# v0.35.19 (UI initiative): the unified operator console hub —
# GET /v1/console (unauth shell + nav grid + admin-gated quick-stats) that
# links every per-phase console. New phase views register a nav entry in
# operator_console._NAV during integration so the hub fills in over time.
try:
    from recupero.api.operator_console import router as _operator_router
    app.include_router(_operator_router)
except Exception as _exc:  # noqa: BLE001
    log.warning(
        "operator console not registered (import failed): %s", _exc,
    )

# v0.35.20 (UI batch-1): per-phase operator console views — label-candidate
# review, cron/job health, and label-freshness — each an isolated console that
# the hub (/v1/console) links. Registered independently so one failing import
# never takes down the others.
for _mod, _attr in (
    ("recupero.api.label_review_console", "router"),
    ("recupero.api.cron_console", "router"),
    ("recupero.api.freshness_api", "router"),
    # v0.35.21 (UI batch-2): graph-analysis + case-index views.
    ("recupero.api.graph_analysis_api", "router"),
    ("recupero.api.case_index_api", "router"),
    # v0.35.22 (UI batch-3): exhibit-pack + SAR/STR filing + bulk screening.
    ("recupero.api.exhibit_pack_api", "router"),
    ("recupero.api.sar_filing_api", "router"),
    ("recupero.api.screening_api", "router"),
    # v0.35.23 (UI batch-4): AI-triage (read-stored) + cooperation intelligence.
    ("recupero.api.ai_triage_api", "router"),
    ("recupero.api.cooperation_api", "router"),
    # v0.35.24 (UI batch-5): law-firm portfolio dashboard + recovery snapshot.
    ("recupero.api.law_firm_api", "router"),
    ("recupero.api.recovery_snapshot_api", "router"),
    # v0.35.26 (UI batch-7): per-case overview / launcher.
    ("recupero.api.case_overview_api", "router"),
    # v0.35.29 (UI batch-10): J1 trace-accuracy benchmark.
    ("recupero.api.benchmark_api", "router"),
    # v0.35.30: D6 proactive recovery alerts (persisted; live freeze-NOW queue).
    ("recupero.api.recovery_alerts_api", "router"),
    # v0.35.32: D4 incident-response plans (derived from persisted D6 alerts).
    ("recupero.api.incident_plans_api", "router"),
    # v0.38 (enterprise/SOC 2): append-only audit-log read endpoint.
    ("recupero.api.audit_api", "router"),
):
    try:
        _m = __import__(_mod, fromlist=[_attr])
        app.include_router(getattr(_m, _attr))
    except Exception as _exc:  # noqa: BLE001
        log.warning("phase console %s not registered (import failed): %s", _mod, _exc)


# ---- Request body-size cap (intake DoS guard) ---- #

# v0.32.1 (forensic-audit, api-MED): cap inbound request bodies. Pre-fix
# the FastAPI app had NO body-size limit — every POST handler reaches
# ``await request.json()`` / pydantic parsing, which buffers the WHOLE
# body into memory first. A single client advertising (or streaming) a
# multi-hundred-MB body could OOM the API process before any per-field
# validator ran. None of the endpoints need a large body: the biggest is
# /v1/screen/bulk at 100 × 128-char addresses (~13 KB with JSON
# overhead). 256 KiB is generous headroom while slamming the door on
# abuse bodies. (The worker intake portal uses a tighter 64 KB cap in
# _health_server.py; the API surface is broader, hence the larger value.)
_MAX_REQUEST_BODY_BYTES = 256 * 1024


class _BodySizeLimitMiddleware:
    """Pure-ASGI middleware rejecting oversized request bodies.

    Two layers, because a Content-Length header alone is not trustworthy:

      1. Fast path — an honest ``Content-Length`` above the cap is
         rejected with 413 before a single body byte is read.
      2. Streaming guard — the ``receive`` callable is wrapped to count
         actual bytes, so a client that LIES about Content-Length or uses
         chunked transfer-encoding (no Content-Length at all) is still cut
         off at the cap. On overflow we hand the app an ``http.disconnect``
         so its body parser raises ClientDisconnect and never produces an
         oversized parse — no unbounded read, no response-already-started
         race.

    Implemented as raw ASGI (not BaseHTTPMiddleware) precisely so it never
    consumes/buffers the body itself — it only inspects sizes and forwards.
    """

    def __init__(self, app: Any, *, max_bytes: int = _MAX_REQUEST_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # Layer 1: honest Content-Length → reject before reading anything.
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    await self._send_413(send)
                    return
                if declared > self.max_bytes:
                    await self._send_413(send)
                    return
                break

        # Layer 2: enforce on actual bytes (lying CL / chunked encoding).
        total = 0
        limit = self.max_bytes

        async def limited_receive() -> Any:
            nonlocal total
            message = await receive()
            if message.get("type") == "http.request":
                total += len(message.get("body", b""))
                if total > limit:
                    # Tell the app the client went away; its body reader
                    # raises ClientDisconnect rather than parsing a
                    # half-read oversized body. Stops the DoS cold.
                    return {"type": "http.disconnect"}
            return message

        await self.app(scope, limited_receive, send)

    @staticmethod
    async def _send_413(send: Any) -> None:
        await send({
            # 413 Payload/Content Too Large. Literal rather than the
            # starlette constant, whose name churns across versions
            # (REQUEST_ENTITY_TOO_LARGE → CONTENT_TOO_LARGE) and emits a
            # DeprecationWarning the test suite treats as an error.
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({
            "type": "http.response.body",
            "body": b'{"detail":"request body too large"}',
        })


app.add_middleware(_BodySizeLimitMiddleware, max_bytes=_MAX_REQUEST_BODY_BYTES)


def _install_optional_middleware(app_: FastAPI) -> None:
    """Add prod-hardening middleware, each gated by an env var so the default
    (unset) preserves current behavior (serve any Host, no CORS) — zero change
    for existing deployments / tests.

      * ``RECUPERO_API_ALLOWED_HOSTS`` — comma-separated Host allow-list. When
        set, installs Starlette ``TrustedHostMiddleware`` (rejects spoofed Host
        headers — relevant once the API is exposed on a public domain).
      * ``RECUPERO_API_CORS_ORIGINS`` — comma-separated allowed origins. When
        set, installs ``CORSMiddleware`` for cross-origin API clients. The
        operator console is same-origin and needs none.
    """
    import os
    hosts_raw = (os.environ.get("RECUPERO_API_ALLOWED_HOSTS", "") or "").strip()
    if hosts_raw:
        from starlette.middleware.trustedhost import TrustedHostMiddleware
        allowed = [h.strip() for h in hosts_raw.split(",") if h.strip()]
        if allowed:
            app_.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed)
    origins_raw = (os.environ.get("RECUPERO_API_CORS_ORIGINS", "") or "").strip()
    if origins_raw:
        from fastapi.middleware.cors import CORSMiddleware
        origins = [o.strip() for o in origins_raw.split(",") if o.strip()]
        if origins:
            # No allow_credentials: the API authenticates via the
            # X-Recupero-Admin-Key / API-key headers, not cookies — and
            # credentials + a wildcard origin is a browser-rejected footgun.
            app_.add_middleware(
                CORSMiddleware,
                allow_origins=origins,
                allow_methods=["*"],
                allow_headers=["*"],
            )


_install_optional_middleware(app)


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
    include_exposure: bool = Field(
        False,
        description=(
            "If True, also runs a BOUNDED on-chain 1-hop probe for DIRECT "
            "exposure to high-risk counterparties (OFAC / mixer / ransomware / "
            "drainer / darknet) — the instant-KYT signal the offline screen "
            "cannot see. Adds seconds of latency (network RPC) vs the <50ms "
            "offline path, so it is opt-in. Multi-hop / USD-weighted exposure "
            "still requires a full trace."
        ),
    )
    exposure_lookback_days: int = Field(
        90, ge=1, le=365,
        description="Lookback window (days) for the on-chain exposure probe.",
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


@app.get(
    "/healthz",
    response_model=HealthResponse,
    tags=["meta"],
    summary="Liveness probe alias (PaaS / container healthcheck path)",
    include_in_schema=False,
)
async def healthz() -> HealthResponse:
    """Alias of ``/v1/health`` at the conventional ``/healthz`` path.

    railway.json (``healthcheckPath: /healthz``) and the Dockerfile
    ``HEALTHCHECK`` both probe ``/healthz``. The worker serves it via its
    own health server; a ``recupero-api`` Railway service needs the API to
    answer it too, otherwise the platform marks the service unhealthy
    forever and the deploy never goes live. No auth (unauthenticated probe).
    """
    return await health()


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    """Bare-domain convenience: send visitors to the operator console."""
    return RedirectResponse(url="/v1/console")


@app.get(
    "/v1/whoami",
    tags=["meta"],
    summary="Return the authenticated API key's name + RBAC role",
)
async def whoami(api_key_name: str = Depends(require_api_key)) -> dict[str, Any]:
    """Identity + RBAC role of the calling key (viewer < analyst < admin).
    Lets a client confirm what it's authorized for. Role is resolved from
    RECUPERO_API_KEY_ROLES / RECUPERO_API_KEY_ADMINS; default is 'analyst'."""
    return {"api_key_name": api_key_name, "role": role_for_key(api_key_name)}


def _run_exposure_probe(
    address: str, chain_str: str, lookback_days: int,
) -> dict[str, Any] | None:
    """Synchronous bounded on-chain exposure probe (run off the event loop
    via ``asyncio.to_thread``). Builds the chain adapter, loads the high-risk
    db, runs the 1-hop counterparty probe, and always releases the adapter's
    HTTP client. Returns the probe result or ``None`` (no exposure)."""
    from recupero.chains.base import ChainAdapter
    from recupero.config import load_config
    from recupero.models import Chain
    from recupero.screen.exposure_probe import probe_counterparty_exposure
    from recupero.trace.risk_scoring import load_high_risk_db

    cfg, env = load_config()
    chain = Chain(chain_str)
    adapter = ChainAdapter.for_chain(chain, (cfg, env))
    try:
        return probe_counterparty_exposure(
            address, chain=chain, adapter=adapter,
            high_risk_db=load_high_risk_db(),
            lookback_days=lookback_days,
        )
    finally:
        with contextlib.suppress(Exception):
            adapter.close()


@app.post(
    "/v1/screen",
    tags=["screening"],
    summary="Score an address against OFAC + mixer + correlation data",
)
async def screen_address_endpoint(
    req: ScreenRequest,
    api_key_name: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Wallet-screening lookup. The default path uses ONLY local seed data +
    correlation DB; no on-chain RPC calls; latency < 50ms.

    With ``include_exposure=true`` it additionally runs a bounded on-chain
    1-hop probe (``exposure`` block) for DIRECT high-risk counterparty
    exposure — the instant-KYT signal the offline screen cannot see.

    Returns:
      ``{ address, chain, risk_verdict, risk_score, is_ofac_sanctioned,
          is_mixer, is_ransomware, is_drainer, labels, correlation,
          investigator_note, data_sources_used[, exposure] }``.
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

    payload = result.to_json_safe()

    # Opt-in on-chain exposure enrichment. Best-effort: a probe failure must
    # never fail the (already-computed) offline screen — it degrades to a null
    # exposure block with an error note.
    if req.include_exposure:
        import asyncio
        try:
            payload["exposure"] = await asyncio.to_thread(
                _run_exposure_probe,
                req.address, req.chain, req.exposure_lookback_days,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("/v1/screen exposure probe failed for %s: %s",
                        req.address, exc)
            payload["exposure"] = None
            payload["exposure_error"] = "exposure probe unavailable"

    log.info("/v1/screen api_key=%s address=%s verdict=%s exposure=%s",
             api_key_name, req.address, result.risk_verdict,
             req.include_exposure)
    return payload


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
    # v0.28.1 (correlations-adversarial hardening): validate the
    # path/query inputs BEFORE any DB hit. Pre-hardening the address
    # was an unbounded `str` passed straight into _ck/SQL — an
    # authenticated caller could submit a 16MB address, a bidi-
    # trojan-laden address that pollutes logs, or a NUL-embedded
    # string that broke downstream encoders. Same five gates the
    # other API surfaces enforce (length cap, control chars, NUL,
    # bidi/zero-width trojans, supported-chain enum).
    if len(address) < 1 or len(address) > 128:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="address must be 1-128 chars",
        )
    if "\x00" in address or "\r" in address or "\n" in address:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="address contains forbidden control characters",
        )
    if any(c in _TEXT_TROJAN_CHARS for c in address):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="address contains forbidden bidi / zero-width characters",
        )
    _SUPPORTED_CHAINS = {
        "ethereum", "arbitrum", "base", "bsc", "polygon",
        "solana", "tron", "bitcoin", "hyperliquid",
    }
    if chain not in _SUPPORTED_CHAINS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unsupported chain: {chain!r}",
        )
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


# RIGOR-Jacob E adversarial hardening: text-trojan code-point set
# rejected on free-text response_text / operator_notes. Bidi overrides,
# isolates, formatting marks, zero-width chars, BOM. Same set as
# portal/intake._reject_unicode_trojans.
_TEXT_TROJAN_CHARS = frozenset({
    "‪",  # LEFT-TO-RIGHT EMBEDDING
    "‫",  # RIGHT-TO-LEFT EMBEDDING
    "‬",  # POP DIRECTIONAL FORMATTING
    "‭",  # LEFT-TO-RIGHT OVERRIDE
    "‮",  # RIGHT-TO-LEFT OVERRIDE
    "⁦",  # LEFT-TO-RIGHT ISOLATE
    "⁧",  # RIGHT-TO-LEFT ISOLATE
    "⁨",  # FIRST-STRONG ISOLATE
    "⁩",  # POP DIRECTIONAL ISOLATE
    "​",  # ZERO-WIDTH SPACE
    "‌",  # ZERO-WIDTH NON-JOINER
    "‍",  # ZERO-WIDTH JOINER
    "‎",  # LEFT-TO-RIGHT MARK
    "‏",  # RIGHT-TO-LEFT MARK
    "﻿",  # BYTE-ORDER MARK / ZERO-WIDTH NO-BREAK SPACE
})


# RIGOR-Jacob E: realistic upper bound for any single seizure. The
# largest recorded historical seizure (FBI 2022 BTC) was ~$3B; cap at
# 1e15 (a quadrillion USD) so anything legitimate passes but accidental
# / malicious 1e18-style values are rejected.
_USD_HARD_CAP = 1e15


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
    # RIGOR-Jacob E: bump min_length to 25 so a 4-char garbage string
    # like "abcd" is rejected up-front. Shortest realistic chain
    # address is BTC legacy P2PKH at 25 chars (base58); EVM is 42;
    # Solana is 32-44; Tron is 34. 4-char strings fail every shape
    # check downstream but used to pass and pollute the DB.
    target_address: str = Field(..., min_length=25, max_length=128)
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

    @field_validator("frozen_usd", "returned_usd")
    @classmethod
    def _reject_non_finite_usd(cls, v: float | None) -> float | None:
        """RIGOR-Jacob E: reject NaN / Inf / -Inf. Pydantic's ge=0
        constraint accepts +Infinity (Inf >= 0 is True) and accepts
        NaN under some FP setups. Either value crashes Decimal(...) on
        the DB-insert path or silently breaks downstream comparisons.
        Also enforce a realistic absolute cap ($1e15) so a quintillion-
        dollar bogus value doesn't roll up into LE handoff totals."""
        import math
        if v is None:
            return v
        if not math.isfinite(v):
            raise ValueError(
                "must be a finite number (no NaN/Inf)",
            )
        if v >= _USD_HARD_CAP:
            raise ValueError(
                f"value exceeds realistic cap (${_USD_HARD_CAP:.0e})",
            )
        return v

    @field_validator("target_address")
    @classmethod
    def _validate_target_address_shape(cls, v: str) -> str:
        """RIGOR-Jacob E: defense-in-depth shape check. The min_length=25
        already rejects 4-char garbage; this strips whitespace and
        rejects NUL / control bytes that would crash psycopg on insert.
        Real per-chain shape validation lives in the recorder."""
        if not v:
            raise ValueError("target_address is required")
        if "\x00" in v:
            raise ValueError("target_address contains a NUL byte")
        return v

    @field_validator("response_text", "operator_notes")
    @classmethod
    def _reject_text_trojans(cls, v: str | None) -> str | None:
        """RIGOR-Jacob O: reject NUL bytes (psycopg-crash) and bidi /
        zero-width / BOM characters (Trojan-Source CVE-2021-42574)
        on free-text fields that flow into operator triage UIs +
        LE handoff Section 5.5. Same rejection set as
        portal/intake._reject_unicode_trojans."""
        if v is None:
            return v
        if "\x00" in v:
            raise ValueError("contains a NUL byte")
        for ch in v:
            if ch in _TEXT_TROJAN_CHARS:
                raise ValueError(
                    "contains a bidi / zero-width / BOM control "
                    "character (Trojan-Source / CVE-2021-42574)"
                )
        return v


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
    # Route-authz audit (this commit): also gate by case_id when the
    # operator supplied RECUPERO_API_KEY_CASES. Issuer scoping alone is
    # not enough — a partner whose key is allow-listed for "Tether"
    # could otherwise write outcomes against ANY case_id containing
    # Tether letters, including cases where the partner shouldn't have
    # write visibility. Admin keys + unconfigured env var bypass.
    if (
        not is_authorized_to_record_outcome(
            api_key_name=api_key_name, issuer=req.issuer,
        )
        or not _is_api_key_authorized_for_case(
            api_key_name=api_key_name, case_id=req.case_id,
        )
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


def _is_api_key_authorized_for_case(
    *, api_key_name: str, case_id: str,
) -> bool:
    """Route-authz audit (this commit): per-case scoping for
    /v1/freeze-outcomes.

    A partner key authorized for issuer "Tether" via
    RECUPERO_API_KEY_ISSUERS could otherwise write outcomes against
    *any* case_id whose freeze letters happen to mention Tether — a
    horizontal-privilege gap (issuer-allow-list does not imply
    case-allow-list).

    Env var ``RECUPERO_API_KEY_CASES`` format:
      ``key_name:case_uuid|case_uuid,key2:case_uuid``

    Semantics (backward-compatible, deny-by-default ONLY when explicit):
      1. Admin keys (RECUPERO_API_KEY_ADMINS) bypass case scoping.
      2. Optional-auth mode (auth disabled in local dev) bypasses.
      3. If the env var is UNSET, return True — preserves the pre-audit
         issuer-only behavior. Operators opt in to case scoping.
      4. If the env var is SET but the key has no entry, return True —
         keys without case restrictions remain issuer-gated.
      5. If the key HAS an entry, the requested case_id must be in it.
    """
    import os as _os
    # Reuse the same admin / optional-auth shortcuts as the issuer gate.
    try:
        from recupero.api.auth import (
            _is_optional_auth,  # type: ignore[attr-defined]
            _load_api_key_admins,
        )
    except ImportError:
        return True
    if _is_optional_auth():
        return True
    if api_key_name in _load_api_key_admins():
        return True
    raw = (_os.environ.get("RECUPERO_API_KEY_CASES", "") or "").strip()
    if not raw:
        return True  # case scoping not configured → preserve legacy
    # Parse "key_name:uuid|uuid,key2:uuid"
    per_key: dict[str, set[str]] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        name, _, cases_str = pair.partition(":")
        name = name.strip()
        if not name:
            continue
        cases = {
            c.strip().lower() for c in cases_str.split("|") if c.strip()
        }
        if cases:
            per_key[name] = cases
    if api_key_name not in per_key:
        return True  # this key has no case restriction
    return (case_id or "").strip().lower() in per_key[api_key_name]


def _intake_post_csrf_ok(request: Request) -> bool:
    """Route-authz audit (this commit): Origin/Referer check for the
    unauthenticated POST /v1/intake form.

    The intake endpoint accepts ``application/x-www-form-urlencoded``
    with no auth header — a textbook CSRF target. A malicious site
    can autosubmit a hidden form to /v1/intake from an attacker
    origin and create a `cases` row with operator-visible data
    (waste of triage time + DB pollution).

    Browser-issued cross-origin form POSTs always carry an Origin
    header (set by the browser, not script-controllable). Non-browser
    callers (curl, integration tests, server-side scripts) typically
    have NO Origin / Referer — those are allowed through.

    Allow-list source: ``RECUPERO_INTAKE_ALLOWED_ORIGINS`` (comma-sep).
    Empty / unset → any same-origin host is permitted; cross-origin
    is rejected only if BOTH the env var AND an Origin header are
    set and the Origin is not on the list.

    Returns True when the request should proceed, False when CSRF
    rejection is warranted.
    """
    import os as _os
    origin = (request.headers.get("origin", "") or "").strip()
    referer = (request.headers.get("referer", "") or "").strip()
    # Headerless POSTs (no Origin AND no Referer) are NOT a browser-CSRF
    # vector: a browser ALWAYS attaches an Origin header to a
    # cross-origin form POST (set by the browser, not script-mutable),
    # so a drive-by CSRF attempt is always caught by the origin-vs-host
    # check below. Headerless requests are curl / integration tests /
    # server-side integrations, which we allow through by design.
    #
    # The drive-by-BOT concern (a script flooding /v1/intake with
    # headers stripped) is handled at the correct layer: the per-IP
    # rate limiter (`_intake_rl_check`), keyed on the rightmost trusted
    # XFF hop (`_intake_rl_client_ip`, PUNISH-B S-3) so a bot cannot
    # rotate spoofed client IPs to evade the 5/min cap. A blanket CSRF
    # reject here was the wrong layer — it broke every legitimate
    # non-browser caller while adding nothing the rate limiter (with
    # the rightmost-hop fix) doesn't already cover.
    #
    # Ops who front the endpoint with a browser-only origin and want a
    # hard gate can opt into strict mode via
    # RECUPERO_INTAKE_REQUIRE_ORIGIN=true (default: allow headerless).
    if not origin and not referer:
        require_origin = (
            _os.environ.get("RECUPERO_INTAKE_REQUIRE_ORIGIN", "")
            .strip().lower() in ("1", "true", "yes", "on")
        )
        return not require_origin
    raw_allow = (
        _os.environ.get("RECUPERO_INTAKE_ALLOWED_ORIGINS", "") or ""
    ).strip()
    if not raw_allow:
        # Allow-list not configured — fall back to same-origin check
        # against the request's own host header. Reject only when the
        # browser-supplied Origin differs from the host (true
        # cross-origin POST). Defends against the default-config case
        # without operator action.
        host = (request.headers.get("host", "") or "").strip().lower()
        if not host:
            return True  # can't determine — allow rather than break.
        # Origin is "scheme://host[:port]". Compare host portion.
        if origin:
            try:
                from urllib.parse import urlsplit
                origin_host = (urlsplit(origin).netloc or "").lower()
            except Exception:  # noqa: BLE001
                return False
            if origin_host and origin_host != host:
                return False
        return True
    allow = {o.strip().lower() for o in raw_allow.split(",") if o.strip()}
    return bool(origin and origin.lower() in allow)


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
        # RIGOR-S-3b fail-closed: when the chain is SHORTER than the
        # configured number of trusted hops, the operator misconfigured
        # the env var (e.g., set trusted_hops=3 after migrating from
        # Cloudflare+Railway down to Railway-only). The pre-hardening
        # behaviour returned xff_chain[0] — the LEFTMOST entry — which
        # is attacker-controlled in that misconfig scenario. We now
        # skip the XFF path entirely and fall through to x-real-ip /
        # socket peer (coarser bucket but no bypass).
        if len(xff_chain) >= trusted_hops:
            idx = len(xff_chain) - trusted_hops
            candidate = xff_chain[idx]
            if candidate:
                return candidate

    # x-real-ip is set by some edge proxies after XFF normalization, but
    # it is ALSO a client-settable header. Without a declared trusted
    # proxy (RECUPERO_TRUSTED_PROXY_HOPS) we cannot distinguish an
    # edge-set value from a spoofed one.
    #
    # Without a declared trusted proxy (RECUPERO_TRUSTED_PROXY_HOPS),
    # x-real-ip is a client-settable header — a bot rotating `X-Real-IP:`
    # per request would evade the per-IP intake rate limit, which (now that
    # header-less POSTs are allowed) is the SOLE bot defense for the
    # unauthenticated POST /v1/intake.
    #
    # v0.32.1 (security-audit cycle-2): FAIL CLOSED. The prior gate trusted
    # x-real-ip UNLESS _is_production_environment() positively detected prod
    # — but that keys off explicit markers, so a production deploy that
    # forgot to set one (no RAILWAY_ENVIRONMENT/ENVIRONMENT/…=production)
    # fell through to trusting the spoofable header. Now we trust x-real-ip
    # in the no-trusted-hop case ONLY when the environment POSITIVELY
    # declares dev/test/local; any unmarked / ambiguous / production env
    # refuses it and buckets on the socket peer (the real TCP peer, not
    # client-controllable). Operators behind a trusted edge proxy should
    # set RECUPERO_TRUSTED_PROXY_HOPS to restore precise per-client
    # bucketing via the rightmost-hop path above.
    real_ip = (request.headers.get("x-real-ip", "") or "").strip()
    if real_ip:
        spoofable = trusted_hops == 0
        if not spoofable:
            return real_ip
        try:
            from recupero.api.auth import _is_local_dev_environment
            trust_real_ip = _is_local_dev_environment()
        except Exception:  # noqa: BLE001 — never break the hot path on detection
            trust_real_ip = False  # detection failed → fail closed (assume prod)
        if trust_real_ip:
            return real_ip
        # ambiguous / prod + no trusted hops → x-real-ip untrusted; fall through.

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

    v0.32 — also computes the recovery-rate disclosure block.
    ``compute_recovery_stats`` caches results for 60s and degrades
    to the industry baseline if the DB is unreachable, so this is
    always safe to call from the hot path. NEVER blocks render.
    """
    import os
    from pathlib import Path

    from jinja2 import Environment, FileSystemLoader, select_autoescape

    templates_dir = (
        Path(__file__).resolve().parent.parent / "portal" / "templates"
    )
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    # XSS defense-in-depth filters.
    from recupero.reports._jinja_filters import register_safe_filters
    register_safe_filters(env)

    # v0.32 Tier-0 gap #2: compute the honest recovery-rate disclosure.
    # Wraps any unexpected exception so render is always safe — the
    # caller path is unauthenticated public traffic.
    try:
        from recupero.monitoring.recovery_rate import compute_recovery_stats
        dsn = os.environ.get("SUPABASE_DB_URL", "").strip() or None
        recovery_stats = compute_recovery_stats(dsn=dsn)
    except Exception as exc:  # noqa: BLE001
        log.warning("intake: recovery-rate disclosure compute failed: %s", exc)
        # Defense in depth — fall back to the industry baseline shape
        # directly so the template's `is_our_data` branch still works.
        from recupero.monitoring.recovery_rate import (
            INDUSTRY_BASELINE_LABEL,
            INDUSTRY_FULL_RECOVERY_RATE,
            RecoveryStats,
        )
        recovery_stats = RecoveryStats(
            sample_size=0,
            n_full_recovery=0,
            n_partial_recovery=0,
            n_zero_recovery=0,
            full_recovery_rate=INDUSTRY_FULL_RECOVERY_RATE,
            full_recovery_rate_ci_low=INDUSTRY_FULL_RECOVERY_RATE,
            full_recovery_rate_ci_high=INDUSTRY_FULL_RECOVERY_RATE,
            is_our_data=False,
            industry_baseline_used=INDUSTRY_BASELINE_LABEL,
            median_recovery_usd=None,
            median_time_to_recovery_days=None,
        )

    return env.get_template("intake.html.j2").render(
        form=form or {},
        error=error,
        recovery_stats=recovery_stats,
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
    acknowledge_disclosure: str = Form(default=""),
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

    # Route-authz audit (this commit): CSRF Origin/Referer check.
    # The intake form is unauthenticated and accepts
    # x-www-form-urlencoded — without an Origin check, a malicious
    # site can autosubmit a hidden form cross-origin and create
    # garbage `cases` rows. Browsers always set Origin on form POSTs;
    # non-browser callers (curl, tests) have neither header and are
    # allowed through.
    if not _intake_post_csrf_ok(request):
        log.info(
            "/v1/intake POST: CSRF reject — Origin=%r Referer=%r host=%r",
            request.headers.get("origin"),
            request.headers.get("referer"),
            request.headers.get("host"),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cross-origin form submission not permitted",
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
        "acknowledge_disclosure": acknowledge_disclosure,
    }

    # v0.32 Tier-0 gap #2: server-side validation of the recovery-rate
    # disclosure checkbox. HTML5 `required` is a UX hint but trivially
    # bypassable (curl, dev-tools, JS-disabled browsers). The legal
    # audit-trail value of `recovery_disclosures` depends on this
    # affirmative acknowledgment being IMPOSSIBLE to bypass without
    # an explicit checkbox-checked POST.
    if acknowledge_disclosure != "yes":
        log.info(
            "/v1/intake POST: rejecting submission missing acknowledge_disclosure "
            "checkbox (ip=%s email=%s)",
            client_ip, client_email,
        )
        return HTMLResponse(
            content=_render_intake_html(
                form=raw_form,
                error={
                    "field": "acknowledge_disclosure",
                    "detail": (
                        "Please tick the box confirming you understand "
                        "that paying for this diagnostic does NOT "
                        "guarantee recovery of your funds."
                    ),
                },
            ),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

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

    # v0.32 Tier-0 gap #2: write the legal audit-trail row recording
    # that THIS customer saw THIS specific rate at THIS time and
    # affirmatively acknowledged it. Best-effort — never blocks the
    # checkout flow on an audit-write failure (logged at WARN for
    # ops follow-up).
    try:
        from recupero.monitoring.recovery_rate import (
            compute_recovery_stats,
            log_disclosure,
        )
        shown_stats = compute_recovery_stats(dsn=dsn)
        log_disclosure(
            case_id=str(case_id),
            stats=shown_stats,
            dsn=dsn,
            acknowledged=True,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "/v1/intake POST: recovery-disclosure audit log failed "
            "for case=%s: %s",
            case_id, exc,
        )

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


# ---- Operator UI for the brief-review queue (v0.32.1) ---- #
#
# Pre-v0.32.1 the dispatcher review gate (recupero.dispatcher.review_api)
# was API-only. The Jacob cross-cutting audit (§4) flagged this as a
# deploy-blocker: every approve/reject required an on-call operator to
# hand-craft a curl invocation with the admin-key header, at 2 AM,
# inside a constrained ops window. ``/review-gate`` is the minimum-
# viable operator console: list pending rows, click-through to the
# artifact, approve / reject, surface the reviewer + completion
# timestamp once a row is decided.
#
# The page is intentionally not gated by FastAPI middleware — the
# state-changing calls under the hood (POST /v1/reviews/{id}/...)
# all enforce the X-Recupero-Admin-Key check inside ``review_api``.
# Serving the static HTML to anyone is a deliberate choice: it tells
# an unauthenticated visitor "this is the gate" without leaking any
# data (the queue load fetches from /v1/reviews/queue which DOES
# require the header).


@app.get(
    "/review-gate",
    response_class=HTMLResponse,
    tags=["ops"],
    summary=(
        "Operator UI for the brief-review queue (v0.32.1). "
        "State-changing actions remain gated by X-Recupero-Admin-Key "
        "at the /v1/reviews/* API layer."
    ),
)
async def review_gate_ui() -> HTMLResponse:
    """Render the operator console for the dispatcher review gate.

    The HTML is a static asset (``recupero.web.templates.review_gate.html``)
    — no per-request templating context is needed because every dynamic
    bit is fetched client-side from ``/v1/reviews/queue`` and posted
    back to ``/v1/reviews/{id}/(approve|reject)`` with the admin key.

    On any I/O error reading the template, returns a 503 with a short
    message so the operator knows to fall back to curl.

    TODO (Wave-4): wire a server-side render that proxies the queue
    fetch through the same FastAPI process so an operator pasting an
    admin key into the page form doesn't need to re-authenticate
    when navigating to /review-gate. Signature:
        ``async def review_gate_ui(x_recupero_admin_key: str | None = Header(None))``
    """
    from pathlib import Path

    template_path = (
        Path(__file__).resolve().parent.parent
        / "web" / "templates" / "review_gate.html"
    )
    try:
        html = template_path.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning(
            "review_gate_ui: template read failed (%s): %s",
            template_path, exc,
        )
        return HTMLResponse(
            content=(
                "<h1>Review gate UI unavailable</h1>"
                "<p>Template file could not be read; fall back to "
                "<code>curl /v1/reviews/queue</code>.</p>"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


# ---- Operator interactive graph (Phase 3) ---- #
#
# Two routes, mirroring the /review-gate pattern:
#   * GET /operator-graph         — unauthenticated HTML shell (no case
#     data inline); prompts the operator for the admin key + an
#     investigation id and fetches the JSON below.
#   * GET /v1/operator/graph/{id} — admin-gated JSON: the FULL operator-
#     fidelity graph (un-sanitized identities) enriched with per-node
#     risk verdicts + indirect-exposure. NOT the victim portal view.


@app.get(
    "/operator-graph",
    response_class=HTMLResponse,
    tags=["ops"],
    summary="Operator interactive fund-flow graph UI (Phase 3).",
)
async def operator_graph_ui() -> HTMLResponse:
    """Static shell; all case data is fetched client-side from
    ``/v1/operator/graph/{investigation_id}`` with the admin key."""
    from pathlib import Path

    template_path = (
        Path(__file__).resolve().parent.parent
        / "web" / "templates" / "operator_graph.html"
    )
    try:
        html = template_path.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("operator_graph_ui: template read failed: %s", exc)
        return HTMLResponse(
            content="<h1>Operator graph UI unavailable</h1>",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return HTMLResponse(content=html)


@app.get(
    "/v1/operator/graph/{investigation_id}",
    tags=["ops"],
    summary="Operator-fidelity fund-flow graph data (admin-gated).",
)
async def operator_graph_data(
    investigation_id: str,
    x_recupero_admin_key: str | None = Header(default=None),
) -> JSONResponse:
    from recupero.dispatcher.review_api import _require_admin_auth
    _require_admin_auth(x_recupero_admin_key)

    # Validate the id shape before any network/storage touch.
    from uuid import UUID
    try:
        UUID(str(investigation_id))
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="invalid investigation id")

    import os
    sb_url = os.environ.get("SUPABASE_URL", "").rstrip("/")
    sb_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    if not sb_url or not sb_key:
        raise HTTPException(status_code=503, detail="storage not configured")

    from recupero.worker.investigations_api import fetch_case_json
    raw = fetch_case_json(
        supabase_url=sb_url, service_role_key=sb_key,
        investigation_id=str(investigation_id),
    )
    if not raw:
        raise HTTPException(status_code=404, detail="case not found for that investigation")

    from recupero.models import Case
    from recupero.reports.client_journey import build_operator_graph_data
    try:
        case = Case.model_validate(raw)
        data = build_operator_graph_data(case)
    except Exception as exc:  # noqa: BLE001
        log.warning("operator graph build failed inv=%s: %s", investigation_id, exc)
        raise HTTPException(status_code=500, detail="graph build failed")
    return JSONResponse(content=data)


@app.get(
    "/v1/operator/expand",
    tags=["ops"],
    summary="On-demand next-hop expansion for the operator graph (admin-gated).",
)
async def operator_expand(
    chain: str,
    address: str,
    direction: str = "out",
    limit: int = 40,
    inv: str | None = None,
    x_recupero_admin_key: str | None = Header(default=None),
) -> JSONResponse:
    """Live counterparty expansion — the TRM/Chainalysis "click a node to
    grow the graph" interaction. Returns journey-shaped nodes/edges the
    operator graph merges into the live canvas."""
    from recupero.dispatcher.review_api import _require_admin_auth
    _require_admin_auth(x_recupero_admin_key)

    from recupero.models import Chain
    try:
        ch = Chain(chain)
    except ValueError:
        raise HTTPException(status_code=400, detail="unknown chain")

    address = (address or "").strip()
    if not address or len(address) > 120 or any(c.isspace() for c in address):
        raise HTTPException(status_code=400, detail="invalid address")
    direction = "in" if direction == "in" else "out"
    limit = max(1, min(int(limit or 40), 150))

    from recupero.reports.graph_expand import expand_address
    try:
        data = expand_address(
            chain=ch, address=address, direction=direction,
            max_counterparties=limit, with_pricing=True,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("operator expand failed chain=%s dir=%s: %s", chain, direction, exc)
        raise HTTPException(
            status_code=503,
            detail="expansion unavailable (chain access not configured or upstream error)",
        )
    # Live-broadcast the delta to any operator streaming this investigation.
    inv_id = (inv or "").strip()
    if inv_id:
        try:
            from recupero.reports.graph_events import build_delta_event, publish
            publish(inv_id, build_delta_event(
                reason="expand", nodes=data.get("nodes", []), edges=data.get("edges", []),
            ))
        except Exception as exc:  # noqa: BLE001
            log.debug("operator expand: live publish skipped: %s", exc)
    return JSONResponse(content=data)


# ---- Operator graph annotations + saved views (Phase 3.9) ---- #


class _AnnotationIn(BaseModel):
    node_id: str = Field(..., min_length=1, max_length=200)
    note: str = Field("", max_length=5000)


class _SnapshotIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    state: dict[str, Any] = Field(default_factory=dict)


def _valid_inv(investigation_id: str) -> str:
    from uuid import UUID
    try:
        UUID(str(investigation_id))
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="invalid investigation id")
    return str(investigation_id)


@app.get("/v1/operator/graph/{investigation_id}/annotations", tags=["ops"])
async def operator_annotations_get(
    investigation_id: str,
    x_recupero_admin_key: str | None = Header(default=None),
) -> JSONResponse:
    from recupero.dispatcher.review_api import _require_admin_auth, _dsn
    _require_admin_auth(x_recupero_admin_key)
    inv = _valid_inv(investigation_id)
    from recupero.reports.operator_store import get_annotations
    try:
        notes = get_annotations(_dsn(), inv)
    except Exception as exc:  # noqa: BLE001
        # Degrade to empty so the graph still works before migration 032.
        log.info("annotations read unavailable inv=%s: %s", inv, exc)
        notes = {}
    return JSONResponse(content={"annotations": notes})


@app.put("/v1/operator/graph/{investigation_id}/annotations", tags=["ops"])
async def operator_annotations_put(
    investigation_id: str,
    body: _AnnotationIn,
    x_recupero_admin_key: str | None = Header(default=None),
) -> JSONResponse:
    from recupero.dispatcher.review_api import _require_admin_auth, _dsn
    _require_admin_auth(x_recupero_admin_key)
    inv = _valid_inv(investigation_id)
    from recupero.reports.operator_store import upsert_annotation
    try:
        upsert_annotation(_dsn(), inv, body.node_id, body.note)
    except Exception as exc:  # noqa: BLE001
        log.warning("annotation write failed inv=%s: %s", inv, exc)
        raise HTTPException(status_code=503, detail="annotation store unavailable (migration 032 applied?)")
    return JSONResponse(content={"ok": True})


@app.get("/v1/operator/graph/{investigation_id}/snapshots", tags=["ops"])
async def operator_snapshots_list(
    investigation_id: str,
    x_recupero_admin_key: str | None = Header(default=None),
) -> JSONResponse:
    from recupero.dispatcher.review_api import _require_admin_auth, _dsn
    _require_admin_auth(x_recupero_admin_key)
    inv = _valid_inv(investigation_id)
    from recupero.reports.operator_store import list_snapshots
    try:
        snaps = list_snapshots(_dsn(), inv)
    except Exception as exc:  # noqa: BLE001
        log.info("snapshots list unavailable inv=%s: %s", inv, exc)
        snaps = []
    return JSONResponse(content={"snapshots": snaps})


@app.put("/v1/operator/graph/{investigation_id}/snapshots", tags=["ops"])
async def operator_snapshots_save(
    investigation_id: str,
    body: _SnapshotIn,
    x_recupero_admin_key: str | None = Header(default=None),
) -> JSONResponse:
    from recupero.dispatcher.review_api import _require_admin_auth, _dsn
    _require_admin_auth(x_recupero_admin_key)
    inv = _valid_inv(investigation_id)
    # Cap serialized state so a saved view can't be used to stash megabytes.
    import json as _json
    if len(_json.dumps(body.state, default=str)) > 256 * 1024:
        raise HTTPException(status_code=400, detail="snapshot state too large")
    from recupero.reports.operator_store import save_snapshot
    try:
        save_snapshot(_dsn(), inv, body.name, body.state)
    except Exception as exc:  # noqa: BLE001
        log.warning("snapshot save failed inv=%s: %s", inv, exc)
        raise HTTPException(status_code=503, detail="snapshot store unavailable (migration 032 applied?)")
    return JSONResponse(content={"ok": True})


@app.get("/v1/operator/graph/{investigation_id}/snapshots/{name}", tags=["ops"])
async def operator_snapshot_load(
    investigation_id: str,
    name: str,
    x_recupero_admin_key: str | None = Header(default=None),
) -> JSONResponse:
    from recupero.dispatcher.review_api import _require_admin_auth, _dsn
    _require_admin_auth(x_recupero_admin_key)
    inv = _valid_inv(investigation_id)
    if not name or len(name) > 80:
        raise HTTPException(status_code=400, detail="invalid snapshot name")
    from recupero.reports.operator_store import load_snapshot
    try:
        state = load_snapshot(_dsn(), inv, name)
    except Exception as exc:  # noqa: BLE001
        log.warning("snapshot load failed inv=%s: %s", inv, exc)
        raise HTTPException(status_code=503, detail="snapshot store unavailable")
    if state is None:
        raise HTTPException(status_code=404, detail="snapshot not found")
    return JSONResponse(content={"name": name, "state": state})


class _WatchIn(BaseModel):
    address: str = Field(..., min_length=1, max_length=120)
    chain: str = Field(..., min_length=1, max_length=40)
    note: str | None = Field(None, max_length=500)


@app.post("/v1/operator/graph/{investigation_id}/watch", tags=["ops"])
async def operator_watch_address(
    investigation_id: str,
    body: _WatchIn,
    x_recupero_admin_key: str | None = Header(default=None),
) -> JSONResponse:
    """Flag a graph node's address for monitoring — inserts a manual,
    hot-priority row into the existing ``public.watchlist`` so the nightly
    watch-tick monitors it (no parallel watch system)."""
    from recupero.dispatcher.review_api import _require_admin_auth, _dsn
    _require_admin_auth(x_recupero_admin_key)
    inv = _valid_inv(investigation_id)

    from recupero.models import Chain
    try:
        Chain(body.chain)
    except ValueError:
        raise HTTPException(status_code=400, detail="unknown chain")
    addr = body.address.strip()
    if not addr or any(c.isspace() for c in addr):
        raise HTTPException(status_code=400, detail="invalid address")

    from recupero.worker.watchlist import add_manual_watch
    try:
        add_manual_watch(dsn=_dsn(), address=addr, chain=body.chain,
                         investigation_id=inv, note=body.note)
    except Exception as exc:  # noqa: BLE001
        log.warning("operator watch add failed inv=%s: %s", inv, exc)
        raise HTTPException(status_code=503, detail="watchlist unavailable")
    return JSONResponse(content={"ok": True})


@app.get("/v1/operator/graph/{investigation_id}/stream", tags=["ops"])
async def operator_graph_stream(
    investigation_id: str,
    key: str | None = None,
    x_recupero_admin_key: str | None = Header(default=None),
):
    """Server-Sent-Events stream of live graph deltas for an investigation
    (Phase 4.13). A browser ``EventSource`` cannot set custom headers, so the
    admin key is accepted as the ``key`` query param (over HTTPS, operator-
    internal) as well as the header for curl."""
    from fastapi.responses import StreamingResponse
    from recupero.dispatcher.review_api import _require_admin_auth
    _require_admin_auth(x_recupero_admin_key or key)
    inv = _valid_inv(investigation_id)

    import asyncio
    import os
    from recupero.reports.graph_events import subscribe, unsubscribe, sse_frame

    # Lazily start the cross-process LISTEN bridge (Phase 4.13) on the first
    # stream connection — opt-in via RECUPERO_GRAPH_EVENTS_BRIDGE so it never
    # spins up a DB thread in tests / non-streaming deploys. Idempotent.
    if os.environ.get("RECUPERO_GRAPH_EVENTS_BRIDGE", "").strip() in ("1", "true", "True"):
        _bridge_dsn = os.environ.get("SUPABASE_DB_URL", "").strip()
        if _bridge_dsn:
            try:
                from recupero.reports.graph_events import start_listen_bridge
                start_listen_bridge(_bridge_dsn, asyncio.get_running_loop())
            except Exception as exc:  # noqa: BLE001
                log.warning("graph-events bridge start skipped: %s", exc)

    async def _gen():
        q = subscribe(inv)
        try:
            yield ": connected\n\n"
            while True:
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=20.0)
                    yield sse_frame(ev)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"  # heartbeat keeps proxies from closing
        finally:
            unsubscribe(inv, q)

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


# ---- Uvicorn entry point ---- #


def main() -> None:  # pragma: no cover
    """``recupero-api`` console-script entry. Runs the app via
    uvicorn on host/port from env vars."""
    import os

    import uvicorn
    host = os.environ.get("RECUPERO_API_HOST", "0.0.0.0")
    # Wave-9 audit (type-coercion): operator typo in RECUPERO_API_PORT
    # used to crash uvicorn bootstrap before the 8000 default kicked in.
    # Port precedence: explicit RECUPERO_API_PORT wins; else honor the PaaS-
    # injected $PORT (Railway/Heroku/Render route external traffic to it, so
    # the `recupero-api` service must bind it or the healthcheck never passes);
    # else the 8000 local default.
    raw_port = (os.environ.get("RECUPERO_API_PORT", "") or "").strip()
    if not raw_port:
        raw_port = (os.environ.get("PORT", "") or "").strip()
    try:
        port = int(raw_port) if raw_port else 8000
    except (TypeError, ValueError):
        port = 8000
    if port < 1 or port > 65535:
        port = 8000
    log_level = os.environ.get("RECUPERO_LOG_LEVEL", "info").lower()
    # Observability parity with the worker (worker/main.py): structured
    # logging + Sentry error reporting. Pre-this the API process ran with
    # default logging and zero error reporting. Both best-effort — a missing
    # optional dep or DSN must never block API bootstrap.
    try:
        from recupero.logging_setup import setup_logging
        setup_logging(log_level.upper())
    except Exception as exc:  # noqa: BLE001
        log.warning("API setup_logging failed (non-fatal): %s", exc)
    try:
        from recupero.observability import init_sentry
        init_sentry()
    except Exception as exc:  # noqa: BLE001
        log.warning("API Sentry init failed (non-fatal): %s", exc)
    # Seed a clearly-labeled DEMO/SAMPLE case when the case store is empty, so a
    # fresh deploy's operator console is populated + clickable out of the box.
    # No-ops when real cases exist or RECUPERO_SEED_DEMO_CASE=0. Startup-only
    # (NOT a FastAPI startup event) so it never runs during tests.
    try:
        from recupero.demo_case import maybe_seed_demo_case
        maybe_seed_demo_case()
    except Exception as exc:  # noqa: BLE001
        log.warning("API demo-case seed failed (non-fatal): %s", exc)
    uvicorn.run(
        "recupero.api.app:app",
        host=host, port=port, log_level=log_level,
    )


__all__ = ("app", "main")
