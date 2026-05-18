"""Recupero REST API service (v0.15.1).

Exposes the existing screening / token-risk / monitoring / correlation
capabilities as authenticated REST endpoints so exchanges, compliance
teams, KYC providers, and recovery attorneys can integrate against an
OpenAPI-described surface — the TRM Labs business model, monetizing
the platform layer separately from the recovery-service layer.

Endpoints
---------

  POST /v1/screen
    Screen a single address against OFAC + mixer + ransomware +
    drainer seed data plus the cross-case correlation index.
    Returns the same ScreeningResult the CLI prints, JSON-encoded.

  POST /v1/token-risk
    Token honeypot / rug-pull risk score. Accepts contract address +
    optional bytecode + tx-history stats + GoPlus result.

  GET /v1/correlations/{address}
    Cross-case correlation lookup. Returns prior-case count + flags
    (OFAC / mixer / drainer exposure).

  GET /v1/health
    Liveness check. Returns version + git_sha + uptime. Used by
    Railway / Kubernetes health-probes AND by the deploy script's
    /health verification.

  GET /docs (FastAPI built-in)
    Interactive OpenAPI/Swagger documentation.

  GET /openapi.json (FastAPI built-in)
    Machine-readable OpenAPI 3.1 spec for client SDK generation.

Auth
----

API-key auth via the ``X-Recupero-API-Key`` header. Keys live in
``RECUPERO_API_KEYS`` env var as a comma-separated list of
``key_name:secret`` pairs (e.g.,
``binance-compliance:sk-abc123,kraken-aml:sk-def456``). Per-key
rate limits enforced by an in-process token bucket.

Local development / unauthenticated mode: set
``RECUPERO_API_AUTH_OPTIONAL=1`` and the auth middleware passes
through. NEVER set this in production.

Run
---

  recupero-api  # console-script alias for the FastAPI app

  # Or directly:
  uvicorn recupero.api.app:app --host 0.0.0.0 --port 8000

OpenAPI spec auto-publishes at ``/openapi.json``; FastAPI's Swagger
UI at ``/docs``.
"""
