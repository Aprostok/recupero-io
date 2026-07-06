"""Recupero SaaS platform layer — the multi-tenant product shell around the
forensic engine.

The engine (``recupero.trace``, chain adapters, freeze artifacts) and the
Postgres ``investigations`` job queue already exist and scale horizontally. This
package adds what a self-serve, multi-tenant SaaS needs on top:

  * ``tenancy``  — pure crypto + plan/quota policy (stdlib only, no new deps)
  * ``store``    — psycopg data access (orgs / users / keys / usage / queue), org-scoped
  * ``deps``     — FastAPI auth (JWT + org API key) + per-org rate limiting
  * ``router``   — the ``/v2`` tenant API (signup/login, keys, async traces)

Mount into the existing FastAPI app with::

    from recupero.platform.router import router as platform_router
    app.include_router(platform_router)
"""
