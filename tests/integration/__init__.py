"""Integration tests gated on RECUPERO_RUN_INTEGRATION=1.

Unit tests (everything in `tests/test_*.py`) run in every CI build
without external dependencies — they mock the network, the DB, and
the filesystem at the boundary of each module.

Integration tests in THIS package exercise the seams between
Recupero and the outside world:

  * Stripe webhook → payments.dispatcher → DB state transition
  * recupero trace → real Etherscan V2 (or respx-mocked) → case bundle
  * worker pipeline → emit_brief → WeasyPrint PDF render
  * bucket upload → Supabase Storage → bucket read

By default these tests SKIP at collection time unless the operator
opts in with ``RECUPERO_RUN_INTEGRATION=1``. This keeps `pytest tests/`
fast for routine work but lets a release-blocking smoke run before
each ship.

How to run:
    RECUPERO_RUN_INTEGRATION=1 pytest tests/integration/ -v

How to add a new integration test:
    See `tests/integration/README.md` for the fixture catalog and
    layering conventions. New tests should use the `integration_db`
    + `mocked_external_apis` fixtures unless they explicitly want
    real-service coverage (then set RECUPERO_INTEGRATION_LIVE=1).
"""
