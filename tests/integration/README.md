# Integration tests

These tests exercise the **seams between Recupero and the outside world**
that unit tests can't cover: real DB writes, real HTTP shapes, real PDF
rendering. They're gated on an opt-in env var so the routine
`pytest tests/` stays fast.

## Quick start

```bash
# Run the integration suite (mocked external APIs, real test DB)
export RECUPERO_RUN_INTEGRATION=1
export RECUPERO_INTEGRATION_DSN="postgresql://USER:PASS@HOST:6543/recupero_test"
pytest tests/integration/ -v

# Also hit real external services (Etherscan, Helius, CoinGecko, Resend)
# Use sparingly — burns API budget + slower
export RECUPERO_INTEGRATION_LIVE=1
export ETHERSCAN_API_KEY=...
export HELIUS_API_KEY=...
export RESEND_API_KEY=...
pytest tests/integration/ -v -m live
```

## Why gated?

Recupero unit tests (in `tests/test_*.py`) are pure and fast — 1455 tests
run in ~85 seconds with zero external dependencies. They mock at the
boundary of each module (DB connection, HTTP client, filesystem write).

Integration tests are slower, depend on configuration, and would either
burn API budget or fail spuriously in CI without external setup. So
they're opt-in.

## Fixtures (defined in `conftest.py`)

* `integration_enabled` (session-scoped, autouse): skips the entire
  package if `RECUPERO_RUN_INTEGRATION != "1"`.
* `integration_dsn`: yields a Postgres DSN pointing at a TEST DB. Refuses
  to run if the DSN's db-name doesn't contain `test` or `_int` — safety
  guard against accidentally running migrations against a production DB.
* `clean_case_dir(tmp_path)`: a fresh case directory layout for the
  worker pipeline (case.json + briefs/ subdir).
* `live_mode_required`: tests that need real external services depend on
  this; skips unless `RECUPERO_INTEGRATION_LIVE=1`.

## Test catalog

| File | Covers |
|---|---|
| `test_stripe_to_dispatcher.py` | Stripe webhook → dispatcher → DB |
| `test_trace_to_brief.py` | trace CLI → emit_brief → freeze_brief.json |
| `test_brief_to_pdf.py` | generate_briefs → WeasyPrint PDF render |
| `test_bucket_roundtrip.py` | upload_case_dir → bucket read → schema check |

## Adding a new integration test

1. Add `from __future__ import annotations` at the top.
2. Use the fixtures from `conftest.py`. Do NOT redefine `tmp_path` etc.
3. Mark slow tests with `@pytest.mark.slow` so they can be opted out of.
4. Mark tests that need real services with `@pytest.mark.live` — these
   skip unless `RECUPERO_INTEGRATION_LIVE=1` (the `live_mode_required`
   fixture handles this).
5. Document the test's purpose in a module docstring — what seam does
   it cover, what failure does it surface?

## Layering vs unit tests

| Layer | Path | Speed | Mocking | Network |
|---|---|---|---|---|
| Unit | `tests/test_*.py` | Fast | At module boundary | None |
| Integration (default) | `tests/integration/test_*.py` | Slow | At HTTP/DB layer | Mocked via respx |
| Integration (live) | same files, `@pytest.mark.live` | Slowest | None | Real |

A unit test that grew an HTTP mock should probably move here. A unit test
that mocks a method on the module under test belongs in unit.

## Known limitations

* No real Stripe webhook delivery — we synthesize the signed webhook
  body locally. To verify against real Stripe redelivery, use
  Stripe CLI's `stripe trigger checkout.session.completed`.
* No real WeasyPrint subprocess validation in mocked mode — the
  `test_brief_to_pdf.py` runs the subprocess for real (since
  WeasyPrint is local). Skip on Windows where font configuration is
  fragile.
* No real bucket roundtrip in mocked mode — the bucket fixture
  uses an in-memory `MockBucket` matching the Supabase Storage REST
  contract.
