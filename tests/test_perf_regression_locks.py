"""Performance-regression locks on seven hot paths.

Each test exercises a hot path with a realistic input shape and asserts
the median walltime over multiple iterations fits inside a documented
budget. The budgets are NOT "the fastest we can go" — they're set with
a ~3x safety margin over the median observed on a modest dev box (Win11
laptop). A refactor that accidentally turns an O(N) walk into an O(N²)
walk, or a regression that introduces a 5-10x slowdown (e.g., dropping
a memoization, recompiling a regex inside a hot loop, opening + closing
a file per iteration instead of once per call), will blow through the
budget and fail the test loudly.

Why a 3x margin: dev-machine background load, CPU throttling, antivirus
scans, and CI-runner heterogeneity all swing tight perf numbers by
2-3x without anything actually being wrong. We're catching algorithmic
regressions (10x+), not micro-benchmarking. A budget that fires on
normal noise would just train operators to ignore the signal.

These tests are gated behind `@pytest.mark.slow` so the fast inner-loop
CI run skips them. Opt back in with `pytest -m slow tests/test_perf_regression_locks.py`.
The `addopts` in pyproject.toml sets `-m "not slow"` as the default.

Hot paths covered (in spec-order):

  1. ``recupero._common.canonical_address_key`` — called per-address in
     every aggregation pass (flow diagram, graph_ui, label store,
     correlation, dormant detector). 100k calls because a real case
     traces ~5k transfers and each touches 2-4 addresses, with
     dedup/correlation passes multiplying that ~5-10x.
  2. ``recupero.hack_tracker.models._HTML_TAG_RE.sub`` — the W11-01
     ReDoS hardening cap. 16KB was the v0.20.x ceiling chosen because
     it sits comfortably above any realistic title/summary/actor
     field and well below the multi-MB sizes that turned the scrub
     into a DoS. If someone removes the 16KB cap, this test won't
     catch it (the perf path is fine at 16KB); the W11-01 unit test
     covers that. This test guards the OTHER direction: that the
     16KB path itself stays fast.
  3. ``recupero.worker._flow_diagram._aggregate`` — driver of both
     the Graphviz SVG and the D3 interactive graph. 1000 transfers /
     100 distinct addresses is a representative mid-sized case.
  4. ``recupero.reports.graph_ui.build_graph_data`` — calls
     ``_aggregate`` plus per-node/per-edge JSON serialization. 500
     nodes is on the larger side of what we render (the renderer
     itself caps further), so this locks the JSON-build path.
  5. ``recupero.labels.store.LabelStore.lookup`` — called per
     counterparty in every screening pass. 1000 lookups after a
     normal seed load is a representative trace burst.
  6. ``recupero.validators.output_integrity.validate_case_output`` —
     runs 25+ structural checks across the case-output dir. The
     budget is 5s because the validator opens every HTML in the
     dir and runs regex / soup checks; the SLO is "completes in
     normal operator-wait time" not "fast as possible".
  7. ``recupero.pricing.cache.PriceCache`` round-trip — the file-
     backed cache opens + writes a JSON file per put. 1000 ops is
     where we'd notice if someone accidentally introduced fsync on
     every write or switched from sha1-hashed filenames to a per-
     entry directory walk.
"""

from __future__ import annotations

import json
import statistics
import time
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

# All tests in this file are perf-regression locks. They take longer
# than the typical unit test (a few hundred ms each) so they're
# behind the `slow` marker — pyproject.toml's default `addopts`
# excludes that marker, so opting in is explicit (`-m slow`).
pytestmark = pytest.mark.slow


# ──────────────────────────────────────────────────────────────────
# Shared helpers
# ──────────────────────────────────────────────────────────────────


def _median_seconds(fn, *, iterations: int) -> float:
    """Run ``fn`` ``iterations`` times after a single warmup and return
    the median walltime in seconds.

    Median (not mean) so a single GC pause / antivirus stall on one
    iteration doesn't dominate the result. Warmup is critical: the
    first call pays import / module-load / regex-compile / cache-cold
    costs that subsequent calls don't.
    """
    fn()  # warmup
    samples: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples)


# ──────────────────────────────────────────────────────────────────
# 1. canonical_address_key — 100k calls ≤ 0.5s
# ──────────────────────────────────────────────────────────────────


def test_perf_canonical_address_key_100k_calls_under_500ms() -> None:
    """``canonical_address_key`` is on the hot path for every per-
    address dedup / lookup in the aggregator + label store. 100k
    calls models a mid-size case with ~5k transfers feeding multiple
    correlation / clustering passes.

    Budget: 0.5s median. The pure-Python implementation does a
    ``startswith`` + length check + an all-hex char-class scan + a
    ``.lower()`` — measured ~150ms / 100k on a modest laptop.
    Budget is ~3x that to absorb GC and OS noise.
    """
    from recupero._common import canonical_address_key

    # Mix of address shapes the function actually sees:
    #   * EVM checksum (hits the hot 0x + 40-hex branch + .lower())
    #   * EVM lowercase (same hot branch, .lower() is idempotent)
    #   * Solana base58 (passes through; verifies the early non-EVM exit)
    #   * Tron base58 (passes through, 34 chars — len != 42 short-circuit)
    addrs = [
        "0xABCD1234CafeBabeDeadBeef0123456789ABCDEF",
        "0xabcdef0123456789abcdef0123456789abcdef01",
        "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
        "TKzzWoyTtPx7Qzv7mZhVQv7gMC6Q5kbz9w",
    ]

    def run() -> None:
        # Pull locals once; attribute lookups inside the tight loop
        # would skew the measurement.
        fn = canonical_address_key
        a = addrs
        for i in range(100_000):
            fn(a[i & 3])

    elapsed = _median_seconds(run, iterations=3)
    assert elapsed <= 0.5, (
        f"canonical_address_key 100k calls took {elapsed:.3f}s "
        f"(budget 0.5s) — perf regression suspected"
    )


# ──────────────────────────────────────────────────────────────────
# 2. _HTML_TAG_RE.sub on 16KB ≤ 0.1s (W11-01 ReDoS fix lock)
# ──────────────────────────────────────────────────────────────────


def test_perf_html_tag_re_sub_16kb_under_100ms() -> None:
    """W11-01 capped the scrub input at 16KB to defang an O(N²)
    backtrack on dense-`<` inputs. This test locks the OTHER side:
    once we're at the 16KB ceiling, the substitution itself must
    stay fast. A pathological pattern (e.g., 16KB of `<<<<<<<...`)
    would trigger the same backtrack that motivated the cap; we
    verify that the post-cap path completes well inside the budget.

    Budget: 0.1s median. The fix made the worst-case linear, so
    even a hostile input should be ~10ms on a modern CPU; 0.1s
    gives 10x headroom.
    """
    from recupero.hack_tracker.models import _HTML_TAG_RE

    # Build a 16KB worst-ish input: many unmatched `<` interleaved
    # with realistic markup. This is the shape that pre-W11-01
    # blew up — every `<` triggered a scan-to-end-of-string.
    chunk = "<p>foo <b>bar</b> <<<< unclosed " + "x" * 32
    raw = (chunk * 1024)[:16384]
    assert len(raw) == 16384

    def run() -> None:
        _HTML_TAG_RE.sub("", raw)

    elapsed = _median_seconds(run, iterations=5)
    assert elapsed <= 0.1, (
        f"_HTML_TAG_RE.sub on 16KB took {elapsed:.4f}s "
        f"(budget 0.1s) — W11-01 ReDoS regression suspected"
    )


# ──────────────────────────────────────────────────────────────────
# Shared Case-fixture builder for path 3 + 4.
# ──────────────────────────────────────────────────────────────────


def _build_realistic_case(*, n_transfers: int, n_addrs: int):
    """Build a real ``Case`` with ``n_transfers`` real ``Transfer``
    objects spanning ``n_addrs`` unique addresses.

    Returns a real pydantic ``Case`` (not a stub) — the perf budgets
    must reflect the real validation overhead the production code
    pays. The seed address is at index 0; transfers fan out across
    indices 1..n_addrs.
    """
    from recupero.models import (
        Case,
        Chain,
        Counterparty,
        TokenRef,
        Transfer,
    )

    def _addr(i: int) -> str:
        # Deterministic EVM-shaped address: 0x + 40 hex chars.
        return "0x" + f"{i:040x}"

    ts = datetime(2026, 1, 1, tzinfo=UTC)
    token = TokenRef(
        chain=Chain.ethereum,
        contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        symbol="USDC", decimals=6, coingecko_id="usd-coin",
    )
    transfers: list[Transfer] = []
    for i in range(n_transfers):
        # Spread (from, to) over the address pool. Modulo guarantees
        # we hit every address at least once when n_transfers >= n_addrs.
        f_idx = i % n_addrs
        t_idx = (i + 1) % n_addrs
        from_a = _addr(f_idx)
        to_a = _addr(t_idx)
        tx_hash = "0x" + f"{i:064x}"
        transfers.append(Transfer(
            transfer_id=f"ethereum:{tx_hash}:{i}",
            chain=Chain.ethereum,
            tx_hash=tx_hash,
            block_number=10_000_000 + i,
            block_time=ts,
            from_address=from_a,
            to_address=to_a,
            counterparty=Counterparty(
                address=to_a, label=None, is_contract=False,
            ),
            token=token,
            amount_raw=str(1_000_000 * (i + 1)),
            amount_decimal=Decimal(i + 1),
            usd_value_at_tx=Decimal(i + 1),
            hop_depth=1,
            explorer_url=f"https://etherscan.io/tx/{tx_hash}",
            fetched_at=ts,
        ))
    return Case(
        case_id="PERF-TEST",
        seed_address=_addr(0),
        chain=Chain.ethereum,
        incident_time=ts,
        transfers=transfers,
        trace_started_at=ts,
        software_version="perf-test",
        config_used={},
    )


# ──────────────────────────────────────────────────────────────────
# 3. flow_diagram._aggregate on 1000 transfers / 100 addrs ≤ 1s
# ──────────────────────────────────────────────────────────────────


def test_perf_flow_diagram_aggregate_1000_transfers_under_1s() -> None:
    """``_aggregate`` is the shared backend for the static SVG +
    interactive D3 renderers. It walks every transfer, canonicalizes
    addresses, classifies counterparties, and collapses parallel
    edges into a dict keyed by (from, to, src_chain, dst_chain).

    Budget: 1s median for 1000 transfers spanning 100 distinct
    addresses. Each transfer pays ~2 canonical_address_key calls
    + a setdefault + arithmetic on Decimal totals. Linear in
    transfer count; ~50-200ms expected, 1s is the ~5x safety budget.
    """
    from recupero.worker._flow_diagram import _aggregate

    case = _build_realistic_case(n_transfers=1000, n_addrs=100)

    def run() -> None:
        nodes, edges = _aggregate(case)
        # Sanity-check the aggregator did real work; otherwise a
        # silent regression that early-returns would pass the perf
        # test by being trivially fast.
        assert nodes
        assert edges

    elapsed = _median_seconds(run, iterations=3)
    assert elapsed <= 1.0, (
        f"_aggregate on 1000 transfers / 100 addrs took {elapsed:.3f}s "
        f"(budget 1.0s) — perf regression suspected"
    )


# ──────────────────────────────────────────────────────────────────
# 4. graph_ui.build_graph_data on ~500 nodes ≤ 1s
# ──────────────────────────────────────────────────────────────────


def test_perf_graph_ui_build_graph_data_500_nodes_under_1s() -> None:
    """``build_graph_data`` calls ``_aggregate`` then walks the
    resulting node + edge dicts to produce JSON-serializable
    GraphNode / GraphEdge dicts (with formatted USD strings,
    chain-color lookups, explorer URLs).

    Budget: 1s median. We feed 600 transfers spanning 500 unique
    addresses so the rendered graph hits ~500 nodes — the rough
    upper end of what we'd render before pruning.
    """
    from recupero.reports.graph_ui import build_graph_data

    case = _build_realistic_case(n_transfers=600, n_addrs=500)

    def run() -> None:
        data = build_graph_data(case)
        # Spot-check we generated a non-trivial graph.
        assert len(data["nodes"]) >= 100
        assert len(data["edges"]) >= 100

    elapsed = _median_seconds(run, iterations=3)
    assert elapsed <= 1.0, (
        f"build_graph_data on 500-node graph took {elapsed:.3f}s "
        f"(budget 1.0s) — perf regression suspected"
    )


# ──────────────────────────────────────────────────────────────────
# 5. LabelStore.lookup × 1000 ≤ 0.5s
# ──────────────────────────────────────────────────────────────────


def test_perf_label_store_lookup_1000_addrs_under_500ms() -> None:
    """``LabelStore.lookup`` is called per counterparty in screening,
    correlation, and the freeze pipeline. The store loads seed JSON
    lists at startup; lookup is a checksum-normalize + dict get.

    Budget: 0.5s median for 1000 lookups (after the store is loaded).
    The hot path is ``to_checksum_address`` (eth_utils, native-ish)
    plus a dict get. Loading the seeds is amortized — we time the
    1000-lookup burst, not the construction.
    """
    from recupero.config import RecuperoConfig
    from recupero.labels.store import LabelStore
    from recupero.models import Chain, Label, LabelCategory

    cfg = RecuperoConfig()
    store = LabelStore.load(cfg)

    # Mix:
    #   * 500 addresses that miss the store (the typical hot case
    #     during a fresh trace — most counterparties are unlabeled).
    #   * 500 addresses that we explicitly add as hits, so the dict-
    #     get branch is exercised too.
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    miss_addrs = ["0x" + f"{i:040x}" for i in range(500)]
    hit_addrs: list[str] = []
    for i in range(500, 1000):
        a = "0x" + f"{i:040x}"
        hit_addrs.append(a)
        store.add(Label(
            address=a, name=f"label-{i}", category=LabelCategory.unknown,
            source="perf-test", confidence="medium", added_at=ts,
        ))
    addrs = miss_addrs + hit_addrs

    def run() -> None:
        s = store
        chain = Chain.ethereum
        for a in addrs:
            s.lookup(a, chain=chain)

    elapsed = _median_seconds(run, iterations=3)
    assert elapsed <= 0.5, (
        f"LabelStore.lookup 1000 addrs took {elapsed:.3f}s "
        f"(budget 0.5s) — perf regression suspected"
    )


# ──────────────────────────────────────────────────────────────────
# 6. validate_case_output on normal case dir ≤ 5s
# ──────────────────────────────────────────────────────────────────


def _build_perf_case_dir(root: Path) -> Path:
    """Build a normal-shape case-output directory the validator can
    walk end-to-end without finding any critical / high issue.

    Mirrors the minimal-good-case in test_output_integrity_validator.py
    but inlined here so the perf test owns its fixture (the validator
    tests can churn without breaking the perf lock)."""
    case_dir = root / "case"
    briefs = case_dir / "briefs"
    briefs.mkdir(parents=True)

    def _w(path: Path, content: str) -> None:
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(content)

    _w(case_dir / "freeze_asks.json", json.dumps({
        "by_issuer": {
            "Tether": [{"freeze_capability": "yes", "token": "USDT"}],
        }
    }))
    freeze_brief = {
        "CASE_ID": "PERF",
        "TOTAL_FREEZABLE_USD": "$1,000.00",
        "MAX_RECOVERABLE_USD": "$1,000.00",
        "TOTAL_LOSS_USD": "$1,000.00",
        "victim": {"name": "Alice Victim"},
        "asset": {"symbol": "USDT", "issuer": "Tether"},
        "FREEZABLE": [{
            "issuer": "Tether", "token": "USDT",
            "freeze_capability": "yes",
            "holdings": [{"address": "0xaaa", "freeze_capability": "yes",
                          "status": "FREEZABLE"}],
        }],
        "ALL_ISSUER_HOLDINGS": [{
            "issuer": "Tether", "token": "USDT",
            "amount_usd": "$1,000.00", "status": "FREEZABLE",
        }],
    }
    _w(case_dir / "freeze_brief.json", json.dumps(freeze_brief))

    freeze_html = (
        "<!DOCTYPE html>\n<html>"
        "<head><title>Compliance Freeze Request to Tether — Case PERF</title></head>"
        "<body><h1>Freeze Request — Tether</h1>"
        "<p>To: compliance@tether.to</p>"
        "<p>USDT freeze. CASE_ID: PERF. Amount: $1,000.00.</p>"
        "</body></html>"
    )
    _w(briefs / "freeze_request_tether_BRIEF-PERF-1.html", freeze_html)
    le_html = (
        "<!DOCTYPE html>\n<html>"
        "<head><title>LE Handoff — Tether — Case PERF</title></head>"
        "<body><h1>LE Handoff — Tether</h1>"
        "<p>Victim: Alice Victim. CASE_ID: PERF.</p>"
        "<h2>1. Executive Summary</h2><div><p>USDT theft. "
        "The token is issued by Tether. Total loss: $1,000.00.</p></div>"
        "<h2>2. Asset</h2><p>Tether USDT</p>"
        "<h2>4.2 ALL_ISSUER_HOLDINGS</h2>"
        "<table><tr><td>Tether</td><td>USDT</td>"
        "<td>$1,000.00</td><td>FREEZABLE</td></tr></table>"
        "</body></html>"
    )
    _w(briefs / "le_handoff_tether_BRIEF-PERF-1.html", le_html)

    import hashlib
    fs = hashlib.sha256(freeze_html.encode()).hexdigest()
    ls = hashlib.sha256(le_html.encode()).hexdigest()
    _w(briefs / "manifest_BRIEF-PERF-1.json", json.dumps({
        "case_id": "PERF",
        "outputs": {
            "issuer_freeze_request": "freeze_request_tether_BRIEF-PERF-1.html",
            "le_handoff": "le_handoff_tether_BRIEF-PERF-1.html",
        },
        "output_sha256": {
            "issuer_freeze_request": fs, "le_handoff": ls,
        },
    }))
    _w(briefs / "trace_report_abc123.html",
       "<!DOCTYPE html>\n<html><body>"
       "<h1>Internal Trace Report — Case PERF</h1>"
       "<p>Victim: Alice Victim. Asset: USDT. Total: $1,000.00.</p>"
       "</body></html>")
    _w(briefs / "victim_summary_recoverable_def456.html",
       "<!DOCTYPE html>\n<html><body>"
       "<h1>Case Summary — Alice Victim</h1>"
       "<p>CASE_ID: PERF. $1,000.00 freezable.</p></body></html>")
    _w(briefs / "engagement_letter_ghi789.html",
       "<!DOCTYPE html>\n<html><body>"
       "<h1>Engagement Letter — Alice Victim</h1>"
       "<p>Fee: $1,000.00. CASE_ID: PERF.</p></body></html>")
    return case_dir


def test_perf_validate_case_output_under_5s(tmp_path: Path) -> None:
    """``validate_case_output`` runs ~27 structural invariants over
    every artifact in the case dir. On a normal-shape case (one
    issuer letter, one LE handoff, manifest, trace report, victim
    summary, engagement letter) the budget is 5s — generous because
    the validator does real file I/O + per-file regex / soup passes.

    A regression that turns one of the per-file checks into an
    O(files²) cross-comparison would blow through this budget on
    even a small fixture.
    """
    from recupero.validators.output_integrity import validate_case_output

    case_dir = _build_perf_case_dir(tmp_path)

    def run() -> Any:
        result = validate_case_output(case_dir)
        # Guard against a regression that short-circuits the
        # validator (e.g., early-return on a code path that
        # would silently skip every check).
        assert result.checks_run, "validator did no work"
        return result

    elapsed = _median_seconds(run, iterations=3)
    assert elapsed <= 5.0, (
        f"validate_case_output took {elapsed:.3f}s on normal-shape "
        f"case dir (budget 5.0s) — perf regression suspected"
    )


# ──────────────────────────────────────────────────────────────────
# 7. PriceCache get/put round-trip × 1000 ≤ 1s
# ──────────────────────────────────────────────────────────────────


def test_perf_price_cache_roundtrip_1000_ops_under_1s(tmp_path: Path) -> None:
    """File-backed ``PriceCache`` does an atomic write per put (write
    tmp, fsync-implicit-via-os.replace, rename) and a single open +
    json.load per get. 1000 round-trips models a mid-case pricing
    burst — every distinct (token, date) pair lives in its own file.

    Budget: 1s median. ~1ms per round-trip on a modest SSD is the
    expected ballpark; the 1s budget catches anything that
    accidentally adds per-op fsync, recompiles a regex, or stats
    every file in cache_dir instead of jumping straight to the
    hashed path.
    """
    from recupero.pricing.cache import PriceCache

    cache = PriceCache(tmp_path / "price_cache")
    # Pre-seed half the keys so the 1000-op burst hits a mix of
    # hit-existing-key (overwrite path) and write-new-key (cold path).
    seed_value = {"usd": "1.0001"}
    for i in range(500):
        cache.put(f"pre-{i}", seed_value)

    def run() -> None:
        # Each iteration: 500 puts of new keys + 500 gets of
        # pre-seeded keys. Mixing the workload prevents the OS
        # page cache from making either path trivially free.
        for i in range(500):
            cache.put(f"put-{i}", {"usd": str(i)})
        for i in range(500):
            cache.get(f"pre-{i}")

    elapsed = _median_seconds(run, iterations=3)
    assert elapsed <= 1.0, (
        f"PriceCache 1000-op round-trip took {elapsed:.3f}s "
        f"(budget 1.0s) — perf regression suspected"
    )


# ──────────────────────────────────────────────────────────────────
# Module-level smoke: make sure the `slow` marker really is opt-out.
# Run from the harness as a sanity check, NOT a perf lock.
# ──────────────────────────────────────────────────────────────────


@pytest.mark.slow
def test_slow_marker_is_opt_out_in_default_addopts() -> None:
    """Sanity: confirm pyproject.toml's `addopts` filters out `slow`
    by default. This test itself only runs when `-m slow` is passed,
    so simply reaching it proves the opt-in worked.

    Why this guard: a refactor that drops the `-m "not slow"` flag
    from addopts would silently run the perf suite in fast CI,
    producing flaky failures on slow runners. Better to have a
    no-op test document the contract.
    """
    # Locate the pyproject.toml (worktree root, one or two levels up from this file).
    here = Path(__file__).resolve()
    for candidate in (here.parents[1] / "pyproject.toml",
                      here.parents[2] / "pyproject.toml"):
        if candidate.is_file():
            txt = candidate.read_text(encoding="utf-8")
            # Find the addopts line in [tool.pytest.ini_options]. The
            # TOML basic-string form escapes inner quotes as `\"`, so
            # the file literally contains `-m \"not slow\"`. We search
            # for `addopts` then look for `not slow` somewhere on the
            # same line — that's both forgiving and load-bearing.
            for line in txt.splitlines():
                stripped = line.lstrip()
                if not stripped.startswith("addopts"):
                    continue
                assert "not slow" in stripped, (
                    "pyproject.toml addopts must include `-m \"not slow\"` "
                    "so the slow / perf-regression tests are opt-in by "
                    f"default. Found: {stripped!r}"
                )
                return
            pytest.fail("addopts line not found in pyproject.toml")
    pytest.skip("pyproject.toml not found from this worktree layout")
