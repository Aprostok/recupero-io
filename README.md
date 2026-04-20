# Recupero

**Mission:** Trace stolen cryptocurrency from a victim wallet to its endpoints — particularly centralized exchange deposits — and produce law-enforcement-ready evidence packages fast enough that funds can still be frozen.

**Why this exists:** Government agencies can act on stolen funds *only* when those funds reach a regulated centralized exchange. The window between deposit and withdrawal is hours to days. Existing tools (Arkham, Chainalysis, TRM) are excellent but expensive and built for analysts who already have the workflow. We need a tool that goes from `victim_address` to `LE-ready package` with minimal investigator time, so we can pursue cases at the velocity that freezing requires.

---

## Phased Build Plan

### Phase 1 (current): Ethereum-only single-hop tracer
- Input: a victim Ethereum address + incident timestamp
- Pulls all outbound transfers (native ETH and ERC-20)
- Resolves each counterparty against a labels database
- Fetches historical USD valuation at block timestamp
- Writes a structured `case.json` to disk
- **Acceptance test:** run against Zigha victim address, output reconciles with CFI's Attachment 08

### Phase 2: Rapid LE brief + full HTML report
- One-page "freeze brief" per detected exchange endpoint (priority output for tempo)
- Full HTML report in CFI/Zigha style (printable to PDF)
- Static graph rendering from case data

### Phase 3: Solana support
- Helius API integration
- Validates that Phase 1's data model is actually chain-agnostic

### Phase 4: Bridge decoding
- DeBridge, Wormhole, Across, Stargate, Symbiosis, 1inch Fusion, Hyperliquid bridge
- Auto-link source-chain tx to destination-chain tx

### Phase 5: Cross-case entity database
- Addresses identified in past cases auto-recognized in new ones
- The compounding asset that makes Recupero get smarter per case

### Out of scope (for now)
- Active monitoring / alerting
- Real-time price feeds
- Bitcoin, Hyperliquid, BSC, Arbitrum (added per case demand, not speculatively)
- Web UI (CLI-first; web comes later if useful)

---

## Repository Layout

```
recupero/
├── README.md                    # This file
├── pyproject.toml               # Python package definition + dependencies
├── .env.example                 # Template for API keys
├── .gitignore
├── config/
│   └── default.yaml             # Default trace parameters, rate limits, etc.
├── data/
│   ├── cases/                   # One folder per case, named by case_id
│   ├── labels/                  # Address label databases (JSON)
│   └── prices_cache/            # Cached historical price lookups
├── docs/
│   ├── PHASE1_SPEC.md           # Detailed Phase 1 spec — read before coding
│   ├── DATA_MODEL.md            # Schema for case.json, transfers, labels
│   ├── TRACE_ALGORITHM.md       # Pseudocode for the tracing logic
│   └── ZIGHA_TEST_HARNESS.md    # How to validate against Zigha case
├── scripts/
│   ├── trace_address.py         # CLI entry point for Phase 1
│   ├── seed_labels.py           # Bootstrap labels DB from public sources
│   └── verify_zigha.py          # Acceptance test runner
├── src/recupero/
│   ├── __init__.py
│   ├── config.py                # Loads config + .env
│   ├── models.py                # Pydantic models: Case, Transfer, Counterparty, Label
│   ├── chains/
│   │   ├── __init__.py
│   │   ├── base.py              # ChainAdapter abstract base class
│   │   └── ethereum/
│   │       ├── __init__.py
│   │       ├── adapter.py       # EthereumAdapter implementation
│   │       └── etherscan.py     # Thin wrapper over Etherscan API v2
│   ├── labels/
│   │   ├── __init__.py
│   │   ├── store.py             # LabelStore: lookup, add, persist
│   │   └── seeds/               # Static seed lists (CEX deposits, bridges, etc.)
│   ├── pricing/
│   │   ├── __init__.py
│   │   ├── coingecko.py         # CoinGecko historical price client
│   │   └── cache.py             # On-disk price cache to avoid re-fetching
│   ├── trace/
│   │   ├── __init__.py
│   │   ├── tracer.py            # Main trace orchestrator
│   │   ├── policies.py          # Stop conditions, dust filters, depth limits
│   │   └── evidence.py          # Per-tx evidence-receipt builder
│   ├── storage/
│   │   ├── __init__.py
│   │   └── case_store.py        # Read/write case folders on disk
│   └── reports/
│       ├── __init__.py
│       └── (Phase 2 — empty for now)
└── tests/
    ├── __init__.py
    ├── fixtures/                # Recorded API responses for offline tests
    ├── test_models.py
    ├── test_ethereum_adapter.py
    ├── test_label_store.py
    └── test_tracer.py
```

---

## Quickstart

```bash
# 1. Clone / cd into repo
cd recupero

# 2. Create venv and install
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# 3. Set up API keys
cp .env.example .env
# Edit .env and fill in ETHERSCAN_API_KEY and COINGECKO_API_KEY

# 4. Run the Zigha test harness (Phase 1 acceptance test)
python scripts/verify_zigha.py

# 5. Trace a real address
python scripts/trace_address.py \
    --chain ethereum \
    --address 0x0cdC902f4448b51289398261DB41E8ADC99bE955 \
    --incident-time "2025-10-09T00:00:00Z" \
    --case-id ZIGHA-001
```

Output lands in `data/cases/ZIGHA-001/`.

---

## What to read before writing code

In order:

1. `docs/PHASE1_SPEC.md` — the actual spec for what to build
2. `docs/DATA_MODEL.md` — schemas; everything serializes to/from these
3. `docs/TRACE_ALGORITHM.md` — the algorithm in pseudocode
4. `docs/ZIGHA_TEST_HARNESS.md` — what "done" looks like for Phase 1

Then `src/recupero/models.py` is the next file you implement, because everything else depends on it.

---

## Working with Claude Code

This repo is built to be Claude-Code-friendly. When opening a Claude Code session:

- Point it at the repo root.
- Tell it which module from the layout above you're working on.
- Reference the relevant doc in `docs/` so it stays inside the spec.
- Run tests after each module: `pytest tests/ -v`.

Do **not** let Claude Code expand scope mid-session. If it suggests adding Solana support while you're building the Ethereum adapter, say no and stay on Phase 1. Scope discipline is what gets v1 shipped.
