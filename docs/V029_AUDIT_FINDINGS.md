# v0.28 / v0.29.0 / v0.29.1 Forensic-Correctness Audit

Read-only audit of the bridge-label, decoder, and bridge-sync work
shipped under v0.28 → v0.29.1. Scope per the audit charter:
`src/recupero/labels/seeds/*.json`, `labels/validator.py`,
`trace/bridge_calldata.py`, `trace/cross_chain.py`,
`ops/commands/bridge_sync_cmd.py`, `scripts/_v029*.py`,
`tests/test_v029*.py`.

## TIER-1 CRITICAL — silent bad output / corrupt evidence chain

**T1-A. Tornado-Cash-on-BSC entry mislabeled as Ethereum**
`src/recupero/labels/seeds/mixers.json:79-89` —
`"Tornado Cash: 40 BNB (BSC)"` with `notes: "OFAC SANCTIONED — BSC
deployment"` was mass-mutated by `scripts/_v029_1_label_db_sweep.py`
to `chain: "ethereum"`. The sweep blindly stamps `"ethereum"` on any
entry lacking a `chain` field (`_v029_1_label_db_sweep.py:53-58`)
with no name-substring check. A BSC trace will now MISS this OFAC
mixer; worse, an Ethereum trace touching the same byte-form address
(possible because BSC and ETH share EVM address space) would
falsely tag the wallet as touching a sanctioned mixer — i.e. a
false-positive OFAC hit in an LE brief. **Fix:** add a guard in
the sweep that refuses to stamp when the entry name/notes contain
non-Ethereum chain tokens (`BSC`, `Polygon`, `Tron`, `Solana`,
`BNB`, etc.); re-derive the chain manually for those rows.

**T1-B. Validator dup-detection bypassable via chain-case drift**
`src/recupero/labels/validator.py:363-364`,
`src/recupero/labels/validator.py:285` —
`chain_for_key = entry.get("chain") or "ethereum"` is NOT
lower-cased, while `ingest_bridge_seeds` (`cross_chain.py:159`)
lower-cases. Two rows with `chain: "Ethereum"` and
`chain: "ethereum"` on the same address pass the validator (distinct
keys) but collapse in the ingestor — only one wins, the loser is
silently dropped. The set is also typed `set[str]` but stores
tuples, hiding the bug from static analysis. **Fix:**
`chain_for_key = (entry.get("chain") or "ethereum").lower()`; retype
to `set[tuple[str, str]]`.

**T1-C. Provenance markers never reach the LE brief**
`src/recupero/trace/cross_chain.py:187-196`,
`cross_chain.py:319-345` — `BridgeInfo` does NOT carry
`_audit_status` / `_v029_addition` / `_v029_1_addition` /
`last_verified_at`. `handoffs_to_brief_section` therefore cannot
emit them. The seed JSON has the markers, the validator tolerates
them, the bridge-sync filters on them — but the LE-facing brief is
blind. An analyst reading the brief cannot tell whether the bridge
label was WebFetch-verified in v0.29 or is a pre-v0.28 carry-over
of unknown provenance. For a "law-enforcement-grade brief" this is
the exact provenance gap the v0.29 audit was meant to close.
**Fix:** add `audit_status`, `last_verified_at` to `BridgeInfo`;
pass through in `handoffs_to_brief_section`; render in the brief
template.

## TIER-2 HIGH — degrades output quality, visibly

**T2-A. `_our_protocol_chain_pairs` mis-extracts DeBridge family**
`src/recupero/ops/commands/bridge_sync_cmd.py:115-119` — heuristic
splits name on `:` then space. `"deBridgeGate (DLN)"` becomes
family `"debridgegate"`, but L2Beat snapshot uses `"debridge"`. So
the Ethereum + Arbitrum + Optimism `deBridgeGate` rows are
INVISIBLE to the diff; bridge-sync will report DeBridge gaps the
operator already covered. Cron noise → operator ignores → real
gaps get lost. **Fix:** maintain an explicit family-alias map
(`"debridgegate" → "debridge"`, `"hop protocol" → "hop"`), or read
a `protocol` field on each entry rather than parsing the name.

**T2-B. Stale snapshot silently reports "no gaps"**
`src/recupero/ops/commands/bridge_sync_cmd.py:133-165` —
`_l2beat_expected_pairs` and `_defillama_expected_pairs` return a
hard-coded snapshot frozen at the v0.29.1 audit date. When L2Beat
adds a new protocol (e.g., Hyperliquid bridge), the snapshot
doesn't update; `expected - ours` stays empty; the cron job
reports "0 gaps" forever. The docstring says fetchers are stubbed,
but `reachable=True` is returned unconditionally, so
`sources_unavailable` is `[]` — the operator gets no signal that
the source is in fact stale. **Fix:** include a `snapshot_age_days`
field in the diff payload; when fetchers are still stubs, emit a
loud warning in stdout and a field in `bridges_diff.json`.

**T2-C. `decode_bridge_calldata` dispatch is prefix-match, not exact**
`src/recupero/trace/bridge_calldata.py:244-249` —
`bridge_protocol.lower().startswith("wormhole")` accepts
`"Wormhole-fake"`, `"wormhole_v9999"`, etc. A poisoned bridges.json
entry with name `"Wormhole-impostor"` would route into the Wormhole
decoder; for non-matching method-IDs the decoder returns None (safe),
but for a crafted blob carrying a real Wormhole method-ID with a
forged recipientChain, the decoder will emit `confidence="high"`
with attacker-chosen destination. **Fix:** dispatch on
`protocol` field rather than `name`, AND require exact match against
a closed enum.

**T2-D. UTF-16 / non-UTF-8 bridges.json crashes bridge-sync uncaught**
`src/recupero/ops/commands/bridge_sync_cmd.py:89-98` — wraps only
`(OSError, json.JSONDecodeError)`. `UnicodeDecodeError` is a
`ValueError` subclass, NOT caught. A UTF-16 BOM-prefixed
`bridges.json` (the audit prompt explicitly flags this) raises
uncaught from `read_text(encoding="utf-8")`. Same gap in
`labels/validator.py:189-197` (uses `utf-8-sig` so UTF-8 BOM is
fine, but UTF-16 still crashes). **Fix:** add `UnicodeDecodeError`
to the except tuple; return exit code 2.

## TIER-3 MEDIUM — polish + hardening

**T3-A. Matrix regex `\bstargate\b` accepts `"STARGATE-fake"`**
`tests/test_v029_bridge_coverage_matrix.py:202-225` — `\b` matches
the boundary between `STARGATE` and `-`, so a crafted name like
`"STARGATE-fake: Router"` would satisfy the matrix. Not catastrophic
because seed entries are operator-curated, but the matrix is the
last line of defense against the Zigha-shape regression — it should
not accept lookalikes. **Fix:** require an exact word followed by
space or `:` (e.g., `r"(?:^|\s)stargate(?:[:\s]|$)"`), or match on a
`protocol` field rather than free-text name.

**T3-B. `bridge-sync` `--bridges` accepts symlinks / arbitrary paths**
`bridge_sync_cmd.py:230` — `path.read_text` follows symlinks. Low
risk because the operator runs it, but a cron job parameterized
from an env var could be redirected to read e.g. a 50MB
`/var/log/foo` and OOM. The validator has a 50MB cap
(`validator.py:124`); `_load_bridges_json` does not. **Fix:**
mirror the validator's `_MAX_LABEL_FILE_BYTES` cap before reading.

**T3-C. `_is_stale` rstrip is over-eager on trailing chars**
`bridge_sync_cmd.py:177` — `cleaned.rstrip("Z").rstrip("z")` strips
ALL trailing Z/z characters, not just one. Pathological input
`"2026-05-26zzZZZ"` becomes `"2026-05-26"`, parses as a naive date.
Not exploitable, just imprecise. **Fix:** use a single
`removesuffix("Z")` per character class, or just parse with
`fromisoformat` directly (Python 3.11+ accepts the `Z` suffix).

**T3-D. `_v029_1_chain_backfill: true` not in validator schema**
`src/recupero/labels/validator.py:79-92` — `bridges.json` spec
lists `_v029_1_chain_backfill` as optional, but the marker is
actually applied only to `cex_deposits / defi_protocols / mixers`
by the sweep script; bridges.json never receives it. The list is
correct but the comment claims a coupling that doesn't exist —
minor drift. **Fix:** drop the field from the bridges.json optional
list (or document why it's there for forward-compat).

## TIER-4 LOW — nice-to-have

**T4-A. `BridgeDecodeResult` `bridge_method` is unvalidated**
`bridge_calldata.py:97`, no length cap on `raw_calldata_excerpt`
beyond the `:400` slice. The slice already bounds memory, but if
the field is ever serialized into JSON and rendered into a brief,
zero-width / control characters in calldata aren't stripped.
**Fix:** `re.sub(r"[^0-9a-fA-Fx]", "", excerpt)` before the field
hits any rendered surface.

**T4-B. `test_bridge_sync_handles_malformed_bridges_json` is single-case**
`tests/test_v029_1_bridge_sync_cmd.py:118-128` covers only the
"not valid json{" case. Per the audit charter, it does NOT cover:
zero-byte files (which JSONDecodeError handles fine), UTF-16 BOM
(T2-D — currently CRASHES), deeply-nested JSON (the Python default
recursion limit is 1000 — a 5000-deep array of arrays raises
RecursionError, not JSONDecodeError, uncaught), or symlink loops
(T3-B). **Fix:** parametrize the test over these cases once T2-D /
T3-B are fixed.

**T4-C. `_b58encode_no_checksum` produces poison Solana addresses on zero input**
`bridge_calldata.py:55-79` — for a 32-byte zero pubkey, returns
`"11111111111111111111111111111111"` (the Solana SystemProgram
canonical zero address). Not technically a crash, but a brief
emitting "funds bridged to 1111...1111 on Solana" is forensically
worthless. **Fix:** detect the all-zero recipient case and emit
`destination_address=None`, `confidence="medium"` instead of `"high"`.

## Surfaces examined with NO findings

- `src/recupero/trace/cross_chain.py::ingest_bridge_seeds` — defensive
  handling of malformed entries is solid; canonical-address keying via
  `_common.canonical_address_key` correctly preserves base58 case.
- `src/recupero/models.py` Chain enum expansion — every new chain
  value is referenced by at least one seed entry per the matrix test.
- `scripts/_v029_expand_bridges.py` + `_v029_1_expand_more_bridges.py`
  — collision detection at write time (`assert not collisions`) and
  canonical-casing dedup look correct. Idempotency holds.
- `tests/test_v029_1_decoder_seed_pairing.py` — invariants pinned are
  appropriate; the negative test for unknown protocol dispatch is a
  nice tripwire.
