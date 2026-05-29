# JACOB Round-2 validator audit — v0.32.1 semantic invariants G–P

**Branch:** `pdf-deliverables` (HEAD `e0ce7d8`)
**Files audited:**
- `src/recupero/validators/output_integrity.py` (4548 LOC) — dispatcher + wrappers
- `src/recupero/validators/semantic_integrity.py` (1004 LOC, **new in v0.32.1**) — INVARIANTS G–P
- `tests/test_output_integrity_g_h_i.py` (614 LOC) — INVARIANT G/H/I tests
- Round-1 baseline: `docs/JACOB_VALIDATOR_AUDIT_v032.md` (target was ≥ 90% semantic; round-1 was 30%)

**Verdict:** semantic coverage **regressed in honesty** — code exists for all 10 invariants but the **dispatcher is mis-wired, the brief schema is mis-keyed, the test wrappers have inverted signatures, and three invariants are guaranteed no-ops against any production case.** Real-world semantic-bug catch rate **~25%** (worse than round-1 baseline because P is mis-spec'd enough to false-positive-critical every production brief if it ever fired correctly).

---

## TL;DR — quantitative roll-up

| Invariant | Spec coverage | False-positive rate | Test coverage | Wire-up | Net |
| :-------: | :-----------: | :-----------------: | :-----------: | :-----: | :-: |
| G — chain-of-custody | 60 | 70 (low FP) | **0** (signature broken) | 40 (key mismatch) | **35** |
| H — confidence calibration | 60 | 60 | 30 (one test broken) | 50 | **45** |
| I — cross-doc consistency | 50 | 50 | **0** (signature broken) | 40 | **30** |
| J — intra-artifact sum coherence | 75 | 80 | 0 (no tests) | **0** (le_handoff=None hardcoded) | **20** |
| K — brief↔freeze tuple match | 80 (spec) | 70 | 0 (no tests) | **0** (freeze_letters=None always) | **15** |
| L — addr↔chain↔URL | **20** (INVERTED) | 85 | 0 (no tests) | 70 | **35** |
| M — time-window coherence | 65 | 60 | 0 (no tests) | 25 (wrong manifest key) | **30** |
| N — stale-label PIT | 50 | 70 | 0 (no tests) | 25 (wrong manifest key) | **30** |
| O — AI editorial grounding | **25** (only addrs) | 90 | 0 (no tests) | **0** (prose_text=None) | **15** |
| P — parent-link metadata | 30 (invented fields) | **5** (FP-critical always) | 0 (no tests) | 40 | **20** |
| **Weighted average** | | | | | **~25%** |

**Was 30% → target ≥ 90% → actually 25%.** Net **regression of 5 pp.**

The new file `semantic_integrity.py` adds 1,004 lines of plausible code that **never executes against production data** because the dispatcher passes `le_handoff=None` and `prose_text=None`, the brief schema uses `UPPERCASE_KEYS` while the semantic checks read `lowercase_keys`, and `freeze_asks.json` is a dict (not a list) so `freeze_letters=None` always.

---

## Per-INVARIANT findings

### INVARIANT G — chain-of-custody completeness (35/100)

**Source:** `semantic_integrity.py:228-263` (`check_invariant_g_chain_of_custody`).
**Wrapper:** `output_integrity.py:139-147` (`check_invariant_g`).

**Spec coverage (60/100).** Graph walk is a correct BFS. `_walk_transactions` builds directed adjacency, `_bfs_reachable` walks from seeds, set membership of destinations. O(V+E) — no quadratic blow-up. Edge cases mostly handled:
- empty trace → all destinations unreachable → critical per destination (correct)
- no seeds → emits ONE warning then returns (correct; degrades to warning rather than CRITICAL even though "brief claims X with no seed" is a stronger failure than the comment claims)
- self-loop → BFS handles via `visited` set (correct)
- disconnected component → correctly flagged

**False-positive rate (70/100, low FP).** Normalizes addresses with `_normalize_address` (lowercase EVM, preserve Tron/Solana). Solid. Risk: brief schema mismatch → seeds empty → degrades to warning, not critical FP.

**Test coverage (0/100, BROKEN SIGNATURES).** Every test in `TestInvariantG` calls `check_invariant_g(tmp_path, brief)` — but the wrapper signature is `check_invariant_g(brief, trace_evidence, manifest)`. Tests pass `tmp_path` (a `Path` object) as `brief`. The semantic impl does `if not brief or not trace_evidence: return []` — `Path` is truthy and the test's `brief` arg arrives as `trace_evidence`. Then `trace_evidence.get("transactions")` → None (test's brief has `trace_evidence` nested at `brief["trace_evidence"]["transactions"]`, not at top level). **All 7 G-tests fail at runtime or silently pass with `[]` for the wrong reason.**

**Wire-up (40/100, KEY MISMATCH).** Dispatcher calls `run_semantic_invariants(brief=freeze_brief, ...)`. Production `freeze_brief.json` uses UPPERCASE keys: `DESTINATIONS`, `VICTIM_WALLET_FULL`. The semantic helpers `_extract_destination_addresses` / `_extract_seed_addresses` read lowercase `destinations`/`seeds`/`seed_addresses`/`victim_addresses` — none match. **Every production brief gets zero destinations, zero seeds → G silently no-ops with a warning ("No seed addresses found").**

**Findings:**
- G1 (critical): test signature inverted — `check_invariant_g(tmp_path, brief)` cannot work; wrappers take `(brief, trace_evidence, manifest)`.
- G2 (critical): `_extract_destination_addresses` does not include `DESTINATIONS` (uppercase) — the actual brief field name.
- G3 (critical): `_extract_seed_addresses` does not include `VICTIM_WALLET_FULL` — the actual brief seed field.
- G4 (high): no-seed degrades to warning. Spec says "brief claiming destinations with no seeds is unsupported by construction" — should be critical (the test `test_g_seed_missing` even asserts critical, but it never runs cleanly due to G1).

---

### INVARIANT H — confidence calibration (45/100)

**Source:** `semantic_integrity.py:298-341` (`check_invariant_h_confidence_calibration`).
**Wrapper:** `output_integrity.py:150-157`.

**Spec coverage (60/100).** Wilson direction is correct: `wilson_lower < 0.05` + high-confidence leads present → warning. Reverse direction (high wilson_lower + low confidence leads) does NOT fire — spec said "reverse direction silently passes" was OK. Per-lead ≥ 2 sources check exists.

**False-positive rate (60/100).** `_lead_evidence_count` for `evidence_sources: list[dict]` does `len({str(s) for s in sources if s})` — `str()` of dicts produces a deduplication key. For identical dicts `{"type": "X"}, {"type": "X"}` → set size 1 (correct: counted as 1 source). For distinct dicts `{"type": "X"}, {"type": "Y"}` → set size 2. **BUT** for two dicts that differ on an irrelevant field, e.g. `{"type": "X", "ts": 1}, {"type": "X", "ts": 2}` → set size 2 even though both are the same source class. The audit prompt asked: "Are 'label' + 'label' from same source counted as 2?" — **YES, if the dicts differ on anything, including timestamp**. False-positive risk.

**Test coverage (30/100, ONE TEST BROKEN).** `test_h_high_conf_when_base_low_fires_warning` puts `wilson_lower` inside `brief["RECOVERY_RATE"]`, but the impl reads `recovery_disclosure.get("wilson_lower")` where `recovery_disclosure` is the second positional arg — the test calls `check_invariant_h(brief)` with only one arg. **The wilson-warning test path is never exercised in production OR tests.**

**Wire-up (50/100).** Dispatcher loads `case_dir / "recovery_disclosure.json"`. That file does exist (per `_safe_load_json` call). If present with `{"wilson_lower": …}`, the check fires. Lead extraction uses lowercase keys (`leads`, `identified_wallets`, `destinations`, `freeze_candidates`) — all wrong vs production's `DESTINATIONS`. **In production, `_high_confidence_leads` returns [] → both branches no-op.**

**Findings:**
- H1 (high): `_high_confidence_leads` does not include `DESTINATIONS` uppercase or `CEX_CONTINUITY_LEADS`.
- H2 (medium): evidence-source dedup by full `str(dict)` over-counts when dicts differ on irrelevant fields. Should dedup by `source.get("type")` or `source.get("name")`.
- H3 (medium): wilson_lower is read from `recovery_disclosure` arg only — production briefs carry it at `freeze_brief["RECOVERY_RATE"]["wilson_lower"]` (per emit_brief and the failing test). Should fall back.

---

### INVARIANT I — cross-document consistency (30/100)

**Source:** `semantic_integrity.py:357-467`.
**Wrapper:** `output_integrity.py:160-168`.

**Spec coverage (50/100).** Case_id, victim_name, total_usd (within $100), incident_date (first 10 chars), and per-document address sets are all compared. Permissive address logic: "fail only if ≥2 OTHER docs have address X that THIS doc lacks" — that's the spec.

**False-positive rate (50/100).** USD rounding tolerance: implemented as `> Decimal("100")` which matches spec. Date comparison strips first 10 chars (`"2026-04-19T12:00:00Z"[:10]` = `"2026-04-19"`) — good for ISO format BUT FAILS for free-text dates like `"April 19, 2026"` (extracts `"April 19, "` — useless). Tests use both formats, mix poorly. Day vs ISO match: NOT timezone-aware. Permissive vs strict: only fires when ≥2 docs have an address the third lacks, so 2-doc cases (brief+freeze, no LE) never fire address violations.

**Test coverage (0/100, SIGNATURE INVERTED).** Tests call `check_invariant_i(case_dir, brief)` — wrapper is `check_invariant_i(brief, freeze_letters, le_handoff)`. `case_dir` (a `Path`) ends up as `brief`. The impl does `if not brief: return []` — Path is truthy. Then `case_ids = {_norm_case_id(d.get("case_id")) for _, d in docs}` calls `Path.get(...)` → AttributeError. **All 7 I-tests crash.** No useful assertions verified.

**Wire-up (40/100).** Dispatcher passes `le_handoff=None` (line 539) — LE handoff cross-checks NEVER fire in production. `freeze_letters = freeze_asks if isinstance(freeze_asks, list) else None` — but `freeze_asks.json` is a **dict** with `by_issuer` (per `emit_brief.py:705`), not a list. → `freeze_letters=None` always. With only the brief, `len(docs) < 2` → early return. **I never produces violations in production.**

**Findings:**
- I1 (critical): test signature broken — same as G.
- I2 (critical): `freeze_letters` will never be a list in dispatcher path. Need to read rendered freeze-letter HTML or per-issuer JSON sidecars (not `freeze_asks.json`).
- I3 (high): date parser `str(d.get(...))[:10]` will accept text-format dates like "April 19, 2026" silently — comparison becomes `"April 19, " != "April 19, "` (works if both docs use the same text format, fails if one uses ISO). Needs explicit parse-and-normalize.
- I4 (medium): `_norm_case_id` lowercase + strip — accepts `CASE-X` vs `case-x` as identical (good); but does NOT accept `CASE-X-v2` vs `CASE-X` (would correctly violate).
- I5 (low): permissive logic requires 3+ docs to fire address mismatch — in practice production cases ship brief + 1-N freeze letters but NEVER pass `freeze_letters` due to I2 → check never fires.

---

### INVARIANT J — intra-artifact sum coherence (20/100)

**Source:** `semantic_integrity.py:494-551`.
**No wrapper in output_integrity.** Only called via `run_semantic_invariants(le_handoff=...)`.

**Spec coverage (75/100).** Logic compares `total_usd_stolen` ↔ destinations sum, and destinations ↔ freeze_asks+unrecoverable+already_recovered. Within $100 tolerance. The field-name extraction is moderate: covers `usd_value`, `usd_at_theft`, `amount_usd`, `usd_value_at_theft`, `total_usd_freezable`. **Missing names per audit prompt: `total_usd_stolen` (in nested context), `usd_value_at_theft` (already in), and key per-template variants like `usd`, `usd_amount`, `frozen_usd`, `total_value_usd`, `amount`.**

**False-positive rate (80/100).** Tolerance is reasonable. Uses `_parse_usd_string` which handles `$1,234.56` strings correctly per `output_integrity` helper. Skips when total or destinations sum is 0 (avoids spurious "0 disagrees with X" warnings).

**Test coverage (0/100).** No tests in `test_output_integrity_g_h_i.py` exercise J. No file `test_invariant_j_*.py` exists.

**Wire-up (0/100, COMPLETELY DEAD).** Dispatcher hardcodes `le_handoff=None` (line 539). **J never executes in production.** The single biggest claimed semantic gain from round-1 is wired to a `None`.

**Findings:**
- J1 (critical): dispatcher never loads any LE handoff JSON. To make J fire, the dispatcher needs to enumerate `briefs/le_handoff_*.html` and either parse USD figures from HTML or load a sidecar `le_handoff_*.json`. Neither exists today.
- J2 (medium): field-name extraction misses several real template names (e.g. `usd`, `amount`, `frozen_usd`).
- J3 (low): tolerance is absolute $100 only — for $50M cases, $100 is too tight (0.0002%). Round-1 baseline `perpetrator_holdings_reconcile_across_artifacts` uses 1% OR $100 (whichever is larger). J should match.

---

### INVARIANT K — brief↔freeze-letter token/amount/recipient consistency (15/100)

**Source:** `semantic_integrity.py:559-645`.
**No wrapper.**

**Spec coverage (80/100).** Tuple match is `(issuer_norm, token_upper, address_norm)` per spec. Amount comparison: `> Decimal("10")` matches the prompt's $10 spec. Reads `freeze_candidates` / `identified_wallets` from brief.

**Issuer normalization (FAILS spec test).** `_norm_name(issuer)` does `re.sub(r"\s+", " ", str(v).strip().lower())`. So `"Tether Operations Limited"` → `"tether operations limited"` and `"Tether"` → `"tether"` — **NOT equal**. Production `FREEZABLE[*].issuer` carries `"Tether"`, but a freeze-letter context could carry `"Tether Operations Limited"` (legal name added in v0.32.1 per CRIT-FR-2). Tuple match will fail every time. **The prompt explicitly called out: "Handle Tether Operations Limited vs Tether vs USDT issuer" — implementation does NOT.**

**False-positive rate (70/100).** Apart from issuer normalization (false POSITIVE: critical violation for two valid spellings), USD None handling: `if ask_amt is not None` skips comparison entirely if either side is None — silently passes when amounts are unknown. Acceptable for "permissive when data missing", but means the truncation regression class (`1,200,000 → 1,200`) still ships if either side parses to None.

**Test coverage (0/100).** No K-targeted tests.

**Wire-up (0/100, FREEZE_LETTERS NEVER POPULATED).** Same as I: `freeze_letters=None` always because `freeze_asks.json` is a dict, not a list. **K never fires in production.** Also: brief reads `freeze_candidates` and `identified_wallets` (lowercase, neither in production brief) → `brief_tuples = set()` → every freeze ask is reported as "not in brief" if freeze_letters were ever populated.

**Findings:**
- K1 (critical): `freeze_letters` extraction is broken (same root as I2).
- K2 (critical): `_brief_freeze_tuples` reads `freeze_candidates`/`identified_wallets`; production brief uses `FREEZABLE[*].holdings[*]`. Need: iterate `freeze_brief["FREEZABLE"]`, for each issuer expand `holdings` and emit `(issuer, token, address)` tuples.
- K3 (high): issuer normalization does not collapse legal-name variants. Suggest tokenize on whitespace, take first token after stripping common corporate suffixes (`Limited`, `Inc`, `LLC`, `Operations`, `International`).
- K4 (medium): USD None handling silently passes — should at least emit a warning when one side has USD and the other doesn't.

---

### INVARIANT L — address↔chain↔explorer URL coherence (35/100)

**Source:** `semantic_integrity.py:657-704`.
**No wrapper.**

**Spec coverage (20/100, LOGIC INVERTED).** The docstring promises "EVM-shape addresses with chain hint = Arbitrum but URL = etherscan.io is a critical." The implementation does the OPPOSITE: it fires when an EVM 0x-address appears inside a `tronscan`/`solscan`/`solana.fm` URL. **The actual production failure mode** ("Arbitrum holding rendered with `etherscan.io` URL") **is silently ignored.** The `_ADDR_EXPLORER_HOSTS` registry is defined at module top but never consulted in the check function.

**False-positive rate (85/100).** The current narrow check (0x address on Tron explorer) almost never fires — a help link `https://etherscan.io/help` does NOT trigger because no 0x address is embedded in it. Tron-base58-near-EVM-explorer match: window is `html[start-200:end+50]` — could window across unrelated nearby text and yield false positives. Real-world risk: moderate.

**Test coverage (0/100).** No L-targeted tests.

**Wire-up (70/100).** Dispatcher passes `artifact_html_files` correctly. Check runs.

**Findings:**
- L1 (critical): the registry `_ADDR_EXPLORER_HOSTS` is never read — the "chain hint vs URL host" cross-check is unimplemented. Need: for each `<a href>` embedding an address, extract the chain from the surrounding context (e.g. the brief's holding metadata) and verify the URL host is in `_ADDR_EXPLORER_HOSTS[chain]`.
- L2 (high): the inverted check is the only one wired — it catches a real but narrow failure (EVM addr in Tron-explorer URL), missing the more common "EVM addr in wrong-EVM explorer" (Arbitrum holding linked to Etherscan instead of Arbiscan).
- L3 (medium): no chain inference for explorer URLs that lack a path (e.g. https://etherscan.io/ alone is not flagged; only when an addr is in the href).

---

### INVARIANT M — time-window coherence (30/100)

**Source:** `semantic_integrity.py:724-789`.
**No wrapper.**

**Spec coverage (65/100).** Pre-incident attacker-funding window default 1440 min (24h) — matches spec. Future-dated detection: compares `tx.block_time > manifest.generated_at`. Span > 30 days emits a warning. Timezone-aware comparison: `_parse_iso` strips `Z` and tries `datetime.fromisoformat`; assigns `timezone.utc` when naive. Solid foundation.

**False-positive rate (60/100).** The 24h pre-incident window is fine for typical drain cases but too tight for victim-self-funding scenarios where the victim funded the wallet days before. No exemption flag honored on individual transfers. The audit prompt asked: "is 24h the right default?" — for SIM/drain cases yes; for compromised-custody scenarios where attacker accumulates over days, no. Suggest 7 days or per-case configurable.

**Test coverage (0/100).** No M-targeted tests.

**Wire-up (25/100, WRONG KEY).** Dispatcher does `manifest = _safe_load_json(case_dir / "manifest.json") or freeze_brief`. **No `manifest.json` exists at the case root.** Production manifests are `briefs/manifest_BRIEF-<case>-<hash>.json` (per `validate_case_output` docstring lines 219-235). So `manifest` falls back to `freeze_brief`. Then `manifest.get("incident_time")` — production brief uses `INCIDENT_TIMESTAMP_UTC`, not `incident_time`. → `incident_time = None` → check skips entirely (line 740 `if not incident_time: return []`).

**Findings:**
- M1 (critical): dispatcher reads `manifest.json` which doesn't exist. Need to find `briefs/manifest_BRIEF-*.json`.
- M2 (critical): wrong manifest key — production uses `INCIDENT_TIMESTAMP_UTC` not `incident_time`. Same for `generated_at`.
- M3 (medium): no `trace_evidence.json` exists at case root in production — also doesn't write here. Check skips for that reason too.
- M4 (low): pre-incident window default of 24h may be too tight for some case types.

---

### INVARIANT N — stale-label PIT (30/100)

**Source:** `semantic_integrity.py:797-848`.
**No wrapper.**

**Spec coverage (50/100).** Walks `brief["labels"]`/`brief["label_citations"]`/`brief["cited_labels"]` (all lowercase, none exist in production brief schema). For each label, checks `valid_from <= incident_time` AND `valid_to is null OR valid_to >= incident_time`. Direction correct per spec.

**False-positive rate (70/100).** Timezone normalization is consistent. Issue: validator only checks labels embedded IN the brief — does NOT look up labels from the labels DB at incident_time and verify the brief used the right snapshot. The prompt asked: "Where does the validator GET the label timestamps? (Does it actually look them up, or does it assume they're in the artifact?)" — **it assumes they're in the artifact**, which means a brief regenerated with stale labels but no label timestamps in the JSON ships silently.

**Test coverage (0/100).** No N-targeted tests.

**Wire-up (25/100).** Same dispatcher problem as M: `manifest` falls back to brief which has `INCIDENT_TIMESTAMP_UTC` not `incident_time` → no incident_time → check skips. Even if wired correctly, `brief["labels"]` doesn't exist in production briefs (labels are inline on holding rows under non-standardized keys).

**Findings:**
- N1 (critical): label timestamps are not in the brief artifact at all in v0.32.x. The validator's promise to PIT-verify labels is unfulfilled because the data isn't recorded. Either emit a sidecar `briefs/label_pit_audit.json` (per round-1 recommendation) OR look up the label PIT from the DB given `incident_time` and the addresses in the brief.
- N2 (critical): same incident_time / manifest key bug as M.

---

### INVARIANT O — AI-editorial grounding (15/100)

**Source:** `semantic_integrity.py:882-911`.
**No wrapper.**

**Spec coverage (25/100, MOSTLY UNIMPLEMENTED).** The docstring promises "every $-figure, 0x address, and chain name cited in the prose MUST be present in the structured data." **Implementation only checks 0x addresses.** `_USD_PROSE_RE` is defined at module level (line 856-858) but **never referenced** inside the check function. Chain names are not checked at all.

**False-positive rate (90/100, low FP because it barely runs).** Address case-sensitivity: `_normalize_address(m.group(0))` lowercases EVM addresses — correct.

**Test coverage (0/100).** No O-targeted tests. No `prose_text` is ever constructed in any test.

**Wire-up (0/100, DEAD).** Dispatcher hardcodes `prose_text=None` (line 544). **O never executes in production.** Even if it did, only EVM addresses would be checked.

**Findings:**
- O1 (critical): dispatcher passes `prose_text=None`. To make O useful, the dispatcher needs to load `brief["INCIDENT_NARRATIVE_RECUPERO"]`, `brief["INCIDENT_NARRATIVE_FIRST_PERSON"]`, `brief["VICTIM_SUMMARY"]` and concatenate.
- O2 (critical): USD-in-prose check is missing — the `_USD_PROSE_RE` regex exists but is unused.
- O3 (high): chain-name-in-prose check is missing — the audit spec explicitly named it.
- O4 (medium): structured_addrs uses lowercase keys (`destinations`, `identified_wallets`, `freeze_candidates`, `leads`, `subpoena_targets`) — all wrong vs production brief's `DESTINATIONS` / `FREEZABLE`. Even if prose were passed, every legitimate address mention would FP-critical.

---

### INVARIANT P — parent-link metadata (20/100)

**Source:** `semantic_integrity.py:919-958`.
**No wrapper.**

**Spec coverage (30/100, INVENTED FIELDS).** Checks `brief.get("manifest_sha")`, `brief.get("recovery_disclosure_sha")`, `fl.get("parent_brief_sha")`, and on LE handoff: `parent_brief_sha`, `manifest_sha`, `recovery_disclosure_sha`. **None of these fields are emitted anywhere in the codebase.** Grep across `src/recupero/` confirms: only the validator itself references these names. emit_brief.py does NOT write `manifest_sha` into freeze_brief.json. The reports module does NOT add `parent_brief_sha` to any rendered letter.

**False-positive rate (5/100, GUARANTEED FP-CRITICAL).** If the validator runs as written, every production case with a `freeze_brief.json` emits a CRITICAL violation for missing `manifest_sha` and a HIGH violation for missing `recovery_disclosure_sha`. **Every prod case fails validation.** The reason production hasn't broken: this path runs after the structural checks but the result is captured in `result.violations`. `result.ok` excludes critical/high → every prod case is reported as `ok=False`. **Unless this never made it to CI** (which is likely the case since the tests can't even call the wrappers due to signature bugs, so they don't trip P either).

**SHA freshness check:** none — validator only checks "non-empty string". The prompt asked: "does it verify the SHA actually matches a file on disk, or just check non-empty?" — **just non-empty.** A regression that writes the literal string `"PLACEHOLDER"` would pass.

**Test coverage (0/100).** No P-targeted tests. Dispatcher test `test_dispatcher_runs_all_invariants_including_g_h_i` would surface the FP-critical IF the brief made it through dispatcher to P — which it currently does. The test only inspects `checks_run`, not `violations`, so the FP-critical goes undetected.

**Wire-up (40/100).** Dispatcher passes `freeze_letters=None`, `le_handoff=None`. Only the brief path runs. Brief always triggers critical+high.

**Findings:**
- P1 (critical): the fields `manifest_sha`, `recovery_disclosure_sha`, `parent_brief_sha` are not emitted anywhere. Either (a) wire emission in `emit_brief.py` / `freeze_letter_generator` / `le_handoff_generator`, or (b) downgrade P to a warning-only check until the emit side ships.
- P2 (high): non-empty string check is too weak. Should verify the SHA references a known artifact path (e.g. `manifest_sha == sha256(open(briefs/manifest_*.json).read())`).
- P3 (medium): severities split — `manifest_sha` is critical but `recovery_disclosure_sha` is high. Inconsistent rationale.

---

## Cross-cutting findings (apply to ≥ 2 invariants)

### CC1 — Brief schema mismatch (UPPERCASE vs lowercase)
Production `freeze_brief.json` uses UPPERCASE keys (`DESTINATIONS`, `FREEZABLE`, `VICTIM_WALLET_FULL`, `TOTAL_LOSS_USD`, `INCIDENT_TIMESTAMP_UTC`). semantic_integrity reads lowercase (`destinations`, `freeze_candidates`, `identified_wallets`, `victim_addresses`, `total_usd_stolen`, `incident_time`). **G, H, I, K, N, O all no-op silently in production.**
Fix: introduce a single `_get_brief_field(brief, *keys)` helper that tries each key variant, OR canonicalize the brief schema upstream.

### CC2 — Dispatcher hard-codes `None` for half the inputs
`validate_case_output` lines 536-545 passes `le_handoff=None`, `prose_text=None`, and computes `freeze_letters` from `freeze_asks.json` (which is a dict not a list, so always `None`). **J, K, O are guaranteed dead in production.**
Fix: enumerate `briefs/le_handoff_*.html`, parse to a structured dict (or emit sidecar `le_handoff_*.json` from the template renderer), concatenate AI editorial prose from brief fields, and enumerate rendered freeze letters from `briefs/freeze_request_*.html` rather than `freeze_asks.json`.

### CC3 — Manifest path is wrong
`_safe_load_json(case_dir / "manifest.json")` — no such file exists. Production manifests are `briefs/manifest_BRIEF-<case>-<hash>.json`. M and N skip entirely because of this.
Fix: glob `briefs/manifest_BRIEF-*.json` and pick the most-recent.

### CC4 — Test signatures inverted
`test_output_integrity_g_h_i.py` calls `check_invariant_g(tmp_path, brief)`, `check_invariant_i(case_dir, brief)` — the wrappers do not take `case_dir`. **All 22 tests in the file fail or pass for the wrong reason.** I did not run them but the signature analysis is conclusive.
Fix: rewrite the tests to match the wrapper signatures, OR change the wrappers to accept `(case_dir, ...)` and internally load artifacts.

### CC5 — Test asserts dispatcher registers per-invariant check names; dispatcher registers a single rollup name
Test `test_dispatcher_runs_all_invariants_including_g_h_i` expects `"invariant_g_chain_of_custody"`, `"invariant_h_confidence_calibration"`, `"invariant_i_cross_document_consistency"` in `result.checks_run`. Dispatcher only appends `"semantic_invariants_g_through_p"`. Test fails. Also the test uses the name `"invariant_i_cross_document_consistency"` but the impl uses `"invariant_i_cross_doc_consistency"` (doc vs document) — even the violation `check` field name disagrees with the test.

### CC6 — Catch-all `except Exception` around the entire semantic block
Lines 548-554 wraps all 10 semantic invariants in one try/except. **Any one of them raising downgrades the WHOLE GROUP to a single warning.** A bug in K can silently disable G/H/I/J/L/M/N/O/P. The structural block per-check error isolation (lines 491-501) is the correct pattern; the semantic block does not match.

### CC7 — INVARIANT P fields are vapor
None of `manifest_sha` / `recovery_disclosure_sha` / `parent_brief_sha` are emitted by any code path. P is a critical-blocking check on a field nothing writes.

---

## Score summary

| Dimension | Score |
| --------- | :---: |
| Spec coverage (avg) | 50 |
| False-positive rate (avg, higher = less FP) | 65 |
| Test coverage (avg) | 4 |
| Wire-up (avg) | 29 |
| **Net weighted (FP=20%, spec=30%, test=20%, wire-up=30%) ** | **~32%** |

Adjusting for "checks that actually fire in production" (J/K/O/L-coverage-mode are dead; G/H/I/M/N silently no-op on key mismatch; P false-positive-criticals every brief): **real semantic coverage on production cases ≈ 25%.**

**Round-1 was 30%. Round-2 target was 90%. Round-2 actual: 25%.** Net regression: ~5 pp.

The "honest stance" from round-1 still applies, plus a new one:

> The validator's first 30 checks are excellent at structural integrity. They are also Jacob-style "we already shipped this bug once, never again" tests — every named check has a specific bug it was added to catch.

> **v0.32.1 added 1,004 lines of semantic code that does not run against any production brief.** The code looks like a thorough implementation of the round-1 recommendations, but six wiring/schema bugs reduce its effective coverage to roughly zero.

---

## Recommended fix order (in priority)

1. **CC1 + CC2 + CC3 (1 day):** wire the dispatcher to read `briefs/manifest_BRIEF-*.json`, parse LE handoff HTML to a sidecar JSON during emit, glob `briefs/freeze_request_*.html` for freeze_letters, concat AI prose for O. Add uppercase aliases to all `_extract_*` helpers in semantic_integrity. **This alone takes coverage from 25% → ~55%.**
2. **CC4 + CC5 (2 hours):** rewrite the test signatures and dispatcher check-name expectations. Without this, the 22 tests provide no signal.
3. **L1 (4 hours):** implement the actual chain-vs-URL cross-check using `_ADDR_EXPLORER_HOSTS`. The current inverted check is a distraction.
4. **O1+O2+O3 (4 hours):** wire `prose_text` and add USD-figure + chain-name grounding to invariant O.
5. **P1 (1 day):** either emit the SHA fields from the report builders or downgrade P to warning-until-emitted.
6. **K3 (2 hours):** add corporate-suffix stripping to `_norm_name` for issuer comparison.
7. **CC6 (30 min):** move per-invariant try/except inside `run_semantic_invariants` (or move the calls into the `checks` loop in `validate_case_output`) so one crash doesn't kill the group.

Total to reach ≥ 90% coverage: ~3-4 dev days.

---

## Files referenced (absolute paths)

- `C:\Users\apros\Downloads\recupero-io\.claude\worktrees\cranky-fermat-54fcfb\src\recupero\validators\output_integrity.py`
- `C:\Users\apros\Downloads\recupero-io\.claude\worktrees\cranky-fermat-54fcfb\src\recupero\validators\semantic_integrity.py`
- `C:\Users\apros\Downloads\recupero-io\.claude\worktrees\cranky-fermat-54fcfb\tests\test_output_integrity_g_h_i.py`
- `C:\Users\apros\Downloads\recupero-io\.claude\worktrees\cranky-fermat-54fcfb\src\recupero\reports\emit_brief.py` (production brief schema at lines 1971-2105)
- Round-1 baseline: `C:\Users\apros\Downloads\recupero-io\.claude\worktrees\cranky-fermat-54fcfb\docs\JACOB_VALIDATOR_AUDIT_v032.md`
