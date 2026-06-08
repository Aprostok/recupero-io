"""Adversarial-input audit: integrity of committed seeds/*.json.

Tightens the seed-data CI gate beyond what ``validate_seed_files``
catches. Five concrete classes of curation bugs that have appeared in
prior PRs:

1. Schema integrity — every seed JSON must round-trip into a
   ``Label`` (or ``issuers.json`` token shape) with no exceptions.
2. Cross-file duplicates with conflicting categories — an address
   labeled as both a CEX hot wallet AND a defi protocol means
   risk-scoring will silently pick whichever one loaded last.
3. Address shape — every EVM ``address`` field must match
   ``0x[0-9a-fA-F]{40}``; base58 (Solana, Tron T-prefix) and
   other-chain forms allowed only for files that explicitly support
   them. A seed PR pasting a truncated address used to silently fail
   ``LabelStore.lookup`` at runtime.
4. Forbidden categories — an attacker-supplied (or typo) seed with
   a non-enum ``LabelCategory`` value must be rejected at load. The
   loader currently calls ``LabelCategory(entry.get("category"))``
   which already raises ``ValueError`` for unknown values, but
   regressing that would only surface as a silent ``unknown`` label.
5. Confidence enum — only ``high/medium/low`` allowed.

The unicode-controls check covers RTL-override / zero-width attacks
on display names that would let a malicious seed PR render
"Coinbase" while actually labeling an attacker-controlled deposit.
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path

from recupero.models import LabelCategory

_SEEDS_DIR = Path(__file__).resolve().parents[1] / "src" / "recupero" / "labels" / "seeds"

# Solana / Tron base58 alphabet (no 0 / O / I / l).
_BASE58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_EVM_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
# TON raw form: <workchain>:<64 hex> (e.g. 0:b113a9… for the USDT-TON master).
_TON_RE = re.compile(r"^-?\d+:[0-9a-fA-F]{64}$")

# Bidi / zero-width / BOM controls that don't belong in human-readable labels.
_UNICODE_FORBIDDEN_CODEPOINTS = frozenset({
    0x200B, 0x200C, 0x200D,        # zero-width space / non-joiner / joiner
    0x200E, 0x200F,                # LTR / RTL marks
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # bidi embedding / override
    0x2066, 0x2067, 0x2068, 0x2069,          # isolates
    0xFEFF,                        # BOM / zero-width no-break space
})

_ALLOWED_CONFIDENCE = frozenset({"high", "medium", "low"})


def _load_entries(path: Path) -> list[dict]:
    """Unwrap a seed file into a flat list of entry dicts (skip _section)."""
    raw = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(raw, list):
        entries = raw
    elif isinstance(raw, dict):
        # high_risk.json / ransomware.json wrap under "addresses";
        # issuers.json wraps under "tokens". v0.34 (#229): also unwrap
        # "entries" — a staging-file wrapper that previously slipped the
        # whole file past every integrity guard (incl. the checksum guard).
        entries = (
            raw.get("addresses")
            or raw.get("tokens")
            or raw.get("entries")
            or []
        )
    else:
        entries = []
    return [e for e in entries if isinstance(e, dict) and list(e.keys()) != ["_section"]]


def _all_seed_files() -> list[Path]:
    # internal_blacklist_seed.json uses the BlacklistEntry schema (address +
    # label_name + alert_enabled + provenance), NOT the Label seed shape, and
    # is validated by load_blacklist_entries + tests/test_internal_blacklist.py.
    # Exclude it from the Label-seed integrity gate (it deliberately omits the
    # name/category fields these checks require).
    _non_label = {"internal_blacklist_seed.json"}
    return sorted(p for p in _SEEDS_DIR.glob("*.json") if p.name not in _non_label)


# ---------------------------------------------------------------------------
# (1) Schema integrity — every seed parses + has a non-empty primary key
# ---------------------------------------------------------------------------


def test_every_seed_file_parses_and_has_primary_key() -> None:
    """Every entry must carry either `address` (label files) or
    `contract` (issuers.json) and a `name`/`symbol`. Drift here means
    the loader silently drops the entry."""
    failures: list[str] = []
    for path in _all_seed_files():
        entries = _load_entries(path)
        for i, e in enumerate(entries):
            primary = e.get("address") or e.get("contract")
            if not isinstance(primary, str) or not primary:
                failures.append(f"{path.name}[{i}]: missing/empty primary key")
            label_like = e.get("name") or e.get("symbol")
            if not isinstance(label_like, str) or not label_like.strip():
                failures.append(f"{path.name}[{i}]: missing/empty name/symbol")
    assert not failures, "Schema integrity failures:\n  " + "\n  ".join(failures)


# ---------------------------------------------------------------------------
# (3) Address shape — every EVM address matches 0x[0-9a-f]{40}
# ---------------------------------------------------------------------------


def test_no_malformed_evm_addresses_in_seeds() -> None:
    """A seed PR pasting a truncated / typo'd EVM address fails
    ``LabelStore.lookup`` silently at runtime because the wrong-length
    key never collides with a real on-chain hit."""
    bad: list[str] = []
    for path in _all_seed_files():
        entries = _load_entries(path)
        for i, e in enumerate(entries):
            addr = e.get("address") or e.get("contract")
            if not isinstance(addr, str):
                continue
            # EVM if it starts with 0x; otherwise base58 (Solana) or
            # Tron-T-prefix accepted.
            if addr.startswith("0x"):
                if not _EVM_RE.match(addr):
                    bad.append(f"{path.name}[{i}] address={addr!r} (not 0x+40 hex)")
            elif addr.startswith("T"):
                if not _TRON_RE.match(addr):
                    bad.append(f"{path.name}[{i}] address={addr!r} (bad Tron form)")
            elif _TON_RE.match(addr) or (":" in addr and addr.split(":", 1)[0].lstrip("-").isdigit()):
                # TON raw form <workchain>:<64 hex>.
                if not _TON_RE.match(addr):
                    bad.append(f"{path.name}[{i}] address={addr!r} (bad TON raw form)")
            else:
                # Solana base58 (or other non-EVM): just sanity-check length + alphabet.
                if not _BASE58_RE.match(addr):
                    bad.append(f"{path.name}[{i}] address={addr!r} (bad base58)")
    assert not bad, "Malformed addresses in seeds:\n  " + "\n  ".join(bad)


# ---------------------------------------------------------------------------
# (3b) Checksum validity — v0.34 anti-fabrication guard (repo-wide)
# ---------------------------------------------------------------------------
#
# Shape validity (3) is NOT enough: a FABRICATED placeholder can be
# shape-valid yet checksum-invalid (the class of bug that put fake Sinbad /
# Blender / ChipMixer / ransomware addresses in the registries). A real BTC or
# Tron address CANNOT fail its base58check / bech32 checksum. This guard makes
# it impossible to land a fabricated BTC/Tron literal in ANY seed file. (EVM and
# Solana addresses carry no self-checksum in our lowercased/raw form, so they
# stay shape-only — verify those on-chain before adding.)

import hashlib  # noqa: E402

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _bech32_checksum_ok(addr: str) -> bool:
    if addr.lower() != addr and addr.upper() != addr:
        return False
    a = addr.lower()
    pos = a.rfind("1")
    if pos < 1 or pos + 7 > len(a) or len(a) > 90:
        return False
    hrp, data = a[:pos], a[pos + 1:]
    if any(c not in _BECH32_CHARSET for c in data):
        return False
    values = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    values += [_BECH32_CHARSET.find(c) for c in data]
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk in (1, 0x2BC830A3)


def _base58check_ok(s: str) -> bool:
    if any(c not in _B58_ALPHABET for c in s):
        return False
    num = 0
    for c in s:
        num = num * 58 + _B58_ALPHABET.index(c)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) < 5:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def test_no_checksum_invalid_btc_tron_addresses_in_seeds() -> None:
    """Every BTC (bc1.../1.../3...) and Tron (T...) address in every seed file
    must pass its real checksum. A failure means a FABRICATED/placeholder
    literal slipped in — a real on-chain address can never fail its checksum."""
    bad: list[str] = []
    for path in _all_seed_files():
        for i, e in enumerate(_load_entries(path)):
            addr = e.get("address") or e.get("contract")
            if not isinstance(addr, str):
                continue
            if addr.startswith(("bc1", "tb1")):
                ok = _bech32_checksum_ok(addr)
            elif addr.startswith("T") or addr[:1] in "13":
                ok = _base58check_ok(addr)
            else:
                continue  # EVM / Solana — no self-checksum, shape-only (test 3)
            if not ok:
                bad.append(f"{path.name}[{i}] {addr!r} ({e.get('name', '')})")
    assert not bad, (
        "Fabricated (checksum-invalid) BTC/Tron addresses in seeds — a real "
        "address can never fail its checksum:\n  " + "\n  ".join(bad)
    )


# ---------------------------------------------------------------------------
# (2) Cross-file duplicates with conflicting categories
# ---------------------------------------------------------------------------


# Address-class groups: addresses appearing in multiple files are fine when
# the categories agree (e.g., both "mixer"), but a CEX hot wallet that's
# ALSO labeled as a defi_protocol or a bridge is a hard curation bug —
# risk-scoring depends on the category. Only flag the truly incompatible
# pairs; "mixer" + "ofac_sanctioned" overlap is expected.
_HARD_INCOMPATIBLE_PAIRS = frozenset({
    frozenset({"exchange_hot_wallet", "defi_protocol"}),
    frozenset({"exchange_hot_wallet", "bridge"}),
    frozenset({"exchange_deposit", "defi_protocol"}),
    frozenset({"exchange_deposit", "bridge"}),
    frozenset({"exchange_hot_wallet", "mixer"}),
    frozenset({"defi_protocol", "bridge"}),
})


def test_no_cross_file_category_conflicts() -> None:
    """Same address claimed as two semantically-incompatible categories
    across seed files. Example seen in the wild: a token contract
    (e.g., USDC at 0xa0b8...) mis-labeled as a CEX deposit in
    cex_deposits.json while also being the canonical token issuer in
    issuers.json."""
    addr_to_records: dict[str, list[tuple[str, str, str]]] = {}
    for path in _all_seed_files():
        for e in _load_entries(path):
            addr = e.get("address") or e.get("contract")
            if not isinstance(addr, str) or not addr:
                continue
            key = addr.lower() if addr.startswith("0x") else addr
            cat = e.get("category") or e.get("risk_category")
            name = e.get("name") or e.get("symbol") or ""
            # issuers.json has no `category`; treat as "token_issuer"
            # for the purposes of conflict detection.
            if cat is None and path.name == "issuers.json":
                cat = "token_issuer"
            if cat:
                addr_to_records.setdefault(key, []).append((path.name, cat, name))

    conflicts: list[str] = []
    for key, recs in addr_to_records.items():
        cats = {r[1] for r in recs}
        if len(cats) < 2:
            continue
        # Token-issuer + CEX deposit at same address is a classic mis-curate:
        # an ERC-20 contract address is NOT a deposit address. We DO allow
        # token_issuer + defi_protocol because a wrapper contract (WETH) is
        # legitimately both.
        if "token_issuer" in cats and cats & {
            "exchange_deposit", "exchange_hot_wallet", "bridge", "mixer",
        }:
            conflicts.append(
                f"{key}: token contract also labeled non-issuer: {recs}"
            )
            continue
        # Hard incompatibles (e.g., CEX + bridge).
        for pair in _HARD_INCOMPATIBLE_PAIRS:
            if pair.issubset(cats):
                conflicts.append(f"{key}: categories conflict {sorted(cats)} in {recs}")
                break
    assert not conflicts, (
        "Cross-file category conflicts (same address, incompatible categories):\n  "
        + "\n  ".join(conflicts)
    )


# ---------------------------------------------------------------------------
# (2b) Within-file exact duplicates — defi_protocols.json had a 3x repeat
# ---------------------------------------------------------------------------


def test_no_within_file_exact_duplicate_addresses() -> None:
    """Within a single seed file, an address listed twice means
    risk-scoring picks last-write-wins. The validator already warns;
    here we ERROR so the bug actually gets fixed.

    v0.28.0 (Jacob Zigha review item 2, step 2.1): bridges.json
    grew multi-chain entries (same DeBridgeGate / LayerZero v2
    address deployed deterministically on Arbitrum/Optimism/Base/
    Polygon). The bridge DB keys on (chain, address) per
    cross_chain.ingest_bridge_seeds, so the duplicate-check here
    must do the same — otherwise we'd have to remove legitimate
    cross-chain entries that are how multi-chain bridge detection
    works.
    """
    dupes: list[str] = []
    for path in _all_seed_files():
        entries = _load_entries(path)
        seen: dict[str, int] = {}
        for i, e in enumerate(entries):
            addr = e.get("address") or e.get("contract")
            if not isinstance(addr, str) or not addr:
                continue
            key = addr.lower() if addr.startswith("0x") else addr
            # For issuers.json, bridges.json, and mixers.json the unique
            # key is (chain, contract|address); allow the same address
            # under different chains (deterministic deploys are the
            # rule, not exception, for modern protocols).
            # v0.31.0: mixers.json added — RAILGUN's Relay contract is
            # the canonical example: same 0xFA70…4B9 deployed via
            # CREATE2 to Ethereum + Arbitrum + BSC + Polygon. Pre-v0.31
            # only Ethereum was indexed; the multi-chain expansion
            # surfaced the legitimate per-chain duplicates.
            if path.name in ("issuers.json", "bridges.json", "mixers.json"):
                chain = e.get("chain", "")
                key = f"{chain}:{key}"
            if key in seen:
                dupes.append(
                    f"{path.name}: entry [{i}] duplicates [{seen[key]}] address={addr!r}"
                )
            else:
                seen[key] = i
    assert not dupes, "Within-file duplicate addresses:\n  " + "\n  ".join(dupes)


# ---------------------------------------------------------------------------
# (4) Forbidden categories — must be enum members
# ---------------------------------------------------------------------------


def test_label_category_field_is_valid_enum() -> None:
    """Files that use ``category`` (mixers, defi_protocols, cex_deposits,
    bridges) must use values from ``LabelCategory``. A typo or an
    attacker-injected ``category: "trusted"`` would otherwise pass
    through the loader as ``LabelCategory.unknown`` (fallback) and
    silently mis-classify."""
    known = {c.value for c in LabelCategory}
    bad: list[str] = []
    for path in _all_seed_files():
        # high_risk + ransomware use `risk_category` (separate enum,
        # not LabelCategory); issuers.json has no category at all.
        if path.name in {"high_risk.json", "ransomware.json", "issuers.json"}:
            continue
        entries = _load_entries(path)
        for i, e in enumerate(entries):
            cat = e.get("category")
            if cat is None:
                continue
            if cat not in known:
                bad.append(f"{path.name}[{i}] category={cat!r} (not in LabelCategory)")
    assert not bad, "Non-enum LabelCategory values in seeds:\n  " + "\n  ".join(bad)


# ---------------------------------------------------------------------------
# (5) Unicode controls in name/symbol — bidi-override / zero-width attacks
# ---------------------------------------------------------------------------


def test_no_unicode_bidi_or_zero_width_in_names() -> None:
    """An attacker-submitted seed PR with an RTL-override in the
    ``name`` could render as "Coinbase" while the underlying bytes
    spell something else. Reject any zero-width / bidi codepoint in
    a label name or issuer symbol."""
    offenders: list[str] = []
    for path in _all_seed_files():
        entries = _load_entries(path)
        for i, e in enumerate(entries):
            for field in ("name", "symbol", "issuer", "notes"):
                v = e.get(field)
                if not isinstance(v, str):
                    continue
                for ch in v:
                    cp = ord(ch)
                    if cp in _UNICODE_FORBIDDEN_CODEPOINTS:
                        offenders.append(
                            f"{path.name}[{i}].{field}: forbidden codepoint U+{cp:04X} "
                            f"({unicodedata.name(ch, 'unnamed')}) in {v!r}"
                        )
                        break
    assert not offenders, "Unicode controls in seed strings:\n  " + "\n  ".join(offenders)


# ---------------------------------------------------------------------------
# (6) Confidence range — must be high/medium/low
# ---------------------------------------------------------------------------


def test_confidence_field_is_valid_enum() -> None:
    """``confidence`` is a Literal["high","medium","low"] on the Label
    model. A non-enum value at load time would raise during Label
    construction; we want a CI error sooner."""
    bad: list[str] = []
    for path in _all_seed_files():
        entries = _load_entries(path)
        for i, e in enumerate(entries):
            conf = e.get("confidence")
            if conf is None:
                continue
            if conf not in _ALLOWED_CONFIDENCE:
                bad.append(f"{path.name}[{i}] confidence={conf!r}")
    assert not bad, "Invalid confidence values:\n  " + "\n  ".join(bad)


# ---------------------------------------------------------------------------
# (4b) LabelStore.load rejects forbidden categories at runtime
# ---------------------------------------------------------------------------


def test_loader_skips_forbidden_category(tmp_path: Path) -> None:
    """An attacker-supplied seed file with a category value outside
    ``LabelCategory`` must NOT be loaded as ``unknown`` — the loader
    has to skip it explicitly so risk-scoring doesn't see a silently
    re-classified entry. Currently ``LabelCategory(...)`` raises
    ValueError on unknown values; this test pins that contract so a
    refactor to ``.get(..., LabelCategory.unknown)`` would be caught."""
    from recupero.labels.store import LabelStore

    labels_path = tmp_path / "evil.json"
    labels_path.write_text(json.dumps([
        {
            "address": "0x" + "a" * 40,
            "name": "AttackerControlled",
            "category": "trusted_partner",  # NOT in LabelCategory
        },
        {
            "address": "0x" + "b" * 40,
            "name": "GoodLabel",
            "category": "mixer",
        },
    ]), encoding="utf-8")

    store = LabelStore.__new__(LabelStore)
    store._by_addr_lower = {}
    store._load_file(labels_path, source_prefix="test")

    # Only the legitimate entry should have loaded; the attacker entry
    # must be skipped (not silently downgraded to unknown).
    assert len(store._by_addr_lower) == 1
    only = next(iter(store._by_addr_lower.values()))
    assert only.category == LabelCategory.mixer
    assert only.name == "GoodLabel"
