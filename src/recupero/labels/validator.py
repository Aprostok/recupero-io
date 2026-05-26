"""Open labels project: schema validator + contribution-gate (v0.14.4).

Run on every PR that touches src/recupero/labels/seeds/*.json to
catch schema drift, duplicate addresses, missing required fields,
and provenance issues before they land in main.

Exposed both as a Python API (validate_seed_files()) and a CLI:

    python -m recupero.labels.validator

The CLI returns exit code 0 on clean / 1 on validation errors.
Suitable for CI gating.
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


_SEEDS_DIR = Path(__file__).parent / "seeds"

# Files we validate. Each entry: (filename, "addresses" or "by_chain" wrapping,
# required fields per entry).
_LABEL_FILES: dict[str, dict[str, Any]] = {
    "high_risk.json": {
        "wrapping": "addresses",
        "required": ["address", "name", "risk_category", "severity"],
        "optional": ["notes", "confidence", "ofac_listing_date", "source"],
    },
    "mixers.json": {
        "wrapping": "list",
        "required": ["address", "name", "category"],
        # v0.29.1 (label-DB sweep): explicit chain + provenance markers.
        # v0.30.0: `_v030_chain_corrected` records the audit-driven
        # correction for the Tornado-Cash-BSC mislabel.
        "optional": [
            "source", "confidence", "notes", "added_at",
            "chain", "_v029_1_chain_backfill", "last_verified_at",
            "_v030_chain_corrected",
        ],
    },
    "ransomware.json": {
        "wrapping": "addresses",
        "required": ["address", "name"],
        "optional": [
            "risk_category", "severity", "confidence", "notes",
            "operator_name", "cisa_advisory_id", "doj_docket_id",
            "operator", "source",
        ],
    },
    "defi_protocols.json": {
        "wrapping": "list",
        "required": ["address", "name"],
        # v0.29.1 (label-DB sweep, Recommendation #7): explicit `chain`
        # field — backfilled by scripts/_v029_1_label_db_sweep.py so an
        # ad-hoc audit query can ask "what's our defi_protocols coverage
        # on chain X?" and get a real answer.
        "optional": [
            "category", "subcategory", "source", "notes",
            "added_at", "confidence",
            "chain", "_v029_1_chain_backfill", "last_verified_at",
        ],
    },
    "cex_deposits.json": {
        "wrapping": "list",
        "required": ["address", "name"],
        # v0.29.1 (label-DB sweep): explicit `chain` + `last_verified_at`
        # for confidence decay (Recommendation #6).
        "optional": [
            "category", "source", "exchange", "confidence", "notes",
            "added_at",
            "chain", "_v029_1_chain_backfill", "last_verified_at",
        ],
    },
    "bridges.json": {
        "wrapping": "list",
        "required": ["address", "name"],
        # v0.29.1 additions: `_v029_addition` / `_v029_1_addition` /
        # `_audit_status` track provenance for the expansion batches;
        # `last_verified_at` powers the confidence-decay test
        # (Recommendation #6).
        "optional": [
            "category", "source", "notes", "destinations",
            "chain", "contract", "confidence", "added_at",
            "follow_up_url", "supports_to_chains",
            "_v028_addition", "_v029_addition", "_v029_1_addition",
            "_audit_status", "_v029_1_chain_backfill", "last_verified_at",
        ],
    },
    # Issuers map freezable-token contracts → the legal issuer who can
    # freeze them. Schema differs from address-level seed files: the
    # primary key is (chain, contract) not `address`, so duplicate
    # detection runs on contract rather than address. Validating this
    # file catches issuer drift (e.g., a stablecoin migrating issuers,
    # or a wrapper getting added without `delegates_to`).
    "issuers.json": {
        "wrapping": "tokens",
        "required": ["chain", "contract", "symbol", "issuer", "freeze_capability"],
        "optional": [
            "freeze_notes", "primary_contact", "secondary_contact",
            "jurisdiction", "delegates_to", "le_portal_url",
            "freeze_response_time_hours", "notes", "added_at", "source",
        ],
    },
}


_ALLOWED_CONFIDENCE = frozenset(["high", "medium", "low"])

# Issuer freeze_capability is the basis for HIGH/MEDIUM/LOW freezability
# routing in the brief generator. Drift here silently mis-routes freeze
# asks (e.g., a "yes" issuer typo'd as "yse" would fall through to LOW).
_ALLOWED_FREEZE_CAPABILITY = frozenset(["yes", "limited", "no"])

# RIGOR-Jacob Z20: cap label-file size at 50MB. Real seed files top out
# at <300KB; anything north of 50MB in seeds/ is an attack (someone
# committed a quadrillion-entry mixers.json that would OOM the CI
# validator) or an accident (binary blob mis-saved as .json). Refuse to
# read past the cap rather than slurping arbitrary bytes into RAM.
_MAX_LABEL_FILE_BYTES = 50 * 1024 * 1024


@dataclass
class ValidationIssue:
    file: str
    entry_index: int        # -1 for file-level issues
    severity: str           # 'error' | 'warning'
    field: str | None
    message: str


@dataclass
class ValidationReport:
    files_checked: int = 0
    entries_checked: int = 0
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(i.severity == "error" for i in self.issues)


def validate_seed_files(seeds_dir: Path | None = None) -> ValidationReport:
    """Walk the seed-files directory; validate each known file
    against its schema spec.

    Returns a ValidationReport. ``ok`` is True iff zero errors.
    """
    seeds_dir = seeds_dir or _SEEDS_DIR
    report = ValidationReport()

    for filename, spec in _LABEL_FILES.items():
        path = seeds_dir / filename
        if not path.exists():
            report.issues.append(ValidationIssue(
                file=filename, entry_index=-1,
                severity="warning", field=None,
                message=f"File not found (skipping): {path}",
            ))
            continue
        report.files_checked += 1
        # RIGOR-Jacob Z20: size-cap before reading. A 60MB labels.json
        # would otherwise be slurped into RAM, parsed into a list of
        # ~1M Python dicts, and walked entry-by-entry — easy CI-OOM.
        try:
            file_size = path.stat().st_size
        except OSError as e:
            report.issues.append(ValidationIssue(
                file=filename, entry_index=-1,
                severity="error", field=None,
                message=f"Could not stat file: {e}",
            ))
            continue
        if file_size > _MAX_LABEL_FILE_BYTES:
            report.issues.append(ValidationIssue(
                file=filename, entry_index=-1,
                severity="error", field=None,
                message=(
                    f"Label file size {file_size} bytes exceeds the "
                    f"{_MAX_LABEL_FILE_BYTES}-byte cap. Real seed files "
                    "are <1MB; refusing to parse to bound CI memory."
                ),
            ))
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as e:
            report.issues.append(ValidationIssue(
                file=filename, entry_index=-1,
                severity="error", field=None,
                message=f"JSON parse failed: {e}",
            ))
            continue

        # Unwrap to a list of entries.
        if spec["wrapping"] == "list":
            entries = raw if isinstance(raw, list) else None
            if entries is None:
                report.issues.append(ValidationIssue(
                    file=filename, entry_index=-1,
                    severity="error", field=None,
                    message=(
                        f"Expected JSON array at top level, got "
                        f"{type(raw).__name__}"
                    ),
                ))
                continue
        elif spec["wrapping"] == "addresses":
            if not isinstance(raw, dict) or "addresses" not in raw:
                report.issues.append(ValidationIssue(
                    file=filename, entry_index=-1,
                    severity="error", field=None,
                    message=(
                        "Expected object with 'addresses' key at top level"
                    ),
                ))
                continue
            # RIGOR-Jacob Z20: the value at `addresses` MUST itself be
            # a list. Pre-Z20 the code did `raw.get("addresses", [])`
            # and trusted the value, so {"addresses": null} /
            # {"addresses": 42} / {"addresses": {"a": 1}} all leaked
            # through and crashed inside `for entry in entries` with
            # TypeError (NoneType / int not iterable) — one bad PR
            # would OOM the CI gate.
            addresses_value = raw["addresses"]
            if not isinstance(addresses_value, list):
                report.issues.append(ValidationIssue(
                    file=filename, entry_index=-1,
                    severity="error", field="addresses",
                    message=(
                        f"'addresses' must be a JSON array, got "
                        f"{type(addresses_value).__name__}"
                    ),
                ))
                continue
            entries = addresses_value
        elif spec["wrapping"] == "tokens":
            # issuers.json uses {"tokens": [...]}: a list of freezable-token
            # records keyed by (chain, contract). Top-level "_meta" sibling
            # is allowed and ignored.
            if not isinstance(raw, dict) or "tokens" not in raw:
                report.issues.append(ValidationIssue(
                    file=filename, entry_index=-1,
                    severity="error", field=None,
                    message="Expected object with 'tokens' key at top level",
                ))
                continue
            # RIGOR-Jacob Z20: same shape audit as `addresses` — without
            # this guard {"tokens": null} / {"tokens": 42} crash the
            # entry loop with an uncaught TypeError.
            tokens_value = raw["tokens"]
            if not isinstance(tokens_value, list):
                report.issues.append(ValidationIssue(
                    file=filename, entry_index=-1,
                    severity="error", field="tokens",
                    message=(
                        f"'tokens' must be a JSON array, got "
                        f"{type(tokens_value).__name__}"
                    ),
                ))
                continue
            entries = tokens_value
        else:
            entries = []

        _validate_entries(filename, entries, spec, report)

    return report


def _validate_entries(
    filename: str,
    entries: list[Any],
    spec: dict[str, Any],
    report: ValidationReport,
) -> None:
    required = spec["required"]
    optional = spec.get("optional", [])
    allowed = set(required) | set(optional)

    seen_addresses: set[str] = set()
    # For issuers.json (wrapping="tokens"), the unique key is (chain, contract)
    # rather than `address`. Tracked separately so we don't false-positive on
    # the same contract appearing under different chains.
    seen_token_keys: set[tuple[str, str]] = set()
    is_issuers_file = spec.get("wrapping") == "tokens"
    for i, entry in enumerate(entries):
        report.entries_checked += 1
        if not isinstance(entry, dict):
            report.issues.append(ValidationIssue(
                file=filename, entry_index=i,
                severity="error", field=None,
                message=f"Entry must be an object, got {type(entry).__name__}",
            ))
            continue

        # Section markers: entries with only a ``_section`` key are
        # human-readable separators (e.g., comments-as-JSON in the
        # absence of real JSON comments). Skip without validation.
        if list(entry.keys()) == ["_section"]:
            continue

        for req_field in required:
            if req_field not in entry:
                report.issues.append(ValidationIssue(
                    file=filename, entry_index=i,
                    severity="error", field=req_field,
                    message=f"Missing required field {req_field!r}",
                ))

        # Issuer-file extras: freeze_capability enum + (chain, contract) dedup.
        if is_issuers_file:
            fc = entry.get("freeze_capability")
            if fc is not None and fc not in _ALLOWED_FREEZE_CAPABILITY:
                report.issues.append(ValidationIssue(
                    file=filename, entry_index=i,
                    severity="error", field="freeze_capability",
                    message=(
                        f"freeze_capability must be one of "
                        f"{sorted(_ALLOWED_FREEZE_CAPABILITY)}, got {fc!r}"
                    ),
                ))
            chain_v = entry.get("chain")
            contract_v = entry.get("contract")
            if isinstance(chain_v, str) and isinstance(contract_v, str) and contract_v:
                tk = (chain_v.lower(), contract_v.lower())
                if tk in seen_token_keys:
                    report.issues.append(ValidationIssue(
                        file=filename, entry_index=i,
                        severity="warning", field="contract",
                        message=(
                            f"Duplicate (chain, contract) within file: "
                            f"({chain_v!r}, {contract_v!r}). Each token "
                            "should appear at most once."
                        ),
                    ))
                seen_token_keys.add(tk)

        addr = entry.get("address")
        if isinstance(addr, str) and addr:
            # Normalize for dup-detection. W13-09 fuzzer caught that the
            # naive `addr.startswith("T") else addr.lower()` heuristic
            # downcased Solana mints (base58 case-sensitive) and Bitcoin
            # P2PKH addresses (Base58Check case-sensitive), letting an
            # attacker slip a lowercased duplicate past the dup-check.
            # `canonical_address_key` is chain-aware and only lowercases
            # the `0x...` EVM form.
            from recupero._common import canonical_address_key
            addr_key = canonical_address_key(addr)
            # v0.29.1: dup-detection is (chain, address) keyed, not
            # address-only. Many bridges deterministically deploy at the
            # same address across chains (LiFi Diamond, Squid Router,
            # Synapse Router all share an address on Eth / Arb / Op /
            # Polygon / etc). Pre-v0.29.1 the validator flagged those
            # as duplicate-address warnings, drowning real curation
            # gaps in deterministic-deploy noise. Keying on (chain,
            # address) means "the same address with the same chain
            # appears twice" is the actual error condition.
            chain_for_key = entry.get("chain") or "ethereum"
            addr_key = (chain_for_key, addr_key)
            if addr_key in seen_addresses:
                # Duplicates are surfaced as WARNINGS rather than
                # errors. The seed files have some pre-existing
                # duplicates (same address labeled twice; same
                # address claimed by two different exchanges) that
                # are real curation TODOs but shouldn't block CI.
                # PR contributors are still encouraged to resolve
                # warnings touching their changes.
                report.issues.append(ValidationIssue(
                    file=filename, entry_index=i,
                    severity="warning", field="address",
                    message=(
                        f"Duplicate address within file: {addr!r}. "
                        "Each address should appear at most once per file. "
                        "If two entries genuinely conflict (different "
                        "operators claiming the same address), reconcile "
                        "via on-chain verification."
                    ),
                ))
            seen_addresses.add(addr_key)

        confidence = entry.get("confidence")
        if confidence is not None and confidence not in _ALLOWED_CONFIDENCE:
            report.issues.append(ValidationIssue(
                file=filename, entry_index=i,
                severity="error", field="confidence",
                message=(
                    f"confidence must be one of {sorted(_ALLOWED_CONFIDENCE)}, "
                    f"got {confidence!r}"
                ),
            ))

        severity = entry.get("severity")
        if severity is not None:
            try:
                sev_int = int(severity)
                if not (1 <= sev_int <= 4):
                    report.issues.append(ValidationIssue(
                        file=filename, entry_index=i,
                        severity="error", field="severity",
                        message=f"severity must be 1..4, got {severity}",
                    ))
            except (TypeError, ValueError):
                report.issues.append(ValidationIssue(
                    file=filename, entry_index=i,
                    severity="error", field="severity",
                    message=f"severity must be int 1..4, got {severity!r}",
                ))

        # Unknown fields → warning (forward-compat, don't break).
        extra = set(entry.keys()) - allowed
        if extra:
            report.issues.append(ValidationIssue(
                file=filename, entry_index=i,
                severity="warning", field=None,
                message=(
                    f"Unknown field(s): {sorted(extra)}. Either add to the "
                    "schema spec in labels/validator.py or remove from "
                    "the entry."
                ),
            ))


def main() -> int:
    """CLI entry: validate seed files, print report, exit 0/1."""
    logging.basicConfig(level=logging.INFO)
    report = validate_seed_files()
    print("=== Recupero label-data validator ===")
    print(f"  Files checked: {report.files_checked}")
    print(f"  Entries checked: {report.entries_checked}")
    print()
    if not report.issues:
        print("Clean — zero issues.")
        return 0
    errors = [i for i in report.issues if i.severity == "error"]
    warnings = [i for i in report.issues if i.severity == "warning"]
    print(f"  Errors:   {len(errors)}")
    print(f"  Warnings: {len(warnings)}")
    print()
    for issue in errors:
        loc = f"{issue.file}[{issue.entry_index}]"
        if issue.field:
            loc += f".{issue.field}"
        print(f"  [ERR]  {loc}: {issue.message}")
    for issue in warnings:
        loc = f"{issue.file}[{issue.entry_index}]"
        if issue.field:
            loc += f".{issue.field}"
        print(f"  [warn] {loc}: {issue.message}")
    return 1 if errors else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = (
    "ValidationIssue",
    "ValidationReport",
    "validate_seed_files",
    "main",
)
