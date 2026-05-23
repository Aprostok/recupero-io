"""Signed hash-chain attestations for chain-of-custody (v0.13.7).

Pure functions where possible. The cryptography library does the
Ed25519 work; this module orchestrates the chain structure +
canonical-JSON serialization + per-stage attestation writers.

Canonical-JSON note
-------------------

The signature target MUST be a deterministic byte sequence — any
serialization variance (key order, whitespace, escape forms) breaks
verification. We use Python's ``json.dumps`` with ``sort_keys=True,
separators=(",", ":"), ensure_ascii=True``. This matches RFC 8785
(JCS — JSON Canonicalization Scheme) closely enough for our needs,
and crucially is stable across Python versions.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

log = logging.getLogger(__name__)


# Default key location — overridable via RECUPERO_CUSTODY_KEY_PATH.
_DEFAULT_KEY_PATH = Path.home() / ".recupero" / "custody_key"


# ---- Models ---- #


@dataclass(frozen=True)
class AttestedArtifact:
    """One artifact covered by an attestation entry."""
    relative_path: str       # path relative to the case dir
    sha256_hex: str          # SHA-256 hash, lowercase hex
    size_bytes: int


@dataclass(frozen=True)
class AttestationEntry:
    """One signed entry in the custody chain.

    Hash chain semantics:
      * ``prev_hash`` is the SHA-256 of the canonical-JSON serialization
        of the PREVIOUS entry's signed payload (excluding the signature
        field itself). The first entry's prev_hash is a constant
        genesis value.
      * ``signed_payload_sha256`` is the SHA-256 of THIS entry's
        canonical-JSON serialization (excluding the signature field).
        Useful for fast verification + as the basis for the NEXT
        entry's prev_hash.
      * ``signature_b64`` is the Ed25519 signature over the canonical
        bytes of the signed_payload (everything except the signature
        itself). Base64-encoded for JSON-friendliness.
    """
    chain_id: str            # case_id (so multiple cases don't crosswire)
    entry_index: int         # sequence number starting at 0
    stage: str               # e.g. 'trace', 'list-freeze-targets', 'emit-brief'
    timestamp_iso: str       # UTC ISO 8601 with Z suffix
    operator: str            # operator-identifying string (email or username)
    public_key_fingerprint: str  # SHA-256 of the public key, first 16 hex chars
    prev_hash: str           # SHA-256 hex of prior entry (or GENESIS for first)
    artifacts: list[AttestedArtifact]
    note: str | None         # optional free-form annotation
    signed_payload_sha256: str
    signature_b64: str


# Constant genesis prev_hash for the first entry in any chain.
GENESIS_PREV_HASH = "0" * 64


# ---- Key management ---- #


def generate_keypair(output_path: Path | None = None) -> tuple[Path, Path]:
    """Generate a new Ed25519 keypair and write PEM files.

    Returns (private_key_path, public_key_path).

    The private key is written with mode 0600 on POSIX. The public
    key is written as base64 (raw, no PEM headers) so it can be
    pasted into a brief or web page easily.
    """
    out = output_path or _DEFAULT_KEY_PATH
    out.parent.mkdir(parents=True, exist_ok=True)

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    pub_raw = pub.public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw,
    )

    out.write_bytes(priv_pem)
    try:
        os.chmod(out, 0o600)
    except (PermissionError, OSError):
        # Windows / non-POSIX — chmod is best-effort.
        pass

    pub_path = out.with_suffix(".pub")
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    pub_path.write_text(pub_b64 + "\n", encoding="utf-8")
    return out, pub_path


def load_private_key(key_path: Path | None = None) -> Ed25519PrivateKey:
    """Load the operator's private key from PEM."""
    path = key_path or Path(
        os.environ.get("RECUPERO_CUSTODY_KEY_PATH", str(_DEFAULT_KEY_PATH))
    )
    if not path.exists():
        raise FileNotFoundError(
            f"Custody private key not found at {path}. Generate one with "
            "`recupero-ops custody-keygen`."
        )
    priv = load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError(
            f"Key at {path} is not an Ed25519 private key "
            f"(got {type(priv).__name__})"
        )
    return priv


def load_public_key_b64(public_key_b64: str) -> Ed25519PublicKey:
    """Decode a raw-Ed25519 base64 public key into a usable object."""
    try:
        raw = base64.b64decode(public_key_b64.strip(), validate=True)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"public key not valid base64: {e}") from e
    if len(raw) != 32:
        raise ValueError(
            f"Ed25519 public key must decode to 32 bytes; got {len(raw)}"
        )
    return Ed25519PublicKey.from_public_bytes(raw)


def public_key_b64(priv: Ed25519PrivateKey) -> str:
    """Return the public key as raw base64 (matches what
    generate_keypair writes to <key>.pub)."""
    pub_raw = priv.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw,
    )
    return base64.b64encode(pub_raw).decode("ascii")


def public_key_fingerprint_b64(pub_b64: str) -> str:
    """SHA-256 of the raw public-key bytes, first 16 hex chars.

    Used as a stable, short identifier embedded in every entry so a
    verifier can confirm which key signed (without trusting the
    entry's own public-key claim — they look up the key by
    fingerprint from an out-of-band trusted source).
    """
    pub = load_public_key_b64(pub_b64)
    raw = pub.public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


# ---- Canonical serialization ---- #


def _canonical_json(obj: Any) -> bytes:
    """Deterministic JSON serialization for signing + hashing.

    Sorted keys, no whitespace, ASCII-escaped non-ASCII characters.
    Matches RFC 8785 (JCS) closely enough for our verification
    needs.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_file(path: Path) -> tuple[str, int]:
    """Return (sha256_hex, size_bytes) for a file."""
    sha = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha.update(chunk)
            size += len(chunk)
    return sha.hexdigest(), size


# ---- Entry construction ---- #


def _entry_payload_dict(
    *,
    chain_id: str,
    entry_index: int,
    stage: str,
    timestamp_iso: str,
    operator: str,
    public_key_fingerprint: str,
    prev_hash: str,
    artifacts: list[AttestedArtifact],
    note: str | None,
) -> dict[str, Any]:
    """Build the dict that gets signed (no signature field).

    Sorted-key canonical JSON of this dict is what the signature
    covers. The dict is also what gets stored alongside the
    signature in the chain file (with the signature field added).
    """
    return {
        "chain_id": chain_id,
        "entry_index": entry_index,
        "stage": stage,
        "timestamp": timestamp_iso,
        "operator": operator,
        "public_key_fingerprint": public_key_fingerprint,
        "prev_hash": prev_hash,
        "artifacts": [asdict(a) for a in artifacts],
        "note": note,
    }


def create_attestation(
    *,
    case_dir: Path,
    chain_id: str,
    stage: str,
    operator: str,
    artifact_paths: list[Path],
    prev_hash: str,
    entry_index: int,
    note: str | None = None,
    private_key: Ed25519PrivateKey | None = None,
    now: datetime | None = None,
) -> AttestationEntry:
    """Hash each artifact, build the payload, sign with the
    operator's private key, return the AttestationEntry.

    Does NOT write to the chain file — the caller does that with
    append_to_chain(). Splitting these lets tests verify entry
    construction without I/O, and lets the worker batch attestations
    if it wants to.
    """
    priv = private_key or load_private_key()
    artifacts: list[AttestedArtifact] = []
    for p in artifact_paths:
        if not p.exists():
            raise FileNotFoundError(
                f"Cannot attest non-existent artifact: {p}"
            )
        try:
            relative = p.relative_to(case_dir)
        except ValueError:
            # Artifact is outside case_dir — keep its absolute path
            # but log a warning (this should be rare; usually
            # everything we attest is case-local).
            log.warning(
                "attestation: artifact %s is outside case_dir %s; "
                "using absolute path", p, case_dir,
            )
            relative = p
        digest, size = _hash_file(p)
        artifacts.append(AttestedArtifact(
            relative_path=str(relative).replace("\\", "/"),
            sha256_hex=digest,
            size_bytes=size,
        ))

    timestamp_iso = (
        (now or datetime.now(UTC))
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    pub_b64 = public_key_b64(priv)
    fp = public_key_fingerprint_b64(pub_b64)

    payload = _entry_payload_dict(
        chain_id=chain_id,
        entry_index=entry_index,
        stage=stage,
        timestamp_iso=timestamp_iso,
        operator=operator,
        public_key_fingerprint=fp,
        prev_hash=prev_hash,
        artifacts=artifacts,
        note=note,
    )
    canonical = _canonical_json(payload)
    signed_payload_sha256 = _sha256_hex(canonical)
    signature = priv.sign(canonical)
    signature_b64 = base64.b64encode(signature).decode("ascii")

    return AttestationEntry(
        chain_id=chain_id,
        entry_index=entry_index,
        stage=stage,
        timestamp_iso=timestamp_iso,
        operator=operator,
        public_key_fingerprint=fp,
        prev_hash=prev_hash,
        artifacts=artifacts,
        note=note,
        signed_payload_sha256=signed_payload_sha256,
        signature_b64=signature_b64,
    )


# ---- Chain file I/O ---- #


def chain_file_path(case_dir: Path) -> Path:
    """Conventional location of the chain file inside a case dir."""
    return case_dir / "custody" / "chain.jsonl"


def public_key_file_path(case_dir: Path) -> Path:
    return case_dir / "custody" / "public_key.txt"


def append_to_chain(
    case_dir: Path,
    entry: AttestationEntry,
    *,
    public_key_b64_str: str | None = None,
) -> Path:
    """Append the entry to ``case_dir/custody/chain.jsonl`` and
    write the public key alongside (idempotent — same key written
    each time is fine).

    Returns the chain file path.
    """
    chain_path = chain_file_path(case_dir)
    chain_path.parent.mkdir(parents=True, exist_ok=True)
    # One JSON object per line.
    line = json.dumps(asdict(entry), sort_keys=True, separators=(",", ":"))
    with chain_path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    if public_key_b64_str:
        pub_path = public_key_file_path(case_dir)
        pub_path.write_text(public_key_b64_str + "\n", encoding="utf-8")
    return chain_path


def load_chain(case_dir: Path) -> list[AttestationEntry]:
    """Read the chain file back into AttestationEntry dataclasses.

    Returns [] if the chain doesn't exist yet.

    Adversarial-hardening:
      * A corrupt JSON line is logged and skipped — the chain is
        append-only and one mangled line should not destroy the whole
        verifier. Subsequent valid entries (and the prev_hash chain
        check during verify_chain) will catch any tampering.
      * Forward-compatible field drift: an entry / artifact carrying
        extra keys from a future pipeline version is accepted by
        dropping the unknown keys, NOT by crashing the loader. The
        dropped key set is logged for diagnosis.
    """
    chain_path = chain_file_path(case_dir)
    if not chain_path.exists():
        return []

    # Known field sets — anything else is dropped during forward-compat
    # tolerant decode. These mirror the dataclass definitions above.
    _ARTIFACT_KEYS = {"relative_path", "sha256_hex", "size_bytes"}
    _ENTRY_KEYS = {
        "chain_id", "entry_index", "stage", "timestamp_iso", "operator",
        "public_key_fingerprint", "prev_hash", "note",
        "signed_payload_sha256", "signature_b64",
    }

    out: list[AttestationEntry] = []
    with chain_path.open("r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError as e:
                log.warning(
                    "skipping malformed JSON in chain.jsonl line %d: %s",
                    line_no, e,
                )
                continue
            if not isinstance(d, dict):
                log.warning(
                    "skipping non-object JSON in chain.jsonl line %d", line_no,
                )
                continue
            raw_artifacts = d.pop("artifacts", []) or []
            artifacts: list[AttestedArtifact] = []
            for a in raw_artifacts:
                if not isinstance(a, dict):
                    continue
                known = {k: v for k, v in a.items() if k in _ARTIFACT_KEYS}
                extras = set(a) - _ARTIFACT_KEYS
                if extras:
                    log.debug(
                        "dropping unknown artifact keys in line %d: %s",
                        line_no, extras,
                    )
                try:
                    artifacts.append(AttestedArtifact(**known))
                except TypeError as e:
                    log.warning(
                        "skipping malformed artifact in line %d: %s",
                        line_no, e,
                    )
            known_entry = {k: v for k, v in d.items() if k in _ENTRY_KEYS}
            extras = set(d) - _ENTRY_KEYS
            if extras:
                log.debug(
                    "dropping unknown entry keys in line %d: %s",
                    line_no, extras,
                )
            try:
                out.append(AttestationEntry(artifacts=artifacts, **known_entry))
            except TypeError as e:
                log.warning(
                    "skipping malformed entry in line %d: %s", line_no, e,
                )
    return out


def latest_prev_hash(case_dir: Path) -> tuple[str, int]:
    """Return (prev_hash_for_next_entry, next_entry_index).

    For a brand-new chain returns (GENESIS_PREV_HASH, 0). For a
    chain with N entries returns (sha256_of_last_entry, N).
    """
    chain = load_chain(case_dir)
    if not chain:
        return GENESIS_PREV_HASH, 0
    last = chain[-1]
    return last.signed_payload_sha256, last.entry_index + 1


# ---- Verification ---- #


@dataclass
class VerificationFinding:
    """One issue found during chain verification."""
    entry_index: int
    severity: str         # 'critical' | 'warning'
    kind: str             # 'signature_invalid' | 'prev_hash_mismatch' |
                          # 'artifact_missing' | 'artifact_hash_mismatch' |
                          # 'chain_id_mismatch' | 'public_key_changed'
    message: str


@dataclass
class VerificationReport:
    chain_path: str
    case_dir: str
    entries_checked: int
    findings: list[VerificationFinding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(f.severity == "critical" for f in self.findings)


def verify_chain(
    case_dir: Path,
    *,
    public_key_b64_str: str | None = None,
    check_artifacts: bool = True,
) -> VerificationReport:
    """Walk the case's custody chain and verify every link.

    Args:
      case_dir: the case directory containing custody/chain.jsonl.
      public_key_b64_str: the operator's public key. If None, we
        read from case_dir/custody/public_key.txt. For court use,
        callers SHOULD pass this explicitly from an independently-
        sourced public key (e.g. the operator's published key).
        Trusting the case-local public_key.txt assumes the case dir
        itself isn't tampered with.
      check_artifacts: also re-hash referenced artifacts and verify
        they match the recorded sha256. Set False for fast pre-flight
        checks.

    Returns a VerificationReport. ``report.ok`` is True iff zero
    critical findings.
    """
    chain_path = chain_file_path(case_dir)
    report = VerificationReport(
        chain_path=str(chain_path),
        case_dir=str(case_dir),
        entries_checked=0,
    )
    if not chain_path.exists():
        report.findings.append(VerificationFinding(
            entry_index=-1,
            severity="critical",
            kind="chain_missing",
            message=f"No custody chain at {chain_path}",
        ))
        return report

    if public_key_b64_str is None:
        pub_path = public_key_file_path(case_dir)
        if not pub_path.exists():
            report.findings.append(VerificationFinding(
                entry_index=-1,
                severity="critical",
                kind="public_key_missing",
                message=(
                    "No public key file and no explicit public key supplied; "
                    "cannot verify signatures."
                ),
            ))
            return report
        public_key_b64_str = pub_path.read_text(encoding="utf-8").strip()

    try:
        pub = load_public_key_b64(public_key_b64_str)
    except ValueError as e:
        report.findings.append(VerificationFinding(
            entry_index=-1, severity="critical",
            kind="public_key_invalid",
            message=str(e),
        ))
        return report

    expected_fingerprint = public_key_fingerprint_b64(public_key_b64_str)
    chain = load_chain(case_dir)
    expected_prev = GENESIS_PREV_HASH
    expected_chain_id: str | None = None
    expected_index = 0

    for entry in chain:
        report.entries_checked += 1
        if expected_chain_id is None:
            expected_chain_id = entry.chain_id
        if entry.chain_id != expected_chain_id:
            report.findings.append(VerificationFinding(
                entry_index=entry.entry_index, severity="critical",
                kind="chain_id_mismatch",
                message=(
                    f"Entry chain_id={entry.chain_id!r} does not match "
                    f"chain's first entry ({expected_chain_id!r})"
                ),
            ))
        if entry.entry_index != expected_index:
            report.findings.append(VerificationFinding(
                entry_index=entry.entry_index, severity="critical",
                kind="entry_index_skip",
                message=(
                    f"Entry index {entry.entry_index} expected to be "
                    f"{expected_index}"
                ),
            ))
        if entry.prev_hash != expected_prev:
            report.findings.append(VerificationFinding(
                entry_index=entry.entry_index, severity="critical",
                kind="prev_hash_mismatch",
                message=(
                    f"prev_hash recorded as {entry.prev_hash!r} but "
                    f"computed previous-entry hash was {expected_prev!r}. "
                    "Chain may have been tampered or re-ordered."
                ),
            ))
        if entry.public_key_fingerprint != expected_fingerprint:
            report.findings.append(VerificationFinding(
                entry_index=entry.entry_index, severity="critical",
                kind="public_key_changed",
                message=(
                    f"Entry's public_key_fingerprint "
                    f"({entry.public_key_fingerprint!r}) does not match "
                    f"the verifying public key ({expected_fingerprint!r}). "
                    "Wrong key OR signer changed mid-chain."
                ),
            ))

        # Verify signature.
        payload = _entry_payload_dict(
            chain_id=entry.chain_id,
            entry_index=entry.entry_index,
            stage=entry.stage,
            timestamp_iso=entry.timestamp_iso,
            operator=entry.operator,
            public_key_fingerprint=entry.public_key_fingerprint,
            prev_hash=entry.prev_hash,
            artifacts=entry.artifacts,
            note=entry.note,
        )
        canonical = _canonical_json(payload)
        recomputed_sha256 = _sha256_hex(canonical)
        if recomputed_sha256 != entry.signed_payload_sha256:
            report.findings.append(VerificationFinding(
                entry_index=entry.entry_index, severity="critical",
                kind="payload_hash_mismatch",
                message=(
                    "signed_payload_sha256 does not match the recomputed "
                    "SHA-256 of the entry's payload. Entry has been "
                    "modified after signing."
                ),
            ))
        try:
            signature = base64.b64decode(entry.signature_b64, validate=True)
            pub.verify(signature, canonical)
        except (ValueError, InvalidSignature) as e:
            report.findings.append(VerificationFinding(
                entry_index=entry.entry_index, severity="critical",
                kind="signature_invalid",
                message=f"Ed25519 signature verification failed: {e}",
            ))

        # Verify artifact hashes.
        if check_artifacts:
            for art in entry.artifacts:
                art_path = case_dir / art.relative_path
                # Some platforms write \\ in stored paths — normalize on read.
                if not art_path.exists():
                    art_path = case_dir / art.relative_path.replace("\\", "/")
                if not art_path.exists():
                    report.findings.append(VerificationFinding(
                        entry_index=entry.entry_index, severity="warning",
                        kind="artifact_missing",
                        message=(
                            f"Attested artifact {art.relative_path!r} not "
                            "found on disk; cannot verify its current hash."
                        ),
                    ))
                    continue
                current_hash, current_size = _hash_file(art_path)
                if current_hash != art.sha256_hex:
                    report.findings.append(VerificationFinding(
                        entry_index=entry.entry_index, severity="critical",
                        kind="artifact_hash_mismatch",
                        message=(
                            f"Artifact {art.relative_path!r} hash on disk "
                            f"({current_hash}) does not match attested "
                            f"hash ({art.sha256_hex}). Tampering or "
                            "out-of-band modification."
                        ),
                    ))

        # Advance.
        expected_prev = entry.signed_payload_sha256
        expected_index = entry.entry_index + 1

    return report


__all__ = (
    "GENESIS_PREV_HASH",
    "AttestedArtifact",
    "AttestationEntry",
    "VerificationFinding",
    "VerificationReport",
    "generate_keypair",
    "load_private_key",
    "load_public_key_b64",
    "public_key_b64",
    "public_key_fingerprint_b64",
    "create_attestation",
    "append_to_chain",
    "load_chain",
    "latest_prev_hash",
    "verify_chain",
    "chain_file_path",
    "public_key_file_path",
)
