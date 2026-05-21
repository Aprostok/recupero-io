"""Tests for v0.13.7 court-admissible chain-of-custody.

Focus is tamper detection — if we don't actually catch tampering,
the whole system is theater. Each verification path gets a
positive test (clean chain verifies) AND a negative test (modified
case detects).
"""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from recupero.custody.chain import (
    GENESIS_PREV_HASH,
    append_to_chain,
    chain_file_path,
    create_attestation,
    generate_keypair,
    latest_prev_hash,
    load_chain,
    load_private_key,
    load_public_key_b64,
    public_key_b64,
    public_key_fingerprint_b64,
    verify_chain,
)

# ---- Keypair generation ---- #


def test_keygen_writes_private_and_public() -> None:
    with TemporaryDirectory() as tmp:
        priv_path = Path(tmp) / "key"
        priv, pub = generate_keypair(priv_path)
        assert priv.exists()
        assert pub.exists()
        assert pub.suffix == ".pub"
        # Public key is base64 of 32 raw bytes — should decode without error.
        pub_b64_str = pub.read_text(encoding="utf-8").strip()
        load_public_key_b64(pub_b64_str)  # must not raise


def test_load_private_key_round_trip() -> None:
    with TemporaryDirectory() as tmp:
        priv_path = Path(tmp) / "key"
        priv_path_out, pub_path = generate_keypair(priv_path)
        # Roundtrip: load priv, derive pub, verify it matches the .pub file
        priv = load_private_key(priv_path_out)
        derived = public_key_b64(priv)
        on_disk = pub_path.read_text(encoding="utf-8").strip()
        assert derived == on_disk


def test_public_key_fingerprint_stable() -> None:
    """Same public key always produces the same fingerprint."""
    with TemporaryDirectory() as tmp:
        _, pub_path = generate_keypair(Path(tmp) / "key")
        pub_b64_str = pub_path.read_text(encoding="utf-8").strip()
        fp1 = public_key_fingerprint_b64(pub_b64_str)
        fp2 = public_key_fingerprint_b64(pub_b64_str)
        assert fp1 == fp2
        assert len(fp1) == 16  # 16 hex chars


def test_different_keys_produce_different_fingerprints() -> None:
    with TemporaryDirectory() as tmp:
        _, pub1 = generate_keypair(Path(tmp) / "k1")
        _, pub2 = generate_keypair(Path(tmp) / "k2")
        fp1 = public_key_fingerprint_b64(pub1.read_text().strip())
        fp2 = public_key_fingerprint_b64(pub2.read_text().strip())
        assert fp1 != fp2


def test_load_invalid_public_key_raises() -> None:
    with pytest.raises(ValueError, match="not valid base64"):
        load_public_key_b64("!!! not base64 !!!")
    with pytest.raises(ValueError, match="32 bytes"):
        load_public_key_b64("YWJj")  # 'abc' = 3 bytes


# ---- Attestation creation + chain append ---- #


def _write_artifact(case_dir: Path, name: str, content: bytes) -> Path:
    p = case_dir / name
    p.write_bytes(content)
    return p


def test_create_first_entry_uses_genesis_prev_hash() -> None:
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        priv_path = case_dir / "key"
        priv_path, _ = generate_keypair(priv_path)
        priv = load_private_key(priv_path)
        art = _write_artifact(case_dir, "case.json", b'{"v":1}')

        entry = create_attestation(
            case_dir=case_dir,
            chain_id="V-CFI01",
            stage="trace",
            operator="alec@recupero.io",
            artifact_paths=[art],
            prev_hash=GENESIS_PREV_HASH,
            entry_index=0,
            note="initial trace",
            private_key=priv,
        )
        assert entry.entry_index == 0
        assert entry.prev_hash == GENESIS_PREV_HASH
        assert entry.stage == "trace"
        assert entry.chain_id == "V-CFI01"
        assert len(entry.artifacts) == 1
        assert entry.artifacts[0].relative_path == "case.json"
        # SHA-256 of '{"v":1}' is a known constant — verify hash field.
        import hashlib
        expected = hashlib.sha256(b'{"v":1}').hexdigest()
        assert entry.artifacts[0].sha256_hex == expected


def test_append_to_chain_and_load_round_trip() -> None:
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        priv_path, pub_path = generate_keypair(case_dir / "key")
        priv = load_private_key(priv_path)
        art = _write_artifact(case_dir, "case.json", b'{"v":1}')

        entry = create_attestation(
            case_dir=case_dir, chain_id="V-CFI01", stage="trace",
            operator="alec@recupero.io", artifact_paths=[art],
            prev_hash=GENESIS_PREV_HASH, entry_index=0,
            private_key=priv,
        )
        pub_b64_str = pub_path.read_text(encoding="utf-8").strip()
        append_to_chain(case_dir, entry, public_key_b64_str=pub_b64_str)

        chain = load_chain(case_dir)
        assert len(chain) == 1
        assert chain[0].chain_id == "V-CFI01"
        assert chain[0].stage == "trace"
        assert chain[0].signed_payload_sha256 == entry.signed_payload_sha256


def test_latest_prev_hash_advances() -> None:
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        priv_path, _ = generate_keypair(case_dir / "key")
        priv = load_private_key(priv_path)
        art = _write_artifact(case_dir, "f1.json", b'aaa')

        # New chain.
        prev, idx = latest_prev_hash(case_dir)
        assert prev == GENESIS_PREV_HASH
        assert idx == 0

        # Append one entry.
        e1 = create_attestation(
            case_dir=case_dir, chain_id="V", stage="trace",
            operator="op", artifact_paths=[art],
            prev_hash=prev, entry_index=idx, private_key=priv,
        )
        append_to_chain(case_dir, e1)
        prev2, idx2 = latest_prev_hash(case_dir)
        assert prev2 == e1.signed_payload_sha256
        assert idx2 == 1


# ---- Verification: clean chain ---- #


def _build_two_entry_chain(case_dir: Path):
    """Helper: build a clean 2-entry chain and return (priv, pub_b64)."""
    priv_path, pub_path = generate_keypair(case_dir / "key")
    priv = load_private_key(priv_path)
    pub_b64_str = pub_path.read_text(encoding="utf-8").strip()

    art1 = _write_artifact(case_dir, "case.json", b'{"v":1}')
    e1 = create_attestation(
        case_dir=case_dir, chain_id="V", stage="trace",
        operator="op", artifact_paths=[art1],
        prev_hash=GENESIS_PREV_HASH, entry_index=0, private_key=priv,
    )
    append_to_chain(case_dir, e1, public_key_b64_str=pub_b64_str)

    art2 = _write_artifact(case_dir, "freeze_brief.json", b'{"v":2}')
    e2 = create_attestation(
        case_dir=case_dir, chain_id="V", stage="emit-brief",
        operator="op", artifact_paths=[art2],
        prev_hash=e1.signed_payload_sha256, entry_index=1, private_key=priv,
    )
    append_to_chain(case_dir, e2)
    return priv, pub_b64_str


def test_clean_chain_verifies() -> None:
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        _, pub_b64_str = _build_two_entry_chain(case_dir)
        report = verify_chain(case_dir, public_key_b64_str=pub_b64_str)
        assert report.ok is True
        assert report.entries_checked == 2
        assert report.findings == []


# ---- Verification: tamper detection ---- #


def test_modified_artifact_detected() -> None:
    """The headline tamper-detection scenario: an operator alters the
    case.json after signing. Verification must flag this as critical."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        _, pub_b64_str = _build_two_entry_chain(case_dir)
        # Tamper: modify case.json after attestation.
        (case_dir / "case.json").write_bytes(b'{"v":1,"tampered":true}')
        report = verify_chain(case_dir, public_key_b64_str=pub_b64_str)
        assert report.ok is False
        # The critical finding should mention artifact_hash_mismatch.
        kinds = {f.kind for f in report.findings if f.severity == "critical"}
        assert "artifact_hash_mismatch" in kinds


def test_signature_tamper_detected() -> None:
    """Hand-edit the chain file to change an entry's signature.
    Verification must detect the broken signature."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        _, pub_b64_str = _build_two_entry_chain(case_dir)
        # Tamper: swap the signature of entry 0 for entry 1's.
        chain_path = chain_file_path(case_dir)
        lines = chain_path.read_text(encoding="utf-8").splitlines()
        e0 = json.loads(lines[0])
        e1 = json.loads(lines[1])
        e0["signature_b64"] = e1["signature_b64"]
        lines[0] = json.dumps(e0, sort_keys=True, separators=(",", ":"))
        chain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        report = verify_chain(case_dir, public_key_b64_str=pub_b64_str)
        assert report.ok is False
        kinds = {f.kind for f in report.findings if f.severity == "critical"}
        assert "signature_invalid" in kinds


def test_payload_tamper_detected_via_recomputed_hash() -> None:
    """Hand-edit a single field of an entry (without re-signing).
    The recomputed signed_payload_sha256 must mismatch."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        _, pub_b64_str = _build_two_entry_chain(case_dir)
        chain_path = chain_file_path(case_dir)
        lines = chain_path.read_text(encoding="utf-8").splitlines()
        e0 = json.loads(lines[0])
        e0["operator"] = "different-operator"   # forged change
        lines[0] = json.dumps(e0, sort_keys=True, separators=(",", ":"))
        chain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        report = verify_chain(case_dir, public_key_b64_str=pub_b64_str)
        assert report.ok is False


def test_chain_reorder_detected_via_prev_hash() -> None:
    """Swap entries 0 and 1 in the chain — the prev_hash chain
    breaks, and verification catches it."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        _, pub_b64_str = _build_two_entry_chain(case_dir)
        chain_path = chain_file_path(case_dir)
        lines = chain_path.read_text(encoding="utf-8").splitlines()
        # Reverse the order — e1 first, e0 second.
        chain_path.write_text(
            lines[1] + "\n" + lines[0] + "\n", encoding="utf-8",
        )
        report = verify_chain(case_dir, public_key_b64_str=pub_b64_str)
        assert report.ok is False
        kinds = {f.kind for f in report.findings if f.severity == "critical"}
        # Either entry_index_skip OR prev_hash_mismatch — both
        # indicate the chain is out of order.
        assert "entry_index_skip" in kinds or "prev_hash_mismatch" in kinds


def test_wrong_public_key_fails_verification() -> None:
    """Verify with a DIFFERENT public key than the one that signed.
    All signatures should fail."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        _build_two_entry_chain(case_dir)
        # Generate a different key, use its public for verification.
        _, other_pub = generate_keypair(case_dir / "other_key")
        other_pub_b64 = other_pub.read_text(encoding="utf-8").strip()
        report = verify_chain(case_dir, public_key_b64_str=other_pub_b64)
        assert report.ok is False
        # The key-fingerprint check fires AND signatures fail.
        kinds = {f.kind for f in report.findings if f.severity == "critical"}
        assert "public_key_changed" in kinds or "signature_invalid" in kinds


def test_missing_chain_file_reports_critical() -> None:
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        # No chain file written at all.
        report = verify_chain(case_dir, public_key_b64_str="dummy")
        assert report.ok is False
        kinds = {f.kind for f in report.findings if f.severity == "critical"}
        assert "chain_missing" in kinds


def test_missing_artifact_is_warning_not_critical() -> None:
    """If an attested artifact has been deleted but the chain
    itself is intact, the missing artifact is a WARNING (the chain
    isn't tampered, just incomplete). Verification can still pass
    if there are no critical findings."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        _, pub_b64_str = _build_two_entry_chain(case_dir)
        # Delete case.json.
        (case_dir / "case.json").unlink()
        report = verify_chain(case_dir, public_key_b64_str=pub_b64_str)
        # The missing-artifact finding is severity=warning, so
        # ok=True.
        warning_kinds = {
            f.kind for f in report.findings if f.severity == "warning"
        }
        assert "artifact_missing" in warning_kinds
        assert report.ok is True


def test_check_artifacts_false_skips_artifact_verification() -> None:
    """With check_artifacts=False, modified artifacts don't get caught.
    Useful for fast pre-flight chain-structure checks where the
    operator hasn't yet placed the artifacts in their final form."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        _, pub_b64_str = _build_two_entry_chain(case_dir)
        (case_dir / "case.json").write_bytes(b'{"tampered":true}')
        report = verify_chain(
            case_dir, public_key_b64_str=pub_b64_str,
            check_artifacts=False,
        )
        assert report.ok is True   # tamper not detected when check skipped


# ---- Canonicalization round-trip ---- #


def test_canonical_serialization_is_deterministic() -> None:
    """Two equivalent dicts (different key orders) produce identical
    canonical JSON. Critical for cross-platform signing."""
    from recupero.custody.chain import _canonical_json
    d1 = {"a": 1, "b": [3, 2, 1], "c": "hello"}
    d2 = {"c": "hello", "b": [3, 2, 1], "a": 1}
    assert _canonical_json(d1) == _canonical_json(d2)


def test_canonical_serialization_is_sorted_keys() -> None:
    from recupero.custody.chain import _canonical_json
    out = _canonical_json({"z": 1, "a": 2, "m": 3})
    # The output should begin with the smallest key alphabetically.
    assert out.startswith(b'{"a":')
