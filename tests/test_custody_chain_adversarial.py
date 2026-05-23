"""Adversarial tests for the custody chain.

The chain file is operator-trusted on the read path but the verifier
reads attested artifact paths directly from JSON lines. An attacker
who can mutate the chain file (or who provides a tampered case dir
to a verifier) could craft ``relative_path`` entries containing path
traversal segments (``..`` or absolute paths) and have the verifier
hash, leak, or stat files outside the case directory.

Other adversarial vectors covered:
  * Malformed JSON lines must not crash load_chain (skip + continue).
  * AttestedArtifact JSON with extra keys must not raise TypeError
    out of load_chain (defense against pipeline-version drift).
  * Negative size_bytes (clearly invalid) should not be silently
    propagated into a "good" verification.
"""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from recupero.custody.chain import (
    AttestationEntry,
    AttestedArtifact,
    GENESIS_PREV_HASH,
    append_to_chain,
    chain_file_path,
    create_attestation,
    generate_keypair,
    load_chain,
    load_private_key,
    verify_chain,
)


def _write_artifact(case_dir: Path, name: str, content: bytes) -> Path:
    p = case_dir / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    return p


def _build_one_entry_chain(case_dir: Path):
    priv_path, pub_path = generate_keypair(case_dir / "key")
    priv = load_private_key(priv_path)
    pub_b64_str = pub_path.read_text(encoding="utf-8").strip()
    art = _write_artifact(case_dir, "case.json", b'{"v":1}')
    e1 = create_attestation(
        case_dir=case_dir, chain_id="V", stage="trace",
        operator="op", artifact_paths=[art],
        prev_hash=GENESIS_PREV_HASH, entry_index=0, private_key=priv,
    )
    append_to_chain(case_dir, e1, public_key_b64_str=pub_b64_str)
    return priv, pub_b64_str, e1


# ---- Path traversal in attested artifact paths ---- #


def test_verify_rejects_artifact_path_traversal_dot_dot() -> None:
    """An attacker-crafted chain.jsonl with ``relative_path``
    containing ``..`` segments would let the verifier read /hash
    files OUTSIDE the case directory. Verifier must refuse or
    flag this as critical."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        _, pub_b64_str, e1 = _build_one_entry_chain(case_dir)

        # Tamper: rewrite the artifact path to escape case_dir.
        chain_path = chain_file_path(case_dir)
        lines = chain_path.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[0])
        entry["artifacts"][0]["relative_path"] = "../../../etc/passwd"
        lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        chain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = verify_chain(case_dir, public_key_b64_str=pub_b64_str)
        # The verifier should flag this — either via payload-hash
        # mismatch (because we rewrote the line), via signature_invalid,
        # via a dedicated unsafe-path finding, or via artifact_missing
        # (refusing to traverse outside case_dir). What it must NOT do
        # is silently report ok=True after hashing a file outside the
        # case directory.
        assert report.ok is False, (
            "Verifier silently accepted path-traversal artifact entry."
        )


def test_verify_rejects_absolute_artifact_path() -> None:
    """Absolute paths in relative_path are equally dangerous (Windows
    drive letters, POSIX root paths). Verifier must refuse them."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        _, pub_b64_str, e1 = _build_one_entry_chain(case_dir)

        chain_path = chain_file_path(case_dir)
        lines = chain_path.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[0])
        # POSIX absolute path. On Windows pathlib still parses /etc/passwd
        # but Path("/etc/passwd").exists() is generally False — the test
        # still proves the verifier didn't escape case_dir.
        entry["artifacts"][0]["relative_path"] = "/etc/passwd"
        lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        chain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = verify_chain(case_dir, public_key_b64_str=pub_b64_str)
        assert report.ok is False


# ---- Malformed-line robustness ---- #


def test_load_chain_skips_blank_lines() -> None:
    """Existing contract — blank lines are silently skipped. Don't
    regress."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        _, _, e1 = _build_one_entry_chain(case_dir)
        chain_path = chain_file_path(case_dir)
        # Append blank lines + trailing whitespace.
        with chain_path.open("a", encoding="utf-8") as f:
            f.write("\n   \n\n")
        chain = load_chain(case_dir)
        assert len(chain) == 1


def test_load_chain_handles_corrupt_json_line() -> None:
    """A garbage JSON line in chain.jsonl currently crashes
    load_chain with json.JSONDecodeError. A robust loader should
    skip the line and continue (logging) — the chain is append-only
    and one corrupted line should not destroy the whole verifier."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        _, pub_b64_str, _ = _build_one_entry_chain(case_dir)
        chain_path = chain_file_path(case_dir)
        # Append a non-JSON line then a comment-style line.
        with chain_path.open("a", encoding="utf-8") as f:
            f.write("this is not json\n")
            f.write("{partial}\n")
        try:
            chain = load_chain(case_dir)
        except json.JSONDecodeError as e:
            raise AssertionError(
                f"load_chain raised JSONDecodeError on corrupt line: {e}. "
                "Loader should skip + continue."
            ) from e
        # The valid entry must still be readable.
        assert len(chain) >= 1


# ---- Defensive type guards ---- #


def test_load_chain_handles_extra_keys_in_artifact() -> None:
    """A future pipeline writes an extra key. AttestedArtifact is a
    frozen dataclass and will TypeError on ``**a``. load_chain must
    not crash a verifier on a forward-compat field."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        _, _, e1 = _build_one_entry_chain(case_dir)
        chain_path = chain_file_path(case_dir)
        lines = chain_path.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[0])
        entry["artifacts"][0]["extra_future_field"] = "value"
        lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        chain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            chain = load_chain(case_dir)
        except TypeError as e:
            raise AssertionError(
                f"load_chain raised TypeError on forward-compat extra key: {e}"
            ) from e
        assert len(chain) == 1


def test_verify_rejects_null_byte_in_artifact_path() -> None:
    """NUL byte in a path can confuse downstream tools (path-truncation
    bug class). Refuse it during verification."""
    with TemporaryDirectory() as tmp:
        case_dir = Path(tmp)
        _, pub_b64_str, e1 = _build_one_entry_chain(case_dir)
        chain_path = chain_file_path(case_dir)
        lines = chain_path.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[0])
        entry["artifacts"][0]["relative_path"] = "case.json\x00../../etc/passwd"
        lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        chain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # Either load_chain rejects the NUL byte (preferred) OR
        # verify_chain marks it as not-ok. Both are acceptable.
        try:
            report = verify_chain(case_dir, public_key_b64_str=pub_b64_str)
        except ValueError:
            return  # rejected at load time — acceptable
        assert report.ok is False
