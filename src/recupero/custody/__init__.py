"""Court-admissible chain-of-custody attestations (v0.13.7).

Every meaningful pipeline stage (trace, list-freeze-targets,
emit-brief, AI editorial review, freeze-letter dispatch) writes a
signed attestation entry into a case-local hash chain. The chain
is anchored cryptographically:

  * Each entry includes a SHA-256 hash of the CANONICAL JSON
    serialization of every artifact it covers (e.g., the trace
    stage hashes case.json; emit-brief hashes freeze_brief.json).
  * Each entry includes the hash of the PREVIOUS entry's
    canonical bytes, forming a tamper-evident chain.
  * Each entry is signed with the operator's Ed25519 private key.
    Verifiers need only the corresponding public key to check.

What this protects against
--------------------------

Court-admissibility requires showing that the digital evidence
hasn't been altered between collection and the brief that lands
in court. The chain answers:

  Q: "Did the freeze_brief.json that was delivered to the
      customer match what the operator produced?"
  A: The custody chain has a signed entry recording the SHA-256
     of the brief at deliver time. The court verifies the
     signature with the public key, computes SHA-256 of the
     PDF, and compares. Mismatch → tampering detected.

  Q: "Could the operator have re-generated the trace after the
      fact to fit a narrative?"
  A: The chain's hash links would break — the brief's prev_hash
     would no longer match the trace's recorded hash. Any
     re-generation requires re-signing every entry from the
     point of change forward, which the public key proves
     happened.

Architecturally we lean toward "audit log" not "DRM" — the system
doesn't prevent tampering, it makes tampering MATHEMATICALLY
DETECTABLE.

Key management
--------------

  * The operator's private key lives at ``RECUPERO_CUSTODY_KEY_PATH``
    (env var; default ``~/.recupero/custody_key``). Generated via
    ``recupero-ops custody-keygen``. Never transmitted.
  * The public key is published in the brief's metadata + posted
    to the operator's website / GitHub so verifiers can fetch
    it independently.
  * Key rotation: the chain's first entry records the public-key
    fingerprint in use. A new key starts a new chain — old
    chains stay verifiable with the old public key indefinitely.

Files
-----

  case_dir/
    custody/
      chain.jsonl          # one signed attestation per line
      public_key.txt       # base64 Ed25519 public key
"""
