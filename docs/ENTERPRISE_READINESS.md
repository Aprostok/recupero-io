# Enterprise & evidentiary readiness — controls map + gap plan

The non-data gaps vs Chainalysis/TRM/Elliptic split into **codeable controls**
(we build them), **process/attestation** (SOC 2 audit, pen-test — money + time),
and **earned credibility** (court record, expert witnesses — years). This maps
what EXISTS today to the standards buyers ask about, and what's still needed.

## 1. SOC 2 control mapping (Trust Services Criteria)

| TSC | Control | Status in code |
|---|---|---|
| CC6.1 Logical access | API-key auth (constant-time match), admin-key gating, per-key issuer scopes + admin flag (`api/auth.py`) | ✅ present |
| CC6.1 | SSRF defense on all outbound harvest/webhook (host allow-list, private-IP block, no-redirect, body cap) | ✅ present |
| CC6.7 Transmission | HTTPS-only; HMAC-signed webhooks; secrets never logged | ✅ present |
| **CC7.2 Monitoring** | **Append-only audit log** of trusted-data mutations (label promote/reject) — actor, action, target, outcome, IP, ts (`audit/`, migration 034, `GET /v1/audit`) | ✅ **new (v0.38)** |
| CC7.2 | Sentry + Prometheus + structured logging on worker/API | ✅ present |
| CC8.1 Change mgmt | Every change gated on the full test suite; build-failing validators; zero-new-lint discipline | ✅ present |
| CC6.1 | **RBAC roles (viewer/analyst/admin), SSO/SAML, MFA** | ⚠️ partial — admin/issuer scopes exist; full RBAC + SSO **TODO** |
| CC6.6 | **Multi-tenant isolation, data residency** | ❌ single-tenant today |
| A1.2 Availability | `/healthz` + `/v1/health`; Railway healthcheck | ✅ basic; **SLA/status page TODO** |
| — | **SOC 2 Type II report** (the attestation itself) | ❌ requires an external audit period — *not code* |

**Highest-leverage next code:** broaden audit coverage to all admin mutations
(shared `require_admin` choke point) → RBAC roles → SSO. The Type II report is a
6–12 month observation window with an auditor — start the controls now so the
window can begin.

## 2. Evidentiary / Daubert readiness

Courts (Daubert/Frye) ask: is the methodology testable, peer-reviewable, with a
known error rate, generally accepted, and reliably applied? Recupero's design
already answers most of this in code — the gap is *external validation + track
record*, not method.

| Daubert factor | What exists |
|---|---|
| **Testable / reproducible** | Deterministic trace; `Case.software_version` + `config_used` pinned in every output; stable sha256 cluster IDs; re-runnable | ✅ |
| **Known error posture** | Confidence doctrine: `high` ONLY on cryptographic cross-chain-id match or direct label-DB hit; inference always low/medium + labeled; `J1` benchmark harness (recall/precision/F1 vs ground truth) | ✅ |
| **No fabrication** | Build-failing validators (e.g. INVESTIGATE-not-billed-as-freeze-target); addresses are real-on-chain-or-nothing; verified-fixture rule for decoders | ✅ |
| **Chain of custody** | Ed25519 signed custody chain + SHA-256 exhibit manifest (`custody/`, exhibit pack) | ✅ |
| **Peer review / general acceptance** | Methodology doc + open validators; **independent third-party validation TODO** | ⚠️ |
| **Court track record / expert witnesses** | Exhibit/SAR/MLAT artifacts are well-formed but **untested in litigation**; **no expert-witness bench** | ❌ — earned over cases, not code |

**Net:** the *methodology* is Daubert-shaped and auditable today. What's missing
is (a) an independent validation/peer review of the method, and (b) accepted-in-
court precedent + named experts — both of which accrue with real cases, like the
attribution-data moat.

## 3. Honest split of the non-data gaps

- **Code can close:** audit logging (done), RBAC/SSO, status/SLA surface,
  continuous chain-wide clustering, more chain adapters, KYT case-management.
- **Money + time:** SOC 2 Type II audit, penetration test, 24/7 support org,
  own indexing infrastructure at scale.
- **Years + customers:** court track record, expert-witness bench, brand/
  network effects, regulator-recognized standing.

The discipline that's *already* in the codebase (no-fabrication, confidence
doctrine, signed custody, validators, now an audit log) is exactly the
foundation an auditor and a court look for — recupero is unusually well-
positioned to *start* the SOC 2 window and to defend its methodology; it simply
has not yet *run* the audit or *accumulated* the precedent.
