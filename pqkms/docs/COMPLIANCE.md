# PQ-KMS Compliance Posture

How PQ-KMS supports common control frameworks, and — stated plainly — where
certification depends on the deployment or on external attestation that software
alone cannot provide.

## FIPS 140-2/3 boundary statement

- The post-quantum primitives are provided by **liboqs, which is not FIPS-validated**.
  The classical primitives come from OpenSSL via `cryptography`; FIPS status
  depends on the exact OpenSSL build.
- **To operate inside a validated boundary:** hold the Root KEK in a **FIPS
  140-2/3 validated HSM** using the PKCS#11 custodian (`PQKMS_CUSTODY_BACKEND=pkcs11`)
  so the master key is generated and used inside the validated module, and treat
  the app's data-plane crypto according to your accreditation scope. PQ-KMS does
  not claim FIPS validation of its own software module.
- The hybrid design means even where the PQC half is non-validated, the classical
  half provides a defensible baseline while NIST PQC validation programs mature.

## Control mapping (illustrative)

| Framework / control | How PQ-KMS supports it |
|---|---|
| SOC 2 CC6.1 (logical access) | Token scopes + per-resource grants (strict mode), OIDC SSO, principal disable/delete. |
| SOC 2 CC6.6 (encryption) | Envelope encryption; hybrid PQC; keys never leave wrapped. |
| SOC 2 CC7.2 / ISO A.12.4 (logging & monitoring) | Hash-chained, signed audit log; `/metrics`; structured logs; SIEM (CEF) export. |
| ISO 27001 A.10.1 (cryptographic controls) | Documented suites, key hierarchy, rotation, nonce budget (see CRYPTOGRAPHY.md). |
| ISO 27001 A.9.2 (user access mgmt) | Principals as identities; least-privilege grants; credential rotation per principal. |
| PCI-DSS 3.5/3.6 (key management) | Key lifecycle (enable/disable/rotate/scheduled-deletion), split knowledge via Shamir, HSM custody. |
| NIST SP 800-57 (key mgmt lifecycle) | Versioned keys, rotation, archival (rotated versions), destruction with waiting period. |
| NIST PQC migration (NCCoE) | Hybrid X25519+ML-KEM / Ed25519+ML-DSA, crypto-agile suite tagging. |

This mapping is a starting point for an audit, not an attestation. SOC 2 / ISO
certification requires an independent assessor and organizational controls
(change management, personnel, physical security) outside this codebase.

## Data residency & retention

- All state lives in the configured database (SQLite or your PostgreSQL); residency
  follows where you host it.
- Audit retention: mirror to WORM/append-only storage (`PQKMS_AUDIT_LOG_FILE`) and
  apply your retention policy at that layer; the DB chain is the tamper-evident
  source of truth.

## Separation of duties

- `admin` is global; `manage` administers keys only within granted namespaces;
  crypto scopes are per-operation. Shamir custody enforces split knowledge of the
  operator secret (K-of-N). Force key destruction requires the `admin` scope.

## Outstanding items requiring external action

- FIPS 140-3 module validation (vendor/lab process).
- SOC 2 Type II / ISO 27001 audit (independent assessor).
- KMIP / PKCS#11 *client provider* interface for drop-in enterprise integration
  (tracked in [ENTERPRISE_READINESS.md](ENTERPRISE_READINESS.md)).
