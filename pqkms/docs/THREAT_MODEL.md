# PQ-KMS Threat Model

This document states what PQ-KMS defends against, what it explicitly does not,
and the trust boundaries an auditor or operator should reason about. It reflects
the implementation as built (see `app/` and the test suite), not aspirations.

## Assets

| Asset | Sensitivity | Protection |
|---|---|---|
| Root KEK | Critical | Never on disk in plaintext; sealed in a custody envelope (passphrase+Argon2id, Shamir, AWS/GCP KMS, or PKCS#11 HSM). In memory only while unlocked. |
| Managed key material (DEK/KEM/SIG secrets) | Critical | AEAD-wrapped under the Root KEK with per-key/version AAD; never returned over the API. |
| Audit log | High | Hash-chained + hybrid-signed; optional off-box append-only/WORM mirror. |
| API tokens | High | Stored as SHA-384 hashes; raw value shown once. |
| Operator session cookies (SSO) | High | Stateless, HMAC-SHA256 signed, HttpOnly, short TTL. |

## Trust boundaries

1. **Network → API.** All API access requires a bearer token or (for the UI) an
   OIDC-established session. TLS is terminated at the proxy or in-process
   (optionally mTLS). Rate limiting, body-size caps, and strict input validation
   apply at this boundary.
2. **API → KeyStore.** Authorization (scopes + grants) is enforced before any key
   operation; the KeyStore refuses operations on disabled/pending-deletion keys.
3. **KeyStore → custody backend.** The Root KEK is unsealed only by the configured
   custodian. HSM/cloud-KMS backends keep the wrapping key off the host entirely.
4. **Process → storage.** Key material at rest is always AEAD-wrapped; the DB
   alone is insufficient to recover plaintext keys without the Root KEK.

## Adversaries and mitigations

- **Network attacker / unauthenticated caller.** Cannot call the API (401);
  cannot read `/metrics` if the proxy is configured per the runbook. Mitigated by
  auth, TLS/mTLS, rate limiting, generic error bodies (no detail leakage).
- **Quantum adversary ("harvest now, decrypt later").** Key wrapping uses hybrid
  X25519 + ML-KEM-768; signatures use Ed25519 + ML-DSA-65; symmetric is
  AES-256-GCM. Downgrade to classical-only is refused by default
  (`PQKMS_REQUIRE_PQ`). Stored material is suite-tagged for crypto-agility.
- **Compromised low-privilege token.** Scopes bound capability; in strict authz
  mode, grants bound which keys/namespaces are reachable, giving tenant isolation
  and least privilege. Disabled/pending keys refuse use.
- **Insider with DB read access.** Sees only wrapped key material and hashed
  tokens. Cannot unwrap without the Root KEK (ideally HSM/KMS-held).
- **Audit tampering.** Editing history breaks the hash chain and signatures;
  cross-checking the WORM mirror against the DB detects DB-side edits. A
  `UNIQUE(prev_hash)` index makes the chain fork-proof across replicas.
- **Nonce reuse / birthday bound.** Per-key-version encryption budget fails
  closed (HTTP 409) before the AES-GCM random-nonce bound; enforced atomically,
  correct across replicas on Postgres.
- **Credential theft (human).** OIDC SSO removes shared static UI tokens; sessions
  are short-lived and signed; principals can be disabled/deleted to revoke all
  their credentials at once.

## Out of scope / explicit non-goals

- **FIPS 140-3 validated module.** The PQC primitives (liboqs) are not
  FIPS-validated. For a validated boundary, hold the Root KEK in a FIPS 140-2/3
  HSM via the PKCS#11 custodian and treat the data plane accordingly. See
  [COMPLIANCE.md](COMPLIANCE.md).
- **Host/root compromise while unlocked.** An attacker with code execution as the
  service user on an unlocked node can read the in-memory Root KEK. Mitigate with
  HSM custody (key never in host memory in usable form for bulk export), host
  hardening, and least-privilege deployment.
- **Side-channel resistance of the host crypto libraries.** Inherited from
  `cryptography`/OpenSSL and liboqs; see their advisories.
- **Denial of service at the network layer.** Per-IP rate limiting helps; a full
  DoS posture (WAF, L3/4 scrubbing) is the deployment's responsibility.

## Assumptions

- The custody backend (passphrase strength / HSM / cloud KMS IAM) is correctly
  configured and its secrets are managed outside the KMS.
- TLS is terminated with a modern configuration (PQC-hybrid where available).
- Operators rotate the bootstrap admin token after issuing scoped credentials.
