# PQ-KMS Cryptographic Specification

A precise description of the algorithms, key hierarchy, and wire formats, for
reviewers and integrators. Authoritative source is `app/crypto/` and
`app/storage/keystore.py`.

## Algorithm suites

| Purpose | Classical | Post-quantum | Combiner |
|---|---|---|---|
| Key encapsulation (wrapping) | X25519 ECDH | ML-KEM-768 (FIPS 203) | HKDF-SHA384(ss_classical ‖ ss_pq) |
| Digital signatures | Ed25519 | ML-DSA-65 (FIPS 204) | Concatenated hybrid signature |
| Symmetric AEAD (data) | AES-256-GCM | — (AES-256 is Grover-resistant at the 128-bit PQ level) | — |
| Password-derived KEK | Argon2id → HKDF-SHA384 | same | — |

Every stored artifact is tagged with a numeric **suite id** (`app/crypto/suites.py`)
so material is never misinterpreted and the system can migrate when standards
evolve (crypto-agility). Classical-only suites are tagged `CLASSIC_*` and are
only produced when `PQKMS_REQUIRE_PQ=0` is explicitly set.

## Key hierarchy

```
operator secret (passphrase / Shamir / HSM / cloud-KMS)
  └─ custody envelope unseals ─▶ Root KEK (AES-256, in memory only)
        └─ AES-256-GCM wraps ─▶ each managed key's secret material (per key+version)
              ├─ aead: AES-256 data keys
              ├─ kem:  X25519 + ML-KEM-768 private keys
              └─ sig:  Ed25519 + ML-DSA-65 private keys
```

- The Root KEK is generated with a CSPRNG on first bootstrap and **never written
  to disk in plaintext** — only inside a self-describing custody envelope.
- Each managed key is wrapped with **per-key, per-version AAD**
  (`pqkms/key/<id>/v<n>`), binding ciphertext to its identity and version.
- Rotation creates a new version; prior versions remain for decrypt/verify only.

## Wire formats

- **AEAD ciphertext** (returned by `/encrypt`): base64 of
  `‖ suite(1B) ‖ version(4B, big-endian) ‖ AES-GCM(nonce‖ct‖tag)`. `/decrypt`
  routes on the embedded version.
- **Hybrid signature**: concatenation of the classical and PQ signatures; both
  must verify, and verification is bound to the key's stored suite to prevent a
  downgrade to classical-only.
- **Hybrid KEM wrap**: `(encapsulation, AES-256-GCM(shared_secret, data_key))`,
  where `shared_secret = HKDF-SHA384(ss_x25519 ‖ ss_mlkem)`.

## Nonce management

AES-256-GCM uses random 96-bit nonces. Each key version has an enforced
**encryption budget**: the KMS counts encryptions and refuses further use
(HTTP 409) before approaching the random-nonce birthday bound (~2³²), with a soft
warning threshold (~2³⁰). The counter is bumped atomically
(`UPDATE … RETURNING`), so the budget is correct and fail-closed across replicas.

## Audit signing

The audit log is hybrid-signed with a dedicated keypair stored AEAD-wrapped under
the Root KEK. Each entry hashes `prev_hash ‖ payload` (SHA-384) and is signed;
the chain plus a `UNIQUE(prev_hash)` index makes history tamper-evident and
fork-proof.

## Randomness

All key/nonce/salt generation uses the OS CSPRNG (`secrets` / `os.urandom` via
`cryptography` and liboqs). Tokens use `secrets.token_urlsafe`.

## Library provenance

- `cryptography` (OpenSSL-backed) for X25519, Ed25519, AES-GCM, HKDF.
- `argon2-cffi` for Argon2id.
- `liboqs` / `liboqs-python` for ML-KEM-768 and ML-DSA-65, pinned to a release
  tag matching the binding (see `deploy/Dockerfile`).
