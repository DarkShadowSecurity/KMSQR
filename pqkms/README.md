# PQ-KMS — A Deployable Post-Quantum Key Management System

A working Key Management System designed to resist both classical and quantum attacks.
Built with hybrid cryptography (classical + NIST PQC), envelope encryption, a versioned
key hierarchy, hash-chained audit logs, and cryptographic agility baked in from day one.

## Security design

| Layer | Classical | Post-quantum | Combined |
|---|---|---|---|
| Key encapsulation (wrapping) | X25519 ECDH | ML-KEM-768 (FIPS 203) | HKDF-SHA384(ss_classical \|\| ss_pq) |
| Digital signatures | Ed25519 | ML-DSA-65 (FIPS 204) | Concatenated hybrid sig |
| Symmetric (data) | AES-256-GCM | AES-256-GCM (Grover-resistant at 128-bit PQ level) | — |
| Password-derived KEK | Argon2id → HKDF-SHA384 | same | — |

The key hierarchy is Root KEK → Key-Encryption-Keys → Data-Encryption-Keys, with every
stored ciphertext tagged with an algorithm version so the whole system can be migrated
when new standards land.

## Quick start

```bash
cp deploy/.env.example deploy/.env    # then edit PQKMS_PASSPHRASE
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up --build
```

Then open `http://localhost:8080/ui` for the admin dashboard or hit the API at
`http://localhost:8080/api/v1/`.

On first startup, the container prints a one-time bootstrap admin token to its
logs. Copy it — you'll paste it into the UI's login gate.

```bash
docker compose -f deploy/docker-compose.yml logs pqkms | grep "BOOTSTRAP ADMIN"
```

## Running tests

```bash
pip install -r requirements.txt pytest
pytest tests/test_crypto.py tests/test_keystore.py tests/test_auth.py -v   # unit tests
python tests/e2e_integration.py                                              # spawns a server and exercises the full HTTP API
```

## API

All endpoints require `Authorization: Bearer <token>`.

- `POST /api/v1/keys` — create a new managed key
- `GET  /api/v1/keys` — list keys
- `POST /api/v1/keys/{id}/rotate` — rotate, keeping old versions for decrypt
- `POST /api/v1/keys/{id}/encrypt` — envelope-encrypt a payload
- `POST /api/v1/keys/{id}/decrypt` — decrypt (auto-selects the right key version)
- `POST /api/v1/keys/{id}/sign` — hybrid sign
- `POST /api/v1/keys/{id}/verify` — hybrid verify
- `POST /api/v1/keys/{id}/wrap` — wrap a data key with hybrid KEM
- `POST /api/v1/keys/{id}/unwrap` — unwrap
- `GET  /api/v1/audit` — signed, hash-chained audit log

## Files

```
app/
  crypto/        hybrid KEM, signatures, AEAD, KDF
  storage/       SQLite + encrypted-at-rest key material
  api/           FastAPI routes, auth, audit
  ui/            admin dashboard (HTML/CSS/JS)
deploy/          Dockerfile + docker-compose
tests/           unit tests for the crypto layer
```

## Production hardening notes

This is a reference implementation. The current build ships with these
defenses enabled out of the box:

- **CSP + security headers**: the admin UI is served with strict
  `Content-Security-Policy` (`script-src 'self'`, `frame-ancestors 'none'`),
  `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, etc.
- **No third-party network calls** from the UI: fonts use system fallbacks.
- **Per-IP rate limiting** via `slowapi` on every endpoint (defaults: 600/min
  for crypto ops, 30/min for key creation, 10/min for token creation).
- **Request body size cap** (`PQKMS_MAX_BODY_BYTES`, default 16 MiB).
- **Generic error responses**: internal exception details never leak to
  callers; failures are logged with a request id.
- **Mandatory passphrase** with a configurable minimum length
  (`PQKMS_MIN_PASSPHRASE_LEN`, default 16).
- **Pinned liboqs** to a release tag; `apt-get upgrade` runs at image build.

Before trusting it with real secrets, also:

- Put it behind mTLS with PQC-hybrid TLS (OpenSSL 3.5+ with `X25519MLKEM768`).
- Move the Root KEK into an HSM (CloudHSM, Thales Luna, Entrust nShield — all
  now ship PQC firmware).
- Use Shamir secret sharing for the bootstrap passphrase.
- Stream audit logs to an append-only transparency log or WORM storage.
- Pin the Python base image by digest and rebuild on a security cadence.
- **Revoke the bootstrap admin token** after issuing scoped operational tokens:
  `DELETE /api/v1/tokens/<bootstrap-tid>`. The startup log prints the token id
  alongside the secret.
- **Rotate AEAD keys** before approximately 2³² messages per key version.
  AES-256-GCM with random 96-bit nonces has a birthday-bound collision risk
  beyond that point. There is no automatic enforcement; track per-key usage
  externally or call `POST /keys/{id}/rotate` on a schedule.

### Tunables

| Env var                       | Default     | Purpose                                  |
|-------------------------------|-------------|------------------------------------------|
| `PQKMS_PASSPHRASE`            | (required)  | Operator passphrase for the Root KEK.    |
| `PQKMS_MIN_PASSPHRASE_LEN`    | `16`        | Reject shorter passphrases at startup.   |
| `PQKMS_MAX_BODY_BYTES`        | `16777216`  | Request body size cap (16 MiB).          |
| `PQKMS_DATA_DIR`              | `/var/lib/pqkms` | SQLite + key-material location.     |

## License

PQ-KMS is **proprietary software**.

> Copyright (c) 2026 DarkShadowSec LLC. All Rights Reserved.

See [`LICENSE`](LICENSE) for the full terms. No right to use, copy, modify,
or distribute this software is granted without prior written permission
from DarkShadowSec LLC. Third-party dependencies remain governed by their
own (permissive) licenses, listed in [`NOTICES.md`](NOTICES.md).

For commercial licensing or evaluation access, contact DarkShadowSec LLC.
