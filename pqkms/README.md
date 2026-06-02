# PQ-KMS — A Deployable Post-Quantum Key Management System

A working Key Management System designed to resist both classical and quantum attacks.
Built with hybrid cryptography (classical + NIST PQC), envelope encryption, a versioned
key hierarchy, hash-chained audit logs, and cryptographic agility baked in from day one.

> **PQ-KMS is a product of DarkShadowSec LLC**, registered to DarkShadowSec LLC.
> Copyright © 2026 DarkShadowSec LLC. Free and open-source under the **MIT License** —
> free to use (including commercially), **provided "as is" with no warranties**.
> See [LICENSE](LICENSE) and [docs/LICENSING.md](docs/LICENSING.md).

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

## High-availability deployment

For a multi-replica, production-shaped stack (3 stateless app replicas behind a
PQC-hybrid TLS reverse proxy, shared PostgreSQL + Redis, Prometheus + Grafana):

```bash
# 1. create the mounted secrets (see deploy/compose-secrets/README.md)
mkdir -p deploy/compose-secrets
printf '%s' 'a-strong-operator-passphrase-32+chars' > deploy/compose-secrets/pqkms_passphrase
printf '%s' 'a-strong-postgres-password'            > deploy/compose-secrets/postgres_password
printf '%s' 'a-strong-grafana-password'             > deploy/compose-secrets/grafana_password

# 2. bring up the stack
docker compose -f deploy/docker-compose.ha.yml up --build

# 3. grab the bootstrap admin token (printed once by the init service)
docker compose -f deploy/docker-compose.ha.yml logs pqkms-init | grep -A1 "BOOTSTRAP ADMIN"
```

API/UI are served over PQC-hybrid TLS at `https://localhost:8443/`. A one-shot
`pqkms-init` service creates the Root KEK, audit signing key, and bootstrap
token exactly once before the replicas start. The reverse proxy (Caddy by
default; an nginx + OpenSSL 3.5 sample is in `deploy/proxy/`) negotiates
`X25519MLKEM768` and never exposes `/metrics`. Prometheus scrapes the replicas
on the internal network; Grafana is on `:3000`.

For proxy-less or internal deployments you can terminate TLS in the app itself
with `PQKMS_TLS_CERT`/`PQKMS_TLS_KEY` (and `PQKMS_TLS_CLIENT_CA` for mTLS).

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
- `POST /api/v1/keys/import` — BYOK: import external 32-byte AES-256 material
- `GET  /api/v1/keys/{id}/public-key` — export the public half of a sig/kem key
- `POST /api/v1/keys/{id}/disable` · `/enable` — toggle a key's usability
- `POST /api/v1/keys/{id}/rotation-policy` — set/clear an automatic-rotation period (days)
- `POST /api/v1/keys/{id}/schedule-deletion` · `/cancel-deletion` — staged destruction
- `DELETE /api/v1/keys/{id}` — destroy (after the window; `?force=true` is admin-only)
- `POST /api/v1/keys/{id}/encrypt` — envelope-encrypt a payload
- `POST /api/v1/keys/{id}/decrypt` — decrypt (auto-selects the right key version)
- `POST /api/v1/keys/{id}/sign` — hybrid sign
- `POST /api/v1/keys/{id}/verify` — hybrid verify
- `POST /api/v1/keys/{id}/wrap` — wrap a data key with hybrid KEM
- `POST /api/v1/keys/{id}/unwrap` — unwrap
- `GET  /api/v1/audit` — signed, hash-chained audit log
- `POST /api/v1/principals` — create an identity (service or human) for attribution
- `GET  /api/v1/principals` — list principals
- `POST /api/v1/tokens` — mint a token; optionally bind it to an existing
  `principal_id` (omit to auto-create a service principal named after the token)
- `POST /api/v1/namespaces` — create a key-ring (tenant); `GET` to list
- `POST /api/v1/keys` accepts an optional `namespace` (name) — defaults to `default`
- `POST /api/v1/grants` — grant a principal operations on a key or namespace
  (`{principal_id, resource_type: key|namespace, resource_id, operations:[…]}`);
  `GET /api/v1/grants[?principal_id=…]` to list, `DELETE /api/v1/grants/{id}` to revoke

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
  (`PQKMS_MIN_PASSPHRASE_LEN`, default 16). The passphrase may be supplied via a
  mounted secret file (`PQKMS_PASSPHRASE_FILE`, which takes precedence over the
  `PQKMS_PASSPHRASE` env var) so it never appears in `docker inspect` / `/proc`.
- **Post-quantum required by default**: with `PQKMS_REQUIRE_PQ` enabled (the
  default), the server refuses to start if liboqs is unavailable rather than
  silently degrading to classical-only crypto. Set `PQKMS_REQUIRE_PQ=0` to allow
  classical-only operation explicitly (e.g. a dev box without liboqs).
- **Pluggable Root-KEK custody** (`PQKMS_CUSTODY_BACKEND`, default `passphrase`):
  the Root KEK is sealed in a self-describing custody envelope. Cloud-KMS and
  PKCS#11/HSM backends slot in behind the same interface.
- **Enforced AEAD nonce budget**: each key version counts encryptions and
  *refuses* further use (HTTP 409) as it approaches the AES-256-GCM random-nonce
  birthday bound, so the 2³² limit can no longer be exceeded by accident. Rotate
  the key to get a fresh budget.
- **Optional API-token expiry**: pass `ttl_seconds` when creating a token; expired
  tokens are rejected. Existing tokens remain non-expiring.
- **OIDC SSO for human operators** (opt-in, `PQKMS_OIDC_ENABLED`): operators log
  into the UI via your IdP (Okta, Entra ID, Keycloak, Google, …) using the
  authorization-code + PKCE flow instead of pasting a token. The `id_token`
  signature is verified against the IdP's JWKS with issuer/audience/expiry/nonce
  checks; the IdP subject maps to a stable **human principal**, and group claims
  map to scopes (`PQKMS_OIDC_ADMIN_GROUPS` → `admin`). Sessions are HMAC-signed,
  HttpOnly cookies; machine clients keep using bearer tokens (which need no IdP).
  Endpoints: `GET /api/v1/auth/login` · `/callback` · `GET /auth/me` ·
  `POST /auth/logout` · `GET /auth/config`.
- **Attributable identities & audit**: every API token is a credential *of* a
  **principal** (a service or a human). Audit entries record the principal id as
  the actor — actions are attributable to a real identity rather than an
  anonymous scope set. A service may hold several tokens against one principal
  (credential rotation); disabling or deleting a principal invalidates all of
  its tokens at once. Manage via `POST/GET /api/v1/principals`.
- **Automatic key rotation**: set a per-key rotation period
  (`POST /keys/{id}/rotation-policy {period_days}`); a key becomes "due" once
  that many days pass since its current version. Run `python -m app.cli.rotate
  due` on a schedule (cron / k8s CronJob) to rotate all due keys — each rotation
  is audited. `--dry-run` lists what would rotate. Manual rotation is unchanged
  when no policy is set.
- **Full key lifecycle**: keys have an explicit state — `enabled`, `disabled`,
  or `pending_deletion`. Disabled and pending keys **refuse all crypto
  operations** (HTTP 409). Deletion is staged: `schedule-deletion` sets a waiting
  window (default 30 days), `cancel-deletion` reverts to disabled, and the key is
  only destroyable once the window elapses (admins may `?force=true` for
  break-glass). **BYOK** import brings external AES-256 material under the Root
  KEK (tagged `origin=imported`), and the public half of signing/KEM keys is
  exportable.
- **Namespaces & per-resource authorization**: keys live in **namespaces**
  (key-rings) for tenant isolation, and **grants** bind a principal to a set of
  operations on a specific key or a whole namespace. Two authorization modes
  (`PQKMS_AUTHZ_MODE`): `legacy` (default — a scope authorizes any key, the
  historical behaviour, so upgrades are non-breaking) and `strict` (a non-admin
  principal must additionally hold a grant covering the operation and the target
  key/namespace; key listings are filtered to what the caller may read). The
  `admin` scope is a global superuser in both modes. A new `manage` scope lets a
  principal administer keys in granted namespaces without global admin. **Enable
  `strict` for an enterprise least-privilege posture.**
- **Versioned schema migrations**: the database schema is owned by **Alembic** —
  every change ships as a numbered, reversible migration applied automatically
  on startup (a fresh DB is built from scratch; an existing one has only the new
  revisions applied; a pre-Alembic DB is stamped at its baseline first).
  Operators can also drive it from the CLI (`alembic current|history|upgrade`).
- **Liveness vs readiness**: `/livez` (process alive — restart on failure) is
  distinct from `/readyz` (unlocked + DB reachable — gate traffic). `/health`
  remains a readiness alias. Wire `/livez` to the orchestrator liveness probe and
  `/readyz` to the readiness gate / load-balancer.
- **Paginated lists**: `GET /keys`, `/tokens`, `/principals`, `/grants` accept
  `?limit=&offset=` (limit 1..1000, default 200; still a JSON array, newest
  first) so listings stay bounded at scale.
- **SIEM-ready audit export**: set `PQKMS_AUDIT_LOG_FORMAT=cef` to mirror audit
  entries as ArcSight **CEF** lines (Splunk/QRadar/Sentinel-parseable) instead of
  JSON. Ships Prometheus **alert rules** (`deploy/prometheus/alerts.yml`) and a
  **Grafana dashboard** (auto-provisioned). Optional **OpenTelemetry** tracing
  (`PQKMS_OTEL_ENABLED=1`, dependency-optional) exports spans to an OTLP collector.
- **Observability**: a `/metrics` Prometheus endpoint (request counts + latency
  by route template, and a keystore-unlocked gauge), structured JSON logs
  (`PQKMS_LOG_FORMAT=json`), and an `X-Request-ID` on every response that is
  echoed in logs and in 500 error bodies for correlation. Scrape `/metrics` from
  the internal network only — keep it off the public proxy route.
- **Operator tooling**: backup/restore-verify (`python -m app.cli.backup
  {create,verify}`), audit verification (`python -m app.cli.audit verify`), and
  operator-passphrase rotation that re-seals the Root KEK without re-encrypting
  subordinate keys (`python -m app.cli.rekey`). See [`deploy/RUNBOOK.md`](deploy/RUNBOOK.md).
- **Pinned liboqs** to a release tag, plus a **digest-pinned base image**;
  `apt-get upgrade` runs at image build.

Before trusting it with real secrets, also:

- Run multiple replicas behind a load balancer. Set `PQKMS_DB_URL` to a shared
  PostgreSQL and `PQKMS_REDIS_URL` to a shared Redis (install the extras:
  `pip install -r requirements.txt -r requirements-ha.txt`). With Postgres as the
  shared store the AES-GCM nonce budget stays correct and fail-closed across
  replicas (it is an atomic `UPDATE … RETURNING`), and audit appends are
  serialized with a fork-proof `UNIQUE(prev_hash)` index.
- Put it behind mTLS with PQC-hybrid TLS (OpenSSL 3.5+ with `X25519MLKEM768`).
- Move the Root KEK into an HSM or cloud KMS via the pluggable custody backends
  (`PQKMS_CUSTODY_BACKEND`): `awskms`, `gcpkms`, or `pkcs11` (CloudHSM, Thales
  Luna, Entrust nShield, SoftHSM for testing). Install the matching optional
  dependency from `requirements-custody.txt`.
- Use Shamir secret sharing for the operator passphrase
  (`PQKMS_CUSTODY_BACKEND=shamir`): split it with
  `python -m app.cli.shamir split --n 5 --k 3` and supply K shares at boot via
  `PQKMS_SHAMIR_SHARE_FILES` / `PQKMS_SHAMIR_SHARES`. The reconstructed
  passphrase is interchangeable with the `passphrase` backend's envelope.
- Stream audit logs to an append-only transparency log or WORM storage. Set
  `PQKMS_AUDIT_LOG_FILE` to mirror every signed entry to an append-only JSONL
  file (point it at a `chattr +a` mount or object storage with retention), then
  cross-check it against the database chain with
  `python -m app.cli.audit verify`. Audit appends are serialized and a
  `UNIQUE(prev_hash)` index makes the hash-chain fork-proof even across replicas.
- Pin the Python base image by digest and rebuild on a security cadence.
- **Revoke the bootstrap admin token** after issuing scoped operational tokens:
  `DELETE /api/v1/tokens/<bootstrap-tid>`. The startup log prints the token id
  alongside the secret.
- **Rotate AEAD keys** before approximately 2³² messages per key version.
  AES-256-GCM with random 96-bit nonces has a birthday-bound collision risk
  beyond that point. This is now **enforced**: the KMS counts encryptions per key
  version, warns at a soft threshold (~2³⁰), and refuses further encryption at the
  hard bound. You can still rotate proactively via `POST /keys/{id}/rotate`.

### Tunables

| Env var                       | Default     | Purpose                                  |
|-------------------------------|-------------|------------------------------------------|
| `PQKMS_PASSPHRASE`            | (required\*)| Operator passphrase for the Root KEK.    |
| `PQKMS_PASSPHRASE_FILE`       | (unset)     | Path to a secret file holding the passphrase; takes precedence over `PQKMS_PASSPHRASE`. |
| `PQKMS_MIN_PASSPHRASE_LEN`    | `16`        | Reject shorter passphrases at startup.   |
| `PQKMS_REQUIRE_PQ`           | `1`         | Refuse to start without liboqs (post-quantum). Set `0` to allow classical-only. |
| `PQKMS_AUTHZ_MODE`           | `legacy`    | `legacy` = scope authorizes any key (historical). `strict` = non-admins also need a grant on the key/namespace. |
| `PQKMS_OIDC_ENABLED`         | `0`         | `1` enables OIDC SSO for the UI. Requires `PQKMS_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_REDIRECT_URL`. |
| `PQKMS_OIDC_ADMIN_GROUPS`    | (unset)     | Comma-separated IdP groups whose members get the `admin` scope; others get `PQKMS_OIDC_DEFAULT_SCOPES` (default `read`). |
| `PQKMS_SESSION_SECRET`       | (random)    | HMAC key for SSO session cookies. Set explicitly so sessions survive restarts and validate across replicas. |
| `PQKMS_CUSTODY_BACKEND`      | `passphrase`| Root-KEK custody backend: `passphrase`, `shamir`, `awskms`, `gcpkms`, or `pkcs11`. |
| `PQKMS_MAX_BODY_BYTES`        | `16777216`  | Request body size cap (16 MiB).          |
| `PQKMS_DATA_DIR`              | `/var/lib/pqkms` | SQLite + key-material location.     |
| `PQKMS_DB_URL`               | (SQLite file) | SQLAlchemy database URL. Set to `postgresql+psycopg://…` for HA / multi-replica. |
| `PQKMS_AUDIT_LOG_FILE`       | (unset)     | Path to an append-only file; every audit entry is also fsync'd here for off-box WORM verification. |
| `PQKMS_AUDIT_LOG_FORMAT`     | `json`      | `json` (canonical JSONL) or `cef` (ArcSight CEF lines for SIEM ingestion). |
| `PQKMS_OTEL_ENABLED`         | `0`         | `1` enables OpenTelemetry tracing (requires the optional opentelemetry packages; exports via `OTEL_EXPORTER_OTLP_*`). |
| `PQKMS_REDIS_URL`            | (in-memory) | Shared rate-limit storage across replicas, e.g. `redis://redis:6379/0`. Fails open (local fallback) if Redis is unreachable. |
| `PQKMS_LOG_FORMAT`           | `text`      | `json` emits one structured JSON log object per line (with `request_id`) for log shippers. |
| `PQKMS_LOG_LEVEL`            | `INFO`      | Root log level.                          |
| `PQKMS_TLS_CERT` / `PQKMS_TLS_KEY` | (unset) | Enable native in-process TLS (uvicorn). Otherwise terminate TLS at the proxy. |
| `PQKMS_TLS_CLIENT_CA`        | (unset)     | With native TLS, require + verify client certs (mutual TLS). |

\* Required for the `passphrase` custody backend; supply it via `PQKMS_PASSPHRASE`
or `PQKMS_PASSPHRASE_FILE`.

## Documentation

- [docs/ENTERPRISE_READINESS.md](docs/ENTERPRISE_READINESS.md) — what's implemented vs external dependencies
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — assets, trust boundaries, adversaries, non-goals
- [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md) — suites, key hierarchy, wire formats
- [docs/COMPLIANCE.md](docs/COMPLIANCE.md) — FIPS boundary statement + SOC2/ISO/PCI control mapping
- [docs/DR.md](docs/DR.md) — backup/restore, RTO/RPO, continuity drills
- [deploy/RUNBOOK.md](deploy/RUNBOOK.md) · [deploy/RELEASE.md](deploy/RELEASE.md) — operations & release/SBOM/signing
- [docs/LICENSING.md](docs/LICENSING.md) — ownership (DarkShadowSec LLC), MIT license, no-warranty statement

## License & ownership

**PQ-KMS is a product of, and is registered to, DarkShadowSec LLC.**

> Copyright © 2026 DarkShadowSec LLC

It is **free and open-source software**, released under the **MIT License**. You
are free to use, copy, modify, and distribute it — **including commercially, at no
charge** — provided the copyright notice and the MIT permission notice are
retained. The software is provided **"as is", without warranty of any kind**, and
DarkShadowSec LLC accepts **no liability** for its use; you operate it at your own
risk.

See [`LICENSE`](LICENSE) for the authoritative terms and
[`docs/LICENSING.md`](docs/LICENSING.md) for the full ownership, license, and
no-warranty statement. Third-party dependencies remain governed by their own
licenses, listed in [`NOTICES.md`](NOTICES.md).
