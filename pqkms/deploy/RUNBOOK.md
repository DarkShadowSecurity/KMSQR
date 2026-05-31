# PQ-KMS Operations Runbook

Operational procedures for running PQ-KMS in production. All CLIs read the same
environment as the server (`PQKMS_PASSPHRASE[_FILE]`, `PQKMS_DB_URL` /
`PQKMS_DATA_DIR`, `PQKMS_CUSTODY_BACKEND`, `PQKMS_AUDIT_LOG_FILE`).

## Unseal (start / restart)

Every replica unlocks the Root KEK independently at boot from the operator
passphrase (mounted file — never an env var in production). There is no separate
unseal step: provide `PQKMS_PASSPHRASE_FILE` and the process unlocks on start.
`/health` returns 200 only once unlocked and the DB is reachable.

In HA, the one-shot `pqkms-init` service performs first-time bootstrap (Root KEK,
audit signing key, single bootstrap admin token) before replicas start. Capture
the token from its logs:

```sh
docker compose -f deploy/docker-compose.ha.yml logs pqkms-init | grep -A1 "BOOTSTRAP ADMIN"
```

## Revoke the bootstrap admin token

Issue scoped operational tokens, then revoke the bootstrap token:

```sh
curl -fsS -X POST https://HOST:8443/api/v1/tokens \
  -H "Authorization: Bearer $BOOTSTRAP" -H 'Content-Type: application/json' \
  -d '{"name":"app-encryptor","scopes":["encrypt","decrypt"],"ttl_seconds":2592000}'

curl -fsS -X DELETE https://HOST:8443/api/v1/tokens/$BOOTSTRAP_TID \
  -H "Authorization: Bearer $BOOTSTRAP"
```

The bootstrap token id is printed alongside the secret at issue time.

## Rotate the operator passphrase (re-seal the Root KEK)

Re-seals the existing Root KEK under a new passphrase. Subordinate keys are NOT
re-encrypted and no ciphertext is invalidated.

```sh
PQKMS_PASSPHRASE='<current>' PQKMS_NEW_PASSPHRASE='<new, 16+ chars>' \
  python -m app.cli.rekey
# then update the mounted secret / PQKMS_PASSPHRASE_FILE to the new value and
# roll the replicas.
```

> Run this with writers paused (or a single instance) to avoid a replica
> unlocking with the old passphrase mid-rotation. Roll replicas after the secret
> is updated.

## Rotate a managed (subordinate) key

```sh
curl -fsS -X POST https://HOST:8443/api/v1/keys/$KEY_ID/rotate \
  -H "Authorization: Bearer $ADMIN"
```

New encryptions use the new version; old versions still decrypt/verify. Rotation
also resets that key's AES-GCM nonce budget.

## Nonce-budget alerts

Each AES key version refuses encryption (HTTP 409) as it approaches the
AES-256-GCM random-nonce birthday bound (~2^32), and logs a warning at a soft
threshold (~2^30). Alert on the warning and rotate the key before the hard cap.
Watch the `pqkms_http_requests_total{status="409"}` metric.

## Backup & restore

```sh
# SQLite: consistent snapshot + audit file + manifest
python -m app.cli.backup create /backups/$(date +%F)

# Verify a snapshot is restorable and its audit chain is intact (needs the passphrase)
python -m app.cli.backup verify /backups/2026-05-31
```

For PostgreSQL use `pg_dump` / `pg_restore`:

```sh
pg_dump "$PQKMS_DB_URL" -Fc -f /backups/pqkms.dump
# restore into a fresh database, then:
PQKMS_DB_URL=postgresql+psycopg://... python -m app.cli.audit verify
```

Backups contain only ciphertext; a restore is useless without the operator
passphrase / custody backend. Store the passphrase separately from backups.

## Verify audit integrity

```sh
python -m app.cli.audit verify        # DB chain + signatures, and file cross-check
```

If `PQKMS_AUDIT_LOG_FILE` points at append-only/WORM storage, this catches DB
tampering by anyone who could not also rewrite the append-only file.

## Disaster recovery checklist

1. Restore the database snapshot (SQLite file or `pg_restore`).
2. Restore the append-only audit file (if used).
3. `python -m app.cli.audit verify` — confirm the chain + signatures.
4. `python -m app.cli.backup verify <dir>` — confirm head/count vs manifest.
5. Start replicas with the operator passphrase; confirm `/health` is 200.
