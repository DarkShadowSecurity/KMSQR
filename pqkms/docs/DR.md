# PQ-KMS Disaster Recovery

Backup, restore, and recovery objectives. Operational commands are in
[`../deploy/RUNBOOK.md`](../deploy/RUNBOOK.md); this document is the DR plan.

## What must be protected

1. **The database** (SQLite file or PostgreSQL) — holds wrapped key material,
   versions, audit log, tokens, principals, grants, namespaces.
2. **The custody secret** — the operator passphrase / Shamir shares, or access to
   the HSM / cloud-KMS CMK that seals the Root KEK. **Without it the database is
   unrecoverable by design.** Back it up independently, in a different trust
   domain from the database.
3. **The audit WORM mirror** (if used) — append-only copy for cross-checking.

> Losing the custody secret = permanent loss of all keys. Losing the database =
> loss of keys unless restored from backup. Both are required to recover.

## Backup procedure

- Use `python -m app.cli.backup create` for a consistent, restore-verifiable
  snapshot; `python -m app.cli.backup verify` validates a backup without restoring.
- On PostgreSQL, take coordinated DB backups (PITR/WAL archiving) on your normal
  database cadence; the KMS schema is migration-versioned (Alembic), so restores
  land at a known revision.
- Mirror the audit log off-box (`PQKMS_AUDIT_LOG_FILE`) to WORM storage.
- Back up the custody secret per its backend: Shamir shares to separate holders;
  cloud-KMS/HSM access via your IAM/HSM backup process (the CMK never leaves).

## Recovery objectives (targets to validate per deployment)

| Metric | Single-node (SQLite) | HA (Postgres + replicas) |
|---|---|---|
| **RPO** (max data loss) | ≤ last backup interval (e.g. hourly) | ≤ seconds (WAL/PITR) |
| **RTO** (time to restore) | minutes (restore file + restart) | minutes (failover) / hours (full rebuild) |

These are planning targets; measure them in a game-day exercise. RPO/RTO are
governed by your DB backup cadence and infrastructure, not the KMS software.

## Restore procedure

1. Provision a host/cluster and the same custody backend configuration.
2. Restore the database to the target revision; PQ-KMS runs Alembic migrations to
   head on startup (idempotent).
3. Provide the custody secret (passphrase file / Shamir shares / HSM-KMS access).
4. Start the service; confirm `/readyz` is 200 (unlocked + DB reachable).
5. Run `python -m app.cli.audit verify` and cross-check against the WORM mirror to
   confirm the audit chain restored intact.
6. Rotate the operator passphrase if the backup may have been exposed
   (`python -m app.cli.rekey`) — re-seals the Root KEK without re-encrypting keys.

## High availability

Run multiple stateless replicas behind a load balancer with shared PostgreSQL +
Redis (see the HA compose). The nonce budget and audit chain remain correct
across replicas (atomic counter; advisory-locked, fork-proof appends). Migrations
are advisory-locked so concurrent replica starts apply them exactly once.

## Continuity drills

Quarterly: restore a backup into an isolated environment, verify the audit chain,
exercise an operator-passphrase rotation, and time RTO. Record results.
