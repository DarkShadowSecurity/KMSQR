# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Backup / restore-verification.

    python -m app.cli.backup create <out_dir>
    python -m app.cli.backup verify <out_dir>

`create` writes a consistent snapshot of a SQLite-backed KMS (via VACUUM INTO),
copies the append-only audit file if configured, and writes a manifest recording
the audit chain head + count. Everything in the snapshot is CIPHERTEXT — the
Root KEK is sealed by the custodian, so a restore still needs the operator
passphrase / custody backend to be usable.

`verify` opens the snapshot, unlocks it with the custodian, verifies the audit
hash-chain end to end (links + hashes + hybrid signatures), and checks the chain
head + count against the manifest. Exit 0 = good, 1 = discrepancy, 2 = setup.

For PostgreSQL, snapshot the database with `pg_dump` and restore with
`pg_restore` (see deploy/RUNBOOK.md); this tool then `verify`s the restored DB.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import sys
from datetime import datetime, timezone

from sqlalchemy import text

from ..storage.repository import make_repository
from ..storage.keystore import KeyStore
from ..storage.audit import AuditLog, load_or_create_audit_signing_key
from ..custody import make_custodian

MANIFEST = "manifest.json"
SNAPSHOT_DB = "pqkms.sqlite"
SNAPSHOT_AUDIT = "audit.jsonl"


def _passphrase() -> str:
    pf = os.environ.get("PQKMS_PASSPHRASE_FILE")
    if pf:
        data = open(pf, encoding="utf-8").read()
        return data[:-1] if data.endswith("\n") else data
    return os.environ.get("PQKMS_PASSPHRASE", "")


def _chain_head_and_count(repo) -> tuple[str, int]:
    full = repo.iter_audit_asc()
    if not full:
        return base64.b64encode(b"\x00" * 32).decode(), 0
    return base64.b64encode(full[-1]["entry_hash"]).decode(), len(full)


def cmd_create(out_dir: str) -> int:
    os.makedirs(out_dir, exist_ok=True)
    repo = make_repository(data_dir=os.environ.get("PQKMS_DATA_DIR", "/var/lib/pqkms"))
    dialect = repo.engine.dialect.name

    if dialect == "sqlite":
        dest = os.path.join(out_dir, SNAPSHOT_DB)
        if os.path.exists(dest):
            os.remove(dest)
        # VACUUM INTO produces a consistent snapshot of a live database.
        with repo.engine.begin() as c:
            c.execute(text("VACUUM INTO :p"), {"p": dest})
        print(f"snapshot: {dest}")
    else:
        print(f"note: {dialect} backend — snapshot the DB with pg_dump (see RUNBOOK); "
              f"manifest still written for verification.")

    audit_file = os.environ.get("PQKMS_AUDIT_LOG_FILE")
    if audit_file and os.path.exists(audit_file):
        shutil.copy2(audit_file, os.path.join(out_dir, SNAPSHOT_AUDIT))
        print(f"audit file: {SNAPSHOT_AUDIT}")

    head, count = _chain_head_and_count(repo)
    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "dialect": dialect,
        "audit_count": count,
        "audit_head_b64": head,
        "custody_backend": os.environ.get("PQKMS_CUSTODY_BACKEND", "passphrase"),
        "schema": "v1",
    }
    with open(os.path.join(out_dir, MANIFEST), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    print(f"manifest: {count} audit entries, head={head[:16]}…")
    print("OK")
    return 0


def cmd_verify(out_dir: str) -> int:
    manifest_path = os.path.join(out_dir, MANIFEST)
    if not os.path.exists(manifest_path):
        print(f"error: no {MANIFEST} in {out_dir}", file=sys.stderr)
        return 2
    manifest = json.load(open(manifest_path, encoding="utf-8"))

    snap = os.path.join(out_dir, SNAPSHOT_DB)
    if not os.path.exists(snap):
        print(f"error: no {SNAPSHOT_DB} snapshot to verify (PostgreSQL backups verify the "
              f"restored DB via PQKMS_DATA_DIR/PQKMS_DB_URL)", file=sys.stderr)
        return 2

    repo = make_repository(f"sqlite:///{os.path.abspath(snap).replace(os.sep, '/')}")
    passphrase = _passphrase()
    if not passphrase and os.environ.get("PQKMS_CUSTODY_BACKEND", "passphrase") == "passphrase":
        print("error: PQKMS_PASSPHRASE[_FILE] required to verify (unlock + signatures)", file=sys.stderr)
        return 2

    ks = KeyStore(repo, make_custodian(passphrase or None))
    if not ks.is_initialized():
        print("error: snapshot is not an initialized KMS", file=sys.stderr)
        return 2
    try:
        ks.unlock()
    except ValueError:
        print("FAIL: passphrase does not unlock the snapshot", file=sys.stderr)
        return 1

    audit = AuditLog(repo, load_or_create_audit_signing_key(ks))
    ok, bad = audit.verify_chain()
    if not ok:
        print(f"FAIL: audit chain invalid in snapshot (first bad seq={bad})")
        return 1

    head, count = _chain_head_and_count(repo)
    if count != manifest["audit_count"]:
        print(f"FAIL: audit count {count} != manifest {manifest['audit_count']}")
        return 1
    if head != manifest["audit_head_b64"]:
        print(f"FAIL: audit head {head[:16]}… != manifest {manifest['audit_head_b64'][:16]}…")
        return 1

    print(f"OK: snapshot verified — {count} audit entries, chain + signatures valid, "
          f"head matches manifest")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) == 2 and argv[0] in ("create", "verify"):
        return cmd_create(argv[1]) if argv[0] == "create" else cmd_verify(argv[1])
    print("usage: python -m app.cli.backup {create|verify} <dir>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
