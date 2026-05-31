# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Audit verification CLI.

    python -m app.cli.audit verify

Unlocks the KMS (same env as the server: PQKMS_PASSPHRASE[_FILE], PQKMS_DB_URL /
PQKMS_DATA_DIR, PQKMS_CUSTODY_BACKEND), then:

  1. verifies the database hash-chain end to end (prev_hash links, recomputed
     entry hashes, and hybrid signatures);
  2. if PQKMS_AUDIT_LOG_FILE is set, re-derives the chain from the append-only
     file and cross-checks its head against the database head — catching DB
     tampering by anyone who could not also rewrite the append-only file.

Exit code 0 = consistent, 1 = a discrepancy was found, 2 = usage/setup error.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

from ..storage.repository import make_repository
from ..storage.keystore import KeyStore
from ..storage.audit import AuditLog, load_or_create_audit_signing_key
from ..custody import make_custodian


def _load_passphrase() -> str:
    pf = os.environ.get("PQKMS_PASSPHRASE_FILE")
    if pf:
        data = open(pf, encoding="utf-8").read()
        return data[:-1] if data.endswith("\n") else data
    return os.environ.get("PQKMS_PASSPHRASE", "")


def _verify_file_chain(path: str) -> tuple[bool, str]:
    """Recompute the hash chain from the append-only file. Returns (ok, head_b64)."""
    prev = b"\x00" * 32
    head_b64 = base64.b64encode(prev).decode()
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            stored_prev = base64.b64decode(e["prev_hash_b64"])
            if stored_prev != prev:
                return False, f"file line {n}: prev_hash break"
            payload = f"{e['ts']}|{e['actor']}|{e['action']}|{e.get('target') or ''}|{e['detail']}".encode()
            expected = hashlib.sha384(prev + payload).digest()
            if expected != base64.b64decode(e["entry_hash_b64"]):
                return False, f"file line {n}: entry_hash mismatch"
            prev = expected
            head_b64 = e["entry_hash_b64"]
    return True, head_b64


def cmd_verify() -> int:
    passphrase = _load_passphrase()
    if not passphrase and os.environ.get("PQKMS_CUSTODY_BACKEND", "passphrase") == "passphrase":
        print("error: PQKMS_PASSPHRASE or PQKMS_PASSPHRASE_FILE required to unlock", file=sys.stderr)
        return 2

    data_dir = os.environ.get("PQKMS_DATA_DIR", "/var/lib/pqkms")
    repo = make_repository(data_dir=data_dir)
    ks = KeyStore(repo, make_custodian(passphrase or None))
    if not ks.is_initialized():
        print("error: KMS is not initialized (nothing to verify)", file=sys.stderr)
        return 2
    ks.unlock()

    audit = AuditLog(repo, load_or_create_audit_signing_key(ks))
    ok, bad = audit.verify_chain()
    if not ok:
        print(f"DB CHAIN INVALID: first bad seq = {bad}")
        return 1
    full = repo.iter_audit_asc()
    db_head = base64.b64encode(full[-1]["entry_hash"]).decode() if full else base64.b64encode(b"\x00" * 32).decode()
    print(f"DB chain OK: {len(full)} entries, head={db_head[:16]}…")

    log_file = os.environ.get("PQKMS_AUDIT_LOG_FILE")
    if log_file and os.path.exists(log_file):
        file_ok, info = _verify_file_chain(log_file)
        if not file_ok:
            print(f"FILE CHAIN INVALID: {info}")
            return 1
        if info != db_head:
            print(f"MISMATCH: file head {info[:16]}… != db head {db_head[:16]}…")
            return 1
        print(f"File chain OK and matches DB head ({log_file})")
    elif log_file:
        print(f"note: PQKMS_AUDIT_LOG_FILE set but {log_file} does not exist (no file cross-check)")

    print("AUDIT OK")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] != "verify":
        print("usage: python -m app.cli.audit verify", file=sys.stderr)
        return 2
    return cmd_verify()


if __name__ == "__main__":
    raise SystemExit(main())
