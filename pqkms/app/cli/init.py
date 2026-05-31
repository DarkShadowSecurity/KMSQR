# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
One-shot bootstrap, intended to run as a `pqkms-init` service before the app
replicas start (so the Root KEK exists, the audit signing key exists, and the
bootstrap admin token is minted exactly once and printed in a single, known
place rather than in whichever replica happened to win the race).

    python -m app.cli.init

Idempotent: safe to run repeatedly. If the KMS is already initialized and a
token already exists, it reports that and issues nothing.
"""
from __future__ import annotations

import logging
import os
import sys

from ..storage.repository import make_repository
from ..storage.keystore import KeyStore
from ..storage.audit import AuditLog, load_or_create_audit_signing_key
from ..storage.audit_sink import make_audit_sink
from ..custody import make_custodian
from ..api.auth import TokenAuth, SCOPES_ADMIN
from ..obs import configure_logging

log = logging.getLogger("pqkms.init")


def _load_passphrase() -> str:
    pf = os.environ.get("PQKMS_PASSPHRASE_FILE")
    if pf:
        data = open(pf, encoding="utf-8").read()
        return data[:-1] if data.endswith("\n") else data
    return os.environ.get("PQKMS_PASSPHRASE", "")


def main() -> int:
    configure_logging()
    passphrase = _load_passphrase()
    if not passphrase and os.environ.get("PQKMS_CUSTODY_BACKEND", "passphrase") == "passphrase":
        log.error("PQKMS_PASSPHRASE or PQKMS_PASSPHRASE_FILE is required")
        return 2

    repo = make_repository(data_dir=os.environ.get("PQKMS_DATA_DIR", "/var/lib/pqkms"))
    ks = KeyStore(repo, make_custodian(passphrase or None))
    if not ks.is_initialized():
        ks.initialize()
        log.info("KMS initialized")
    else:
        ks.unlock()
        log.info("KMS already initialized; unlocked")

    keypair = load_or_create_audit_signing_key(ks)
    audit = AuditLog(repo, keypair, sink=make_audit_sink(os.environ.get("PQKMS_AUDIT_LOG_FILE")))
    auth = TokenAuth(repo)

    if not auth.has_any_token() and repo.put_meta("bootstrap_admin_issued_v1", b"1", if_absent=True):
        tid, raw = auth.create_token(name="bootstrap-admin", scopes={SCOPES_ADMIN})
        audit.append("system", "bootstrap", target=tid, detail={"event": "initial_admin_token_created"})
        print("=" * 72, flush=True)
        print("BOOTSTRAP ADMIN TOKEN (only shown once — save it now):", flush=True)
        print(f"  {raw}", flush=True)
        print(f"REVOKE via DELETE /api/v1/tokens/{tid} after issuing scoped tokens.", flush=True)
        print("=" * 72, flush=True)
    else:
        log.info("a token already exists; no bootstrap token issued")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
