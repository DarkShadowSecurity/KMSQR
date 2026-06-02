# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Rotate keys whose automatic-rotation period has elapsed. Run on a schedule
(cron / systemd timer / k8s CronJob) so policy-driven rotation happens without
operator action:

    PQKMS_PASSPHRASE=... python -m app.cli.rotate due           # rotate due keys
    PQKMS_PASSPHRASE=... python -m app.cli.rotate due --dry-run # list, don't rotate

Uses the same custody backend / env as the server. Each rotation is recorded in
the audit log via the KeyStore. Set a key's policy with
POST /api/v1/keys/{id}/rotation-policy {"period_days": N}.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

from ..storage.repository import make_repository
from ..storage.keystore import KeyStore
from ..storage.audit import AuditLog, load_or_create_audit_signing_key
from ..custody import make_custodian
from ..obs import configure_logging

log = logging.getLogger("pqkms.rotate")


def main(argv=None) -> int:
    configure_logging()
    ap = argparse.ArgumentParser(description="Rotate keys whose rotation period has elapsed.")
    ap.add_argument("command", choices=["due"], help="'due' rotates all keys past their period")
    ap.add_argument("--dry-run", action="store_true", help="list due keys without rotating")
    args = ap.parse_args(argv)

    passphrase = os.environ.get("PQKMS_PASSPHRASE")
    repo = make_repository(data_dir=os.environ.get("PQKMS_DATA_DIR", "/var/lib/pqkms"))
    ks = KeyStore(repo, make_custodian(passphrase))
    if not ks.is_initialized():
        log.error("KMS is not initialized")
        return 2
    try:
        ks.unlock()
    except ValueError:
        log.error("could not unlock the KMS (wrong custody secret?)")
        return 1

    if args.dry_run:
        due = ks.rotation_due()
        for kid in due:
            print(f"DUE: {kid}")
        print(f"{len(due)} key(s) due for rotation")
        return 0

    # Record rotations in the audit log (the API records them per-call; the CLI
    # path appends its own entries so cron-driven rotations are attributable).
    audit = AuditLog(repo, load_or_create_audit_signing_key(ks))
    rotated = ks.rotate_due()
    for kid in rotated:
        audit.append("system:rotate-cli", "key.rotate", target=kid, detail={"reason": "policy"})
    print(f"rotated {len(rotated)} key(s): {', '.join(rotated) if rotated else '(none due)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
