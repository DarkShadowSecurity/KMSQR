# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Rotate the operator passphrase (re-seal the Root KEK).

    PQKMS_PASSPHRASE=<current> PQKMS_NEW_PASSPHRASE=<new> python -m app.cli.rekey

Decrypts the Root KEK with the current passphrase and re-wraps it under the new
one. Subordinate keys are NOT re-encrypted (they are wrapped by the Root KEK,
which does not change), so this is fast no matter how many keys exist and no
ciphertext is invalidated. A legacy-format database is migrated to the current
custody-envelope format as a side effect.

Current and new passphrases may also be supplied as files via
PQKMS_PASSPHRASE_FILE / PQKMS_NEW_PASSPHRASE_FILE.
"""
from __future__ import annotations

import logging
import os
import sys

from ..storage.repository import make_repository
from ..storage.keystore import KeyStore
from ..custody import make_custodian, PassphraseCustodian
from ..obs import configure_logging

log = logging.getLogger("pqkms.rekey")

DEFAULT_MIN_PASSPHRASE_LEN = 16


def _read(env_val: str, env_file: str) -> str:
    pf = os.environ.get(env_file)
    if pf:
        data = open(pf, encoding="utf-8").read()
        return data[:-1] if data.endswith("\n") else data
    return os.environ.get(env_val, "")


def main() -> int:
    configure_logging()
    current = _read("PQKMS_PASSPHRASE", "PQKMS_PASSPHRASE_FILE")
    new = _read("PQKMS_NEW_PASSPHRASE", "PQKMS_NEW_PASSPHRASE_FILE")
    if not current or not new:
        log.error("both PQKMS_PASSPHRASE[_FILE] (current) and PQKMS_NEW_PASSPHRASE[_FILE] are required")
        return 2
    min_len = int(os.environ.get("PQKMS_MIN_PASSPHRASE_LEN", DEFAULT_MIN_PASSPHRASE_LEN))
    if len(new) < min_len:
        log.error("new passphrase is shorter than the minimum length (%d)", min_len)
        return 2
    if new == current:
        log.error("new passphrase is identical to the current one")
        return 2

    repo = make_repository(data_dir=os.environ.get("PQKMS_DATA_DIR", "/var/lib/pqkms"))
    ks = KeyStore(repo, make_custodian(current))
    if not ks.is_initialized():
        log.error("KMS is not initialized")
        return 2
    try:
        ks.unlock()
    except ValueError:
        log.error("current passphrase is incorrect")
        return 1

    ks.rewrap_root_kek(PassphraseCustodian(new))
    log.info("Root KEK re-sealed under the new passphrase; subordinate keys unchanged")

    # Prove the new passphrase unlocks before declaring success.
    verify = KeyStore(repo, PassphraseCustodian(new))
    verify.unlock()
    print("OK: passphrase rotated. Update PQKMS_PASSPHRASE / the mounted secret now.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
