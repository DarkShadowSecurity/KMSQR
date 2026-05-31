# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Custodian selection. PQKMS_CUSTODY_BACKEND chooses the Root-KEK custody backend:

  passphrase  operator passphrase + Argon2id (default)
  shamir      reconstruct the passphrase from K-of-N Shamir shares, then as above
  awskms      AWS KMS encrypt/decrypt of the Root KEK
  gcpkms      Google Cloud KMS encrypt/decrypt of the Root KEK
  pkcs11      AES-GCM wrap/unwrap on a PKCS#11 HSM

Cloud/HSM backends need their optional dependency (see requirements-custody.txt)
and provider configuration; selecting one without its config/SDK fails fast
rather than silently degrading.
"""
from __future__ import annotations

import os

from .base import RootKeyCustodian
from .passphrase import PassphraseCustodian


def _load_shamir_shares() -> list[bytes]:
    from .shamir import decode_share

    files = os.environ.get("PQKMS_SHAMIR_SHARE_FILES")
    if files:
        return [decode_share(open(p, encoding="utf-8").read()) for p in files.split(",") if p.strip()]
    inline = os.environ.get("PQKMS_SHAMIR_SHARES")
    if inline:
        return [decode_share(s) for s in inline.split(",") if s.strip()]
    raise RuntimeError(
        "shamir backend requires PQKMS_SHAMIR_SHARE_FILES (comma-separated paths) "
        "or PQKMS_SHAMIR_SHARES (comma-separated base64 shares)"
    )


def make_custodian(passphrase: str | None = None) -> RootKeyCustodian:
    backend = os.environ.get("PQKMS_CUSTODY_BACKEND", "passphrase").strip().lower()

    if backend == "passphrase":
        if passphrase is None:
            raise RuntimeError(
                "the passphrase custody backend requires an operator passphrase "
                "(set PQKMS_PASSPHRASE or PQKMS_PASSPHRASE_FILE)"
            )
        return PassphraseCustodian(passphrase)

    if backend == "shamir":
        from .shamir import ShamirCustodian
        return ShamirCustodian(_load_shamir_shares())

    if backend == "awskms":
        from .awskms import AwsKmsCustodian
        return AwsKmsCustodian()

    if backend == "gcpkms":
        from .gcpkms import GcpKmsCustodian
        return GcpKmsCustodian()

    if backend == "pkcs11":
        from .pkcs11 import Pkcs11Custodian
        return Pkcs11Custodian()

    raise RuntimeError(f"unknown PQKMS_CUSTODY_BACKEND: {backend!r}")
