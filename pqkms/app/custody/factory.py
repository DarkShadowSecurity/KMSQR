# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Custodian selection. PQKMS_CUSTODY_BACKEND chooses the Root-KEK custody backend.

Only 'passphrase' is implemented today; 'awskms', 'gcpkms', 'azurekv', 'pkcs11',
and 'shamir' are reserved identifiers wired in a later phase. Selecting an
unimplemented backend fails fast rather than silently falling back, so an
operator never believes the Root KEK is HSM-protected when it isn't.
"""
from __future__ import annotations

import os

from .base import RootKeyCustodian
from .passphrase import PassphraseCustodian

_NOT_YET_IMPLEMENTED = {"awskms", "gcpkms", "azurekv", "pkcs11", "shamir"}


def make_custodian(passphrase: str | None = None) -> RootKeyCustodian:
    backend = os.environ.get("PQKMS_CUSTODY_BACKEND", "passphrase").strip().lower()

    if backend == "passphrase":
        if passphrase is None:
            raise RuntimeError(
                "the passphrase custody backend requires an operator passphrase "
                "(set PQKMS_PASSPHRASE or PQKMS_PASSPHRASE_FILE)"
            )
        return PassphraseCustodian(passphrase)

    if backend in _NOT_YET_IMPLEMENTED:
        raise RuntimeError(
            f"PQKMS_CUSTODY_BACKEND={backend!r} is reserved but not yet implemented. "
            f"Only 'passphrase' is available in this build; cloud-KMS / PKCS#11 / "
            f"Shamir backends land in a later phase. Refusing to start."
        )

    raise RuntimeError(f"unknown PQKMS_CUSTODY_BACKEND: {backend!r}")
