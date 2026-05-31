# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""Key derivation: HKDF for combining shared secrets, Argon2id for passphrases."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from argon2.low_level import hash_secret_raw, Type


def derive_key(
    ikm: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """HKDF-SHA384. Used to combine hybrid KEM shared secrets."""
    return HKDF(
        algorithm=hashes.SHA384(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def derive_from_passphrase(
    passphrase: str,
    salt: bytes,
    length: int = 32,
) -> bytes:
    """
    Argon2id for deriving the root-KEK-wrapping key from an operator passphrase.

    Parameters are OWASP-recommended minimums for interactive use.
    In production, prefer HSM-backed root keys over passphrase derivation.
    """
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,  # 64 MiB
        parallelism=4,
        hash_len=length,
        type=Type.ID,
    )
