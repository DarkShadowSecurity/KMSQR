# Copyright (c) 2026 DarkShadowSec LLC. All Rights Reserved.
# Proprietary and confidential. See LICENSE for terms.
"""
Algorithm identifiers for cryptographic agility.

Every wrapped key and ciphertext produced by this KMS is tagged with an
algorithm suite ID. When PQC standards evolve, we add a new suite, mark
old ones read-only, and migrate at our own pace without breaking stored data.
"""
from enum import IntEnum


class Suite(IntEnum):
    # Hybrid suites: classical + PQC combined via HKDF
    HYBRID_X25519_MLKEM768_AES256GCM = 1
    HYBRID_ED25519_MLDSA65 = 2

    # Classical-only (for interop / fallback when liboqs is unavailable)
    CLASSIC_X25519_AES256GCM = 10
    CLASSIC_ED25519 = 11

    # Symmetric-only (for root KEK wrapping of subordinate keys)
    AES256_GCM = 20


SUITE_NAMES = {
    Suite.HYBRID_X25519_MLKEM768_AES256GCM: "hybrid-x25519-mlkem768-aes256gcm",
    Suite.HYBRID_ED25519_MLDSA65: "hybrid-ed25519-mldsa65",
    Suite.CLASSIC_X25519_AES256GCM: "x25519-aes256gcm",
    Suite.CLASSIC_ED25519: "ed25519",
    Suite.AES256_GCM: "aes256gcm",
}
