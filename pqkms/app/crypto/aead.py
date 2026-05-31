# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""AES-256-GCM authenticated encryption. Quantum-resistant at the 128-bit PQ security level."""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AEAD:
    """AES-256-GCM with 96-bit nonces. Quantum-resistant at 128-bit PQ security level."""

    NONCE_LEN = 12
    KEY_LEN = 32

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(AEAD.KEY_LEN)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Returns nonce || ciphertext || tag."""
        if len(key) != AEAD.KEY_LEN:
            raise ValueError(f"AES-256-GCM requires a {AEAD.KEY_LEN}-byte key")
        nonce = os.urandom(AEAD.NONCE_LEN)
        ct = AESGCM(key).encrypt(nonce, plaintext, aad)
        return nonce + ct

    @staticmethod
    def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
        if len(key) != AEAD.KEY_LEN:
            raise ValueError(f"AES-256-GCM requires a {AEAD.KEY_LEN}-byte key")
        if len(blob) < AEAD.NONCE_LEN + 16:
            raise ValueError("ciphertext too short")
        nonce, ct = blob[: AEAD.NONCE_LEN], blob[AEAD.NONCE_LEN :]
        return AESGCM(key).decrypt(nonce, ct, aad)
