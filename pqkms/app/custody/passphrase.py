# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Passphrase-backed Root-KEK custody (the default backend).

Derives a wrapping key from the operator passphrase with Argon2id and AEAD-wraps
the Root KEK under it. The salt and Argon2 cost parameters are stored in the
envelope metadata (non-secret) so they can be tuned over time without losing the
ability to unwrap older roots. A wrong passphrase is detected by the AEAD
authentication tag failing on unwrap — no separate verification value needed.
"""
from __future__ import annotations

import base64
import os

from ..crypto.aead import AEAD
from ..crypto.kdf import derive_from_passphrase, DEFAULT_ARGON2_PARAMS
from .base import CustodyEnvelope, RootKeyCustodian

# AAD binds the wrapped Root KEK to its purpose. Kept identical to the value the
# pre-custodian KeyStore used, so legacy databases unwrap unchanged.
_ROOT_KEK_AAD = b"pqkms/root-kek/v1"
_SALT_LEN = 32


class PassphraseCustodian(RootKeyCustodian):
    backend_id = "passphrase"

    def __init__(self, passphrase: str, argon2_params: dict | None = None):
        if not passphrase:
            raise ValueError("passphrase must not be empty")
        self._passphrase = passphrase
        self._params = dict(argon2_params or DEFAULT_ARGON2_PARAMS)

    def _wrapping_key(self, salt: bytes, params: dict) -> bytes:
        return derive_from_passphrase(
            self._passphrase,
            salt,
            length=params.get("hash_len", 32),
            time_cost=params["time_cost"],
            memory_cost=params["memory_cost"],
            parallelism=params["parallelism"],
        )

    def initialize(self, root_kek: bytes) -> CustodyEnvelope:
        salt = os.urandom(_SALT_LEN)
        wrapping_key = self._wrapping_key(salt, self._params)
        wrapped = AEAD.encrypt(wrapping_key, root_kek, aad=_ROOT_KEK_AAD)
        return CustodyEnvelope(
            backend_id=self.backend_id,
            wrapped_root_kek=wrapped,
            metadata={"salt_b64": base64.b64encode(salt).decode(), "argon2": self._params},
        )

    def unwrap(self, envelope: CustodyEnvelope) -> bytes:
        self.ensure_backend(envelope)
        try:
            salt = base64.b64decode(envelope.metadata["salt_b64"])
            params = envelope.metadata.get("argon2", DEFAULT_ARGON2_PARAMS)
        except (KeyError, ValueError) as e:
            raise ValueError("malformed passphrase custody envelope") from e
        wrapping_key = self._wrapping_key(salt, params)
        try:
            return AEAD.decrypt(wrapping_key, envelope.wrapped_root_kek, aad=_ROOT_KEK_AAD)
        except Exception as e:
            # AEAD tag failure on the Root KEK == wrong passphrase.
            raise ValueError("invalid passphrase") from e
