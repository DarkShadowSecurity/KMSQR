# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
PKCS#11 (HSM) Root-KEK custody.

Envelope-first: the Root KEK is AES-GCM wrapped/unwrapped by a key that lives on
the HSM and never leaves it. Requires python-pkcs11 (optional extra) and an HSM
(or SoftHSM for testing). Configure via:

  PQKMS_PKCS11_MODULE       path to the PKCS#11 .so/.dll
  PQKMS_PKCS11_TOKEN_LABEL  token label
  PQKMS_PKCS11_PIN          user PIN
  PQKMS_PKCS11_KEY_LABEL    label of the AES wrapping key on the token

The HSM wrapping mechanism is encapsulated behind a small wrapper object, which
can be injected for testing; only that wrapper touches python-pkcs11, so the
custodian's envelope handling is exercisable without an HSM.
"""
from __future__ import annotations

import base64
import os

from .base import CustodyEnvelope, RootKeyCustodian


class _Pkcs11AesGcmWrapper:
    """Wraps/unwraps bytes with an AES-GCM key resident on an HSM token."""

    def __init__(self, module: str, token_label: str, pin: str, key_label: str):
        self._module = module
        self._token_label = token_label
        self._pin = pin
        self._key_label = key_label

    @classmethod
    def from_env(cls) -> "_Pkcs11AesGcmWrapper":
        try:
            module = os.environ["PQKMS_PKCS11_MODULE"]
            token = os.environ["PQKMS_PKCS11_TOKEN_LABEL"]
            pin = os.environ["PQKMS_PKCS11_PIN"]
            key_label = os.environ["PQKMS_PKCS11_KEY_LABEL"]
        except KeyError as e:
            raise RuntimeError(f"pkcs11 custody backend missing env var: {e}") from e
        return cls(module, token, pin, key_label)

    def _key(self, session):
        import pkcs11
        return session.get_key(object_class=pkcs11.ObjectClass.SECRET_KEY, label=self._key_label)

    def _session(self):
        try:
            import pkcs11  # optional dependency
        except ImportError as e:
            raise RuntimeError("the pkcs11 backend requires python-pkcs11 (pip install python-pkcs11)") from e
        lib = pkcs11.lib(self._module)
        token = lib.get_token(token_label=self._token_label)
        return token.open(user_pin=self._pin)

    def wrap(self, plaintext: bytes) -> tuple[bytes, dict]:
        import pkcs11
        iv = os.urandom(12)
        with self._session() as session:
            ct = self._key(session).encrypt(plaintext, mechanism=pkcs11.Mechanism.AES_GCM,
                                             mechanism_param=(iv, b"", 128))
        return ct, {"iv_b64": base64.b64encode(iv).decode(), "key_label": self._key_label}

    def unwrap(self, blob: bytes, metadata: dict) -> bytes:
        import pkcs11
        iv = base64.b64decode(metadata["iv_b64"])
        with self._session() as session:
            return self._key(session).decrypt(blob, mechanism=pkcs11.Mechanism.AES_GCM,
                                               mechanism_param=(iv, b"", 128))


class Pkcs11Custodian(RootKeyCustodian):
    backend_id = "pkcs11"

    def __init__(self, wrapper=None):
        self._wrapper = wrapper  # injectable; built from env lazily otherwise

    def _w(self):
        if self._wrapper is None:
            self._wrapper = _Pkcs11AesGcmWrapper.from_env()
        return self._wrapper

    def initialize(self, root_kek: bytes) -> CustodyEnvelope:
        blob, meta = self._w().wrap(root_kek)
        return CustodyEnvelope(backend_id=self.backend_id, wrapped_root_kek=blob, metadata=meta)

    def unwrap(self, envelope: CustodyEnvelope) -> bytes:
        self.ensure_backend(envelope)
        return self._w().unwrap(envelope.wrapped_root_kek, envelope.metadata)
