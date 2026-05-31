# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Google Cloud KMS Root-KEK custody.

Envelope-first: encrypt/decrypt the Root KEK with a CryptoKey in Cloud KMS.
Requires google-cloud-kms (optional extra) and application default credentials.
Configure the key via PQKMS_GCP_KMS_KEY (the full resource name,
projects/.../locations/.../keyRings/.../cryptoKeys/...).
"""
from __future__ import annotations

import os

from .base import CustodyEnvelope, RootKeyCustodian


class GcpKmsCustodian(RootKeyCustodian):
    backend_id = "gcpkms"

    def __init__(self, key_name: str | None = None, client=None):
        self._key_name = key_name or os.environ.get("PQKMS_GCP_KMS_KEY")
        if not self._key_name:
            raise RuntimeError("PQKMS_GCP_KMS_KEY is required for the gcpkms custody backend")
        self._client = client  # injectable for tests

    def _kms(self):
        if self._client is None:
            try:
                from google.cloud import kms  # optional dependency
            except ImportError as e:
                raise RuntimeError(
                    "the gcpkms backend requires google-cloud-kms (pip install google-cloud-kms)"
                ) from e
            self._client = kms.KeyManagementServiceClient()
        return self._client

    def initialize(self, root_kek: bytes) -> CustodyEnvelope:
        resp = self._kms().encrypt(request={"name": self._key_name, "plaintext": root_kek})
        return CustodyEnvelope(
            backend_id=self.backend_id,
            wrapped_root_kek=resp.ciphertext,
            metadata={"key_name": self._key_name},
        )

    def unwrap(self, envelope: CustodyEnvelope) -> bytes:
        self.ensure_backend(envelope)
        name = envelope.metadata.get("key_name", self._key_name)
        resp = self._kms().decrypt(request={"name": name, "ciphertext": envelope.wrapped_root_kek})
        return resp.plaintext
