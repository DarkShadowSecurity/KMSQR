# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
AWS KMS Root-KEK custody.

Envelope-first: the Root KEK is encrypted/decrypted by a customer master key in
AWS KMS — the wrapping key never leaves KMS. Requires boto3 (optional extra) and
standard AWS credentials in the environment. Configure the CMK via
PQKMS_AWS_KMS_KEY_ID (key id, ARN, or alias).
"""
from __future__ import annotations

import os

from .base import CustodyEnvelope, RootKeyCustodian


class AwsKmsCustodian(RootKeyCustodian):
    backend_id = "awskms"

    def __init__(self, key_id: str | None = None, client=None):
        self._key_id = key_id or os.environ.get("PQKMS_AWS_KMS_KEY_ID")
        if not self._key_id:
            raise RuntimeError("PQKMS_AWS_KMS_KEY_ID is required for the awskms custody backend")
        self._client = client  # injectable for tests; built lazily otherwise

    def _kms(self):
        if self._client is None:
            try:
                import boto3  # optional dependency
            except ImportError as e:
                raise RuntimeError("the awskms backend requires boto3 (pip install boto3)") from e
            self._client = boto3.client("kms")
        return self._client

    def initialize(self, root_kek: bytes) -> CustodyEnvelope:
        resp = self._kms().encrypt(KeyId=self._key_id, Plaintext=root_kek)
        return CustodyEnvelope(
            backend_id=self.backend_id,
            wrapped_root_kek=resp["CiphertextBlob"],
            metadata={"key_id": resp.get("KeyId", self._key_id)},
        )

    def unwrap(self, envelope: CustodyEnvelope) -> bytes:
        self.ensure_backend(envelope)
        key_id = envelope.metadata.get("key_id", self._key_id)
        resp = self._kms().decrypt(CiphertextBlob=envelope.wrapped_root_kek, KeyId=key_id)
        return resp["Plaintext"]

    def healthcheck(self) -> None:
        self._kms().describe_key(KeyId=self._key_id)
