# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Root-KEK custody interface.

The KMS has exactly one Root KEK (a 32-byte AES key). Everything else — every
managed key's secret material, the audit signing key — is wrapped under it. How
that Root KEK is protected at rest is the single most important trust decision
in the system, and it is environment-specific (operator passphrase, cloud KMS,
or a hardware HSM). This module defines the seam so the backend is pluggable.

The interface is **envelope-first**: a custodian wraps the Root KEK directly and
returns an opaque `CustodyEnvelope`, and later unwraps that envelope back to the
Root KEK. This shape fits all three backends:

  * passphrase — derive a wrapping key (Argon2id) and AEAD-wrap the Root KEK;
  * cloud KMS  — call Encrypt/Decrypt (the wrapping key never leaves the KMS);
  * PKCS#11    — C_WrapKey/C_UnwrapKey on the HSM.

An interface built around "give me a wrapping key" could not be honored by an
HSM, which never releases key material — so we wrap/unwrap the Root KEK instead.
"""
from __future__ import annotations

import abc
import base64
import json
from dataclasses import dataclass, field


@dataclass
class CustodyEnvelope:
    """
    Opaque, self-describing wrapper around the Root KEK.

    `backend_id` records which custodian produced it so we can refuse to unlock
    with a mismatched backend. `metadata` carries backend-specific, NON-SECRET
    parameters needed to unwrap (e.g. Argon2 salt + cost params, or a KMS key
    ARN). It must never contain the wrapping key or the Root KEK.
    """
    backend_id: str
    wrapped_root_kek: bytes
    metadata: dict = field(default_factory=dict)

    SERIALIZATION_VERSION = 1

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "v": self.SERIALIZATION_VERSION,
                "backend": self.backend_id,
                "wrapped_b64": base64.b64encode(self.wrapped_root_kek).decode(),
                "metadata": self.metadata,
            },
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> "CustodyEnvelope":
        d = json.loads(bytes(raw).decode("utf-8"))
        if d.get("v") != cls.SERIALIZATION_VERSION:
            raise ValueError(f"unsupported custody envelope version: {d.get('v')!r}")
        return cls(
            backend_id=d["backend"],
            wrapped_root_kek=base64.b64decode(d["wrapped_b64"]),
            metadata=d.get("metadata", {}),
        )


class RootKeyCustodian(abc.ABC):
    """Abstract base for Root-KEK custody backends."""

    #: stable identifier persisted in the envelope; subclasses must override.
    backend_id: str = "abstract"

    @abc.abstractmethod
    def initialize(self, root_kek: bytes) -> CustodyEnvelope:
        """Wrap a freshly generated Root KEK, returning the envelope to persist."""

    @abc.abstractmethod
    def unwrap(self, envelope: CustodyEnvelope) -> bytes:
        """Recover the Root KEK from a persisted envelope. Raise ValueError on
        bad credentials (wrong passphrase, denied KMS call)."""

    def healthcheck(self) -> None:
        """Optional: verify the backend is reachable/usable. Default no-op."""
        return None

    def ensure_backend(self, envelope: CustodyEnvelope) -> None:
        """Refuse to operate on an envelope produced by a different backend —
        silently re-wrapping under a new custodian would be a security footgun."""
        if envelope.backend_id != self.backend_id:
            raise RuntimeError(
                f"custody backend mismatch: envelope was sealed by "
                f"{envelope.backend_id!r} but the configured backend is "
                f"{self.backend_id!r}. Set PQKMS_CUSTODY_BACKEND to match, or "
                f"run an explicit re-key migration."
            )
